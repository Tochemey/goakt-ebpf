//go:build linux

// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for the goakt-ebpf agent.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/tochemey/goakt-ebpf/internal/instrumentation"
	"github.com/tochemey/goakt-ebpf/internal/instrumentation/bpf/github.com/tochemey/goakt/actor"
	"github.com/tochemey/goakt-ebpf/internal/process"
	"github.com/tochemey/goakt-ebpf/pipeline/otelsdk"
)

var errTargetExited = errors.New("target process exited")

const (
	envTargetPID = "GOAKT_EBPF_TARGET_PID"
	envLogLevel  = "GOAKT_EBPF_LOG_LEVEL"
	defaultLevel = "info"
)

func main() {
	pid := flag.Int("pid", 0, "Target process ID to instrument")
	exe := flag.String("exe", "", "Target executable path (finds PID by matching /proc/<pid>/exe)")
	logLevel := flag.String("log-level", "", "Log level: debug, info, warn, error (default: info, or "+envLogLevel+")")
	flag.Parse()

	level := resolveLogLevel(*logLevel)
	logger, levelValid := newLoggerChecked(level)
	if !levelValid {
		logger.Warn("invalid log level, defaulting to info", "requested", level)
	}

	targetPID, err := resolveTarget(*pid, *exe)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		printUsage()
		os.Exit(1)
	}

	if err := run(logger, targetPID); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// newLoggerChecked parses level, returning whether it was valid so the caller
// can warn on a typo instead of silently falling back to info.
func newLoggerChecked(level string) (*slog.Logger, bool) {
	var l slog.Level
	valid := l.UnmarshalText([]byte(level)) == nil
	if !valid {
		l = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: l}
	return slog.New(slog.NewJSONHandler(os.Stderr, opts)), valid
}

func resolveLogLevel(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv(envLogLevel); v != "" {
		return v
	}
	return defaultLevel
}

func resolveTarget(pid int, exe string) (int, error) {
	// Priority: -pid > GOAKT_EBPF_TARGET_PID > -exe
	if pid > 0 {
		return pid, nil
	}
	if v := os.Getenv(envTargetPID); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%s must be a valid PID: %w", envTargetPID, err)
		}
		if p > 0 {
			return p, nil
		}
	}
	if exe != "" {
		id, err := process.FindByExe(exe)
		if err != nil {
			return 0, fmt.Errorf("find process by exe: %w", err)
		}
		return int(id), nil
	}
	return 0, fmt.Errorf("must specify -pid, -exe, or %s", envTargetPID)
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: goakt-ebpf -pid <PID> | -exe <path>")
	fmt.Fprintf(os.Stderr, "  -pid: target process ID\n")
	fmt.Fprintf(os.Stderr, "  -exe: target executable path (finds PID by matching /proc/<pid>/exe)\n")
	fmt.Fprintf(os.Stderr, "  -log-level: debug, info, warn, error (default: info)\n")
	fmt.Fprintf(os.Stderr, "  %s: environment variable for target PID\n", envTargetPID)
	fmt.Fprintf(os.Stderr, "  %s: environment variable for log level\n", envLogLevel)
}

const targetCheckInterval = 2 * time.Second

func run(logger *slog.Logger, pid int) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	procID := process.ID(pid)
	if err := procID.Validate(); err != nil {
		return fmt.Errorf("invalid PID %d: %w", pid, err)
	}

	// Cancel context when target process exits.
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go watchTarget(ctx, procID, cancel)

	// Once shutdown has begun, a second signal force-exits rather than being
	// absorbed while cleanup (up to the manager's shutdown timeout) runs.
	go forceExitOnSecondSignal(ctx, logger)

	handler, err := otelsdk.NewHandler(ctx, otelsdk.WithLogger(logger), otelsdk.WithEnv())
	if err != nil {
		return fmt.Errorf("create handler: %w", err)
	}

	cfg := instrumentation.NewNoopConfigProvider(nil)
	manager, err := instrumentation.NewManager(
		logger,
		handler,
		procID,
		cfg,
		actor.New(logger, instrumentation.Version, int(procID)),
	)
	if err != nil {
		return fmt.Errorf("create manager: %w", err)
	}

	if err := manager.Load(ctx); err != nil {
		return fmt.Errorf("load: %w", err)
	}

	err = manager.Run(ctx)

	// A graceful stop — the target exiting or an operator signal (Ctrl-C /
	// SIGTERM) — is a clean shutdown, not a failure. Report it as success so
	// supervisors and CI do not see a non-zero exit code.
	cause := context.Cause(ctx)
	switch {
	case errors.Is(cause, errTargetExited):
		logger.Info("target process exited, shutting down")
		return nil
	case errors.Is(cause, context.Canceled):
		logger.Info("received shutdown signal, shutting down")
		return nil
	}
	return err
}

// forceExitOnSecondSignal waits until shutdown has begun (ctx cancelled) and
// then force-exits on the next signal, so a second Ctrl-C/SIGTERM is not
// absorbed while cleanup runs. The goroutine is reaped by process exit.
func forceExitOnSecondSignal(ctx context.Context, logger *slog.Logger) {
	<-ctx.Done()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	logger.Warn("second signal received during shutdown, forcing exit")
	os.Exit(1)
}

func watchTarget(ctx context.Context, pid process.ID, cancel context.CancelCauseFunc) {
	ticker := time.NewTicker(targetCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !pid.Exists() {
				cancel(errTargetExited)
				return
			}
		}
	}
}
