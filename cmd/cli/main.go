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

	logger := newLogger(resolveLogLevel(*logLevel))

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

func resolveLogLevel(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv(envLogLevel); v != "" {
		return v
	}
	return defaultLevel
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: l}
	h := slog.NewJSONHandler(os.Stderr, opts)
	return slog.New(h)
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
	if errors.Is(context.Cause(ctx), errTargetExited) {
		logger.Info("target process exited, shutting down")
	}
	return err
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
