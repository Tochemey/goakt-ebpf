//go:build linux

// Copyright The OpenTelemetry Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

package process

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// FindByExe scans /proc for a process whose executable matches the given path.
// The path is resolved to an absolute path before matching.
// Returns the first matching PID, or an error if none found.
func FindByExe(exePath string) (ID, error) {
	abs, err := filepath.Abs(exePath)
	if err != nil {
		return 0, fmt.Errorf("resolve exe path: %w", err)
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		procID := ID(pid)
		link, err := procID.ExeLink()
		if err != nil {
			continue
		}
		if link == abs {
			return procID, nil
		}
	}

	return 0, errors.New("no process found matching executable path")
}
