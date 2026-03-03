//go:build !linux

// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for the goakt-ebpf agent.
// This file provides a stub for non-Linux platforms (eBPF requires Linux).
package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintf(os.Stderr, "goakt-ebpf requires Linux (current: %s)\n", runtime.GOOS)
	os.Exit(1)
}
