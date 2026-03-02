// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

//go:build !linux

package bpffs

import "github.com/tochemey/goakt-ebpf/internal/process"

// Stubs for non-linux systems

func PathForTargetApplication(target *process.Info) string {
	return ""
}

func Mount(target *process.Info) error {
	return nil
}

func Cleanup(target *process.Info) error {
	return nil
}
