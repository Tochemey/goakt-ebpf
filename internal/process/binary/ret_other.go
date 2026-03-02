// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

//go:build !linux

package binary

// Stubs for non-linux systems

func findRetInstructions(data []byte) ([]uint64, error) {
	return nil, nil
}
