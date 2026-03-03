//go:build !linux

// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package process

import "errors"

// FindByExe is not supported on non-Linux platforms.
func FindByExe(exePath string) (ID, error) {
	return 0, errors.New("FindByExe requires Linux")
}
