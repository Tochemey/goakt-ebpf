// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

//go:build linux

package kernel

import (
	"syscall"

	"github.com/Masterminds/semver/v3"
)

// unameFn is allows testing with a mock for syscall.Uname.
var unameFn = syscall.Uname

func version() *semver.Version {
	// Adapted from https://github.com/golang/go/blob/go1.21.3/src/internal/syscall/unix/kernel_version_linux.go

	var uname syscall.Utsname
	if err := unameFn(&uname); err != nil {
		return nil
	}

	// Expect a release of the form "major.minor..." (e.g. "5.15.0-generic").
	// Anything else returns nil rather than a mis-parsed version: callers
	// treat nil conservatively, while a bogus 0.0.0 would silently pass
	// version gates such as SupportsContextPropagation.
	var (
		values [2]uint64
		value  uint64
		vi     int
		digits int
	)
	for _, c := range uname.Release {
		if '0' <= c && c <= '9' {
			value = (value * 10) + uint64(c-'0') // nolint:gosec  // c >= '0'
			digits++
			continue
		}
		if digits == 0 {
			// Empty numeric component.
			return nil
		}
		values[vi] = value
		vi++
		if vi >= len(values) {
			break
		}
		if c != '.' {
			// Major and minor must be dot-separated.
			return nil
		}
		value, digits = 0, 0
	}
	if vi < len(values) {
		return nil
	}
	return semver.New(values[0], values[1], 0, "", "")
}
