// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyscallReturn(t *testing.T) {
	t.Run("valid address is returned unchanged", func(t *testing.T) {
		v, err := syscallReturn(0x7f0000000000)
		require.NoError(t, err)
		assert.Equal(t, uint64(0x7f0000000000), v)
	})

	t.Run("MAP_FAILED (-1) is an errno", func(t *testing.T) {
		// A raw mmap failure returns (void *)-1, which must be reported as
		// an error rather than passing as a valid address.
		_, err := syscallReturn(^uint64(0))
		require.Error(t, err)
		assert.Equal(t, syscall.Errno(1), err)
	})

	t.Run("ENOMEM (-12) is an errno", func(t *testing.T) {
		_, err := syscallReturn(^uint64(0) - 11)
		require.Error(t, err)
		assert.Equal(t, syscall.ENOMEM, err)
	})

	t.Run("value just past the errno range is a valid return", func(t *testing.T) {
		// -4096 is outside [-MAX_ERRNO, -1] and must not be treated as an error.
		v, err := syscallReturn(^uint64(0) - 4095)
		require.NoError(t, err)
		assert.Equal(t, ^uint64(0)-4095, v)
	})
}
