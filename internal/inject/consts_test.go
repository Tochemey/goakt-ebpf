// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

package inject

import (
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tochemey/goakt-ebpf/internal/process"
	"github.com/tochemey/goakt-ebpf/internal/structfield"
)

func TestWithAllocationDetails(t *testing.T) {
	const start, end, nCPU uint64 = 1, 2, 3
	alloc := process.Allocation{
		StartAddr: start,
		EndAddr:   end,
		NumCPU:    nCPU,
	}

	opts := []Option{WithAllocation(alloc)}
	got, err := newConsts(opts)
	require.NoError(t, err)
	require.Contains(t, got, keyTotalCPUs)
	require.Contains(t, got, keyStartAddr)
	require.Contains(t, got, keyEndAddr)

	v := got[keyTotalCPUs]
	require.IsType(t, *(new(uint64)), v)
	assert.Equal(t, nCPU, v.(uint64))

	v = got[keyStartAddr]
	require.IsType(t, *(new(uint64)), v)
	assert.Equal(t, start, v.(uint64))

	v = got[keyEndAddr]
	require.IsType(t, *(new(uint64)), v)
	assert.Equal(t, end, v.(uint64))
}

func TestWithOffset(t *testing.T) {
	v10 := semver.New(1, 0, 0, "", "")
	v18 := semver.New(1, 8, 0, "", "")

	const off uint64 = 1
	id := structfield.NewID("std", "net/http", "Request", "Method")

	origOff := offsets
	t.Cleanup(func() { offsets = origOff })
	offsets = structfield.NewIndex()
	offsets.PutOffset(id, v10, off, true)
	offsets.PutOffset(id, v18, off, true)

	const name = "test_name"
	opts := []Option{WithOffset(name, id, v10)}
	got, err := newConsts(opts)
	require.NoError(t, err)
	require.Contains(t, got, name)

	v := got[name]
	require.IsType(t, *(new(uint64)), v)
	assert.Equal(t, off, v.(uint64))

	// Failed look-ups need to be returned as an error.
	id.Struct += "Alt"
	opts = []Option{WithOffset(name, id, v10)}
	_, err = newConsts(opts)
	assert.ErrorIs(t, err, errNotFound)
}

func TestWithKeyValue(t *testing.T) {
	const key, val = "test_key", uint64(42)
	opts := []Option{WithKeyValue(key, val)}
	got, err := newConsts(opts)
	require.NoError(t, err)
	require.Contains(t, got, key)
	assert.Equal(t, val, got[key])
}

func TestGetOffset(t *testing.T) {
	id := structfield.NewID("std", "net/http", "Request", "Method")
	v := semver.MustParse("1.19.0")
	off, ok := GetOffset(id, v)
	assert.True(t, ok)
	assert.True(t, off.Valid)
	assert.Equal(t, uint64(0), off.Offset)
}

func TestGetOffsetNotFound(t *testing.T) {
	id := structfield.NewID("nonexistent", "pkg", "Struct", "Field")
	v := semver.MustParse("1.0.0")
	_, ok := GetOffset(id, v)
	assert.False(t, ok)
}

func TestGetLatestOffset(t *testing.T) {
	id := structfield.NewID("std", "net/http", "Request", "Method")
	off, ver := GetLatestOffset(id)
	assert.True(t, off.Valid)
	assert.NotNil(t, ver)
}

func TestGetLatestOffsetNotFound(t *testing.T) {
	id := structfield.NewID("nonexistent", "pkg", "Struct", "Field")
	off, ver := GetLatestOffset(id)
	assert.False(t, off.Valid)
	assert.Nil(t, ver)
}
