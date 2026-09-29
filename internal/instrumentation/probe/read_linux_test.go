//go:build linux

// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestInitReader(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("needs privileges to create eBPF maps: %v", err)
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{Name: DefaultBufferMapName, Type: ebpf.PerfEventArray})
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("needs privileges to create eBPF maps: %v", err)
	}

	require.NoError(t, err)
	t.Cleanup(func() { _ = events.Close() })

	p := newReadProbe(nil)
	p.collection = &ebpf.Collection{Maps: map[string]*ebpf.Map{DefaultBufferMapName: events}}

	err = p.initReader()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("needs privileges to open perf events: %v", err)
	}

	require.NoError(t, err)
	require.Len(t, p.closers, 1)

	// Nothing was written, so a read ends at the flush interval.
	event, err := p.read()
	require.NoError(t, err)
	require.Nil(t, event)
	require.NoError(t, p.reader.Close())

	_, err = p.reader.Read()
	require.ErrorIs(t, err, os.ErrClosed)
}
