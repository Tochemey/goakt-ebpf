// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/stretchr/testify/require"
)

type testEvent struct {
	Value uint64
}

// fakeReader returns one canned result per Read.
type fakeReader struct {
	record   perf.Record
	err      error
	deadline time.Time
}

func (r *fakeReader) Read() (perf.Record, error) { return r.record, r.err }
func (r *fakeReader) SetDeadline(t time.Time)    { r.deadline = t }
func (r *fakeReader) Close() error               { return nil }

func newReadProbe(r *fakeReader) *Base[struct{}, testEvent] {
	return &Base[struct{}, testEvent]{Logger: slog.Default(), reader: r}
}

func TestRead(t *testing.T) {
	sample := []byte{42, 0, 0, 0, 0, 0, 0, 0}

	t.Run("decodes a record into an event", func(t *testing.T) {
		r := &fakeReader{record: perf.Record{RawSample: sample}}

		event, err := newReadProbe(r).read()
		require.NoError(t, err)
		require.Equal(t, &testEvent{Value: 42}, event)
		require.WithinDuration(t, time.Now().Add(perfFlushInterval), r.deadline, time.Second,
			"every read is bounded so events below the wakeup mark are flushed")
	})

	t.Run("decodes with ProcessRecord when set", func(t *testing.T) {
		p := newReadProbe(&fakeReader{record: perf.Record{RawSample: sample}})
		p.ProcessRecord = func(perf.Record) (*testEvent, error) { return &testEvent{Value: 7}, nil }

		event, err := p.read()
		require.NoError(t, err)
		require.Equal(t, &testEvent{Value: 7}, event)
	})

	t.Run("fails when ProcessRecord fails", func(t *testing.T) {
		p := newReadProbe(&fakeReader{record: perf.Record{RawSample: sample}})
		p.ProcessRecord = func(perf.Record) (*testEvent, error) { return nil, errors.New("bad record") }

		event, err := p.read()
		require.ErrorContains(t, err, "bad record")
		require.Nil(t, event)
	})

	t.Run("has no event when none arrived before the flush interval", func(t *testing.T) {
		event, err := newReadProbe(&fakeReader{err: os.ErrDeadlineExceeded}).read()
		require.NoError(t, err)
		require.Nil(t, event)
	})

	t.Run("has no event for a lost-samples record", func(t *testing.T) {
		event, err := newReadProbe(&fakeReader{record: perf.Record{LostSamples: 3}}).read()
		require.NoError(t, err)
		require.Nil(t, event)
	})

	t.Run("fails on a record smaller than the event", func(t *testing.T) {
		event, err := newReadProbe(&fakeReader{record: perf.Record{RawSample: sample[:4]}}).read()
		require.ErrorContains(t, err, "too small")
		require.Nil(t, event)
	})

	t.Run("fails once the reader is closed or broken", func(t *testing.T) {
		for _, readErr := range []error{perf.ErrClosed, errors.New("read failed")} {
			event, err := newReadProbe(&fakeReader{err: readErr}).read()
			require.ErrorIs(t, err, readErr)
			require.Nil(t, event)
		}
	})
}

func TestInitReaderWithoutEventsMap(t *testing.T) {
	p := newReadProbe(nil)
	p.collection = &ebpf.Collection{Maps: map[string]*ebpf.Map{}}

	require.ErrorContains(t, p.initReader(), DefaultBufferMapName)
}
