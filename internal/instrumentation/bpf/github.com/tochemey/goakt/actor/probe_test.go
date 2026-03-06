package actor

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	instcontext "github.com/tochemey/goakt-ebpf/internal/instrumentation/context"
)

func TestProcessEventParentPrecedence(t *testing.T) {
	logger := slog.Default()

	t.Run("prefers parent from kernel event over context extraction", func(t *testing.T) {
		origExtract := extractParentSpanFromContext
		t.Cleanup(func() { extractParentSpanFromContext = origExtract })

		extracted := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9},
			SpanID:  trace.SpanID{8, 8, 8, 8, 8, 8, 8, 8},
			Remote:  true,
		})
		calls := 0
		extractParentSpanFromContext = func(_ int, _ uint64, _ *slog.Logger) *trace.SpanContext {
			calls++
			return &extracted
		}

		e := &event{
			EventType: eventTypeDoReceive,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 1,
				EndTime:   2,
				SpanContext: instcontext.EBPFSpanContext{
					TraceID: trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
					SpanID:  trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2},
				},
				ParentSpanContext: instcontext.EBPFSpanContext{
					SpanID: trace.SpanID{3, 3, 3, 3, 3, 3, 3, 3},
				},
			},
			ContextPtr: 0x1234,
		}

		spans := processEvent(e, logger, 42)
		require.Equal(t, 1, spans.Len())
		span := spans.At(0)

		require.Equal(t, 0, calls, "context extraction should not run when eBPF parent is present")
		require.Equal(t, e.ParentSpanContext.SpanID, trace.SpanID(span.ParentSpanID()))
		require.Equal(t, e.SpanContext.TraceID, trace.TraceID(span.TraceID()))
	})

	t.Run("uses context extraction when kernel parent is absent", func(t *testing.T) {
		origExtract := extractParentSpanFromContext
		t.Cleanup(func() { extractParentSpanFromContext = origExtract })

		extracted := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7},
			SpanID:  trace.SpanID{6, 6, 6, 6, 6, 6, 6, 6},
			Remote:  true,
		})
		calls := 0
		extractParentSpanFromContext = func(_ int, _ uint64, _ *slog.Logger) *trace.SpanContext {
			calls++
			return &extracted
		}

		e := &event{
			EventType: eventTypeDoReceive,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 1,
				EndTime:   2,
				SpanContext: instcontext.EBPFSpanContext{
					TraceID: trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
					SpanID:  trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2},
				},
			},
			ContextPtr: 0x1234,
		}

		spans := processEvent(e, logger, 42)
		require.Equal(t, 1, spans.Len())
		span := spans.At(0)

		require.Equal(t, 1, calls, "context extraction should run when eBPF parent is absent")
		require.Equal(t, extracted.SpanID(), trace.SpanID(span.ParentSpanID()))
		require.Equal(t, extracted.TraceID(), trace.TraceID(span.TraceID()))
	})
}

func TestMakeProcessFnPropagatesTraceID(t *testing.T) {
	origExtract := extractParentSpanFromContext
	t.Cleanup(func() { extractParentSpanFromContext = origExtract })

	appTraceID := trace.TraceID{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22,
		0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
	appSpanID := trace.SpanID{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	extractParentSpanFromContext = func(_ int, _ uint64, _ *slog.Logger) *trace.SpanContext {
		sc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: appTraceID, SpanID: appSpanID, Remote: true,
		})
		return &sc
	}

	processFn := makeProcessFn(slog.Default(), 42)

	bpfTraceID := trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	doReceiveBPFSpanID := trace.SpanID{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}
	processBPFSpanID := trace.SpanID{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}

	t.Run("buffers process event and resolves on doReceive", func(t *testing.T) {
		processE := &event{
			EventType: eventTypeProcess,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 10,
				EndTime:   20,
				SpanContext: instcontext.EBPFSpanContext{
					TraceID: bpfTraceID,
					SpanID:  processBPFSpanID,
				},
				ParentSpanContext: instcontext.EBPFSpanContext{
					TraceID: bpfTraceID,
					SpanID:  doReceiveBPFSpanID,
				},
			},
			ContextPtr: 0, // process has no context
		}

		spans := processFn(processE)
		require.Equal(t, 0, spans.Len(), "process event should be buffered")

		doReceiveE := &event{
			EventType: eventTypeDoReceive,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 5,
				EndTime:   25,
				SpanContext: instcontext.EBPFSpanContext{
					TraceID: bpfTraceID,
					SpanID:  doReceiveBPFSpanID,
				},
			},
			ContextPtr: 0x1234,
		}

		spans = processFn(doReceiveE)
		require.Equal(t, 2, spans.Len(), "doReceive should emit itself and the buffered process")

		drSpan := spans.At(0)
		require.Equal(t, "actor.doReceive", drSpan.Name())
		require.Equal(t, appTraceID, trace.TraceID(drSpan.TraceID()))
		require.Equal(t, appSpanID, trace.SpanID(drSpan.ParentSpanID()))

		pSpan := spans.At(1)
		require.Equal(t, "actor.process", pSpan.Name())
		require.Equal(t, appTraceID, trace.TraceID(pSpan.TraceID()),
			"process must inherit the userspace-resolved TraceID")
		require.Equal(t, doReceiveBPFSpanID, trace.SpanID(pSpan.ParentSpanID()),
			"process parent should be doReceive's BPF SpanID")
	})

	t.Run("grain process buffered and resolved on grainDoReceive", func(t *testing.T) {
		grainDRSpanID := trace.SpanID{0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}
		grainPSpanID := trace.SpanID{0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88}

		grainProcessE := &event{
			EventType: eventTypeGrainProcess,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 10,
				EndTime:   20,
				SpanContext: instcontext.EBPFSpanContext{
					TraceID: bpfTraceID,
					SpanID:  grainPSpanID,
				},
				ParentSpanContext: instcontext.EBPFSpanContext{
					TraceID: bpfTraceID,
					SpanID:  grainDRSpanID,
				},
			},
			ContextPtr: 0,
		}

		spans := processFn(grainProcessE)
		require.Equal(t, 0, spans.Len())

		grainDRE := &event{
			EventType: eventTypeGrainDoReceive,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 5,
				EndTime:   25,
				SpanContext: instcontext.EBPFSpanContext{
					TraceID: bpfTraceID,
					SpanID:  grainDRSpanID,
				},
			},
			ContextPtr: 0x5678,
		}

		spans = processFn(grainDRE)
		require.Equal(t, 2, spans.Len())

		require.Equal(t, appTraceID, trace.TraceID(spans.At(0).TraceID()))
		require.Equal(t, appTraceID, trace.TraceID(spans.At(1).TraceID()))
	})

	t.Run("process without BPF parent is not buffered", func(t *testing.T) {
		e := &event{
			EventType: eventTypeProcess,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 1,
				EndTime:   2,
				SpanContext: instcontext.EBPFSpanContext{
					TraceID: bpfTraceID,
					SpanID:  trace.SpanID{0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99},
				},
			},
			ContextPtr: 0,
		}

		spans := processFn(e)
		require.Equal(t, 1, spans.Len(), "process without BPF parent should emit immediately")
		require.Equal(t, "actor.process", spans.At(0).Name())
	})
}
