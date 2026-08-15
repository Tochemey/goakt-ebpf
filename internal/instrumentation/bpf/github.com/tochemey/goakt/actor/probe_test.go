package actor

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/trace"

	instcontext "github.com/tochemey/goakt-ebpf/internal/instrumentation/context"
)

func TestProcessEventParentPrecedence(t *testing.T) {
	logger := slog.Default()

	t.Run("prefers userspace context over kernel parent when both exist", func(t *testing.T) {
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

		require.Equal(t, 1, calls, "context extraction should run even when an eBPF parent is present")
		require.Equal(t, extracted.SpanID(), trace.SpanID(span.ParentSpanID()))
		require.Equal(t, extracted.TraceID(), trace.TraceID(span.TraceID()))
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

	bpfTraceID := trace.TraceID{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	doReceiveBPFSpanID := trace.SpanID{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}
	processBPFSpanID := trace.SpanID{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66}
	const receiveCtxPtr = 0xCAFEF00D

	// enqueueEvent is the doReceive span (carries the app context) that both
	// resolves its own TraceID and becomes the parent of the handling span.
	enqueueEvent := func() *event {
		return &event{
			EventType: eventTypeDoReceive,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 5,
				EndTime:   25,
				SpanContext: instcontext.EBPFSpanContext{
					TraceID: bpfTraceID,
					SpanID:  doReceiveBPFSpanID,
				},
			},
			ContextPtr:    0x1234,
			ReceiveCtxPtr: receiveCtxPtr,
		}
	}
	// handlingEvent is the handleReceived span, on a different goroutine, with
	// only the shared ReceiveCtxPtr to correlate it back to the enqueue span.
	handlingEvent := func() *event {
		return &event{
			EventType: eventTypeProcess,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 10,
				EndTime:   20,
				SpanContext: instcontext.EBPFSpanContext{
					TraceID: bpfTraceID,
					SpanID:  processBPFSpanID,
				},
			},
			ReceiveCtxPtr: receiveCtxPtr,
		}
	}

	assertLinked := func(t *testing.T, drSpan, pSpan ptrace.Span) {
		t.Helper()
		require.Equal(t, "actor.doReceive", drSpan.Name())
		require.Equal(t, appTraceID, trace.TraceID(drSpan.TraceID()))
		require.Equal(t, appSpanID, trace.SpanID(drSpan.ParentSpanID()))

		require.Equal(t, "actor.process", pSpan.Name())
		require.Equal(t, appTraceID, trace.TraceID(pSpan.TraceID()),
			"handling span must inherit the enqueue span's resolved TraceID")
		require.Equal(t, doReceiveBPFSpanID, trace.SpanID(pSpan.ParentSpanID()),
			"handling span parent should be the enqueue span's SpanID")
	}

	t.Run("handling arrives before enqueue (buffered, resolved on enqueue)", func(t *testing.T) {
		processFn := makeProcessFn(slog.Default(), 42)

		spans := processFn(handlingEvent())
		require.Equal(t, 0, spans.Len(), "handling event should be buffered until its enqueue arrives")

		spans = processFn(enqueueEvent())
		require.Equal(t, 2, spans.Len(), "enqueue should emit itself and the buffered handling span")
		assertLinked(t, spans.At(0), spans.At(1))
	})

	t.Run("enqueue arrives before handling (link resolved immediately)", func(t *testing.T) {
		processFn := makeProcessFn(slog.Default(), 42)

		spans := processFn(enqueueEvent())
		require.Equal(t, 1, spans.Len(), "enqueue emits only itself")
		drSpan := spans.At(0)

		spans = processFn(handlingEvent())
		require.Equal(t, 1, spans.Len(), "handling links immediately to the known enqueue span")
		assertLinked(t, drSpan, spans.At(0))
	})

	t.Run("grain handling links to grain enqueue", func(t *testing.T) {
		processFn := makeProcessFn(slog.Default(), 42)
		const grainPtr = 0x5678

		grainEnqueue := &event{
			EventType: eventTypeGrainDoReceive,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 5, EndTime: 25,
				SpanContext: instcontext.EBPFSpanContext{TraceID: bpfTraceID, SpanID: doReceiveBPFSpanID},
			},
			ContextPtr:    0x9999,
			ReceiveCtxPtr: grainPtr,
		}
		grainHandling := &event{
			EventType: eventTypeGrainProcess,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime: 10, EndTime: 20,
				SpanContext: instcontext.EBPFSpanContext{TraceID: bpfTraceID, SpanID: processBPFSpanID},
			},
			ReceiveCtxPtr: grainPtr,
		}

		require.Equal(t, 1, processFn(grainEnqueue).Len())
		spans := processFn(grainHandling)
		require.Equal(t, 1, spans.Len())
		require.Equal(t, "grain.process", spans.At(0).Name())
		require.Equal(t, appTraceID, trace.TraceID(spans.At(0).TraceID()))
		require.Equal(t, doReceiveBPFSpanID, trace.SpanID(spans.At(0).ParentSpanID()))
	})

	t.Run("handling without a correlation pointer emits immediately", func(t *testing.T) {
		processFn := makeProcessFn(slog.Default(), 42)
		e := handlingEvent()
		e.ReceiveCtxPtr = 0

		spans := processFn(e)
		require.Equal(t, 1, spans.Len(), "handling with no ReceiveCtxPtr should emit immediately")
		require.Equal(t, "actor.process", spans.At(0).Name())
	})

	t.Run("duplicate enqueue for the same pointer is ignored", func(t *testing.T) {
		processFn := makeProcessFn(slog.Default(), 42)

		require.Equal(t, 1, processFn(enqueueEvent()).Len())
		require.Equal(t, 0, processFn(enqueueEvent()).Len(),
			"build+doReceive both emit doReceive for the same *ReceiveContext")

		spans := processFn(handlingEvent())
		require.Equal(t, 1, spans.Len())
		require.Equal(t, doReceiveBPFSpanID, trace.SpanID(spans.At(0).ParentSpanID()))
	})

	t.Run("pooled pointer attaches only one pending handling span", func(t *testing.T) {
		processFn := makeProcessFn(slog.Default(), 42)

		require.Equal(t, 0, processFn(handlingEvent()).Len())
		second := handlingEvent()
		second.BaseSpanProperties.SpanContext.SpanID = trace.SpanID{0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77}
		require.Equal(t, 0, processFn(second).Len())

		spans := processFn(enqueueEvent())
		require.Equal(t, 2, spans.Len(), "enqueue should emit itself and exactly one buffered handling span")
		require.Equal(t, "actor.doReceive", spans.At(0).Name())
		require.Equal(t, "actor.process", spans.At(1).Name())
		require.Equal(t, processBPFSpanID, trace.SpanID(spans.At(1).SpanID()))
	})
}
