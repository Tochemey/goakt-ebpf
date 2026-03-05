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
