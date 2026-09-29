package actor

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/trace"

	instcontext "github.com/tochemey/goakt-ebpf/internal/instrumentation/context"
)

func TestProcessEventUsesProbeResolvedParent(t *testing.T) {
	traceID := trace.TraceID{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	spanID := trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2}

	newEvent := func(parent instcontext.EBPFSpanContext) *event {
		return &event{
			EventType: eventTypeDoReceive,
			BaseSpanProperties: instcontext.BaseSpanProperties{
				StartTime:         1,
				EndTime:           2,
				SpanContext:       instcontext.EBPFSpanContext{TraceID: traceID, SpanID: spanID},
				ParentSpanContext: parent,
			},
		}
	}

	t.Run("links to the parent the probe resolved", func(t *testing.T) {
		parent := instcontext.EBPFSpanContext{TraceID: traceID, SpanID: trace.SpanID{8, 8, 8, 8, 8, 8, 8, 8}}

		spans := processEvent(newEvent(parent))
		require.Equal(t, 1, spans.Len())
		span := spans.At(0)

		require.Equal(t, "actor.doReceive", span.Name())
		require.Equal(t, traceID, trace.TraceID(span.TraceID()))
		require.Equal(t, spanID, trace.SpanID(span.SpanID()))
		require.Equal(t, parent.SpanID, trace.SpanID(span.ParentSpanID()))
	})

	t.Run("is a root span when the probe found no parent", func(t *testing.T) {
		spans := processEvent(newEvent(instcontext.EBPFSpanContext{}))
		require.Equal(t, 1, spans.Len())
		span := spans.At(0)

		require.True(t, span.ParentSpanID().IsEmpty())
		require.Equal(t, traceID, trace.TraceID(span.TraceID()))
	})
}

func TestProcessEventSpanKinds(t *testing.T) {
	cases := []struct {
		eventType   uint8
		name        string
		kind        ptrace.SpanKind
		operation   string
		destination string
	}{
		{eventTypeDoReceive, "actor.doReceive", ptrace.SpanKindConsumer, "receive", "actor"},
		{eventTypeGrainDoReceive, "grain.doReceive", ptrace.SpanKindConsumer, "receive", "grain"},
		{eventTypeTellGrain, "grain.tell", ptrace.SpanKindProducer, "send", "grain"},
		{eventTypeAskGrain, "grain.ask", ptrace.SpanKindClient, "request", "grain"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &event{
				EventType: tc.eventType,
				BaseSpanProperties: instcontext.BaseSpanProperties{
					StartTime: 5, EndTime: 25,
					SpanContext: instcontext.EBPFSpanContext{
						TraceID: trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
						SpanID:  trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
					},
				},
			}

			spans := processEvent(e)
			require.Equal(t, 1, spans.Len())
			span := spans.At(0)
			require.Equal(t, tc.name, span.Name())
			require.Equal(t, tc.kind, span.Kind())

			op, ok := span.Attributes().Get("messaging.operation")
			require.True(t, ok)
			require.Equal(t, tc.operation, op.Str())
			dest, ok := span.Attributes().Get("messaging.destination")
			require.True(t, ok)
			require.Equal(t, tc.destination, dest.Str())
		})
	}

	t.Run("handling spans", func(t *testing.T) {
		for et, name := range map[uint8]string{
			eventTypeProcess:      "actor.process",
			eventTypeGrainProcess: "grain.process",
		} {
			spans := processEvent(&event{EventType: et})
			require.Equal(t, 1, spans.Len())
			require.Equal(t, name, spans.At(0).Name())
			require.Equal(t, ptrace.SpanKindInternal, spans.At(0).Kind())
		}
	})
}

// Every event type the probes emit must convert to its own named span; only
// an unrecognized type falls back to actor.unknown.
func TestProcessEventNamesEveryEventType(t *testing.T) {
	eventTypes := []uint8{
		eventTypeDoReceive,
		eventTypeRemoteTell,
		eventTypeRemoteAsk,
		eventTypeProcess,
		eventTypeGrainProcess,
		eventTypeGrainDoReceive,
		eventTypeSystemSpawn,
		eventTypeSpawnChild,
		eventTypeRemoteSpawn,
		eventTypeRemoteSpawnChild,
		eventTypeRemoteTellReceive,
		eventTypeRemoteAskReceive,
		eventTypeRelocation,
		eventTypeRemoteTellGrain,
		eventTypeRemoteAskGrain,
		eventTypeRemoteLookup,
		eventTypeRemoteReSpawn,
		eventTypeRemoteStop,
		eventTypeRemoteAskGrainReceive,
		eventTypeRemoteTellGrainReceive,
		eventTypeRemoteActivateGrain,
		eventTypeRemoteReinstate,
		eventTypeRemotePassivationStrategy,
		eventTypeRemoteState,
		eventTypeRemoteChildren,
		eventTypeRemoteParent,
		eventTypeRemoteKind,
		eventTypeRemoteDependencies,
		eventTypeRemoteMetric,
		eventTypeRemoteRole,
		eventTypeRemoteStashSize,
		eventTypeSpawnOn,
		eventTypeActorOf,
		eventTypeSpawnNamedFromFunc,
		eventTypeSpawnFromFunc,
		eventTypeSpawnRouter,
		eventTypeSpawnSingleton,
		eventTypeKill,
		eventTypeReSpawn,
		eventTypeActorExists,
		eventTypeSystemMetric,
		eventTypeActors,
		eventTypeStart,
		eventTypeStop,
		eventTypeScheduleOnce,
		eventTypeSchedule,
		eventTypeScheduleWithCron,
		eventTypeTell,
		eventTypeAsk,
		eventTypeSendAsync,
		eventTypeSendSync,
		eventTypeDiscoverActor,
		eventTypePIDStop,
		eventTypeRestart,
		eventTypePIDMetric,
		eventTypeReinstateNamed,
		eventTypePipeTo,
		eventTypePipeToName,
		eventTypeBatchTell,
		eventTypeBatchAsk,
		eventTypePIDRemoteLookup,
		eventTypePIDRemoteStop,
		eventTypePIDRemoteReSpawn,
		eventTypeShutdown,
		eventTypeTellGrain,
		eventTypeAskGrain,
	}

	seen := make(map[string]uint8, len(eventTypes))
	for _, et := range eventTypes {
		for _, success := range []uint8{0, 1} {
			spans := processEvent(&event{EventType: et, HandledSuccessfully: success})
			require.Equal(t, 1, spans.Len())
			name := spans.At(0).Name()
			require.NotEqual(t, "actor.unknown", name, "event type %d", et)

			if prev, dup := seen[name]; dup && prev != et {
				t.Fatalf("event types %d and %d both map to %q", prev, et, name)
			}

			seen[name] = et
		}
	}

	spans := processEvent(&event{EventType: 255})
	require.Equal(t, "actor.unknown", spans.At(0).Name())
}

func TestNew(t *testing.T) {
	p := New(slog.Default(), "test")
	require.Equal(t, pkg, p.Manifest().ID.InstrumentedPkg)
}
