// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Uses patterns and structure from OpenTelemetry Go Instrumentation
// (https://github.com/open-telemetry/opentelemetry-go-instrumentation).

// Package actor provides eBPF instrumentation probes for GoAkt actor message handling.
package actor

import (
	"log/slog"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/tochemey/goakt-ebpf/internal/process"
	"github.com/tochemey/goakt-ebpf/internal/structfield"

	"github.com/tochemey/goakt-ebpf/internal/instrumentation/context"
	"github.com/tochemey/goakt-ebpf/internal/instrumentation/kernel"
	"github.com/tochemey/goakt-ebpf/internal/instrumentation/pdataconv"
	"github.com/tochemey/goakt-ebpf/internal/instrumentation/probe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf ./bpf/probe.bpf.c

const pkg = "github.com/tochemey/goakt/v4/actor"

// Event type constants (must match C EVENT_TYPE_*)
const (
	eventTypeDoReceive                 = 1
	eventTypeRemoteTell                = 2
	eventTypeRemoteAsk                 = 3
	eventTypeProcess                   = 4
	eventTypeGrainProcess              = 5
	eventTypeGrainDoReceive            = 6
	eventTypeSystemSpawn               = 7
	eventTypeSpawnChild                = 8
	eventTypeRemoteSpawn               = 9
	eventTypeRemoteSpawnChild          = 10
	eventTypeRemoteTellReceive         = 11
	eventTypeRemoteAskReceive          = 12
	eventTypeRelocation                = 13
	eventTypeRemoteTellGrain           = 14
	eventTypeRemoteAskGrain            = 15
	eventTypeRemoteLookup              = 16
	eventTypeRemoteReSpawn             = 17
	eventTypeRemoteStop                = 18
	eventTypeRemoteAskGrainReceive     = 19
	eventTypeRemoteTellGrainReceive    = 20
	eventTypeRemoteActivateGrain       = 21
	eventTypeRemoteReinstate           = 22
	eventTypeRemotePassivationStrategy = 23
	eventTypeRemoteState               = 24
	eventTypeRemoteChildren            = 25
	eventTypeRemoteParent              = 26
	eventTypeRemoteKind                = 27
	eventTypeRemoteDependencies        = 28
	eventTypeRemoteMetric              = 29
	eventTypeRemoteRole                = 30
	eventTypeRemoteStashSize           = 31
	eventTypeSpawnOn                   = 32
	eventTypeActorOf                   = 33
	eventTypeSpawnNamedFromFunc        = 34
	eventTypeSpawnFromFunc             = 35
	eventTypeSpawnRouter               = 36
	eventTypeSpawnSingleton            = 37
	eventTypeKill                      = 38
	eventTypeReSpawn                   = 39
	eventTypeActorExists               = 40
	eventTypeSystemMetric              = 41
	eventTypeActors                    = 42
	eventTypeStart                     = 43
	eventTypeStop                      = 44
	eventTypeScheduleOnce              = 45
	eventTypeSchedule                  = 46
	eventTypeScheduleWithCron          = 47
	eventTypeTell                      = 48
	eventTypeAsk                       = 49
	eventTypeSendAsync                 = 50
	eventTypeSendSync                  = 51
	eventTypeDiscoverActor             = 52
	eventTypePIDStop                   = 53
	eventTypeRestart                   = 54
	eventTypePIDMetric                 = 55
	eventTypeReinstateNamed            = 56
	eventTypePipeTo                    = 57
	eventTypePipeToName                = 58
	eventTypeBatchTell                 = 59
	eventTypeBatchAsk                  = 60
	eventTypePIDRemoteLookup           = 61
	eventTypePIDRemoteStop             = 62
	eventTypePIDRemoteReSpawn          = 63
	eventTypeShutdown                  = 64
)

// New returns a new [probe.Probe] for GoAkt actor instrumentation (all targets).
// targetPID enables userspace context reading for remote trace propagation when > 0.
func New(logger *slog.Logger, version string, targetPID int) probe.Probe {
	id := probe.ID{
		SpanKind:        trace.SpanKindConsumer,
		InstrumentedPkg: pkg,
	}
	receiveContextContextID := structfield.NewID(
		"github.com/tochemey/goakt/v4",
		"github.com/tochemey/goakt/v4/actor",
		"ReceiveContext",
		"ctx",
	)
	processFn := makeProcessFn(logger, targetPID)
	return &probe.SpanProducer[bpfObjects, event]{
		Base: probe.Base[bpfObjects, event]{
			ID:     id,
			Logger: logger,
			Consts: []probe.Const{
				probe.StructFieldConst{
					Key: "receive_context_ctx_offset",
					ID:  receiveContextContextID,
				},
			},
			Uprobes: []*probe.Uprobe{
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).doReceive",
					EntryProbe:  "uprobe_doReceive",
					ReturnProbe: "uprobe_doReceive_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).handleRemoteTell",
					EntryProbe:  "uprobe_handleRemoteTell",
					ReturnProbe: "uprobe_handleRemoteTell_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).handleRemoteAsk",
					EntryProbe:  "uprobe_handleRemoteAsk",
					ReturnProbe: "uprobe_handleRemoteAsk_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).process",
					EntryProbe:  "uprobe_process",
					ReturnProbe: "uprobe_process_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*grainPID).process",
					EntryProbe:  "uprobe_grainPID_process",
					ReturnProbe: "uprobe_grainPID_process_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*grainPID).handleGrainContext",
					EntryProbe:  "uprobe_handleGrainContext",
					ReturnProbe: "uprobe_handleGrainContext_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).Spawn",
					EntryProbe:  "uprobe_Spawn",
					ReturnProbe: "uprobe_Spawn_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).SpawnOn",
					EntryProbe:  "uprobe_SpawnOn",
					ReturnProbe: "uprobe_SpawnOn_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).ActorOf",
					EntryProbe:  "uprobe_ActorOf",
					ReturnProbe: "uprobe_ActorOf_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).SpawnNamedFromFunc",
					EntryProbe:  "uprobe_SpawnNamedFromFunc",
					ReturnProbe: "uprobe_SpawnNamedFromFunc_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).SpawnFromFunc",
					EntryProbe:  "uprobe_SpawnFromFunc",
					ReturnProbe: "uprobe_SpawnFromFunc_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).SpawnRouter",
					EntryProbe:  "uprobe_SpawnRouter",
					ReturnProbe: "uprobe_SpawnRouter_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).SpawnSingleton",
					EntryProbe:  "uprobe_SpawnSingleton",
					ReturnProbe: "uprobe_SpawnSingleton_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).Kill",
					EntryProbe:  "uprobe_Kill",
					ReturnProbe: "uprobe_Kill_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).ReSpawn",
					EntryProbe:  "uprobe_ReSpawn",
					ReturnProbe: "uprobe_ReSpawn_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).ActorExists",
					EntryProbe:  "uprobe_ActorExists",
					ReturnProbe: "uprobe_ActorExists_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).Metric",
					EntryProbe:  "uprobe_actorSystem_Metric",
					ReturnProbe: "uprobe_actorSystem_Metric_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).Actors",
					EntryProbe:  "uprobe_Actors",
					ReturnProbe: "uprobe_Actors_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).Start",
					EntryProbe:  "uprobe_Start",
					ReturnProbe: "uprobe_Start_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).Stop",
					EntryProbe:  "uprobe_actorSystem_Stop",
					ReturnProbe: "uprobe_actorSystem_Stop_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).ScheduleOnce",
					EntryProbe:  "uprobe_ScheduleOnce",
					ReturnProbe: "uprobe_ScheduleOnce_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).Schedule",
					EntryProbe:  "uprobe_Schedule",
					ReturnProbe: "uprobe_Schedule_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).ScheduleWithCron",
					EntryProbe:  "uprobe_ScheduleWithCron",
					ReturnProbe: "uprobe_ScheduleWithCron_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).Tell",
					EntryProbe:  "uprobe_Tell",
					ReturnProbe: "uprobe_Tell_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).Ask",
					EntryProbe:  "uprobe_Ask",
					ReturnProbe: "uprobe_Ask_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).SendAsync",
					EntryProbe:  "uprobe_SendAsync",
					ReturnProbe: "uprobe_SendAsync_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).SendSync",
					EntryProbe:  "uprobe_SendSync",
					ReturnProbe: "uprobe_SendSync_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).DiscoverActor",
					EntryProbe:  "uprobe_DiscoverActor",
					ReturnProbe: "uprobe_DiscoverActor_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).Stop",
					EntryProbe:  "uprobe_pid_Stop",
					ReturnProbe: "uprobe_pid_Stop_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).Restart",
					EntryProbe:  "uprobe_Restart",
					ReturnProbe: "uprobe_Restart_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).Metric",
					EntryProbe:  "uprobe_pid_Metric",
					ReturnProbe: "uprobe_pid_Metric_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).ReinstateNamed",
					EntryProbe:  "uprobe_ReinstateNamed",
					ReturnProbe: "uprobe_ReinstateNamed_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).PipeTo",
					EntryProbe:  "uprobe_PipeTo",
					ReturnProbe: "uprobe_PipeTo_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).PipeToName",
					EntryProbe:  "uprobe_PipeToName",
					ReturnProbe: "uprobe_PipeToName_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).BatchTell",
					EntryProbe:  "uprobe_BatchTell",
					ReturnProbe: "uprobe_BatchTell_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).BatchAsk",
					EntryProbe:  "uprobe_BatchAsk",
					ReturnProbe: "uprobe_BatchAsk_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).RemoteLookup",
					EntryProbe:  "uprobe_RemoteLookup",
					ReturnProbe: "uprobe_RemoteLookup_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).RemoteStop",
					EntryProbe:  "uprobe_RemoteStop",
					ReturnProbe: "uprobe_RemoteStop_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).RemoteReSpawn",
					EntryProbe:  "uprobe_RemoteReSpawn",
					ReturnProbe: "uprobe_RemoteReSpawn_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).Shutdown",
					EntryProbe:  "uprobe_Shutdown",
					ReturnProbe: "uprobe_Shutdown_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).SpawnChild",
					EntryProbe:  "uprobe_SpawnChild",
					ReturnProbe: "uprobe_SpawnChild_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteSpawnHandler",
					EntryProbe:  "uprobe_remoteSpawnHandler",
					ReturnProbe: "uprobe_remoteSpawnHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteSpawnChildHandler",
					EntryProbe:  "uprobe_remoteSpawnChildHandler",
					ReturnProbe: "uprobe_remoteSpawnChildHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteTellHandler",
					EntryProbe:  "uprobe_remoteTellHandler",
					ReturnProbe: "uprobe_remoteTellHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteAskHandler",
					EntryProbe:  "uprobe_remoteAskHandler",
					ReturnProbe: "uprobe_remoteAskHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteTellGrain",
					EntryProbe:  "uprobe_remoteTellGrain",
					ReturnProbe: "uprobe_remoteTellGrain_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteAskGrain",
					EntryProbe:  "uprobe_remoteAskGrain",
					ReturnProbe: "uprobe_remoteAskGrain_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteLookupHandler",
					EntryProbe:  "uprobe_remoteLookupHandler",
					ReturnProbe: "uprobe_remoteLookupHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteReSpawnHandler",
					EntryProbe:  "uprobe_remoteReSpawnHandler",
					ReturnProbe: "uprobe_remoteReSpawnHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteStopHandler",
					EntryProbe:  "uprobe_remoteStopHandler",
					ReturnProbe: "uprobe_remoteStopHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteAskGrainHandler",
					EntryProbe:  "uprobe_remoteAskGrainHandler",
					ReturnProbe: "uprobe_remoteAskGrainHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteTellGrainHandler",
					EntryProbe:  "uprobe_remoteTellGrainHandler",
					ReturnProbe: "uprobe_remoteTellGrainHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteActivateGrainHandler",
					EntryProbe:  "uprobe_remoteActivateGrainHandler",
					ReturnProbe: "uprobe_remoteActivateGrainHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteReinstateHandler",
					EntryProbe:  "uprobe_remoteReinstateHandler",
					ReturnProbe: "uprobe_remoteReinstateHandler_Returns",
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remotePassivationStrategyHandler",
					EntryProbe:  "uprobe_remotePassivationStrategyHandler",
					ReturnProbe: "uprobe_remotePassivationStrategyHandler_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteStateHandler",
					EntryProbe:  "uprobe_remoteStateHandler",
					ReturnProbe: "uprobe_remoteStateHandler_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteChildrenHandler",
					EntryProbe:  "uprobe_remoteChildrenHandler",
					ReturnProbe: "uprobe_remoteChildrenHandler_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteParentHandler",
					EntryProbe:  "uprobe_remoteParentHandler",
					ReturnProbe: "uprobe_remoteParentHandler_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteKindHandler",
					EntryProbe:  "uprobe_remoteKindHandler",
					ReturnProbe: "uprobe_remoteKindHandler_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteDependenciesHandler",
					EntryProbe:  "uprobe_remoteDependenciesHandler",
					ReturnProbe: "uprobe_remoteDependenciesHandler_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteMetricHandler",
					EntryProbe:  "uprobe_remoteMetricHandler",
					ReturnProbe: "uprobe_remoteMetricHandler_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteRoleHandler",
					EntryProbe:  "uprobe_remoteRoleHandler",
					ReturnProbe: "uprobe_remoteRoleHandler_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*actorSystem).remoteStashSizeHandler",
					EntryProbe:  "uprobe_remoteStashSizeHandler",
					ReturnProbe: "uprobe_remoteStashSizeHandler_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*relocator).Relocate",
					EntryProbe:  "uprobe_Relocate",
					ReturnProbe: "uprobe_Relocate_Returns",
					FailureMode: probe.FailureModeWarn,
				},
				{
					Sym:         "github.com/tochemey/goakt/v4/actor.(*PID).handleReceivedError",
					EntryProbe:  "uprobe_handleReceivedError",
					FailureMode: probe.FailureModeWarn, // Symbol may not exist in all GoAkt versions
				},
			},
			SpecFn: loadBpf,
		},
		Version:   version,
		SchemaURL: semconv.SchemaURL,
		ProcessFn: processFn,
	}
}

// makeProcessFn returns a processFn that uses userspace context reading when
// targetPID > 0. It buffers process/grainProcess events whose BPF parent
// (doReceive) has not yet been processed — since process() is an inner call
// that returns before doReceive(), its event always arrives first. When the
// parent doReceive event arrives and resolves the app-level TraceID via
// userspace extraction, the buffered child is fixed up and emitted together.
func makeProcessFn(logger *slog.Logger, targetPID int) func(*event) ptrace.SpanSlice {
	pending := make(map[pcommon.SpanID]event) // BPF parent SpanID → buffered child
	const maxPending = 256

	return func(e *event) ptrace.SpanSlice {
		if isProcessWithBPFParent(e) {
			if len(pending) >= maxPending {
				clear(pending)
			}
			pending[pcommon.SpanID(e.ParentSpanContext.SpanID)] = *e
			return ptrace.NewSpanSlice()
		}

		spans := processEvent(e, logger, targetPID)

		if len(pending) > 0 {
			myID := pcommon.SpanID(e.SpanContext.SpanID)
			if pe, ok := pending[myID]; ok {
				child := processEvent(&pe, logger, targetPID)
				if child.Len() > 0 && spans.Len() > 0 {
					child.At(0).SetTraceID(spans.At(0).TraceID())
					child.MoveAndAppendTo(spans)
				}
				delete(pending, myID)
			}
		}

		return spans
	}
}

// isProcessWithBPFParent reports whether the event is a contextless process
// span (context_pos=0) that obtained its parent from the BPF goid map.
func isProcessWithBPFParent(e *event) bool {
	return (e.EventType == eventTypeProcess || e.EventType == eventTypeGrainProcess) &&
		e.ParentSpanContext.SpanID.IsValid() &&
		e.ContextPtr == 0
}

// event represents an instrumentation event (layout must match C struct goakt_actor_span_t).
type event struct {
	EventType           uint8
	HandledSuccessfully uint8
	_                   [6]byte // padding for alignment
	context.BaseSpanProperties
	ContextPtr uint64 // context.Context data pointer for userspace trace extraction (0 when N/A)
}

// baseAttrs is shared to avoid per-span allocation.
var baseAttrs = []attribute.KeyValue{attribute.String("messaging.system", "goakt")}

var extractParentSpanFromContext = process.ExtractSpanContextFromContext

func processEvent(e *event, logger *slog.Logger, targetPID int) ptrace.SpanSlice {
	spans := ptrace.NewSpanSlice()
	span := spans.AppendEmpty()

	span.SetStartTimestamp(kernel.BootOffsetToTimestamp(e.StartTime))
	span.SetEndTimestamp(kernel.BootOffsetToTimestamp(e.EndTime))
	span.SetTraceID(pcommon.TraceID(e.SpanContext.TraceID))
	span.SetSpanID(pcommon.SpanID(e.SpanContext.SpanID))
	span.SetFlags(uint32(trace.FlagsSampled))

	if e.ParentSpanContext.SpanID.IsValid() {
		span.SetParentSpanID(pcommon.SpanID(e.ParentSpanContext.SpanID))
	} else if targetPID > 0 && e.ContextPtr != 0 {
		if psc := extractParentSpanFromContext(targetPID, e.ContextPtr, logger); psc != nil {
			span.SetParentSpanID(pcommon.SpanID(psc.SpanID()))
			span.SetTraceID(pcommon.TraceID(psc.TraceID()))
		}
	}

	ts := eventTimestamps{
		sent:     kernel.BootOffsetToTimestamp(e.StartTime),
		received: kernel.BootOffsetToTimestamp(e.StartTime),
		handled:  kernel.BootOffsetToTimestamp(e.EndTime),
		success:  e.HandledSuccessfully != 0,
	}

	switch {
	case applyLocalSpan(e.EventType, span, ts):
	case applySpawnSpan(e.EventType, span):
	case applyRemoteSpan(e.EventType, span, ts):
	default:
		span.SetName("actor.unknown")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), baseAttrs...)
	}

	return spans
}

type eventTimestamps struct {
	sent, received, handled pcommon.Timestamp
	success                 bool
}

// applyLocalSpan handles local actor messaging and processing spans.
// Returns true if the event type was handled.
func applyLocalSpan(et uint8, span ptrace.Span, ts eventTimestamps) bool {
	switch et {
	case eventTypeDoReceive:
		span.SetName("actor.doReceive")
		span.SetKind(ptrace.SpanKindConsumer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
			attribute.Int64("messaging.message.handled_timestamp", int64(ts.handled)),
			attribute.Bool("messaging.message.handled_successfully", ts.success),
		)...)
	case eventTypeGrainDoReceive:
		span.SetName("grain.doReceive")
		span.SetKind(ptrace.SpanKindConsumer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
			attribute.Int64("messaging.message.handled_timestamp", int64(ts.handled)),
			attribute.Bool("messaging.message.handled_successfully", ts.success),
		)...)
	case eventTypeProcess:
		span.SetName("actor.process")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.type", "pid"))...)
	case eventTypeGrainProcess:
		span.SetName("grain.process")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.type", "grain"))...)
	case eventTypeRelocation:
		span.SetName("actor.relocation")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "relocation"))...)
	case eventTypeActorOf:
		span.SetName("actorSystem.actorOf")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "actor_of"))...)
	case eventTypeKill:
		span.SetName("actorSystem.kill")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "kill"))...)
	case eventTypeReSpawn:
		span.SetName("actorSystem.reSpawn")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "respawn"))...)
	case eventTypeActorExists:
		span.SetName("actorSystem.actorExists")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "actor_exists"))...)
	case eventTypeSystemMetric:
		span.SetName("actorSystem.metric")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "system_metric"))...)
	case eventTypeActors:
		span.SetName("actorSystem.actors")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "actors"))...)
	case eventTypeStart:
		span.SetName("actorSystem.start")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "start"))...)
	case eventTypeStop:
		span.SetName("actorSystem.stop")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "stop"))...)
	case eventTypeScheduleOnce:
		span.SetName("actorSystem.scheduleOnce")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "schedule_once"))...)
	case eventTypeSchedule:
		span.SetName("actorSystem.schedule")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "schedule"))...)
	case eventTypeScheduleWithCron:
		span.SetName("actorSystem.scheduleWithCron")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "schedule_with_cron"))...)
	case eventTypeSendAsync:
		span.SetName("actor.sendAsync")
		span.SetKind(ptrace.SpanKindProducer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "send"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeSendSync:
		span.SetName("actor.sendSync")
		span.SetKind(ptrace.SpanKindClient)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "request"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeDiscoverActor:
		span.SetName("actor.discoverActor")
		span.SetKind(ptrace.SpanKindClient)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "discover_actor"))...)
	case eventTypePIDStop:
		span.SetName("actor.stop")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "stop"))...)
	case eventTypeRestart:
		span.SetName("actor.restart")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "restart"))...)
	case eventTypePIDMetric:
		span.SetName("actor.metric")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "metric"))...)
	case eventTypeReinstateNamed:
		span.SetName("actor.reinstateNamed")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "reinstate_named"))...)
	case eventTypePipeTo:
		span.SetName("actor.pipeTo")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "pipe_to"))...)
	case eventTypePipeToName:
		span.SetName("actor.pipeToName")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "pipe_to_name"))...)
	case eventTypeShutdown:
		span.SetName("actor.shutdown")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "shutdown"))...)
	default:
		return false
	}
	return true
}

// applySpawnSpan handles spawn lifecycle spans (local and remote placement).
// Returns true if the event type was handled.
func applySpawnSpan(et uint8, span ptrace.Span) bool {
	type spawnDef struct {
		name string
		kind ptrace.SpanKind
		op   string
	}
	defs := map[uint8]spawnDef{
		eventTypeSystemSpawn:        {"actorSystem.spawn", ptrace.SpanKindInternal, "spawn"},
		eventTypeSpawnOn:            {"actorSystem.spawnOn", ptrace.SpanKindClient, "spawn_on"},
		eventTypeSpawnChild:         {"actor.spawnChild", ptrace.SpanKindInternal, "spawn_child"},
		eventTypeRemoteSpawn:        {"actorSystem.remoteSpawn", ptrace.SpanKindServer, "remote_spawn"},
		eventTypeRemoteSpawnChild:   {"actorSystem.remoteSpawnChild", ptrace.SpanKindServer, "remote_spawn_child"},
		eventTypeSpawnNamedFromFunc: {"actorSystem.spawnNamedFromFunc", ptrace.SpanKindInternal, "spawn_named_from_func"},
		eventTypeSpawnFromFunc:      {"actorSystem.spawnFromFunc", ptrace.SpanKindInternal, "spawn_from_func"},
		eventTypeSpawnRouter:        {"actorSystem.spawnRouter", ptrace.SpanKindInternal, "spawn_router"},
		eventTypeSpawnSingleton:     {"actorSystem.spawnSingleton", ptrace.SpanKindInternal, "spawn_singleton"},
	}
	d, ok := defs[et]
	if !ok {
		return false
	}
	span.SetName(d.name)
	span.SetKind(d.kind)
	pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", d.op))...)
	return true
}

// applyRemoteSpan handles remote messaging and inspection handler spans.
// Returns true if the event type was handled.
func applyRemoteSpan(et uint8, span ptrace.Span, ts eventTimestamps) bool { //nolint:cyclop
	switch et {
	case eventTypeRemoteTell:
		span.SetName("actorSystem.remoteTell")
		span.SetKind(ptrace.SpanKindProducer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "send"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeRemoteAsk:
		span.SetName("actorSystem.remoteAsk")
		span.SetKind(ptrace.SpanKindClient)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "request"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeRemoteTellReceive:
		span.SetName("actorSystem.remoteTellReceive")
		span.SetKind(ptrace.SpanKindConsumer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
		)...)
	case eventTypeRemoteAskReceive:
		span.SetName("actorSystem.remoteAskReceive")
		span.SetKind(ptrace.SpanKindServer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
		)...)
	case eventTypeRemoteTellGrain:
		span.SetName("grain.remoteTell")
		span.SetKind(ptrace.SpanKindProducer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "send"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeRemoteAskGrain:
		span.SetName("grain.remoteAsk")
		span.SetKind(ptrace.SpanKindClient)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "request"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeRemoteAskGrainReceive:
		span.SetName("grain.remoteAskReceive")
		span.SetKind(ptrace.SpanKindServer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
		)...)
	case eventTypeRemoteTellGrainReceive:
		span.SetName("grain.remoteTellReceive")
		span.SetKind(ptrace.SpanKindConsumer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
		)...)
	case eventTypeTell:
		span.SetName("actor.tell")
		span.SetKind(ptrace.SpanKindProducer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "send"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeAsk:
		span.SetName("actor.ask")
		span.SetKind(ptrace.SpanKindClient)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "request"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeBatchTell:
		span.SetName("actor.batchTell")
		span.SetKind(ptrace.SpanKindProducer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "send"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeBatchAsk:
		span.SetName("actor.batchAsk")
		span.SetKind(ptrace.SpanKindClient)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "request"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	default:
		return applyRemoteOpSpan(et, span)
	}
	return true
}

// applyRemoteOpSpan handles remote operation handler spans (lookup, stop, inspect, etc.).
// Returns true if the event type was handled.
func applyRemoteOpSpan(et uint8, span ptrace.Span) bool {
	type opDef struct {
		name string
		op   string
	}
	defs := map[uint8]opDef{
		eventTypeRemoteLookup:              {"actorSystem.remoteLookup", "remote_lookup"},
		eventTypeRemoteReSpawn:             {"actorSystem.remoteReSpawn", "remote_respawn"},
		eventTypeRemoteStop:                {"actorSystem.remoteStop", "remote_stop"},
		eventTypeRemoteActivateGrain:       {"grain.remoteActivate", "remote_activate_grain"},
		eventTypeRemoteReinstate:           {"actorSystem.remoteReinstate", "remote_reinstate"},
		eventTypeRemotePassivationStrategy: {"actorSystem.remotePassivationStrategy", "remote_passivation_strategy"},
		eventTypeRemoteState:               {"actorSystem.remoteState", "remote_state"},
		eventTypeRemoteChildren:            {"actorSystem.remoteChildren", "remote_children"},
		eventTypeRemoteParent:              {"actorSystem.remoteParent", "remote_parent"},
		eventTypeRemoteKind:                {"actorSystem.remoteKind", "remote_kind"},
		eventTypeRemoteDependencies:        {"actorSystem.remoteDependencies", "remote_dependencies"},
		eventTypeRemoteMetric:              {"actorSystem.remoteMetric", "remote_metric"},
		eventTypeRemoteRole:                {"actorSystem.remoteRole", "remote_role"},
		eventTypeRemoteStashSize:           {"actorSystem.remoteStashSize", "remote_stash_size"},
		eventTypePIDRemoteLookup:           {"actor.remoteLookup", "remote_lookup"},
		eventTypePIDRemoteStop:             {"actor.remoteStop", "remote_stop"},
		eventTypePIDRemoteReSpawn:          {"actor.remoteReSpawn", "remote_respawn"},
	}
	d, ok := defs[et]
	if !ok {
		return false
	}
	span.SetName(d.name)
	span.SetKind(ptrace.SpanKindServer)
	pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", d.op))...)
	return true
}
