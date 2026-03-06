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
		span.SetName("actor.grainDoReceive")
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
		span.SetName("actor.grainProcess")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.type", "grain"))...)
	case eventTypeRelocation:
		span.SetName("actor.relocation")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "relocation"))...)
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
		eventTypeSystemSpawn:      {"actor.systemSpawn", ptrace.SpanKindInternal, "spawn"},
		eventTypeSpawnOn:          {"actor.spawnOn", ptrace.SpanKindClient, "spawn_on"},
		eventTypeSpawnChild:       {"actor.spawnChild", ptrace.SpanKindInternal, "spawn_child"},
		eventTypeRemoteSpawn:      {"actor.remoteSpawn", ptrace.SpanKindServer, "remote_spawn"},
		eventTypeRemoteSpawnChild: {"actor.remoteSpawnChild", ptrace.SpanKindServer, "remote_spawn_child"},
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
		span.SetName("actor.remoteTell")
		span.SetKind(ptrace.SpanKindProducer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "send"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeRemoteAsk:
		span.SetName("actor.remoteAsk")
		span.SetKind(ptrace.SpanKindClient)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "request"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeRemoteTellReceive:
		span.SetName("actor.remoteTellReceive")
		span.SetKind(ptrace.SpanKindConsumer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
		)...)
	case eventTypeRemoteAskReceive:
		span.SetName("actor.remoteAskReceive")
		span.SetKind(ptrace.SpanKindServer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
		)...)
	case eventTypeRemoteTellGrain:
		span.SetName("actor.remoteTellGrain")
		span.SetKind(ptrace.SpanKindProducer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "send"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeRemoteAskGrain:
		span.SetName("actor.remoteAskGrain")
		span.SetKind(ptrace.SpanKindClient)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "request"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.sent_timestamp", int64(ts.sent)),
		)...)
	case eventTypeRemoteAskGrainReceive:
		span.SetName("actor.remoteAskGrainReceive")
		span.SetKind(ptrace.SpanKindServer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
		)...)
	case eventTypeRemoteTellGrainReceive:
		span.SetName("actor.remoteTellGrainReceive")
		span.SetKind(ptrace.SpanKindConsumer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.received_timestamp", int64(ts.received)),
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
		eventTypeRemoteLookup:              {"actor.remoteLookup", "remote_lookup"},
		eventTypeRemoteReSpawn:             {"actor.remoteReSpawn", "remote_respawn"},
		eventTypeRemoteStop:                {"actor.remoteStop", "remote_stop"},
		eventTypeRemoteActivateGrain:       {"actor.remoteActivateGrain", "remote_activate_grain"},
		eventTypeRemoteReinstate:           {"actor.remoteReinstate", "remote_reinstate"},
		eventTypeRemotePassivationStrategy: {"actor.remotePassivationStrategy", "remote_passivation_strategy"},
		eventTypeRemoteState:               {"actor.remoteState", "remote_state"},
		eventTypeRemoteChildren:            {"actor.remoteChildren", "remote_children"},
		eventTypeRemoteParent:              {"actor.remoteParent", "remote_parent"},
		eventTypeRemoteKind:                {"actor.remoteKind", "remote_kind"},
		eventTypeRemoteDependencies:        {"actor.remoteDependencies", "remote_dependencies"},
		eventTypeRemoteMetric:              {"actor.remoteMetric", "remote_metric"},
		eventTypeRemoteRole:                {"actor.remoteRole", "remote_role"},
		eventTypeRemoteStashSize:           {"actor.remoteStashSize", "remote_stash_size"},
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
