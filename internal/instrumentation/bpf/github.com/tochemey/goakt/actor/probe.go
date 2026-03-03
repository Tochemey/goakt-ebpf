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

	"github.com/tochemey/goakt-ebpf/internal/instrumentation/context"
	"github.com/tochemey/goakt-ebpf/internal/instrumentation/kernel"
	"github.com/tochemey/goakt-ebpf/internal/instrumentation/pdataconv"
	"github.com/tochemey/goakt-ebpf/internal/instrumentation/probe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf ./bpf/probe.bpf.c

const pkg = "github.com/tochemey/goakt/v4/actor"

// Event type constants (must match C EVENT_TYPE_*)
const (
	eventTypeDoReceive         = 1
	eventTypeRemoteTell        = 2
	eventTypeRemoteAsk         = 3
	eventTypeProcess           = 4
	eventTypeGrainProcess      = 5
	eventTypeGrainDoReceive    = 6
	eventTypeSystemSpawn       = 7
	eventTypeSpawnChild        = 8
	eventTypeRemoteSpawn       = 9
	eventTypeRemoteSpawnChild  = 10
	eventTypeRemoteTellReceive = 11
	eventTypeRemoteAskReceive  = 12
	eventTypeRelocation        = 13
)

// New returns a new [probe.Probe] for GoAkt actor instrumentation (all targets).
func New(logger *slog.Logger, version string) probe.Probe {
	id := probe.ID{
		SpanKind:        trace.SpanKindConsumer,
		InstrumentedPkg: pkg,
	}
	return &probe.SpanProducer[bpfObjects, event]{
		Base: probe.Base[bpfObjects, event]{
			ID:     id,
			Logger: logger,
			Consts: []probe.Const{},
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
					Sym:         "github.com/tochemey/goakt/v4/actor.(*relocator).Relocate",
					EntryProbe:  "uprobe_Relocate",
					ReturnProbe: "uprobe_Relocate_Returns",
					FailureMode: probe.FailureModeWarn, // relocator is unexported; may be absent in some builds
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

// event represents an instrumentation event (layout must match C struct goakt_actor_span_t).
type event struct {
	EventType           uint8
	HandledSuccessfully uint8
	_                   [6]byte // padding for alignment
	context.BaseSpanProperties
}

// baseAttrs is shared to avoid per-span allocation.
var baseAttrs = []attribute.KeyValue{attribute.String("messaging.system", "goakt")}

func processFn(e *event) ptrace.SpanSlice {
	spans := ptrace.NewSpanSlice()
	span := spans.AppendEmpty()

	span.SetStartTimestamp(kernel.BootOffsetToTimestamp(e.StartTime))
	span.SetEndTimestamp(kernel.BootOffsetToTimestamp(e.EndTime))
	span.SetTraceID(pcommon.TraceID(e.SpanContext.TraceID))
	span.SetSpanID(pcommon.SpanID(e.SpanContext.SpanID))
	span.SetFlags(uint32(trace.FlagsSampled))

	if e.ParentSpanContext.SpanID.IsValid() {
		span.SetParentSpanID(pcommon.SpanID(e.ParentSpanContext.SpanID))
	}

	// Timestamp and success attributes for messaging spans.
	// Future: add actor.sender.id, actor.receiver.id, actor.system.name via StructFieldConst
	// (requires DWARF offsets from ReceiveContext.sender, ReceiveContext.self, PID.path, path.system, path.name).
	sentTs := kernel.BootOffsetToTimestamp(e.StartTime)
	receivedTs := kernel.BootOffsetToTimestamp(e.StartTime)
	handledTs := kernel.BootOffsetToTimestamp(e.EndTime)

	switch e.EventType {
	case eventTypeDoReceive:
		span.SetName("actor.doReceive")
		span.SetKind(ptrace.SpanKindConsumer)
		attrs := append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.received_timestamp", int64(receivedTs)),
			attribute.Int64("messaging.message.handled_timestamp", int64(handledTs)),
			attribute.Bool("messaging.message.handled_successfully", e.HandledSuccessfully != 0),
		)
		pdataconv.Attributes(span.Attributes(), attrs...)
	case eventTypeRemoteTell:
		span.SetName("actor.remoteTell")
		span.SetKind(ptrace.SpanKindProducer)
		attrs := append(baseAttrs,
			attribute.String("messaging.operation", "send"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(sentTs)),
		)
		pdataconv.Attributes(span.Attributes(), attrs...)
	case eventTypeRemoteAsk:
		span.SetName("actor.remoteAsk")
		span.SetKind(ptrace.SpanKindClient)
		attrs := append(baseAttrs,
			attribute.String("messaging.operation", "request"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.sent_timestamp", int64(sentTs)),
		)
		pdataconv.Attributes(span.Attributes(), attrs...)
	case eventTypeProcess:
		span.SetName("actor.process")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.type", "pid"))...)
	case eventTypeGrainProcess:
		span.SetName("actor.grainProcess")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.type", "grain"))...)
	case eventTypeGrainDoReceive:
		span.SetName("actor.grainDoReceive")
		span.SetKind(ptrace.SpanKindConsumer)
		attrs := append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "grain"),
			attribute.Int64("messaging.message.received_timestamp", int64(receivedTs)),
			attribute.Int64("messaging.message.handled_timestamp", int64(handledTs)),
			attribute.Bool("messaging.message.handled_successfully", e.HandledSuccessfully != 0),
		)
		pdataconv.Attributes(span.Attributes(), attrs...)
	case eventTypeSystemSpawn:
		span.SetName("actor.systemSpawn")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "spawn"))...)
	case eventTypeSpawnChild:
		span.SetName("actor.spawnChild")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "spawn_child"))...)
	case eventTypeRemoteSpawn:
		span.SetName("actor.remoteSpawn")
		span.SetKind(ptrace.SpanKindServer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "remote_spawn"))...)
	case eventTypeRemoteSpawnChild:
		span.SetName("actor.remoteSpawnChild")
		span.SetKind(ptrace.SpanKindServer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "remote_spawn_child"))...)
	case eventTypeRemoteTellReceive:
		span.SetName("actor.remoteTellReceive")
		span.SetKind(ptrace.SpanKindConsumer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.received_timestamp", int64(receivedTs)),
		)...)
	case eventTypeRemoteAskReceive:
		span.SetName("actor.remoteAskReceive")
		span.SetKind(ptrace.SpanKindServer)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs,
			attribute.String("messaging.operation", "receive"),
			attribute.String("messaging.destination", "actor"),
			attribute.Int64("messaging.message.received_timestamp", int64(receivedTs)),
		)...)
	case eventTypeRelocation:
		span.SetName("actor.relocation")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), append(baseAttrs, attribute.String("actor.operation", "relocation"))...)
	default:
		span.SetName("actor.unknown")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), baseAttrs...)
	}

	return spans
}
