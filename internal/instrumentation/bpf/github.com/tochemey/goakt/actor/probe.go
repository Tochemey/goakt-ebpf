// Copyright (c) 2025 The GoAkt eBPF Authors.
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
	eventTypeDoReceive      = 1
	eventTypeRemoteTell     = 2
	eventTypeRemoteAsk      = 3
	eventTypeProcess        = 4
	eventTypeGrainProcess   = 5
	eventTypeGrainDoReceive = 6
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
	default:
		span.SetName("actor.unknown")
		span.SetKind(ptrace.SpanKindInternal)
		pdataconv.Attributes(span.Attributes(), baseAttrs...)
	}

	return spans
}
