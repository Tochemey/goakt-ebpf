// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0
//
// GoAkt-specific context extraction constants, injected at load time.

#ifndef _GOAKT_CONTEXT_H_
#define _GOAKT_CONTEXT_H_

#include "bpf_helpers.h"

// Offset of Context field in ReceiveContext struct. Injected from DWARF.
volatile const u64 receive_context_ctx_offset;

// Offset of ctx field in GrainContext struct. Injected from DWARF. Distinct
// from ReceiveContext even though the two currently coincide.
volatile const u64 grain_context_ctx_offset;

// Go runtime type addresses in the target, injected from DWARF (0 when the
// binary lacks the type). The app span context walk uses them to identify
// each context node and value by its real type.
volatile const u64 ctx_type_value;          // *context.valueCtx
volatile const u64 ctx_type_cancel;         // *context.cancelCtx
volatile const u64 ctx_type_timer;          // *context.timerCtx
volatile const u64 ctx_type_after_func;     // *context.afterFuncCtx
volatile const u64 ctx_type_without_cancel; // context.withoutCancelCtx
volatile const u64 ctx_type_stop;           // context.stopCtx
volatile const u64 ctx_type_background;     // context.backgroundCtx
volatile const u64 ctx_type_todo;           // context.todoCtx
volatile const u64 otel_span_key_type;      // otel/trace.traceContextKeyType
volatile const u64 otel_span_type_recording;        // *otel/sdk/trace.recordingSpan
volatile const u64 otel_span_type_sdk_nonrecording; // otel/sdk/trace.nonRecordingSpan
volatile const u64 otel_span_type_api_nonrecording; // otel/trace.nonRecordingSpan

// Offset of the span's own SpanContext in each OTel span type, injected from
// DWARF (0 when the binary lacks the type, which no real offset is).
volatile const u64 otel_recording_span_sc_offset;        // recordingSpan.spanContext
volatile const u64 otel_sdk_nonrecording_span_sc_offset; // sdk nonRecordingSpan.sc
volatile const u64 otel_api_nonrecording_span_sc_offset; // trace nonRecordingSpan.sc

#endif
