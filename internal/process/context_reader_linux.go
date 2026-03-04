//go:build linux

// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Userspace context reader for remote trace propagation.
//
// Reads Go context.Context chain from target process memory via process_vm_readv
// to extract OpenTelemetry span context (trace_id, span_id) from remote messages.
//
// Memory layout (Go 64-bit):
//
//	context.valueCtx {
//	    Context  context.Context  // interface: {itab, data} = 16 bytes
//	    key      any              // interface: {type, data} = 16 bytes
//	    val      any              // interface: {type, data} = 16 bytes
//	}                            // total: 48 bytes
//
// Four concrete span struct layouts are recognized (amd64/arm64, validated
// against go.opentelemetry.io/otel v1.41.0 and go.opentelemetry.io/auto/sdk v1.2.1):
//
// Layout A — trace.nonRecordingSpan (go.opentelemetry.io/otel/trace):
//
//	offset  0  size 16   noopSpan (embedded.Span interface, always zero)
//	offset 16  size 64   sc trace.SpanContext
//	  └─ offset 16  TraceID [16]byte
//	  └─ offset 32  SpanID  [8]byte
//	  └─ offset 40  TraceFlags byte
//
//	Appears when: trace.ContextWithSpanContext(ctx, sc) — W3C/B3 remote propagation.
//	Heuristic: bytes [0:16] == zero; bytes [16:24] non-zero (TraceID starts here).
//
// Layout B — sdk/trace.nonRecordingSpan (go.opentelemetry.io/otel/sdk/trace, not-sampled):
//
//	offset  0  size 16   embedded.Span (always zero)
//	offset 16  size  8   tracer *tracer (non-zero pointer)
//	offset 24  size 64   sc trace.SpanContext
//	  └─ offset 24  TraceID [16]byte
//	  └─ offset 40  SpanID  [8]byte
//	  └─ offset 48  TraceFlags byte
//
//	Appears when: tracer.Start(ctx, "name") with NeverSample TracerProvider.
//	Heuristic: bytes [0:16] == zero; bytes [16:24] non-zero pointer; valid TraceID at 24.
//
// Layout C — *sdk/trace.recordingSpan (go.opentelemetry.io/otel/sdk/trace, sampled):
//
//	offset   0  size  16   embedded.Span (always zero)
//	offset  16  size   8   mu sync.Mutex (zero when unlocked)
//	offset  24  size  64   parent trace.SpanContext (caller's span — not the current span)
//	  ...
//	offset 192  size  64   spanContext trace.SpanContext (current span's own context)
//	  └─ offset 192  TraceID [16]byte
//	  └─ offset 208  SpanID  [8]byte
//	  └─ offset 216  TraceFlags byte
//
//	Appears when: tracer.Start(ctx, "name") with a sampled TracerProvider (otelhttp, otelgrpc, etc.).
//	Heuristic: bytes [0:24] == zero (embedded + unlocked mutex); valid TraceID at offset 192.
//
// Layout D — *auto/sdk.span (go.opentelemetry.io/auto/sdk):
//
//	Not supported via userspace context reader: spanContext is zero-initialized in
//	user-space (the eBPF instrumentation layer populates it). eBPF-level probes on
//	tracer.Start are required for parent-child correlation with the Auto SDK.
//
// Probe order: C (most common for HTTP/gRPC) → A (remote propagation) → B (not-sampled).
// Only sampled span contexts (TraceFlags & 0x01 != 0) are returned as parents.
//
// Set GOAKT_EBPF_DEBUG_CONTEXT_READER=1 to enable verbose per-node debug logging.
package process

import (
	"encoding/binary"
	"log/slog"
	"os"
	"unsafe"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
)

const (
	ifaceSize     = 16 // size of a Go interface value (type/itab + data pointer)
	valueCtxSize  = 48 // parent(16) + key(16) + val(16)
	parentDataOff = 8  // offset of parent.data within any context struct (all embed Context first)
	valDataOff    = 40 // offset of val.data within valueCtx

	// spanReadSize is the minimum bytes to read from each candidate span pointer.
	// Must cover Layout C's spanContext at offset 192+64 = 256.
	spanReadSize = 256

	// Layout A — trace.nonRecordingSpan (go.opentelemetry.io/otel/trace):
	// noopSpan[0:16] == zero; TraceID at 16; SpanID at 32; TraceFlags at 40.
	layoutATraceIDOff = 16
	layoutASpanIDOff  = 32
	layoutAFlagsOff   = 40

	// Layout B — sdk/trace.nonRecordingSpan (go.opentelemetry.io/otel/sdk/trace, not-sampled):
	// embedded[0:16] == zero; tracer ptr[16:24] non-zero; TraceID at 24; SpanID at 40; TraceFlags at 48.
	layoutBTracerPtrOff = 16
	layoutBTraceIDOff   = 24
	layoutBSpanIDOff    = 40
	layoutBFlagsOff     = 48

	// Layout C — *sdk/trace.recordingSpan (go.opentelemetry.io/otel/sdk/trace, sampled):
	// embedded[0:16] == zero; mutex[16:24] == zero (unlocked); spanContext.TraceID at 192.
	layoutCTraceIDOff = 192
	layoutCSpanIDOff  = 208
	layoutCFlagsOff   = 216

	traceIDSize   = 16
	spanIDSize    = 8
	maxChainDepth = 32
)

// debugContextReader is true when GOAKT_EBPF_DEBUG_CONTEXT_READER=1 is set.
var debugContextReader = os.Getenv("GOAKT_EBPF_DEBUG_CONTEXT_READER") == "1"

// ExtractSpanContextFromContext reads the target process memory at ctxDataPtr,
// walks the Go context.Context chain (speculatively treating each node as a
// valueCtx), and returns the first valid, sampled OTEL span context found.
//
// ctxDataPtr is the data pointer of a context.Context interface captured by
// the BPF probe. It points to the concrete context implementation in the
// target process.
//
// Returns nil when extraction fails or no valid span context is found.
func ExtractSpanContextFromContext(pid int, ctxDataPtr uint64, logger *slog.Logger) *trace.SpanContext {
	if pid <= 0 || ctxDataPtr == 0 {
		return nil
	}

	nodePtr := ctxDataPtr
	nodeBuf := make([]byte, valueCtxSize)
	spanBuf := make([]byte, spanReadSize)

	for depth := 0; depth < maxChainDepth; depth++ {
		if nodePtr == 0 {
			if debugContextReader {
				logger.Debug("context walk exhausted with no parent span",
					"nodes_visited", depth,
				)
			}
			break
		}

		// Read 48 bytes from the current context node, treating it as a valueCtx.
		// For non-valueCtx types (cancelCtx, timerCtx) the bytes at valDataOff
		// will be unrelated data; the span context validation catches this.
		n, err := readRemote(pid, nodePtr, nodeBuf)
		if err != nil || n < valueCtxSize {
			if debugContextReader {
				logger.Debug("context walk stopped: remote read failed",
					"nodes_visited", depth,
					"error", err,
				)
			}
			break
		}

		valData := binary.LittleEndian.Uint64(nodeBuf[valDataOff:])
		if valData != 0 {
			sc := tryReadSpanContext(pid, valData, spanBuf, logger)
			if sc != nil {
				if debugContextReader {
					logger.Debug("context walk complete: parent span found",
						"nodes_visited", depth+1,
						"trace_id", sc.TraceID(),
						"span_id", sc.SpanID(),
					)
				}
				return sc
			}
		}

		// Follow parent: data word of the Context interface (offset 8).
		nodePtr = binary.LittleEndian.Uint64(nodeBuf[parentDataOff:])
	}

	return nil
}

// tryReadSpanContext reads spanReadSize bytes from addr in the target process and
// attempts to decode a valid, sampled OTEL SpanContext using the empirically
// validated span struct layouts. Layouts are probed in order of likelihood:
//
//  1. Layout C (*sdk/trace.recordingSpan) — sampled spans from otelhttp, otelgrpc, manual Start
//  2. Layout A (trace.nonRecordingSpan)   — remote-propagated contexts (W3C/B3 propagators)
//  3. Layout B (sdk/trace.nonRecordingSpan) — not-sampled spans (NeverSample TracerProvider)
func tryReadSpanContext(pid int, addr uint64, buf []byte, logger *slog.Logger) *trace.SpanContext {
	n, err := readRemote(pid, addr, buf[:spanReadSize])
	if err != nil || n < spanReadSize {
		return nil
	}

	// Common guard: embedded.Span interface (bytes [0:16]) must be zero for all layouts.
	if !isZero(buf[0:16]) {
		return nil
	}

	// Layout C: *sdk/trace.recordingSpan (sampled — otelhttp, otelgrpc, manual tracer.Start).
	// Discriminator: bytes [16:24] == zero (unlocked mutex); TraceID at offset 192.
	if isZero(buf[16:24]) {
		if sc := extractSpanContext(buf, layoutCTraceIDOff, layoutCSpanIDOff, layoutCFlagsOff); sc != nil {
			if debugContextReader {
				logger.Debug("matched span layout C (sdk/trace.recordingSpan)",
					"trace_id", sc.TraceID(),
					"span_id", sc.SpanID(),
					"addr", addr,
				)
			}
			return sc
		}
	}

	// Layout A: trace.nonRecordingSpan (remote-propagated via ContextWithSpanContext).
	// Discriminator: bytes [0:16] == zero; TraceID starts at offset 16 (so bytes [16:24] are non-zero).
	// Only attempted when bytes [16:24] are non-zero — this naturally excludes Layout C data.
	if !isZero(buf[16:24]) {
		if sc := extractSpanContext(buf, layoutATraceIDOff, layoutASpanIDOff, layoutAFlagsOff); sc != nil {
			if debugContextReader {
				logger.Debug("matched span layout A (trace.nonRecordingSpan/API)",
					"trace_id", sc.TraceID(),
					"span_id", sc.SpanID(),
					"addr", addr,
				)
			}
			return sc
		}
	}

	// Layout B: sdk/trace.nonRecordingSpan (not-sampled, NeverSample TracerProvider).
	// Discriminator: bytes [16:24] non-zero (tracer pointer); TraceID at offset 24.
	// Attempted last; not-sampled spans have TraceFlags == 0 so extractSpanContext will
	// reject them (only sampled contexts pass the IsSampled guard).
	if binary.LittleEndian.Uint64(buf[layoutBTracerPtrOff:]) != 0 {
		if sc := extractSpanContext(buf, layoutBTraceIDOff, layoutBSpanIDOff, layoutBFlagsOff); sc != nil {
			if debugContextReader {
				logger.Debug("matched span layout B (sdk/trace.nonRecordingSpan)",
					"trace_id", sc.TraceID(),
					"span_id", sc.SpanID(),
					"addr", addr,
				)
			}
			return sc
		}
	}

	return nil
}

// extractSpanContext parses a SpanContext from buf at the given field offsets.
// It returns nil when either the TraceID or SpanID is invalid, or when the
// span is not sampled (TraceFlags & FlagsSampled == 0). Only sampled contexts
// are valid parents for goakt-ebpf spans.
func extractSpanContext(buf []byte, traceIDOff, spanIDOff, flagsOff int) *trace.SpanContext {
	if flagsOff+1 > len(buf) || spanIDOff+spanIDSize > len(buf) || traceIDOff+traceIDSize > len(buf) {
		return nil
	}

	flags := trace.TraceFlags(buf[flagsOff])
	if flags&trace.FlagsSampled == 0 {
		return nil
	}

	var traceID trace.TraceID
	copy(traceID[:], buf[traceIDOff:traceIDOff+traceIDSize])
	if !traceID.IsValid() {
		return nil
	}

	var spanID trace.SpanID
	copy(spanID[:], buf[spanIDOff:spanIDOff+spanIDSize])
	if !spanID.IsValid() {
		return nil
	}

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: flags,
		Remote:     true,
	})
	return &sc
}

// isZero reports whether all bytes in b are zero.
func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// readRemote reads len(buf) bytes from addr in the target process.
func readRemote(pid int, addr uint64, buf []byte) (int, error) {
	remote := []unix.RemoteIovec{
		{Base: uintptr(addr), Len: len(buf)},
	}
	local := []unix.Iovec{
		{Base: (*byte)(unsafe.Pointer(&buf[0])), Len: uint64(len(buf))},
	}
	return unix.ProcessVMReadv(pid, local, remote, 0)
}
