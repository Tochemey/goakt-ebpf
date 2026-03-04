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
// OTEL stores a nonRecordingSpan in the context via ContextWithSpan:
//
//	trace.nonRecordingSpan {
//	    noopSpan {
//	        embedded.Span  // interface: {itab, data} = 16 bytes (nil when constructed)
//	    }
//	    sc SpanContext {
//	        traceID    [16]byte  // offset 16 from nonRecordingSpan start
//	        spanID     [8]byte   // offset 32
//	        traceFlags byte      // offset 40
//	        ...                  // traceState, remote (not needed)
//	    }
//	}

package process

import (
	"encoding/binary"
	"log/slog"
	"unsafe"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
)

const (
	ifaceSize     = 16 // size of a Go interface value (type/itab + data pointer)
	valueCtxSize  = 48 // parent(16) + key(16) + val(16)
	parentDataOff = 8  // offset of parent.data within any context struct (all embed Context first)
	valDataOff    = 40 // offset of val.data within valueCtx

	// nonRecordingSpan layout: noopSpan(16) + SpanContext fields
	nrsNoopSpanSize = 16 // size of embedded noopSpan (nil interface)
	scTraceIDOff    = nrsNoopSpanSize
	scTraceIDSize   = 16
	scSpanIDOff     = scTraceIDOff + scTraceIDSize // 32
	scSpanIDSize    = 8
	scFlagsOff      = scSpanIDOff + scSpanIDSize // 40
	nrsReadSize     = scFlagsOff + 1             // 41 bytes total from nonRecordingSpan start

	maxChainDepth = 32
)

// ExtractSpanContextFromContext reads the target process memory at ctxDataPtr,
// walks the Go context.Context chain (speculatively treating each node as a
// valueCtx), and returns the first valid OTEL span context found.
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
	nrsBuf := make([]byte, nrsReadSize)

	for depth := 0; depth < maxChainDepth; depth++ {
		if nodePtr == 0 {
			break
		}

		// Read 48 bytes from the current context node, treating it as a valueCtx.
		// For non-valueCtx types (cancelCtx, timerCtx) the bytes at valDataOff
		// will be unrelated data; the span context validation catches this.
		n, err := readRemote(pid, nodePtr, nodeBuf)
		if err != nil || n < valueCtxSize {
			break
		}

		valData := binary.LittleEndian.Uint64(nodeBuf[valDataOff:])
		if valData != 0 {
			sc := tryReadSpanContext(pid, valData, nrsBuf, logger)
			if sc != nil {
				return sc
			}
		}

		// Follow parent: data word of the Context interface (offset 8).
		nodePtr = binary.LittleEndian.Uint64(nodeBuf[parentDataOff:])
	}

	return nil
}

// tryReadSpanContext reads nrsReadSize bytes from addr in the target process,
// interprets the data as a nonRecordingSpan, and validates the span context.
func tryReadSpanContext(pid int, addr uint64, buf []byte, logger *slog.Logger) *trace.SpanContext {
	n, err := readRemote(pid, addr, buf[:nrsReadSize])
	if err != nil || n < nrsReadSize {
		return nil
	}

	// Heuristic: noopSpan embedded interface should be nil ({0, 0}).
	// This reduces false positives when the node is not a valueCtx.
	for i := 0; i < nrsNoopSpanSize; i++ {
		if buf[i] != 0 {
			return nil
		}
	}

	var traceID trace.TraceID
	copy(traceID[:], buf[scTraceIDOff:scTraceIDOff+scTraceIDSize])
	if !traceID.IsValid() {
		return nil
	}

	var spanID trace.SpanID
	copy(spanID[:], buf[scSpanIDOff:scSpanIDOff+scSpanIDSize])
	if !spanID.IsValid() {
		return nil
	}

	flags := trace.TraceFlags(buf[scFlagsOff])

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: flags,
		Remote:     true,
	})
	logger.Debug("extracted remote span context",
		"trace_id", traceID,
		"span_id", spanID,
		"flags", flags,
	)
	return &sc
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
