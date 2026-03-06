//go:build linux

// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Userspace context reader for remote trace propagation.
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
	parentDataOff  = 8
	valDataOff     = 40
	parentReadSize = 16
	ptrReadSize    = 8
	spanReadSize   = 256

	layoutATraceIDOff = 16
	layoutASpanIDOff  = 32
	layoutAFlagsOff   = 40

	layoutBTracerPtrOff = 16
	layoutBTraceIDOff   = 24
	layoutBSpanIDOff    = 40
	layoutBFlagsOff     = 48

	layoutCTraceIDOff = 192
	layoutCSpanIDOff  = 208
	layoutCFlagsOff   = 216

	traceIDSize   = 16
	spanIDSize    = 8
	maxChainDepth = 32
)

var debugContextReader = os.Getenv("GOAKT_EBPF_DEBUG_CONTEXT_READER") == "1"

func ExtractSpanContextFromContext(pid int, ctxDataPtr uint64, logger *slog.Logger) *trace.SpanContext {
	if pid <= 0 || ctxDataPtr == 0 {
		return nil
	}

	nodePtr := ctxDataPtr
	// Keep buffers on stack to avoid per-event heap allocations and GC churn.
	var parentBuf [parentReadSize]byte
	var valBuf [ptrReadSize]byte
	var spanBuf [spanReadSize]byte

	for depth := 0; depth < maxChainDepth; depth++ {
		if nodePtr == 0 {
			if debugContextReader {
				logger.Debug("context walk exhausted with no parent span",
					"nodes_visited", depth,
				)
			}
			break
		}

		n, err := readRemote(pid, nodePtr, parentBuf[:])
		if err != nil || n < parentReadSize {
			if debugContextReader {
				logger.Debug("context walk stopped: remote read failed",
					"nodes_visited", depth,
					"error", err,
				)
			}
			break
		}

		parentPtr := binary.LittleEndian.Uint64(parentBuf[parentDataOff:])

		// valueCtx keeps the value pointer at +40. Read it independently so
		// traversal can continue even when the concrete context node is not
		// valueCtx-sized.
		valData := uint64(0)
		n, err = readRemote(pid, nodePtr+valDataOff, valBuf[:])
		if err == nil && n >= ptrReadSize {
			valData = binary.LittleEndian.Uint64(valBuf[:])
		}

		if valData != 0 {
			sc := tryReadSpanContext(pid, valData, spanBuf[:], logger)
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

		nodePtr = parentPtr
	}

	return nil
}

func tryReadSpanContext(pid int, addr uint64, buf []byte, logger *slog.Logger) *trace.SpanContext {
	n, err := readRemote(pid, addr, buf[:spanReadSize])
	if err != nil || n < spanReadSize {
		return nil
	}

	// Try Layout C (recordingSpan) first — most common for otelhttp/otelgrpc.
	// Do not require buf[16:24] (mutex) to be zero: when the span is in use,
	// the mutex can be locked, causing the previous heuristic to fail and
	// incorrectly fall through to Layout A (wrong offsets).
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

	if !isZero(buf[0:16]) {
		return nil
	}

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

func extractSpanContext(buf []byte, traceIDOff, spanIDOff, flagsOff int) *trace.SpanContext {
	if flagsOff+1 > len(buf) || spanIDOff+spanIDSize > len(buf) || traceIDOff+traceIDSize > len(buf) {
		return nil
	}

	flags := trace.TraceFlags(buf[flagsOff])

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

func isZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func readRemote(pid int, addr uint64, buf []byte) (int, error) {
	remote := []unix.RemoteIovec{
		{Base: uintptr(addr), Len: len(buf)},
	}
	local := []unix.Iovec{
		{Base: (*byte)(unsafe.Pointer(&buf[0])), Len: uint64(len(buf))},
	}
	return unix.ProcessVMReadv(pid, local, remote, 0)
}
