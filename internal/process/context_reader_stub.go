//go:build !linux

// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Stub for context reader on non-Linux (process_vm_readv is Linux-only).

package process

import (
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

// ExtractSpanContextFromContext is a no-op on non-Linux.
func ExtractSpanContextFromContext(_ int, _ uint64, _ *slog.Logger) *trace.SpanContext {
	return nil
}
