// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

package otelsdk

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestNewMultiplexer(t *testing.T) {
	ctx := context.Background()
	m, err := NewMultiplexer(ctx, WithServiceName("test-service"), WithLogger(slog.Default()))
	require.NoError(t, err)
	require.NotNil(t, m)
}

func TestMultiplexerHandler(t *testing.T) {
	ctx := context.Background()
	m, err := NewMultiplexer(ctx, WithServiceName("test-service"), WithLogger(slog.Default()))
	require.NoError(t, err)

	// Use pid 1 - on Linux /proc/1/exe exists; on macOS withProcResAttrs will fail
	// but WithLogger ensures we don't panic when logging the error
	handler := m.Handler(1)
	require.NotNil(t, handler)
	assert.NotNil(t, handler.TraceHandler)
}

func TestMultiplexerShutdown(t *testing.T) {
	ctx := context.Background()
	m, err := NewMultiplexer(ctx, WithServiceName("test-service"), WithLogger(slog.Default()))
	require.NoError(t, err)

	err = m.Shutdown(ctx)
	assert.NoError(t, err)

	// Handler after shutdown should still work (returns handler in shutdown state)
	handler := m.Handler(1)
	require.NotNil(t, handler)
	assert.NotNil(t, handler.TraceHandler)
	// TraceHandler may be a no-op after shutdown - just verify we get a handler
	_ = handler
}

func TestMultiplexerHandlerTraceDropsAfterShutdown(t *testing.T) {
	ctx := context.Background()
	m, err := NewMultiplexer(ctx, WithServiceName("test-service"), WithLogger(slog.Default()))
	require.NoError(t, err)

	require.NoError(t, m.Shutdown(ctx))

	handler := m.Handler(1)
	// HandleTrace on shutdown handler should not panic - it drops telemetry
	if handler.TraceHandler != nil {
		handler.TraceHandler.HandleTrace(
			pcommon.NewInstrumentationScope(),
			"",
			ptrace.NewSpanSlice(),
		)
	}
}
