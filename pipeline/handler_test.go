// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

package pipeline

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestHandlerWithScope(t *testing.T) {
	h := Handler{}
	scope := pcommon.NewInstrumentationScope()
	scope.SetName("test")
	scope.SetVersion("v1")
	const schemaURL = "http://example.com/schema"

	got := h.WithScope(scope, schemaURL)
	assert.Equal(t, schemaURL, got.schemaURL)
	assert.Nil(t, got.TraceHandler)
	assert.Nil(t, got.MetricHandler)
	assert.Nil(t, got.LogHandler)
}

func TestHandlerTraceNilHandler(t *testing.T) {
	h := Handler{TraceHandler: nil}
	spans := ptrace.NewSpanSlice()
	span := spans.AppendEmpty()
	span.SetName("test")
	// Should not panic - drops spans when TraceHandler is nil
	h.Trace(spans)
}

func TestHandlerMetricNilHandler(t *testing.T) {
	h := Handler{MetricHandler: nil}
	metrics := pmetric.NewMetricSlice()
	// Should not panic - drops metrics when MetricHandler is nil
	h.Metric(metrics)
}

func TestHandlerLogNilHandler(t *testing.T) {
	h := Handler{LogHandler: nil}
	logs := plog.NewLogRecordSlice()
	// Should not panic - drops logs when LogHandler is nil
	h.Log(logs)
}

func TestHandlerShutdownNilTraceHandler(t *testing.T) {
	h := &Handler{TraceHandler: nil}
	err := h.Shutdown(context.Background())
	assert.NoError(t, err)
}

type noopTraceHandler struct{}

func (noopTraceHandler) HandleTrace(_ pcommon.InstrumentationScope, _ string, _ ptrace.SpanSlice) {}

type shutdownTraceHandler struct {
	noopTraceHandler
	shutdownErr error
}

func (h *shutdownTraceHandler) Shutdown(ctx context.Context) error {
	return h.shutdownErr
}

func TestHandlerShutdownWithShutdownHandler(t *testing.T) {
	wantErr := context.Canceled
	th := &shutdownTraceHandler{shutdownErr: wantErr}
	h := &Handler{TraceHandler: th}
	err := h.Shutdown(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, wantErr)
}

func TestHandlerShutdownWithNonShutdownHandler(t *testing.T) {
	th := noopTraceHandler{}
	h := &Handler{TraceHandler: th}
	err := h.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestHandlerTraceWithHandler(t *testing.T) {
	called := false
	th := &captureTraceHandler{fn: func(_ pcommon.InstrumentationScope, url string, spans ptrace.SpanSlice) {
		called = true
		assert.Equal(t, "http://test/schema", url)
		assert.Equal(t, 1, spans.Len())
	}}
	h := Handler{TraceHandler: th}.WithScope(pcommon.NewInstrumentationScope(), "http://test/schema")
	spans := ptrace.NewSpanSlice()
	spans.AppendEmpty().SetName("test")
	h.Trace(spans)
	assert.True(t, called)
}

func TestHandlerMetricWithHandler(t *testing.T) {
	called := false
	mh := &captureMetricHandler{fn: func(_ pcommon.InstrumentationScope, _ string, metrics pmetric.MetricSlice) {
		called = true
		assert.Equal(t, 1, metrics.Len())
	}}
	h := Handler{MetricHandler: mh}.WithScope(pcommon.NewInstrumentationScope(), "")
	metrics := pmetric.NewMetricSlice()
	metrics.AppendEmpty().SetName("test")
	h.Metric(metrics)
	assert.True(t, called)
}

func TestHandlerLogWithHandler(t *testing.T) {
	called := false
	lh := &captureLogHandler{fn: func(_ pcommon.InstrumentationScope, _ string, logs plog.LogRecordSlice) {
		called = true
		assert.Equal(t, 1, logs.Len())
	}}
	h := Handler{LogHandler: lh}.WithScope(pcommon.NewInstrumentationScope(), "")
	logs := plog.NewLogRecordSlice()
	logs.AppendEmpty().Body().SetStr("test")
	h.Log(logs)
	assert.True(t, called)
}

type captureTraceHandler struct {
	fn func(pcommon.InstrumentationScope, string, ptrace.SpanSlice)
}

func (h *captureTraceHandler) HandleTrace(scope pcommon.InstrumentationScope, url string, spans ptrace.SpanSlice) {
	h.fn(scope, url, spans)
}

type captureMetricHandler struct {
	fn func(pcommon.InstrumentationScope, string, pmetric.MetricSlice)
}

func (h *captureMetricHandler) HandleMetric(scope pcommon.InstrumentationScope, url string, metrics pmetric.MetricSlice) {
	h.fn(scope, url, metrics)
}

type captureLogHandler struct {
	fn func(pcommon.InstrumentationScope, string, plog.LogRecordSlice)
}

func (h *captureLogHandler) HandleLog(scope pcommon.InstrumentationScope, url string, logs plog.LogRecordSlice) {
	h.fn(scope, url, logs)
}
