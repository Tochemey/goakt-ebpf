// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

package context

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace"
)

func TestBaseSpanProperties(t *testing.T) {
	props := BaseSpanProperties{
		StartTime:   1000,
		EndTime:     2000,
		SpanContext: EBPFSpanContext{TraceID: trace.TraceID{0x1}, SpanID: trace.SpanID{0x1}},
	}
	assert.Equal(t, uint64(1000), props.StartTime)
	assert.Equal(t, uint64(2000), props.EndTime)
	assert.Equal(t, trace.TraceID{0x1}, props.SpanContext.TraceID)
	assert.Equal(t, trace.SpanID{0x1}, props.SpanContext.SpanID)
}

func TestEBPFSpanContext(t *testing.T) {
	sc := EBPFSpanContext{
		TraceID:    trace.TraceID{0x1, 0x2},
		SpanID:     trace.SpanID{0x3, 0x4},
		TraceFlags: trace.TraceFlags(1),
	}
	assert.Equal(t, trace.TraceID{0x1, 0x2}, sc.TraceID)
	assert.Equal(t, trace.SpanID{0x3, 0x4}, sc.SpanID)
	assert.Equal(t, trace.TraceFlags(1), sc.TraceFlags)
}
