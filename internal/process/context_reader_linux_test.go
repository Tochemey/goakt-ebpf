//go:build linux

package process

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func TestExtractSpanContextAllowsUnsampledParent(t *testing.T) {
	buf := make([]byte, spanReadSize)
	traceIDOff := 24
	spanIDOff := 40
	flagsOff := 48

	traceID := trace.TraceID{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	spanID := trace.SpanID{2, 2, 2, 2, 2, 2, 2, 2}
	copy(buf[traceIDOff:traceIDOff+traceIDSize], traceID[:])
	copy(buf[spanIDOff:spanIDOff+spanIDSize], spanID[:])
	buf[flagsOff] = byte(0) // unsampled

	sc := extractSpanContext(buf, traceIDOff, spanIDOff, flagsOff)
	require.NotNil(t, sc)
	require.Equal(t, traceID, sc.TraceID())
	require.Equal(t, spanID, sc.SpanID())
	require.Equal(t, trace.TraceFlags(0), sc.TraceFlags())
	require.True(t, sc.IsRemote())
}

func TestExtractSpanContextRejectsInvalidIDs(t *testing.T) {
	buf := make([]byte, spanReadSize)
	traceIDOff := 24
	spanIDOff := 40
	flagsOff := 48

	// invalid trace/span IDs (all zero)
	buf[flagsOff] = byte(trace.FlagsSampled)

	sc := extractSpanContext(buf, traceIDOff, spanIDOff, flagsOff)
	require.Nil(t, sc)
}
