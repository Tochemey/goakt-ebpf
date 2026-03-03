// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

package instrumentation

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"

	"github.com/tochemey/goakt-ebpf/internal/instrumentation/probe/sampling"
)

func TestNameAndVersion(t *testing.T) {
	assert.Equal(t, "goakt-ebpf", Name)
	assert.Equal(t, "0.1.0", Version)
}

func TestNewNoopConfigProvider(t *testing.T) {
	sc := &sampling.Config{}
	provider := NewNoopConfigProvider(sc)
	require.NotNil(t, provider)

	cfg := provider.InitialConfig(context.Background())
	assert.Equal(t, sc, cfg.SamplingConfig)

	watchCh := provider.Watch()
	_, ok := <-watchCh
	assert.False(t, ok, "watch channel should be closed")

	err := provider.Shutdown(context.Background())
	assert.NoError(t, err)
}

func TestNewNoopConfigProviderNilSampling(t *testing.T) {
	provider := NewNoopConfigProvider(nil)
	require.NotNil(t, provider)

	cfg := provider.InitialConfig(context.Background())
	assert.Nil(t, cfg.SamplingConfig)
}

func TestLibraryID(t *testing.T) {
	id := LibraryID{
		InstrumentedPkg: "net/http",
		SpanKind:        trace.SpanKindServer,
	}
	assert.Equal(t, "net/http", id.InstrumentedPkg)
	assert.Equal(t, trace.SpanKindServer, id.SpanKind)
}

func TestConfig(t *testing.T) {
	cfg := Config{
		DefaultTracesDisabled: true,
		InstrumentationLibraryConfigs: map[LibraryID]Library{
			{InstrumentedPkg: "pkg"}: {TracesEnabled: ptr(true)},
		},
	}
	assert.True(t, cfg.DefaultTracesDisabled)
	assert.Len(t, cfg.InstrumentationLibraryConfigs, 1)
}

func ptr(b bool) *bool {
	return &b
}
