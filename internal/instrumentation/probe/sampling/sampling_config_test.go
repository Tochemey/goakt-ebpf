// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

package sampling

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTraceIDRatioConfig(t *testing.T) {
	cfg, err := NewTraceIDRatioConfig(0.5)
	require.NoError(t, err)
	// 0.5 * math.MaxUint32 = 2147483647.5, truncates to 2147483647
	assert.Equal(t, uint64(2147483647), cfg.samplingRateNumerator)

	_, err = NewTraceIDRatioConfig(1.5)
	assert.ErrorIs(t, err, errInvalidFraction)

	_, err = NewTraceIDRatioConfig(-0.1)
	assert.ErrorIs(t, err, errInvalidFraction)

	cfg, err = NewTraceIDRatioConfig(0)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), cfg.samplingRateNumerator)

	cfg, err = NewTraceIDRatioConfig(1)
	require.NoError(t, err)
	assert.Equal(t, uint64(samplingRateDenominator), cfg.samplingRateNumerator)
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg)
	assert.Len(t, cfg.Samplers, 3)
	assert.Contains(t, cfg.Samplers, AlwaysOnID)
	assert.Contains(t, cfg.Samplers, AlwaysOffID)
	assert.Contains(t, cfg.Samplers, ParentBasedID)
	assert.Equal(t, ParentBasedID, cfg.ActiveSampler)
}

func TestDefaultParentBasedSampler(t *testing.T) {
	pb := DefaultParentBasedSampler()
	assert.Equal(t, AlwaysOnID, pb.Root)
	assert.Equal(t, AlwaysOnID, pb.RemoteSampled)
	assert.Equal(t, AlwaysOffID, pb.RemoteNotSampled)
	assert.Equal(t, AlwaysOnID, pb.LocalSampled)
	assert.Equal(t, AlwaysOffID, pb.LocalNotSampled)
}

func TestSamplerConfigMarshalUnmarshalAlwaysOn(t *testing.T) {
	sc := SamplerConfig{SamplerType: SamplerAlwaysOn}
	data, err := sc.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, sampleConfigSize)

	var got SamplerConfig
	err = got.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.Equal(t, SamplerAlwaysOn, got.SamplerType)
	assert.Nil(t, got.Config)
}

func TestSamplerConfigMarshalUnmarshalTraceIDRatio(t *testing.T) {
	sc := SamplerConfig{
		SamplerType: SamplerTraceIDRatio,
		Config:      TraceIDRatioConfig{samplingRateNumerator: 42},
	}
	data, err := sc.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, sampleConfigSize)

	var got SamplerConfig
	err = got.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.Equal(t, SamplerTraceIDRatio, got.SamplerType)
	require.IsType(t, TraceIDRatioConfig{}, got.Config)
	assert.Equal(t, uint64(42), got.Config.(TraceIDRatioConfig).samplingRateNumerator)
}

func TestSamplerConfigMarshalUnmarshalParentBased(t *testing.T) {
	pb := DefaultParentBasedSampler()
	sc := SamplerConfig{
		SamplerType: SamplerParentBased,
		Config:      pb,
	}
	data, err := sc.MarshalBinary()
	require.NoError(t, err)
	assert.Len(t, data, sampleConfigSize)

	var got SamplerConfig
	err = got.UnmarshalBinary(data)
	require.NoError(t, err)
	assert.Equal(t, SamplerParentBased, got.SamplerType)
	require.IsType(t, ParentBasedConfig{}, got.Config)
	assert.Equal(t, pb, got.Config.(ParentBasedConfig))
}

func TestSamplerConfigUnmarshalInvalidSize(t *testing.T) {
	var sc SamplerConfig
	err := sc.UnmarshalBinary(make([]byte, 10))
	assert.ErrorContains(t, err, "invalid data size")
}
