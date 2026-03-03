// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

package debug

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerifierLogEnabled(t *testing.T) {
	// Default: not set
	assert.False(t, VerifierLogEnabled())

	// Set to true
	t.Setenv(VerifierLogKey, "true")
	assert.True(t, VerifierLogEnabled())

	// Set to false
	t.Setenv(VerifierLogKey, "false")
	assert.False(t, VerifierLogEnabled())

	// Invalid value - should return false
	t.Setenv(VerifierLogKey, "invalid")
	assert.False(t, VerifierLogEnabled())

	// Unset
	os.Unsetenv(VerifierLogKey)
	assert.False(t, VerifierLogEnabled())
}

func TestVerifierLogKey(t *testing.T) {
	assert.Equal(t, "OTEL_GO_AUTO_SHOW_VERIFIER_LOG", VerifierLogKey)
}
