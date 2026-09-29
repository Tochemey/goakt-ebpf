// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tochemey/goakt-ebpf/internal/inject"
	"github.com/tochemey/goakt-ebpf/internal/process"
)

var layoutConst = GoLayoutConst{
	Types:  map[string]string{"ctx_type_value": "*context.valueCtx"},
	Fields: map[string]process.StructField{"sample_sc_offset": {Struct: "main.sample", Field: "sc"}},
}

func TestGoLayoutConstInjectsZerosWhenUnreadable(t *testing.T) {
	zeros := inject.WithKeyValues(map[string]interface{}{
		"ctx_type_value":   uint64(0),
		"sample_sc_offset": uint64(0),
	})

	for name, c := range map[string]Const{
		"with a logger":    layoutConst.SetLogger(slog.Default()),
		"without a logger": layoutConst,
	} {
		t.Run(name, func(t *testing.T) {
			opt, err := c.InjectOption(&process.Info{ID: -1})
			require.NoError(t, err, "an unreadable binary must not stop the probe from loading")
			require.Equal(t, zeros, opt)
		})
	}
}
