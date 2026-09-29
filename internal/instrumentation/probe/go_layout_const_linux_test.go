//go:build linux

// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"bufio"
	"fmt"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/tochemey/goakt-ebpf/internal/inject"
	"github.com/tochemey/goakt-ebpf/internal/process"
)

func TestGoLayoutConstInjectsTargetLayout(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "golayout")
	build := exec.Command("go", "build", "-o", bin, "../../process/testdata/golayout") //nolint:gosec  // Test-fixed arguments.
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))

	cmd := exec.Command(bin) //nolint:gosec  // Test-built binary.
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})

	var valueCtx uint64
	line, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	_, err = fmt.Sscan(line, &valueCtx)
	require.NoError(t, err)

	opt, err := layoutConst.InjectOption(&process.Info{ID: process.ID(cmd.Process.Pid)})
	require.NoError(t, err)
	require.Equal(t, inject.WithKeyValues(map[string]interface{}{
		"ctx_type_value":   valueCtx,
		"sample_sc_offset": uint64(24),
	}), opt)
}
