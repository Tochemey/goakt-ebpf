//go:build linux

// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bufio"
	"fmt"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
)

// startTarget runs testdata/golayout built with the given build mode, and
// returns its PID and the type addresses it reports for itself.
func startTarget(t *testing.T, buildMode string) (ID, uint64, uint64) {
	t.Helper()

	cmd := exec.Command(buildTarget(t, "-buildmode="+buildMode)) //nolint:gosec  // Test-built binary.
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})

	var valueCtx, withoutCancel uint64
	line, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	_, err = fmt.Sscan(line, &valueCtx, &withoutCancel)
	require.NoError(t, err)
	return ID(cmd.Process.Pid), valueCtx, withoutCancel
}

// Looking up types in another process by PID, as the agent does, must yield
// exactly the type pointers that process uses at runtime.
func TestGoLayoutMatchesLiveTypes(t *testing.T) {
	const withoutCancelType = "context.withoutCancelCtx"

	for _, mode := range []string{"exe", "pie"} {
		t.Run(mode, func(t *testing.T) {
			pid, valueCtx, withoutCancel := startTarget(t, mode)

			layout, err := (&Info{ID: pid}).GoLayout([]string{valueCtxType, withoutCancelType}, nil)
			require.NoError(t, err)
			require.Equal(t, map[string]uint64{
				valueCtxType:      valueCtx,
				withoutCancelType: withoutCancel,
			}, layout.TypeAddrs)
		})
	}
}
