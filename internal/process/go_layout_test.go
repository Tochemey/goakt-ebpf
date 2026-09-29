// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const valueCtxType = "*context.valueCtx"

var sampleField = StructField{Struct: "main.sample", Field: "sc"}

// buildTarget compiles testdata/golayout as a Linux executable with the
// extra go build arguments and returns its path.
func buildTarget(t *testing.T, args ...string) string {
	t.Helper()

	bin := filepath.Join(t.TempDir(), "golayout")
	args = append(append([]string{"build"}, args...), "-o", bin, "./testdata/golayout")
	build := exec.Command("go", args...) //nolint:gosec  // Test-fixed arguments.
	build.Env = append(os.Environ(), "GOOS=linux", "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))
	return bin
}

// patchTarget copies the ELF at src with patch applied to its bytes.
func patchTarget(t *testing.T, src string, patch func(raw []byte, f *elf.File)) string {
	t.Helper()

	raw, err := os.ReadFile(src)
	require.NoError(t, err)
	f, err := elf.NewFile(bytes.NewReader(raw))
	require.NoError(t, err)
	patch(raw, f)

	dst := filepath.Join(t.TempDir(), "patched")
	require.NoError(t, os.WriteFile(dst, raw, 0o600)) //nolint:gosec  // Test temp file.
	return dst
}

// breakDWARF overwrites the DWARF entry that follows the one selected by at,
// in a binary built with uncompressed DWARF.
func breakDWARF(t *testing.T, raw []byte, f *elf.File, at func(*dwarf.Entry) bool) {
	t.Helper()

	d, err := f.DWARF()
	require.NoError(t, err)

	r := d.Reader()
	for {
		e, err := r.Next()
		require.NoError(t, err)
		require.NotNil(t, e, "no DWARF entry selected")

		if !at(e) {
			continue
		}

		next, err := r.Next()
		require.NoError(t, err)
		start := f.Section(".debug_info").Offset + uint64(next.Offset)
		for i := start; i < start+8; i++ {
			raw[i] = 0xFF
		}

		return
	}
}

// fakeProc points procDir at a temp dir holding an exe link to target and
// the given maps content, and returns the dir.
func fakeProc(t *testing.T, target, maps string) string {
	t.Helper()

	dir := t.TempDir()
	orig := procDir
	procDir = func(ID) string { return dir }
	t.Cleanup(func() { procDir = orig })

	require.NoError(t, os.Symlink(target, filepath.Join(dir, "exe")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "maps"), []byte(maps), 0o600))
	return dir
}

func TestGoLayout(t *testing.T) {
	info := &Info{ID: 1}

	t.Run("finds the types and struct fields of a Go binary", func(t *testing.T) {
		fakeProc(t, buildTarget(t), "")

		layout, err := info.GoLayout([]string{valueCtxType}, []StructField{sampleField})
		require.NoError(t, err)
		require.NotZero(t, layout.TypeAddrs[valueCtxType])
		require.Equal(t, map[StructField]uint64{sampleField: 24}, layout.FieldOffsets)
	})

	t.Run("leaves out what the binary does not contain", func(t *testing.T) {
		fakeProc(t, buildTarget(t), "")

		layout, err := info.GoLayout(
			[]string{valueCtxType, "*example.com/not/linked.Type"},
			[]StructField{
				sampleField,
				{Struct: "main.sample", Field: "absent"},
				{Struct: "example.com/not/linked.Type", Field: "sc"},
			},
		)
		require.NoError(t, err)
		require.Len(t, layout.TypeAddrs, 1)
		require.NotZero(t, layout.TypeAddrs[valueCtxType])
		require.Equal(t, map[StructField]uint64{sampleField: 24}, layout.FieldOffsets)
	})

	t.Run("finds nothing when nothing is asked for", func(t *testing.T) {
		fakeProc(t, buildTarget(t), "")

		layout, err := info.GoLayout(nil, nil)
		require.NoError(t, err)
		require.Empty(t, layout.TypeAddrs)
		require.Empty(t, layout.FieldOffsets)
	})

	t.Run("adds the load bias of a PIE binary", func(t *testing.T) {
		bin := buildTarget(t, "-buildmode=pie")

		fakeProc(t, bin, "0-1000 r--p 00000000 00:2a 123 "+bin+"\n")
		linked, err := info.GoLayout([]string{valueCtxType}, nil)
		require.NoError(t, err)

		fakeProc(t, bin, "55550000-55560000 r--p 00000000 00:2a 123 "+bin+"\n")
		loaded, err := info.GoLayout([]string{valueCtxType}, nil)
		require.NoError(t, err)
		require.Equal(t, linked.TypeAddrs[valueCtxType]+0x55550000, loaded.TypeAddrs[valueCtxType])
	})

	t.Run("fails when a PIE binary is not mapped", func(t *testing.T) {
		fakeProc(t, buildTarget(t, "-buildmode=pie"), "")

		_, err := info.GoLayout([]string{valueCtxType}, nil)
		require.Error(t, err)
	})

	t.Run("fails without a symbol table", func(t *testing.T) {
		fakeProc(t, buildTarget(t, "-ldflags=-s"), "")

		_, err := info.GoLayout([]string{valueCtxType}, nil)
		require.Error(t, err)
	})

	t.Run("fails without the runtime.types symbol", func(t *testing.T) {
		bin := patchTarget(t, buildTarget(t), func(raw []byte, f *elf.File) {
			strtab := f.Section(".strtab")
			names := raw[strtab.Offset : strtab.Offset+strtab.Size]
			at := bytes.Index(names, []byte("\x00runtime.types\x00"))
			require.GreaterOrEqual(t, at, 0)
			names[at+1] = 'X'
		})

		fakeProc(t, bin, "")

		_, err := info.GoLayout([]string{valueCtxType}, nil)
		require.ErrorContains(t, err, "runtime.types")
	})

	t.Run("fails without DWARF", func(t *testing.T) {
		fakeProc(t, buildTarget(t, "-ldflags=-w"), "")

		_, err := info.GoLayout([]string{valueCtxType}, nil)
		require.Error(t, err)
	})

	t.Run("fails on an unreadable DWARF entry", func(t *testing.T) {
		bin := patchTarget(t, buildTarget(t, "-ldflags=-compressdwarf=false"), func(raw []byte, f *elf.File) {
			breakDWARF(t, raw, f, func(e *dwarf.Entry) bool { return e.Tag == dwarf.TagCompileUnit })
		})

		fakeProc(t, bin, "")

		_, err := info.GoLayout([]string{valueCtxType}, nil)
		require.Error(t, err)
	})

	t.Run("fails on an unreadable struct field", func(t *testing.T) {
		bin := patchTarget(t, buildTarget(t, "-ldflags=-compressdwarf=false"), func(raw []byte, f *elf.File) {
			breakDWARF(t, raw, f, func(e *dwarf.Entry) bool {
				name, _ := e.Val(dwarf.AttrName).(string)
				return e.Tag == dwarf.TagStructType && name == sampleField.Struct
			})
		})

		fakeProc(t, bin, "")

		_, err := info.GoLayout(nil, []StructField{sampleField})
		require.Error(t, err)
	})

	t.Run("fails on a file that is not an ELF", func(t *testing.T) {
		target := filepath.Join(t.TempDir(), "not-elf")
		require.NoError(t, os.WriteFile(target, []byte("plain text"), 0o600))
		fakeProc(t, target, "")

		_, err := info.GoLayout([]string{valueCtxType}, nil)
		require.Error(t, err)
	})
}

func TestLoadBias(t *testing.T) {
	pie := func(vaddr uint64) *elf.File {
		return &elf.File{
			FileHeader: elf.FileHeader{Type: elf.ET_DYN},
			Progs: []*elf.Prog{
				{ProgHeader: elf.ProgHeader{Type: elf.PT_PHDR, Off: 0x40, Vaddr: 0x40}},
				{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 0, Vaddr: vaddr}},
			},
		}
	}

	t.Run("position-dependent binaries are not relocated", func(t *testing.T) {
		f := &elf.File{FileHeader: elf.FileHeader{Type: elf.ET_EXEC}}

		bias, err := loadBias(1, f)
		require.NoError(t, err)
		require.Zero(t, bias)
	})

	t.Run("PIE bias is where the executable's first segment was mapped", func(t *testing.T) {
		fakeProc(t, "/app/bin/svc", ""+
			"7f0000000000-7f0000001000 r--p 00000000 00:2a 99 /lib/ld-linux.so\n"+
			"55540000-55550000 r-xp 00010000 00:2a 123 /app/bin/svc\n"+
			"55550000-55560000 r--p 00000000 00:2a 123 /app/bin/svc\n")

		bias, err := loadBias(1, pie(0))
		require.NoError(t, err)
		require.Equal(t, uint64(0x55550000), bias)
	})

	t.Run("PIE bias accounts for a non-zero first segment address", func(t *testing.T) {
		fakeProc(t, "/app/bin/svc", "55550000-55560000 r--p 00000000 00:2a 123 /app/bin/svc\n")

		bias, err := loadBias(1, pie(0x10000))
		require.NoError(t, err)
		require.Equal(t, uint64(0x55540000), bias)
	})

	t.Run("errors when the executable is not mapped at file offset 0", func(t *testing.T) {
		fakeProc(t, "/app/bin/svc", ""+
			"55550000-55560000 r--p 00000000 00:2a 123 /app/bin/other\n"+
			"55560000-55570000 r--p zz 00:2a 123 /app/bin/svc\n")

		_, err := loadBias(1, pie(0))
		require.ErrorContains(t, err, "not mapped")
	})

	t.Run("errors when the binary has no segment at file offset 0", func(t *testing.T) {
		fakeProc(t, "/app/bin/svc", "")
		f := &elf.File{FileHeader: elf.FileHeader{Type: elf.ET_DYN}}

		_, err := loadBias(1, f)
		require.Error(t, err)
	})

	t.Run("errors when the executable link cannot be read", func(t *testing.T) {
		dir := fakeProc(t, "/app/bin/svc", "")
		require.NoError(t, os.Remove(filepath.Join(dir, "exe")))

		_, err := loadBias(1, pie(0))
		require.Error(t, err)
	})

	t.Run("errors when the memory mappings cannot be opened", func(t *testing.T) {
		dir := fakeProc(t, "/app/bin/svc", "")
		require.NoError(t, os.Remove(filepath.Join(dir, "maps")))

		_, err := loadBias(1, pie(0))
		require.Error(t, err)
	})

	t.Run("errors when the memory mappings cannot be scanned", func(t *testing.T) {
		fakeProc(t, "/app/bin/svc", strings.Repeat("x", 128*1024))

		_, err := loadBias(1, pie(0))
		require.Error(t, err)
	})
}
