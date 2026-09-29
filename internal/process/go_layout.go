// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package process

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// dwAtGoRuntimeType is the Go-specific DWARF attribute that holds a type's
// runtime type descriptor, as an offset from the runtime.types symbol.
const dwAtGoRuntimeType = dwarf.Attr(0x2904)

// StructField names a field of a Go struct.
type StructField struct {
	// Struct is the struct type as named in DWARF, e.g.
	// "go.opentelemetry.io/otel/trace.nonRecordingSpan".
	Struct string
	// Field is the field name.
	Field string
}

// GoLayout is where the target process keeps Go types and struct fields.
type GoLayout struct {
	// TypeAddrs is the address of the runtime type descriptor of each type
	// found, by its DWARF name.
	TypeAddrs map[string]uint64
	// FieldOffsets is the offset of each field found within its struct.
	FieldOffsets map[StructField]uint64
}

// GoLayout looks up types (named as in DWARF, e.g. "*context.valueCtx") and
// fields in the DWARF of the target binary. Types and fields the binary does
// not contain are left out of the result.
func (i *Info) GoLayout(types []string, fields []StructField) (*GoLayout, error) {
	f, err := elf.Open(i.ID.ExePath())
	if err != nil {
		return nil, err
	}

	defer f.Close()

	base, err := runtimeTypesBase(f)
	if err != nil {
		return nil, err
	}

	bias, err := loadBias(i.ID, f)
	if err != nil {
		return nil, err
	}

	d, err := f.DWARF()
	if err != nil {
		return nil, err
	}

	scan := newLayoutScan(types, fields, bias+base)
	if err := scan.run(d.Reader()); err != nil {
		return nil, err
	}

	return scan.found, nil
}

// layoutScan is one pass over the top-level DWARF entries, which hold every
// type, looking for the wanted types and struct fields.
type layoutScan struct {
	typesBase uint64
	types     map[string]bool
	fields    map[string]map[string]bool // struct → fields
	pending   int
	found     *GoLayout
}

func newLayoutScan(types []string, fields []StructField, typesBase uint64) *layoutScan {
	s := &layoutScan{
		typesBase: typesBase,
		types:     make(map[string]bool, len(types)),
		fields:    make(map[string]map[string]bool, len(fields)),
		found: &GoLayout{
			TypeAddrs:    make(map[string]uint64, len(types)),
			FieldOffsets: make(map[StructField]uint64, len(fields)),
		},
	}

	for _, t := range types {
		s.types[t] = true
	}

	for _, f := range fields {
		if s.fields[f.Struct] == nil {
			s.fields[f.Struct] = make(map[string]bool)
		}

		s.fields[f.Struct][f.Field] = true
	}

	s.pending = len(s.types)
	for _, names := range s.fields {
		s.pending += len(names)
	}

	return s
}

func (s *layoutScan) run(r *dwarf.Reader) error {
	for s.pending > 0 {
		e, err := r.Next()
		if err != nil {
			return err
		}

		if e == nil {
			break
		}

		name, _ := e.Val(dwarf.AttrName).(string)
		if off, ok := e.Val(dwAtGoRuntimeType).(uint64); ok && s.types[name] {
			delete(s.types, name)
			s.pending--
			s.found.TypeAddrs[name] = s.typesBase + off
		}

		switch {
		case e.Tag == dwarf.TagCompileUnit || !e.Children:
		case e.Tag == dwarf.TagStructType && s.fields[name] != nil:
			if err := s.readFields(r, name); err != nil {
				return err
			}
		default:
			r.SkipChildren()
		}
	}

	return nil
}

// readFields reads the members of the struct the reader just entered.
func (s *layoutScan) readFields(r *dwarf.Reader, structName string) error {
	wanted := s.fields[structName]
	delete(s.fields, structName)
	s.pending -= len(wanted)

	for {
		e, err := r.Next()
		if err != nil {
			return err
		}

		if e.Tag == 0 {
			return nil
		}

		name, _ := e.Val(dwarf.AttrName).(string)
		off, ok := e.Val(dwarf.AttrDataMemberLoc).(int64)
		if ok && off >= 0 && e.Tag == dwarf.TagMember && wanted[name] {
			s.found.FieldOffsets[StructField{Struct: structName, Field: name}] = uint64(off) //nolint:gosec  // off >= 0.
		}
	}
}

func runtimeTypesBase(f *elf.File) (uint64, error) {
	syms, err := f.Symbols()
	if err != nil {
		return 0, err
	}

	for _, s := range syms {
		if s.Name == "runtime.types" {
			return s.Value, nil
		}
	}

	return 0, errors.New("runtime.types symbol not found")
}

// loadBias returns how far the target process mapped f from its link-time
// addresses: 0 for position-dependent (ET_EXEC) binaries, and for PIE the
// start of the executable's mapping at file offset 0 minus that segment's
// link-time address.
func loadBias(id ID, f *elf.File) (uint64, error) {
	if f.Type != elf.ET_DYN {
		return 0, nil
	}

	var vaddr uint64
	found := false
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Off == 0 {
			vaddr, found = p.Vaddr, true
			break
		}
	}

	if !found {
		return 0, errors.New("no loadable segment at file offset 0")
	}

	exe, err := id.ExeLink()
	if err != nil {
		return 0, err
	}

	start, err := mappingStart(id, exe)
	if err != nil {
		return 0, err
	}

	return start - vaddr, nil
}

// mappingStart returns the start address of path's mapping at file offset 0
// in the process's /proc/<pid>/maps.
func mappingStart(id ID, path string) (uint64, error) {
	maps, err := os.Open(id.dir() + "/maps")
	if err != nil {
		return 0, err
	}

	defer maps.Close()

	// Each line: start-end perms offset dev inode path
	s := bufio.NewScanner(maps)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 6 || strings.Join(fields[5:], " ") != path {
			continue
		}

		if off, err := strconv.ParseUint(fields[2], 16, 64); err != nil || off != 0 {
			continue
		}

		start, _, _ := strings.Cut(fields[0], "-")
		return strconv.ParseUint(start, 16, 64)
	}

	if err := s.Err(); err != nil {
		return 0, err
	}

	return 0, fmt.Errorf("%s is not mapped at file offset 0", path)
}
