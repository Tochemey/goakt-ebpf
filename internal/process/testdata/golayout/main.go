// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

// Command golayout prints the runtime type addresses behind a valueCtx and a
// withoutCancelCtx, then waits for stdin to close. It is the target binary
// and process of the GoLayout tests.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"unsafe"
)

// sample gives the tests a struct with a known field offset.
type sample struct {
	head [24]byte
	sc   int64
}

func main() {
	type key struct{}
	valueCtx := context.WithValue(context.Background(), key{}, sample{})
	withoutCancel := context.WithoutCancel(valueCtx)

	fmt.Println(ifaceType(valueCtx), ifaceType(withoutCancel))
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// ifaceType returns the dynamic type address behind a non-empty interface:
// its first word is the itab, whose second word is the type.
func ifaceType(ctx context.Context) uintptr {
	itab := (*[2]unsafe.Pointer)(unsafe.Pointer(&ctx))[0]
	return *(*uintptr)(unsafe.Add(itab, 8))
}
