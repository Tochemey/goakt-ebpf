// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0
//
// GoAkt-specific context extraction constants.
// Injected at load time via StructFieldConst for ReceiveContext.Context.

#ifndef _GOAKT_CONTEXT_H_
#define _GOAKT_CONTEXT_H_

#include "bpf_helpers.h"

// Offset of Context field in ReceiveContext struct. Injected from DWARF.
volatile const u64 receive_context_ctx_offset;

#endif
