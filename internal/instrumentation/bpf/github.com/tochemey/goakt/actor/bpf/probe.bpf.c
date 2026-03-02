// Copyright (c) 2025 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Uses patterns and headers from OpenTelemetry Go Instrumentation
// (https://github.com/open-telemetry/opentelemetry-go-instrumentation).

#include "arguments.h"
#include "trace/span_context.h"
#include "go_context.h"
#include "uprobe.h"
#include "trace/span_output.h"
#include "trace/start_span.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_CONCURRENT 1000

#define EVENT_TYPE_DO_RECEIVE 1
#define EVENT_TYPE_REMOTE_TELL 2
#define EVENT_TYPE_REMOTE_ASK 3
#define EVENT_TYPE_PROCESS 4
#define EVENT_TYPE_GRAIN_PROCESS 5
#define EVENT_TYPE_GRAIN_DO_RECEIVE 6

struct goakt_actor_span_t {
	u8 event_type;
	u8 handled_successfully; /* 1 = success, 0 = failure (handleReceivedError called) */
	u8 padding[6];
	BASE_SPAN_PROPERTIES
};

struct uprobe_data_t {
	struct goakt_actor_span_t span;
};

// Maps for each probe pair (entry stores data, return reads and outputs)
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_do_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_tell SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_ask SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_process SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_grain_process SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_grain_do_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct uprobe_data_t));
	__uint(max_entries, 1);
} goakt_actor_uprobe_storage_map SEC(".maps");

static __always_inline void start_span_and_store(struct pt_regs *ctx, void *key,
						 struct uprobe_data_t *uprobe_data,
						 u8 event_type, void *map) {
	__builtin_memset(uprobe_data, 0, sizeof(struct uprobe_data_t));

	struct goakt_actor_span_t *span = &uprobe_data->span;
	span->event_type = event_type;
	span->handled_successfully = 1; /* default success; handleReceivedError sets 0 */
	span->start_time = bpf_ktime_get_ns();

	struct go_iface go_context = {0};
	start_span_params_t start_span_params = {
		.ctx = ctx,
		.go_context = &go_context,
		.psc = &span->psc,
		.sc = &span->sc,
		.get_parent_span_context_fn = NULL,
	};
	start_span(&start_span_params);

	bpf_map_update_elem(map, &key, uprobe_data, 0);
}

static __always_inline void finish_span_and_output(struct pt_regs *ctx, void *key,
						  void *map) {
	u64 end_time = bpf_ktime_get_ns();

	struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(map, &key);
	if (uprobe_data == NULL) {
		return;
	}

	struct goakt_actor_span_t *span = &uprobe_data->span;
	span->end_time = end_time;

	output_span_event(ctx, span, sizeof(*span), &span->sc);
	stop_tracking_span(&span->sc, &span->psc);
	bpf_map_delete_elem(map, &key);
}

// --- (*PID).doReceive ---
SEC("uprobe/doReceive")
int uprobe_doReceive(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_do_receive, &key) != NULL) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_DO_RECEIVE,
			    &goakt_actor_do_receive);
	return 0;
}

SEC("uprobe/doReceive_Returns")
int uprobe_doReceive_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_do_receive);
	return 0;
}

// --- (*actorSystem).handleRemoteTell ---
SEC("uprobe/handleRemoteTell")
int uprobe_handleRemoteTell(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_tell, &key) != NULL) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_TELL,
			    &goakt_actor_remote_tell);
	return 0;
}

SEC("uprobe/handleRemoteTell_Returns")
int uprobe_handleRemoteTell_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_tell);
	return 0;
}

// --- (*actorSystem).handleRemoteAsk ---
SEC("uprobe/handleRemoteAsk")
int uprobe_handleRemoteAsk(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_ask, &key) != NULL) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ASK,
			    &goakt_actor_remote_ask);
	return 0;
}

SEC("uprobe/handleRemoteAsk_Returns")
int uprobe_handleRemoteAsk_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_ask);
	return 0;
}

// --- (*PID).process ---
SEC("uprobe/process")
int uprobe_process(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_process, &key) != NULL) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_PROCESS,
			    &goakt_actor_process);
	return 0;
}

SEC("uprobe/process_Returns")
int uprobe_process_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_process);
	return 0;
}

// --- (*grainPID).process ---
SEC("uprobe/grainPID_process")
int uprobe_grainPID_process(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_grain_process, &key) != NULL) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_GRAIN_PROCESS,
			    &goakt_actor_grain_process);
	return 0;
}

SEC("uprobe/grainPID_process_Returns")
int uprobe_grainPID_process_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_grain_process);
	return 0;
}

// --- (*grainPID).handleGrainContext ---
SEC("uprobe/handleGrainContext")
int uprobe_handleGrainContext(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_grain_do_receive, &key) != NULL) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_GRAIN_DO_RECEIVE,
			    &goakt_actor_grain_do_receive);
	return 0;
}

SEC("uprobe/handleGrainContext_Returns")
int uprobe_handleGrainContext_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_grain_do_receive);
	return 0;
}

// --- (*PID).handleReceivedError ---
// Called from within doReceive when message handling fails. Marks the active
// doReceive span as handled_successfully=0 so it will be emitted with failure status.
SEC("uprobe/handleReceivedError")
int uprobe_handleReceivedError(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);

	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_do_receive, &key);
	if (uprobe_data == NULL) {
		return 0;
	}

	uprobe_data->span.handled_successfully = 0;
	return 0;
}
