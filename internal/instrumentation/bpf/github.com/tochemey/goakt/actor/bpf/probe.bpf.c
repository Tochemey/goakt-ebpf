// Copyright (c) 2026 The GoAkt eBPF Authors.
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
#define EVENT_TYPE_SYSTEM_SPAWN 7
#define EVENT_TYPE_SPAWN_CHILD 8
#define EVENT_TYPE_SPAWN_ON 32
#define EVENT_TYPE_REMOTE_SPAWN 9
#define EVENT_TYPE_REMOTE_SPAWN_CHILD 10
#define EVENT_TYPE_REMOTE_TELL_RECEIVE 11
#define EVENT_TYPE_REMOTE_ASK_RECEIVE 12
#define EVENT_TYPE_RELOCATION 13
#define EVENT_TYPE_REMOTE_TELL_GRAIN 14
#define EVENT_TYPE_REMOTE_ASK_GRAIN 15
#define EVENT_TYPE_REMOTE_LOOKUP 16
#define EVENT_TYPE_REMOTE_RE_SPAWN 17
#define EVENT_TYPE_REMOTE_STOP 18
#define EVENT_TYPE_REMOTE_ASK_GRAIN_RECEIVE 19
#define EVENT_TYPE_REMOTE_TELL_GRAIN_RECEIVE 20
#define EVENT_TYPE_REMOTE_ACTIVATE_GRAIN 21
#define EVENT_TYPE_REMOTE_REINSTATE 22
#define EVENT_TYPE_REMOTE_PASSIVATION_STRATEGY 23
#define EVENT_TYPE_REMOTE_STATE 24
#define EVENT_TYPE_REMOTE_CHILDREN 25
#define EVENT_TYPE_REMOTE_PARENT 26
#define EVENT_TYPE_REMOTE_KIND 27
#define EVENT_TYPE_REMOTE_DEPENDENCIES 28
#define EVENT_TYPE_REMOTE_METRIC 29
#define EVENT_TYPE_REMOTE_ROLE 30
#define EVENT_TYPE_REMOTE_STASH_SIZE 31

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
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_system_spawn SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_spawn_on SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_spawn_child SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_spawn SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_spawn_child SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_tell_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_ask_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_relocation SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_tell_grain SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_ask_grain SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_lookup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_re_spawn SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_stop SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_ask_grain_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_tell_grain_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_activate_grain SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_reinstate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_passivation_strategy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_children SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_parent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_kind SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_dependencies SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_metric SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_role SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_stash_size SEC(".maps");

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

// --- (*actorSystem).Spawn ---
SEC("uprobe/Spawn")
int uprobe_Spawn(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_system_spawn, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_SYSTEM_SPAWN,
			    &goakt_actor_system_spawn);
	return 0;
}

SEC("uprobe/Spawn_Returns")
int uprobe_Spawn_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_system_spawn);
	return 0;
}

// --- (*actorSystem).SpawnOn (remote placement) ---
SEC("uprobe/SpawnOn")
int uprobe_SpawnOn(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_spawn_on, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_SPAWN_ON,
			    &goakt_actor_spawn_on);
	return 0;
}
SEC("uprobe/SpawnOn_Returns")
int uprobe_SpawnOn_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_spawn_on);
	return 0;
}

// --- (*PID).SpawnChild ---
SEC("uprobe/SpawnChild")
int uprobe_SpawnChild(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_spawn_child, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_SPAWN_CHILD,
			    &goakt_actor_spawn_child);
	return 0;
}

SEC("uprobe/SpawnChild_Returns")
int uprobe_SpawnChild_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_spawn_child);
	return 0;
}

// --- (*actorSystem).remoteSpawnHandler ---
SEC("uprobe/remoteSpawnHandler")
int uprobe_remoteSpawnHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_spawn, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_SPAWN,
			    &goakt_actor_remote_spawn);
	return 0;
}

SEC("uprobe/remoteSpawnHandler_Returns")
int uprobe_remoteSpawnHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_spawn);
	return 0;
}

// --- (*actorSystem).remoteSpawnChildHandler ---
SEC("uprobe/remoteSpawnChildHandler")
int uprobe_remoteSpawnChildHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_spawn_child, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_SPAWN_CHILD,
			    &goakt_actor_remote_spawn_child);
	return 0;
}

SEC("uprobe/remoteSpawnChildHandler_Returns")
int uprobe_remoteSpawnChildHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_spawn_child);
	return 0;
}

// --- (*actorSystem).remoteTellHandler ---
SEC("uprobe/remoteTellHandler")
int uprobe_remoteTellHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_tell_receive, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_TELL_RECEIVE,
			    &goakt_actor_remote_tell_receive);
	return 0;
}

SEC("uprobe/remoteTellHandler_Returns")
int uprobe_remoteTellHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_tell_receive);
	return 0;
}

// --- (*actorSystem).remoteAskHandler ---
SEC("uprobe/remoteAskHandler")
int uprobe_remoteAskHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_ask_receive, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ASK_RECEIVE,
			    &goakt_actor_remote_ask_receive);
	return 0;
}

SEC("uprobe/remoteAskHandler_Returns")
int uprobe_remoteAskHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_ask_receive);
	return 0;
}

// --- (*relocator).Relocate ---
SEC("uprobe/Relocate")
int uprobe_Relocate(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_relocation, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_RELOCATION,
			    &goakt_actor_relocation);
	return 0;
}

SEC("uprobe/Relocate_Returns")
int uprobe_Relocate_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_relocation);
	return 0;
}

// --- (*actorSystem).remoteTellGrain (client) ---
SEC("uprobe/remoteTellGrain")
int uprobe_remoteTellGrain(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_tell_grain, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_TELL_GRAIN,
			    &goakt_actor_remote_tell_grain);
	return 0;
}
SEC("uprobe/remoteTellGrain_Returns")
int uprobe_remoteTellGrain_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_tell_grain);
	return 0;
}

// --- (*actorSystem).remoteAskGrain (client) ---
SEC("uprobe/remoteAskGrain")
int uprobe_remoteAskGrain(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_ask_grain, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ASK_GRAIN,
			    &goakt_actor_remote_ask_grain);
	return 0;
}
SEC("uprobe/remoteAskGrain_Returns")
int uprobe_remoteAskGrain_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_ask_grain);
	return 0;
}

// --- (*actorSystem).remoteLookupHandler ---
SEC("uprobe/remoteLookupHandler")
int uprobe_remoteLookupHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_lookup, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_LOOKUP,
			    &goakt_actor_remote_lookup);
	return 0;
}
SEC("uprobe/remoteLookupHandler_Returns")
int uprobe_remoteLookupHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_lookup);
	return 0;
}

// --- (*actorSystem).remoteReSpawnHandler ---
SEC("uprobe/remoteReSpawnHandler")
int uprobe_remoteReSpawnHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_re_spawn, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_RE_SPAWN,
			    &goakt_actor_remote_re_spawn);
	return 0;
}
SEC("uprobe/remoteReSpawnHandler_Returns")
int uprobe_remoteReSpawnHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_re_spawn);
	return 0;
}

// --- (*actorSystem).remoteStopHandler ---
SEC("uprobe/remoteStopHandler")
int uprobe_remoteStopHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_stop, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_STOP,
			    &goakt_actor_remote_stop);
	return 0;
}
SEC("uprobe/remoteStopHandler_Returns")
int uprobe_remoteStopHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_stop);
	return 0;
}

// --- (*actorSystem).remoteAskGrainHandler ---
SEC("uprobe/remoteAskGrainHandler")
int uprobe_remoteAskGrainHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_ask_grain_receive, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ASK_GRAIN_RECEIVE,
			    &goakt_actor_remote_ask_grain_receive);
	return 0;
}
SEC("uprobe/remoteAskGrainHandler_Returns")
int uprobe_remoteAskGrainHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_ask_grain_receive);
	return 0;
}

// --- (*actorSystem).remoteTellGrainHandler ---
SEC("uprobe/remoteTellGrainHandler")
int uprobe_remoteTellGrainHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_tell_grain_receive, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_TELL_GRAIN_RECEIVE,
			    &goakt_actor_remote_tell_grain_receive);
	return 0;
}
SEC("uprobe/remoteTellGrainHandler_Returns")
int uprobe_remoteTellGrainHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_tell_grain_receive);
	return 0;
}

// --- (*actorSystem).remoteActivateGrainHandler ---
SEC("uprobe/remoteActivateGrainHandler")
int uprobe_remoteActivateGrainHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_activate_grain, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ACTIVATE_GRAIN,
			    &goakt_actor_remote_activate_grain);
	return 0;
}
SEC("uprobe/remoteActivateGrainHandler_Returns")
int uprobe_remoteActivateGrainHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_activate_grain);
	return 0;
}

// --- (*actorSystem).remoteReinstateHandler ---
SEC("uprobe/remoteReinstateHandler")
int uprobe_remoteReinstateHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_reinstate, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_REINSTATE,
			    &goakt_actor_remote_reinstate);
	return 0;
}
SEC("uprobe/remoteReinstateHandler_Returns")
int uprobe_remoteReinstateHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_reinstate);
	return 0;
}

// --- (*actorSystem).remotePassivationStrategyHandler ---
SEC("uprobe/remotePassivationStrategyHandler")
int uprobe_remotePassivationStrategyHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_passivation_strategy, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_PASSIVATION_STRATEGY,
			    &goakt_actor_remote_passivation_strategy);
	return 0;
}
SEC("uprobe/remotePassivationStrategyHandler_Returns")
int uprobe_remotePassivationStrategyHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_passivation_strategy);
	return 0;
}

// --- (*actorSystem).remoteStateHandler ---
SEC("uprobe/remoteStateHandler")
int uprobe_remoteStateHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_state, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_STATE,
			    &goakt_actor_remote_state);
	return 0;
}
SEC("uprobe/remoteStateHandler_Returns")
int uprobe_remoteStateHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_state);
	return 0;
}

// --- (*actorSystem).remoteChildrenHandler ---
SEC("uprobe/remoteChildrenHandler")
int uprobe_remoteChildrenHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_children, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_CHILDREN,
			    &goakt_actor_remote_children);
	return 0;
}
SEC("uprobe/remoteChildrenHandler_Returns")
int uprobe_remoteChildrenHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_children);
	return 0;
}

// --- (*actorSystem).remoteParentHandler ---
SEC("uprobe/remoteParentHandler")
int uprobe_remoteParentHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_parent, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_PARENT,
			    &goakt_actor_remote_parent);
	return 0;
}
SEC("uprobe/remoteParentHandler_Returns")
int uprobe_remoteParentHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_parent);
	return 0;
}

// --- (*actorSystem).remoteKindHandler ---
SEC("uprobe/remoteKindHandler")
int uprobe_remoteKindHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_kind, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_KIND,
			    &goakt_actor_remote_kind);
	return 0;
}
SEC("uprobe/remoteKindHandler_Returns")
int uprobe_remoteKindHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_kind);
	return 0;
}

// --- (*actorSystem).remoteDependenciesHandler ---
SEC("uprobe/remoteDependenciesHandler")
int uprobe_remoteDependenciesHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_dependencies, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_DEPENDENCIES,
			    &goakt_actor_remote_dependencies);
	return 0;
}
SEC("uprobe/remoteDependenciesHandler_Returns")
int uprobe_remoteDependenciesHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_dependencies);
	return 0;
}

// --- (*actorSystem).remoteMetricHandler ---
SEC("uprobe/remoteMetricHandler")
int uprobe_remoteMetricHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_metric, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_METRIC,
			    &goakt_actor_remote_metric);
	return 0;
}
SEC("uprobe/remoteMetricHandler_Returns")
int uprobe_remoteMetricHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_metric);
	return 0;
}

// --- (*actorSystem).remoteRoleHandler ---
SEC("uprobe/remoteRoleHandler")
int uprobe_remoteRoleHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_role, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ROLE,
			    &goakt_actor_remote_role);
	return 0;
}
SEC("uprobe/remoteRoleHandler_Returns")
int uprobe_remoteRoleHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_role);
	return 0;
}

// --- (*actorSystem).remoteStashSizeHandler ---
SEC("uprobe/remoteStashSizeHandler")
int uprobe_remoteStashSizeHandler(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (bpf_map_lookup_elem(&goakt_actor_remote_stash_size, &key) != NULL) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_STASH_SIZE,
			    &goakt_actor_remote_stash_size);
	return 0;
}
SEC("uprobe/remoteStashSizeHandler_Returns")
int uprobe_remoteStashSizeHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_stash_size);
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
