// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Uses patterns and headers from OpenTelemetry Go Instrumentation
// (https://github.com/open-telemetry/opentelemetry-go-instrumentation).

#include "arguments.h"
#include "goakt_context.h"
#include "go_context.h"
#include "trace/span_context.h"
#include "trace/span_output.h"
#include "trace/start_span.h"
#include "uprobe.h"

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
#define EVENT_TYPE_ACTOR_OF 33
#define EVENT_TYPE_SPAWN_NAMED_FROM_FUNC 34
#define EVENT_TYPE_SPAWN_FROM_FUNC 35
#define EVENT_TYPE_SPAWN_ROUTER 36
#define EVENT_TYPE_SPAWN_SINGLETON 37
#define EVENT_TYPE_KILL 38
#define EVENT_TYPE_RE_SPAWN 39
#define EVENT_TYPE_ACTOR_EXISTS 40
#define EVENT_TYPE_SYSTEM_METRIC 41
#define EVENT_TYPE_ACTORS 42
#define EVENT_TYPE_START 43
#define EVENT_TYPE_STOP 44
#define EVENT_TYPE_SCHEDULE_ONCE 45
#define EVENT_TYPE_SCHEDULE 46
#define EVENT_TYPE_SCHEDULE_WITH_CRON 47
#define EVENT_TYPE_TELL 48
#define EVENT_TYPE_ASK 49
#define EVENT_TYPE_SEND_ASYNC 50
#define EVENT_TYPE_SEND_SYNC 51
#define EVENT_TYPE_DISCOVER_ACTOR 52
#define EVENT_TYPE_PID_STOP 53
#define EVENT_TYPE_RESTART 54
#define EVENT_TYPE_PID_METRIC 55
#define EVENT_TYPE_REINSTATE_NAMED 56
#define EVENT_TYPE_PIPE_TO 57
#define EVENT_TYPE_PIPE_TO_NAME 58
#define EVENT_TYPE_BATCH_TELL 59
#define EVENT_TYPE_BATCH_ASK 60
#define EVENT_TYPE_PID_REMOTE_LOOKUP 61
#define EVENT_TYPE_PID_REMOTE_STOP 62
#define EVENT_TYPE_PID_REMOTE_RE_SPAWN 63
#define EVENT_TYPE_SHUTDOWN 64
#define EVENT_TYPE_TELL_GRAIN 65
#define EVENT_TYPE_ASK_GRAIN 66

struct goakt_actor_span_t {
	u8 event_type;
	u8 handled_successfully; /* 1 = success, 0 = failure (handleReceivedError called) */
	u8 padding[6];
	BASE_SPAN_PROPERTIES
};

struct uprobe_data_t {
	struct goakt_actor_span_t span;
	/* Distance of the probed frame from the top of the goroutine stack.
	 * Go keeps it when it copies a stack, so it tells a restart of the same
	 * call apart from a nested one. Not sent to userspace. */
	u64 frame_depth;
	/* Parent found by the eBPF lookups (context chain or goid), before an
	 * app span replaces it in span.psc. Context tracking is restored from
	 * it on return. Not sent to userspace. */
	struct span_context tracked_psc;
	/* *ReceiveContext / *GrainContext a handling span belongs to, whose
	 * enqueue record is released on return. 0 for every other span. */
	u64 handled_msg;
	/* Saved goid->sc entry that this span shadowed on entry, restored on
	 * return so an outer span keeps propagating after a nested span ends.
	 * Not sent to userspace: only span (goakt_actor_span_t) is output. */
	struct span_context prev_goid_sc;
	u8 had_prev_goid;
	/* Nesting depth for same-symbol re-entry on one goroutine: entry bumps
	 * it, return decrements, and the span is only emitted when it hits 0. */
	u32 depth;
};

// Maps for each probe pair (entry stores data, return reads and outputs)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_do_receive SEC(".maps");

/* Separate from do_receive so a missed uretprobe on one symbol cannot
 * swallow the other. Both emit EVENT_TYPE_DO_RECEIVE; userspace dedupes. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_receive_ctx_build SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_tell SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_ask SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_process SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_grain_process SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_grain_do_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_system_spawn SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_spawn_on SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_spawn_child SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_spawn SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_spawn_child SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_tell_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_ask_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_relocation SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_tell_grain SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_ask_grain SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_lookup SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_re_spawn SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_stop SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_ask_grain_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_tell_grain_receive SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_activate_grain SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_reinstate SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_passivation_strategy SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_children SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_parent SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_kind SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_dependencies SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_metric SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_role SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_remote_stash_size SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_actor_of SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_spawn_named_from_func SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_spawn_from_func SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_spawn_router SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_spawn_singleton SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_kill SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_re_spawn SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_actor_exists SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_system_metric SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_actors SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_start SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_stop SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_schedule_once SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_schedule SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_schedule_with_cron SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_tell SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_ask SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_send_async SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_send_sync SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_discover_actor SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_pid_stop SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_restart SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_pid_metric SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_reinstate_named SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_pipe_to SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_pipe_to_name SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_batch_tell SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_batch_ask SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_pid_remote_lookup SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_pid_remote_stop SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_pid_remote_re_spawn SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_shutdown SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_tell_grain SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *);
	__type(value, struct uprobe_data_t);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_ask_grain SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct uprobe_data_t));
	__uint(max_entries, 1);
} goakt_actor_uprobe_storage_map SEC(".maps");

// Goroutine-scoped span map for same-goroutine propagation.
// Methods like process() have no context arg; they inherit from doReceive via goid.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, void *); /* goroutine ID */
	__type(value, struct span_context);
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_goid_to_span_context SEC(".maps");

/* Messages can wait in mailboxes, so allow many more in flight than spans. */
#define MAX_ENQUEUED_MESSAGES 10240

// The enqueue span of each message in flight, keyed by its *ReceiveContext /
// *GrainContext. GoAkt v4 enqueues on the caller's goroutine and handles on a
// dispatcher worker, and the pointer flows through the mailbox between them.
// Correlating here, in the order the kernel saw the calls, stays exact when
// GoAkt pools and reuses the pointer; correlating in userspace did not,
// because perf events can arrive out of order.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64); /* *ReceiveContext or *GrainContext */
	__type(value, struct span_context);
	__uint(max_entries, MAX_ENQUEUED_MESSAGES);
} goakt_actor_enqueued SEC(".maps");

// The *ReceiveContext each goroutine built and has not yet passed to
// doReceive. build and doReceive both run for one Tell/Ask; the entry lets
// doReceive recognize that message and leave it to the build span.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, u64); /* goroutine */
	__type(value, u64); /* *ReceiveContext */
	__uint(max_entries, MAX_CONCURRENT);
} goakt_actor_built SEC(".maps");

// continues_build reports whether doReceive for msg follows the build call
// this goroutine made for it. It stays true until doReceive returns, so a
// restarted doReceive is recognized again.
static __always_inline bool continues_build(u64 goid, u64 msg) {
	u64 *built = bpf_map_lookup_elem(&goakt_actor_built, &goid);
	return built != NULL && *built == msg;
}

// release_enqueue forgets the enqueue record of a handled message, unless
// the pointer already carries the record of a newer message.
static __always_inline void release_enqueue(u64 msg, struct span_context *enqueue_sc) {
	struct span_context *sc = bpf_map_lookup_elem(&goakt_actor_enqueued, &msg);
	if (sc == NULL) {
		return;
	}

	u64 recorded, handled;
	__builtin_memcpy(&recorded, sc->SpanID, sizeof(recorded));
	__builtin_memcpy(&handled, enqueue_sc->SpanID, sizeof(handled));
	if (recorded == handled) {
		bpf_map_delete_elem(&goakt_actor_enqueued, &msg);
	}
}

static __always_inline void find_app_span_context(struct go_iface *ctx, struct span_context *out);

// get_parent_span_context_goid_first resolves a span's parent: the enqueue
// span of the message being handled, else the app (OTel SDK) span on the
// context, else the eBPF span on the go_context chain, else the goroutine's.
// Used as get_parent_span_context_fn, so the sampler sees that parent and an
// unsampled app trace is left unsampled.
struct goid_parent_handle {
	struct pt_regs *ctx;
	struct go_iface *go_context;
	/* *ReceiveContext / *GrainContext being handled; 0 for other spans. */
	u64 handled_msg;
	/* Out: the eBPF parent, which context tracking is restored from on
	 * return, also when an app span is the parent. */
	struct span_context *tracked_psc;
};

static long get_parent_span_context_goid_first(void *handle, struct span_context *psc) {
	struct goid_parent_handle *h = (struct goid_parent_handle *)handle;
	if (h->handled_msg != 0) {
		struct span_context *enqueue_sc =
			bpf_map_lookup_elem(&goakt_actor_enqueued, &h->handled_msg);
		if (enqueue_sc != NULL) {
			*psc = *enqueue_sc;
			return 0;
		}
	}

	long found = -1;
	void *goid = (void *)GOROUTINE(h->ctx);
	struct span_context *ebpf_psc = get_parent_span_context(h->go_context);
	if (ebpf_psc == NULL) {
		ebpf_psc = bpf_map_lookup_elem(&goakt_actor_goid_to_span_context, &goid);
	}

	if (ebpf_psc != NULL) {
		*psc = *ebpf_psc;
		*h->tracked_psc = *ebpf_psc;
		found = 0;
	}

	if (h->go_context->data != NULL) {
		struct span_context app_psc = {0};
		find_app_span_context(h->go_context, &app_psc);
		if (!bpf_is_zero(app_psc.SpanID, SPAN_ID_SIZE)) {
			*psc = app_psc;
			found = 0;
		}
	}

	return found;
}

/* An active same-symbol entry older than this indicates a missed return probe
 * (the function was unwound without returning, leaving an unmatched map
 * entry). The instrumented functions complete in well under this bound, and
 * without healing a single missed return silently swallows every subsequent
 * call on that goroutine forever. */
#define MAX_ACTIVE_SPAN_AGE_NS (10ULL * 1000000000ULL)

/* runtime.g starts with stack{lo, hi uintptr}. */
#define GO_G_STACK_HI_OFF 8

// frame_depth returns how far below the top of the goroutine stack the probed
// function's frame is. Stack copies preserve it; a nested call is deeper.
static __always_inline u64 frame_depth(struct pt_regs *ctx) {
	u64 hi = 0;
	bpf_probe_read_user(&hi, sizeof(hi), (void *)GOROUTINE(ctx) + GO_G_STACK_HI_OFF);
	return hi - (u64)PT_REGS_SP(ctx);
}

// actor_reentered reports whether a span for this key is already active on the
// goroutine, in which case the caller should return without starting a span.
// The frame depth tells the cases apart:
//   - deeper: a nested call of the same function. The nesting depth is bumped
//     so the matching return does not emit the span early.
//   - same: Go restarted the call, after growing the stack or preempting the
//     goroutine in the function's prologue, which re-fires the entry probe.
//     The active span covers it.
//   - shallower, or older than MAX_ACTIVE_SPAN_AGE_NS: the active call was
//     unwound without its return probe firing. It is dropped so the goroutine
//     heals, and the caller starts a span.
static __always_inline bool actor_reentered(struct pt_regs *ctx, void *map, void *key) {
	struct uprobe_data_t *d = bpf_map_lookup_elem(map, &key);
	if (d == NULL) {
		return false;
	}

	u64 depth = frame_depth(ctx);
	u64 age = bpf_ktime_get_ns() - d->span.start_time;
	if (age > MAX_ACTIVE_SPAN_AGE_NS || depth < d->frame_depth) {
		/* Also drop the goid propagation entry, but only when it still
		 * points at the stale span; otherwise it belongs to a live outer
		 * span of a different symbol and must be kept. */
		struct span_context *goid_sc =
			bpf_map_lookup_elem(&goakt_actor_goid_to_span_context, &key);
		if (goid_sc != NULL) {
			u64 stale_id, goid_id;
			__builtin_memcpy(&stale_id, d->span.sc.SpanID, sizeof(stale_id));
			__builtin_memcpy(&goid_id, goid_sc->SpanID, sizeof(goid_id));
			if (stale_id == goid_id) {
				bpf_map_delete_elem(&goakt_actor_goid_to_span_context, &key);
			}
		}
		bpf_map_delete_elem(map, &key);
		return false;
	}

	if (depth > d->frame_depth) {
		d->depth++;
	}

	return true;
}

/* Go runtime layouts used by the context walk. */
#define GO_ITAB_TYPE_OFF 8 /* runtime.itab._type */
#define GO_IFACE_DATA_OFF 8 /* interface value: {itab or type, data} */
/* context.valueCtx: parent Context at 0, key any at 16, val any at 32. */
#define VALUE_CTX_KEY_TYPE_OFF 16
#define VALUE_CTX_VAL_TYPE_OFF 32
#define VALUE_CTX_VAL_DATA_OFF 40
#define MAX_APP_CTX_DEPTH 32

// embeds_parent_ctx reports whether a context of this runtime type is a
// standard library context that holds its parent Context as the first field.
static __always_inline bool embeds_parent_ctx(u64 typ) {
	return typ == ctx_type_value || typ == ctx_type_cancel || typ == ctx_type_timer ||
	       typ == ctx_type_after_func || typ == ctx_type_without_cancel ||
	       typ == ctx_type_stop;
}

// span_sc_offset returns where the SpanContext sits in an OTel span of this
// runtime type, or 0 for a span type that is not read (e.g. Auto SDK).
static __always_inline u64 span_sc_offset(u64 typ) {
	if (typ == otel_span_type_recording) {
		return otel_recording_span_sc_offset;
	}

	if (typ == otel_span_type_sdk_nonrecording) {
		return otel_sdk_nonrecording_span_sc_offset;
	}

	if (typ == otel_span_type_api_nonrecording) {
		return otel_api_nonrecording_span_sc_offset;
	}

	return 0;
}

// read_span_context copies the SpanContext at off in an OTel span, whose
// leading TraceID, SpanID and TraceFlags match struct span_context. It is
// accepted only when both IDs are non-zero.
static __always_inline void read_span_context(void *span, u64 off, struct span_context *out) {
	struct span_context sc = {0};
	if (bpf_probe_read_user(&sc, TRACE_ID_SIZE + SPAN_ID_SIZE + TRACE_FLAGS_SIZE,
				span + off) != 0) {
		return;
	}

	if (bpf_is_zero(sc.TraceID, TRACE_ID_SIZE) || bpf_is_zero(sc.SpanID, SPAN_ID_SIZE)) {
		return;
	}

	*out = sc;
}

// find_app_span_context walks the context.Context chain from ctx and stores
// the current OTel span's context in out. Nodes and values are identified by
// their Go runtime type, so a span is only read from memory that really is
// one. The walk ends at the root context. A context type it does not know is
// taken to embed its parent Context first, as custom contexts usually do, and
// the walk goes on only if that parent is a standard context.
static __always_inline void find_app_span_context(struct go_iface *ctx,
						  struct span_context *out) {
	void *itab = ctx->type;
	void *node = ctx->data;
	bool after_custom = false;

	for (int i = 0; i < MAX_APP_CTX_DEPTH; i++) {
		if (itab == NULL || node == NULL) {
			return;
		}

		u64 typ = 0;
		if (bpf_probe_read_user(&typ, sizeof(typ), itab + GO_ITAB_TYPE_OFF) != 0 || typ == 0 ||
		    typ == ctx_type_background || typ == ctx_type_todo) {
			return;
		}

		bool standard = embeds_parent_ctx(typ);
		if (!standard && after_custom) {
			return;
		}

		after_custom = !standard;

		if (typ == ctx_type_value) {
			u64 key_type = 0;
			bpf_probe_read_user(&key_type, sizeof(key_type),
					    node + VALUE_CTX_KEY_TYPE_OFF);
			if (key_type == otel_span_key_type) {
				/* The nearest span entry is the current span: use it
				 * or nothing, never an outer one. */
				u64 val_type = 0;
				void *val = NULL;
				bpf_probe_read_user(&val_type, sizeof(val_type),
						    node + VALUE_CTX_VAL_TYPE_OFF);
				bpf_probe_read_user(&val, sizeof(val), node + VALUE_CTX_VAL_DATA_OFF);
				u64 off = span_sc_offset(val_type);
				if (off != 0 && val != NULL) {
					read_span_context(val, off, out);
				}

				return;
			}
		}

		if (bpf_probe_read_user(&itab, sizeof(itab), node) != 0 ||
		    bpf_probe_read_user(&node, sizeof(node), node + GO_IFACE_DATA_OFF) != 0) {
			return;
		}
	}
}

// Context extraction params: context_pos 0 = no context (e.g. process()).
// passed_as_arg: 1 = context.Context as direct arg, 0 = context inside struct.
// handled_msg: the *ReceiveContext / *GrainContext a handling span belongs to,
// whose enqueue span becomes its parent; NULL for every other span.
static __always_inline void start_span_and_store_msg(struct pt_regs *ctx, void *key,
						     struct uprobe_data_t *uprobe_data,
						     u8 event_type, void *map,
						     int context_pos, u64 context_offset,
						     bool passed_as_arg, void *handled_msg) {
	__builtin_memset(uprobe_data, 0, sizeof(struct uprobe_data_t));

	struct goakt_actor_span_t *span = &uprobe_data->span;
	span->event_type = event_type;
	span->handled_successfully = 1; /* default success; handleReceivedError sets 0 */
	span->start_time = bpf_ktime_get_ns();
	uprobe_data->frame_depth = frame_depth(ctx);
	uprobe_data->handled_msg = (u64)handled_msg;

	struct go_iface go_context = {0};
	if (context_pos > 0) {
		get_Go_context(ctx, context_pos, context_offset, passed_as_arg,
				&go_context);
	}

	struct goid_parent_handle goid_handle = {
		.ctx = ctx,
		.go_context = &go_context,
		.handled_msg = (u64)handled_msg,
		.tracked_psc = &uprobe_data->tracked_psc,
	};
	start_span_params_t start_span_params = {
		.ctx = ctx,
		.go_context = &go_context,
		.psc = &span->psc,
		.sc = &span->sc,
		.get_parent_span_context_fn = get_parent_span_context_goid_first,
		.get_parent_span_context_arg = &goid_handle,
	};
	start_span(&start_span_params);

	if (go_context.data != NULL) {
		start_tracking_span(go_context.data, &span->sc);
	}

	/* Save any goid->sc entry we are about to shadow so the outer span's
	 * propagation is restored when this (nested) span ends. */
	void *goid_key = (void *)GOROUTINE(ctx);
	struct span_context *existing =
		bpf_map_lookup_elem(&goakt_actor_goid_to_span_context, &goid_key);
	if (existing != NULL) {
		uprobe_data->prev_goid_sc = *existing;
		uprobe_data->had_prev_goid = 1;
	}
	bpf_map_update_elem(&goakt_actor_goid_to_span_context, &goid_key, &span->sc, 0);

	bpf_map_update_elem(map, &key, uprobe_data, 0);
}

static __always_inline void start_span_and_store(struct pt_regs *ctx, void *key,
						 struct uprobe_data_t *uprobe_data,
						 u8 event_type, void *map,
						 int context_pos, u64 context_offset,
						 bool passed_as_arg) {
	start_span_and_store_msg(ctx, key, uprobe_data, event_type, map, context_pos,
				 context_offset, passed_as_arg, NULL);
}

static __always_inline void finish_span_and_output(struct pt_regs *ctx, void *key,
						  void *map) {
	u64 end_time = bpf_ktime_get_ns();

	struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(map, &key);
	if (uprobe_data == NULL) {
		return;
	}

	if (uprobe_data->depth > 0) {
		/* Inner return of a same-symbol re-entry: keep the span until the
		 * outermost return so its end time is not truncated. The map value
		 * is modified in place. */
		uprobe_data->depth--;
		return;
	}

	struct goakt_actor_span_t *span = &uprobe_data->span;
	span->end_time = end_time;

	output_span_event(ctx, span, sizeof(*span), &span->sc);
	stop_tracking_span(&span->sc, &uprobe_data->tracked_psc);
	if (uprobe_data->handled_msg != 0) {
		release_enqueue(uprobe_data->handled_msg, &span->psc);
	}

	/* Restore the goid->sc entry we shadowed on entry (if any) so an outer
	 * span keeps propagating; only delete when we were the outermost. */
	void *goid_key = (void *)GOROUTINE(ctx);
	if (uprobe_data->had_prev_goid) {
		bpf_map_update_elem(&goakt_actor_goid_to_span_context, &goid_key,
				    &uprobe_data->prev_goid_sc, 0);
	} else {
		bpf_map_delete_elem(&goakt_actor_goid_to_span_context, &goid_key);
	}

	bpf_map_delete_elem(map, &key);
}

// --- (*PID).doReceive ---
SEC("uprobe/doReceive")
int uprobe_doReceive(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_do_receive, key)) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	u64 msg = (u64)get_argument(ctx, 2);
	if (continues_build((u64)key, msg)) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_DO_RECEIVE,
			    &goakt_actor_do_receive, 2,
			    receive_context_ctx_offset, false);
	bpf_map_update_elem(&goakt_actor_enqueued, &msg, &uprobe_data->span.sc, BPF_ANY);
	return 0;
}

SEC("uprobe/doReceive_Returns")
int uprobe_doReceive_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_do_receive);
	bpf_map_delete_elem(&goakt_actor_built, &key);
	return 0;
}

// --- (*ReceiveContext).build ---
// Called for every Tell/Ask before doReceive. The user's context.Context is
// a direct argument (not yet wrapped by WithoutCancel), and the receiver is
// the pooled *ReceiveContext used to correlate handleReceived.
SEC("uprobe/receiveContextBuild")
int uprobe_receiveContextBuild(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_receive_ctx_build, key)) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	u64 msg = (u64)get_argument(ctx, 1);
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_DO_RECEIVE,
			    &goakt_actor_receive_ctx_build, 2, 0, true);
	bpf_map_update_elem(&goakt_actor_enqueued, &msg, &uprobe_data->span.sc, BPF_ANY);
	bpf_map_update_elem(&goakt_actor_built, &key, &msg, BPF_ANY);
	return 0;
}

SEC("uprobe/receiveContextBuild_Returns")
int uprobe_receiveContextBuild_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_receive_ctx_build);
	return 0;
}

// --- (*actorSystem).handleRemoteTell ---
SEC("uprobe/handleRemoteTell")
int uprobe_handleRemoteTell(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_remote_tell, key)) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_TELL,
			    &goakt_actor_remote_tell, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_ask, key)) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ASK,
			    &goakt_actor_remote_ask, 2, 0, true);
	return 0;
}

SEC("uprobe/handleRemoteAsk_Returns")
int uprobe_handleRemoteAsk_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_ask);
	return 0;
}

// --- (*PID).handleReceived --- (actual message handling on a dispatcher
// worker goroutine; the "actor.process" span). Its parent is the doReceive
// (enqueue) span, resolved in userspace via the shared *ReceiveContext pointer.
SEC("uprobe/handleReceived")
int uprobe_handleReceived(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_process, key)) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store_msg(ctx, key, uprobe_data, EVENT_TYPE_PROCESS,
				 &goakt_actor_process, 0, 0, false, get_argument(ctx, 2));
	return 0;
}

SEC("uprobe/handleReceived_Returns")
int uprobe_handleReceived_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_process);
	return 0;
}

// --- (*grainPID).receive --- (enqueue into the grain mailbox on the caller's
// goroutine; the "grain.doReceive" span, parent of the grain handling span).
SEC("uprobe/grainReceive")
int uprobe_grainReceive(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_grain_do_receive, key)) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_GRAIN_DO_RECEIVE,
			    &goakt_actor_grain_do_receive, 2,
			    grain_context_ctx_offset, false);
	u64 msg = (u64)get_argument(ctx, 2);
	bpf_map_update_elem(&goakt_actor_enqueued, &msg, &uprobe_data->span.sc, BPF_ANY);
	return 0;
}

SEC("uprobe/grainReceive_Returns")
int uprobe_grainReceive_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_grain_do_receive);
	return 0;
}

// --- (*grainPID).handleGrainContext --- (actual grain handling on a dispatcher
// worker goroutine; the "grain.process" span, linked under grain.doReceive via
// the shared *GrainContext pointer).
SEC("uprobe/handleGrainContext")
int uprobe_handleGrainContext(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_grain_process, key)) {
		return 0;
	}

	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}

	start_span_and_store_msg(ctx, key, uprobe_data, EVENT_TYPE_GRAIN_PROCESS,
				 &goakt_actor_grain_process, 0, 0, false, get_argument(ctx, 2));
	return 0;
}

SEC("uprobe/handleGrainContext_Returns")
int uprobe_handleGrainContext_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_grain_process);
	return 0;
}

// --- (*actorSystem).Spawn ---
SEC("uprobe/Spawn")
int uprobe_Spawn(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_system_spawn, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_SYSTEM_SPAWN,
			    &goakt_actor_system_spawn, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_spawn_on, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_SPAWN_ON,
			    &goakt_actor_spawn_on, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_spawn_child, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_SPAWN_CHILD,
			    &goakt_actor_spawn_child, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_spawn, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_SPAWN,
			    &goakt_actor_remote_spawn, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_spawn_child, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_SPAWN_CHILD,
			    &goakt_actor_remote_spawn_child, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_tell_receive, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_TELL_RECEIVE,
			    &goakt_actor_remote_tell_receive, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_ask_receive, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ASK_RECEIVE,
			    &goakt_actor_remote_ask_receive, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_relocation, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_RELOCATION,
			    &goakt_actor_relocation, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_tell_grain, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_TELL_GRAIN,
			    &goakt_actor_remote_tell_grain, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_ask_grain, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ASK_GRAIN,
			    &goakt_actor_remote_ask_grain, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_lookup, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_LOOKUP,
			    &goakt_actor_remote_lookup, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_re_spawn, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_RE_SPAWN,
			    &goakt_actor_remote_re_spawn, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_stop, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_STOP,
			    &goakt_actor_remote_stop, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_ask_grain_receive, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ASK_GRAIN_RECEIVE,
			    &goakt_actor_remote_ask_grain_receive, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_tell_grain_receive, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_TELL_GRAIN_RECEIVE,
			    &goakt_actor_remote_tell_grain_receive, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_activate_grain, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ACTIVATE_GRAIN,
			    &goakt_actor_remote_activate_grain, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_reinstate, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_REINSTATE,
			    &goakt_actor_remote_reinstate, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_passivation_strategy, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_PASSIVATION_STRATEGY,
			    &goakt_actor_remote_passivation_strategy, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_state, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_STATE,
			    &goakt_actor_remote_state, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_children, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_CHILDREN,
			    &goakt_actor_remote_children, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_parent, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_PARENT,
			    &goakt_actor_remote_parent, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_kind, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_KIND,
			    &goakt_actor_remote_kind, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_dependencies, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_DEPENDENCIES,
			    &goakt_actor_remote_dependencies, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_metric, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_METRIC,
			    &goakt_actor_remote_metric, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_role, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_ROLE,
			    &goakt_actor_remote_role, 2, 0, true);
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
	if (actor_reentered(ctx, &goakt_actor_remote_stash_size, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_REMOTE_STASH_SIZE,
			    &goakt_actor_remote_stash_size, 2, 0, true);
	return 0;
}
SEC("uprobe/remoteStashSizeHandler_Returns")
int uprobe_remoteStashSizeHandler_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_remote_stash_size);
	return 0;
}

// --- (*actorSystem).ActorOf ---
SEC("uprobe/ActorOf")
int uprobe_ActorOf(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_actor_of, key)) {
		return 0;
	}
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data =
		bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) {
		return 0;
	}
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_ACTOR_OF,
			    &goakt_actor_actor_of, 2, 0, true);
	return 0;
}
SEC("uprobe/ActorOf_Returns")
int uprobe_ActorOf_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_actor_of);
	return 0;
}

#define PROBE_ENTRY_RETURN(name, map, event_type) \
SEC("uprobe/" #name) \
int uprobe_##name(struct pt_regs *ctx) { \
	void *key = (void *)GOROUTINE(ctx); \
	if (bpf_map_lookup_elem(&map, &key) != NULL) return 0; \
	u32 map_id = 0; \
	struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id); \
	if (uprobe_data == NULL) return 0; \
	start_span_and_store(ctx, key, uprobe_data, event_type, &map, 2, 0, true); \
	return 0; \
} \
SEC("uprobe/" #name "_Returns") \
int uprobe_##name##_Returns(struct pt_regs *ctx) { \
	void *key = (void *)GOROUTINE(ctx); \
	finish_span_and_output(ctx, key, &map); \
	return 0; \
}

PROBE_ENTRY_RETURN(SpawnNamedFromFunc, goakt_actor_spawn_named_from_func, EVENT_TYPE_SPAWN_NAMED_FROM_FUNC)
PROBE_ENTRY_RETURN(SpawnFromFunc, goakt_actor_spawn_from_func, EVENT_TYPE_SPAWN_FROM_FUNC)
PROBE_ENTRY_RETURN(SpawnRouter, goakt_actor_spawn_router, EVENT_TYPE_SPAWN_ROUTER)
PROBE_ENTRY_RETURN(SpawnSingleton, goakt_actor_spawn_singleton, EVENT_TYPE_SPAWN_SINGLETON)
PROBE_ENTRY_RETURN(Kill, goakt_actor_kill, EVENT_TYPE_KILL)
PROBE_ENTRY_RETURN(ReSpawn, goakt_actor_re_spawn, EVENT_TYPE_RE_SPAWN)
PROBE_ENTRY_RETURN(ActorExists, goakt_actor_actor_exists, EVENT_TYPE_ACTOR_EXISTS)
PROBE_ENTRY_RETURN(Actors, goakt_actor_actors, EVENT_TYPE_ACTORS)
PROBE_ENTRY_RETURN(Start, goakt_actor_start, EVENT_TYPE_START)
PROBE_ENTRY_RETURN(ScheduleOnce, goakt_actor_schedule_once, EVENT_TYPE_SCHEDULE_ONCE)
PROBE_ENTRY_RETURN(Schedule, goakt_actor_schedule, EVENT_TYPE_SCHEDULE)
PROBE_ENTRY_RETURN(ScheduleWithCron, goakt_actor_schedule_with_cron, EVENT_TYPE_SCHEDULE_WITH_CRON)
PROBE_ENTRY_RETURN(TellGrain, goakt_actor_tell_grain, EVENT_TYPE_TELL_GRAIN)
PROBE_ENTRY_RETURN(AskGrain, goakt_actor_ask_grain, EVENT_TYPE_ASK_GRAIN)

/* actorSystem.Stop and actorSystem.Metric - unique SEC names to avoid PID conflict */
SEC("uprobe/actorSystem_Stop")
int uprobe_actorSystem_Stop(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_stop, key)) return 0;
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) return 0;
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_STOP, &goakt_actor_stop, 2, 0, true);
	return 0;
}
SEC("uprobe/actorSystem_Stop_Returns")
int uprobe_actorSystem_Stop_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_stop);
	return 0;
}
SEC("uprobe/actorSystem_Metric")
int uprobe_actorSystem_Metric(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_system_metric, key)) return 0;
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) return 0;
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_SYSTEM_METRIC, &goakt_actor_system_metric, 2, 0, true);
	return 0;
}
SEC("uprobe/actorSystem_Metric_Returns")
int uprobe_actorSystem_Metric_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_system_metric);
	return 0;
}

#undef PROBE_ENTRY_RETURN

// --- (*PID) methods (same package, different receiver) ---
#define PROBE_PID_ENTRY_RETURN(name, map, event_type) \
SEC("uprobe/" #name) \
int uprobe_##name(struct pt_regs *ctx) { \
	void *key = (void *)GOROUTINE(ctx); \
	if (bpf_map_lookup_elem(&map, &key) != NULL) return 0; \
	u32 map_id = 0; \
	struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id); \
	if (uprobe_data == NULL) return 0; \
	start_span_and_store(ctx, key, uprobe_data, event_type, &map, 2, 0, true); \
	return 0; \
} \
SEC("uprobe/" #name "_Returns") \
int uprobe_##name##_Returns(struct pt_regs *ctx) { \
	void *key = (void *)GOROUTINE(ctx); \
	finish_span_and_output(ctx, key, &map); \
	return 0; \
}

PROBE_PID_ENTRY_RETURN(Tell, goakt_actor_tell, EVENT_TYPE_TELL)
PROBE_PID_ENTRY_RETURN(Ask, goakt_actor_ask, EVENT_TYPE_ASK)
PROBE_PID_ENTRY_RETURN(SendAsync, goakt_actor_send_async, EVENT_TYPE_SEND_ASYNC)
PROBE_PID_ENTRY_RETURN(SendSync, goakt_actor_send_sync, EVENT_TYPE_SEND_SYNC)
PROBE_PID_ENTRY_RETURN(DiscoverActor, goakt_actor_discover_actor, EVENT_TYPE_DISCOVER_ACTOR)
PROBE_PID_ENTRY_RETURN(Restart, goakt_actor_restart, EVENT_TYPE_RESTART)
PROBE_PID_ENTRY_RETURN(ReinstateNamed, goakt_actor_reinstate_named, EVENT_TYPE_REINSTATE_NAMED)
PROBE_PID_ENTRY_RETURN(PipeTo, goakt_actor_pipe_to, EVENT_TYPE_PIPE_TO)
PROBE_PID_ENTRY_RETURN(PipeToName, goakt_actor_pipe_to_name, EVENT_TYPE_PIPE_TO_NAME)
PROBE_PID_ENTRY_RETURN(BatchTell, goakt_actor_batch_tell, EVENT_TYPE_BATCH_TELL)
PROBE_PID_ENTRY_RETURN(BatchAsk, goakt_actor_batch_ask, EVENT_TYPE_BATCH_ASK)
PROBE_PID_ENTRY_RETURN(RemoteLookup, goakt_actor_pid_remote_lookup, EVENT_TYPE_PID_REMOTE_LOOKUP)
PROBE_PID_ENTRY_RETURN(RemoteStop, goakt_actor_pid_remote_stop, EVENT_TYPE_PID_REMOTE_STOP)
PROBE_PID_ENTRY_RETURN(RemoteReSpawn, goakt_actor_pid_remote_re_spawn, EVENT_TYPE_PID_REMOTE_RE_SPAWN)
PROBE_PID_ENTRY_RETURN(Shutdown, goakt_actor_shutdown, EVENT_TYPE_SHUTDOWN)

/* PID.Stop and PID.Metric - unique SEC names to avoid actorSystem conflict */
SEC("uprobe/pid_Stop")
int uprobe_pid_Stop(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_pid_stop, key)) return 0;
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) return 0;
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_PID_STOP, &goakt_actor_pid_stop, 2, 0, true);
	return 0;
}
SEC("uprobe/pid_Stop_Returns")
int uprobe_pid_Stop_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_pid_stop);
	return 0;
}
SEC("uprobe/pid_Metric")
int uprobe_pid_Metric(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	if (actor_reentered(ctx, &goakt_actor_pid_metric, key)) return 0;
	u32 map_id = 0;
	struct uprobe_data_t *uprobe_data = bpf_map_lookup_elem(&goakt_actor_uprobe_storage_map, &map_id);
	if (uprobe_data == NULL) return 0;
	start_span_and_store(ctx, key, uprobe_data, EVENT_TYPE_PID_METRIC, &goakt_actor_pid_metric, 2, 0, true);
	return 0;
}
SEC("uprobe/pid_Metric_Returns")
int uprobe_pid_Metric_Returns(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);
	finish_span_and_output(ctx, key, &goakt_actor_pid_metric);
	return 0;
}

#undef PROBE_PID_ENTRY_RETURN

// --- (*PID).handleReceivedError ---
// Called from within doReceive when message handling fails. Marks the active
// doReceive span as handled_successfully=0 so it will be emitted with failure status.
SEC("uprobe/handleReceivedError")
int uprobe_handleReceivedError(struct pt_regs *ctx) {
	void *key = (void *)GOROUTINE(ctx);

	/* handleReceivedError runs either on the sender goroutine (enqueue errors,
	 * doReceive span) or on a dispatcher worker (handling errors, process
	 * span). Mark whichever span is active on this goroutine. */
	struct uprobe_data_t *d = bpf_map_lookup_elem(&goakt_actor_do_receive, &key);
	if (d != NULL) {
		d->span.handled_successfully = 0;
	}
	d = bpf_map_lookup_elem(&goakt_actor_process, &key);
	if (d != NULL) {
		d->span.handled_successfully = 0;
	}
	return 0;
}
