# Architecture

## Overview

goakt-ebpf is a standalone eBPF agent that instruments [GoAkt](https://github.com/tochemey/goakt) applications without code changes. It attaches uprobes to GoAkt runtime functions and exports traces via OpenTelemetry Protocol (OTLP).

## What is eBPF?

**eBPF** (extended Berkeley Packet Filter) is a Linux kernel technology that allows running sandboxed programs in the kernel without changing kernel source code or loading modules. For goakt-ebpf, we use **uprobes** — user-space probes that attach to function entry and exit points in the target process. When a GoAkt application handles a message, the eBPF program runs in kernel space, records timestamps and IDs, and sends events to userspace via a perf buffer. This approach is safe, low-overhead, and requires no instrumentation in your application code.

## Components

```
┌────────────────────────────────────────────────────────────────────────────┐
│                              goakt-ebpf                                    │
├────────────────────────────────────────────────────────────────────────────┤
│  CLI (cmd/cli)                                                             │
│    ├── Resolve target PID (-pid, -exe, GOAKT_EBPF_TARGET_PID)              │
│    └── Start instrumentation manager                                       │
├────────────────────────────────────────────────────────────────────────────┤
│  Instrumentation Manager (internal/instrumentation)                        │
│    ├── Load eBPF probes (uprobes on GoAkt symbols)                         │
│    ├── Process perf events → spans                                         │
│    └── Export via OTLP (pipeline/otelsdk)                                  │
├────────────────────────────────────────────────────────────────────────────┤
│  Process (internal/process)                                                │
│    ├── Symbol lookup, function offsets (DWARF)                             │
│    └── Allocation map for entry/return correlation                         │
├────────────────────────────────────────────────────────────────────────────┤
│  GoAkt Probes (internal/instrumentation/bpf/.../actor)                     │
│    ├── probe.go — probe config, span processing                            │
│    └── bpf/probe.bpf.c — eBPF C (uprobes, perf output)                     │
└────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

1. **Attach**: Agent resolves target PID, loads eBPF programs, attaches uprobes to GoAkt symbols.
2. **Capture**: On function entry, eBPF allocates a span slot (keyed by goroutine ID), records start time, generates span/trace IDs. On function return (or `handleReceivedError` for failure), eBPF records end time and outputs the span via perf buffer.
3. **Correlate (Go-side)**: For each perf event, the span processor resolves parent context through two mechanisms:
   - **Userspace context reading**: When `context_ptr` is non-zero, reads the target process memory via `process_vm_readv(2)` to extract an OTEL span from the app's `context.Context` chain. Overrides the BPF-assigned TraceID/ParentSpanID with the app's values.
   - **Enqueue/handling correlation**: GoAkt v4 delivers a message by enqueueing it (`doReceive`/`receive`, on the caller goroutine) and later handling it on a dispatcher worker (`handleReceived`/`handleGrainContext`, a different goroutine). The two share the `*ReceiveContext`/`*GrainContext` pointer, emitted as `receive_ctx_ptr`. The enqueue span resolves its own app-level trace, and the handling span inherits that TraceID and is parented under it. See [Enqueue/Handling Correlation](#enqueuehandling-correlation).
4. **Export**: Converts events to OTLP spans and exports to configured endpoint (e.g. OTel Collector, Jaeger).

## Probe Model

Each instrumented function has:

- **Entry uprobe**: Allocates span, records start time, generates IDs, stores in per-goroutine map.
- **Return uprobe**: Records end time, outputs span, deallocates.
- **Optional failure probe** (e.g. `handleReceivedError`): Marks active span as failed; uses `FailureModeWarn` so missing symbols don't block load.

## Instrumented Symbols (GoAkt v4)

Full reference of probe targets, span names, and attributes. Symbols use the full package path `github.com/tochemey/goakt/v4/actor`.

### Message handling (PID)

GoAkt v4 message handling is asynchronous: the message is enqueued into the actor's mailbox on the caller's goroutine, then handled later on a dispatcher worker goroutine. The enqueue produces the `doReceive` span and the handling produces the `process` span; the two are linked by the shared `*ReceiveContext`/`*GrainContext` pointer (see [Enqueue/Handling Correlation](#enqueuehandling-correlation)).

| Symbol                           | Span                     | Role    | Attributes                                                  |
|----------------------------------|--------------------------|---------|-------------------------------------------------------------|
| `(*PID).doReceive`               | actor.doReceive          | enqueue | received_timestamp, handled_timestamp, handled_successfully |
| `(*PID).handleReceived`          | actor.process            | handle  | actor.type=pid                                              |
| `(*grainPID).receive`            | grain.doReceive          | enqueue | received_timestamp, handled_timestamp, handled_successfully |
| `(*grainPID).handleGrainContext` | grain.process            | handle  | actor.type=grain                                            |
| `(*PID).handleReceivedError`     | (marks active span failed) | —     | handled_successfully=false                                  |

### Local messaging (PID)

| Symbol             | Span            | Attributes     |
|--------------------|-----------------|----------------|
| `(*PID).Tell`      | actor.tell      | sent_timestamp |
| `(*PID).Ask`       | actor.ask       | sent_timestamp |
| `(*PID).SendAsync` | actor.sendAsync | sent_timestamp |
| `(*PID).SendSync`  | actor.sendSync  | sent_timestamp |
| `(*PID).BatchTell` | actor.batchTell | sent_timestamp |
| `(*PID).BatchAsk`  | actor.batchAsk  | sent_timestamp |

### Local grain messaging (System)

`(*actorSystem).TellGrain` and `(*actorSystem).AskGrain` are the local grain send entry points. `GrainContext.TellGrain`/`AskGrain` delegate to them, so grain-to-grain sends are covered by the same probes.

| Symbol                     | Span       | Attributes     |
|----------------------------|------------|----------------|
| `(*actorSystem).TellGrain` | grain.tell | sent_timestamp |
| `(*actorSystem).AskGrain`  | grain.ask  | sent_timestamp |

### Remote messaging (System)

| Symbol                                      | Span                          | Attributes                            |
|---------------------------------------------|-------------------------------|---------------------------------------|
| `(*actorSystem).handleRemoteTell`           | actorSystem.remoteTell        | sent_timestamp                        |
| `(*actorSystem).handleRemoteAsk`            | actorSystem.remoteAsk         | sent_timestamp                        |
| `(*actorSystem).remoteTellHandler`          | actorSystem.remoteTellReceive | received_timestamp                    |
| `(*actorSystem).remoteAskHandler`           | actorSystem.remoteAskReceive  | received_timestamp                    |
| `(*actorSystem).remoteTellGrain`            | grain.remoteTell              | sent_timestamp                        |
| `(*actorSystem).remoteAskGrain`             | grain.remoteAsk               | sent_timestamp                        |
| `(*actorSystem).remoteAskGrainHandler`      | grain.remoteAskReceive        | received_timestamp                    |
| `(*actorSystem).remoteTellGrainHandler`     | grain.remoteTellReceive       | received_timestamp                    |
| `(*actorSystem).remoteActivateGrainHandler` | grain.remoteActivate          | actor.operation=remote_activate_grain |

### Spawn lifecycle (System)

| Symbol                                   | Span                           | Attributes                            |
|------------------------------------------|--------------------------------|---------------------------------------|
| `(*actorSystem).Spawn`                   | actorSystem.spawn              | actor.operation=spawn                 |
| `(*actorSystem).SpawnOn`                 | actorSystem.spawnOn            | actor.operation=spawn_on              |
| `(*actorSystem).ActorOf`                 | actorSystem.actorOf            | actor.operation=actor_of              |
| `(*actorSystem).SpawnNamedFromFunc`      | actorSystem.spawnNamedFromFunc | actor.operation=spawn_named_from_func |
| `(*actorSystem).SpawnFromFunc`           | actorSystem.spawnFromFunc      | actor.operation=spawn_from_func       |
| `(*actorSystem).SpawnRouter`             | actorSystem.spawnRouter        | actor.operation=spawn_router          |
| `(*actorSystem).SpawnSingleton`          | actorSystem.spawnSingleton     | actor.operation=spawn_singleton       |
| `(*actorSystem).remoteSpawnHandler`      | actorSystem.remoteSpawn        | actor.operation=remote_spawn          |
| `(*actorSystem).remoteSpawnChildHandler` | actorSystem.remoteSpawnChild   | actor.operation=remote_spawn_child    |

### Spawn lifecycle (PID)

| Symbol              | Span             | Attributes                  |
|---------------------|------------------|-----------------------------|
| `(*PID).SpawnChild` | actor.spawnChild | actor.operation=spawn_child |

### Actor system operations

| Symbol                       | Span                    | Attributes                    |
|------------------------------|-------------------------|-------------------------------|
| `(*actorSystem).Start`       | actorSystem.start       | actor.operation=start         |
| `(*actorSystem).Stop`        | actorSystem.stop        | actor.operation=stop          |
| `(*actorSystem).Kill`        | actorSystem.kill        | actor.operation=kill          |
| `(*actorSystem).ReSpawn`     | actorSystem.reSpawn     | actor.operation=respawn       |
| `(*actorSystem).ActorExists` | actorSystem.actorExists | actor.operation=actor_exists  |
| `(*actorSystem).Actors`      | actorSystem.actors      | actor.operation=actors        |
| `(*actorSystem).Metric`      | actorSystem.metric      | actor.operation=system_metric |

### Scheduling (System)

| Symbol                            | Span                         | Attributes                         |
|-----------------------------------|------------------------------|------------------------------------|
| `(*actorSystem).ScheduleOnce`     | actorSystem.scheduleOnce     | actor.operation=schedule_once      |
| `(*actorSystem).Schedule`         | actorSystem.schedule         | actor.operation=schedule           |
| `(*actorSystem).ScheduleWithCron` | actorSystem.scheduleWithCron | actor.operation=schedule_with_cron |

### Remote metadata and lifecycle (System)

| Symbol                                            | Span                                  | Attributes                                  |
|---------------------------------------------------|---------------------------------------|---------------------------------------------|
| `(*actorSystem).remoteLookupHandler`              | actorSystem.remoteLookup              | actor.operation=remote_lookup               |
| `(*actorSystem).remoteReSpawnHandler`             | actorSystem.remoteReSpawn             | actor.operation=remote_respawn              |
| `(*actorSystem).remoteStopHandler`                | actorSystem.remoteStop                | actor.operation=remote_stop                 |
| `(*actorSystem).remoteReinstateHandler`           | actorSystem.remoteReinstate           | actor.operation=remote_reinstate            |
| `(*actorSystem).remotePassivationStrategyHandler` | actorSystem.remotePassivationStrategy | actor.operation=remote_passivation_strategy |
| `(*actorSystem).remoteStateHandler`               | actorSystem.remoteState               | actor.operation=remote_state                |
| `(*actorSystem).remoteChildrenHandler`            | actorSystem.remoteChildren            | actor.operation=remote_children             |
| `(*actorSystem).remoteParentHandler`              | actorSystem.remoteParent              | actor.operation=remote_parent               |
| `(*actorSystem).remoteKindHandler`                | actorSystem.remoteKind                | actor.operation=remote_kind                 |
| `(*actorSystem).remoteDependenciesHandler`        | actorSystem.remoteDependencies        | actor.operation=remote_dependencies         |
| `(*actorSystem).remoteMetricHandler`              | actorSystem.remoteMetric              | actor.operation=remote_metric               |
| `(*actorSystem).remoteRoleHandler`                | actorSystem.remoteRole                | actor.operation=remote_role                 |
| `(*actorSystem).remoteStashSizeHandler`           | actorSystem.remoteStashSize           | actor.operation=remote_stash_size           |

### Remote operations (PID)

| Symbol                 | Span                | Attributes                     |
|------------------------|---------------------|--------------------------------|
| `(*PID).RemoteLookup`  | actor.remoteLookup  | actor.operation=remote_lookup  |
| `(*PID).RemoteStop`    | actor.remoteStop    | actor.operation=remote_stop    |
| `(*PID).RemoteReSpawn` | actor.remoteReSpawn | actor.operation=remote_respawn |

### PID operations

| Symbol                  | Span                 | Attributes                      |
|-------------------------|----------------------|---------------------------------|
| `(*PID).Stop`           | actor.stop           | actor.operation=stop            |
| `(*PID).Restart`        | actor.restart        | actor.operation=restart         |
| `(*PID).Metric`         | actor.metric         | actor.operation=metric          |
| `(*PID).ReinstateNamed` | actor.reinstateNamed | actor.operation=reinstate_named |
| `(*PID).PipeTo`         | actor.pipeTo         | actor.operation=pipe_to         |
| `(*PID).PipeToName`     | actor.pipeToName     | actor.operation=pipe_to_name    |
| `(*PID).DiscoverActor`  | actor.discoverActor  | actor.operation=discover_actor  |
| `(*PID).Shutdown`       | actor.shutdown       | actor.operation=shutdown        |

### Relocation

| Symbol                  | Span             | Attributes                 |
|-------------------------|------------------|----------------------------|
| `(*relocator).Relocate` | actor.relocation | actor.operation=relocation |

## Trace Context Propagation

goakt-ebpf runs as a separate process and attaches via uprobes. Without context propagation, every span starts a new trace and appears disconnected in Jaeger/Tempo. Three mechanisms resolve parent context, and a Go-side event buffering step ensures consistent TraceIDs across the final output:

### In-Kernel Context Chain

Every probe that has access to `context.Context` calls `get_Go_context()` to read the context interface from function arguments. After creating a span, `start_tracking_span()` registers the span context in the `go_context_to_sc` map. Child calls on the same context chain find the parent via `get_parent_span_context()`, which walks the context chain looking for registered entries.

`start_span_and_store` accepts per-probe parameters (`context_pos`, `context_offset`, `passed_as_arg`) to handle both patterns:

| Context source                                                     | `passed_as_arg` | `context_pos` | `context_offset` |
|--------------------------------------------------------------------|-----------------|---------------|------------------|
| `context.Context` as direct arg (e.g. `Spawn`, `handleRemoteTell`) | true            | 2             | 0                |
| `context.Context` inside struct (e.g. `ReceiveContext`)            | false           | 2             | DWARF offset     |
| No context (e.g. `process()`)                                      | —               | 0             | —                |

This links spans that share a context (e.g. `actor.doReceive` as parent of nested calls via the same context). It does not help when the parent span comes from application-level OTEL, since `go_context_to_sc` only contains spans created by goakt-ebpf probes.

### Goroutine-Scoped Span Map

A `goid_to_span_context` eBPF map (key: goroutine ID, value: span_context) propagates context within the same goroutine. On span start the map is updated, and the previous entry (if any) is saved in the per-probe storage so it can be restored; on span end the saved outer entry is restored, or the entry is deleted when there was none. This keeps an outer span propagating after a nested span on the same goroutine ends, instead of leaving the goroutine with no registered parent. `get_parent_span_context_goid_first` tries the context chain first, then falls back to this map.

Same-symbol re-entry on one goroutine is tracked with a nesting depth counter in the per-probe map value: the entry probe bumps the depth instead of overwriting, and the return probe only emits the span (with its true end time) once the depth returns to zero. The per-probe and goid maps are `BPF_MAP_TYPE_LRU_HASH`, so an entry orphaned by a return that never fires (e.g. a probed function unwound by a Go panic) is evicted under pressure rather than eventually wedging the probe when it reaches capacity.

This links nested calls that share a goroutine (e.g. a call the actor makes while handling a message). It does not connect the enqueue and handling spans, which run on different goroutines in GoAkt v4; that link is made through the shared `*ReceiveContext` pointer instead (see [Enqueue/Handling Correlation](#enqueuehandling-correlation)).

The goid map does not connect spans across goroutines (e.g. remoting goroutine to actor goroutine).

### Userspace Context Reading

When BPF-side lookup finds no parent and `context_ptr` is non-zero, userspace reads the target process memory via `process_vm_readv(2)` to extract an OTEL span context from the Go `context.Context` chain.

The reader speculatively walks the chain, treating each node as a `valueCtx` (48 bytes). For each node it reads 256 bytes from `val.data` and probes four empirically validated span struct layouts in order of likelihood:

```
valueCtx (48 bytes):
  [0:8]   Context.itab     [8:16]  Context.data  -> parent context
  [16:24] key.type         [24:32] key.data
  [32:40] val.type         [40:48] val.data      -> concrete span struct ptr
```

#### Layout A — `trace.nonRecordingSpan` (go.opentelemetry.io/otel/trace)

```
offset  0  size 16   noopSpan (embedded.Span interface, always zero)
offset 16  size 64   sc trace.SpanContext
  [16:32] TraceID [16]byte   [32:40] SpanID [8]byte   [40] TraceFlags
```

**When it appears:** `trace.ContextWithSpanContext(ctx, sc)` — W3C/B3 remote propagation stores a `nonRecordingSpan` in context before starting the local child span.  
**Heuristic:** bytes `[0:16]` == zero; bytes `[16:24]` non-zero (start of TraceID); valid sampled TraceID/SpanID at offsets 16/32.

#### Layout B — `sdk/trace.nonRecordingSpan` (go.opentelemetry.io/otel/sdk/trace, not-sampled)

```
offset  0  size 16   embedded.Span (always zero)
offset 16  size  8   tracer *tracer (non-zero pointer)
offset 24  size 64   sc trace.SpanContext
  [24:40] TraceID [16]byte   [40:48] SpanID [8]byte   [48] TraceFlags
```

**When it appears:** `tracer.Start(ctx, "name")` with `NeverSample()` TracerProvider.  
**Heuristic:** bytes `[0:16]` == zero; bytes `[16:24]` non-zero pointer (tracer); valid sampled TraceID/SpanID at offsets 24/40. Since not-sampled spans have `TraceFlags == 0`, they are filtered out by the sampled guard and do not produce a parent link.

#### Layout C — `*sdk/trace.recordingSpan` (go.opentelemetry.io/otel/sdk/trace, sampled)

```
offset   0  size  16   embedded.Span (always zero)
offset  16  size   8   mu sync.Mutex (zero when unlocked)
offset  24  size  64   parent trace.SpanContext  <- caller's context (NOT the current span)
  ...
offset 192  size  64   spanContext trace.SpanContext  <- current span's own context
  [192:208] TraceID [16]byte   [208:216] SpanID [8]byte   [216] TraceFlags
```

**When it appears:** `tracer.Start(ctx, "name")` with a sampled `TracerProvider` — this is what `otelhttp`, `otelgrpc`, and all standard instrumentation libraries create. **This is the most common layout for HTTP and gRPC parent spans.**  
**Heuristic:** bytes `[0:16]` == zero (embedded.Span); bytes `[16:24]` (mutex) are **not** checked — the mutex can be locked during an active HTTP/gRPC handler, which is normal. Valid sampled TraceID/SpanID at offsets 192/208.  
**Key insight:** `parent` at offset 24 holds the *caller's* span context (used when building the trace tree on export). `spanContext` at offset 192 is the *current* span's own ID, which goakt-ebpf needs as the parent for actor spans. Reading at the wrong offset (16 or 24) yields the mutex or partial parent TraceID — not the current span.

#### Layout D — `*auto/sdk.span` (go.opentelemetry.io/auto/sdk) — Not Supported

```
offset  0  size 80   noop.Span (embedded.Span[16] + sc SpanContext[64], all zero in user-space)
offset 80  size 64   spanContext trace.SpanContext  <- zero-initialized; never populated in user-space
```

**When it appears:** `tracer.Start(ctx, "name")` with `autosdk.TracerProvider()`.  
**Limitation:** The `spanContext` field is zero-initialized at span creation and never populated in user-space — the eBPF instrumentation layer fills it via kernel probes. The userspace context reader cannot extract parent context from Auto SDK spans. **eBPF-level probes on `tracer.Start` are required** for parent-child correlation when using the Auto SDK.

#### Probe Order and Sampled Guard

All layouts share `embedded.Span` (16 zero bytes) at offset 0 — this is checked first to reject non-span objects. Layouts are then probed in order C → A → B:
- Layout C does **not** require `bytes[16:24]` (mutex) to be zero, since the mutex can be locked during an active HTTP/gRPC handler.
- Layouts A and B are tried when Layout C doesn't match, using `bytes[16:24]` to discriminate between them.
- Not-sampled spans (Layout B) are still returned; the caller decides whether to use them.

Set `GOAKT_EBPF_DEBUG_CONTEXT_READER=1` to enable verbose per-node logging that reports which layout matched and how many nodes were visited.

This connects goakt-ebpf spans to application-level OTEL spans (HTTP, gRPC, manual, or remote) and to remote trace context injected by GoAkt's `ContextPropagator`.

**Limitations:**
- `valueCtx` layout is stable since Go 1.7 but not a public API.
- Span struct layouts are empirically validated against `go.opentelemetry.io/otel v1.41.0` and `go.opentelemetry.io/auto/sdk v1.2.1`. Offsets are recorded in `internal/inject/offset_results.json`.
- Auto SDK parent extraction requires eBPF-level probes (not supported via the userspace reader).
- Requires `CAP_SYS_PTRACE` (already required for uprobes).

### Enqueue/Handling Correlation

GoAkt v4 handles a message asynchronously. `doReceive` (for actors) and `receive` (for grains) run on the caller's goroutine and only enqueue the message into the mailbox. A dispatcher worker later handles it on a different goroutine via `handleReceived` (actors) or `handleGrainContext` (grains). So the `doReceive`/`process` parent-child pair no longer share a goroutine, and the goid map cannot link them.

The link is made through the `*ReceiveContext`/`*GrainContext` pointer, which is the same object from enqueue to handling (it flows through the mailbox unchanged). Both probes emit it as `receive_ctx_ptr`. The enqueue span resolves its own app-level trace via userspace context reading; `makeProcessFn` records that resolved `{TraceID, SpanID}` keyed by the pointer, and the handling span inherits the TraceID and is parented under the enqueue span's SpanID:

```
Event arrival (usual order):
  1. doReceive event (context_ptr + receive_ctx_ptr set) → userspace extraction → app TraceID
     └── record link[receive_ctx_ptr] = {app TraceID, doReceive SpanID}, emit doReceive
  2. handleReceived event (receive_ctx_ptr set)          → look up link → inherit TraceID + parent, emit

Result:
  app_span (app TraceID)
    └── actor.doReceive (app TraceID, parent = app_span)
          └── actor.process (app TraceID, parent = doReceive)
```

The perf ring does not guarantee cross-CPU ordering, so a handling event may arrive before its enqueue. In that case the handling event is buffered by `receive_ctx_ptr` and emitted when the enqueue resolves the link. Both the link map and the pending-handling buffer are bounded (`maxEntries = 512`) with arbitrary-entry eviction (logged) on overflow. Events are processed serially in `SpanProducer.Run`, so no locking is needed. If an enqueue never produces a handling (message dropped), its link entry is eventually evicted as newer entries fill the map. A handling event whose `receive_ctx_ptr` is zero (correlation unavailable) is emitted immediately as an unlinked span.

### Context Extraction by Method

| Symbol                            | Context source | `passed_as_arg` | `context_pos` | `context_offset`                |
|-----------------------------------|----------------|-----------------|---------------|---------------------------------|
| `(*PID).doReceive`                | ReceiveContext | false           | 2             | DWARF: `ReceiveContext.ctx`     |
| `(*grainPID).receive`             | GrainContext   | false           | 2             | DWARF: `GrainContext.ctx`       |
| `(*actorSystem).handleRemoteTell` | Direct arg     | true            | 2             | 0                               |
| `(*actorSystem).handleRemoteAsk`  | Direct arg     | true            | 2             | 0                               |
| `(*actorSystem).Spawn`            | Direct arg     | true            | 2             | 0                               |
| `(*actorSystem).SpawnOn`          | Direct arg     | true            | 2             | 0                               |
| `(*PID).SpawnChild`               | Direct arg     | true            | 2             | 0                               |
| `(*actorSystem).remote*Handler`   | Direct arg     | true            | 2             | 0                               |
| `(*actorSystem).remoteTellGrain`  | Direct arg     | true            | 2             | 0                               |
| `(*actorSystem).remoteAskGrain`   | Direct arg     | true            | 2             | 0                               |
| `(*actorSystem).TellGrain`        | Direct arg     | true            | 2             | 0                               |
| `(*actorSystem).AskGrain`         | Direct arg     | true            | 2             | 0                               |
| `(*relocator).Relocate`           | Direct arg     | true            | 2             | 0                               |
| `(*PID).handleReceived`           | No context     | —               | 0             | —                               |
| `(*grainPID).handleGrainContext`  | No context     | —               | 0             | —                               |

## Dependencies

- **Cilium eBPF** — Load and attach eBPF programs.
- **OpenTelemetry** — Span model, OTLP export.
- **internal/include** — eBPF C headers (from OpenTelemetry Go Instrumentation).

## Deployment

- **Linux required**: eBPF is a Linux kernel feature.
- **Capabilities**: `SYS_PTRACE`, `SYS_ADMIN`, `BPF`, `PERFMON`.
- **PID namespace**: When running in Docker, share PID namespace with the target (`--pid=container:TARGET`) so the agent can attach.
- **Non-root**: The Docker image runs as non-root; capabilities are added at runtime.
