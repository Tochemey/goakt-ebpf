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
2. **Capture**: On function entry, eBPF allocates a span slot (keyed by goroutine ID), records start time, generates span/trace IDs.
3. **Correlate**: On function return (or `handleReceivedError` for failure), eBPF records end time and outputs the span via perf buffer.
4. **Export**: Userspace reads perf events, converts to OTLP spans, exports to configured endpoint (e.g. OTel Collector, Jaeger).

## Probe Model

Each instrumented function has:

- **Entry uprobe**: Allocates span, records start time, generates IDs, stores in per-goroutine map.
- **Return uprobe**: Records end time, outputs span, deallocates.
- **Optional failure probe** (e.g. `handleReceivedError`): Marks active span as failed; uses `FailureModeWarn` so missing symbols don't block load.

## Instrumented Symbols (GoAkt v4)

Full reference of probe targets, span names, and attributes:

| Symbol                                            | Span                            | Attributes                                                  |
|---------------------------------------------------|---------------------------------|-------------------------------------------------------------|
| `(*PID).doReceive`                                | actor.doReceive                 | received_timestamp, handled_timestamp, handled_successfully |
| `(*grainPID).handleGrainContext`                  | actor.grainDoReceive            | received_timestamp, handled_timestamp, handled_successfully |
| `(*actorSystem).handleRemoteTell`                 | actor.remoteTell                | sent_timestamp                                              |
| `(*actorSystem).handleRemoteAsk`                  | actor.remoteAsk                 | sent_timestamp                                              |
| `(*actorSystem).remoteTellHandler`                | actor.remoteTellReceive         | received_timestamp                                          |
| `(*actorSystem).remoteAskHandler`                 | actor.remoteAskReceive          | received_timestamp                                          |
| `(*actorSystem).remoteTellGrain`                  | actor.remoteTellGrain           | sent_timestamp (grain client)                               |
| `(*actorSystem).remoteAskGrain`                   | actor.remoteAskGrain            | sent_timestamp (grain client)                               |
| `(*actorSystem).Spawn`                            | actor.systemSpawn               | actor.operation=spawn                                       |
| `(*actorSystem).SpawnOn`                          | actor.spawnOn                   | actor.operation=spawn_on (remote placement, optional)       |
| `(*actorSystem).remoteSpawnHandler`               | actor.remoteSpawn               | actor.operation=remote_spawn                                |
| `(*actorSystem).remoteSpawnChildHandler`          | actor.remoteSpawnChild          | actor.operation=remote_spawn_child                          |
| `(*actorSystem).remoteLookupHandler`              | actor.remoteLookup              | actor.operation=remote_lookup                               |
| `(*actorSystem).remoteReSpawnHandler`             | actor.remoteReSpawn             | actor.operation=remote_respawn                              |
| `(*actorSystem).remoteStopHandler`                | actor.remoteStop                | actor.operation=remote_stop                                 |
| `(*actorSystem).remoteAskGrainHandler`            | actor.remoteAskGrainReceive     | received_timestamp (grain server)                           |
| `(*actorSystem).remoteTellGrainHandler`           | actor.remoteTellGrainReceive    | received_timestamp (grain server)                           |
| `(*actorSystem).remoteActivateGrainHandler`       | actor.remoteActivateGrain       | actor.operation=remote_activate_grain                       |
| `(*actorSystem).remoteReinstateHandler`           | actor.remoteReinstate           | actor.operation=remote_reinstate                            |
| `(*actorSystem).remotePassivationStrategyHandler` | actor.remotePassivationStrategy | (optional)                                                  |
| `(*actorSystem).remoteStateHandler`               | actor.remoteState               | (optional)                                                  |
| `(*actorSystem).remoteChildrenHandler`            | actor.remoteChildren            | (optional)                                                  |
| `(*actorSystem).remoteParentHandler`              | actor.remoteParent              | (optional)                                                  |
| `(*actorSystem).remoteKindHandler`                | actor.remoteKind                | (optional)                                                  |
| `(*actorSystem).remoteDependenciesHandler`        | actor.remoteDependencies        | (optional)                                                  |
| `(*actorSystem).remoteMetricHandler`              | actor.remoteMetric              | (optional)                                                  |
| `(*actorSystem).remoteRoleHandler`                | actor.remoteRole                | (optional)                                                  |
| `(*actorSystem).remoteStashSizeHandler`           | actor.remoteStashSize           | (optional)                                                  |
| `(*PID).process`                                  | actor.process                   | actor.type=pid                                              |
| `(*PID).SpawnChild`                               | actor.spawnChild                | actor.operation=spawn_child                                 |
| `(*grainPID).process`                             | actor.grainProcess              | actor.type=grain                                            |
| `(*relocator).Relocate`                           | actor.relocation                | actor.operation=relocation (optional)                       |
| `(*PID).handleReceivedError`                      | (marks doReceive failed)        | handled_successfully=false                                  |

## Trace Context Propagation

goakt-ebpf runs as a separate process and attaches via uprobes. Without context propagation, every span starts a new trace and appears disconnected in Jaeger/Tempo. Three mechanisms connect spans into coherent traces:

### In-Kernel Context Chain

Every probe that has access to `context.Context` calls `get_Go_context()` to read the context interface from function arguments. After creating a span, `start_tracking_span()` registers the span context in the `go_context_to_sc` map. Child calls on the same context chain find the parent via `get_parent_span_context()`, which walks the context chain looking for registered entries.

`start_span_and_store` accepts per-probe parameters (`context_pos`, `context_offset`, `passed_as_arg`) to handle both patterns:

| Context source | `passed_as_arg` | `context_pos` | `context_offset` |
|---|---|---|---|
| `context.Context` as direct arg (e.g. `Spawn`, `handleRemoteTell`) | true | 2 | 0 |
| `context.Context` inside struct (e.g. `ReceiveContext`) | false | 2 | DWARF offset |
| No context (e.g. `process()`) | — | 0 | — |

This links spans that share a context (e.g. `actor.doReceive` as parent of nested calls via the same context). It does not help when the parent span comes from application-level OTEL, since `go_context_to_sc` only contains spans created by goakt-ebpf probes.

### Goroutine-Scoped Span Map

A `goid_to_span_context` eBPF map (key: goroutine ID, value: span_context) propagates context within the same goroutine. On span start, the map is updated; on span end, the entry is deleted. Lookup tries this map first, then falls back to the context chain.

This links `actor.process` as a child of `actor.doReceive` since they run on the same goroutine. It does not connect spans across goroutines (e.g. remoting goroutine to actor goroutine).

### Userspace Context Reading

When BPF-side lookup finds no parent and `context_ptr` is non-zero, userspace reads the target process memory via `process_vm_readv(2)` to extract an OTEL span context from the Go `context.Context` chain.

The reader speculatively walks the chain, treating each node as a `valueCtx` (48 bytes). For each node it reads `val.data` and checks whether the pointed-to value looks like a `nonRecordingSpan`:

```
valueCtx (48 bytes):
  [0:8]   Context.itab     [8:16]  Context.data  -> parent context
  [16:24] key.type         [24:32] key.data
  [32:40] val.type         [40:48] val.data      -> nonRecordingSpan ptr

nonRecordingSpan:
  [0:16]  noopSpan (embedded.Span interface, always nil = zeros)
  [16:32] SpanContext.traceID  [16]byte
  [32:40] SpanContext.spanID   [8]byte
  [40]    SpanContext.traceFlags byte
```

Validation: first 16 bytes (noopSpan) must be zero; both TraceID and SpanID must be non-zero. Non-valueCtx nodes produce either read failures or invalid data, which the validation catches.

This connects goakt-ebpf spans to application-level OTEL spans and to remote trace context injected by GoAkt's `ContextPropagator`.

**Limitations:**
- `valueCtx` layout is stable since Go 1.7 but not a public API.
- `nonRecordingSpan` layout depends on the OTEL SDK version.
- Requires `CAP_SYS_PTRACE` (already required for uprobes).

### Context Extraction by Method

| Symbol | Context source | `passed_as_arg` | `context_pos` | `context_offset` |
|---|---|---|---|---|
| `(*PID).doReceive` | ReceiveContext | false | 2 | DWARF: `ReceiveContext.Context` |
| `(*grainPID).handleGrainContext` | ReceiveContext | false | 2 | DWARF: `ReceiveContext.Context` |
| `(*actorSystem).handleRemoteTell` | Direct arg | true | 2 | 0 |
| `(*actorSystem).handleRemoteAsk` | Direct arg | true | 2 | 0 |
| `(*actorSystem).Spawn` | Direct arg | true | 2 | 0 |
| `(*actorSystem).SpawnOn` | Direct arg | true | 2 | 0 |
| `(*PID).SpawnChild` | Direct arg | true | 2 | 0 |
| `(*actorSystem).remote*Handler` | Direct arg | true | 2 | 0 |
| `(*actorSystem).remoteTellGrain` | Direct arg | true | 2 | 0 |
| `(*actorSystem).remoteAskGrain` | Direct arg | true | 2 | 0 |
| `(*relocator).Relocate` | Direct arg | true | 2 | 0 |
| `(*PID).process` | No context | — | 0 | — |
| `(*grainPID).process` | No context | — | 0 | — |

## Dependencies

- **Cilium eBPF** — Load and attach eBPF programs.
- **OpenTelemetry** — Span model, OTLP export.
- **internal/include** — eBPF C headers (from OpenTelemetry Go Instrumentation).

## Deployment

- **Linux required**: eBPF is a Linux kernel feature.
- **Capabilities**: `SYS_PTRACE`, `SYS_ADMIN`, `BPF`, `PERFMON`.
- **PID namespace**: When running in Docker, share PID namespace with the target (`--pid=container:TARGET`) so the agent can attach.
- **Non-root**: The Docker image runs as non-root; capabilities are added at runtime.
