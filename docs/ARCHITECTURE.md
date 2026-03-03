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

## Dependencies

- **Cilium eBPF** — Load and attach eBPF programs.
- **OpenTelemetry** — Span model, OTLP export.
- **internal/include** — eBPF C headers (from OpenTelemetry Go Instrumentation).

## Deployment

- **Linux required**: eBPF is a Linux kernel feature.
- **Capabilities**: `SYS_PTRACE`, `SYS_ADMIN`, `BPF`, `PERFMON`.
- **PID namespace**: When running in Docker, share PID namespace with the target (`--pid=container:TARGET`) so the agent can attach.
- **Non-root**: The Docker image runs as non-root; capabilities are added at runtime.
