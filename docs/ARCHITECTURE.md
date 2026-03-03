# Architecture

## Overview

goakt-ebpf is a standalone eBPF agent that instruments [GoAkt](https://github.com/tochemey/goakt) applications without code changes. It attaches uprobes to GoAkt runtime functions and exports traces via OpenTelemetry Protocol (OTLP).

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

| Symbol                               | Purpose                             |
|--------------------------------------|-------------------------------------|
| `(*PID).doReceive`                   | Actor message receive               |
| `(*grainPID).handleGrainContext`     | Grain message receive               |
| `(*actorSystem).handleRemoteTell`    | Remote Tell send                    |
| `(*actorSystem).handleRemoteAsk`      | Remote Ask send                     |
| `(*actorSystem).remoteTellHandler`    | Remote Tell receive (TCP)           |
| `(*actorSystem).remoteAskHandler`     | Remote Ask receive (TCP)            |
| `(*actorSystem).Spawn`               | Actor system spawn                  |
| `(*actorSystem).remoteSpawnHandler`   | Remote spawn receive (TCP)          |
| `(*actorSystem).remoteSpawnChildHandler` | Remote spawn child receive (TCP) |
| `(*PID).process`                     | Actor mailbox loop                  |
| `(*PID).SpawnChild`                  | PID spawn child                     |
| `(*grainPID).process`                | Grain mailbox loop                  |
| `(*relocator).Relocate`              | Cluster relocation (optional)       |
| `(*PID).handleReceivedError`         | Mark doReceive as failed (optional) |

## Dependencies

- **Cilium eBPF** — Load and attach eBPF programs.
- **OpenTelemetry** — Span model, OTLP export.
- **internal/include** — eBPF C headers (from OpenTelemetry Go Instrumentation).

## Deployment

- **Linux required**: eBPF is a Linux kernel feature.
- **Capabilities**: `SYS_PTRACE`, `SYS_ADMIN`, `BPF`, `PERFMON`.
- **PID namespace**: When running in Docker, share PID namespace with the target (`--pid=container:TARGET`) so the agent can attach.
- **Non-root**: The Docker image runs as non-root; capabilities are added at runtime.
