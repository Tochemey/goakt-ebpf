<h2 align="center">
  <img src="docs/assets/goakt-ebpf-tracing-agent.png" alt="goakt-ebpf - eBPF tracing agent for GoAkt" width="800"/><br />
  eBPF tracing agent for GoAkt
</h2>

---

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Tochemey/goakt-ebpf/ci.yml?branch=main)](https://github.com/Tochemey/goakt-ebpf/actions/workflows/ci.yml)

eBPF tracing agent for [GoAkt](https://github.com/tochemey/goakt) — zero-instrumentation tracing of actor message flow, remoting, and grains.

## 📖 Overview

goakt-ebpf attaches to running GoAkt applications and observes actor message handling, remote Tell/Ask, and grain processing without any code changes or redeployment. The agent runs as a sidecar process and exports traces via OpenTelemetry Protocol (OTLP), so you can visualize spans in Jaeger, Grafana Tempo, or any OTLP-compatible backend.

## 💡 What is eBPF?

**eBPF** (extended Berkeley Packet Filter) is a Linux kernel technology that allows running sandboxed programs in the kernel without changing kernel source code or loading modules. For goakt-ebpf, we use **uprobes** — user-space probes that attach to function entry and exit points in the target process. When a GoAkt application handles a message, the eBPF program runs in kernel space, records timestamps and IDs, and sends events to userspace via a perf buffer. This approach is safe, low-overhead, and requires no instrumentation in your application code.

## 📡 OpenTelemetry Integration

goakt-ebpf is built for the OpenTelemetry ecosystem. The agent:

- **Produces OTLP traces** — Spans follow the OpenTelemetry trace model and are exported over HTTP or gRPC.
- **Uses standard OTLP exporters** — Configure `OTEL_EXPORTER_OTLP_ENDPOINT` to send traces to any OTLP receiver (OpenTelemetry Collector, Jaeger, Grafana Tempo, Honeycomb, etc.).
- **Correlates with GoAkt** — When GoAkt is configured with TraceContext propagation, the agent’s spans can be linked to cross-node traces.

You run the agent alongside your GoAkt app, point it at an OTLP endpoint, and traces appear in your observability platform. No SDK changes or instrumentation in your application.

## 📋 Prerequisites

- **Linux** — eBPF is a Linux kernel feature. The agent does not run on macOS or Windows (Docker Desktop’s Linux VM typically does not support eBPF).
- **Go 1.26+** — For building from source.

## ✨ Features

- **Zero instrumentation** — No code changes, no redeployment. Attach to any GoAkt v4 process.
- **Actor-level spans** — Traces for `doReceive`, `process`, remote Tell/Ask, and grain handling.
- **OTLP export** — Standard OpenTelemetry Protocol; works with any OTLP backend.
- **Sidecar deployment** — Runs as a separate process; share PID namespace with the target in Docker/Kubernetes.
- **Cross-node correlation** — Integrates with GoAkt’s TraceContext propagation for distributed traces.

## 🚀 Quick Start

The agent is distributed as a Docker image. Pull and run it, sharing the PID namespace with your GoAkt application:

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/tochemey/goakt-ebpf:latest

# Run (share PID namespace with target container)
docker run --rm \
  --cap-add=SYS_PTRACE,SYS_ADMIN,BPF,PERFMON \
  --pid=container:YOUR_GOAKT_APP_CONTAINER \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 \
  ghcr.io/tochemey/goakt-ebpf:latest -pid 1
```

When sharing PID namespace with a container, the target process is typically PID 1. See [Deployment](#-deployment) for Kubernetes and other environments.

## ⚙️ Configuration

### Flags

| Flag                 | Description                                                                      |
|----------------------|----------------------------------------------------------------------------------|
| `-pid <pid>`         | Target process ID. Use `1` when sharing PID namespace with the target container. |
| `-exe <path>`        | Target executable path; finds PID by matching `/proc/<pid>/exe`.                 |
| `-log-level <level>` | Log verbosity: `debug`, `info`, `warn`, `error` (default: `info`).               |

### Environment Variables

| Variable                      | Description                                           |
|-------------------------------|-------------------------------------------------------|
| `GOAKT_EBPF_TARGET_PID`       | Target PID (used if `-pid` is not set).               |
| `GOAKT_EBPF_LOG_LEVEL`        | Log level (overridden by `-log-level`).               |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP endpoint (e.g. `http://otel-collector:4318`).    |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` or `grpc` (default: `http/protobuf`). |

Spans are exported via OTLP. Configure `OTEL_EXPORTER_OTLP_ENDPOINT` to point to your OpenTelemetry Collector, Jaeger, or other OTLP receiver.

## 🔧 Build (from source)

For local development only. The agent is distributed as a Docker image.

```bash
go mod tidy
# On non-Linux: ./scripts/generate-bpf.sh (uses Docker)
go build -o goakt-ebpf ./cmd/cli/...
```

## 🧪 Integration Example

Run the full stack locally to verify the agent:

```bash
make build
make start
make view     # Opens Jaeger UI
```

Or: `docker compose -f examples/integration/docker-compose.yml up --build`. **On macOS:** use [Lima](https://github.com/lima-vm/lima) instead of Docker Desktop (eBPF requires a Linux kernel). See [examples/integration/README.md](examples/integration/README.md) for step-by-step Lima setup.

## 📦 Deployment

### Docker

Run the agent as a sidecar with your GoAkt app. The agent must share the PID namespace with the target so it can attach uprobes:

```bash
docker run --rm \
  --cap-add=SYS_PTRACE,SYS_ADMIN,BPF,PERFMON \
  --pid=container:goakt-app \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 \
  ghcr.io/tochemey/goakt-ebpf:latest -pid 1
```

### Kubernetes

Run the agent as a sidecar in the same pod as your GoAkt application. Share the PID namespace via `shareProcessNamespace: true`:

```yaml
spec:
  shareProcessNamespace: true
  containers:
    - name: goakt-app
      image: your-goakt-app:latest
      # ...
    - name: goakt-ebpf
      image: ghcr.io/tochemey/goakt-ebpf:latest
      securityContext:
        capabilities:
          add: [SYS_PTRACE, SYS_ADMIN, BPF, PERFMON]
      env:
        - name: OTEL_EXPORTER_OTLP_ENDPOINT
          value: "http://otel-collector:4318"
      args: ["-pid", "1"]
```

### Bare Metal / Systemd

When the agent and GoAkt app run on the same Linux host, use `-pid` with the target process ID or `-exe` with the executable path.

**Obtaining the executable** — Either build from source or extract from the Docker image:

```bash
# Option 1: Build from source (requires Linux; see Build section for non-Linux)
go mod tidy
# On non-Linux: ./scripts/generate-bpf.sh first
go build -o goakt-ebpf ./cmd/cli/...

# Option 2: Extract from Docker image (no build required)
docker pull ghcr.io/tochemey/goakt-ebpf:latest
docker run --rm --entrypoint cat ghcr.io/tochemey/goakt-ebpf:latest /usr/local/bin/goakt-ebpf > goakt-ebpf
chmod +x goakt-ebpf
```

**Run the agent:**

```bash
./goakt-ebpf -pid $(pgrep -f your-goakt-app)
# or
./goakt-ebpf -exe /path/to/your-goakt-app
```

## 🔗 Distributed Tracing (Cross-Node)

Configure GoAkt with OpenTelemetry's TraceContext propagator for cross-node correlation:

```go
import "go.opentelemetry.io/otel/propagation"

remote.WithContextPropagator(propagation.NewCompositeTextMapPropagator(
    propagation.TraceContext{},
    propagation.Baggage{},
))
```

## 🎯 Instrumentation Targets

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

## 🔄 How It Works

1. **Attach** — The agent resolves the target PID, loads eBPF programs, and attaches uprobes to GoAkt runtime symbols.
2. **Capture** — On function entry (e.g. `doReceive`), the eBPF program allocates a span slot, records start time, and generates trace/span IDs.
3. **Correlate** — On function return (or `handleReceivedError` for failures), the program records end time and emits the span via a perf buffer.
4. **Export** — Userspace reads perf events, converts them to OTLP spans, and exports to the configured endpoint.

For more detail, see [Architecture](docs/ARCHITECTURE.md).

## ✅ Compatibility

- **GoAkt** — v4.x (instrumented symbols match GoAkt v4).
- **Linux** — Required; eBPF is a Linux kernel feature. Docker Desktop on macOS/Windows uses a Linux VM that typically does not support eBPF; you may see `operation not permitted` when attaching to the target process.
- **Non-stripped binaries** — The target Go binary must be built without `-ldflags="-s -w"` (or similar) so that DWARF debug info is available for symbol lookup.

## 🔍 Troubleshooting

| Issue                                    | Cause                                                     | Fix                                                                   |
|------------------------------------------|-----------------------------------------------------------|-----------------------------------------------------------------------|
| `invalid PID 1: operation not permitted` | eBPF not supported (e.g. Docker Desktop on macOS/Windows) | Run on a Linux host.                                                  |
| `could not find offset for function ...` | Symbol missing (older GoAkt, stripped binary)             | Use non-stripped binary. Optional probes use FailureModeWarn.         |
| `permission denied`                      | eBPF requires capabilities                                | Use `--cap-add=SYS_PTRACE,SYS_ADMIN,BPF,PERFMON` when running Docker. |
| No spans in Jaeger                       | OTLP misconfigured                                        | Set `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g. `http://localhost:4318`).     |
| `bpf_x86_bpfel.o: no matching files`     | BPF not generated                                         | Run `./scripts/generate-bpf.sh` on macOS/Windows.                     |

## 📚 Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Instrumentation Plan](docs/INSTRUMENTATION_PLAN.md) — New probes and cross-platform testing via Docker
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## 📄 License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
