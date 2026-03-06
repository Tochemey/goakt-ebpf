<h2 align="center">
  <img src="docs/assets/goakt-ebpf-tracing-agent.png" alt="goakt-ebpf - eBPF tracing agent for GoAkt" width="800"/><br />
  eBPF tracing agent for GoAkt
</h2>

---

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Tochemey/goakt-ebpf/ci.yml?branch=main)](https://github.com/Tochemey/goakt-ebpf/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Tochemey/goakt-ebpf/graph/badge.svg?token=InGAauux3l)](https://codecov.io/gh/Tochemey/goakt-ebpf)

Zero-instrumentation tracing agent for [GoAkt](https://github.com/tochemey/goakt) actor systems.
Attach to any running GoAkt v4 application and get full actor-level traces — no code changes, no redeployment, no SDK dependency in your app.

## How It Works

goakt-ebpf runs as a sidecar process next to your GoAkt application. It uses [eBPF](https://ebpf.io/) uprobes to observe actor message handling at runtime and exports traces via [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otlp/) to any compatible backend (Jaeger, Grafana Tempo, Honeycomb, etc.).

```
Your GoAkt app          goakt-ebpf agent         OTLP backend
 ┌────────────┐          ┌────────────┐          ┌──────────┐
 │ actor.Tell │◄─uprobe──│  captures  │ ──OTLP──▶│  Jaeger  │
 │ actor.Ask  │          │  spans     │          │  Tempo   │
 │ doReceive  │          │            │          │  etc.    │
 └────────────┘          └────────────┘          └──────────┘
      (no changes)        (sidecar process)
```

**Your application does not need any OpenTelemetry SDK, any tracing library, or any code changes.** The agent produces complete actor traces on its own.

## Connecting App Spans to Actor Spans

If your application already uses the **standard OpenTelemetry Go SDK** (`go.opentelemetry.io/otel/sdk`) to create spans — from HTTP handlers, gRPC interceptors, or manual `tracer.Start` calls — goakt-ebpf automatically links its actor spans as children of your application spans.

This gives you a connected trace tree like:

```
GET /api/order                    ← your app span (otelhttp / otelgrpc)
  └── actor.doReceive             ← goakt-ebpf span (auto-linked)
        └── actor.process         ← goakt-ebpf span (auto-linked)
```

**What you need for this to work:**

1. Use the standard OTEL SDK: `sdktrace.NewTracerProvider(...)` with a sampled exporter.
2. Set it globally: `otel.SetTracerProvider(tp)`.
3. Instrument your entry points (HTTP handlers, gRPC interceptors, etc.) so spans exist in `context.Context`.
4. **Pass that context into actor calls**: `actor.Tell(ctx, pid, msg)`, `actor.Ask(ctx, pid, msg)`, etc.

If any of these steps is missing, actor spans still appear — they just won't be linked to your app spans (they appear as root spans).

**Not supported:** The OpenTelemetry Auto SDK (`go.opentelemetry.io/auto/sdk`) cannot be used for parent-child linking because its span context is zero-initialized in user-space.

## Prerequisites

- **Linux** — eBPF is a Linux kernel feature. The agent does not run on macOS or Windows. Docker Desktop's VM typically does not support eBPF; use [Lima](https://github.com/lima-vm/lima) on macOS instead (see [integration example](examples/integration/README.md)).
- **Non-stripped binary** — The target Go binary must retain DWARF debug info (do not build with `-ldflags="-s -w"`).
- **GoAkt v4** — Instrumented symbols match GoAkt v4.

## Quick Start

### Docker (recommended)

Pull the agent image and run it alongside your GoAkt app, sharing the PID namespace:

```bash
docker run --rm \
  --cap-add=SYS_PTRACE,SYS_ADMIN,BPF,PERFMON \
  --pid=container:YOUR_GOAKT_APP \
  -e OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318 \
  ghcr.io/tochemey/goakt-ebpf:latest -pid 1
```

When sharing PID namespace, the target process is typically PID 1.

### Bare metal

Build from source or extract from the Docker image, then run with the target PID:

```bash
# Option 1: Build from source (Linux only)
go build -o goakt-ebpf ./cmd/cli/...

# Option 2: Extract from Docker image
docker run --rm --entrypoint cat ghcr.io/tochemey/goakt-ebpf:latest \
  /usr/local/bin/goakt-ebpf > goakt-ebpf && chmod +x goakt-ebpf

# Run
sudo ./goakt-ebpf -pid $(pgrep -f your-goakt-app)
# or
sudo ./goakt-ebpf -exe /path/to/your-goakt-app
```

### Try it locally

Run the full integration example with Docker Compose:

```bash
make build && make start && make view   # opens Jaeger UI
```

Or: `docker compose -f examples/integration/docker-compose.yml up --build`, then open http://localhost:16686.

See [examples/integration/README.md](examples/integration/README.md) for Lima setup on macOS.

## Configuration

### Flags

| Flag                 | Description                                                        |
|----------------------|--------------------------------------------------------------------|
| `-pid <pid>`         | Target process ID. Use `1` when sharing PID namespace.             |
| `-exe <path>`        | Target executable path; finds PID by matching `/proc/<pid>/exe`.   |
| `-log-level <level>` | Log verbosity: `debug`, `info`, `warn`, `error` (default: `info`). |

### Environment Variables

| Variable                          | Description                                                       |
|-----------------------------------|-------------------------------------------------------------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT`     | OTLP endpoint (e.g. `http://otel-collector:4318`).                |
| `OTEL_EXPORTER_OTLP_PROTOCOL`     | `http/protobuf` or `grpc` (default: `http/protobuf`).             |
| `OTEL_SERVICE_NAME`               | Service name for exported traces (default: `goakt-ebpf`).         |
| `GOAKT_EBPF_TARGET_PID`           | Target PID (used if `-pid` is not set).                           |
| `GOAKT_EBPF_LOG_LEVEL`            | Log level (overridden by `-log-level`).                           |
| `GOAKT_EBPF_DEBUG_CONTEXT_READER` | Set to `1` to log context chain walking and span layout matching. |

## What You See in Traces

The agent produces spans for all actor operations without any code changes:

| Category             | Spans                                                                                                          | Description                                                                |
|----------------------|----------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| **Message handling** | `actor.doReceive`, `actor.process`                                                                             | When actors receive and process messages, with timing and success/failure. |
| **Grain processing** | `actor.grainDoReceive`, `actor.grainProcess`                                                                   | Grain message handling and lifecycle.                                      |
| **Remote messaging** | `actor.remoteTell`, `actor.remoteAsk`, `actor.remoteTellReceive`, `actor.remoteAskReceive`                     | Sends and receives across nodes.                                           |
| **Remote grains**    | `actor.remoteTellGrain`, `actor.remoteAskGrain`, `actor.remoteTellGrainReceive`, `actor.remoteAskGrainReceive` | Cross-node grain operations.                                               |
| **Actor lifecycle**  | `actor.systemSpawn`, `actor.spawnChild`, `actor.spawnOn`                                                       | Local actor creation.                                                      |
| **Remote lifecycle** | `actor.remoteSpawn`, `actor.remoteSpawnChild`, `actor.remoteStop`, `actor.remoteReSpawn`, `actor.relocation`   | Remote actor management.                                                   |
| **Remote metadata**  | `actor.remoteLookup`, `actor.remoteState`, `actor.remoteKind`, `actor.remoteMetric`, ...                       | Inspection and management operations.                                      |

## Deployment

### Docker Compose

```yaml
services:
  goakt-app:
    image: your-goakt-app:latest

  goakt-ebpf:
    image: ghcr.io/tochemey/goakt-ebpf:latest
    cap_add: [SYS_PTRACE, SYS_ADMIN, BPF, PERFMON]
    pid: "container:goakt-app"
    environment:
      OTEL_EXPORTER_OTLP_ENDPOINT: http://otel-collector:4318
    entrypoint: ["/bin/sh", "-c", "sleep 3 && exec /usr/local/bin/goakt-ebpf -pid 1"]
```

### Kubernetes

Run the agent as a sidecar in the same pod with shared PID namespace:

```yaml
spec:
  shareProcessNamespace: true
  containers:
    - name: goakt-app
      image: your-goakt-app:latest
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

## Distributed Tracing (Cross-Node)

For cross-node trace correlation, configure GoAkt with OpenTelemetry's TraceContext propagator:

```go
import "go.opentelemetry.io/otel/propagation"

remote.WithContextPropagator(propagation.NewCompositeTextMapPropagator(
    propagation.TraceContext{},
    propagation.Baggage{},
))
```

## Building from Source

```bash
# Linux
go mod tidy
go generate ./internal/instrumentation/bpf/github.com/tochemey/goakt/actor/...
go build -o goakt-ebpf ./cmd/cli/...

# macOS / Windows (BPF generation requires Linux)
make docker-generate   # runs go generate in a Docker container
make docker-test       # runs generate + tests in Docker
```

## Troubleshooting

| Issue                                  | Cause                                                     | Fix                                                                                                                                           |
|----------------------------------------|-----------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
| `operation not permitted`              | eBPF not supported (Docker Desktop, missing capabilities) | Run on Linux. Use `--cap-add=SYS_PTRACE,SYS_ADMIN,BPF,PERFMON`. On macOS use [Lima](examples/integration/README.md).                          |
| `could not find offset for function`   | Symbol missing (stripped binary, older GoAkt)             | Build without `-ldflags="-s -w"`. Optional probes log a warning and continue.                                                                 |
| No spans in backend                    | OTLP misconfigured                                        | Set `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g. `http://localhost:4318`).                                                                             |
| Actor spans are root spans (no parent) | Context not propagated, or Auto SDK used                  | Pass the HTTP/gRPC `ctx` into `actor.Tell`/`Ask`. Use the standard OTEL SDK, not Auto SDK. Enable debug: `GOAKT_EBPF_DEBUG_CONTEXT_READER=1`. |
| `bpf_x86_bpfel.o: no matching files`   | BPF objects not generated                                 | Run `make docker-generate` (macOS/Windows) or `go generate ./...` (Linux).                                                                    |

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — eBPF probe design, span layout heuristics, context extraction internals.
- [Integration Example](examples/integration/README.md) — Full Docker Compose setup with Jaeger.
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
