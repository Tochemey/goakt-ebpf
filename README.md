<h2 align="center">
  <img src="docs/assets/goakt-ebpf-tracing-agent.png" alt="goakt-ebpf - eBPF tracing agent for GoAkt" width="800"/><br />
  eBPF tracing agent for GoAkt
</h2>

---

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Tochemey/goakt-ebpf/ci.yml?branch=main)](https://github.com/Tochemey/goakt-ebpf/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/Tochemey/goakt-ebpf/graph/badge.svg?token=InGAauux3l)](https://codecov.io/gh/Tochemey/goakt-ebpf)
<a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License"></a>
<a href="https://human-oss.dev"><img src="https://human-oss.dev/badge.svg" alt="Open Source AI Manifesto" /></a>
<a href="https://join.slack.com/t/oss-r2l2029/shared_invite/zt-42zcqua8y-unSUH0tFlOQzwT_smzYfOQ"><img src="https://img.shields.io/badge/Slack-Join%20our%20community-4A154B?logo=slack&logoColor=white" alt="Join our Slack" /></a>

Zero-instrumentation tracing agent for [GoAkt](https://github.com/tochemey/goakt) actor systems.
It attaches to a running GoAkt v4 application and produces actor-level traces. Your application does not need code changes, redeployment, or an SDK dependency.

## How It Works

goakt-ebpf runs as a sidecar process alongside your GoAkt application. It uses [eBPF](https://ebpf.io/) uprobes to observe actor message handling at runtime and exports traces via the [OpenTelemetry Protocol (OTLP)](https://opentelemetry.io/docs/specs/otlp/) to any compatible backend such as SigNoz, Jaeger, Grafana Tempo, or Honeycomb.

```
Your GoAkt app          goakt-ebpf agent         OTLP backend
 ┌────────────┐          ┌────────────┐          ┌──────────┐
 │ actor.Tell │◄─uprobe──│  captures  │ ──OTLP──▶│  SigNoz  │
 │ actor.Ask  │          │  spans     │          │  Jaeger  │
 │ doReceive  │          │            │          │  Tempo   │
 └────────────┘          └────────────┘          └──────────┘
      (no changes)        (sidecar process)
```

## Connecting App Spans to Actor Spans

If your application already uses the standard OpenTelemetry Go SDK (`go.opentelemetry.io/otel/sdk`) to create spans, whether from HTTP handlers, gRPC interceptors, or manual `tracer.Start` calls, goakt-ebpf links its actor spans as children of your application spans.

The result is a connected trace tree:

```
GET /api/order                    ← your app span (otelhttp / otelgrpc)
  └── actor.doReceive             ← goakt-ebpf span (auto-linked)
        └── actor.process         ← goakt-ebpf span (auto-linked)
```

To enable this:

1. Use the standard OTEL SDK: `sdktrace.NewTracerProvider(...)` with a sampled exporter.
2. Set it globally: `otel.SetTracerProvider(tp)`.
3. Instrument your entry points (HTTP handlers, gRPC interceptors, and so on) so spans exist in `context.Context`.
4. Pass that context into actor calls: `actor.Tell(ctx, pid, msg)`, `actor.Ask(ctx, pid, msg)`, and the rest.

If any of these steps is missing, actor spans still appear, but they are not linked to your application spans and show up as root spans.

HTTP middleware such as `otelhttp` stores the span on a cancelable request context. The agent reads that context from process memory; a raw `r.Context()` is easy to miss. The [integration example](examples/integration/README.md) rebinds the current span onto a non-cancelable `valueCtx` before `Tell`/`Ask` so HTTP traces link the same way as manual `tracer.Start` spans.

**Not supported:** The OpenTelemetry Auto SDK (`go.opentelemetry.io/auto/sdk`) does not work for parent-child linking, because its span context is zero-initialized in user space.

## Prerequisites

- **Linux.** eBPF is a Linux kernel feature, so the agent does not run on macOS or Windows. Docker Desktop's VM typically does not support eBPF; use [Lima](https://github.com/lima-vm/lima) on macOS instead (see the [integration example](examples/integration/README.md)).
- **Non-stripped binary.** The target Go binary must retain DWARF debug info. Do not build with `-ldflags="-s -w"`.
- **GoAkt v4.** The instrumented symbols match GoAkt v4.

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

When sharing the PID namespace, the target process is typically PID 1.

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

Run the full integration example with Docker Compose. It starts a GoAkt app, the eBPF agent, and a self-hosted [SigNoz](https://signoz.io/) UI:

```bash
make build    # fetch SigNoz and build images (first run can take several minutes)
make start    # start the stack and call GET /echo and GET /ask
make view     # open SigNoz at http://localhost:8080
```

Log in with `admin@goakt.local` / `GoAkt-eBPF-2026!` (local demo only). In **Traces**, switch to **Trace View** and open a `GET /echo` or `GET /ask` trace. You should see:

```
GET /ask                      ← integration-app (otelhttp)
  └── actor.doReceive         ← goakt-ebpf
        └── actor.process     ← goakt-ebpf
```

The app also emits `send-tell` / `send-ask` every 5 seconds with the same 3-level tree. See [examples/integration/README.md](examples/integration/README.md) for Lima setup on macOS, credentials, and troubleshooting.

## Configuration

### Flags

| Flag                 | Description                                                        |
|----------------------|--------------------------------------------------------------------|
| `-pid <pid>`         | Target process ID. Use `1` when sharing the PID namespace.        |
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

The agent produces spans for actor operations without any code changes:

| Category                          | Spans                                                                                                                                                                                     | Description                                                                |
|-----------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------|
| **Message handling (PID)**        | `actor.doReceive`, `actor.process`                                                                                                                                                        | When actors receive and process messages, with timing and success/failure. |
| **Grain processing**              | `grain.doReceive`, `grain.process`                                                                                                                                                        | Grain message handling and lifecycle.                                      |
| **Grain messaging**               | `grain.tell`, `grain.ask`                                                                                                                                                                 | Local grain sends and requests (client-side).                              |
| **Remote messaging (System)**     | `actorSystem.remoteTell`, `actorSystem.remoteAsk`, `actorSystem.remoteTellReceive`, `actorSystem.remoteAskReceive`                                                                        | Sends and receives across nodes.                                           |
| **Remote grains**                 | `grain.remoteTell`, `grain.remoteAsk`, `grain.remoteTellReceive`, `grain.remoteAskReceive`, `grain.remoteActivate`                                                                        | Cross-node grain operations.                                               |
| **Spawn lifecycle (System)**      | `actorSystem.spawn`, `actorSystem.spawnOn`, `actorSystem.actorOf`, `actorSystem.spawnNamedFromFunc`, `actorSystem.spawnFromFunc`, `actorSystem.spawnRouter`, `actorSystem.spawnSingleton` | Actor system spawn operations.                                             |
| **Spawn lifecycle (PID)**         | `actor.spawnChild`                                                                                                                                                                        | PID child spawning.                                                        |
| **Actor system operations**       | `actorSystem.start`, `actorSystem.stop`, `actorSystem.kill`, `actorSystem.reSpawn`, `actorSystem.actorExists`, `actorSystem.actors`, `actorSystem.metric`                                 | System lifecycle and inspection.                                           |
| **Scheduling (System)**           | `actorSystem.scheduleOnce`, `actorSystem.schedule`, `actorSystem.scheduleWithCron`                                                                                                        | Message scheduling.                                                        |
| **Local messaging (PID)**         | `actor.tell`, `actor.ask`, `actor.sendAsync`, `actor.sendSync`, `actor.batchTell`, `actor.batchAsk`                                                                                       | Local actor messaging (client-side).                                       |
| **Remote lifecycle (System)**     | `actorSystem.remoteSpawn`, `actorSystem.remoteSpawnChild`, `actorSystem.remoteStop`, `actorSystem.remoteReSpawn`, `actor.relocation`                                                      | Remote actor management.                                                   |
| **Remote metadata (System)**      | `actorSystem.remoteLookup`, `actorSystem.remoteState`, `actorSystem.remoteKind`, `actorSystem.remoteMetric`, `actorSystem.remoteReinstate`, `actorSystem.remotePassivationStrategy`       | System-level inspection and management.                                    |
| **Remote metadata (System cont)** | `actorSystem.remoteChildren`, `actorSystem.remoteParent`, `actorSystem.remoteDependencies`, `actorSystem.remoteRole`, `actorSystem.remoteStashSize`                                       | Additional system-level remote operations.                                 |
| **Remote operations (PID)**       | `actor.remoteLookup`, `actor.remoteStop`, `actor.remoteReSpawn`                                                                                                                           | PID-level remote operations.                                               |
| **PID operations**                | `actor.stop`, `actor.restart`, `actor.metric`, `actor.reinstateNamed`, `actor.pipeTo`, `actor.pipeToName`, `actor.discoverActor`, `actor.shutdown`                                        | PID lifecycle and utilities.                                               |

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

Run the agent as a sidecar in the same pod with a shared PID namespace:

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
| Actor spans are root spans (no parent) | Context not propagated, Auto SDK used, or raw `otelhttp` request context | Pass the HTTP/gRPC `ctx` into `actor.Tell`/`Ask`. Use the standard OTEL SDK, not Auto SDK. For `otelhttp`, rebind the span as in the [integration example](examples/integration/README.md). Enable debug: `GOAKT_EBPF_DEBUG_CONTEXT_READER=1`. |
| `bpf_x86_bpfel.o: no matching files`   | BPF objects not generated                                 | Run `make docker-generate` (macOS/Windows) or `go generate ./...` (Linux).                                                                    |

## Documentation

- [Architecture](docs/ARCHITECTURE.md): eBPF probe design, span layout heuristics, and context extraction internals.
- [Integration Example](examples/integration/README.md): full Docker Compose setup with SigNoz.
- [Grains Example](examples/grains/README.md): virtual actors (grains) traced end-to-end with zero instrumentation code.
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
