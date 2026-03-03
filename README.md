<h2 align="center">
  <img src="docs/assets/goakt-ebpf-tracing-agent.png" alt="goakt-ebpf - eBPF tracing agent for GoAkt" width="800"/><br />
  eBPF tracing agent for GoAkt
</h2>

---

[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Tochemey/goakt-ebpf/ci.yml?branch=main)](https://github.com/Tochemey/goakt-ebpf/actions/workflows/ci.yml)

eBPF tracing agent for [GoAkt](https://github.com/tochemey/goakt) — zero-instrumentation tracing of actor message flow, remoting, and grains.

## 📋 Prerequisites

- Go 1.26+
- Linux (eBPF requires Linux; use Docker for macOS/Windows)

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

**Flags:**

- `-pid <pid>` — Attach to process by PID (use `1` when sharing PID namespace with target container)
- `-exe <path>` — Attach by executable path (finds PID matching `/proc/<pid>/exe`)
- `-log-level <debug|info|warn|error>` — Log verbosity (default: `info`)

**Environment variables:** `GOAKT_EBPF_TARGET_PID`, `GOAKT_EBPF_LOG_LEVEL`

Spans are exported via OTLP. Set `OTEL_EXPORTER_OTLP_ENDPOINT` to configure the export destination.

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
docker compose -f examples/integration/docker-compose.yml up --build
```

Then open http://localhost:16686 (Jaeger UI). See [examples/integration/README.md](examples/integration/README.md).

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

| Symbol                            | Span                     | Attributes                                                  |
|-----------------------------------|--------------------------|-------------------------------------------------------------|
| `(*PID).doReceive`                | actor.doReceive          | received_timestamp, handled_timestamp, handled_successfully |
| `(*grainPID).handleGrainContext`  | actor.grainDoReceive     | received_timestamp, handled_timestamp, handled_successfully |
| `(*actorSystem).handleRemoteTell` | actor.remoteTell         | sent_timestamp                                              |
| `(*actorSystem).handleRemoteAsk`  | actor.remoteAsk          | sent_timestamp                                              |
| `(*PID).process`                  | actor.process            | —                                                           |
| `(*grainPID).process`             | actor.grainProcess       | —                                                           |
| `(*PID).handleReceivedError`      | (marks doReceive failed) | handled_successfully=false                                  |

## 🔍 Troubleshooting

| Issue                                    | Cause                                         | Fix                                                              |
|------------------------------------------|-----------------------------------------------|------------------------------------------------------------------|
| `could not find offset for function ...` | Symbol missing (older GoAkt, stripped binary) | Use non-stripped binary. Optional probes use FailureModeWarn.    |
| `permission denied`                      | eBPF requires capabilities                    | Use `--cap-add=SYS_PTRACE,SYS_ADMIN,BPF,PERFMON` when running Docker |
| No spans in Jaeger                       | OTLP misconfigured                            | Set `OTEL_EXPORTER_OTLP_ENDPOINT` (e.g. `http://localhost:4318`) |
| `bpf_x86_bpfel.o: no matching files`     | BPF not generated                             | Run `./scripts/generate-bpf.sh` on macOS/Windows                 |

## 📚 Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Contributing](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## 📄 License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
