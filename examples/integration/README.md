# Integration Example

End-to-end example for goakt-ebpf using Docker Compose. Run this locally to verify the agent works with a GoAkt application.

## Prerequisites

- Docker and Docker Compose
- **Linux host** — eBPF requires a Linux kernel. Docker Desktop on macOS/Windows uses a Linux VM that typically does not support eBPF; you may see `operation not permitted` when attaching to the target process.

## Quick Start

From the repository root:

```bash
docker compose -f examples/integration/docker-compose.yml up --build
```

| Service          | Purpose                                      | Ports      |
|------------------|----------------------------------------------|------------|
| **goakt-app**    | Minimal GoAkt app (Tell/Ask between actors)  | —          |
| **goakt-ebpf**   | eBPF agent attaching to goakt-app             | —          |
| **otel-collector** | Receives OTLP traces, forwards to Jaeger   | 4317, 4318 |
| **jaeger**       | Trace visualization                           | 16686 (UI) |

## View Traces

1. Open http://localhost:16686 (Jaeger UI)
2. Select service `goakt-ebpf`
3. Click **Find Traces**

The app sends Tell and Ask messages on startup. Spans should appear within a few seconds.

## Architecture

```
    ┌─────────────────┐
    │   goakt-app     │
    │   (PID 1)       │
    └────────┬────────┘
             │ eBPF uprobes (shared PID ns)
             ▼
    ┌─────────────────┐
    │  goakt-ebpf     │
    │     agent       │
    └────────┬────────┘
             │ OTLP HTTP
             ▼
    ┌─────────────────┐
    │ otel-collector  │
    └────────┬────────┘
             │ OTLP gRPC
             ▼
    ┌─────────────────┐
    │     Jaeger      │
    └─────────────────┘
```

The agent runs in the same PID namespace as the app (`pid: "container:goakt-app"`) so it can attach uprobes.

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| `invalid PID 1: operation not permitted` | eBPF not supported (e.g. Docker Desktop on macOS/Windows) | Run on a Linux host |
| `operation not permitted` when attaching | Insufficient capabilities | The compose file uses `privileged: true`; ensure Docker has permission |

## Cleanup

```bash
docker compose -f examples/integration/docker-compose.yml down
```
