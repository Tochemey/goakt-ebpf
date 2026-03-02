# Integration Example

End-to-end example for goakt-ebpf using Docker Compose. Run this locally to verify the agent works with a GoAkt application.

## Prerequisites

- Docker and Docker Compose
- Linux host (eBPF requires Linux; Docker Desktop on macOS/Windows uses a Linux VM)

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
┌─────────────┐     eBPF uprobes      ┌─────────────┐     OTLP HTTP      ┌──────────────────┐     OTLP gRPC     ┌────────┐
│ goakt-ebpf  │ ◄──────────────────── │  goakt-app   │                    │ otel-collector   │ ─────────────────► │ Jaeger │
│   agent     │   (shared PID ns)     │  (PID 1)     │                    │                  │                    │        │
└─────────────┘                       └─────────────┘                    └──────────────────┘                    └────────┘
```

The agent runs in the same PID namespace as the app (`pid: "container:goakt-app"`) so it can attach uprobes.

## Cleanup

```bash
docker compose -f examples/integration/docker-compose.yml down
```
