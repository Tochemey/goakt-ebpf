# Integration Example

> **Note:** This implementation is still WIP (work in progress).

End-to-end example for goakt-ebpf using Docker Compose. Run this locally to verify the agent works with a GoAkt application.

## 📋 Prerequisites

- Docker and Docker Compose
- **Linux host** — eBPF requires a Linux kernel. Docker Desktop on macOS/Windows uses a Linux VM that typically does not support eBPF; you may see `operation not permitted` when attaching to the target process.

## 🔧 Running on Mac with Lima

[Lima](https://github.com/lima-vm/lima) runs a real Linux VM with eBPF support. Use it instead of Docker Desktop to run this example on macOS.

### 1. Install Lima

```bash
brew install lima
```

### 2. Create and start a Lima VM with Docker

```bash
limactl start template:docker
```

When prompted, choose **Proceed with the current configuration** (or customize CPU/memory if needed). Wait until you see `READY`.

**If you get `operation not permitted`** (e.g. from `make diagnose`): Lima's vz driver and Colima on Apple Silicon restrict eBPF. Use Lima with QEMU instead (requires `brew install qemu`):

```bash
limactl start --name=ebpf --vm-type=qemu template:docker
```

When ready, use the `ebpf` instance:

```bash
export DOCKER_HOST=$(limactl list ebpf --format 'unix://{{.Dir}}/sock/docker.sock')
make down && make build && make start
```

QEMU is slower than vz but uses a more standard Linux kernel that supports eBPF.

### 3. Point Docker CLI at the Lima VM

**Important:** If Docker Desktop is installed, it will be used by default. You must set `DOCKER_HOST` so Docker uses Lima instead:

```bash
export DOCKER_HOST=$(limactl list docker --format 'unix://{{.Dir}}/sock/docker.sock')
```

Add this line to your `~/.zshrc` or `~/.bashrc` so it runs in new shells. **Quit and reopen your terminal** (or run the export) before `make start`.

If the command fails, run `limactl list` — your instance may have a different name (e.g. `default`). Use that name: `limactl list <name> --format '...'`.

### 4. Verify you're using Lima

```bash
make verify-lima
```

Or: `echo $DOCKER_HOST` should show a path containing `lima`. Then `docker info` should show a Linux server.

### 5. Run the integration example

Ensure the repo is under a path Lima mounts (e.g. `~/go/src/goakt-ebpf` or `/Users/you/...`). From the repository root:

```bash
make build
make start
make view     # Opens Jaeger UI in your browser
```

Or: `docker compose -f examples/integration/docker-compose.yml up --build`

### 6. View traces

Run `make view` to open the Jaeger UI, or go to http://localhost:16686. Select service `goakt-ebpf` and click **Find Traces**.

### Stopping Lima

When done, stop the VM to free resources:

```bash
limactl stop docker
```

Start it again later with `limactl start docker`.

---

## 🔗 Other options (Mac or Windows)

eBPF is a Linux kernel feature. Docker Desktop's VM (linuxkit on Mac, WSL2 on Windows) usually lacks eBPF support or has permission restrictions.

| Option                   | Mac                                                                    | Windows                                                                                                                                   |
|--------------------------|------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------|
| **Colima**               | ⚠️ Same limitation as Lima vz on Apple Silicon — eBPF attach fails.    | —                                                                                                                                         |
| **Linux VM**             | ✅ Multipass, VMware, Parallels, or UTM — run Ubuntu and Docker inside. | ✅ Multipass, VMware, or Hyper-V — run Ubuntu and Docker inside.                                                                           |
| **WSL2 (custom kernel)** | —                                                                      | ⚠️ Possible but complex: recompile the WSL2 kernel with eBPF flags. See [WSL eBPF guides](https://github.com/microsoft/WSL/issues/13047). |
| **Remote Linux**         | ✅ Use a cloud VM (AWS, GCP, etc.), GitHub Codespaces, or a CI runner.  | ✅ Same.                                                                                                                                   |

---

## 🚀 Quick Start (Linux or Lima)

From the repository root, use the Makefile:

```bash
make build    # Build Docker images
make start    # Start the integration example
make view     # Open Jaeger UI in your browser
```

Or with Docker Compose directly:

```bash
docker compose -f examples/integration/docker-compose.yml up --build
```

| Service            | Purpose                                     | Ports      |
|--------------------|---------------------------------------------|------------|
| **goakt-app**      | Minimal GoAkt app (Tell/Ask between actors) | —          |
| **goakt-ebpf**     | eBPF agent attaching to goakt-app           | —          |
| **otel-collector** | Receives OTLP traces, forwards to Jaeger    | 4317, 4318 |
| **jaeger**         | Trace visualization                         | 16686 (UI) |

## 🎯 View Traces

1. Open http://localhost:16686 (Jaeger UI)
2. Select service `goakt-ebpf`
3. Click **Find Traces**

The app sends Tell and Ask messages every 5 seconds (so the agent, which attaches after ~3s, can capture them). Spans should appear within 10–15 seconds.

**No services in Jaeger?** Run `make diagnose` to check DOCKER_HOST and agent logs. See [Troubleshooting](#troubleshooting).

### Trace validation (CI)

The CI integration test uses `scripts/assert-jaeger-traces` to validate traces in Jaeger:

- **Expected span names:** `actor.doReceive`, `actor.process` (from Tell/Ask and message handling; `actor.systemSpawn` is excluded because Spawn is called before the agent attaches)
- **App span names:** At least one of `send-tell` or `send-ask` (manual spans created by the integration app)
- **Minimum span count:** ≥ 4 spans across all traces
- **Parent propagation:** Spans with `CHILD_OF` references have their parent span present in the same trace
- **Layout C assertion:** At least one `actor.doReceive` span must have an app span (`send-tell` or `send-ask`) as its parent — validates that the userspace context reader correctly extracts parent span context from `*sdk/trace.recordingSpan`

Set `JAEGER_QUERY_URL` (default `http://localhost:16686`) and `JAEGER_SERVICE` (default `goakt-ebpf`) to override.

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

## 🔍 Troubleshooting

| Error                                    | Cause                                                     | Fix                                                                                                                                          |
|------------------------------------------|-----------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------|
| No services in Jaeger                    | Docker using Docker Desktop (not Lima)                    | Run `make diagnose`. If DOCKER_HOST is unset, set it (step 3 above). Quit Docker Desktop. Then `make down && make build && make start`.      |
| `operation not permitted` (Lima vz)      | Lima's vz driver restricts eBPF on Apple Silicon          | Create a Lima instance with QEMU: `limactl start --name=ebpf --vm-type=qemu template:docker`, then set `DOCKER_HOST` to the `ebpf` instance. |
| No services in Jaeger                    | Agent failed to attach (eBPF)                             | Run `make diagnose` and look for `operation not permitted` in agent logs. Try Lima with QEMU (see above) or a Linux host.                    |
| No services in Jaeger                    | Agent attached but no traces yet                          | Wait 10–15 seconds. Select service `goakt-ebpf` in Jaeger dropdown, then click **Find Traces**. Run `make logs` to confirm agent is running. |
| `invalid PID 1: operation not permitted` | eBPF not supported (e.g. Docker Desktop on macOS/Windows) | Use Lima/Colima (Mac), a Linux VM, or a remote Linux host                                                                                    |
| `operation not permitted` when attaching | Insufficient capabilities                                 | The compose file uses `privileged: true`; ensure Docker has permission                                                                       |
| `limactl list docker` returns nothing    | Instance may have a different name                        | Run `limactl list` to see instances; use that name in `limactl list <name>` and `limactl stop <name>`                                        |

## Cleanup

```bash
make down
```

Or: `docker compose -f examples/integration/docker-compose.yml down`
