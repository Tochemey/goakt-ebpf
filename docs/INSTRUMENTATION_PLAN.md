# Instrumentation and Testing Plan

> **Status:** Phases 1–6 and Part 2 implemented. Probes cover all remote server and client calls plus SpawnOn. Cross-platform: `make docker-test`, `make docker-generate`, `make docker-precommit`.

## Part 1: New Instrumentation Targets

### Phase 1: Actor System Spawn (High Value, Low Risk)

**Target:** `(*actorSystem).Spawn`

- **Symbol:** `github.com/tochemey/goakt/v4/actor.(*actorSystem).Spawn`
- **Span:** `actor.systemSpawn`
- **Attributes:** `actor.name`, `actor.kind` (if extractable)
- **Notes:** Main spawn entry point; `SpawnOn`, `SpawnNamedFromFunc`, etc. may call into it or similar paths.

### Phase 1b: SpawnOn (Optional — Implemented)

**Target:** `(*actorSystem).SpawnOn`

- **Symbol:** `github.com/tochemey/goakt/v4/actor.(*actorSystem).SpawnOn`
- **Span:** `actor.spawnOn`
- **Attributes:** `actor.operation=spawn_on`
- **Notes:** Remote placement; uses `FailureModeWarn` (may be absent when cluster disabled).

---

### Phase 2: PID Spawn Child (High Value, Low Risk)

**Target:** `(*PID).SpawnChild`

- **Symbol:** `github.com/tochemey/goakt/v4/actor.(*PID).SpawnChild`
- **Span:** `actor.spawnChild`
- **Attributes:** `actor.name`, `actor.kind`, `actor.parent` (if extractable)

---

### Phase 3: TCP Proto Handlers (Medium Value, Medium Effort)

**Targets:** Remote handlers in `actor/remote_server.go` (receive side of remoting):

| Handler                   | Symbol                                   | Span Name                 |
|---------------------------|------------------------------------------|---------------------------|
| `remoteSpawnHandler`      | `(*actorSystem).remoteSpawnHandler`      | `actor.remoteSpawn`       |
| `remoteSpawnChildHandler` | `(*actorSystem).remoteSpawnChildHandler` | `actor.remoteSpawnChild`  |
| `remoteTellHandler`       | `(*actorSystem).remoteTellHandler`       | `actor.remoteTellReceive` |
| `remoteAskHandler`        | `(*actorSystem).remoteAskHandler`        | `actor.remoteAskReceive`  |

- **Notes:** `remoteTellHandler` / `remoteAskHandler` complement existing `handleRemoteTell` / `handleRemoteAsk` (send side). Package is `actor`, but symbols live in `actor/remote_server.go` (same package).

---

### Phase 4: Relocation (Medium Value, Higher Risk)

**Target:** `(*relocator).Relocate`

- **Symbol:** `github.com/tochemey/goakt/v4/actor.(*relocator).Relocate`
- **Span:** `actor.relocation`
- **Attributes:** `relocation.peer_count` (if extractable)
- **Notes:** `relocator` is unexported; verify symbol is present in non-stripped binaries. Use `FailureModeWarn` if it may be absent.

---

### Implementation Order

| Phase           | Effort | Impact | Risk   |
|-----------------|--------|--------|--------|
| 1. Spawn        | Low    | High   | Low    |
| 2. SpawnChild   | Low    | High   | Low    |
| 3. TCP handlers | Medium | Medium | Low    |
| 4. Relocation   | Medium | Medium | Medium |

---

### Per-Phase Steps

For each new probe:

1. **probe.go** — Add `Uprobe` entry with `Sym`, `EntryProbe`, `ReturnProbe`.
2. **probe.bpf.c** — Add `EVENT_TYPE_*`, map, entry/return uprobes (reuse `start_span_and_store` / `finish_span_and_output`).
3. **processFn** — Add `eventType` branch and span name/attributes.
4. **Regenerate** — Run `go generate ./internal/instrumentation/bpf/.../actor/...`.

---

### Efficiency Notes

1. **Shared event struct** — Keep using `goakt_actor_span_t`; add new `event_type` values.
2. **One map per probe pair** — Follow existing pattern (e.g. `goakt_actor_do_receive`) for goroutine-keyed correlation.
3. **Batch phases** — Do Phase 1 + 2 first (spawn paths), then Phase 3 (TCP handlers), then Phase 4 (relocation).
4. **Optional probes** — Use `FailureModeWarn` for relocation and any symbols that might not exist in all GoAkt versions.

---

### Symbol Verification

Before implementing, confirm symbols in a built GoAkt binary:

```bash
go build -o /tmp/goakt-app ./cmd/...
nm /tmp/goakt-app | grep -E "Spawn|Relocate|remoteSpawn|remoteTell"
```

Or use `go tool nm` on the built binary to validate exact symbol names.

---

## Part 2: Cross-Platform Testing via Docker

> **Status:** Implemented. Use `make docker-test` or `make docker-generate`. See [CONTRIBUTING.md](../CONTRIBUTING.md#running-tests-on-any-platform).

eBPF requires Linux. Developers on macOS or Windows cannot run the full test suite natively. The [OpenTelemetry Go Instrumentation](https://github.com/open-telemetry/opentelemetry-go-instrumentation) project runs tests inside Docker, enabling cross-platform development.

### Approach (from OpenTelemetry Go Instrumentation)

1. **Base Docker image** — Build an image with Go, clang, llvm, libbpf-dev (Linux). Lint uses `golangci/golangci-lint` image.
2. **Run tests inside container** — Mount the repo, run `go test` with `--privileged` (for eBPF tests).
3. **Make targets** — `docker-test`, `docker-generate`, `docker-precommit` for common workflows.

### Implementation

#### 1. Add a "base" stage to the Dockerfile

Create or extend `Dockerfile` with a multi-stage build. The base stage should include:

- `golang:1.26-bookworm` (or match go.mod)
- `clang`, `llvm`, `linux-headers-generic`, `libbpf-dev` (or equivalent)
- `make` (optional, for Makefile-based workflows)

```dockerfile
# Base stage for build/test (Linux with eBPF tools)
FROM golang:1.26-bookworm AS base
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm linux-headers-generic libbpf-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Builder stage (existing)
FROM base AS builder
# ... rest of Dockerfile
```

#### 2. Create `scripts/docker-test.sh`

```bash
#!/usr/bin/env bash
# Run tests inside Docker (works on macOS, Windows, Linux).
# Requires: Docker, repo mounted at /app

set -e
cd "$(dirname "$0")/.."
REPODIR="$(pwd)"

# Build base image
docker build -t goakt-ebpf-base --target base .

# Run tests with privileged mode (for eBPF tests)
docker run --rm \
  --privileged \
  --network=host \
  -v "${REPODIR}:/app" \
  -w /app \
  -e BPF2GO_CFLAGS="-I/app/internal/include/libbpf -I/app/internal/include" \
  -e GOFLAGS="-mod=mod" \
  goakt-ebpf-base \
  /bin/sh -c "go generate ./internal/instrumentation/bpf/.../actor/... && go test -v -race -count=1 ./..."
```

#### 3. Makefile targets (optional)

Add to `Makefile` (or document in CONTRIBUTING.md):

```makefile
.PHONY: docker-test
docker-test:
	docker build -t goakt-ebpf-base --target base .
	docker run --rm --privileged --network=host \
		-v "$(shell pwd):/app" -w /app \
		-e BPF2GO_CFLAGS="-I/app/internal/include/libbpf -I/app/internal/include" \
		goakt-ebpf-base \
		/bin/sh -c "go generate ./... && go test -v -race -count=1 ./..."

.PHONY: docker-generate
docker-generate:
	docker build -t goakt-ebpf-base --target base .
	docker run --rm -v "$(shell pwd):/app" -w /app \
		-e BPF2GO_CFLAGS="-I/app/internal/include/libbpf -I/app/internal/include" \
		goakt-ebpf-base \
		/bin/sh -c "go generate ./internal/instrumentation/bpf/.../actor/..."
```

#### 4. Update CONTRIBUTING.md

Document the Docker-based workflow:

```markdown
## Running Tests on Any Platform

eBPF requires Linux. On macOS or Windows, run the full test suite via Docker:

```bash
./scripts/docker-test.sh
```

Or with Make:

```bash
make docker-test
```

This builds a Linux base image, runs BPF generation, and executes all tests (including Linux-only and eBPF tests) inside the container.
```

#### 5. CI consideration

CI already runs on `ubuntu-latest`, so tests run natively. The Docker-based approach is optional for CI but useful for:

- macOS/Windows contributors
- Local verification before pushing
- Consistency with OpenTelemetry Go Instrumentation workflow

### Key Differences from OpenTelemetry

| Aspect        | OpenTelemetry Go Instrumentation                 | goakt-ebpf                            |
|---------------|--------------------------------------------------|---------------------------------------|
| Base image    | `golang:1.26-bookworm` + clang, llvm, libbpf-dev | Same (add clang, llvm, linux-headers) |
| Test mount    | `-v REPODIR:/usr/src/go.opentelemetry.io/auto`   | `-v REPODIR:/app`                     |
| Privileged    | `--privileged` for eBPF tests                    | Same                                  |
| Docker socket | `-v /var/run/docker.sock` (for Docker-in-Docker) | Not needed for basic tests            |
| User          | `--user=root`                                    | Default (root) for privileged         |

### Summary

- **`scripts/docker-test.sh`** — Run `go generate` + `go test` in Docker.
- **Dockerfile base stage** — Linux image with Go, clang, llvm, libbpf-dev, bpf2go.
- **CONTRIBUTING.md** — Document `./scripts/docker-test.sh` and `make docker-precommit` for cross-platform users.
- **Makefile** — `make docker-test`, `make docker-generate`, `make docker-precommit`.

---

## Part 3: Richer Span Attributes (Deferred)

**Target:** Extract `actor.name`, `actor.kind`, `actor.parent` via StructFieldConst.

**Requirements:**

1. **Offset index** — Create JSON index of DWARF-derived offsets for GoAkt structs (e.g., `PID.path`, `path.name`, `path.system`).
2. **StructFieldConst** — Add Const entries to the probe; inject offsets into BPF.
3. **BPF reads** — Extend `goakt_actor_span_t` or event handling to read struct fields at injected offsets.
4. **String handling** — Go strings are (ptr, len); eBPF must read from process memory with bounds checks.

**Deferred:** Requires offset extraction tooling and GoAkt struct layout stability. See `internal/structfield` and `internal/inject` for the framework.
