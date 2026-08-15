# Contributing

We welcome contributions. This project adheres to [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

## Prerequisites

- [Docker](https://docs.docker.com/get-started/get-docker/)
- [Go](https://go.dev/doc/install) 1.26+

## Getting Started

1. Fork and clone the repository.
2. Run `go mod tidy`.
3. On non-Linux hosts, run `make docker-generate` (or `./scripts/generate-bpf.sh`) to generate eBPF artifacts via Docker.

If you change `internal/instrumentation/bpf/**/probe.bpf.c` or the probe manifest, regenerate the committed BPF bindings (`bpf_*_bpfel.go`) with `make docker-generate` before opening a PR.

## Making Contributions

1. Make your changes.
2. Ensure tests pass (see [Running Tests on Any Platform](#running-tests-on-any-platform)).
3. Run the linter: `golangci-lint run` (or `make docker-precommit` for generate + test + lint).
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/).
5. Open a pull request against `main`.

## Running Tests on Any Platform

eBPF requires Linux. On macOS or Windows, run the full test suite via Docker:

```bash
make docker-test
```

Or use the script directly:

```bash
./scripts/docker-test.sh
```

This builds a Linux base image, runs BPF generation, and executes all tests (including eBPF tests) inside the container. To regenerate BPF artifacts only:

```bash
make docker-generate
```

For a full pre-commit check (generate + test + lint):

```bash
make docker-precommit
```

**On Linux:** Run tests natively with `go test ./...`.

## Testing the Integration Example

The local example is a Docker Compose stack: the GoAkt app, the eBPF agent, and a self-hosted [SigNoz](https://signoz.io/) UI. From the repository root:

```bash
make build    # fetch SigNoz and build images (first run can take several minutes)
make start    # start the stack and call GET /echo and GET /ask
make view     # open SigNoz at http://localhost:8080
```

Log in with `admin@goakt.local` / `GoAkt-eBPF-2026!` (local demo only). In **Traces**, switch to **Trace View** and open a recent `GET /echo` or `GET /ask` trace. You should see:

```
GET /ask                      ← integration-app (otelhttp)
  └── actor.doReceive         ← goakt-ebpf
        └── actor.process     ← goakt-ebpf
```

`make start` already hits those HTTP endpoints. To generate more traces:

```bash
make trace-http
# or
curl http://localhost:8081/echo
curl http://localhost:8081/ask
```

The app also emits `send-tell` / `send-ask` every 5 seconds with the same 3-level tree.

**On macOS:** eBPF requires a Linux kernel. Use [Lima](https://github.com/lima-vm/lima) instead of Docker Desktop — see [examples/integration/README.md](examples/integration/README.md). Run `make verify-lima` before `make start`, and `make diagnose` if traces do not appear.

```bash
make down     # remove containers, volumes, and networks
```

CI still validates traces against Jaeger via `examples/integration/docker-compose.ci.yml` and `scripts/assert-jaeger-traces`. That path is separate from the local SigNoz stack.
