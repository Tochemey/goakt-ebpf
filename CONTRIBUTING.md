# Contributing

We welcome contributions. This project adheres to [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

## Prerequisites

- [Docker](https://docs.docker.com/get-started/get-docker/)
- [Go](https://go.dev/doc/install) 1.26+

## Getting Started

1. Fork and clone the repository.
2. Run `go mod tidy`.
3. On non-Linux hosts, run `make docker-generate` or `./scripts/generate-bpf.sh` to generate eBPF artifacts via Docker.

## Making Contributions

1. Make your changes.
2. Ensure tests pass (see [Running Tests on Any Platform](#running-tests-on-any-platform)).
3. Run the linter: `golangci-lint run`
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

To verify end-to-end behavior locally:

```bash
make build
make start
make view     # Opens Jaeger UI
```

Or: `docker compose -f examples/integration/docker-compose.yml up --build`. **On macOS:** eBPF requires a Linux kernel. Use [Lima](https://github.com/lima-vm/lima) instead of Docker Desktop — see [examples/integration/README.md](examples/integration/README.md) for setup steps.
