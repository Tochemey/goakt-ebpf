# Contributing

We welcome contributions. This project adheres to [Conventional Commits](https://www.conventionalcommits.org/) for commit messages.

## Prerequisites

- [Docker](https://docs.docker.com/get-started/get-docker/)
- [Go](https://go.dev/doc/install) 1.26+

## Getting Started

1. Fork and clone the repository.
2. Run `go mod tidy`.
3. On non-Linux hosts, run `./scripts/generate-bpf.sh` to generate eBPF artifacts via Docker.

## Making Contributions

1. Make your changes.
2. Ensure tests pass: `go test ./...`
3. Run the linter: `golangci-lint run`
4. Commit using [Conventional Commits](https://www.conventionalcommits.org/).
5. Open a pull request against `main`.

## Testing the Integration Example

To verify end-to-end behavior locally:

```bash
docker compose -f examples/integration/docker-compose.yml up --build
```

Then open http://localhost:16686 (Jaeger UI) to view traces.
