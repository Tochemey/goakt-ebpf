#!/usr/bin/env bash
# Run tests inside Docker (works on macOS, Windows, Linux).
# eBPF requires Linux; this script enables cross-platform development.
# See docs/INSTRUMENTATION_PLAN.md#part-2-cross-platform-testing-via-docker

set -e

cd "$(dirname "$0")/.."
REPODIR="$(pwd)"

echo "Building goakt-ebpf base image..."
docker build -t goakt-ebpf-base --target base .

echo "Running generate + test in Docker..."
docker run --rm \
  --privileged \
  -v "${REPODIR}:/app" \
  -w /app \
  -e BPF2GO_CFLAGS="-I/app/internal/include/libbpf -I/app/internal/include" \
  -e GOFLAGS="-mod=mod" \
  goakt-ebpf-base \
  /bin/sh -c "go generate ./internal/instrumentation/bpf/github.com/tochemey/goakt/actor/... && go test -v -race -count=1 ./..."

echo "Done."
