#!/usr/bin/env bash
# Generate BPF .o files (requires Linux with clang/llvm).
# Run via Docker on macOS: ./scripts/generate-bpf.sh

set -e

cd "$(dirname "$0")/.."
REPODIR="$(pwd)"

# Use Docker if not on Linux
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Not on Linux; running generate in Docker..."
  docker run --rm \
    -v "${REPODIR}:/build" \
    -w /build \
    -e BPF2GO_CFLAGS="-I/build/internal/include/libbpf -I/build/internal/include" \
    -e GOFLAGS="-mod=mod" \
    golang:1.26-bookworm \
    bash -c 'apt-get update -qq && apt-get install -y -qq clang llvm linux-headers-generic > /dev/null && go install github.com/cilium/ebpf/cmd/bpf2go@v0.20.0 && go generate ./internal/instrumentation/bpf/github.com/tochemey/goakt/actor/...'
  echo "Done. Verify: ls internal/instrumentation/bpf/github.com/tochemey/goakt/actor/*.o"
  exit 0
fi

# On Linux, run directly
export BPF2GO_CFLAGS="-I${REPODIR}/internal/include/libbpf -I${REPODIR}/internal/include"
export GOFLAGS="-mod=mod"
go generate ./internal/instrumentation/bpf/github.com/tochemey/goakt/actor/...
echo "Done."
