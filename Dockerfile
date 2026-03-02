# syntax=docker/dockerfile:1
# Production Dockerfile for goakt-ebpf eBPF tracing agent
# Build: docker build -t goakt-ebpf .
# Run:  docker run --cap-add=SYS_PTRACE,SYS_ADMIN,BPF,PERFMON --pid=container:TARGET goakt-ebpf -pid 1

# -----------------------------------------------------------------------------
# Stage 1: Build
# -----------------------------------------------------------------------------
FROM golang:1.26-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    linux-headers-generic \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.20.0

WORKDIR /build

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
ARG REPODIR=/build
ENV BPF2GO_CFLAGS="-I${REPODIR}/internal/include/libbpf -I${REPODIR}/internal/include"
ENV GOFLAGS="-mod=mod"
ENV CGO_ENABLED=0

RUN go generate ./internal/instrumentation/bpf/github.com/tochemey/goakt/actor/... \
    && go build -ldflags="-s -w" -o goakt-ebpf ./cmd/cli/...

# -----------------------------------------------------------------------------
# Stage 2: Runtime (minimal)
# -----------------------------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" --uid 65532 appuser

# eBPF requires capabilities at runtime:
#   --cap-add=SYS_PTRACE,SYS_ADMIN,BPF,PERFMON
#   --pid=container:TARGET (share PID namespace with target process)
COPY --from=builder /build/goakt-ebpf /usr/local/bin/goakt-ebpf

USER appuser
ENTRYPOINT ["/usr/local/bin/goakt-ebpf"]
