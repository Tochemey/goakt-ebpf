# goakt-ebpf Earthfile
# Phase 1: Foundation - deps, generate (BPF), build
# Uses Earthly for reproducible builds. See https://earthly.dev

VERSION 0.8

# Base image with Go and build tools for eBPF (clang, llvm, libbpf)
FROM golang:1.26-bookworm

# Install eBPF build dependencies: clang, llvm, linux headers
# Use linux-headers-generic for platform-agnostic headers (works on amd64 and arm64)
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    linux-headers-generic \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install bpf2go for eBPF code generation
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.20.0

WORKDIR /app

# -----------------------------------------------------------------------------
# copy-include: Fetch internal/include from OpenTelemetry go-instrumentation.
# Run once to populate, or again to refresh: earthly +copy-include
# -----------------------------------------------------------------------------
copy-include:
    RUN git clone --depth 1 https://github.com/open-telemetry/opentelemetry-go-instrumentation.git /tmp/otel-go
    RUN mkdir -p /app/internal
    RUN cp -r /tmp/otel-go/internal/include /app/internal/
    RUN rm -rf /tmp/otel-go
    SAVE ARTIFACT /app/internal/include AS LOCAL internal/

# -----------------------------------------------------------------------------
# deps: Download Go module dependencies
# -----------------------------------------------------------------------------
deps:
    COPY go.mod ./
    RUN go mod download
    RUN go mod tidy
    SAVE ARTIFACT go.mod go.sum AS LOCAL .

# -----------------------------------------------------------------------------
# generate: Run go generate with BPF2GO_CFLAGS for eBPF C compilation.
# Requires internal/include to exist (run +copy-include first if missing).
# -----------------------------------------------------------------------------
generate:
    FROM +deps
    COPY --dir . .
    ARG REPODIR=/app
    ENV BPF2GO_CFLAGS="-I${REPODIR}/internal/include/libbpf -I${REPODIR}/internal/include"
    RUN go generate ./...
    SAVE ARTIFACT /app/internal/instrumentation/bpf AS LOCAL internal/instrumentation/bpf

# -----------------------------------------------------------------------------
# build: Build the goakt-ebpf binary (requires +generate for eBPF probes)
# -----------------------------------------------------------------------------
build:
    FROM +generate
    RUN CGO_ENABLED=0 go build -o goakt-ebpf ./cmd/cli/...
    SAVE ARTIFACT goakt-ebpf AS LOCAL goakt-ebpf

# -----------------------------------------------------------------------------
# all: Default target - deps and build
# -----------------------------------------------------------------------------
all:
    BUILD +build
