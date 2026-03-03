#!/usr/bin/env bash
# Run integration test with app and agent on host (not in Docker).
# eBPF works on GitHub Actions when run directly on the runner; see
# https://keploy.io/blog/community/executing-ebpf-in-github-actions
set -e

cd "$(dirname "$0")/.."
ROOT=$(pwd)

APP_PID=""
AGENT_PID=""
cleanup() {
  [[ -n "$AGENT_PID" ]] && sudo kill $AGENT_PID 2>/dev/null || true
  [[ -n "$APP_PID" ]] && kill $APP_PID 2>/dev/null || true
  docker compose -f examples/integration/docker-compose.backend.yml down -v 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Starting backend (collector + Jaeger) ==="
docker compose -f examples/integration/docker-compose.backend.yml up -d
sleep 5

echo "=== Building integration app ==="
cd examples/integration/app
go build -o /tmp/integration-app .
cd "$ROOT"

echo "=== Installing BPF tools and generating ==="
sudo apt-get update -qq
sudo apt-get install -y -qq clang llvm linux-headers-generic
export BPF2GO_CFLAGS="-I$ROOT/internal/include/libbpf -I$ROOT/internal/include"
export GOFLAGS="-mod=mod"
go generate ./internal/instrumentation/bpf/github.com/tochemey/goakt/actor/...

echo "=== Building goakt-ebpf agent ==="
go build -o /tmp/goakt-ebpf ./cmd/cli/...

echo "=== Starting integration app in background ==="
/tmp/integration-app &
APP_PID=$!
sleep 3

echo "=== Starting agent (attach to PID $APP_PID) ==="
# Use `sudo env` to explicitly pass OTEL vars - sudo env_reset strips them even with -E.
sudo env \
  OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
  OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
  OTEL_SERVICE_NAME=goakt-ebpf \
  /tmp/goakt-ebpf -pid $APP_PID &
AGENT_PID=$!

echo "=== Waiting for traces (60s) ==="
sleep 60

echo "=== Verifying traces in Jaeger ==="
TRACES=$(curl -sf "http://localhost:16686/api/traces?service=goakt-ebpf&limit=1" 2>/dev/null || echo "{}")
if echo "$TRACES" | grep -qE '"data":\s*\[[^]]+'; then
  echo "Traces found in Jaeger - integration OK"
else
  echo "No traces in Jaeger. Response: $TRACES"
  exit 1
fi

echo "=== Integration test passed ==="
