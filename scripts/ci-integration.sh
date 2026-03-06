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
go build -mod=mod -o /tmp/integration-app .
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
HTTP_PORT=8080
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
OTEL_SERVICE_NAME=integration-app \
OTEL_TRACES_STDOUT=1 \
HTTP_PORT=$HTTP_PORT \
/tmp/integration-app &
APP_PID=$!
sleep 3

echo "=== Starting agent (attach to PID $APP_PID) ==="
# Use `sudo env` to explicitly pass OTEL vars - sudo env_reset strips them even with -E.
sudo env \
  OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318 \
  OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf \
  OTEL_SERVICE_NAME=goakt-ebpf \
  OTEL_TRACES_STDOUT=1 \
  /tmp/goakt-ebpf -pid $APP_PID &
AGENT_PID=$!

echo "=== Waiting for agent to attach (5s) ==="
sleep 5

echo "=== Triggering HTTP requests (otelhttp + Layout C validation) ==="
for i in 1 2 3 4 5; do
  curl -sf "http://localhost:$HTTP_PORT/echo" >/dev/null || true
  curl -sf "http://localhost:$HTTP_PORT/ask" >/dev/null || true
  sleep 1
done

echo "=== Waiting for traces (55s) ==="
sleep 55

echo "=== Verifying traces in Jaeger ==="
SERVICES=$(curl -sf "http://localhost:16686/api/services" 2>/dev/null || echo '{"data":[]}')
echo "Jaeger services: $SERVICES"
go build -o /tmp/assert-jaeger-traces ./scripts/assert-jaeger-traces
/tmp/assert-jaeger-traces

echo "=== Integration test passed ==="
