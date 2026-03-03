# Makefile for goakt-ebpf
# Run from repository root

COMPOSE_FILE := examples/integration/docker-compose.yml
JAEGER_URL := http://localhost:16686

# Cross-platform BPF/test (macOS, Windows, Linux)
DOCKER_BASE_IMAGE := goakt-ebpf-base
DOCKER_MOUNT := -v "$(CURDIR):/app" -w /app
DOCKER_BPF_ENV := -e BPF2GO_CFLAGS="-I/app/internal/include/libbpf -I/app/internal/include" -e GOFLAGS="-mod=mod"
BPF_GENERATE := go generate ./internal/instrumentation/bpf/github.com/tochemey/goakt/actor/...

.PHONY: help build start up stop down view logs verify-lima diagnose docker-test docker-generate docker-precommit

.DEFAULT_GOAL := help

help:
	@echo "Integration example targets:"
	@echo "  make build          - Build Docker images"
	@echo "  make start          - Start the integration example (builds if needed)"
	@echo "  make up             - Start with foreground logs (Ctrl+C to stop)"
	@echo "  make stop           - Stop the integration example"
	@echo "  make down           - Stop and remove containers"
	@echo "  make view           - Open Jaeger UI in browser to view traces"
	@echo "  make logs           - Follow container logs"
	@echo "  make verify-lima    - Verify Docker is using Lima (Mac only)"
	@echo "  make diagnose       - Show agent logs and Docker host (for troubleshooting)"
	@echo ""
	@echo "Cross-platform (eBPF requires Linux):"
	@echo "  make docker-test     - Run BPF generate + tests in Docker (macOS/Windows/Linux)"
	@echo "  make docker-generate - Regenerate BPF artifacts in Docker"
	@echo "  make docker-precommit - Run generate + test + lint in Docker (full pre-commit check)"

## Build Docker images for the integration example
build:
	docker compose -f $(COMPOSE_FILE) build

## Start the integration example (builds if needed, runs in background)
start:
	docker compose -f $(COMPOSE_FILE) up --build -d
	@echo ""
	@echo "Integration example is running. View traces: make view"
	@echo "Or open $(JAEGER_URL) in your browser"

## Start with foreground logs (useful for debugging)
up:
	docker compose -f $(COMPOSE_FILE) up --build

## Stop the integration example
stop:
	docker compose -f $(COMPOSE_FILE) stop

## Remove containers and networks
down:
	docker compose -f $(COMPOSE_FILE) down

## Open Jaeger UI in browser to view traces
view:
	@echo "Opening Jaeger UI at $(JAEGER_URL)..."
	@command -v open >/dev/null 2>&1 && open $(JAEGER_URL) || \
	command -v xdg-open >/dev/null 2>&1 && xdg-open $(JAEGER_URL) || \
	echo "Open $(JAEGER_URL) in your browser (service: goakt-ebpf)"

## Follow container logs
logs:
	docker compose -f $(COMPOSE_FILE) logs -f

## Verify Docker is using Lima (Mac). Run before make start if traces don't appear.
verify-lima:
	@echo "Checking Docker host..."
	@if [ -z "$$DOCKER_HOST" ]; then \
		echo "ERROR: DOCKER_HOST is not set. Docker may be using Docker Desktop (no eBPF)."; \
		echo ""; \
		echo "Run:"; \
		echo "  export DOCKER_HOST=\$$(limactl list docker --format 'unix://{{.Dir}}/sock/docker.sock')"; \
		echo ""; \
		echo "Then add that line to ~/.zshrc or ~/.bashrc."; \
		exit 1; \
	fi
	@if echo "$$DOCKER_HOST" | grep -q lima; then \
		echo "OK: DOCKER_HOST points to Lima ($$DOCKER_HOST)"; \
	else \
		echo "WARNING: DOCKER_HOST ($$DOCKER_HOST) may not be Lima."; \
		echo "For eBPF on Mac, use: export DOCKER_HOST=\$$(limactl list docker --format 'unix://{{.Dir}}/sock/docker.sock')"; \
	fi
	@echo ""; \
	docker info 2>/dev/null | grep -E "Operating System|Server Version" || true

## Show agent logs and Docker host (run after make start if no traces appear)
diagnose:
	@echo "=== DOCKER_HOST ==="
	@echo "$${DOCKER_HOST:-<not set - Docker may be using Docker Desktop!>}"
	@echo ""
	@echo "=== goakt-ebpf agent logs (last 40 lines) ==="
	@docker compose -f $(COMPOSE_FILE) logs goakt-ebpf 2>&1 | tail -40
	@echo ""
	@echo "If you see 'operation not permitted' above, eBPF is not supported."
	@echo "On Mac: use Lima with QEMU (brew install qemu, then limactl start --name=ebpf --vm-type=qemu template:docker)."

## Regenerate BPF artifacts in Docker (works on macOS, Windows, Linux)
docker-generate:
	docker build -t $(DOCKER_BASE_IMAGE) --target base .
	docker run --rm $(DOCKER_MOUNT) $(DOCKER_BPF_ENV) $(DOCKER_BASE_IMAGE) \
		/bin/sh -c "$(BPF_GENERATE)"

## Run BPF generate + tests in Docker (works on macOS, Windows, Linux)
docker-test:
	docker build -t $(DOCKER_BASE_IMAGE) --target base .
	docker run --rm --privileged $(DOCKER_MOUNT) $(DOCKER_BPF_ENV) $(DOCKER_BASE_IMAGE) \
		/bin/sh -c "$(BPF_GENERATE) && go test -v -race -count=1 ./..."

## Run generate + test + lint in Docker (full pre-commit check)
docker-precommit:
	$(MAKE) docker-test
	docker run --rm $(DOCKER_MOUNT) -w /app golangci/golangci-lint:latest \
		golangci-lint run --timeout 10m
