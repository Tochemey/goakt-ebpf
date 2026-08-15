# Makefile for goakt-ebpf
# Run from repository root

COMPOSE_FILE := examples/integration/docker-compose.yml
SIGNOZ_SOURCE_DIR := examples/integration/.signoz
SIGNOZ_VERSION := v0.129.0
SIGNOZ_COMPOSE := $(SIGNOZ_SOURCE_DIR)/deploy/docker/docker-compose.yaml
SIGNOZ_COMPOSE_CLEAN := $(SIGNOZ_SOURCE_DIR)/deploy/docker/.goakt-compose.yaml
SIGNOZ_VERSION_MARKER := $(SIGNOZ_SOURCE_DIR)/.goakt-version
APP_URL := http://localhost:8081
SIGNOZ_URL := http://localhost:8080

# Cross-platform BPF/test (macOS, Windows, Linux)
DOCKER_BASE_IMAGE := goakt-ebpf-base
DOCKER_MOUNT := -v "$(CURDIR):/app" -w /app
DOCKER_BPF_ENV := -e BPF2GO_CFLAGS="-I/app/internal/include/libbpf -I/app/internal/include" -e GOFLAGS="-mod=mod"
BPF_GENERATE := go generate ./internal/instrumentation/bpf/github.com/tochemey/goakt/actor/...

.PHONY: help build start view trace-http signoz-source up stop down logs verify-lima diagnose docker-test docker-generate docker-precommit

.DEFAULT_GOAL := help

help:
	@echo "Integration example targets:"
	@echo "  make build           - Fetch SigNoz and build all images"
	@echo "  make start           - Start SigNoz and the integration example"
	@echo "  make view            - Open the SigNoz UI"
	@echo "  make trace-http      - Call /echo and /ask to generate fresh traces"
	@echo "  make up              - Start with foreground logs (Ctrl+C to stop)"
	@echo "  make logs            - Follow container logs"
	@echo "  make stop            - Stop containers without removing them"
	@echo "  make down            - Remove all containers, volumes, and networks"
	@echo "  make verify-lima     - Verify Docker is using Lima (Mac only)"
	@echo "  make diagnose        - Show agent logs and Docker host (troubleshooting)"
	@echo ""
	@echo "Cross-platform (eBPF requires Linux):"
	@echo "  make docker-test      - Run BPF generate + tests in Docker"
	@echo "  make docker-generate  - Regenerate BPF artifacts in Docker"
	@echo "  make docker-precommit - Run generate + test + lint in Docker"

# Download the pinned SigNoz release (skips the network when already in sync)
# and generate the Compose file included by $(COMPOSE_FILE).
signoz-source:
	@set -e; \
	if [ "$$(cat "$(SIGNOZ_VERSION_MARKER)" 2>/dev/null)" != "$(SIGNOZ_VERSION)" ]; then \
		if [ ! -d "$(SIGNOZ_SOURCE_DIR)/.git" ]; then \
			git clone --depth 1 --branch "$(SIGNOZ_VERSION)" https://github.com/SigNoz/signoz.git "$(SIGNOZ_SOURCE_DIR)"; \
		else \
			git -C "$(SIGNOZ_SOURCE_DIR)" fetch --depth 1 origin "refs/tags/$(SIGNOZ_VERSION)" && \
			git -C "$(SIGNOZ_SOURCE_DIR)" checkout --detach FETCH_HEAD; \
		fi; \
		echo "$(SIGNOZ_VERSION)" > "$(SIGNOZ_VERSION_MARKER)"; \
	fi
	@sed '/^version:[[:space:]]*/d' "$(SIGNOZ_COMPOSE)" > "$(SIGNOZ_COMPOSE_CLEAN)"

## Fetch SigNoz and build all required Docker images
build: signoz-source
	docker compose -f $(COMPOSE_FILE) build

## Start the integration example (builds if needed, runs in background)
start: build
	docker compose -f $(COMPOSE_FILE) up -d
	$(MAKE) trace-http
	@echo ""
	@echo "SigNoz and the integration example are running. View traces: make view"

## Call the instrumented HTTP endpoints to generate fresh traces
trace-http:
	@echo "Waiting for the app and eBPF agent to become ready..."
	@echo "GET /echo:"
	@curl --fail --silent --show-error --retry 15 --retry-delay 2 --retry-connrefused "$(APP_URL)/echo"
	@echo "GET /ask:"
	@curl --fail --silent --show-error --retry 15 --retry-delay 2 --retry-connrefused -o /dev/null -w "%{http_code}\n" "$(APP_URL)/ask"

## Start with foreground logs (useful for debugging)
up: signoz-source
	docker compose -f $(COMPOSE_FILE) up

## Stop the integration example
stop:
	docker compose -f $(COMPOSE_FILE) stop

## Remove all containers, volumes, and networks (always succeeds)
down:
	@if [ -f "$(SIGNOZ_COMPOSE)" ] && [ ! -f "$(SIGNOZ_COMPOSE_CLEAN)" ]; then \
		sed '/^version:[[:space:]]*/d' "$(SIGNOZ_COMPOSE)" > "$(SIGNOZ_COMPOSE_CLEAN)"; \
	fi
	@if [ -f "$(SIGNOZ_COMPOSE_CLEAN)" ]; then \
		docker compose -f "$(COMPOSE_FILE)" down --volumes --remove-orphans --timeout 0 || true; \
	fi
	@# Force-remove anything Compose left behind (e.g. zombie containers).
	@leftovers="$$(docker ps -aq --filter label=com.docker.compose.project=signoz) \
		$$(docker ps -aq --filter label=com.docker.compose.project=integration) \
		$$(docker ps -aq --filter name=signoz --filter name=integration-)"; \
	leftovers="$$(echo $$leftovers | tr ' ' '\n' | sort -u)"; \
	if [ -n "$$leftovers" ]; then docker rm -f $$leftovers 2>/dev/null || true; fi
	@volumes="$$(docker volume ls -q --filter name=signoz) \
		$$(docker volume ls -q --filter name=integration_)"; \
	if [ -n "$$volumes" ]; then docker volume rm -f $$volumes 2>/dev/null || true; fi
	@networks="$$(docker network ls -q --filter name=signoz) \
		$$(docker network ls -q --filter name=integration_)"; \
	if [ -n "$$networks" ]; then docker network rm $$networks 2>/dev/null || true; fi
	@echo "All integration and SigNoz containers, volumes, and networks removed."

## Open SigNoz UI in browser to view traces
view:
	@echo "Opening SigNoz at $(SIGNOZ_URL)..."
	@if command -v open >/dev/null 2>&1 && open "$(SIGNOZ_URL)" >/dev/null 2>&1; then :; \
	elif command -v xdg-open >/dev/null 2>&1 && xdg-open "$(SIGNOZ_URL)" >/dev/null 2>&1; then :; \
	else echo "Could not open a browser automatically. Open $(SIGNOZ_URL) manually."; fi

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
