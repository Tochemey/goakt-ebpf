# Build stage: compile the minimal GoAkt integration app
FROM golang:1.26-bookworm AS builder

WORKDIR /build

COPY app/go.mod app/go.sum ./
RUN go mod download

COPY app/ .
RUN CGO_ENABLED=0 go build -o integration-app .

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/integration-app /usr/local/bin/integration-app

ENTRYPOINT ["integration-app"]
