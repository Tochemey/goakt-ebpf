# Grains Example

Demonstrates eBPF auto-instrumentation of GoAkt **grains** (virtual actors).
The app contains **zero tracing code in the grain implementations** — the
`goakt-ebpf` agent produces the grain spans by attaching uprobes to the GoAkt
runtime, and links them under the app's own OTEL spans (otelhttp and manual
`tracer.Start`) via userspace context extraction.

## What the app does

- **`counterGrain`** — a stateful virtual actor, one activation per identity
  (`counter-<id>`), holding that identity's count. Handles `increment`
  (fire-and-forget) and `get` (request/response).
- **`auditGrain`** — notified by every counter via `ctx.TellGrain` on each
  increment: a grain-to-grain send, which delegates to
  `actorSystem.TellGrain` and is therefore captured by the same agent probes.
- **Two trigger paths** (the same two span sources the integration example
  validates):
  - `otelhttp` handlers: `GET /increment?id=<key>` → `TellGrain`,
    `GET /count?id=<key>` → `AskGrain`
  - a 5s ticker with manual spans: `send-tell-grain`, `send-ask-grain`

App spans are pretty-printed to stdout by default (OTEL stdout trace
exporter) so traces are viewable without a backend. Set
`OTEL_TRACES_STDOUT=0` to silence.

## Spans the agent produces

| Span              | Probe target                       | Meaning                                    |
|-------------------|------------------------------------|--------------------------------------------|
| `grain.tell`      | `(*actorSystem).TellGrain`         | Caller-side fire-and-forget send           |
| `grain.ask`       | `(*actorSystem).AskGrain`          | Caller-side request, includes wait time    |
| `grain.doReceive` | `(*grainPID).receive`              | Enqueue into the grain mailbox             |
| `grain.process`   | `(*grainPID).handleGrainContext`   | Actual handling on a dispatcher worker     |

Expected trace shape for a `GET /count` request:

```
GET /count (otelhttp, app span)
├── grain.ask            eBPF: caller side, includes response wait
└── grain.doReceive      eBPF: mailbox enqueue
    └── grain.process    eBPF: grain handling
```

An `increment` additionally produces the audit notification's
`grain.tell` → `grain.doReceive` → `grain.process` chain from inside the
counter grain's handler.

## Run it

Everything runs in Docker ([docker-compose.yml](docker-compose.yml)): the
OTel Collector + Jaeger backend, the app, and the agent attached to the
app's PID namespace. eBPF needs a Linux kernel — native on Linux, via
[Lima](https://github.com/lima-vm/lima) on macOS (`make verify-lima`;
Docker Desktop's VM does not support eBPF, see
[../integration](../integration/README.md) for Lima setup).

From the repo root:

```bash
make grains-start   # build + start backend, app, and agent; generates traces
make grains-trace   # call /increment and /count for fresh traces
make grains-view    # open the Jaeger UI (http://localhost:16686)
make grains-logs    # follow app/agent logs, including stdout spans
make grains-stop    # tear everything down
```

`grains-start` generates traffic two ways: the app's built-in 5s ticker
(`send-tell-grain` / `send-ask-grain`) starts immediately, and the target
ends by curling both HTTP endpoints (`make grains-trace`).

> The backend binds ports 4317/4318 and 16686 — stop the integration
> example's stack first if it is running (`make down`).

To run against a host app on Linux instead (the flow CI uses), see
[../../scripts/ci-integration.sh](../../scripts/ci-integration.sh): start
`examples/integration/docker-compose.ci.yml`, run the app with OTLP pointed
at `localhost:4318`, and attach the agent with
`sudo goakt-ebpf -pid <app pid>`.

Trigger grain messages by key and view traces at <http://localhost:16686>
(service `goakt-ebpf`):

```bash
curl "http://localhost:8082/increment?id=alice"
curl "http://localhost:8082/count?id=alice"
```

CI runs this example end-to-end on every PR: `scripts/ci-integration.sh`
starts the app, attaches the agent, and `scripts/assert-jaeger-traces`
verifies the `app → grain.doReceive → grain.process` chains and the
caller-side `grain.tell`/`grain.ask` linkage.
