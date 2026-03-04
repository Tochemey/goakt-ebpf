# Recommendations for goakt-ebpf

Based on inspection of the goakt-ebpf source and empirical validation of actual Go struct layouts
(via reflection + binary memory scanning against `go.opentelemetry.io/otel v1.41.0` and
`go.opentelemetry.io/auto/sdk v1.2.1`), the following recommendations are provided to improve
**parent-child span correlation** between application-level spans and goakt-ebpf actor spans.

---

## Executive Summary

goakt-ebpf uses **Userspace Context Reading** (`internal/process/context_reader_linux.go`) to
extract OTEL span context from the target process's Go `context.Context` chain. This enables
goakt-ebpf spans (actor.doReceive, actor.process, remote Tell/Ask, etc.) to become **children**
of any application-level span when the context flows into the actor system.

**Goal:** Extract parent-child span relations **regardless of the parent's origin**. The parent
span may come from:

- **HTTP** (otelhttp, chi, echo, gin, etc.)
- **gRPC** (otelgrpc, connect, etc.)
- **Message queues** (Kafka, RabbitMQ, NATS — when trace context is propagated)
- **Manual spans** (`tracer.Start(ctx, "operation")`)
- **Other instrumentation** (DB drivers, RPC clients, etc.)
- **Remote propagation** (GoAkt's ContextPropagator for cross-node traces)

**goakt-ebpf must support both SDKs:**

- **Standard OTEL SDK** (`go.opentelemetry.io/otel/sdk/trace`) — applications that initialize
  their own `TracerProvider` with OTLP export
- **Auto SDK** (`go.opentelemetry.io/auto/sdk`) — applications that use
  `autosdk.TracerProvider()` for eBPF-friendly context propagation

The context reader must recognize span structures from both SDKs so that **any** application span
(HTTP, gRPC, manual, or otherwise) can serve as the parent of goakt-ebpf actor spans when its
context reaches the instrumented functions.

---

## 1. Dual-SDK Context Reader Support — Validated Layouts

**Current behavior:** `ExtractSpanContextFromContext` reads `val.data` from each `valueCtx` node
and interprets it using a single layout (`trace.nonRecordingSpan` from the API package).  It reads
41 bytes, validates that bytes `[0:16]` are zero (the embedded `noopSpan`), and extracts the
`SpanContext` starting at offset 16.

### Why This Breaks for HTTP Spans

The current layout only matches **one** of the four concrete span types that appear in
`context.Context` chains. When `otelhttp` (or any sampled instrumentation library) calls
`tracer.Start(ctx, "name")`, it stores a `*recordingSpan` — not a `nonRecordingSpan` — in the
context. The current reader silently fails to decode it, causing actor spans to appear as root
spans with no parent.

### Empirically Validated Layouts (amd64/arm64, OTEL SDK v1.41.0 / Auto SDK v1.2.1)

#### Layout A — `trace.nonRecordingSpan` (API package: `go.opentelemetry.io/otel/trace`)

```
offset  0  size 16   noopSpan (trace.noopSpan = embedded.Span wrapper, always zero)
offset 16  size 64   sc trace.SpanContext
  └─ offset 16  TraceID [16]byte
  └─ offset 32  SpanID  [8]byte
  └─ offset 40  TraceFlags byte
total size: 80 bytes
```

**When it appears:** `trace.ContextWithSpanContext(ctx, sc)` — used by W3C/B3 propagators to
store a remote parent before starting the local child span. The context reader's current
implementation correctly handles this layout.

**Heuristic:** bytes `[0:16]` == zero; valid `TraceID` at offset 16.

#### Layout B — `sdk/trace.nonRecordingSpan` (SDK package: `go.opentelemetry.io/otel/sdk/trace`)

```
offset  0  size 16   embedded.Span (always zero)
offset 16  size  8   tracer *tracer (pointer, non-zero)
offset 24  size 64   sc trace.SpanContext
  └─ offset 24  TraceID [16]byte
  └─ offset 40  SpanID  [8]byte
  └─ offset 48  TraceFlags byte
total size: 88 bytes
```

**When it appears:** `tracer.Start(ctx, "name")` when the sampler returns `DROP`
(e.g., `sdktrace.NeverSample()`). The span is stored as a value (not a pointer) in the interface.

**Heuristic:** bytes `[0:16]` == zero; bytes `[16:24]` are a non-zero pointer (tracer);
valid `TraceID` at offset 24. The current reader misses this layout (reads wrong offset).

#### Layout C — `*sdk/trace.recordingSpan` (SDK package, pointer in interface)

```
offset   0  size  16   embedded.Span (always zero)
offset  16  size   8   mu sync.Mutex (zero when unlocked)
offset  24  size  64   parent trace.SpanContext  ← PARENT's context, not current span
offset  88  size   8   spanKind
offset  96  size  16   name string
...
offset 192  size  64   spanContext trace.SpanContext  ← current span's OWN context ✓
  └─ offset 192  TraceID [16]byte
  └─ offset 208  SpanID  [8]byte
  └─ offset 216  TraceFlags byte
total size: 480 bytes
```

**When it appears:** `tracer.Start(ctx, "name")` with a sampled `TracerProvider` — this is
what `otelhttp`, `otelgrpc`, and all standard instrumentation libraries create. It is stored as a
`*recordingSpan` (pointer) in the context interface.  **This is the most important layout to add.**

**Heuristic:** bytes `[0:16]` == zero; bytes `[16:24]` == zero (unlocked mutex);
**valid `TraceID` at offset 192** (the span's own `spanContext`, not `parent` at offset 24).
Reading at offset 16 (current code) would yield garbage (mu + partial parent traceID) and either
fail `IsValid()` or silently return a wrong trace ID.

> **Key insight:** `parent` at offset 24 holds the *caller's* span context (used to link in the
> trace tree on export). `spanContext` at offset 192 holds the *current* span's ID, which is what
> goakt-ebpf needs as the parent for actor operation spans.

#### Layout D — `*auto/sdk.span` (Auto SDK: `go.opentelemetry.io/auto/sdk`)

```
offset  0  size  80   noop.Span (NOT 16 bytes — contains embedded.Span + sc SpanContext)
  └─ noop.Span.embedded.Span  offset  0  size 16 (zero)
  └─ noop.Span.sc             offset 16  size 64 (zero-initialized, not used for context propagation)
offset 80  size  64   spanContext trace.SpanContext
  └─ offset 80  TraceID [16]byte
  └─ offset 96  SpanID  [8]byte
  └─ offset 104 TraceFlags byte
total size: 176 bytes
```

**Critical finding:** In the current Auto SDK (`v1.2.1`), `span.spanContext` is **zero-initialized
at creation time and never populated in user-space**. The eBPF instrumentation layer is expected
to observe and fill in span data via kernel probes, not via the Go `context.Context` chain.
Verified via memory scanning: calling `tracer.Start(ctx, "name")` with `autosdk.TracerProvider()`
and a non-zero remote parent produces a span where `span.SpanContext()` returns an empty
`SpanContext{}`.

**Implication:** The user-space context reader **cannot** extract parent context from Auto SDK
spans using the current architecture. Supporting Auto SDK parent extraction requires a different
approach (see Section 1.1 below).

> **Note:** The previous recommendation stated `noop.Span = 16 bytes (interface)` and
> `spanContext at +16`. Both are incorrect. `noop.Span` is **80 bytes** and `spanContext` is at
> offset **80**.

---

### 1.1 Recommended Changes to `tryReadSpanContext`

**Replace the current single-layout reader with a multi-layout probe:**

1. Read **at least 256 bytes** from `addr` (enough to cover `recordingSpan.spanContext` at
   offset 192 + 64 = 256).
2. Check bytes `[0:16]` == zero (common guard across all layouts).
3. **Try Layout C first** (recordingSpan — most common for instrumented HTTP/gRPC):
   - bytes `[16:24]` == zero (unlocked mutex) AND valid `TraceID` at offset 192.
4. **Try Layout A** (trace.nonRecordingSpan — remote-propagated contexts):
   - bytes `[16:24]` are zero AND valid `TraceID` at offset 16.
5. **Try Layout B** (sdk.nonRecordingSpan — not-sampled spans):
   - bytes `[16:24]` are a non-zero pointer AND valid `TraceID` at offset 24.
6. Return the first valid `SpanContext`; log which layout matched (see Section 4).

Update `nrsReadSize` (currently 41) to at least **256 bytes** to cover all layouts.

---

## 2. Versioned Layout Resolution

**Recommendation:** Extend `offset_results.json` (in `internal/inject/`) with `SpanContext`
offsets *relative to the containing span struct* for each SDK version:

| Module                         | Package                              | Struct             | Field         | Offset (v1.41.0) |
|--------------------------------|--------------------------------------|--------------------|---------------|------------------|
| `go.opentelemetry.io/otel`     | `go.opentelemetry.io/otel/trace`     | `nonRecordingSpan` | `sc`          | 16               |
| `go.opentelemetry.io/otel/sdk` | `go.opentelemetry.io/otel/sdk/trace` | `nonRecordingSpan` | `sc`          | 24               |
| `go.opentelemetry.io/otel/sdk` | `go.opentelemetry.io/otel/sdk/trace` | `recordingSpan`    | `spanContext` | 192              |
| `go.opentelemetry.io/auto/sdk` | `go.opentelemetry.io/auto/sdk`       | `span`             | `spanContext` | 80               |

At startup, load these offsets via `structfield.Index` (already present in the codebase) and pass
them to `ExtractSpanContextFromContext`. This replaces hardcoded constants and allows the reader
to adapt as SDK versions evolve.

---

## 3. Auto SDK Parent Extraction — Alternative Approaches

Since `span.spanContext` is not populated in user-space for Auto SDK spans (Section 1, Layout D),
the context reader approach does not work. Two alternatives:

**Option A — eBPF probe on `tracer.Start`:**  
Attach an uprobe to the Auto SDK's `tracer.Start` function. When it fires, read the parent
`SpanContext` from the function arguments (the `context.Context` passed in) and correlate with
the resulting span. This is the same mechanism the OBI (OpenTelemetry eBPF Instrumentation) agent
uses.

**Option B — Userspace probe on `span.spanContext` population:**  
If a future Auto SDK version populates `span.spanContext` in user-space before actor calls are
reached, the reader could then use Layout D (offset 80) once that field is reliably non-zero.
Track the Auto SDK version in `offset_results.json` and enable Layout D dynamically.

---

## 4. Application-Side Requirements (Context Propagation)

For goakt-ebpf spans to have the correct parent (regardless of whether the parent is HTTP, gRPC,
manual, or remote), the **context containing the parent span must flow into the actor system**.
Applications may use **either** SDK:

**Option A — Standard OTEL SDK:**

1. Initialize `sdktrace.TracerProvider` with OTLP exporter.
2. Set it globally with `otel.SetTracerProvider(tp)`.
3. Instrument entry points (HTTP, gRPC, queues, etc.) so spans are created and stored in
   `context.Context`.
4. **Propagate that context** into actor calls: `goakt.Ask(ctx, pid, msg)`,
   `goakt.Tell(ctx, pid, msg)`, `actorSystem.Spawn(ctx, ...)`, etc.
5. Set the propagator for cross-boundary propagation (headers, message metadata).

**Option B — Auto SDK:**

1. Use `otel.SetTracerProvider(autosdk.TracerProvider())`.
2. Instrument entry points (or rely on zero-code instrumentation).
3. **Propagate context** into actor calls.
4. Set the propagator. Export is handled by the eBPF instrumentation agent.
5. Note: parent-child correlation via the user-space context reader is not currently possible for
   Auto SDK spans (see Section 3). Parent extraction requires eBPF-level probes.

**Universal requirement:** Any code path that creates a span and then invokes actors must pass the
span's context (e.g., `r.Context()` for HTTP, `stream.Context()` for gRPC, or the result of
`tracer.Start(ctx, "op")`) into the actor system. goakt-ebpf reads the context at the probe sites
(doReceive, process, remote handlers, etc.) and uses whatever span it finds as the parent.

---

## 5. Debugging and Observability

**Recommendation:** Add optional debug logging when `ExtractSpanContextFromContext` succeeds or
fails:

- Log when a valid parent span context is extracted: include `trace_id`, `span_id`, and **which
  layout matched** (Layout A / B / C) at debug level.
- Log when the context chain is walked but no valid span is found (including how many nodes were
  visited).
- Consider `GOAKT_EBPF_DEBUG_CONTEXT_READER=1` to enable verbose context-reader logs.

---

## 6. Documentation Updates

**Recommendation:** Update `docs/ARCHITECTURE.md` and `README.md` to:

- State that goakt-ebpf supports the standard OTEL SDK (`recordingSpan`, `nonRecordingSpan`) for
  parent span extraction.
- Document that Auto SDK parent extraction requires eBPF-level probes (not the userspace context
  reader) and is not yet supported via the context reader path.
- Document that **any** application span (HTTP, gRPC, manual, message queue, remote) can be a
  parent when its context is propagated into actor calls and the application uses the standard
  OTEL SDK.
- Add troubleshooting: "Actor spans not linked to parent" → verify (a) context propagation from
  the entry point into `goakt.Ask`/`goakt.Tell`/`Spawn`, (b) the app uses the standard OTEL SDK
  (not Auto SDK), and (c) the TracerProvider is sampled.

---

## 7. Testing

**Recommendation:** Add integration tests for **both** SDKs and **multiple parent sources**:

- **Standard SDK — sampled span test:** HTTP server + otelhttp → actor work → assert parent-child
  in traces. (Requires Layout C fix — this is broken today.)
- **Standard SDK — not-sampled span test:** HTTP server + NeverSample TracerProvider → actor
  work → assert no parent link (no crash).
- **Manual span test:** Application creates a manual span with `tracer.Start(ctx, "work")`,
  passes context to actor call → assert parent-child. (Requires Layout C fix.)
- **Remote propagation test:** W3C traceparent header propagated in → actor work → assert the
  remote span becomes the parent (Layout A — works today).
- **gRPC test (if applicable):** gRPC handler span → actor work → assert parent-child.
- **Auto SDK test:** Use `autosdk.TracerProvider()` → actor work → confirm no false-positive
  parent links from the context reader; document that eBPF-level probes are required for
  parent-child correlation.

This ensures layout changes in either SDK are caught and that parent-child correlation works
regardless of the parent's origin.

---

## Summary Table

| Area                | Finding / Recommendation                                                                                                                                           |
|---------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Root cause          | `otelhttp` puts `*recordingSpan` in context; current reader only handles `nonRecordingSpan` (API)                                                                  |
| Layout A (current)  | `trace.nonRecordingSpan` (API): traceID at offset 16 — **correctly handled today**                                                                                 |
| Layout B (missing)  | `sdk.nonRecordingSpan` (not sampled): traceID at offset **24** — not handled                                                                                       |
| Layout C (critical) | `*sdk.recordingSpan` (sampled HTTP/gRPC span): traceID at offset **192** — not handled                                                                             |
| Layout D (Auto SDK) | `*auto/sdk.span`: `spanContext` at offset **80** (not 16 as previously stated); however `spanContext` is **zero in user-space** — context reader cannot extract it |
| Fix                 | Probe all layouts in `tryReadSpanContext`; read ≥256 bytes; add entries to `offset_results.json`                                                                   |
| Auto SDK            | User-space context reader is insufficient; eBPF probes on `tracer.Start` are needed                                                                                |
| Parent sources      | Support any parent: HTTP, gRPC, manual, queues, remote propagation                                                                                                 |
| App requirements    | Standard SDK: propagate context into actor calls. Auto SDK: requires eBPF probes.                                                                                  |
| Debugging           | Log which layout matched; log failed walks                                                                                                                         |
| Docs                | Clarify per-layout support; Auto SDK limitations; troubleshooting guide                                                                                            |
| Testing             | Integration tests per layout (A/B/C) and per parent source (HTTP, manual, gRPC, remote)                                                                            |
