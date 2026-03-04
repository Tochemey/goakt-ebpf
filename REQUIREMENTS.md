goakt-ebpf runs in a separate process and attaches via eBPF uprobes. When it creates spans for goakt functions, it doesn’t know the current trace context, so it starts new traces and the spans appear disconnected.

Fix: Propagate trace context from the traced process
goakt-ebpf must read the trace context (trace_id, span_id) from the accounts process when the probe fires, and use it as the parent when creating spans.

1. Capture context at probe time
The goakt functions (Spawn, Ask, ActorOf, doReceive, handleRemoteAsk, etc.) receive context.Context as the first argument. When the uprobe fires at function entry, the eBPF program should capture:
Goroutine ID (goid)
The context.Context pointer (first argument)
These can be sent to userspace via a perf/ring buffer.

2. Read process memory from userspace
The goakt-ebpf userspace process must read the traced process’s memory at the captured context pointer, e.g. via:
process_vm_readv(2)
/proc/<pid>/mem
Or a shared eBPF map if the traced process cooperates (not zero‑instrumentation)

3. Parse the Go context.Context chain
context.Context in Go is a linked list. The OTEL span is stored with a specific key. The code needs to:
Follow the context chain (e.g. valueCtx nodes).
Find the node whose key matches the OTEL span context key.
Extract trace_id (16 bytes) and span_id (8 bytes) from the stored span.
This depends on the internal layout of the OTEL SDK and Go version, so it can be brittle.
4. Use the extracted context as parent
When exporting spans to OTLP, set the parent span context from the extracted trace_id and span_id instead of starting a new trace.