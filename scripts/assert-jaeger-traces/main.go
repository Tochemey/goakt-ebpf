// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

// assert-jaeger-traces fetches traces from Jaeger's HTTP API and validates
// trace context propagation: expected span names exist, parent-child
// relationships form correct chains (app → doReceive → process), and both
// manual (tracer.Start) and HTTP (otelhttp) paths produce linked traces.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

type traceResponse struct {
	Data []trace `json:"data"`
}

type trace struct {
	TraceID string `json:"traceID"`
	Spans   []span `json:"spans"`
}

type span struct {
	TraceID       string      `json:"traceID"`
	SpanID        string      `json:"spanID"`
	OperationName string      `json:"operationName"`
	References    []reference `json:"references"`
}

type reference struct {
	RefType string `json:"refType"`
	TraceID string `json:"traceID"`
	SpanID  string `json:"spanID"`
}

var appSpanNames = map[string]bool{
	"send-tell": true, "send-ask": true,
	"GET /echo": true, "GET /ask": true,
}

var httpSpanNames = map[string]bool{
	"GET /echo": true, "GET /ask": true,
}

var manualSpanNames = map[string]bool{
	"send-tell": true, "send-ask": true,
}

// grainAppSpanNames are the grains-app spans expected to parent the eBPF
// grain spans (grain.tell, grain.ask, grain.doReceive).
var grainAppSpanNames = map[string]bool{
	"send-tell-grain": true, "send-ask-grain": true,
	"GET /increment": true, "GET /count": true,
}

// nolint:funlen
// nolint:gocognit
// nolint:gocyclo
func main() {
	// set jeager query URL and service name via env vars for CI flexibility; defaults work for local testing with docker-compose
	baseURL := strings.TrimSuffix(envOr("JAEGER_QUERY_URL", "http://localhost:16686"), "/")
	service := envOr("JAEGER_SERVICE", "goakt-ebpf")

	traces := fetchTraces(baseURL, service)
	if len(traces) == 0 {
		fatal("no traces found for service=%s", service)
	}

	requiredNames := []string{
		"actor.doReceive", "actor.process",
		"send-tell", "send-ask",
		"GET /echo", "GET /ask",
		"grain.tell", "grain.ask",
		"grain.doReceive", "grain.process",
		"send-tell-grain", "send-ask-grain",
		"GET /increment", "GET /count",
	}

	foundNames := make(map[string]bool)

	var stats struct {
		totalSpans           int
		multiSpanTraces      int
		processTotal         int
		processWithDR        int // actor.process with actor.doReceive as parent
		receiveTotal         int
		receiveWithApp       int // actor.doReceive with app span as parent
		receiveWithHTTP      int // actor.doReceive with HTTP span as parent
		receiveWithManual    int // actor.doReceive with manual span as parent
		completeChains       int // app → doReceive → process (3-level chain)
		httpCompleteChains   int // GET → doReceive → process
		manualCompleteChains int // send-* → doReceive → process
		grainCallerTotal     int // grain.tell / grain.ask spans
		grainCallerWithApp   int // grain.tell / grain.ask with app span as parent
		grainReceiveTotal    int
		grainReceiveWithApp  int // grain.doReceive with app span as parent
		grainProcessTotal    int
		grainProcessWithDR   int // grain.process with grain.doReceive as parent
		grainCompleteChains  int // app → grain.doReceive → grain.process
	}

	for _, t := range traces {
		spanByID := make(map[string]span, len(t.Spans))
		for _, s := range t.Spans {
			spanByID[s.SpanID] = s
			foundNames[s.OperationName] = true
		}

		stats.totalSpans += len(t.Spans)
		if len(t.Spans) > 1 {
			stats.multiSpanTraces++
		}

		for _, s := range t.Spans {
			switch s.OperationName {
			case "actor.process":
				stats.processTotal++
				parent := parentSpan(s, spanByID)
				if parent == nil || parent.OperationName != "actor.doReceive" {
					continue
				}
				stats.processWithDR++

				grandparent := parentSpan(*parent, spanByID)
				if grandparent == nil || !appSpanNames[grandparent.OperationName] {
					continue
				}
				stats.completeChains++
				if httpSpanNames[grandparent.OperationName] {
					stats.httpCompleteChains++
				}
				if manualSpanNames[grandparent.OperationName] {
					stats.manualCompleteChains++
				}

			case "actor.doReceive":
				stats.receiveTotal++
				parent := parentSpan(s, spanByID)
				if parent == nil || !appSpanNames[parent.OperationName] {
					continue
				}
				stats.receiveWithApp++
				if httpSpanNames[parent.OperationName] {
					stats.receiveWithHTTP++
				}
				if manualSpanNames[parent.OperationName] {
					stats.receiveWithManual++
				}

			case "grain.process":
				stats.grainProcessTotal++
				parent := parentSpan(s, spanByID)
				if parent == nil || parent.OperationName != "grain.doReceive" {
					continue
				}
				stats.grainProcessWithDR++

				grandparent := parentSpan(*parent, spanByID)
				if grandparent != nil && grainAppSpanNames[grandparent.OperationName] {
					stats.grainCompleteChains++
				}

			case "grain.doReceive":
				stats.grainReceiveTotal++
				if parent := parentSpan(s, spanByID); parent != nil && grainAppSpanNames[parent.OperationName] {
					stats.grainReceiveWithApp++
				}

			case "grain.tell", "grain.ask":
				stats.grainCallerTotal++
				if parent := parentSpan(s, spanByID); parent != nil && grainAppSpanNames[parent.OperationName] {
					stats.grainCallerWithApp++
				}
			}
		}
	}

	// --- Assertions (fail with trace dump for debugging) ---

	passed := true
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
		passed = false
	}

	// 1. All required span names must be present.
	for _, name := range requiredNames {
		if !foundNames[name] {
			fail("required span name %q not found in any trace", name)
		}
	}

	// 2. Minimum span count (at least 2 complete chains worth).
	const minSpans = 6
	if stats.totalSpans < minSpans {
		fail("expected at least %d spans, got %d", minSpans, stats.totalSpans)
	}

	// 3. Multi-span traces must exist.
	if stats.multiSpanTraces == 0 {
		fail("no traces have more than 1 span (context propagation not working)")
	}

	// 4. actor.process must have actor.doReceive as parent (not just any parent).
	if stats.processTotal == 0 {
		fail("no actor.process spans found")
	} else if stats.processWithDR == 0 {
		fail("no actor.process spans have actor.doReceive as parent (buffering/goid propagation broken)")
	} else if ratio := pct(stats.processWithDR, stats.processTotal); ratio < 30 {
		fail("only %d/%d (%d%%) actor.process spans have actor.doReceive as parent; want >= 30%%",
			stats.processWithDR, stats.processTotal, ratio)
	}

	// 5. actor.doReceive must have an app span as parent (userspace context extraction).
	if stats.receiveTotal == 0 {
		fail("no actor.doReceive spans found")
	} else if stats.receiveWithApp == 0 {
		fail("no actor.doReceive spans have app span as parent (userspace context extraction broken)")
	}

	// 6. Both HTTP and manual paths must produce linked doReceive spans.
	if stats.receiveWithHTTP == 0 {
		fail("no actor.doReceive spans have HTTP parent (GET /echo, GET /ask) — otelhttp + Layout C broken")
	}
	if stats.receiveWithManual == 0 {
		fail("no actor.doReceive spans have manual parent (send-tell, send-ask) — manual context propagation broken")
	}

	// 7. Complete 3-level chains must exist (app → doReceive → process).
	if stats.completeChains == 0 {
		fail("no complete trace chains (app → actor.doReceive → actor.process) found")
	}

	// 8. At least one HTTP-triggered complete chain.
	if stats.httpCompleteChains == 0 {
		fail("no HTTP-triggered complete chains (GET → doReceive → process)")
	}

	// 9. At least one manual-triggered complete chain.
	if stats.manualCompleteChains == 0 {
		fail("no manual-triggered complete chains (send-* → doReceive → process)")
	}

	// 10. Grain caller-side spans (grain.tell/grain.ask) must be linked under
	// app spans (verifies the actorSystem.TellGrain/AskGrain probes).
	if stats.grainCallerTotal == 0 {
		fail("no grain.tell/grain.ask spans found (grain send probes not firing)")
	} else if stats.grainCallerWithApp == 0 {
		fail("no grain.tell/grain.ask spans have an app span as parent (grain caller context extraction broken)")
	}

	// 11. grain.doReceive must be linked under app spans.
	if stats.grainReceiveTotal == 0 {
		fail("no grain.doReceive spans found")
	} else if stats.grainReceiveWithApp == 0 {
		fail("no grain.doReceive spans have an app span as parent (grain context extraction broken)")
	}

	// 12. grain.process must chain under grain.doReceive, with complete chains present.
	if stats.grainProcessTotal == 0 {
		fail("no grain.process spans found")
	} else if stats.grainProcessWithDR == 0 {
		fail("no grain.process spans have grain.doReceive as parent (grain enqueue/handling correlation broken)")
	}
	if stats.grainCompleteChains == 0 {
		fail("no complete grain chains (app → grain.doReceive → grain.process) found")
	}

	if !passed {
		fmt.Fprintln(os.Stderr, "\n--- Trace dump for debugging ---")
		dumpTraces(traces)
		os.Exit(1)
	}

	fmt.Println("assert-jaeger-traces: OK")
	fmt.Printf("  traces: %d (%d with multiple spans)\n", len(traces), stats.multiSpanTraces)
	fmt.Printf("  total spans: %d\n", stats.totalSpans)
	fmt.Printf("  actor.process: %d/%d with doReceive parent\n", stats.processWithDR, stats.processTotal)
	fmt.Printf("  actor.doReceive: %d/%d with app parent (%d HTTP, %d manual)\n",
		stats.receiveWithApp, stats.receiveTotal, stats.receiveWithHTTP, stats.receiveWithManual)
	fmt.Printf("  complete chains (app→doReceive→process): %d (%d HTTP, %d manual)\n",
		stats.completeChains, stats.httpCompleteChains, stats.manualCompleteChains)
	fmt.Printf("  grain.tell/grain.ask: %d/%d with app parent\n",
		stats.grainCallerWithApp, stats.grainCallerTotal)
	fmt.Printf("  grain.doReceive: %d/%d with app parent\n",
		stats.grainReceiveWithApp, stats.grainReceiveTotal)
	fmt.Printf("  grain.process: %d/%d with doReceive parent\n",
		stats.grainProcessWithDR, stats.grainProcessTotal)
	fmt.Printf("  complete grain chains (app→grain.doReceive→grain.process): %d\n",
		stats.grainCompleteChains)
}

// parentSpan resolves the CHILD_OF parent within the same trace's span map.
func parentSpan(s span, byID map[string]span) *span {
	for _, ref := range s.References {
		if ref.RefType == "CHILD_OF" && ref.SpanID != "" {
			if p, ok := byID[ref.SpanID]; ok {
				return &p
			}
		}
	}
	return nil
}

func pct(n, total int) int {
	if total == 0 {
		return 0
	}
	return n * 100 / total
}

// dumpTraces prints a compact tree view of each trace for CI debugging.
func dumpTraces(traces []trace) {
	for i, t := range traces {
		fmt.Fprintf(os.Stderr, "\nTrace %d [%s] (%d spans):\n", i+1, t.TraceID, len(t.Spans))

		// Index all spans first so parent lookups work regardless of the
		// order spans appear in the response.
		spanByID := make(map[string]span, len(t.Spans))
		for _, s := range t.Spans {
			spanByID[s.SpanID] = s
		}

		roots := make([]string, 0)
		for _, s := range t.Spans {
			isRoot := true
			for _, ref := range s.References {
				if ref.RefType == "CHILD_OF" && ref.SpanID != "" {
					if _, ok := spanByID[ref.SpanID]; ok {
						isRoot = false
						break
					}
				}
			}
			if isRoot {
				roots = append(roots, s.SpanID)
			}
		}

		children := make(map[string][]string)
		for _, s := range t.Spans {
			for _, ref := range s.References {
				if ref.RefType == "CHILD_OF" && ref.SpanID != "" {
					if _, ok := spanByID[ref.SpanID]; ok {
						children[ref.SpanID] = append(children[ref.SpanID], s.SpanID)
						break
					}
				}
			}
		}

		sort.Strings(roots)
		var printTree func(id string, indent int)
		printTree = func(id string, indent int) {
			s := spanByID[id]
			prefix := strings.Repeat("  ", indent)
			fmt.Fprintf(os.Stderr, "%s%s [%s]\n", prefix, s.OperationName, s.SpanID[:min(8, len(s.SpanID))])
			kids := children[id]
			sort.Strings(kids)
			for _, kid := range kids {
				printTree(kid, indent+1)
			}
		}
		for _, root := range roots {
			printTree(root, 1)
		}
	}
}

// fetchTraces retrieves traces from the agent and app services and merges
// them by trace ID so that cross-service parent references resolve correctly.
func fetchTraces(baseURL, service string) []trace {
	agentTraces := fetchServiceTraces(baseURL, service)

	merged := make(map[string]*trace)
	for i := range agentTraces {
		t := &agentTraces[i]
		merged[t.TraceID] = t
	}

	for _, appService := range []string{"integration-app", "grains-app"} {
		for _, t := range fetchServiceTraces(baseURL, appService) {
			if existing, ok := merged[t.TraceID]; ok {
				existing.Spans = append(existing.Spans, t.Spans...)
			} else {
				dup := t
				merged[t.TraceID] = &dup
			}
		}
	}

	out := make([]trace, 0, len(merged))
	for _, t := range merged {
		out = append(out, *t)
	}
	return out
}

// httpClient bounds every Jaeger query so a hung backend fails CI promptly
// instead of stalling indefinitely.
var httpClient = &http.Client{Timeout: 15 * time.Second}

// fetchServiceTraces returns the traces for a service. Infrastructure failures
// (unreachable Jaeger, non-200, undecodable body) are fatal with a clear
// message so CI does not misdiagnose them as "context propagation broken"; an
// empty-but-successful response returns an empty slice.
func fetchServiceTraces(baseURL, service string) []trace {
	rawURL := fmt.Sprintf("%s/api/traces?service=%s&limit=50", baseURL, service)
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		fatal("invalid Jaeger query URL %q: %v", rawURL, err)
	}
	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		fatal("build Jaeger request: %v", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		fatal("query Jaeger at %s (is it running?): %v", baseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fatal("Jaeger returned HTTP %d for service=%s", resp.StatusCode, service)
	}
	var tr traceResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		fatal("decode Jaeger response for service=%s: %v", service, err)
	}
	return tr.Data
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "assert-jaeger-traces: "+format+"\n", args...)
	os.Exit(1)
}
