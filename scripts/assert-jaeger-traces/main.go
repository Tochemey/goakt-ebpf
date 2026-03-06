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

// nolint:funlen
// nolint:gocognit
// nolint:gocyclo
func main() {
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

		spanByID := make(map[string]span, len(t.Spans))
		children := make(map[string][]string)
		roots := make([]string, 0)

		for _, s := range t.Spans {
			spanByID[s.SpanID] = s
			parentID := ""
			for _, ref := range s.References {
				if ref.RefType == "CHILD_OF" && ref.SpanID != "" {
					parentID = ref.SpanID
					break
				}
			}
			if parentID == "" || spanByID[parentID].SpanID == "" {
				roots = append(roots, s.SpanID)
			} else {
				children[parentID] = append(children[parentID], s.SpanID)
			}
		}

		// Re-check roots after all spans indexed (parent might appear after child).
		roots = roots[:0]
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

		// Rebuild children map.
		children = make(map[string][]string)
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

// fetchTraces retrieves traces from both services and merges them by trace ID
// so that cross-service parent references resolve correctly.
func fetchTraces(baseURL, service string) []trace {
	agentTraces := fetchServiceTraces(baseURL, service)
	appTraces := fetchServiceTraces(baseURL, "integration-app")

	merged := make(map[string]*trace)
	for i := range agentTraces {
		t := &agentTraces[i]
		merged[t.TraceID] = t
	}
	for _, t := range appTraces {
		if existing, ok := merged[t.TraceID]; ok {
			existing.Spans = append(existing.Spans, t.Spans...)
		} else {
			dup := t
			merged[t.TraceID] = &dup
		}
	}

	out := make([]trace, 0, len(merged))
	for _, t := range merged {
		out = append(out, *t)
	}
	return out
}

func fetchServiceTraces(baseURL, service string) []trace {
	rawURL := fmt.Sprintf("%s/api/traces?service=%s&limit=50", baseURL, service)
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return nil
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var tr traceResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil
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
