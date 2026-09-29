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
	"io"
	"net/http"
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
	StartTime     int64       `json:"startTime"` // microseconds since epoch
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

func main() {
	os.Exit(run(os.Getenv, os.Stdout, os.Stderr))
}

// run validates the traces and returns the process exit code.
//
// nolint:funlen
// nolint:gocognit
// nolint:gocyclo
func run(getenv func(string) string, stdout, stderr io.Writer) int {
	// set jeager query URL and service name via env vars for CI flexibility; defaults work for local testing with docker-compose
	baseURL := strings.TrimSuffix(envOr(getenv, "JAEGER_QUERY_URL", "http://localhost:16686"), "/")
	service := envOr(getenv, "JAEGER_SERVICE", "goakt-ebpf")

	traces, err := fetchTraces(baseURL, service, stderr)
	if err == nil && len(traces) == 0 {
		err = fmt.Errorf("no traces found for service=%s", service)
	}

	if err != nil {
		fmt.Fprintf(stderr, "assert-jaeger-traces: %v\n", err)
		return 1
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
		fmt.Fprintf(stderr, "FAIL: "+format+"\n", args...)
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
		fail("no actor.process spans have actor.doReceive as parent (enqueue/handling correlation broken)")
	} else if ratio := pct(stats.processWithDR, stats.processTotal); ratio < 30 {
		fail("only %d/%d (%d%%) actor.process spans have actor.doReceive as parent; want >= 30%%",
			stats.processWithDR, stats.processTotal, ratio)
	}

	// 5. actor.doReceive must have an app span as parent (app span context extraction).
	if stats.receiveTotal == 0 {
		fail("no actor.doReceive spans found")
	} else if stats.receiveWithApp == 0 {
		fail("no actor.doReceive spans have app span as parent (app span context extraction broken)")
	}

	// 6. Both HTTP and manual paths must produce linked doReceive spans.
	if stats.receiveWithHTTP == 0 {
		fail("no actor.doReceive spans have HTTP parent (GET /echo, GET /ask) — otelhttp context extraction broken")
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

	links := checkLinks(traces)

	// 13. The checks below must have requests to look at.
	if links.checkedRequests == 0 {
		fail("no app requests made after the agent attached were found to check")
	}

	// 14. No request may be missing agent spans.
	if links.incomplete > 0 {
		fail("%d of %d app requests are missing agent spans (spans lost)", links.incomplete, links.checkedRequests)
	}

	// 15. No trace may hold spans of another request.
	if links.overfull > 0 {
		fail("%d of %d app requests hold agent spans of other requests", links.overfull, links.checkedRequests)
	}

	if links.overfullEnqueues > 0 {
		fail("%d spans parent the handling spans of several messages", links.overfullEnqueues)
	}

	// 16. No agent span may point at a parent missing from its trace: that
	// parent was misread, and the span shows up detached.
	if links.danglingParents > 0 {
		fail("%d agent spans reference a parent that is not in their trace (misread parent)", links.danglingParents)
	}

	// 17. Every agent span in these examples belongs to an app request.
	if links.parentlessSpans > 0 {
		fail("%d agent spans have no parent (detached from their request)", links.parentlessSpans)
	}

	if !passed {
		fmt.Fprintln(stderr, "\n--- Trace dump for debugging ---")
		dumpTraces(stderr, traces)
		return 1
	}

	fmt.Fprintln(stdout, "assert-jaeger-traces: OK")
	fmt.Fprintf(stdout, "  traces: %d (%d with multiple spans)\n", len(traces), stats.multiSpanTraces)
	fmt.Fprintf(stdout, "  total spans: %d\n", stats.totalSpans)
	fmt.Fprintf(stdout, "  actor.process: %d/%d with doReceive parent\n", stats.processWithDR, stats.processTotal)
	fmt.Fprintf(stdout, "  actor.doReceive: %d/%d with app parent (%d HTTP, %d manual)\n",
		stats.receiveWithApp, stats.receiveTotal, stats.receiveWithHTTP, stats.receiveWithManual)
	fmt.Fprintf(stdout, "  complete chains (app→doReceive→process): %d (%d HTTP, %d manual)\n",
		stats.completeChains, stats.httpCompleteChains, stats.manualCompleteChains)
	fmt.Fprintf(stdout, "  grain.tell/grain.ask: %d/%d with app parent\n",
		stats.grainCallerWithApp, stats.grainCallerTotal)
	fmt.Fprintf(stdout, "  grain.doReceive: %d/%d with app parent\n",
		stats.grainReceiveWithApp, stats.grainReceiveTotal)
	fmt.Fprintf(stdout, "  grain.process: %d/%d with doReceive parent\n",
		stats.grainProcessWithDR, stats.grainProcessTotal)
	fmt.Fprintf(stdout, "  complete grain chains (app→grain.doReceive→grain.process): %d\n",
		stats.grainCompleteChains)
	fmt.Fprintf(stdout, "  app requests with exactly their agent spans: %d checked\n", links.checkedRequests)

	return 0
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
func dumpTraces(w io.Writer, traces []trace) {
	for i, t := range traces {
		fmt.Fprintf(w, "\nTrace %d [%s] (%d spans):\n", i+1, t.TraceID, len(t.Spans))

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
			fmt.Fprintf(w, "%s%s [%s]\n", prefix, s.OperationName, s.SpanID[:min(8, len(s.SpanID))])
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
func fetchTraces(baseURL, service string, stderr io.Writer) ([]trace, error) {
	var fetched [][]trace
	for _, svc := range []string{service, "integration-app", "grains-app"} {
		traces, err := fetchServiceTraces(baseURL, svc)
		if err != nil {
			return nil, err
		}

		if len(traces) >= traceLimit {
			fmt.Fprintf(stderr, "note: only the latest %d traces of service=%s are checked\n", traceLimit, svc)
		}

		fetched = append(fetched, traces)
	}

	return mergeTraces(fetched, time.Now().Add(-settleTime).UnixMicro()), nil
}

// traceLimit is the most traces fetched per service: enough for a whole CI
// run, so that the traces reach back to when the agent attached.
var traceLimit = 20000

// httpClient bounds every Jaeger query so a hung backend fails CI promptly
// instead of stalling indefinitely.
var httpClient = &http.Client{Timeout: 60 * time.Second}

// fetchServiceTraces returns the traces for a service. Infrastructure failures
// (unreachable Jaeger, non-200, undecodable body) are errors with a clear
// message so CI does not misdiagnose them as "context propagation broken"; an
// empty-but-successful response returns an empty slice.
func fetchServiceTraces(baseURL, service string) ([]trace, error) {
	rawURL := fmt.Sprintf("%s/api/traces?service=%s&limit=%d", baseURL, service, traceLimit)
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid Jaeger query URL %q: %w", rawURL, err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query Jaeger at %s (is it running?): %w", baseURL, err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got HTTP %d from Jaeger for service=%s", resp.StatusCode, service)
	}

	var tr traceResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decode Jaeger response for service=%s: %w", service, err)
	}

	return tr.Data, nil
}

func envOr(getenv func(string) string, key, fallback string) string {
	if v := getenv(key); v != "" {
		return v
	}

	return fallback
}
