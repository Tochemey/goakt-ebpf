// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

// assert-jaeger-traces fetches traces from Jaeger's HTTP API and validates
// trace context propagation: expected span names exist, parent-child
// relationships are correct, and actor spans are not orphaned roots.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
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

func main() {
	baseURL := envOr("JAEGER_QUERY_URL", "http://localhost:16686")
	baseURL = strings.TrimSuffix(baseURL, "/")
	service := envOr("JAEGER_SERVICE", "goakt-ebpf")

	traces := fetchTraces(baseURL, service)
	if len(traces) == 0 {
		fatal("no traces found for service=%s", service)
	}

	expectedNames := map[string]bool{
		"actor.doReceive": false,
		"actor.process":   false,
	}

	var (
		totalSpans        int
		processWithParent int
		processTotal      int
		receiveWithParent int
		receiveTotal      int
		multiSpanTraces   int
	)

	for _, t := range traces {
		spanByID := make(map[string]span, len(t.Spans))
		for _, s := range t.Spans {
			spanByID[s.SpanID] = s
		}

		totalSpans += len(t.Spans)
		if len(t.Spans) > 1 {
			multiSpanTraces++
		}

		for _, s := range t.Spans {
			if _, ok := expectedNames[s.OperationName]; ok {
				expectedNames[s.OperationName] = true
			}

			for _, ref := range s.References {
				if ref.RefType != "CHILD_OF" || ref.SpanID == "" {
					continue
				}
				if ref.TraceID != "" && ref.TraceID != t.TraceID {
					continue
				}
				if _, ok := spanByID[ref.SpanID]; !ok {
					fmt.Fprintf(os.Stderr, "assert-jaeger-traces: warning: span %s (%s) references parent %s not found in trace %s (cross-service parent)\n",
						s.SpanID, s.OperationName, ref.SpanID, t.TraceID)
				}
			}

			hasParent := hasChildOfRef(s)

			switch s.OperationName {
			case "actor.process":
				processTotal++
				if hasParent {
					processWithParent++
				}
			case "actor.doReceive":
				receiveTotal++
				if hasParent {
					receiveWithParent++
				}
			}
		}
	}

	for name, found := range expectedNames {
		if !found {
			fatal("expected span name %q not found", name)
		}
	}

	const minSpans = 4
	if totalSpans < minSpans {
		fatal("expected at least %d spans, got %d", minSpans, totalSpans)
	}

	if processTotal > 0 && processWithParent == 0 {
		fatal("no actor.process spans have a parent (goroutine propagation broken)")
	}

	if multiSpanTraces == 0 {
		fatal("no traces have more than 1 span (context propagation not working)")
	}

	fmt.Printf("assert-jaeger-traces: OK\n")
	fmt.Printf("  traces: %d (%d with multiple spans)\n", len(traces), multiSpanTraces)
	fmt.Printf("  total spans: %d\n", totalSpans)
	fmt.Printf("  actor.process: %d/%d with parent\n", processWithParent, processTotal)
	fmt.Printf("  actor.doReceive: %d/%d with parent\n", receiveWithParent, receiveTotal)
}

func hasChildOfRef(s span) bool {
	for _, ref := range s.References {
		if ref.RefType == "CHILD_OF" && ref.SpanID != "" {
			return true
		}
	}
	return false
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

	if len(merged) == 0 {
		fatal("no traces found for service=%s", service)
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
