// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

// assert-jaeger-traces fetches traces from Jaeger's HTTP API and validates
// that expected span names exist, minimum span count is met, and parent
// references are consistent. Used by CI integration tests.
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Jaeger trace API response (internal, undocumented format).
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
	SpanID  string `json:"spanID"`
}

func main() {
	baseURL := "http://localhost:16686"
	if u := os.Getenv("JAEGER_QUERY_URL"); u != "" {
		baseURL = strings.TrimSuffix(u, "/")
	}
	service := "goakt-ebpf"
	if s := os.Getenv("JAEGER_SERVICE"); s != "" {
		service = s
	}
	limit := 20
	url := fmt.Sprintf("%s/api/traces?service=%s&limit=%d", baseURL, service, limit)

	resp, err := http.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "assert-jaeger-traces: GET %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "assert-jaeger-traces: GET %s: status %d\n", url, resp.StatusCode)
		os.Exit(1)
	}

	var tr traceResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		fmt.Fprintf(os.Stderr, "assert-jaeger-traces: decode JSON: %v\n", err)
		os.Exit(1)
	}

	if len(tr.Data) == 0 {
		fmt.Fprintf(os.Stderr, "assert-jaeger-traces: no traces found for service=%s\n", service)
		os.Exit(1)
	}

	// Expected span names from integration app (Tell/Ask between echo and pong)
	expectedNames := map[string]bool{
		"actor.systemSpawn": true,
		"actor.doReceive":   true,
		"actor.process":     true,
	}

	foundNames := make(map[string]bool)
	totalSpans := 0

	for _, t := range tr.Data {
		spanByID := make(map[string]span)
		for _, s := range t.Spans {
			spanByID[s.SpanID] = s
			totalSpans++
			if expectedNames[s.OperationName] {
				foundNames[s.OperationName] = true
			}
		}

		// Validate parent propagation: spans with CHILD_OF reference have parent in same trace
		for _, s := range t.Spans {
			for _, ref := range s.References {
				if ref.RefType == "CHILD_OF" && ref.SpanID != "" {
					if _, ok := spanByID[ref.SpanID]; !ok {
						fmt.Fprintf(os.Stderr, "assert-jaeger-traces: span %s references unknown parent %s\n", s.SpanID, ref.SpanID)
						os.Exit(1)
					}
				}
			}
		}
	}

	for name := range expectedNames {
		if !foundNames[name] {
			fmt.Fprintf(os.Stderr, "assert-jaeger-traces: expected span name %q not found\n", name)
			os.Exit(1)
		}
	}

	const minSpans = 4
	if totalSpans < minSpans {
		fmt.Fprintf(os.Stderr, "assert-jaeger-traces: expected at least %d spans, got %d\n", minSpans, totalSpans)
		os.Exit(1)
	}

	fmt.Printf("assert-jaeger-traces: OK - %d traces, %d spans, expected names present, parent refs valid\n", len(tr.Data), totalSpans)
}
