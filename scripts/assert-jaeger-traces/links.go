// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import "time"

// settleTime is how recent a trace may be and still be checked. Newer traces
// may not have every service's spans exported yet.
const settleTime = 15 * time.Second

// attachMargin is how long after the agent's first span requests are still
// left unchecked. The agent attaches its probes one by one, so requests made
// meanwhile are only partly traced.
const attachMargin = 10 * time.Second

// agentSpanNames are the spans the eBPF agent emits in these examples.
var agentSpanNames = map[string]bool{
	"actor.doReceive": true, "actor.process": true,
	"grain.tell": true, "grain.ask": true,
	"grain.doReceive": true, "grain.process": true,
}

var handlingSpanNames = map[string]bool{
	"actor.process": true, "grain.process": true,
}

var (
	actorChain     = map[string]int{"actor.doReceive": 1, "actor.process": 1}
	grainAskChain  = map[string]int{"grain.ask": 1, "grain.doReceive": 1, "grain.process": 1}
	grainTellChain = map[string]int{"grain.tell": 2, "grain.doReceive": 2, "grain.process": 2}
)

// expectedAgentSpans is what the agent emits for one app request, by the
// request's span name. An increment also notifies the audit grain, so its
// chain appears twice.
var expectedAgentSpans = map[string]map[string]int{
	"GET /echo": actorChain, "GET /ask": actorChain,
	"send-tell": actorChain, "send-ask": actorChain,
	"GET /count": grainAskChain, "send-ask-grain": grainAskChain,
	"GET /increment": grainTellChain, "send-tell-grain": grainTellChain,
}

// linkReport counts the ways the agent linked its spans wrongly.
type linkReport struct {
	checkedRequests  int // app requests compared with their expected agent spans
	incomplete       int // checked requests missing agent spans
	overfull         int // checked requests holding agent spans of other requests
	danglingParents  int // agent spans whose parent is not in their trace
	parentlessSpans  int // agent spans with no parent at all
	overfullEnqueues int // spans parenting the handling spans of several messages
}

// checkLinks compares every trace with what the agent should have produced.
// Requests and parentless spans from before the agent finished attaching are
// not counted.
func checkLinks(traces []trace) linkReport {
	var report linkReport
	checkedFrom := firstAgentSpanStart(traces) + attachMargin.Microseconds()

	for _, t := range traces {
		spanByID := make(map[string]span, len(t.Spans))
		for _, s := range t.Spans {
			spanByID[s.SpanID] = s
		}

		agentSpans := make(map[string]int)
		handlingPerParent := make(map[string]int)
		for _, s := range t.Spans {
			if !agentSpanNames[s.OperationName] {
				continue
			}

			agentSpans[s.OperationName]++
			parent := parentSpan(s, spanByID)
			switch {
			case parent == nil && len(s.References) > 0:
				report.danglingParents++
			case parent == nil && s.StartTime >= checkedFrom:
				report.parentlessSpans++
			case parent != nil && handlingSpanNames[s.OperationName]:
				handlingPerParent[parent.SpanID]++
			}
		}

		for _, n := range handlingPerParent {
			if n > 1 {
				report.overfullEnqueues++
			}
		}

		for _, s := range t.Spans {
			expected, isRequest := expectedAgentSpans[s.OperationName]
			if !isRequest || s.StartTime < checkedFrom {
				continue
			}

			report.checkedRequests++
			switch {
			case hasFewer(agentSpans, expected):
				report.incomplete++
			case hasFewer(expected, agentSpans):
				report.overfull++
			}
		}
	}

	return report
}

// hasFewer reports whether got has fewer spans of any name than want.
func hasFewer(got, want map[string]int) bool {
	for name, n := range want {
		if got[name] < n {
			return true
		}
	}

	return false
}

// firstAgentSpanStart returns when the earliest agent span started, or 0
// when there is none.
func firstAgentSpanStart(traces []trace) int64 {
	var first int64
	for _, t := range traces {
		for _, s := range t.Spans {
			if agentSpanNames[s.OperationName] && (first == 0 || s.StartTime < first) {
				first = s.StartTime
			}
		}
	}

	return first
}

// mergeTraces merges the traces fetched for each service by trace ID. Jaeger
// returns whole traces for every service in them, so spans are deduplicated
// by ID. Traces with a span started after cutoff are left out as unsettled.
func mergeTraces(fetched [][]trace, cutoff int64) []trace {
	merged := make(map[string]*trace)
	seen := make(map[string]bool)
	for _, traces := range fetched {
		for _, t := range traces {
			existing, ok := merged[t.TraceID]
			if !ok {
				existing = &trace{TraceID: t.TraceID}
				merged[t.TraceID] = existing
			}

			for _, s := range t.Spans {
				if !seen[s.SpanID] {
					seen[s.SpanID] = true
					existing.Spans = append(existing.Spans, s)
				}
			}
		}
	}

	out := make([]trace, 0, len(merged))
	for _, t := range merged {
		if latestStart(t.Spans) <= cutoff {
			out = append(out, *t)
		}
	}

	return out
}

func latestStart(spans []span) int64 {
	var latest int64
	for _, s := range spans {
		latest = max(latest, s.StartTime)
	}

	return latest
}
