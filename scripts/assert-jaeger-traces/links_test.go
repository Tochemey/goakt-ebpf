// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	attached = int64(1_000_000_000)  // when the agent's first span started
	settled  = attached + 20_000_000 // after the attach margin
)

// newSpan returns a span started at start, under parent when it is not empty.
func newSpan(id, name string, start int64, parent string) span {
	s := span{SpanID: id, OperationName: name, StartTime: start}
	if parent != "" {
		s.References = []reference{{RefType: "CHILD_OF", SpanID: parent}}
	}

	return s
}

// attachTrace is a request traced while the agent was attaching: it sets the
// time of the agent's first span and is itself left unchecked.
func attachTrace() trace {
	return trace{TraceID: "attach", Spans: []span{
		newSpan("attach/root", "send-tell", attached, ""),
		newSpan("attach/enqueue", "actor.doReceive", attached, "attach/root"),
	}}
}

// actorRequest is the trace of the app request named name to an actor.
func actorRequest(name string, start int64) trace {
	return trace{TraceID: name, Spans: []span{
		newSpan(name+"/root", name, start, ""),
		newSpan(name+"/enqueue", "actor.doReceive", start, name+"/root"),
		newSpan(name+"/handle", "actor.process", start, name+"/enqueue"),
	}}
}

// grainRequest is the trace of the app request named name, which sends to
// grains with caller (grain.tell or grain.ask) the given number of times.
func grainRequest(name, caller string, sends int, start int64) trace {
	t := trace{TraceID: name, Spans: []span{newSpan(name+"/root", name, start, "")}}
	for i := range sends {
		id := name + "/" + string(rune('a'+i))
		t.Spans = append(t.Spans,
			newSpan(id+"/send", caller, start, name+"/root"),
			newSpan(id+"/enqueue", "grain.doReceive", start, name+"/root"),
			newSpan(id+"/handle", "grain.process", start, id+"/enqueue"),
		)
	}

	return t
}

func TestCheckLinks(t *testing.T) {
	t.Run("complete requests have no problems", func(t *testing.T) {
		report := checkLinks([]trace{
			attachTrace(),
			actorRequest("GET /echo", settled),
			grainRequest("GET /increment", "grain.tell", 2, settled),
			grainRequest("GET /count", "grain.ask", 1, settled),
		})

		require.Equal(t, linkReport{checkedRequests: 3}, report)
	})

	t.Run("requests made while the agent attached are not checked", func(t *testing.T) {
		untraced := trace{TraceID: "u", Spans: []span{newSpan("u0", "GET /echo", attached+1, "")}}

		report := checkLinks([]trace{attachTrace(), untraced})
		require.Equal(t, linkReport{}, report)
	})

	t.Run("a request missing agent spans is incomplete", func(t *testing.T) {
		lost := actorRequest("GET /echo", settled)
		lost.Spans = lost.Spans[:2]
		untraced := trace{TraceID: "u", Spans: []span{newSpan("u0", "send-ask", settled, "")}}

		report := checkLinks([]trace{attachTrace(), lost, untraced})
		require.Equal(t, linkReport{checkedRequests: 2, incomplete: 2}, report)
	})

	t.Run("every request is checked when the agent emitted nothing", func(t *testing.T) {
		untraced := trace{TraceID: "u", Spans: []span{newSpan("u0", "GET /echo", attached, "")}}

		report := checkLinks([]trace{untraced})
		require.Equal(t, linkReport{checkedRequests: 1, incomplete: 1}, report)
	})

	t.Run("a request holding spans of another request is overfull", func(t *testing.T) {
		mixed := actorRequest("GET /echo", settled)
		mixed.Spans = append(mixed.Spans,
			newSpan("other/enqueue", "actor.doReceive", settled, "GET /echo/root"),
			newSpan("other/handle", "actor.process", settled, "other/enqueue"),
		)

		report := checkLinks([]trace{attachTrace(), mixed})
		require.Equal(t, linkReport{checkedRequests: 1, overfull: 1}, report)
	})

	t.Run("a span parenting the handling of several messages is overfull", func(t *testing.T) {
		mixed := actorRequest("GET /echo", settled)
		mixed.Spans = append(mixed.Spans, newSpan("other/handle", "actor.process", settled, "GET /echo/enqueue"))

		report := checkLinks([]trace{attachTrace(), mixed})
		require.Equal(t, linkReport{checkedRequests: 1, overfull: 1, overfullEnqueues: 1}, report)
	})

	t.Run("an agent span whose parent is not in its trace is dangling", func(t *testing.T) {
		detached := trace{TraceID: "d", Spans: []span{
			newSpan("d1", "grain.tell", settled, "missing"),
		}}

		report := checkLinks([]trace{attachTrace(), detached})
		require.Equal(t, linkReport{danglingParents: 1}, report)
	})

	t.Run("an agent span without a parent is parentless once the agent attached", func(t *testing.T) {
		early := trace{TraceID: "e", Spans: []span{newSpan("e1", "grain.process", attached+1, "")}}
		late := trace{TraceID: "p", Spans: []span{newSpan("p1", "grain.process", settled, "")}}

		report := checkLinks([]trace{attachTrace(), early, late})
		require.Equal(t, linkReport{parentlessSpans: 1}, report)
	})
}

func TestMergeTraces(t *testing.T) {
	cutoff := settled
	whole := actorRequest("GET /echo", attached)
	appOnly := trace{TraceID: "a", Spans: []span{newSpan("a0", "send-tell", attached, "")}}
	unsettled := actorRequest("GET /ask", cutoff+1)

	merged := mergeTraces([][]trace{
		{whole, unsettled},
		{whole, appOnly},
	}, cutoff)

	require.ElementsMatch(t, []trace{whole, appOnly}, merged,
		"a trace returned for several services keeps one copy of each span, and unsettled traces are left out")
}
