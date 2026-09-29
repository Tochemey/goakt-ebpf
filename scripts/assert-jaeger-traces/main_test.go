// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// tracedRun is a run of both examples that the agent traced correctly, by
// request name.
func tracedRun() map[string]trace {
	run := map[string]trace{
		"attach":          attachTrace(),
		"GET /count":      grainRequest("GET /count", "grain.ask", 1, settled),
		"send-ask-grain":  grainRequest("send-ask-grain", "grain.ask", 1, settled),
		"GET /increment":  grainRequest("GET /increment", "grain.tell", 2, settled),
		"send-tell-grain": grainRequest("send-tell-grain", "grain.tell", 2, settled),
	}

	for _, name := range []string{"GET /echo", "GET /ask", "send-tell", "send-ask"} {
		run[name] = actorRequest(name, settled)
	}

	return run
}

// dropSpans removes the spans named name from every trace.
func dropSpans(run map[string]trace, name string) {
	for id, t := range run {
		kept := t.Spans[:0]
		for _, s := range t.Spans {
			if s.OperationName != name {
				kept = append(kept, s)
			}
		}

		t.Spans = kept
		run[id] = t
	}
}

// reparent puts the spans named name of the given requests under their
// request's span instead of their parent.
func reparent(run map[string]trace, name string, requests ...string) {
	for _, request := range requests {
		for i, s := range run[request].Spans {
			if s.OperationName == name {
				run[request].Spans[i].References[0].SpanID = request + "/root"
			}
		}
	}
}

// detach makes the spans named name point at a parent outside their trace.
func detach(run map[string]trace, name string) {
	for _, t := range run {
		for i, s := range t.Spans {
			if s.OperationName == name {
				t.Spans[i].References[0].SpanID = "missing"
			}
		}
	}
}

// newJaeger serves traces for every service, as Jaeger returns whole traces.
func newJaeger(t *testing.T, run map[string]trace) *httptest.Server {
	t.Helper()

	traces := make([]trace, 0, len(run))
	for _, tr := range run {
		traces = append(traces, tr)
	}

	jaeger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/traces", r.URL.Path)
		require.Equal(t, strconv.Itoa(traceLimit), r.URL.Query().Get("limit"))
		_ = json.NewEncoder(w).Encode(traceResponse{Data: traces})
	}))
	t.Cleanup(jaeger.Close)
	return jaeger
}

// validate runs the tool against url and returns its exit code and outputs.
func validate(url string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	getenv := func(key string) string {
		if key == "JAEGER_QUERY_URL" {
			return url
		}

		return ""
	}

	code := run(getenv, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRunPassesOnACorrectlyTracedRun(t *testing.T) {
	code, stdout, stderr := validate(newJaeger(t, tracedRun()).URL + "/")

	require.Zero(t, code, stderr)
	require.Empty(t, stderr)
	require.Contains(t, stdout, "assert-jaeger-traces: OK")
	require.Contains(t, stdout, "actor.process: 4/4 with doReceive parent")
	require.Contains(t, stdout, "grain.process: 6/6 with doReceive parent")
	require.Contains(t, stdout, "app requests with exactly their agent spans: 8 checked")
}

func TestRunFails(t *testing.T) {
	actorRequests := []string{"GET /echo", "GET /ask", "send-tell", "send-ask"}
	grainRequests := []string{"GET /count", "send-ask-grain", "GET /increment", "send-tell-grain"}

	cases := map[string]struct {
		mutate func(run map[string]trace)
		want   string
	}{
		"a required span name is missing": {
			mutate: func(run map[string]trace) { delete(run, "GET /echo") },
			want:   `required span name "GET /echo" not found`,
		},
		"there are too few spans": {
			mutate: func(run map[string]trace) {
				for name := range run {
					if name != "attach" {
						delete(run, name)
					}
				}
			},
			want: "expected at least 6 spans, got 2",
		},
		"no trace has several spans": {
			mutate: func(run map[string]trace) {
				for name, t := range run {
					t.Spans = t.Spans[:1]
					run[name] = t
				}
			},
			want: "no traces have more than 1 span",
		},
		"there are no actor.process spans": {
			mutate: func(run map[string]trace) { dropSpans(run, "actor.process") },
			want:   "no actor.process spans found",
		},
		"no actor.process span is under actor.doReceive": {
			mutate: func(run map[string]trace) { reparent(run, "actor.process", actorRequests...) },
			want:   "no actor.process spans have actor.doReceive as parent",
		},
		"few actor.process spans are under actor.doReceive": {
			mutate: func(run map[string]trace) { reparent(run, "actor.process", actorRequests[1:]...) },
			want:   "only 1/4 (25%) actor.process spans have actor.doReceive as parent",
		},
		"there are no actor.doReceive spans": {
			mutate: func(run map[string]trace) { dropSpans(run, "actor.doReceive") },
			want:   "no actor.doReceive spans found",
		},
		"no actor.doReceive span is under an app span": {
			mutate: func(run map[string]trace) { detach(run, "actor.doReceive") },
			want:   "no actor.doReceive spans have app span as parent",
		},
		"no actor.doReceive span is under an HTTP span": {
			mutate: func(run map[string]trace) {
				delete(run, "GET /echo")
				delete(run, "GET /ask")
			},
			want: "no actor.doReceive spans have HTTP parent",
		},
		"no actor.doReceive span is under a manual span": {
			mutate: func(run map[string]trace) {
				delete(run, "attach")
				delete(run, "send-tell")
				delete(run, "send-ask")
			},
			want: "no actor.doReceive spans have manual parent",
		},
		"there is no complete actor chain": {
			mutate: func(run map[string]trace) { detach(run, "actor.doReceive") },
			want:   "no complete trace chains",
		},
		"there is no complete HTTP chain": {
			mutate: func(run map[string]trace) { reparent(run, "actor.process", "GET /echo", "GET /ask") },
			want:   "no HTTP-triggered complete chains",
		},
		"there is no complete manual chain": {
			mutate: func(run map[string]trace) { reparent(run, "actor.process", "send-tell", "send-ask") },
			want:   "no manual-triggered complete chains",
		},
		"there are no grain caller spans": {
			mutate: func(run map[string]trace) {
				dropSpans(run, "grain.tell")
				dropSpans(run, "grain.ask")
			},
			want: "no grain.tell/grain.ask spans found",
		},
		"no grain caller span is under an app span": {
			mutate: func(run map[string]trace) {
				detach(run, "grain.tell")
				detach(run, "grain.ask")
			},
			want: "no grain.tell/grain.ask spans have an app span as parent",
		},
		"there are no grain.doReceive spans": {
			mutate: func(run map[string]trace) { dropSpans(run, "grain.doReceive") },
			want:   "no grain.doReceive spans found",
		},
		"no grain.doReceive span is under an app span": {
			mutate: func(run map[string]trace) { detach(run, "grain.doReceive") },
			want:   "no grain.doReceive spans have an app span as parent",
		},
		"there are no grain.process spans": {
			mutate: func(run map[string]trace) { dropSpans(run, "grain.process") },
			want:   "no grain.process spans found",
		},
		"no grain.process span is under grain.doReceive": {
			mutate: func(run map[string]trace) { reparent(run, "grain.process", grainRequests...) },
			want:   "no grain.process spans have grain.doReceive as parent",
		},
		"there is no complete grain chain": {
			mutate: func(run map[string]trace) { detach(run, "grain.doReceive") },
			want:   "no complete grain chains",
		},
		"no request was made after the agent attached": {
			mutate: func(run map[string]trace) {
				for _, t := range run {
					for i := range t.Spans {
						t.Spans[i].StartTime = attached
					}
				}
			},
			want: "no app requests made after the agent attached",
		},
		"a request is missing agent spans": {
			mutate: func(run map[string]trace) {
				t := run["GET /ask"]
				t.Spans = t.Spans[:2]
				run["GET /ask"] = t
			},
			want: "1 of 8 app requests are missing agent spans",
		},
		"a request holds agent spans of another request": {
			mutate: func(run map[string]trace) {
				t := run["GET /ask"]
				t.Spans = append(t.Spans,
					newSpan("other/enqueue", "actor.doReceive", settled, "GET /ask/root"),
					newSpan("other/handle", "actor.process", settled, "other/enqueue"),
				)
				run["GET /ask"] = t
			},
			want: "1 of 8 app requests hold agent spans of other requests",
		},
		"a span parents the handling of several messages": {
			mutate: func(run map[string]trace) {
				t := run["GET /ask"]
				t.Spans = append(t.Spans, newSpan("other/handle", "actor.process", settled, "GET /ask/enqueue"))
				run["GET /ask"] = t
			},
			want: "1 spans parent the handling spans of several messages",
		},
		"an agent span has a parent outside its trace": {
			mutate: func(run map[string]trace) {
				run["detached"] = trace{TraceID: "detached", Spans: []span{
					newSpan("detached/send", "grain.tell", settled, "missing"),
				}}
			},
			want: "1 agent spans reference a parent that is not in their trace",
		},
		"an agent span has no parent": {
			mutate: func(run map[string]trace) {
				run["detached"] = trace{TraceID: "detached", Spans: []span{
					newSpan("detached/handle", "grain.process", settled, ""),
				}}
			},
			want: "1 agent spans have no parent",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			traced := tracedRun()
			tc.mutate(traced)

			code, stdout, stderr := validate(newJaeger(t, traced).URL)
			require.Equal(t, 1, code)
			require.Empty(t, stdout)
			require.Contains(t, stderr, "FAIL: "+tc.want)
			require.Contains(t, stderr, "--- Trace dump for debugging ---")
		})
	}
}

func TestRunDumpsTracesAsTrees(t *testing.T) {
	traced := tracedRun()
	delete(traced, "GET /echo")

	_, _, stderr := validate(newJaeger(t, traced).URL)
	require.Contains(t, stderr, strings.Join([]string{
		"[GET /ask] (3 spans):",
		"  GET /ask [GET /ask]",
		"    actor.doReceive [GET /ask]",
		"      actor.process [GET /ask]",
	}, "\n"))
}

func TestRunFailsWhenJaegerCannotBeQueried(t *testing.T) {
	respond := func(status int, body string) string {
		jaeger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(jaeger.Close)
		return jaeger.URL
	}

	stopped := httptest.NewServer(http.NotFoundHandler())
	stopped.Close()

	for name, tc := range map[string]struct{ url, want string }{
		"the URL is invalid":         {"http://bad host", "invalid Jaeger query URL"},
		"Jaeger is not running":      {stopped.URL, "query Jaeger at " + stopped.URL},
		"Jaeger returns an error":    {respond(http.StatusInternalServerError, ""), "got HTTP 500 from Jaeger for service=goakt-ebpf"},
		"the response is not JSON":   {respond(http.StatusOK, "<html>"), "decode Jaeger response for service=goakt-ebpf"},
		"there are no traces at all": {respond(http.StatusOK, `{"data":[]}`), "no traces found for service=goakt-ebpf"},
	} {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := validate(tc.url)
			require.Equal(t, 1, code)
			require.Empty(t, stdout)
			require.Contains(t, stderr, "assert-jaeger-traces: "+tc.want)
		})
	}
}

func TestRunQueriesTheConfiguredService(t *testing.T) {
	var services []string
	jaeger := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		services = append(services, r.URL.Query().Get("service"))
		_ = json.NewEncoder(w).Encode(traceResponse{})
	}))
	t.Cleanup(jaeger.Close)

	var stdout, stderr bytes.Buffer
	env := map[string]string{"JAEGER_QUERY_URL": jaeger.URL, "JAEGER_SERVICE": "my-agent"}
	code := run(func(key string) string { return env[key] }, &stdout, &stderr)

	require.Equal(t, 1, code)
	require.Contains(t, stderr.String(), "no traces found for service=my-agent")
	require.Equal(t, []string{"my-agent", "integration-app", "grains-app"}, services)
}

func TestRunNotesWhenAServiceHasMoreTracesThanTheLimit(t *testing.T) {
	orig := traceLimit
	traceLimit = 9
	t.Cleanup(func() { traceLimit = orig })

	code, _, stderr := validate(newJaeger(t, tracedRun()).URL)
	require.Zero(t, code)
	require.Contains(t, stderr, "note: only the latest 9 traces of service=goakt-ebpf are checked")
}

func TestPct(t *testing.T) {
	require.Equal(t, 25, pct(1, 4))
	require.Zero(t, pct(1, 0))
}
