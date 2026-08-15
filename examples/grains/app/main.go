// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

// Grain example app for goakt-ebpf: virtual actors (grains) with zero
// instrumentation in the grain code. The eBPF agent produces the caller-side
// spans (grain.tell, grain.ask), the enqueue span (grain.doReceive), and the
// handling span (grain.process); app-level OTEL spans become their parents
// via userspace context extraction.
//
// Two span sources validate context propagation:
//  1. Manual tracer.Start (send-tell-grain, send-ask-grain) — periodic ticker
//  2. otelhttp middleware (GET /increment, GET /count) — HTTP handlers
//
// The counter grain also notifies an audit grain via ctx.TellGrain on every
// increment, exercising the grain-to-grain send path (GrainContext.TellGrain
// delegates to actorSystem.TellGrain, which the agent probes).
//
// App spans are pretty-printed to stdout by default (OTEL stdout trace
// exporter) so traces are viewable without a backend; set
// OTEL_TRACES_STDOUT=0 to silence.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/tochemey/goakt/v4/actor"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdown, err := initTracer(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "init tracer:", err)
		os.Exit(1)
	}
	defer func() { _ = shutdown(context.Background()) }()

	tracer := otel.Tracer("grains-app")

	sys, err := actor.NewActorSystem("grains-system")
	if err != nil {
		fmt.Fprintln(os.Stderr, "NewActorSystem:", err)
		os.Exit(1)
	}

	if err := sys.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Start:", err)
		os.Exit(1)
	}
	defer func() { _ = sys.Stop(ctx) }()

	// counterID resolves the per-key counter grain, activating a zero-value
	// counterGrain on demand. The audit grain identity is resolved in the
	// counter's OnActivate hook.
	counterID := func(ctx context.Context, r *http.Request) (*actor.GrainIdentity, error) {
		key := r.URL.Query().Get("id")
		if key == "" {
			key = "default"
		}
		return actor.GrainOf[*counterGrain](ctx, sys, "counter-"+key)
	}

	// Start HTTP server with otelhttp — validates Layout C extraction from
	// recordingSpan created by HTTP middleware (same path as real services).
	port := envInt("HTTP_PORT", 8082)
	mux := http.NewServeMux()
	mux.Handle("/increment", otelhttp.NewHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := counterID(r.Context(), r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if err := sys.TellGrain(extractableContext(r), id, "increment"); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte("ok\n"))
		}), "GET /increment"))
	mux.Handle("/count", otelhttp.NewHandler(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := counterID(r.Context(), r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			count, err := sys.AskGrain(extractableContext(r), id, "get", 2*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			fmt.Fprintf(w, "%v\n", count)
		}), "GET /count"))
	srv := &http.Server{Addr: ":" + strconv.Itoa(port), Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, "HTTP server:", err)
		}
	}()
	defer func() { _ = srv.Shutdown(context.Background()) }()

	sendGrainMessages(ctx, tracer, sys)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendGrainMessages(ctx, tracer, sys)
		}
	}
}

// extractableContext re-binds the otelhttp span onto a valueCtx under
// WithoutCancel. That is the same layout tracer.Start produces, which the
// eBPF userspace reader can walk. The raw request context is a cancelCtx
// chain that the reader often misses, leaving GET /increment and GET /count
// as single-span traces.
func extractableContext(r *http.Request) context.Context {
	return trace.ContextWithSpan(context.WithoutCancel(r.Context()), trace.SpanFromContext(r.Context()))
}

func envInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultVal
}

func sendGrainMessages(ctx context.Context, tracer trace.Tracer, sys actor.ActorSystem) {
	// send-tell-grain and send-ask-grain are independent sibling spans under
	// ctx, not a chain: each derives its span context from the original ctx
	// so ending one does not orphan the other.
	tellCtx, tellSpan := tracer.Start(ctx, "send-tell-grain")
	id, err := actor.GrainOf[*counterGrain](tellCtx, sys, "counter-ticker")
	if err != nil {
		fmt.Fprintln(os.Stderr, "GrainOf:", err)
		tellSpan.End()
		return
	}
	if err := sys.TellGrain(tellCtx, id, "increment"); err != nil {
		fmt.Fprintln(os.Stderr, "TellGrain:", err)
	}
	tellSpan.End()

	askCtx, askSpan := tracer.Start(ctx, "send-ask-grain")
	if _, err := sys.AskGrain(askCtx, id, "get", 2*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "AskGrain:", err)
	}
	askSpan.End()
}

func initTracer(ctx context.Context) (func(context.Context) error, error) {
	otlpExporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName("grains-app")),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithBatcher(otlpExporter),
		sdktrace.WithResource(res),
	}

	// Pretty-print every app span to stdout so traces are viewable without a
	// backend (default on for this example). Set OTEL_TRACES_STDOUT=0 to silence.
	if os.Getenv("OTEL_TRACES_STDOUT") != "0" {
		stdoutExp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("create stdout exporter: %w", err)
		}
		opts = append(opts, sdktrace.WithBatcher(stdoutExp))
	}

	tp := sdktrace.NewTracerProvider(opts...)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp.Shutdown, nil
}

// counterGrain is a stateful virtual actor: one activation per identity
// (counter-<key>), holding that identity's count. GoAkt guarantees
// single-threaded message handling per grain, so no locking is needed.
type counterGrain struct {
	count int64
	audit *actor.GrainIdentity
}

func (g *counterGrain) OnActivate(ctx context.Context, props *actor.GrainProps) error {
	// Grains are constructed as zero values; initialization belongs here.
	// Resolve (and activate if needed) the audit grain this counter notifies.
	id, err := actor.GrainOf[*auditGrain](ctx, props.ActorSystem(), "audit")
	if err != nil {
		return err
	}
	g.audit = id
	return nil
}

func (g *counterGrain) OnDeactivate(context.Context, *actor.GrainProps) error { return nil }

func (g *counterGrain) OnReceive(ctx *actor.GrainContext) {
	switch ctx.Message() {
	case "increment":
		g.count++

		// Grain-to-grain send: delegates to actorSystem.TellGrain, so the
		// agent emits a nested grain.tell → grain.doReceive → grain.process.
		if err := ctx.TellGrain(g.audit, "count-changed"); err != nil {
			ctx.Err(err)
			return
		}
		ctx.NoErr()
	case "get":
		ctx.Response(g.count)
	default:
		ctx.Unhandled()
	}
}

// auditGrain counts change notifications sent by counter grains.
type auditGrain struct {
	events int64
}

func (g *auditGrain) OnActivate(context.Context, *actor.GrainProps) error   { return nil }
func (g *auditGrain) OnDeactivate(context.Context, *actor.GrainProps) error { return nil }

func (g *auditGrain) OnReceive(ctx *actor.GrainContext) {
	switch ctx.Message() {
	case "count-changed":
		g.events++
		ctx.NoErr()
	default:
		ctx.Unhandled()
	}
}
