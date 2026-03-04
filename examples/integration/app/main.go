// Copyright (c) 2026 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

// Integration test app for goakt-ebpf trace context propagation.
// Creates application-level OTEL spans around Tell/Ask so the eBPF agent
// can link actor spans (doReceive, process) as children of these app spans.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tochemey/goakt/v4/actor"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
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

	tracer := otel.Tracer("integration-app")

	sys, err := actor.NewActorSystem("test-system")
	if err != nil {
		fmt.Fprintln(os.Stderr, "NewActorSystem:", err)
		os.Exit(1)
	}

	if err := sys.Start(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Start:", err)
		os.Exit(1)
	}
	defer func() { _ = sys.Stop(ctx) }()

	echo, err := sys.Spawn(ctx, "echo", &echoActor{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Spawn echo:", err)
		os.Exit(1)
	}

	pong, err := sys.Spawn(ctx, "pong", &pongActor{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "Spawn pong:", err)
		os.Exit(1)
	}

	sendMessages(ctx, tracer, echo, pong)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendMessages(ctx, tracer, echo, pong)
		}
	}
}

func sendMessages(ctx context.Context, tracer trace.Tracer, echo, pong *actor.PID) {
	ctx, tellSpan := tracer.Start(ctx, "send-tell")
	actor.Tell(ctx, echo, "hello")
	tellSpan.End()

	ctx, askSpan := tracer.Start(ctx, "send-ask")
	if _, err := actor.Ask(ctx, pong, "ping", 2*time.Second); err != nil {
		fmt.Fprintln(os.Stderr, "Ask:", err)
	}
	askSpan.End()
}

func initTracer(ctx context.Context) (func(context.Context) error, error) {
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("create OTLP exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName("integration-app")),
	)
	if err != nil {
		return nil, fmt.Errorf("create resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return tp.Shutdown, nil
}

type echoActor struct{}

func (a *echoActor) PreStart(*actor.Context) error { return nil }
func (a *echoActor) PostStop(*actor.Context) error { return nil }
func (a *echoActor) Receive(ctx *actor.ReceiveContext) {
	switch ctx.Message().(type) {
	case string:
	}
}

type pongActor struct{}

func (a *pongActor) PreStart(*actor.Context) error { return nil }
func (a *pongActor) PostStop(*actor.Context) error { return nil }
func (a *pongActor) Receive(ctx *actor.ReceiveContext) {
	switch msg := ctx.Message().(type) {
	case string:
		if msg == "ping" {
			ctx.Response("pong")
		}
	}
}
