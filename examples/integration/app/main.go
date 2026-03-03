// Copyright (c) 2025 The GoAkt eBPF Authors.
// SPDX-License-Identifier: Apache-2.0

// Minimal GoAkt app for goakt-ebpf integration testing.
// Sends Tell and Ask messages between two actors.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tochemey/goakt/v4/actor"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

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

	// Tell (fire-and-forget)
	actor.Tell(ctx, echo, "hello")

	// Ask (request-response)
	res, err := actor.Ask(ctx, pong, "ping", 2*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Ask:", err)
	} else {
		_ = res // "pong"
	}

	// Run until stopped so goakt-ebpf can attach and capture spans
	<-ctx.Done()
}

type echoActor struct{}

func (a *echoActor) PreStart(ctx *actor.Context) error { return nil }
func (a *echoActor) PostStop(ctx *actor.Context) error { return nil }
func (a *echoActor) Receive(ctx *actor.ReceiveContext) {
	switch ctx.Message().(type) {
	case string:
		// no-op
	}
}

type pongActor struct{}

func (a *pongActor) PreStart(ctx *actor.Context) error { return nil }
func (a *pongActor) PostStop(ctx *actor.Context) error { return nil }
func (a *pongActor) Receive(ctx *actor.ReceiveContext) {
	switch msg := ctx.Message().(type) {
	case string:
		if msg == "ping" {
			ctx.Response("pong")
		}
	}
}
