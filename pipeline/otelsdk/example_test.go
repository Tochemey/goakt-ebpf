// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0
//
// Copied from go.opentelemetry.io/auto and adapted for GoAkt eBPF agent.

package otelsdk_test

import (
	"context"
	"log/slog"
	"os/signal"
	"sync"
	"syscall"

	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/tochemey/goakt-ebpf/internal/instrumentation"
	"github.com/tochemey/goakt-ebpf/internal/process"
	"github.com/tochemey/goakt-ebpf/pipeline/otelsdk"
)

func Example_multiplex() {
	// Create a context that cancels when a SIGTERM is received. This ensures
	// that each instrumentation goroutine below can shut down cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()

	// Create a new multiplexer to handle instrumentation events from multiple
	// sources. This will act as a central router for telemetry handlers.
	m, err := otelsdk.NewMultiplexer(ctx)
	if err != nil {
		panic(err)
	}

	// Simulated process IDs to be instrumented. These would typically be real
	// process IDs in a production scenario.
	pids := []int{1297, 1331, 9827}

	var wg sync.WaitGroup
	for _, pid := range pids {
		wg.Add(1)

		go func(id int) {
			defer wg.Done()

			// Create a handler for this process.
			handler := m.Handler(id)

			// Create a new instrumentation manager for the process.
			// NOTE: Error handling is omitted here for brevity. In production
			// code, always check and handle errors.
			// NOTE: No probes are registered yet - add GoAkt probes when implemented.
			cfg := instrumentation.NewNoopConfigProvider(nil)
			manager, _ := instrumentation.NewManager(
				slog.Default(),
				handler,
				process.ID(id),
				cfg,
			)

			// Load and start the instrumentation for the process.
			_ = manager.Load(ctx)
			_ = manager.Run(ctx)
		}(pid)
	}

	// Wait for all instrumentation goroutines to complete.
	wg.Wait()

	// Shut down the multiplexer, cleaning up any remaining resources.
	_ = m.Shutdown(ctx)
}

type detector struct{}

func (d *detector) Detect(ctx context.Context) (*resource.Resource, error) {
	// Implement your custom resource detection logic here.
	// This is a placeholder implementation.
	return resource.Empty(), nil
}

// This example show how to configure resource detectors that are used to generate
// the resource associated with the telemetry data.
func Example_resourceDetectors() {
	handler, err := otelsdk.NewHandler(
		context.Background(),
		// Explicitly included custom detectors using WithResourceDetector.
		otelsdk.WithResourceDetector(&detector{}),
		// WithEnv will automatically include resource detectors defined in the
		// OTEL_GO_AUTO_RESOURCE_DETECTORS environment variable if set.
		otelsdk.WithEnv(),
	)
	if err != nil {
		panic(err)
	}
	// Use the handler to create an instrumentation and have the detected
	// Resource associated with the generated telemetry.

	_ = handler
}
