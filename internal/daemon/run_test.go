// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/alert"
	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/core/runtime"
	"github.com/tagwright/core/runtime/runtimetest"
)

// stubBackend is a no-op observe.Backend: it names itself for the health
// tracker and returns three already-closed channels. The fault this test
// injects lands in the initial reconcile (a runtime List failure), which run
// hits before it ever calls backend.Run, so the backend must not be what
// fails; it is here only so the Daemon can be constructed.
type stubBackend struct{}

func (stubBackend) Name() string { return "stub" }
func (stubBackend) Run(context.Context) (<-chan observe.Event, <-chan observe.Stat, <-chan error) {
	events := make(chan observe.Event)
	stats := make(chan observe.Stat)
	errs := make(chan error)
	close(events)
	close(stats)
	close(errs)
	return events, stats, errs
}

var _ observe.Backend = stubBackend{}

// TestRun_InjectedListFailureSurfaces is airlock's Level 2 wiring test for the
// Testing Standard (#549/#550): it drives airlock through its real production
// entry seam, run(Deps), with the canonical fake runtime, injects a failure on
// a runtime operation the daemon's startup path genuinely calls (List, which
// the initial reconcile runs first), and asserts that failure SURFACES as
// run's error return, never a silent success. Without the injected fault
// (Faults.List) this test would prove only the happy path, which the suite
// audit found is where the fake tier misses every real bug; the standard
// forbids a double with no error knob for exactly that reason.
//
// List is the fault that genuinely surfaces here: a runtime Watch error is by
// design logged and swallowed (the runtime watch is non-fatal), and a backend
// error is restarted with backoff, so neither returns from run. The initial
// reconcile's List is airlock's analog of ballast's initial-discovery pass,
// and a failure there is a hard startup error.
func TestRun_InjectedListFailureSurfaces(t *testing.T) {
	cfg := newTestConfig(t)

	rt := runtimetest.New()
	rt.Containers = []runtime.Container{{
		ID:    "c-abc123",
		Name:  "web",
		State: "running",
		Labels: map[string]string{
			"airlock.enable": "true",
			"airlock.allow":  "example.com",
		},
	}}
	// The injected failure: the fleet list fails on demand. This is the knob
	// the standard requires a wiring test to trip.
	injected := errors.New("injected list failure")
	rt.Faults.List = injected

	// A log-only alerter (beacon's built-in "log" backend), so no network I/O.
	alerter, err := alert.New(cfg, nil)
	if err != nil {
		t.Fatalf("alert.New: %v", err)
	}

	deps := Deps{
		Runtime:           rt,
		NetInsp:           rt, // runtimetest.Runtime is also a NetworkInspector
		Backend:           stubBackend{},
		Alerter:           alerter,
		Clock:             rt.Clock.Now, // fake clock, threaded through Deps
		Config:            cfg,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		HeartbeatInterval: time.Minute,
		Debounce:          10 * time.Millisecond,
		ResolvConfPath:    "/nonexistent-resolv-conf-for-airlock-tests",
		StatePath:         filepath.Join(t.TempDir(), "state.json"),
		StateInterval:     time.Hour,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = run(ctx, deps)
	if err == nil {
		t.Fatalf("injected list failure did not surface: run returned nil (a silent success)")
	}
	if !errors.Is(err, injected) {
		t.Fatalf("injected list failure did not surface intact: run error = %v, want it to wrap %v", err, injected)
	}
}
