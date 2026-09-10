// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"testing"
	"time"

	"github.com/tagwright/courier"
	"github.com/tagwright/courier/beacontest"

	"github.com/tagwright/airlock/internal/alert"
	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/core/runtime"
)

// TestDeviationAlert_FiresOperatorAlert is the additive notifier assertion for
// airlock's one alert-contracted surface: a live egress deviation reaches the
// operator ONLY through courier. airlock v1 is detect-and-alert, so a deviation
// has no error return and no run record; the beacon alert is the whole output.
// This drives a real violation through the daemon's observe-event wiring
// (handleObserveEvent -> recordAndAlertViolation -> alerter.Violation ->
// beacon) with the shared beacontest capturing beacon injected into the
// alerter, and asserts the Error-level alert actually fires.
//
// A bare-IP connection from an armed container is engine.ClassUnresolvedIP,
// which classLevel maps to LevelError. A swallowed alert here is a security
// tool going silent on a deviation, exactly the fail-to-alert class the
// Testing Standard closes; the runtimetest Level 2 test cannot reach this
// notifier-only surface.
func TestDeviationAlert_FiresOperatorAlert(t *testing.T) {
	capBeacon, capture := beacontest.New(courier.LevelInfo)

	cfg := newTestConfig(t)
	c := armedContainer("c1", "web", map[string]string{"airlock.allow": "example.com"})
	rt := &fakeRuntime{containers: []runtime.Container{c}}
	d := newTestDaemon(t, cfg, rt, alert.WithBeacon(capBeacon))
	ctx := context.Background()

	if err := d.reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// A connection to a bare IP with no DNS or SNI correlation, from a container
	// whose only allow rule is example.com, is an unresolved-ip violation, which
	// alerts at Error.
	d.handleObserveEvent(ctx, observe.Event{
		Kind:          observe.Connection,
		ContainerID:   "c1",
		ContainerName: "web",
		DstIP:         mustAddr(t, "198.51.100.7"),
		DstPort:       443,
		Proto:         "tcp",
		Timestamp:     time.Now(),
	})

	if capture.Count() == 0 {
		t.Fatal("egress deviation fired no operator alert: airlock went silent on a violation, and beacon is its only surface for a deviation")
	}
	if !capture.FiredAtLevel(courier.LevelError) {
		lvl, _ := capture.HighestLevel()
		t.Fatalf("deviation alert did not fire at Error level (unresolved-ip maps to LevelError); highest captured level was %v; captured: %+v", lvl, capture.Notifications())
	}
	if !capture.Contains(courier.LevelError, "violation") {
		t.Fatalf("the Error-level alert did not read as a violation alert; captured: %+v", capture.Notifications())
	}
}
