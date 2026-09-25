// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tagwright/courier"

	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/core/runtime"
)

// captureBackend records every notification routed to it, so a wiring test can
// assert an alert actually reached the operator alert channel. It is wired the
// same way internal/alert's own tests wire their capture: registered as an
// ordinary courier backend type and selected through a real config channel, so
// the daemon under test builds and delivers through exactly the *courier.Beacon
// it would in production, with no test-only construction path bolted onto
// alert.New.
type captureBackend struct {
	mu   sync.Mutex
	sent []courier.Notification
}

func (c *captureBackend) Name() string { return "capture" }

func (c *captureBackend) Send(_ context.Context, n courier.Notification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, n)
	return nil
}

func (c *captureBackend) notifications() []courier.Notification {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]courier.Notification(nil), c.sent...)
}

// The capture backend type is registered once for the whole test binary. Each
// test registers its own captureBackend under a unique id and selects it through
// a config channel carrying that id, so parallel tests never cross wires.
var (
	captureRegistryMu sync.Mutex
	captureRegistry   = map[string]*captureBackend{}
)

func init() {
	courier.RegisterBackend("capture", func(settings map[string]string, _ courier.SecretResolver) (courier.Backend, error) {
		id := settings["id"]
		captureRegistryMu.Lock()
		defer captureRegistryMu.Unlock()
		cb, ok := captureRegistry[id]
		if !ok {
			return nil, fmt.Errorf("capture: unknown id %q", id)
		}
		return cb, nil
	})
}

// registerCapture wires a fresh captureBackend into cfg as a real notification
// channel and returns it for assertions, cleaning up the registry when the test
// ends. The alerter the daemon builds from cfg then delivers through it exactly
// as it would through a real channel.
func registerCapture(t *testing.T, cfg *config.Config) *captureBackend {
	t.Helper()
	cb := &captureBackend{}
	id := t.Name()
	captureRegistryMu.Lock()
	captureRegistry[id] = cb
	captureRegistryMu.Unlock()
	t.Cleanup(func() {
		captureRegistryMu.Lock()
		delete(captureRegistry, id)
		captureRegistryMu.Unlock()
	})
	cfg.Notifications.Channels = append(cfg.Notifications.Channels, config.NotificationChannel{
		Type:     "capture",
		Settings: map[string]string{"id": id},
	})
	return cb
}

// TestDeviationAlert_FiresOperatorAlert is the additive notifier assertion for
// airlock's one alert-contracted surface: a live egress deviation reaches the
// operator ONLY through courier. airlock v1 is detect-and-alert, so a deviation
// has no error return and no run record; the beacon alert is the whole output.
// This drives a real violation through the daemon's observe-event wiring
// (handleObserveEvent -> recordAndAlertViolation -> alerter.Violation ->
// beacon) with a capturing channel wired into the daemon's real alerter through
// config, and asserts the Error-level alert actually fires.
//
// A bare-IP connection from an armed container is engine.ClassUnresolvedIP,
// which classLevel maps to LevelError. A swallowed alert here is a security
// tool going silent on a deviation, exactly the fail-to-alert class the
// Testing Standard closes; the runtimetest Level 2 test cannot reach this
// notifier-only surface.
func TestDeviationAlert_FiresOperatorAlert(t *testing.T) {
	cfg := newTestConfig(t)
	cb := registerCapture(t, cfg)

	c := armedContainer("c1", "web", map[string]string{"airlock.allow": "example.com"})
	rt := &fakeRuntime{containers: []runtime.Container{c}}
	d := newTestDaemon(t, cfg, rt)
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

	got := cb.notifications()
	if len(got) == 0 {
		t.Fatal("egress deviation fired no operator alert: airlock went silent on a violation, and beacon is its only surface for a deviation")
	}

	firedAtError := false
	errorReadsAsViolation := false
	var highest courier.Level
	for _, n := range got {
		if n.Level > highest {
			highest = n.Level
		}
		if n.Level == courier.LevelError {
			firedAtError = true
		}
		if n.Level >= courier.LevelError && (strings.Contains(n.Title, "violation") || strings.Contains(n.Body, "violation")) {
			errorReadsAsViolation = true
		}
	}

	if !firedAtError {
		t.Fatalf("deviation alert did not fire at Error level (unresolved-ip maps to LevelError); highest captured level was %v; captured: %+v", highest, got)
	}
	if !errorReadsAsViolation {
		t.Fatalf("the Error-level alert did not read as a violation alert; captured: %+v", got)
	}
}
