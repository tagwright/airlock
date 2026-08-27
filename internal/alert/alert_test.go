// SPDX-License-Identifier: GPL-3.0-or-later

package alert

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tagwright/beacon"

	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/discovery"
	"github.com/tagwright/airlock/internal/engine"
	"github.com/tagwright/airlock/internal/policy"
)

// captureBackend records every notification sent to it, for test
// assertions, instead of contacting any real channel.
type captureBackend struct {
	mu   sync.Mutex
	sent []beacon.Notification
}

func (c *captureBackend) Name() string { return "capture" }

func (c *captureBackend) Send(_ context.Context, n beacon.Notification) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, n)
	return nil
}

func (c *captureBackend) notifications() []beacon.Notification {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]beacon.Notification, len(c.sent))
	copy(out, c.sent)
	return out
}

// The capture backend type is registered once for the whole test binary.
// Individual tests are isolated from each other by a unique "id" setting
// looked up in captureRegistry, not by registering a new backend type per
// test (beacon.RegisterBackend panics on a duplicate type name).
var (
	captureRegistryMu sync.Mutex
	captureRegistry   = map[string]*captureBackend{}
)

func init() {
	beacon.RegisterBackend("capture", func(settings map[string]string, _ beacon.SecretResolver) (beacon.Backend, error) {
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

// testClock is a settable clock handed to New via WithClock, so window and
// flood-breaker logic (built around hour-and-minute scale durations) is
// testable without a real sleep.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newTestAlerter builds an Alerter wired to a fresh, isolated
// captureBackend and a controllable clock starting at t0.
func newTestAlerter(t *testing.T, window time.Duration, floodCap int, t0 time.Time) (*Alerter, *captureBackend, *testClock) {
	t.Helper()

	id := t.Name()
	cb := &captureBackend{}
	captureRegistryMu.Lock()
	captureRegistry[id] = cb
	captureRegistryMu.Unlock()
	t.Cleanup(func() {
		captureRegistryMu.Lock()
		delete(captureRegistry, id)
		captureRegistryMu.Unlock()
	})

	cfg := &config.Config{
		Notifications: config.Notifications{
			Channels: []config.NotificationChannel{
				{Type: "capture", Settings: map[string]string{"id": id}},
			},
		},
		Defaults: config.Defaults{
			AlertWindow: window.String(),
			AlertFlood:  floodCap,
		},
	}

	clock := &testClock{t: t0}
	a, err := New(cfg, nil, WithClock(clock.Now))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, cb, clock
}

func testViolation(service, dest string, port uint16, class engine.Class, mode policy.Mode, containerID, containerName string) engine.Violation {
	return engine.Violation{
		Service:       service,
		Destination:   dest,
		Port:          port,
		Class:         class,
		ContainerID:   containerID,
		ContainerName: containerName,
		Timestamp:     time.Now(),
		Mode:          mode,
	}
}

var t0 = time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)

// The "log" floor channel New always wires ahead of any configured channel
// means every test's captureBackend receives every notification the log
// backend also would, but never the reverse: only cb's own notifications
// are asserted on below.

func TestFirstHitImmediate(t *testing.T) {
	a, cb, _ := newTestAlerter(t, time.Hour, 30, t0)
	ctx := context.Background()

	v := testViolation("renovate", "unlisted.example.com", 443, engine.ClassNoMatch, policy.Alert, "abcdef012345", "renovate-1")
	if err := a.Violation(ctx, v); err != nil {
		t.Fatalf("Violation: %v", err)
	}

	got := cb.notifications()
	if len(got) != 1 {
		t.Fatalf("len(notifications) = %d, want 1 (first hit must alert immediately)", len(got))
	}
	n := got[0]
	if n.Level != beacon.LevelWarning {
		t.Errorf("Level = %v, want LevelWarning for no-match", n.Level)
	}
	if !strings.Contains(n.Body, "renovate") || !strings.Contains(n.Body, "unlisted.example.com") {
		t.Errorf("Body = %q, want it to mention service and destination", n.Body)
	}
	if n.Fields["since_last_alert"] != "" {
		t.Errorf("Fields[since_last_alert] = %q, want empty on a first hit", n.Fields["since_last_alert"])
	}
}

func TestRepeatSuppressedAndCounted(t *testing.T) {
	a, cb, clock := newTestAlerter(t, time.Hour, 30, t0)
	ctx := context.Background()

	v := testViolation("renovate", "unlisted.example.com", 443, engine.ClassNoMatch, policy.Alert, "abcdef012345", "renovate-1")
	if err := a.Violation(ctx, v); err != nil {
		t.Fatalf("Violation (first): %v", err)
	}
	clock.Advance(time.Minute)
	if err := a.Violation(ctx, v); err != nil {
		t.Fatalf("Violation (repeat): %v", err)
	}
	clock.Advance(time.Minute)
	if err := a.Violation(ctx, v); err != nil {
		t.Fatalf("Violation (repeat 2): %v", err)
	}

	if got := len(cb.notifications()); got != 1 {
		t.Fatalf("len(notifications) after 2 repeats within the window = %d, want 1 (repeats suppressed)", got)
	}

	if err := a.Digest(ctx); err != nil {
		t.Fatalf("Digest: %v", err)
	}
	got := cb.notifications()
	if len(got) != 2 {
		t.Fatalf("len(notifications) after Digest = %d, want 2 (immediate + digest)", len(got))
	}
	digest := got[1]
	if !strings.Contains(digest.Body, "2 suppressed") {
		t.Errorf("digest Body = %q, want it to report 2 suppressed", digest.Body)
	}
}

func TestWindowRollReAlertsWithCount(t *testing.T) {
	a, cb, clock := newTestAlerter(t, time.Hour, 30, t0)
	ctx := context.Background()

	v := testViolation("renovate", "unlisted.example.com", 443, engine.ClassNoMatch, policy.Alert, "abcdef012345", "renovate-1")
	if err := a.Violation(ctx, v); err != nil {
		t.Fatalf("Violation (first): %v", err)
	}
	clock.Advance(10 * time.Minute)
	if err := a.Violation(ctx, v); err != nil { // suppressed
		t.Fatalf("Violation (suppressed): %v", err)
	}
	clock.Advance(time.Hour) // rolls the window
	if err := a.Violation(ctx, v); err != nil {
		t.Fatalf("Violation (window rolled): %v", err)
	}

	got := cb.notifications()
	if len(got) != 2 {
		t.Fatalf("len(notifications) = %d, want 2 (first hit + window-rolled re-alert)", len(got))
	}
	reAlert := got[1]
	if reAlert.Fields["since_last_alert"] != "1" {
		t.Errorf("Fields[since_last_alert] = %q, want %q", reAlert.Fields["since_last_alert"], "1")
	}
	if !strings.Contains(reAlert.Body, "1 suppressed since the last alert") {
		t.Errorf("Body = %q, want it to mention the suppressed count", reAlert.Body)
	}
}

func TestAuditModeNeverImmediateButDigest(t *testing.T) {
	a, cb, _ := newTestAlerter(t, time.Hour, 30, t0)
	ctx := context.Background()

	v := testViolation("legacy", "mystery.example.com", 443, engine.ClassDeny, policy.Audit, "111111111111", "legacy-1")
	for i := 0; i < 3; i++ {
		if err := a.Violation(ctx, v); err != nil {
			t.Fatalf("Violation: %v", err)
		}
	}
	if got := len(cb.notifications()); got != 0 {
		t.Fatalf("len(notifications) = %d, want 0 (audit mode never alerts immediately)", got)
	}

	if err := a.Digest(ctx); err != nil {
		t.Fatalf("Digest: %v", err)
	}
	got := cb.notifications()
	if len(got) != 1 {
		t.Fatalf("len(notifications) after Digest = %d, want 1", len(got))
	}
	if !strings.Contains(got[0].Body, "Audit-mode tallies") || !strings.Contains(got[0].Body, "legacy") {
		t.Errorf("digest Body = %q, want an audit-mode tally mentioning legacy", got[0].Body)
	}
}

func TestClassLevelMapping(t *testing.T) {
	cases := []struct {
		class engine.Class
		want  beacon.Level
	}{
		{engine.ClassDeny, beacon.LevelError},
		{engine.ClassUnresolvedIP, beacon.LevelError},
		{engine.ClassNoMatch, beacon.LevelWarning},
	}
	for _, c := range cases {
		if got := classLevel(c.class); got != c.want {
			t.Errorf("classLevel(%v) = %v, want %v", c.class, got, c.want)
		}
	}
}

func TestFloodBreakerCollapsesAtCap(t *testing.T) {
	a, cb, clock := newTestAlerter(t, time.Hour, 3, t0)
	ctx := context.Background()

	send := func(dest string) {
		t.Helper()
		v := testViolation("scanner", dest, 443, engine.ClassNoMatch, policy.Alert, "deadbeef0001", "scanner-1")
		if err := a.Violation(ctx, v); err != nil {
			t.Fatalf("Violation(%s): %v", dest, err)
		}
		clock.Advance(time.Second)
	}

	// Cap is 3: the first 3 distinct identities alert normally.
	send("host1.example.com")
	send("host2.example.com")
	send("host3.example.com")
	if got := len(cb.notifications()); got != 3 {
		t.Fatalf("len(notifications) after 3 distinct identities = %d, want 3", got)
	}

	// The 4th distinct identity crosses the cap: collapse to one flood alert.
	send("host4.example.com")
	got := cb.notifications()
	if len(got) != 4 {
		t.Fatalf("len(notifications) after crossing the flood cap = %d, want 4 (3 normal + 1 flood)", len(got))
	}
	flood := got[3]
	if flood.Level != beacon.LevelError {
		t.Errorf("flood notification Level = %v, want LevelError", flood.Level)
	}
	if !strings.Contains(flood.Title, "flooding") {
		t.Errorf("flood notification Title = %q, want it to mention flooding", flood.Title)
	}

	// A 5th distinct identity while still flooding is absorbed silently:
	// no new notification.
	send("host5.example.com")
	if got := len(cb.notifications()); got != 4 {
		t.Fatalf("len(notifications) after a 5th distinct identity mid-flood = %d, want 4 (still absorbed)", got)
	}

	// The digest reports the episode.
	if err := a.Digest(ctx); err != nil {
		t.Fatalf("Digest: %v", err)
	}
	digest := cb.notifications()[4]
	if !strings.Contains(digest.Body, "Flood episodes") || !strings.Contains(digest.Body, "5 distinct violations") {
		t.Errorf("digest Body = %q, want a flood episode reporting 5 distinct violations", digest.Body)
	}
}

func TestStickyDiagnosticSurfacesOnceThenRecursThenAgesOut(t *testing.T) {
	a, cb, _ := newTestAlerter(t, time.Hour, 30, t0)
	ctx := context.Background()

	d := discovery.Diagnostic{
		Level:   discovery.Error,
		Sticky:  true,
		Message: "unknown policy set \"typo-name\"",
	}

	// First report: alerts immediately.
	if err := a.Diagnostic(ctx, "c1", "wordpress-1", d); err != nil {
		t.Fatalf("Diagnostic (first): %v", err)
	}
	if got := len(cb.notifications()); got != 1 {
		t.Fatalf("len(notifications) after first sticky Error = %d, want 1", got)
	}

	// Re-fed on a later reconcile pass, unchanged: does not re-alert.
	a.StartReconcile()
	if err := a.Diagnostic(ctx, "c1", "wordpress-1", d); err != nil {
		t.Fatalf("Diagnostic (re-feed): %v", err)
	}
	a.EndReconcile()
	if got := len(cb.notifications()); got != 1 {
		t.Fatalf("len(notifications) after re-feeding the same sticky diagnostic = %d, want 1 (no re-alert)", got)
	}

	// It shows up in the digest while still active.
	if err := a.Digest(ctx); err != nil {
		t.Fatalf("Digest: %v", err)
	}
	notifs := cb.notifications()
	digest := notifs[len(notifs)-1]
	if !strings.Contains(digest.Body, "wordpress-1") || !strings.Contains(digest.Body, "typo-name") {
		t.Errorf("digest Body = %q, want it to list the sticky diagnostic", digest.Body)
	}

	// A reconcile pass completes without re-feeding it: it ages out.
	a.StartReconcile()
	a.EndReconcile()

	if err := a.Digest(ctx); err != nil {
		t.Fatalf("Digest (after age-out): %v", err)
	}
	notifs = cb.notifications()
	final := notifs[len(notifs)-1]
	if strings.Contains(final.Body, "typo-name") {
		t.Errorf("digest Body = %q, want the aged-out sticky diagnostic gone", final.Body)
	}
}

func TestDigestResetsCounters(t *testing.T) {
	a, cb, clock := newTestAlerter(t, time.Hour, 30, t0)
	ctx := context.Background()

	v := testViolation("svc", "example.com", 443, engine.ClassNoMatch, policy.Alert, "c1", "svc-1")
	if err := a.Violation(ctx, v); err != nil {
		t.Fatalf("Violation (first): %v", err)
	}
	clock.Advance(time.Minute)
	if err := a.Violation(ctx, v); err != nil { // suppressed, counted
		t.Fatalf("Violation (repeat): %v", err)
	}

	if err := a.Digest(ctx); err != nil {
		t.Fatalf("Digest (1): %v", err)
	}
	first := cb.notifications()
	firstDigest := first[len(first)-1]
	if !strings.Contains(firstDigest.Body, "1 suppressed") {
		t.Fatalf("first digest Body = %q, want it to report 1 suppressed", firstDigest.Body)
	}

	// With nothing new since, the next digest should report nothing.
	if err := a.Digest(ctx); err != nil {
		t.Fatalf("Digest (2): %v", err)
	}
	all := cb.notifications()
	secondDigest := all[len(all)-1]
	if secondDigest.Body != "Nothing to report this period." {
		t.Errorf("second digest Body = %q, want the reset digest to report nothing", secondDigest.Body)
	}
}

func TestReportWrapsHealth(t *testing.T) {
	a, _, _ := newTestAlerter(t, time.Hour, 30, t0)
	if err := a.Report(context.Background(), true); err != nil {
		t.Fatalf("Report(true): %v", err)
	}
	if err := a.Report(context.Background(), false); err != nil {
		t.Fatalf("Report(false): %v", err)
	}
}

func TestSetWindowOverridesPerService(t *testing.T) {
	a, cb, clock := newTestAlerter(t, time.Hour, 30, t0)
	ctx := context.Background()

	// A short per-service override lets a chatty-but-legitimate service
	// re-alert well inside the fleet-wide 1h default.
	a.SetWindow("crawler", 5*time.Minute)

	v := testViolation("crawler", "example.com", 443, engine.ClassNoMatch, policy.Alert, "c1", "crawler-1")
	if err := a.Violation(ctx, v); err != nil {
		t.Fatalf("Violation (first): %v", err)
	}
	clock.Advance(6 * time.Minute) // past the 5m override, well inside the 1h default
	if err := a.Violation(ctx, v); err != nil {
		t.Fatalf("Violation (after override window): %v", err)
	}

	if got := len(cb.notifications()); got != 2 {
		t.Fatalf("len(notifications) = %d, want 2 (per-service window override should have rolled)", got)
	}
}
