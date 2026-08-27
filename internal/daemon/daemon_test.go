// SPDX-License-Identifier: GPL-3.0-or-later

package daemon

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/alert"
	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/engine"
	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/core/runtime"
)

// newTestDaemon builds a Daemon around a fakeRuntime, with no observe
// backend (these tests never call Run, only the individual methods it
// coordinates) and a real alert.Alerter wired only to beacon's built-in
// "log" backend, so Violation/Diagnostic/Digest/Report are safe to call
// with no network I/O.
func newTestDaemon(t *testing.T, cfg *config.Config, rt *fakeRuntime) *Daemon {
	t.Helper()
	alerter, err := alert.New(cfg, nil)
	if err != nil {
		t.Fatalf("alert.New: %v", err)
	}
	w := newWorld()
	return &Daemon{
		cfg:               cfg,
		logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		rt:                rt,
		netInsp:           rt,
		alerter:           alerter,
		engine:            engine.New(w),
		world:             w,
		health:            newBackendHealthTracker("test"),
		violations:        newViolationTally(),
		unpolicied:        newUnpoliciedTracker(),
		heartbeatInterval: time.Minute,
		debounce:          10 * time.Millisecond,
		resolvConfPath:    "/nonexistent-resolv-conf-for-airlock-tests",
		statePath:         filepath.Join(t.TempDir(), "state.json"),
		stateInterval:     time.Hour,
	}
}

func TestDaemon_ReconcileDropsRemovedContainerAndForgetsEngineState(t *testing.T) {
	cfg := newTestConfig(t)
	c := armedContainer("c1", "web", map[string]string{"airlock.allow": "example.com"})
	rt := &fakeRuntime{containers: []runtime.Container{c}}
	d := newTestDaemon(t, cfg, rt)
	ctx := context.Background()

	if err := d.reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if _, ok := d.world.ResolvedPolicy("c1"); !ok {
		t.Fatalf("ResolvedPolicy(c1) after first reconcile: ok = false, want true")
	}

	now := time.Now()
	dst := mustAddr(t, "203.0.113.5")

	// Correlate example.com -> dst via a DNS answer, then confirm a
	// connection to dst is judged allowed while that correlation is
	// live.
	d.engine.Process(observe.Event{
		Kind: observe.DNSAnswer, ContainerID: "c1", QName: "example.com",
		Answers: []netip.Addr{dst}, TTL: time.Minute, Timestamp: now,
	})
	if v := d.engine.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", DstIP: dst, DstPort: 443, Timestamp: now,
	}); len(v) != 0 {
		t.Fatalf("Process(conn) before removal = %+v, want allowed via DNS correlation", v)
	}

	// A destroy event must (1) arm the reconcile debounce and (2)
	// immediately forget c1's engine correlation state, ahead of any
	// reconcile.
	rt.containers = nil
	if arm := d.handleRuntimeEvent(runtime.Event{Type: runtime.EventDestroy, ID: "c1"}); !arm {
		t.Errorf("handleRuntimeEvent(destroy) = false, want true (should arm debounce)")
	}

	// The DNS correlation is gone immediately, before any reconcile
	// runs: the same connection now resolves synchronously and finally
	// to unresolved-ip, proving the DNS cache was actually cleared rather
	// than merely stale.
	v := d.engine.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", DstIP: dst, DstPort: 443, Timestamp: now,
	})
	if len(v) != 1 || v[0].Class != engine.ClassUnresolvedIP {
		t.Fatalf("Process(conn) after Forget = %+v, want one unresolved-ip violation", v)
	}

	// And the next reconcile drops c1 from the World snapshot entirely,
	// since the fake runtime no longer lists it.
	if err := d.reconcile(ctx); err != nil {
		t.Fatalf("reconcile after removal: %v", err)
	}
	if _, ok := d.world.ResolvedPolicy("c1"); ok {
		t.Errorf("ResolvedPolicy(c1) after removal reconcile: ok = true, want false")
	}
}

func TestDaemon_HandleRuntimeEvent_IrrelevantEventDoesNotArm(t *testing.T) {
	cfg := newTestConfig(t)
	d := newTestDaemon(t, cfg, &fakeRuntime{})

	if arm := d.handleRuntimeEvent(runtime.Event{Type: "health_status"}); arm {
		t.Errorf("handleRuntimeEvent(unrelated) = true, want false")
	}
}

func TestDaemon_HandleObserveEvent_RecordsUnarmedConnectionAsObserved(t *testing.T) {
	cfg := newTestConfig(t)
	// c1 is present in the world but carries no airlock labels at all,
	// so it resolves unarmed.
	c := runtime.Container{ID: "c1", Name: "plain", Labels: map[string]string{}}
	rt := &fakeRuntime{containers: []runtime.Container{c}}
	d := newTestDaemon(t, cfg, rt)
	ctx := context.Background()

	if err := d.reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	d.handleObserveEvent(ctx, observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "plain",
		DstIP: mustAddr(t, "198.51.100.7"), DstPort: 443, Proto: "tcp", Timestamp: time.Now(),
	})

	got := d.engine.Observed("c1")
	if len(got) != 1 {
		t.Fatalf("engine.Observed(c1) = %+v, want exactly one recorded destination", got)
	}
	if got[0].DstIP.String() != "198.51.100.7" || got[0].Port != 443 {
		t.Errorf("recorded observation = %+v, want 198.51.100.7:443", got[0])
	}
	if got[0].Verdict != "observed" {
		t.Errorf("recorded verdict = %q, want %q (unarmed container)", got[0].Verdict, "observed")
	}
}

func TestDaemon_HandleObserveEvent_ArmedConnectionRecordsRealVerdict(t *testing.T) {
	cfg := newTestConfig(t)
	c := armedContainer("c1", "web", map[string]string{"airlock.allow": "*"})
	rt := &fakeRuntime{containers: []runtime.Container{c}}
	d := newTestDaemon(t, cfg, rt)
	ctx := context.Background()

	if err := d.reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	d.handleObserveEvent(ctx, observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "web",
		DstIP: mustAddr(t, "198.51.100.7"), DstPort: 443, Proto: "tcp", Timestamp: time.Now(),
	})

	got := d.engine.Observed("c1")
	if len(got) != 1 {
		t.Fatalf("engine.Observed(c1) = %+v, want exactly one recorded destination", got)
	}
	if got[0].Verdict != "allowed" {
		t.Errorf("recorded verdict for an armed, allow: \"*\" container = %q, want %q", got[0].Verdict, "allowed")
	}
}

// TestRecordAndAlertViolation_Tallies proves recordAndAlertViolation -- the
// single choke point handleObserveEvent routes every synchronous verdict
// through -- tallies each call into d.violations, since `airlock status`'s
// per-container violation counts read that tally, not the alerter.
func TestRecordAndAlertViolation_Tallies(t *testing.T) {
	cfg := newTestConfig(t)
	d := newTestDaemon(t, cfg, &fakeRuntime{})
	ctx := context.Background()

	v := engine.Violation{
		Service:     "web",
		Destination: "1.1.1.1",
		Port:        443,
		Class:       engine.ClassUnresolvedIP,
		ContainerID: "c1",
		Timestamp:   time.Now(),
	}

	d.recordAndAlertViolation(ctx, v)
	d.recordAndAlertViolation(ctx, v)

	tally := d.violations.Snapshot()
	if got := tally["c1"]["unresolved-ip"]; got != 2 {
		t.Fatalf("violations tally for c1/unresolved-ip = %d, want 2 (one per recordAndAlertViolation call)", got)
	}
}

func TestBuildRuntime_UnknownRuntimeErrors(t *testing.T) {
	t.Setenv("AIRLOCK_RUNTIME", "bogus")
	cfg := newTestConfig(t)
	if _, err := buildRuntime(cfg); err == nil {
		t.Errorf("buildRuntime(AIRLOCK_RUNTIME=bogus) error = nil, want an error")
	}
}

func TestBuildRuntime_DefaultsToDocker(t *testing.T) {
	t.Setenv("AIRLOCK_RUNTIME", "")
	cfg := newTestConfig(t)
	rt, err := buildRuntime(cfg)
	if err != nil {
		t.Fatalf("buildRuntime: %v", err)
	}
	defer rt.Close()
	if _, ok := rt.(runtime.NetworkInspector); !ok {
		t.Errorf("default runtime %T does not implement runtime.NetworkInspector", rt)
	}
}

// TestObserveRuntimes_TracksAirlockRuntime pins the fix this integration
// pass made: buildObserveBackend must scope ig's -r/--runtimes flag to
// whichever single runtime AIRLOCK_RUNTIME actually selects, never a
// multi-runtime hedge -- see observeRuntimes' and ig.DefaultRuntimes' doc
// comments for the real, confirmed-against-a-live-ig-run failure this
// fixes (ig fails its entire startup, emitting zero events forever, the
// moment any listed runtime other than the live one has no socket).
func TestObserveRuntimes_TracksAirlockRuntime(t *testing.T) {
	cases := []struct {
		envRuntime string
		want       string
	}{
		{envRuntime: "", want: "docker"},
		{envRuntime: "docker", want: "docker"},
		{envRuntime: "podman", want: "podman"},
		{envRuntime: "PODMAN", want: "podman"},
	}
	for _, tc := range cases {
		t.Run(tc.envRuntime, func(t *testing.T) {
			t.Setenv("AIRLOCK_RUNTIME", tc.envRuntime)
			cfg := newTestConfig(t)
			if got := observeRuntimes(cfg); got != tc.want {
				t.Errorf("observeRuntimes(AIRLOCK_RUNTIME=%q) = %q, want %q", tc.envRuntime, got, tc.want)
			}
		})
	}
}

// TestObserveRuntimes_ExplicitConfigWins proves an operator's explicit
// airlock.yml observe.runtimes setting is never overridden by
// AIRLOCK_RUNTIME's default derivation -- e.g. a deployment that
// deliberately wants ig scoped to more than one runtime can still ask for
// that.
func TestObserveRuntimes_ExplicitConfigWins(t *testing.T) {
	t.Setenv("AIRLOCK_RUNTIME", "podman")
	cfg := newTestConfig(t)
	cfg.Observe.Runtimes = "docker,podman"
	if got := observeRuntimes(cfg); got != "docker,podman" {
		t.Errorf("observeRuntimes with explicit config = %q, want docker,podman", got)
	}
}
