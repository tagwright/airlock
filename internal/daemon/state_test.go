// SPDX-License-Identifier: GPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/core/runtime"
)

// TestWriteStateSnapshotAtomic_RoundTrips proves a written snapshot reads
// back identically via LoadStateSnapshot, and that the write goes through
// a temp-file-plus-rename (no leftover temp file after a successful
// write).
func TestWriteStateSnapshotAtomic_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "state.json")

	want := StateSnapshot{
		SchemaVersion: stateSchemaVersion,
		GeneratedAt:   time.Now().UTC().Truncate(time.Second),
		Version:       "test-version",
		Backend: BackendHealth{
			Name:          "inspektor-gadget",
			EventsFlowing: true,
			Restarts:      2,
			DroppedEvents: 0,
		},
		Containers: []ArmedContainer{
			{ID: "c1", Name: "web", Service: "web", Mode: "alert", Scope: "external",
				MatchedGroups:     []string{"media-stack"},
				ViolationsByClass: map[string]int{"no-match": 3},
				Suppressed:        1,
			},
		},
		Suggestions: []SuggestContainer{
			{ID: "c2", Name: "legacy", Destinations: []SuggestDest{
				{Name: "api.github.com", IP: "140.82.112.3", Port: 443, Proto: "tcp", Count: 5, Verdict: "no-match"},
			}},
		},
	}

	if err := writeStateSnapshotAtomic(path, want); err != nil {
		t.Fatalf("writeStateSnapshotAtomic: %v", err)
	}

	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(path) {
			t.Errorf("leftover file in state dir after a successful write: %s", e.Name())
		}
	}

	got, err := LoadStateSnapshot(path)
	if err != nil {
		t.Fatalf("LoadStateSnapshot: %v", err)
	}

	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("round-tripped snapshot mismatch\n got: %s\nwant: %s", gotJSON, wantJSON)
	}
}

// TestLoadStateSnapshot_MissingFile proves the CLI-facing reader returns a
// plain error (not a panic, not a zero-value success) for a state file that
// does not exist -- the "daemon not running" / "not yet written" case.
func TestLoadStateSnapshot_MissingFile(t *testing.T) {
	_, err := LoadStateSnapshot(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("LoadStateSnapshot(missing file) = nil error, want an error")
	}
}

// TestBuildStateSnapshot_ArmedAndSuggestData drives a Daemon through
// reconcile plus a couple of observed connections, then proves
// buildStateSnapshot's output carries the armed container's mode/scope/
// matched-group metadata, its violation tally, and the suggest data for an
// unarmed container -- the whole state-snapshot assembly path, with no
// filesystem I/O (that is writeStateSnapshotAtomic's own, separately
// tested, job).
func TestBuildStateSnapshot_ArmedAndSuggestData(t *testing.T) {
	cfg := newTestConfig(t)
	armed := armedContainer("c1", "web", map[string]string{"airlock.allow": "10.0.0.0/8"})
	unarmed := runtime.Container{ID: "c2", Name: "legacy", Labels: map[string]string{}}
	rt := &fakeRuntime{containers: []runtime.Container{armed, unarmed}}
	d := newTestDaemon(t, cfg, rt)
	ctx := context.Background()

	if err := d.reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	now := time.Now()
	// c1 (armed) reaches an undeclared, unresolved bare IP: no DNS/SNI
	// evidence at all makes this an unresolved-ip violation, per Fork 6.
	d.handleObserveEvent(ctx, observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "web",
		DstIP: mustAddr(t, "203.0.113.9"), DstPort: 8443, Proto: "tcp", Timestamp: now,
	})
	// c2 (unarmed) is just observed.
	d.handleObserveEvent(ctx, observe.Event{
		Kind: observe.Connection, ContainerID: "c2", ContainerName: "legacy",
		DstIP: mustAddr(t, "198.51.100.5"), DstPort: 443, Proto: "tcp", Timestamp: now,
	})

	snap := d.buildStateSnapshot()

	if len(snap.Containers) != 1 {
		t.Fatalf("Containers = %+v, want exactly one armed container", snap.Containers)
	}
	ac := snap.Containers[0]
	if ac.ID != "c1" || ac.Mode != "alert" || ac.Scope != "external" {
		t.Errorf("armed container meta = %+v, want id=c1 mode=alert scope=external", ac)
	}
	if ac.ViolationsByClass["unresolved-ip"] != 1 {
		t.Errorf("ViolationsByClass = %+v, want unresolved-ip=1", ac.ViolationsByClass)
	}

	// Suggestions carries BOTH armed and unarmed containers' observed
	// egress (the frozen brief: "per container, armed or
	// observed-unarmed"), distinguished by each destination's Verdict.
	byID := map[string]SuggestContainer{}
	for _, sc := range snap.Suggestions {
		byID[sc.ID] = sc
	}

	c2, ok := byID["c2"]
	if !ok || len(c2.Destinations) != 1 || c2.Destinations[0].Verdict != "observed" {
		t.Errorf("c2 (unarmed) suggestions = %+v, ok=%v, want one entry with verdict \"observed\"", c2, ok)
	}

	c1, ok := byID["c1"]
	if !ok || len(c1.Destinations) != 1 || c1.Destinations[0].Verdict != "unresolved-ip" {
		t.Errorf("c1 (armed) suggestions = %+v, ok=%v, want one entry with verdict \"unresolved-ip\"", c1, ok)
	}
}
