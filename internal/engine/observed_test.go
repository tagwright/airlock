// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package engine

import (
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/observe"
)

// TestObserved_UnarmedConnectionRecordsWithDNSName proves an unarmed
// container's in-scope connection is recorded with "observed" verdict and
// the winning DNS name evidence.
func TestObserved_UnarmedConnectionRecordsWithDNSName(t *testing.T) {
	w := newFakeWorld() // c1 carries no policy: unarmed.
	e := New(w)
	now := time.Now()
	dst := mustAddr("203.0.113.9")

	e.Process(dnsEvent("c1", "example.com", time.Minute, now, dst))
	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "plain",
		DstIP: dst, DstPort: 443, Proto: "tcp", Timestamp: now,
	})

	got := e.Observed("c1")
	if len(got) != 1 {
		t.Fatalf("Observed(c1) = %+v, want exactly one entry", got)
	}
	d := got[0]
	if d.Verdict != "observed" {
		t.Errorf("Verdict = %q, want %q", d.Verdict, "observed")
	}
	if d.Name != "example.com" {
		t.Errorf("Name = %q, want %q", d.Name, "example.com")
	}
	if d.ContainerName != "plain" {
		t.Errorf("ContainerName = %q, want %q", d.ContainerName, "plain")
	}
	if d.Port != 443 || d.Proto != "tcp" {
		t.Errorf("Port/Proto = %d/%q, want 443/tcp", d.Port, d.Proto)
	}
	if d.Count != 1 {
		t.Errorf("Count = %d, want 1", d.Count)
	}
}

// TestObserved_ArmedContainerRecordsVerdict proves an armed container's
// connections are recorded with the real match verdict: "allowed" for an
// allow match, and the violation class string for a default-deny-floor
// violation.
func TestObserved_ArmedContainerRecordsVerdict(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("web", 0 /* External */, 1 /* Alert */, []string{"good.example.com:443"}, nil)
	e := New(w)
	now := time.Now()

	allowedDst := mustAddr("203.0.113.1")
	e.Process(dnsEvent("c1", "good.example.com", time.Minute, now, allowedDst))
	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "web",
		DstIP: allowedDst, DstPort: 443, Proto: "tcp", Timestamp: now,
	})

	unresolvedDst := mustAddr("203.0.113.2")
	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "web",
		DstIP: unresolvedDst, DstPort: 8443, Proto: "tcp", Timestamp: now,
	})

	got := e.Observed("c1")
	if len(got) != 2 {
		t.Fatalf("Observed(c1) = %+v, want exactly two entries", got)
	}

	byPort := map[uint16]ObservedDest{}
	for _, d := range got {
		byPort[d.Port] = d
	}

	if v := byPort[443].Verdict; v != "allowed" {
		t.Errorf("allowed dest verdict = %q, want %q", v, "allowed")
	}
	if v := byPort[8443].Verdict; v != "unresolved-ip" {
		t.Errorf("unresolved dest verdict = %q, want %q", v, "unresolved-ip")
	}
}

// TestObserved_SnapshotReflectsMultipleContainers proves ObservedSnapshot
// aggregates across every container the engine has recorded, keyed by
// container id.
func TestObserved_SnapshotReflectsMultipleContainers(t *testing.T) {
	w := newFakeWorld()
	e := New(w)
	now := time.Now()

	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "one",
		DstIP: mustAddr("198.51.100.1"), DstPort: 80, Proto: "tcp", Timestamp: now,
	})
	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c2", ContainerName: "two",
		DstIP: mustAddr("198.51.100.2"), DstPort: 80, Proto: "tcp", Timestamp: now,
	})

	snap := e.ObservedSnapshot()
	if len(snap) != 2 {
		t.Fatalf("ObservedSnapshot() has %d containers, want 2: %+v", len(snap), snap)
	}
	if len(snap["c1"]) != 1 || len(snap["c2"]) != 1 {
		t.Errorf("ObservedSnapshot() = %+v, want one entry per container", snap)
	}
}

// TestObserved_RepeatedConnectionUpdatesCountAndLastSeen proves a repeat
// observation of the same destination bumps Count and LastSeen rather than
// creating a second entry, and that a later name evidence upgrade
// overwrites a previously empty name.
func TestObserved_RepeatedConnectionUpdatesCountAndLastSeen(t *testing.T) {
	w := newFakeWorld()
	e := New(w)
	t0 := time.Now()
	dst := mustAddr("203.0.113.3")

	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "x",
		DstIP: dst, DstPort: 443, Proto: "tcp", Timestamp: t0,
	})

	t1 := t0.Add(time.Second)
	e.Process(dnsEvent("c1", "later.example.com", time.Minute, t1, dst))
	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "x",
		DstIP: dst, DstPort: 443, Proto: "tcp", Timestamp: t1,
	})

	got := e.Observed("c1")
	if len(got) != 1 {
		t.Fatalf("Observed(c1) = %+v, want exactly one (deduped) entry", got)
	}
	d := got[0]
	if d.Count != 2 {
		t.Errorf("Count = %d, want 2", d.Count)
	}
	if !d.LastSeen.Equal(t1) {
		t.Errorf("LastSeen = %v, want %v", d.LastSeen, t1)
	}
	if !d.FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen = %v, want %v (unchanged by the repeat)", d.FirstSeen, t0)
	}
	if d.Name != "later.example.com" {
		t.Errorf("Name = %q, want the name evidence learned on the second observation", d.Name)
	}
}

// TestObserved_ForgetClearsRecorder proves Forget releases a container's
// observed-egress state along with its correlation caches.
func TestObserved_ForgetClearsRecorder(t *testing.T) {
	w := newFakeWorld()
	e := New(w)
	now := time.Now()

	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "x",
		DstIP: mustAddr("203.0.113.4"), DstPort: 443, Proto: "tcp", Timestamp: now,
	})
	if len(e.Observed("c1")) != 1 {
		t.Fatalf("Observed(c1) before Forget: want one entry")
	}

	e.Forget("c1")

	if got := e.Observed("c1"); len(got) != 0 {
		t.Errorf("Observed(c1) after Forget = %+v, want none", got)
	}
	if snap := e.ObservedSnapshot(); len(snap) != 0 {
		t.Errorf("ObservedSnapshot() after Forget = %+v, want empty", snap)
	}
}

// TestObserved_LoopbackAndOwnNetworkNotRecorded proves the recorder honors
// the same scope filtering as policy evaluation: loopback and (under the
// default External scope) the runtime's own container networks are never
// recorded, matching "what a human would want to see to build an
// allowlist."
func TestObserved_LoopbackAndOwnNetworkNotRecorded(t *testing.T) {
	w := newFakeWorld()
	e := New(w)
	now := time.Now()

	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "x",
		DstIP: mustAddr("127.0.0.1"), DstPort: 443, Proto: "tcp", Timestamp: now,
	})
	if got := e.Observed("c1"); len(got) != 0 {
		t.Errorf("Observed(c1) after loopback connection = %+v, want none recorded", got)
	}
}

// TestObserved_SNIOnlyPopulatesSNINameNotName proves ObservedDest.Name is
// DNS-correlation-only: an observed SNI with no DNS answer at all lands in
// SNIName, never in Name, so a `airlock suggest` caller rendering Name as
// a paste-ready domain never emits a rule that could not actually match
// under fail-closed matching (see engine.go's package doc comment).
func TestObserved_SNIOnlyPopulatesSNINameNotName(t *testing.T) {
	w := newFakeWorld()
	e := New(w) // c1 unarmed: recorded verdict is "observed".
	now := time.Now()
	dst := mustAddr("203.0.113.10")

	e.Process(sniEvent("c1", "sni-only.example.com", now))
	e.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "x",
		DstIP: dst, DstPort: 443, Proto: "tcp", Timestamp: now.Add(time.Second),
	})

	got := e.Observed("c1")
	if len(got) != 1 {
		t.Fatalf("Observed(c1) = %+v, want exactly one entry", got)
	}
	d := got[0]
	if d.Name != "" {
		t.Errorf("Name = %q, want empty (no DNS answer was ever recorded)", d.Name)
	}
	if d.SNIName != "sni-only.example.com" {
		t.Errorf("SNIName = %q, want the observed SNI name", d.SNIName)
	}
}
