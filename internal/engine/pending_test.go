// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/policy"
)

func TestDeferredConnectionAllowedByLateSNI(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"example.com:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("198.51.100.9")

	// No DNS, no SNI yet: a name-based allow exists, so this is deferred
	// rather than emitted as unresolved-ip immediately.
	wantNoViolation(t, e.Process(connEvent("c1", ip, 443, now)))

	// The SNI arrives just after the connect and names the allowed host.
	// Process(TLSHello) itself never returns a violation.
	wantNoViolation(t, e.Process(sniEvent("c1", "example.com", now.Add(time.Second))))

	// The deferred verdict was dropped on the spot: Flush past the
	// deadline finds nothing pending for it and emits nothing.
	flushed := e.Flush(now.Add(sniWindow + time.Second))
	wantNoViolation(t, flushed)
}

func TestDeferredConnectionEmitsAtDeadlineWithoutSNI(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"example.com:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("198.51.100.9")

	wantNoViolation(t, e.Process(connEvent("c1", ip, 443, now)))

	// No SNI ever arrives. Before the deadline, Flush must not emit yet.
	wantNoViolation(t, e.Flush(now.Add(sniWindow/2)))

	// Past the deadline, the deferred verdict surfaces with the correct
	// class: no name evidence was ever found, so unresolved-ip.
	got := e.Flush(now.Add(sniWindow + time.Second))
	wantOneViolation(t, got, ClassUnresolvedIP)
}

func TestPureIPPolicyViolationIsImmediateNeverDeferred(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"203.0.113.7:443"}, nil)
	e := New(w)

	now := time.Now()
	got := e.Process(connEvent("c1", mustAddr("198.51.100.9"), 443, now))
	wantOneViolation(t, got, ClassUnresolvedIP)

	// Nothing was ever deferred, so Flush has nothing to say about it.
	flushed := e.Flush(now.Add(sniWindow + time.Second))
	wantNoViolation(t, flushed)
}

func TestDenyMatchIsNeverDeferred(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"*"}, []string{"bad.example:443"})
	e := New(w)

	now := time.Now()
	ip := mustAddr("198.51.100.9")
	e.Process(dnsEvent("c1", "bad.example", 300*time.Second, now, ip))
	got := e.Process(connEvent("c1", ip, 443, now.Add(time.Second)))
	wantOneViolation(t, got, ClassDeny)

	flushed := e.Flush(now.Add(sniWindow + 2*time.Second))
	wantNoViolation(t, flushed)
}

func TestPendingCapOverflowEvaluatesOldestImmediatelyRatherThanDropping(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"example.com:443"}, nil)
	e := New(w)

	now := time.Now()

	var oldestIP netip.Addr
	for i := 0; i < pendingCapPerContainer; i++ {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)})
		if i == 0 {
			oldestIP = ip
		}
		wantNoViolation(t, e.Process(connEvent("c1", ip, 443, now)))
	}

	// The queue is now exactly at cap. One more deferrable connection
	// must force the oldest entry out, evaluated immediately, rather
	// than being silently dropped.
	overflowIP := netip.AddrFrom4([4]byte{198, 51, 100, 250})
	got := e.Process(connEvent("c1", overflowIP, 443, now))
	v := wantOneViolation(t, got, ClassUnresolvedIP)
	if v.DstIP != oldestIP {
		t.Fatalf("expected the forced-out violation to be the oldest pending connection %v, got %v", oldestIP, v.DstIP)
	}

	// The newest (overflowIP) connection itself, and every other one
	// still short of its own deadline, remain pending; only the one
	// forced-out entry was emitted early.
	flushed := e.Flush(now.Add(sniWindow + time.Second))
	if len(flushed) != pendingCapPerContainer {
		t.Fatalf("expected %d remaining deferred violations at Flush, got %d", pendingCapPerContainer, len(flushed))
	}
}
