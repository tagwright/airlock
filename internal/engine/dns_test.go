// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/policy"
)

// -- direct dnsCache unit tests --

func TestDNSCacheLookupWithinTTL(t *testing.T) {
	c := newDNSCache()
	now := time.Now()
	addr := mustAddr("203.0.113.1")
	c.put(addr, "example.com", now.Add(60*time.Second))

	name, ok := c.lookup(addr, now.Add(30*time.Second))
	if !ok || name != "example.com" {
		t.Fatalf("expected a hit for example.com, got %q ok=%v", name, ok)
	}
}

func TestDNSCacheGraceWindow(t *testing.T) {
	c := newDNSCache()
	now := time.Now()
	addr := mustAddr("203.0.113.1")
	expiry := now.Add(30 * time.Second)
	c.put(addr, "example.com", expiry)

	// Just past the raw expiry but still within grace: still a hit.
	if _, ok := c.lookup(addr, expiry.Add(dnsGrace-time.Second)); !ok {
		t.Fatalf("expected a hit within the grace window")
	}
	// Past expiry plus grace: a miss, and the entry is evicted.
	if _, ok := c.lookup(addr, expiry.Add(dnsGrace+time.Second)); ok {
		t.Fatalf("expected a miss past expiry plus grace")
	}
	if _, present := c.entries[addr]; present {
		t.Fatalf("expected the expired entry to be evicted on read")
	}
}

func TestDNSCacheCapBoundsMemoryUnderFlood(t *testing.T) {
	c := newDNSCache()
	now := time.Now()
	flood := dnsCachePerContainerCap + 500
	for i := 0; i < flood; i++ {
		addr := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		c.put(addr, "flood.example", now.Add(time.Hour))
	}
	if len(c.entries) > dnsCachePerContainerCap {
		t.Fatalf("expected cache to stay at or under cap %d, got %d entries", dnsCachePerContainerCap, len(c.entries))
	}
	// The most recently inserted address must still be present: FIFO
	// eviction drops the oldest, never the newest, so a hostile flood
	// degrades correlation for old lookups, not the connection actually
	// in flight.
	last := netip.AddrFrom4([4]byte{10, byte((flood - 1) >> 16), byte((flood - 1) >> 8), byte(flood - 1)})
	if _, ok := c.lookup(last, now); !ok {
		t.Fatalf("expected the most recently inserted entry to survive the flood")
	}
}

// -- TTL floor as applied through the engine's public Process path --

func TestEngineAppliesTTLFloorToShortAnswers(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"example.com:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("93.184.216.34")
	// A 1-second TTL is floored up to dnsTTLFloor (30s), so a connection
	// well past 1 second but before the floor must still correlate.
	e.Process(dnsEvent("c1", "example.com", 1*time.Second, now, ip))
	got := e.Process(connEvent("c1", ip, 443, now.Add(15*time.Second)))
	wantNoViolation(t, got)
}
