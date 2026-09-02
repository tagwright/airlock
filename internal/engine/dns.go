// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package engine

import (
	"net/netip"
	"time"
)

const (
	// dnsTTLFloor is the minimum TTL the engine honors for a DNS answer,
	// regardless of what the answer itself claimed (including a
	// backend-reported zero TTL, which observe.Event documents as
	// possible when the backend cannot surface it). A floor exists
	// because a very short or zero TTL would otherwise make the
	// DNS-to-connection correlation window narrower than the time it
	// takes a process to actually open the connection it just resolved
	// for, defeating correlation for the most common case (resolve, then
	// immediately connect). The frozen doc requires "TTL with a floor and
	// a short grace window" but does not fix the numbers; this value is a
	// judgment call, called out as such in the implementation report.
	dnsTTLFloor = 30 * time.Second

	// dnsGrace extends every cache entry's effective lifetime past its
	// (floored) expiry by this much before it is treated as gone. This
	// absorbs clock skew between the DNS answer and the connection
	// events, plus the ordinary case of a long-lived HTTP client that
	// resolves once and reuses the address slightly past the TTL it was
	// told. Not specified numerically by the frozen doc; called out in
	// the implementation report.
	dnsGrace = 30 * time.Second

	// dnsCachePerContainerCap bounds how many distinct resolved addresses
	// one container's DNS cache remembers at once. This is the hostile-
	// flood defense the frozen doc's correlation design calls for: a
	// container cannot make its OWN cache grow without bound (it cannot
	// pollute another container's cache at all, since correlation is
	// strictly per-container), but a compromised container cycling
	// through many distinct resolved names is exactly the noisy-
	// compromise shape airlock targets, so the cache must not become an
	// unbounded memory sink while that happens. Eviction is FIFO by
	// insertion, not by remaining TTL, which is a simple, cheap policy
	// that is adequate for a bound whose job is memory safety, not
	// correlation accuracy under flood (accuracy degrades gracefully:
	// evicted entries just fall back to "no name evidence").
	dnsCachePerContainerCap = 4096
)

// dnsRecord is one cached DNS answer: the queried name and the absolute
// time (already TTL-floored) after which it is no longer honored, before
// the grace window is added at read time.
type dnsRecord struct {
	qname  string
	expiry time.Time
}

// dnsCache is one container's DNS answer cache: destination IP -> the most
// recent qname that resolved to it, per Fork 4/the honesty section. It is
// not safe for concurrent use on its own; the owning Engine's mutex
// serializes all access.
type dnsCache struct {
	entries map[netip.Addr]dnsRecord
	// order records insertion order of NEW keys only (a re-answer of an
	// already-cached address updates entries in place and does not
	// re-append), so it bounds memory growth without needing a full LRU.
	// It may accumulate stale addresses already removed from entries by
	// expiry or by a prior eviction; evictOverCap tolerates that.
	order []netip.Addr
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[netip.Addr]dnsRecord)}
}

// put records that addr resolved to qname, expiring at expiry (the
// caller has already applied dnsTTLFloor), and enforces the
// per-container cap.
func (c *dnsCache) put(addr netip.Addr, qname string, expiry time.Time) {
	if _, exists := c.entries[addr]; !exists {
		c.order = append(c.order, addr)
	}
	c.entries[addr] = dnsRecord{qname: qname, expiry: expiry}
	c.evictOverCap()
}

// lookup returns the qname this container most recently resolved addr to,
// if that answer is still within its TTL plus grace as of now. An entry
// found to be past its grace period is evicted on the read.
func (c *dnsCache) lookup(addr netip.Addr, now time.Time) (string, bool) {
	rec, ok := c.entries[addr]
	if !ok {
		return "", false
	}
	if now.After(rec.expiry.Add(dnsGrace)) {
		delete(c.entries, addr)
		return "", false
	}
	return rec.qname, true
}

func (c *dnsCache) evictOverCap() {
	for len(c.entries) > dnsCachePerContainerCap && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldest)
	}
}
