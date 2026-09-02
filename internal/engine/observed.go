// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package engine

import (
	"net/netip"
	"strconv"
	"time"
)

// observedCapPerContainer bounds how many distinct destinations one
// container's observed-egress recorder remembers at once, the same
// hostile-flood defense rationale as the DNS cache and SNI store: a
// container cannot make its own recorder grow without bound. Eviction is
// FIFO by insertion, matching dnsCache's own policy.
const observedCapPerContainer = 500

// ObservedDest is one destination observed on a container's egress,
// exported by ObservedSnapshot/Observed for `airlock status`'s unpolicied
// digest summary and `airlock suggest`'s allowlist-builder to render. It is
// the engine's own record, because the engine is the only place in airlock
// with live DNS/SNI correlation for a connection -- a reader elsewhere
// (the daemon, a CLI) cannot reconstruct the name evidence after the fact.
type ObservedDest struct {
	// ContainerName is the container's runtime name at the time of the
	// most recent observation, denormalized onto every entry so a reader
	// keying only off ObservedSnapshot's containerID map need not
	// cross-reference anything else to render a human-readable line.
	ContainerName string

	DstIP netip.Addr
	Port  uint16
	Proto string

	// Name is the DNS-cache-correlated name for this destination, or empty
	// when this container's DNS cache holds nothing for it. This is
	// deliberately the SAME name evidence the policy engine itself will
	// match a Domain/DomainWildcard entry against (see match.go's
	// fail-closed-on-SNI doc comment): `airlock suggest` renders Name
	// straight into a "name:port" allow entry precisely because, unlike an
	// SNI-only name, it is guaranteed to actually match if pasted back in.
	// Empty means the frozen doc's unresolved-ip shape as far as a
	// PASTEABLE name rule is concerned, even if SNIName below is
	// non-empty.
	Name string

	// SNIName is the observed TLS SNI name for this destination, if any,
	// carried purely as informational enrichment -- exactly like
	// Violation.SNIName. It is NEVER the right value to render as a
	// suggested allow entry's domain: a name rule built from an SNI-only
	// observation would never match again under fail-closed matching (see
	// engine.go's package doc comment), so a caller building suggest
	// output should render Name if non-empty, else the destination IP,
	// and may show SNIName only as an informational aside on the IP line.
	SNIName string

	FirstSeen time.Time
	LastSeen  time.Time
	Count     int

	// Verdict is "observed" for a connection recorded from an unarmed (or
	// unknown-to-World) container -- this container's declared policy, if
	// any, was never evaluated against this connection -- or, for an armed
	// container, the actual, final outcome: "allowed" or a Class.String()
	// value. Evaluation is synchronous and final at connect time (see
	// evaluateConnection), so this is never a placeholder for a verdict
	// that might still change.
	Verdict string
}

// observedEntry is one destination's bookkeeping within one container's
// recorder entry. Not safe for concurrent use on its own; the owning
// Engine's mutex serializes all access (see the Engine.observed field's
// doc comment).
type observedEntry struct {
	order         int
	containerName string
	dstIP         netip.Addr
	port          uint16
	proto         string
	name          string // DNS-cache-correlated name only; see ObservedDest.Name
	sniName       string // informational enrichment only; see ObservedDest.SNIName
	firstSeen     time.Time
	lastSeen      time.Time
	count         int
	verdict       string
}

// observedContainer is one container's observed-egress recorder entry:
// every distinct destination seen from it, bounded and FIFO-evicted at
// observedCapPerContainer.
type observedContainer struct {
	entries map[string]*observedEntry
	seq     int
}

// observedKey combines a destination IP, port, and protocol into the
// per-container map key. A literal "#" separator (never valid inside an IP,
// a port number, or a protocol name) keeps this unambiguous, mirroring
// suggestStore's identical reasoning for its own destination key.
func observedKey(dst netip.Addr, port uint16, proto string) string {
	return dst.String() + "#" + strconv.Itoa(int(port)) + "#" + proto
}

// recordObserved records one observed destination for containerID, either
// updating an existing entry (bumping its count and last-seen, and
// refreshing its name evidence and verdict to the latest observation) or
// creating a new one, evicting the oldest entry first if the container's
// recorder is already at observedCapPerContainer.
//
// Caller must hold e.mu -- see the Engine.observed field's doc comment.
// This is always true in practice: the only caller is evaluateConnection,
// itself only ever reached from Process, which takes e.mu for its entire
// body. dnsName and sniName are recorded independently, per
// ObservedDest.Name/SNIName's doc comments -- dnsName is the only one
// `airlock suggest` may ever render as a suggested entry's domain.
func (e *Engine) recordObserved(containerID, containerName string, dst netip.Addr, port uint16, proto, dnsName, sniName string, when time.Time, verdict string) {
	if containerID == "" {
		return
	}
	oc := e.observed[containerID]
	if oc == nil {
		oc = &observedContainer{entries: make(map[string]*observedEntry)}
		e.observed[containerID] = oc
	}

	key := observedKey(dst, port, proto)
	entry, ok := oc.entries[key]
	if !ok {
		if len(oc.entries) >= observedCapPerContainer {
			evictOldestObservedLocked(oc)
		}
		entry = &observedEntry{order: oc.seq, dstIP: dst, port: port, proto: proto, firstSeen: when}
		oc.seq++
		oc.entries[key] = entry
	}
	if containerName != "" {
		entry.containerName = containerName
	}
	entry.count++
	entry.lastSeen = when
	entry.verdict = verdict
	// Only overwrite name evidence when this observation actually carries
	// some, independently for each source: a later connection to the same
	// destination with no name evidence this time (a stale DNS cache
	// entry, no SNI this time) should not blank out a good name a human
	// would want to see on the suggested/displayed line.
	if dnsName != "" {
		entry.name = dnsName
	}
	if sniName != "" {
		entry.sniName = sniName
	}
}

// evictOldestObservedLocked drops oc's entry with the smallest insertion
// order. Caller must hold e.mu and know len(oc.entries) is at capacity.
func evictOldestObservedLocked(oc *observedContainer) {
	var oldestKey string
	oldest := -1
	for k, entry := range oc.entries {
		if oldest == -1 || entry.order < oldest {
			oldest = entry.order
			oldestKey = k
		}
	}
	if oldest != -1 {
		delete(oc.entries, oldestKey)
	}
}

// snapshotObservedContainerLocked converts one container's recorder into
// the exported ObservedDest slice. Caller must hold e.mu.
func snapshotObservedContainerLocked(oc *observedContainer) []ObservedDest {
	out := make([]ObservedDest, 0, len(oc.entries))
	for _, entry := range oc.entries {
		out = append(out, ObservedDest{
			ContainerName: entry.containerName,
			DstIP:         entry.dstIP,
			Port:          entry.port,
			Proto:         entry.proto,
			Name:          entry.name,
			SNIName:       entry.sniName,
			FirstSeen:     entry.firstSeen,
			LastSeen:      entry.lastSeen,
			Count:         entry.count,
			Verdict:       entry.verdict,
		})
	}
	return out
}

// ObservedSnapshot returns every currently recorded observed destination
// across every container the engine has processed a Connection for, keyed
// by container id. Safe to call from any goroutine, concurrently with
// Process/Flush: it takes the same mutex those do (see the package doc
// comment's concurrency section), so a daemon's periodic status-snapshot
// writer can call this from its own timer goroutine while the single feeder
// goroutine keeps calling Process.
func (e *Engine) ObservedSnapshot() map[string][]ObservedDest {
	e.mu.Lock()
	defer e.mu.Unlock()

	out := make(map[string][]ObservedDest, len(e.observed))
	for id, oc := range e.observed {
		out[id] = snapshotObservedContainerLocked(oc)
	}
	return out
}

// Observed returns every currently recorded observed destination for one
// container, or nil if the engine has recorded nothing for it. Safe to call
// from any goroutine; see ObservedSnapshot's doc comment.
func (e *Engine) Observed(containerID string) []ObservedDest {
	e.mu.Lock()
	defer e.mu.Unlock()

	oc, ok := e.observed[containerID]
	if !ok {
		return nil
	}
	return snapshotObservedContainerLocked(oc)
}
