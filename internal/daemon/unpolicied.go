// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"strconv"
	"sync"
	"time"

	"github.com/tagwright/airlock/internal/engine"
)

// maxUnpoliciedTrackedKeys bounds unpoliciedTracker's total memory: past
// this many tracked (container, destination) pairs across the whole fleet,
// the tracker resets outright rather than evicting piecemeal (see the type
// doc comment for why a coarse reset is an acceptable bound here, unlike
// the FIFO eviction the engine's and alerter's own state uses).
const maxUnpoliciedTrackedKeys = 50000

// unpoliciedTracker recalls which (container, destination) pairs have
// already been reported in the unpolicied first-seen digest summary (Fork
// 6 / AIRLOCK_UNPOLICIED_DIGEST), so NewSince reports each destination
// once per period, matching the retired suggestStore.PendingDigestSummary
// contract -- but sourced from the engine's own observed-egress recorder
// (internal/engine/observed.go), which carries name evidence the old
// names-less suggestStore never could, instead of a separate store that
// duplicated its bookkeeping.
//
// The engine's own Verdict field does the "unarmed" filtering for free:
// recordObserved only ever writes the verdict "observed" for a connection
// from a container the World did not consider armed at observation time
// (see engine.Engine.evaluateConnection); an armed container always gets a
// real verdict ("allowed" or a violation class), never "observed". This
// matters structurally, not just for convenience: NewSince runs on the
// digest cron's own goroutine, never the daemon's single event-loop
// goroutine that owns World (see world.go's "deliberately NOT safe for
// concurrent access" contract), so a design that needed to ask World
// "is this container armed" here could not do so safely at all.
type unpoliciedTracker struct {
	mu       sync.Mutex
	reported map[string]map[string]bool // containerID -> destKey -> reported
	total    int
}

func newUnpoliciedTracker() *unpoliciedTracker {
	return &unpoliciedTracker{reported: make(map[string]map[string]bool)}
}

// NewSince returns one human-readable line per (container, destination)
// pair in observed carrying the "observed" (unarmed) verdict that this
// tracker has not already reported, then marks them reported. The daemon's
// digest cron calls this once per period (gated by
// cfg.Defaults.UnpoliciedDigest) with d.engine.ObservedSnapshot(), and
// feeds the result to alert.Alerter.FeedUnpoliciedSummary just before
// calling Digest -- the same shape suggestStore.PendingDigestSummary used.
func (t *unpoliciedTracker) NewSince(observed map[string][]engine.ObservedDest) []string {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.total > maxUnpoliciedTrackedKeys {
		// A coarse reset, not piecemeal eviction: this tracker is digest
		// bookkeeping, not a security control, so the worst case of
		// resetting early is a handful of already-reported destinations
		// being reported again once, which is a harmless nuisance.
		t.reported = make(map[string]map[string]bool)
		t.total = 0
	}

	var lines []string
	for id, dests := range observed {
		for _, d := range dests {
			if d.Verdict != "observed" {
				continue
			}
			seen := t.reported[id]
			if seen == nil {
				seen = make(map[string]bool)
				t.reported[id] = seen
			}
			key := observedDestKey(d)
			if seen[key] {
				continue
			}
			seen[key] = true
			t.total++

			label := d.ContainerName
			if label == "" {
				label = id
			}
			dest := d.Name
			if dest == "" {
				dest = d.DstIP.String()
			}
			if d.Port != 0 {
				dest += ":" + strconv.Itoa(int(d.Port))
			}
			lines = append(lines, label+": "+dest+" (first seen "+d.FirstSeen.UTC().Format(time.RFC3339)+")")
		}
	}
	return lines
}

// observedDestKey mirrors the engine's own observedKey (internal, not
// exported) closely enough for this package's dedup purposes: destination
// IP, port, and protocol combined with a "#" separator.
func observedDestKey(d engine.ObservedDest) string {
	return d.DstIP.String() + "#" + strconv.Itoa(int(d.Port)) + "#" + d.Proto
}
