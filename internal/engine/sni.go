// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package engine

import "time"

const (
	// sniWindow is how far apart in time an SNI observation and a
	// Connection observation for the same container may be and still be
	// treated as the same underlying connection, since trace_sni carries
	// no destination IP/4-tuple to join on directly (the honesty
	// section). The frozen doc says "recency" without a number; this
	// value is a judgment call flagged in the implementation report,
	// chosen short enough that it is very unlikely to span two unrelated
	// connections from a moderately busy container, and long enough to
	// cover a normal TCP-connect-then-TLS-handshake gap.
	sniWindow = 5 * time.Second

	// sniCapPerContainer bounds how many recent SNI observations one
	// container's store remembers at once, the same hostile-flood
	// defense rationale as the DNS cache: a container rapidly opening
	// many TLS connections cannot make its own store grow without
	// bound. Entries are also pruned by sniWindow on every read and
	// write, so this cap is a backstop, not the primary bound.
	sniCapPerContainer = 32
)

// sniRecord is one observed TLS ClientHello SNI name and when it was seen.
type sniRecord struct {
	name string
	at   time.Time
}

// sniStore is one container's recent-SNI window: trace_sni gives a server
// name but not necessarily a destination IP, so correlation to a
// Connection event is by same-container plus temporal proximity rather
// than by 4-tuple (the honesty section, restated in the frozen doc's
// "Settled" list). It is not safe for concurrent use on its own; the
// owning Engine's mutex serializes all access.
type sniStore struct {
	recent []sniRecord
}

// record notes an observed SNI name at time at, pruning anything already
// outside sniWindow and enforcing the size cap.
func (s *sniStore) record(name string, at time.Time) {
	s.prune(at)
	s.recent = append(s.recent, sniRecord{name: name, at: at})
	if len(s.recent) > sniCapPerContainer {
		s.recent = s.recent[len(s.recent)-sniCapPerContainer:]
	}
}

// lookup returns the SNI name temporally closest to now, if any recorded
// name falls within sniWindow of it, and CONSUMES that record (removes it
// from s.recent) so it can never be returned to a second, later lookup.
// Ties (equal distance) favor the most recently recorded observation.
//
// BUG FIX (integration pass 2): consuming on lookup closes a residual
// misattribution risk from the same root cause docs/TESTING.md's
// "RESOLVED: SNI correlation could misattribute across close-together
// connections" section already fixed for MATCHING (fail-closed on SNI
// removed it from matchEntry entirely) but not for the no-match/
// unresolved-ip CLASSIFICATION step in engine.go's evaluateConnection,
// which still reads sniOK from this same store purely to decide how
// alarming a default-deny-floor violation reads. Confirmed live by this
// pass's regression re-run of run-detect.sh, fired with no deliberate
// spacing between connections (the 8s workaround this suite used to
// dodge exactly this class of bug is gone): the example.com connection's
// real SNI observation was still the temporally-closest entry in the
// store when the VERY NEXT connection (the bare-IP 1.1.1.1 one, which
// sends no SNI at all) was evaluated moments later -- misattributing
// someone else's SNI to it and silently downgrading it from
// unresolved-ip (the frozen doc's named exfiltration shape) to the
// less-alarming no-match. Non-destructive lookup let the SAME
// observation satisfy an unbounded number of later connections within
// its window; consuming it bounds that to exactly one.
func (s *sniStore) lookup(now time.Time) (string, bool) {
	s.prune(now)
	best := -1
	var bestDiff time.Duration
	for i, r := range s.recent {
		diff := now.Sub(r.at)
		if diff < 0 {
			diff = -diff
		}
		if diff > sniWindow {
			continue
		}
		if best < 0 || diff <= bestDiff {
			best = i
			bestDiff = diff
		}
	}
	if best < 0 {
		return "", false
	}
	name := s.recent[best].name
	s.recent = append(s.recent[:best], s.recent[best+1:]...)
	return name, true
}

// prune drops every observation more than sniWindow away from now in
// either direction, so the store never carries stale entries indefinitely
// between events.
func (s *sniStore) prune(now time.Time) {
	if len(s.recent) == 0 {
		return
	}
	kept := s.recent[:0]
	for _, r := range s.recent {
		diff := now.Sub(r.at)
		if diff < 0 {
			diff = -diff
		}
		if diff <= sniWindow {
			kept = append(kept, r)
		}
	}
	s.recent = kept
}
