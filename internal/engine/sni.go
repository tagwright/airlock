// SPDX-License-Identifier: GPL-3.0-or-later

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
// name falls within sniWindow of it. Ties (equal distance) favor the
// most recently recorded observation.
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
	return s.recent[best].name, true
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
