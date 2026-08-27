// SPDX-License-Identifier: GPL-3.0-or-later

package daemon

import (
	"strconv"
	"sync"
	"time"
)

// Bounds on suggestStore's memory, the same FIFO-eviction discipline
// internal/alert uses for its own hostile-flood backstops: a full scan to
// find the single oldest entry is cheap at these sizes, and the real
// defense against an unbounded flood of distinct containers or
// destinations is that this store only ever records connections from
// UNARMED containers in the first place (an armed container's traffic is
// the engine's job, not this one's).
const (
	maxSuggestContainers        = 2000
	maxDestinationsPerContainer = 500
)

// suggestion is one destination observed from an unarmed container,
// exported as Suggestion via Snapshot/ContainerSnapshot for a future
// `airlock suggest` CLI (or any other in-process reader) to render as a
// candidate allow entry.
type Suggestion struct {
	ContainerID   string
	ContainerName string
	Destination   string // the raw destination IP, in v1 (see suggestStore's doc comment)
	Port          uint16
	Count         int
	FirstSeen     time.Time
	LastSeen      time.Time
}

// destObservation is one destination's bookkeeping within one container's
// entry.
type destObservation struct {
	order       int
	destination string
	port        uint16
	count       int
	firstSeen   time.Time
	lastSeen    time.Time
	// pending marks a destination not yet included in an unpolicied-
	// digest summary line. Set on first observation, cleared by
	// PendingDigestSummary.
	pending bool
}

// containerEntry is one unarmed container's observed-destinations record.
type containerEntry struct {
	order         int
	containerName string
	destinations  map[string]*destObservation
	destSeq       int
}

// suggestStore is a bounded, in-memory recorder of destinations observed
// from containers with no armed policy at all: the raw material for the
// unpolicied-first-seen digest summary (Fork 6) and for a future `airlock
// suggest` command that renders a starter allowlist from what a container
// has actually been seen reaching.
//
// SEAM, not a finished feature: this store only ever sees what the daemon
// itself observes while it is running, keyed by the raw destination IP
// (the engine's own DNS/SNI correlation caches are private to
// internal/engine and not surfaced through any exported API a second
// package could read, so this store cannot currently enrich a recorded
// destination with the name evidence a human would actually want on a
// suggested allow line). It also has no wire format or IPC of its own: a
// `airlock suggest` command running as a SEPARATE process from the daemon
// cannot reach this store's memory at all. Exposing it usefully to a
// separate CLI invocation (a control socket, a status endpoint, a
// snapshot file) is left for the CLI chunk to design, since it is a
// transport decision, not a bookkeeping one; Snapshot/ContainerSnapshot
// below are what an in-process reader (or a future HTTP/socket handler
// built on top of this same struct) would call.
//
// Safe for concurrent use: Record is called from the daemon's single
// event-loop goroutine, PendingDigestSummary from the digest cron's own
// goroutine (see internal/alert's concurrency doc comment for the
// identical split on the alerter side), and a future status reader could
// call Snapshot from yet a third goroutine. All three are real
// possibilities here, unlike world's single-goroutine-only contract, so
// this type carries its own mutex.
type suggestStore struct {
	mu         sync.Mutex
	containers map[string]*containerEntry
	seq        int
}

// newSuggestStore returns an empty suggestStore.
func newSuggestStore() *suggestStore {
	return &suggestStore{containers: make(map[string]*containerEntry)}
}

// Record notes one observed destination for containerID, an unarmed or
// unknown container. when is normally the observed Connection event's own
// timestamp.
func (s *suggestStore) Record(containerID, containerName, destination string, port uint16, when time.Time) {
	if containerID == "" || destination == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.containers[containerID]
	if !ok {
		if len(s.containers) >= maxSuggestContainers {
			s.evictOldestContainerLocked()
		}
		c = &containerEntry{order: s.seq, destinations: make(map[string]*destObservation)}
		s.seq++
		s.containers[containerID] = c
	}
	if containerName != "" {
		c.containerName = containerName
	}

	key := destinationKey(destination, port)
	d, ok := c.destinations[key]
	if !ok {
		if len(c.destinations) >= maxDestinationsPerContainer {
			evictOldestDestinationLocked(c)
		}
		d = &destObservation{order: c.destSeq, destination: destination, port: port, firstSeen: when, pending: true}
		c.destSeq++
		c.destinations[key] = d
	}
	d.count++
	d.lastSeen = when
}

// destinationKey combines destination and port into suggestStore's
// per-container map key, since the same destination on two different
// ports is two distinct observations worth suggesting separately. A
// literal "#" separator (never valid inside a bare IP or a port number)
// keeps this unambiguous regardless of what destination itself contains,
// unlike a ":"-joined key, which an IPv6 destination could collide with.
func destinationKey(destination string, port uint16) string {
	return destination + "#" + strconv.Itoa(int(port))
}

// Snapshot returns every currently recorded suggestion across every
// container, for a future `airlock suggest --all` or status view.
func (s *suggestStore) Snapshot() []Suggestion {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Suggestion
	for id, c := range s.containers {
		out = append(out, snapshotContainerLocked(id, c)...)
	}
	return out
}

// ContainerSnapshot returns every currently recorded suggestion for one
// container, for a future `airlock suggest <container>`.
func (s *suggestStore) ContainerSnapshot(containerID string) []Suggestion {
	s.mu.Lock()
	defer s.mu.Unlock()

	c, ok := s.containers[containerID]
	if !ok {
		return nil
	}
	return snapshotContainerLocked(containerID, c)
}

func snapshotContainerLocked(containerID string, c *containerEntry) []Suggestion {
	out := make([]Suggestion, 0, len(c.destinations))
	for _, d := range c.destinations {
		out = append(out, Suggestion{
			ContainerID:   containerID,
			ContainerName: c.containerName,
			Destination:   d.destination,
			Port:          d.port,
			Count:         d.count,
			FirstSeen:     d.firstSeen,
			LastSeen:      d.lastSeen,
		})
	}
	return out
}

// PendingDigestSummary returns one human-readable line per destination
// observed since the last call to this method, across every unarmed
// container, then clears every entry's pending flag. The daemon's digest
// cron calls this once per period (gated by
// cfg.Defaults.UnpoliciedDigest) and feeds the result to
// alert.Alerter.FeedUnpoliciedSummary just before calling Digest.
//
// JUDGMENT CALL: the frozen doc's config comment calls this a
// "first-seen-destination-per-day" summary, but this store has no
// calendar-day concept of its own -- it only knows "new since the last
// time this was called." With the default digest schedule (once daily at
// midnight), those coincide exactly; a fleet that reconfigures
// AIRLOCK_DIGEST_SCHEDULE to fire more or less often gets "new since the
// last digest" instead, which is the more useful reading of "first-seen"
// for an operator anyway (a destination is never reported twice).
func (s *suggestStore) PendingDigestSummary() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var lines []string
	for id, c := range s.containers {
		label := c.containerName
		if label == "" {
			label = id
		}
		for _, d := range c.destinations {
			if !d.pending {
				continue
			}
			d.pending = false
			dest := d.destination
			if d.port != 0 {
				dest += ":" + strconv.Itoa(int(d.port))
			}
			lines = append(lines, label+": "+dest+" (first seen "+d.firstSeen.UTC().Format(time.RFC3339)+")")
		}
	}
	return lines
}

// evictOldestContainerLocked drops the container entry with the smallest
// insertion order. Caller must hold s.mu and know len(s.containers) is at
// capacity.
func (s *suggestStore) evictOldestContainerLocked() {
	var oldestKey string
	oldest := -1
	for k, c := range s.containers {
		if oldest == -1 || c.order < oldest {
			oldest = c.order
			oldestKey = k
		}
	}
	if oldest != -1 {
		delete(s.containers, oldestKey)
	}
}

// evictOldestDestinationLocked drops c's destination entry with the
// smallest insertion order. Caller must hold the store's mu and know
// len(c.destinations) is at capacity.
func evictOldestDestinationLocked(c *containerEntry) {
	var oldestKey string
	oldest := -1
	for k, d := range c.destinations {
		if oldest == -1 || d.order < oldest {
			oldest = d.order
			oldestKey = k
		}
	}
	if oldest != -1 {
		delete(c.destinations, oldestKey)
	}
}
