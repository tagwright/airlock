// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import "sync"

// maxViolationTallyContainers bounds the per-container violation tally the
// state-snapshot writer reads, the same FIFO-eviction discipline the
// engine's own recorders and internal/alert's own state use: a full scan
// for the single oldest entry is cheap at this size.
const maxViolationTallyContainers = 4000

// violationTally counts every classified engine.Violation the daemon has
// routed to the alerter, per container, by class string ("deny",
// "no-match", "unresolved-ip"). It exists purely for `airlock status`'s
// "violations by class" column: unlike alert.Alerter's own identity-keyed
// dedup state (which is keyed by service, not container, since replicas
// share dedup by design), a Violation always carries its own container id,
// so this small daemon-owned tally is the natural place to answer "how
// many of each class has THIS container produced," counting every
// classified connection regardless of whether the alerter went on to
// suppress it as a within-window repeat (see alert.Alerter.SuppressedByService
// for that complementary view).
//
// Fed only from handleObserveEvent, the daemon's single event-loop
// goroutine; read from the state-snapshot writer's own timer goroutine via
// Snapshot. Carries its own mutex for exactly that cross-goroutine reason.
type violationTally struct {
	mu    sync.Mutex
	byID  map[string]map[string]int
	order map[string]int
	seq   int
}

func newViolationTally() *violationTally {
	return &violationTally{
		byID:  make(map[string]map[string]int),
		order: make(map[string]int),
	}
}

// Record notes one classified violation for containerID.
func (t *violationTally) Record(containerID, class string) {
	if containerID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	m, ok := t.byID[containerID]
	if !ok {
		if len(t.byID) >= maxViolationTallyContainers {
			t.evictOldestLocked()
		}
		m = make(map[string]int)
		t.byID[containerID] = m
		t.order[containerID] = t.seq
		t.seq++
	}
	m[class]++
}

// Snapshot returns a deep copy of every container's tally, keyed by
// container id then class. Safe to call from any goroutine.
func (t *violationTally) Snapshot() map[string]map[string]int {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make(map[string]map[string]int, len(t.byID))
	for id, m := range t.byID {
		cp := make(map[string]int, len(m))
		for k, v := range m {
			cp[k] = v
		}
		out[id] = cp
	}
	return out
}

// evictOldestLocked drops the container tally with the smallest insertion
// order. Caller must hold t.mu and know len(t.byID) is at capacity.
func (t *violationTally) evictOldestLocked() {
	var oldestKey string
	oldest := -1
	for k, o := range t.order {
		if oldest == -1 || o < oldest {
			oldest = o
			oldestKey = k
		}
	}
	if oldest != -1 {
		delete(t.byID, oldestKey)
		delete(t.order, oldestKey)
	}
}
