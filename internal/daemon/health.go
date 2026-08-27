// SPDX-License-Identifier: GPL-3.0-or-later

package daemon

import (
	"sync"
	"time"

	"github.com/tagwright/airlock/internal/observe"
)

// eventsFlowingWindow is how recently an event must have been recorded for
// Snapshot to report EventsFlowing true. JUDGMENT CALL: not specified by
// the frozen doc or this chunk's brief; a low-traffic but healthy fleet can
// legitimately go a while between observed connections, so this is
// deliberately generous relative to DefaultStateInterval rather than tuned
// to it -- it is meant to catch a genuinely dead backend, not to flag an
// idle one.
const eventsFlowingWindow = 2 * time.Minute

// backendHealthTracker is the daemon's own read-side for `airlock
// status`'s backend-health section: the observation backend's name, the
// last time any event was actually seen flowing through it, and the
// latest observe.Stat it reported (restarts, dropped events). It exists
// because Run's handleObserveEvent/handleStat run on the single event-loop
// goroutine while the state-snapshot writer (state.go) reads this from its
// own timer goroutine -- unlike world (single-goroutine-only by design,
// see world.go's type doc comment), this small amount of state genuinely
// needs to cross that boundary safely, so it carries its own mutex.
type backendHealthTracker struct {
	name string

	mu            sync.Mutex
	lastEventAt   time.Time
	restarts      uint64
	lastRestartAt time.Time
	droppedEvents uint64
}

func newBackendHealthTracker(name string) *backendHealthTracker {
	return &backendHealthTracker{name: name}
}

// RecordEvent notes that an observe.Event was just processed, at
// wall-clock time now (not the event's own possibly-buffered Timestamp):
// "events flowing" is a liveness question about the pipe into this
// process, not about the backend's own clock.
func (h *backendHealthTracker) RecordEvent(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lastEventAt = now
}

// RecordStat folds in the latest observe.Stat. Restarts and DroppedEvents
// are both cumulative counters per Stat's own doc comment ("since the
// backend started"), so the latest reported value simply replaces the
// stored one; a rise in Restarts also stamps lastRestartAt at now, since
// Stat itself carries no "when did this restart happen" field of its own
// beyond its own Time (the backend's clock, not necessarily comparable to
// this process's).
func (h *backendHealthTracker) RecordStat(st observe.Stat) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if st.Restarts > h.restarts {
		h.lastRestartAt = time.Now()
	}
	h.restarts = st.Restarts
	if st.DroppedEvents > h.droppedEvents {
		h.droppedEvents = st.DroppedEvents
	}
}

// Snapshot returns the current BackendHealth for the state-snapshot writer.
// Safe to call from any goroutine.
func (h *backendHealthTracker) Snapshot() BackendHealth {
	h.mu.Lock()
	defer h.mu.Unlock()
	return BackendHealth{
		Name:          h.name,
		EventsFlowing: !h.lastEventAt.IsZero() && time.Since(h.lastEventAt) < eventsFlowingWindow,
		LastEventAt:   h.lastEventAt,
		Restarts:      h.restarts,
		LastRestartAt: h.lastRestartAt,
		DroppedEvents: h.droppedEvents,
	}
}
