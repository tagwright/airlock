// SPDX-License-Identifier: GPL-3.0-or-later

package observe

import "context"

// Backend observes container egress activity and streams normalized Event
// values until ctx is cancelled. Implementations own their own
// supervision: if an underlying source (a subprocess, a connection, etc.)
// crashes, the Backend restarts it internally, with backoff, rather than
// tearing down the whole stream. Callers only see a continuous Event
// stream and periodic Stat updates; a crashed-and-restarted source is not
// itself an error.
//
// A Backend implementation must not leak any backend-specific type through
// this interface or through Event/Stat -- that is what lets a second
// backend (for example a future Rust/aya-based probe, run behind its own
// process boundary) be added later as a second implementation of this
// exact interface, with airlock's correlation and policy layers unchanged.
type Backend interface {
	// Name identifies the backend for logging, e.g. "inspektor-gadget".
	Name() string

	// Run starts observing and returns three channels:
	//
	//   - events carries normalized observations as they occur.
	//   - stats carries health/loss signals (see Stat) as they occur.
	//   - errs carries at most one terminal error and is then closed. A
	//     Backend that runs until ctx is cancelled without encountering a
	//     fatal condition closes errs without ever sending on it.
	//
	// All three channels are closed once Run's internal work has fully
	// stopped, which happens promptly after ctx is cancelled. Run itself
	// does not block; it starts its supervision goroutines and returns.
	Run(ctx context.Context) (events <-chan Event, stats <-chan Stat, errs <-chan error)
}
