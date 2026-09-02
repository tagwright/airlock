// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package cli

import (
	"fmt"
	"time"

	"github.com/tagwright/airlock/internal/daemon"
)

// loadSnapshot reads the state file at path via daemon.LoadStateSnapshot
// and returns it alongside its age (time.Since(snap.GeneratedAt)), for
// status and suggest to share. A missing or unparsable file is returned as
// a plain error naming path, so both commands can render the same "is the
// daemon running?" guidance.
func loadSnapshot(path string) (*daemon.StateSnapshot, time.Duration, error) {
	snap, err := daemon.LoadStateSnapshot(path)
	if err != nil {
		return nil, 0, fmt.Errorf("read state snapshot %s: %w", path, err)
	}
	return snap, time.Since(snap.GeneratedAt), nil
}

// noSnapshotHelp renders the "no snapshot available" guidance shared by
// status and suggest.
func noSnapshotHelp(path string, err error) string {
	return fmt.Sprintf(
		"state snapshot unavailable at %s: %v\nIs the airlock daemon running? It writes this file every %s (AIRLOCK_STATE_INTERVAL).\n",
		path, err, daemon.DefaultStateInterval)
}

// staleWarning returns a warning line when age exceeds
// daemon.StateStaleAfter, or "" when the snapshot is fresh enough to trust.
func staleWarning(age time.Duration) string {
	if age <= daemon.StateStaleAfter {
		return ""
	}
	return fmt.Sprintf("WARNING: state snapshot is %s old (stale after %s) -- the daemon may be stuck or stopped.\n",
		age.Round(time.Second), daemon.StateStaleAfter)
}
