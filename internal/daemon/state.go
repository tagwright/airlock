// SPDX-License-Identifier: GPL-3.0-or-later

package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/tagwright/airlock/internal/version"
)

// DESIGN: status and suggest use a file snapshot, not an IPC server. The
// daemon periodically writes an atomic state-snapshot file; a separate
// `airlock status`/`airlock suggest` process reads it. This keeps the CLI
// a plain, offline-capable binary (no socket dialing, no protocol
// versioning against a live daemon) at the cost of the CLI seeing a value
// up to DefaultStateInterval stale, which is a fine trade for a status
// surface that is a debugging aid, not a control plane.
const (
	// DefaultStatePath is where the daemon writes, and `airlock
	// status`/`airlock suggest` read by default, the JSON state snapshot.
	// AIRLOCK_STATE_PATH overrides it on either side, so a non-default
	// deployment layout only needs to set the env var once for both.
	DefaultStatePath = "/run/airlock/state.json"

	// DefaultStateInterval is how often the daemon refreshes the state
	// snapshot file. AIRLOCK_STATE_INTERVAL (a Go duration string)
	// overrides it.
	DefaultStateInterval = 5 * time.Second

	// StateStaleAfter is the age at which `airlock status` warns that the
	// snapshot may no longer reflect a running daemon. JUDGMENT CALL: not
	// specified by the frozen doc or this chunk's brief; four times
	// DefaultStateInterval gives a comfortable margin over ordinary write
	// jitter while still catching a stopped daemon within well under a
	// minute at the default interval.
	StateStaleAfter = 4 * DefaultStateInterval

	// stateSchemaVersion is bumped whenever StateSnapshot's shape changes
	// in a way a reader needs to know about. It exists so a future reader
	// can decide whether to trust an old daemon's snapshot rather than
	// discovering a shape mismatch as a JSON decode error; v1 has exactly
	// one version and no reader-side check yet.
	stateSchemaVersion = 1

	// maxStateContainers and maxStateDestsPerContainer bound the snapshot
	// file's size: only the first N armed containers and the first N
	// suggest containers (sorted by id for determinism), and the first M
	// observed destinations per suggest container, are written. A fleet
	// this large is not the normal case this file format is sized for;
	// status/suggest simply reports a partial picture rather than growing
	// the file without bound.
	maxStateContainers        = 500
	maxStateDestsPerContainer = 200
)

// StateSnapshot is the CLI<->daemon contract: the shape the daemon writes
// to the state file and `airlock status`/`airlock suggest` read back. See
// the package-level DESIGN comment above for why this is a file rather
// than a socket.
type StateSnapshot struct {
	SchemaVersion int       `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Version       string    `json:"version"`

	Backend BackendHealth `json:"backend"`

	// Containers is every currently armed container, sorted by id.
	// Bounded at maxStateContainers.
	Containers []ArmedContainer `json:"containers"`

	// Suggestions is the observed-egress recorder's data for every
	// container the engine has recorded anything for, armed or not:
	// `airlock suggest`'s only data source. Bounded at maxStateContainers
	// containers and maxStateDestsPerContainer destinations each.
	Suggestions []SuggestContainer `json:"suggestions"`
}

// BackendHealth summarizes the observation backend's health for `airlock
// status`.
type BackendHealth struct {
	Name          string    `json:"name"`
	EventsFlowing bool      `json:"events_flowing"`
	LastEventAt   time.Time `json:"last_event_at,omitempty"`
	Restarts      uint64    `json:"restarts"`
	LastRestartAt time.Time `json:"last_restart_at,omitempty"`
	DroppedEvents uint64    `json:"dropped_events"`
}

// ArmedContainer is one armed container's status-worthy state.
type ArmedContainer struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Service string `json:"service"`
	Mode    string `json:"mode"`
	Scope   string `json:"scope"`

	// MatchedGroups names every airlock.yml group whose Match selected
	// this container (resolve.Resolved.MatchedGroups), regardless of
	// whether that group actually won any scalar.
	MatchedGroups []string `json:"matched_groups,omitempty"`

	// ViolationsByClass tallies every classified Violation the engine has
	// produced for this container since the daemon started, keyed by
	// engine.Class.String() ("deny", "no-match", "unresolved-ip"). This
	// counts every classified connection, whether or not it was actually
	// delivered as an immediate alert -- a window-suppressed repeat still
	// counts here. Suppressed below is the complementary alert-volume
	// view.
	ViolationsByClass map[string]int `json:"violations_by_class,omitempty"`

	// Suppressed is the service's current digest-scoped suppressed count
	// (alert.Alerter.SuppressedByService), shared across every replica of
	// this Service name per the frozen doc's identity tuple (dedup keys
	// on service, never on container id).
	Suppressed int `json:"suppressed"`
}

// SuggestContainer is one container's observed-egress recorder data: the
// entire data source for `airlock suggest`.
type SuggestContainer struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Destinations []SuggestDest `json:"destinations"`
}

// SuggestDest is one observed destination, populated straight from
// engine.ObservedDest.
type SuggestDest struct {
	// Name is the DNS-cache-correlated name, or empty when this
	// container's DNS cache holds nothing for this destination. This is
	// the only name evidence the CLI's suggest command may render as a
	// suggested allow entry's domain -- see engine.ObservedDest.Name's doc
	// comment for why: under fail-closed matching, only a DNS-correlated
	// name is guaranteed to match again if pasted back in.
	Name string `json:"name,omitempty"`

	// SNIName is the observed TLS SNI name, if any, carried purely as
	// informational enrichment -- see engine.ObservedDest.SNIName. Never
	// the right value to render as a suggested entry's domain.
	SNIName   string    `json:"sni,omitempty"`
	IP        string    `json:"ip"`
	Port      uint16    `json:"port"`
	Proto     string    `json:"proto"`
	Count     int       `json:"count"`
	Verdict   string    `json:"verdict"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// StatePath resolves the state-snapshot file path: AIRLOCK_STATE_PATH if
// set, otherwise DefaultStatePath. Both the daemon's writer (New, below)
// and the CLI's reader call this, so they agree on a default with nothing
// shared beyond the environment.
func StatePath() string {
	if v := strings.TrimSpace(os.Getenv("AIRLOCK_STATE_PATH")); v != "" {
		return v
	}
	return DefaultStatePath
}

// resolveStateInterval resolves the snapshot refresh cadence:
// AIRLOCK_STATE_INTERVAL (a Go duration string) if set and valid,
// otherwise DefaultStateInterval.
func resolveStateInterval() time.Duration {
	if v := strings.TrimSpace(os.Getenv("AIRLOCK_STATE_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return DefaultStateInterval
}

// LoadStateSnapshot reads and parses the state file at path, for `airlock
// status`/`airlock suggest`. It returns a plain error (missing file,
// malformed JSON) for the caller to render as "no snapshot" / "corrupt
// snapshot" -- a state file is small enough that a successful unmarshal is
// either whole or the read failed outright, so there is no partial-success
// return here.
func LoadStateSnapshot(path string) (*StateSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var snap StateSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parse state snapshot %s: %w", path, err)
	}
	return &snap, nil
}

// runStateWriter refreshes the state snapshot file on d.stateInterval
// until ctx is cancelled, writing once immediately on start so a freshly
// started daemon has a snapshot available right away rather than waiting a
// full interval.
//
// This runs on its OWN goroutine, separate from Run's single event-loop
// goroutine, and touches only thread-safe read-sides: d.engine's
// ObservedSnapshot (engine.go's own mutex), d.alerter's
// SuppressedByService (alert.Alerter's own mutex), d.health's and
// d.violations' Snapshot methods (this package's own mutexes, see
// health.go and tally.go), and d.armedMeta (an atomic.Pointer written once
// per reconcile by the main goroutine and read here with no lock at all).
// It never touches d.world directly -- see world.go's "deliberately NOT
// safe for concurrent access" contract -- and never calls into
// d.engine.Process.
func (d *Daemon) runStateWriter(ctx context.Context) {
	d.writeStateSnapshot()

	ticker := time.NewTicker(d.stateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.writeStateSnapshot()
		}
	}
}

// writeStateSnapshot assembles the current StateSnapshot and writes it
// atomically. A write failure is logged, never fatal to the daemon: a
// missing or stale state file degrades `airlock status`/`airlock
// suggest`, it never degrades egress observation or alerting.
func (d *Daemon) writeStateSnapshot() {
	snap := d.buildStateSnapshot()
	if err := writeStateSnapshotAtomic(d.statePath, snap); err != nil {
		d.logger.Warn("daemon: write state snapshot", "path", d.statePath, "error", err)
	}
}

// buildStateSnapshot is the pure assembly step, split out from
// writeStateSnapshot so it is unit-testable without touching the
// filesystem.
func (d *Daemon) buildStateSnapshot() StateSnapshot {
	suppressed := d.alerter.SuppressedByService()
	tally := d.violations.Snapshot()

	var containers []ArmedContainer
	if meta := d.armedMeta.Load(); meta != nil {
		for _, m := range *meta {
			if len(containers) >= maxStateContainers {
				break
			}
			containers = append(containers, ArmedContainer{
				ID:                m.id,
				Name:              m.name,
				Service:           m.service,
				Mode:              m.mode,
				Scope:             m.scope,
				MatchedGroups:     m.matchedGroups,
				ViolationsByClass: tally[m.id],
				Suppressed:        suppressed[m.service],
			})
		}
	}

	observed := d.engine.ObservedSnapshot()
	ids := make([]string, 0, len(observed))
	for id := range observed {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var suggestions []SuggestContainer
	for _, id := range ids {
		if len(suggestions) >= maxStateContainers {
			break
		}
		dests := observed[id]

		var name string
		out := make([]SuggestDest, 0, len(dests))
		for i, dst := range dests {
			if name == "" {
				name = dst.ContainerName
			}
			if i >= maxStateDestsPerContainer {
				continue
			}
			out = append(out, SuggestDest{
				Name:      dst.Name,
				SNIName:   dst.SNIName,
				IP:        dst.DstIP.String(),
				Port:      dst.Port,
				Proto:     dst.Proto,
				Count:     dst.Count,
				Verdict:   dst.Verdict,
				FirstSeen: dst.FirstSeen,
				LastSeen:  dst.LastSeen,
			})
		}
		suggestions = append(suggestions, SuggestContainer{ID: id, Name: name, Destinations: out})
	}

	return StateSnapshot{
		SchemaVersion: stateSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Version:       version.Version,
		Backend:       d.health.Snapshot(),
		Containers:    containers,
		Suggestions:   suggestions,
	}
}

// writeStateSnapshotAtomic marshals snap and writes it to path via a
// temp-file-plus-rename, so a reader never observes a partially written
// file. It creates path's directory (best-effort) if it does not exist.
func writeStateSnapshotAtomic(path string, snap StateSnapshot) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state snapshot: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".state-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp state file to %s: %w", path, err)
	}
	return nil
}
