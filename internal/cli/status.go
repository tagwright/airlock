// SPDX-License-Identifier: GPL-3.0-or-later

package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tagwright/airlock/internal/daemon"
)

// newStatusCmd builds "airlock status": a read-only summary of the
// daemon's most recently written state snapshot (internal/daemon/state.go)
// -- backend health, and every armed container's mode, scope, matched
// groups, and violation counts. It never talks to a running daemon
// directly (there is no IPC server in this architecture); a missing or
// stale snapshot is reported plainly rather than treated as an error the
// caller must debug.
func newStatusCmd() *cobra.Command {
	var statePath string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the daemon's backend health and armed-container policy status",
		Long: `status reads the daemon's periodically written state snapshot file and
prints backend health (is the observation backend restarting, dropping
events, or has it gone quiet) plus every currently armed container's mode,
scope, matched airlock.yml groups, and violation counts.

It is entirely offline: it reads a file, nothing more. The snapshot can be
up to AIRLOCK_STATE_INTERVAL (default 5s) stale relative to the running
daemon.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()

			snap, age, err := loadSnapshot(statePath)
			if err != nil {
				fmt.Fprint(out, noSnapshotHelp(statePath, err))
				return errNoSnapshot
			}
			if w := staleWarning(age); w != "" {
				fmt.Fprint(out, w)
			}

			fmt.Fprintf(out, "airlock %s  (snapshot age: %s, path: %s)\n", snap.Version, age.Round(time.Second), statePath)

			b := snap.Backend
			flowing := "no"
			if b.EventsFlowing {
				flowing = "yes"
			}
			fmt.Fprintf(out, "backend: %s  events_flowing: %s  restarts: %d  dropped_events: %d\n",
				b.Name, flowing, b.Restarts, b.DroppedEvents)
			if !b.LastEventAt.IsZero() {
				fmt.Fprintf(out, "  last event: %s ago\n", time.Since(b.LastEventAt).Round(time.Second))
			}
			if !b.LastRestartAt.IsZero() {
				fmt.Fprintf(out, "  last restart: %s ago\n", time.Since(b.LastRestartAt).Round(time.Second))
			}

			fmt.Fprintf(out, "\narmed containers: %d\n", len(snap.Containers))
			containers := append([]daemon.ArmedContainer(nil), snap.Containers...)
			sort.Slice(containers, func(i, j int) bool { return containers[i].Name < containers[j].Name })
			for _, c := range containers {
				fmt.Fprintf(out, "  - %s (%s)  service=%s  mode=%s  scope=%s", c.Name, shortID(c.ID), c.Service, c.Mode, c.Scope)
				if len(c.MatchedGroups) > 0 {
					fmt.Fprintf(out, "  groups=%s", strings.Join(c.MatchedGroups, ","))
				}
				fmt.Fprintln(out)
				if len(c.ViolationsByClass) > 0 || c.Suppressed > 0 {
					fmt.Fprintf(out, "      violations: %s  suppressed: %d\n", formatClassCounts(c.ViolationsByClass), c.Suppressed)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&statePath, "state", daemon.StatePath(), "path to the daemon's state snapshot file")
	return cmd
}

// errNoSnapshot drives status's nonzero exit when the snapshot cannot be
// read, without Cobra reprinting usage (SilenceUsage is set on the root).
var errNoSnapshot = fmt.Errorf("state snapshot unavailable")

// formatClassCounts renders a violation-class tally as a stable,
// comma-joined "class=count" list, sorted by class name so output is
// deterministic across runs.
func formatClassCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return "none"
	}
	classes := make([]string, 0, len(counts))
	for c := range counts {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	parts := make([]string, 0, len(classes))
	for _, c := range classes {
		parts = append(parts, fmt.Sprintf("%s=%d", c, counts[c]))
	}
	return strings.Join(parts, ", ")
}
