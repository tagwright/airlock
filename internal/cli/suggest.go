// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package cli

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/tagwright/airlock/internal/daemon"
)

// newSuggestCmd builds "airlock suggest <container>": the audit-onramp
// command the frozen "Airlock Label Grammar (Draft)" describes under Fork
// 2 -- observe in audit mode, run suggest, prune, paste, flip to alert.
// It reads the daemon's state snapshot (internal/daemon/state.go) for the
// named container's observed-egress data and renders it as paste-ready
// allow entries.
//
// DESIGN DECISION (flagged per this chunk's brief): suggest shows EVERY
// in-scope observed destination for the container, regardless of the
// Verdict the engine recorded for it at observation time (allowed, a
// specific violation class, or "observed" for an unarmed container). The
// point of suggest is building the FIRST allowlist, and an operator
// running audit mode wants to see everything their container actually
// reached so they can prune what does not belong -- filtering to only
// "would-be-violation" destinations would silently hide a destination
// that happened to match something already in a partial allowlist (a
// policy set, an @self entry), which is exactly the kind of "why isn't
// this here" surprise this command should never produce. Verdict is
// still shown per line so the operator can tell which destinations were
// already covered.
func newSuggestCmd() *cobra.Command {
	var statePath string
	var yamlOut bool

	cmd := &cobra.Command{
		Use:   "suggest <container>",
		Short: "Render a container's observed egress as ready-to-paste allow entries",
		Long: `suggest reads the daemon's state snapshot and renders every distinct
in-scope destination observed from <container> (matched by name or id) as
a ready-to-paste airlock.allow value: "name:port" when the engine had a
DNS-cache-correlated name for that destination, else "ip:port". A name
rule only matches again if pasted back in when it came from DNS
correlation (fail-closed matching never consults SNI, see the engine's
package doc comment), so an observed SNI name is never rendered as a
suggested entry's domain -- it is shown only as an informational aside on
the ip:port line it accompanies, when there is one. Entries with no
DNS-correlated name are called out separately so the operator can review
them before trusting them -- see the frozen grammar's honesty section on
the unresolved-ip shape.

The onboarding workflow this command is built for: set airlock.enable=true
and airlock.mode=audit with an empty or partial allowlist, let it run for a
representative period, run suggest, prune what does not belong, paste the
result into airlock.allow (or an airlock.yml policy set with --yaml), then
delete the mode label to move the container onto default-deny alert mode.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			target := args[0]

			snap, age, err := loadSnapshot(statePath)
			if err != nil {
				fmt.Fprint(out, noSnapshotHelp(statePath, err))
				return errNoSnapshot
			}
			if w := staleWarning(age); w != "" {
				fmt.Fprint(out, w)
			}

			sc := findSuggestContainer(snap.Suggestions, target)
			if sc == nil {
				fmt.Fprintf(out, "no observed egress recorded for %q in the state snapshot (age %s, path %s).\n",
					target, age.Round(time.Second), statePath)
				fmt.Fprintln(out, "Is the container name/id correct, and has it made any egress connections since the daemon started?")
				return errNoObservations
			}

			entries := renderSuggestEntries(sc.Destinations)
			if len(entries) == 0 {
				fmt.Fprintf(out, "%s (%s): no in-scope destinations observed yet.\n", sc.Name, shortID(sc.ID))
				return nil
			}

			fmt.Fprintf(out, "# airlock suggest %s -- %s (%s), %d destination(s) observed, snapshot age %s\n",
				target, sc.Name, shortID(sc.ID), len(sc.Destinations), age.Round(time.Second))
			fmt.Fprintln(out, "#")
			for _, e := range entries {
				note := ""
				if e.ipOnly {
					note = "  # NO NAME EVIDENCE -- review before trusting"
					if e.sniName != "" {
						note += fmt.Sprintf(" (observed SNI %q, not usable as a name rule under fail-closed matching)", e.sniName)
					}
				}
				fmt.Fprintf(out, "# %-40s %5d conn, last seen %s, verdict=%s%s\n",
					e.text, e.count, e.lastSeen.UTC().Format(time.RFC3339), e.verdict, note)
			}
			fmt.Fprintln(out, "#")

			csv := make([]string, len(entries))
			for i, e := range entries {
				csv[i] = e.text
			}
			fmt.Fprintf(out, "airlock.allow: %q\n", strings.Join(csv, ","))

			if yamlOut {
				fmt.Fprintln(out)
				fmt.Fprintln(out, "# airlock.yml policy-set block:")
				fmt.Fprintf(out, "policies:\n  %s-suggested:\n    allow:\n", sanitizeSetName(sc.Name))
				for _, e := range entries {
					fmt.Fprintf(out, "      - %q\n", e.text)
				}
			}

			var ipOnly []string
			for _, e := range entries {
				if e.ipOnly {
					ipOnly = append(ipOnly, e.text)
				}
			}
			if len(ipOnly) > 0 {
				fmt.Fprintln(out)
				fmt.Fprintf(out, "# %d entry(ies) above have no DNS-correlated name (an observed SNI, shown above when there is one, is informational only and never usable as a name rule under fail-closed matching): %s\n",
					len(ipOnly), strings.Join(ipOnly, ", "))
				fmt.Fprintln(out, "# Review each one before trusting it -- see the frozen grammar's unresolved-ip honesty section.")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&statePath, "state", daemon.StatePath(), "path to the daemon's state snapshot file")
	cmd.Flags().BoolVar(&yamlOut, "yaml", false, "also render an airlock.yml policy-set block")
	return cmd
}

// errNoObservations drives suggest's nonzero exit when the named
// container has no recorded observations, without Cobra reprinting usage.
var errNoObservations = fmt.Errorf("no observations recorded for container")

// findSuggestContainer matches target against a SuggestContainer's id
// (exact, or as a prefix -- the conventional short-id match) or name.
func findSuggestContainer(containers []daemon.SuggestContainer, target string) *daemon.SuggestContainer {
	for i := range containers {
		c := &containers[i]
		if c.Name == target || c.ID == target || strings.HasPrefix(c.ID, target) {
			return c
		}
	}
	return nil
}

// suggestEntry is one rendered, deduplicated allow-entry candidate.
type suggestEntry struct {
	text   string // "name:port" or "ip:port" (IPv6 bracketed), the paste-ready form
	ipOnly bool

	// sniName is the observed SNI name for this destination, if any,
	// carried purely as an informational aside for an ipOnly entry's
	// review note -- see daemon.SuggestDest.SNIName's doc comment. Never
	// part of text: an SNI-only name would never match again under
	// fail-closed matching if pasted back in as a domain rule.
	sniName string

	count    int
	lastSeen time.Time
	verdict  string
}

// renderSuggestEntries converts observed destinations into deduplicated,
// sorted suggestEntry values. Two destinations that render to the same
// text (e.g. two connections to the same name on the same port, observed
// under slightly different Proto casing) are merged: counts sum, and
// lastSeen/verdict take the most recently seen of the two. host is always
// d.Name (the DNS-cache-correlated name) or, when that is empty, the raw
// IP -- never d.SNIName, since only a DNS-correlated name is guaranteed to
// match again under fail-closed matching if pasted back in as a rule; see
// engine.ObservedDest.Name's doc comment.
func renderSuggestEntries(dests []daemon.SuggestDest) []suggestEntry {
	byText := make(map[string]*suggestEntry)
	var order []string

	for _, d := range dests {
		host := d.Name
		ipOnly := host == ""
		if ipOnly {
			host = d.IP
		}

		text := host
		if d.Port != 0 {
			if strings.Contains(host, ":") {
				// A domain name never contains a colon, so this is
				// reliably an IPv6 literal -- the grammar requires
				// brackets around one when a port follows.
				text = fmt.Sprintf("[%s]:%d", host, d.Port)
			} else {
				text = fmt.Sprintf("%s:%d", host, d.Port)
			}
		}

		e, ok := byText[text]
		if !ok {
			e = &suggestEntry{text: text, ipOnly: ipOnly}
			byText[text] = e
			order = append(order, text)
		}
		e.count += d.Count
		if d.SNIName != "" {
			e.sniName = d.SNIName
		}
		if d.LastSeen.After(e.lastSeen) {
			e.lastSeen = d.LastSeen
			e.verdict = d.Verdict
		}
	}

	out := make([]suggestEntry, 0, len(order))
	for _, text := range order {
		out = append(out, *byText[text])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].text < out[j].text })
	return out
}

// sanitizeSetName lowercases and replaces anything but letters, digits,
// and hyphens with a hyphen, per the frozen grammar's policy-set
// identifier rule (lowercase, no commas -- "the ballast destination-name
// rule"), so a rendered --yaml block's set name is always a legal
// reference even when the container's own service name is not.
func sanitizeSetName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	if b.Len() == 0 {
		return "suggested"
	}
	return b.String()
}
