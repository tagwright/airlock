// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/daemon"
)

func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := newRootCmd()
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return out.String(), errBuf.String(), err
}

// TestVersion_PrintsVersion proves "airlock version" prints something
// nonempty and exits clean.
func TestVersion_PrintsVersion(t *testing.T) {
	out, _, err := runCLI(t, "version")
	if err != nil {
		t.Fatalf("version: unexpected error %v", err)
	}
	if !strings.Contains(out, "airlock ") {
		t.Errorf("version output = %q, want it to contain \"airlock \"", out)
	}
}

// TestValidate_GoodConfig proves "validate" exits clean and prints OK for
// a config that passes config.Validate.
func TestValidate_GoodConfig(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "airlock.yml")
	if err := os.WriteFile(good, []byte("policies:\n  debian-updates:\n    allow:\n      - \"deb.debian.org:443\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, err := runCLI(t, "validate", "--config", good)
	if err != nil {
		t.Fatalf("validate (good config): unexpected error %v\noutput: %s", err, out)
	}
	if !strings.Contains(out, "config: OK") {
		t.Errorf("validate output = %q, want it to contain \"config: OK\"", out)
	}
}

// TestValidate_BadConfig proves "validate" exits nonzero and reports the
// failure for a config that fails config.Validate.
func TestValidate_BadConfig(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "airlock.yml")
	// An unknown group match dimension combination / bad mode value fails
	// config.Validate's defaults check.
	if err := os.WriteFile(bad, []byte("defaults:\n  default_mode: bogus\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, _, err := runCLI(t, "validate", "--config", bad)
	if err == nil {
		t.Fatalf("validate (bad config): want a nonzero result, got success\noutput: %s", out)
	}
	if !strings.Contains(out, "INVALID") {
		t.Errorf("validate output = %q, want it to contain \"INVALID\"", out)
	}
}

// fixtureSnapshot builds a small, deterministic daemon.StateSnapshot for
// status/suggest rendering tests, and writes it to a temp file. now is a
// fixed generation time so tests can assert on age without racing the
// clock.
func fixtureSnapshot(t *testing.T, now time.Time) string {
	t.Helper()

	snap := daemon.StateSnapshot{
		SchemaVersion: 1,
		GeneratedAt:   now,
		Version:       "00.01.00b1",
		Backend: daemon.BackendHealth{
			Name:          "inspektor-gadget",
			EventsFlowing: true,
			LastEventAt:   now.Add(-time.Second),
			Restarts:      1,
			DroppedEvents: 0,
		},
		Containers: []daemon.ArmedContainer{
			{
				ID:   "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccddddddddddddeeeeeeeeeeeeffff",
				Name: "web", Service: "web", Mode: "alert", Scope: "external",
				MatchedGroups:     []string{"media-stack"},
				ViolationsByClass: map[string]int{"no-match": 2, "unresolved-ip": 1},
				Suppressed:        4,
			},
		},
		Suggestions: []daemon.SuggestContainer{
			{
				ID: "legacy123456", Name: "legacy",
				Destinations: []daemon.SuggestDest{
					{Name: "api.github.com", IP: "140.82.112.3", Port: 443, Proto: "tcp", Count: 12, Verdict: "no-match", FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Minute)},
					{Name: "", IP: "203.0.113.9", Port: 8443, Proto: "tcp", Count: 2, Verdict: "unresolved-ip", FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-2 * time.Minute)},
					// A second, distinct-port observation of the same
					// name to prove suggest keeps distinct ports as
					// distinct entries.
					{Name: "api.github.com", IP: "140.82.112.3", Port: 80, Proto: "tcp", Count: 1, Verdict: "no-match", FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-3 * time.Minute)},
				},
			},
		},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture snapshot: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture snapshot: %v", err)
	}
	return path
}

// TestStatus_RendersArmedContainer proves "status" reads a fixture
// snapshot and renders backend health and the armed container's
// mode/scope/matched-groups/violation summary.
func TestStatus_RendersArmedContainer(t *testing.T) {
	now := time.Now().UTC()
	path := fixtureSnapshot(t, now)

	out, _, err := runCLI(t, "status", "--state", path)
	if err != nil {
		t.Fatalf("status: unexpected error %v\noutput: %s", err, out)
	}

	for _, want := range []string{
		"inspektor-gadget", "events_flowing: yes", "restarts: 1",
		"web (aaaaaaaaaaaa)", "service=web", "mode=alert", "scope=external",
		"groups=media-stack",
		"no-match=2", "unresolved-ip=1", "suppressed: 4",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q\n---\n%s", want, out)
		}
	}
}

// TestStatus_MissingSnapshot proves "status" reports a clear message and a
// nonzero result when the snapshot file does not exist.
func TestStatus_MissingSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.json")
	out, _, err := runCLI(t, "status", "--state", path)
	if err == nil {
		t.Fatalf("status (missing snapshot): want a nonzero result, got success\noutput: %s", out)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("status output = %q, want it to explain the snapshot is unavailable", out)
	}
}

// TestSuggest_RendersNameAndIPOnlyEntries proves suggest renders a
// name:port entry for a destination with name evidence, an ip:port entry
// (flagged separately) for one without, dedups/sorts, and keeps distinct
// ports on the same name as distinct entries.
func TestSuggest_RendersNameAndIPOnlyEntries(t *testing.T) {
	now := time.Now().UTC()
	path := fixtureSnapshot(t, now)

	out, _, err := runCLI(t, "suggest", "legacy", "--state", path)
	if err != nil {
		t.Fatalf("suggest: unexpected error %v\noutput: %s", err, out)
	}

	if !strings.Contains(out, `airlock.allow: "203.0.113.9:8443,api.github.com:443,api.github.com:80"`) {
		t.Errorf("suggest csv line wrong, got:\n%s", out)
	}
	if !strings.Contains(out, "NO NAME EVIDENCE") {
		t.Errorf("suggest output missing the IP-only review note:\n%s", out)
	}
	if !strings.Contains(out, "203.0.113.9:8443") {
		t.Errorf("suggest output missing the ip-only entry in its own note:\n%s", out)
	}
}

// TestSuggest_YAMLBlock proves --yaml additionally renders an airlock.yml
// policy-set block containing the same entries.
func TestSuggest_YAMLBlock(t *testing.T) {
	now := time.Now().UTC()
	path := fixtureSnapshot(t, now)

	out, _, err := runCLI(t, "suggest", "legacy", "--state", path, "--yaml")
	if err != nil {
		t.Fatalf("suggest --yaml: unexpected error %v\noutput: %s", err, out)
	}
	for _, want := range []string{"policies:", "legacy-suggested:", "allow:", `"api.github.com:443"`} {
		if !strings.Contains(out, want) {
			t.Errorf("suggest --yaml output missing %q\n---\n%s", want, out)
		}
	}
}

// TestSuggest_SNIOnlyDestinationSuggestsIPNotDomain proves an observed
// destination with an SNI name but no DNS-correlated name renders as an
// ip:port allow entry, never as the SNI name -- a name rule built from an
// SNI-only observation would never match again under fail-closed matching
// (see engine.go's package doc comment) -- and that the SNI name still
// appears as an informational aside on that entry's review note.
func TestSuggest_SNIOnlyDestinationSuggestsIPNotDomain(t *testing.T) {
	now := time.Now().UTC()
	path := fixtureSnapshotWithSNIOnly(t, now)

	out, _, err := runCLI(t, "suggest", "legacy", "--state", path)
	if err != nil {
		t.Fatalf("suggest: unexpected error %v\noutput: %s", err, out)
	}

	if !strings.Contains(out, `airlock.allow: "203.0.113.20:443"`) {
		t.Errorf("suggest csv line wrong (want the bare IP, never the SNI-only domain), got:\n%s", out)
	}
	if strings.Contains(out, "sni-only.example.com:443") {
		t.Errorf("suggest output must never render an SNI-only name as a suggested entry:\n%s", out)
	}
	if !strings.Contains(out, `observed SNI "sni-only.example.com"`) {
		t.Errorf("suggest output missing the informational SNI aside on the ip-only line:\n%s", out)
	}
}

// fixtureSnapshotWithSNIOnly builds a minimal state snapshot with exactly
// one suggest destination that has an observed SNI name but no
// DNS-correlated name, for TestSuggest_SNIOnlyDestinationSuggestsIPNotDomain.
func fixtureSnapshotWithSNIOnly(t *testing.T, now time.Time) string {
	t.Helper()
	snap := daemon.StateSnapshot{
		SchemaVersion: 1,
		GeneratedAt:   now,
		Version:       "00.01.00b1",
		Suggestions: []daemon.SuggestContainer{
			{
				ID: "legacy123456", Name: "legacy",
				Destinations: []daemon.SuggestDest{
					{
						Name: "", SNIName: "sni-only.example.com",
						IP: "203.0.113.20", Port: 443, Proto: "tcp",
						Count: 3, Verdict: "no-match",
						FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Minute),
					},
				},
			},
		},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture snapshot: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write fixture snapshot: %v", err)
	}
	return path
}

// TestSuggest_UnknownContainer proves suggest reports a clear message and
// a nonzero result for a container with no recorded observations.
func TestSuggest_UnknownContainer(t *testing.T) {
	now := time.Now().UTC()
	path := fixtureSnapshot(t, now)

	out, _, err := runCLI(t, "suggest", "no-such-container", "--state", path)
	if err == nil {
		t.Fatalf("suggest (unknown container): want a nonzero result, got success\noutput: %s", out)
	}
	if !strings.Contains(out, "no observed egress recorded") {
		t.Errorf("suggest output = %q, want the no-observations message", out)
	}
}

// TestFindSuggestContainer_MatchesByNameIDOrPrefix exercises the lookup
// helper directly for all three accepted forms.
func TestFindSuggestContainer_MatchesByNameIDOrPrefix(t *testing.T) {
	containers := []daemon.SuggestContainer{
		{ID: "abcdef0123456789", Name: "web"},
	}
	if c := findSuggestContainer(containers, "web"); c == nil {
		t.Error("match by name failed")
	}
	if c := findSuggestContainer(containers, "abcdef0123456789"); c == nil {
		t.Error("match by full id failed")
	}
	if c := findSuggestContainer(containers, "abcdef"); c == nil {
		t.Error("match by id prefix failed")
	}
	if c := findSuggestContainer(containers, "nope"); c != nil {
		t.Error("unexpected match for an unrelated target")
	}
}

// TestRenderSuggestEntries_DedupSortAndIPv6Bracket proves entry rendering
// dedups identical name:port pairs (summing counts), sorts lexically, and
// brackets an IPv6-literal-only destination when a port is present.
func TestRenderSuggestEntries_DedupSortAndIPv6Bracket(t *testing.T) {
	dests := []daemon.SuggestDest{
		{Name: "b.example.com", Port: 443, Count: 3, Verdict: "no-match", LastSeen: time.Unix(100, 0)},
		{Name: "b.example.com", Port: 443, Count: 2, Verdict: "no-match", LastSeen: time.Unix(200, 0)},
		{Name: "a.example.com", Port: 443, Count: 1, Verdict: "allowed", LastSeen: time.Unix(50, 0)},
		{IP: "2606:4700:4700::1111", Port: 443, Count: 1, Verdict: "unresolved-ip", LastSeen: time.Unix(10, 0)},
	}
	entries := renderSuggestEntries(dests)

	if len(entries) != 3 {
		t.Fatalf("renderSuggestEntries() = %+v, want 3 deduplicated entries", entries)
	}
	// '[' sorts before any lowercase letter, so the bracketed IPv6-only
	// entry (no name evidence) sorts first.
	if entries[0].text != "[2606:4700:4700::1111]:443" {
		t.Errorf("first entry (sorted) = %q, want the bracketed IPv6 literal", entries[0].text)
	}
	if !entries[0].ipOnly {
		t.Errorf("bracketed IPv6 entry ipOnly = false, want true (no name evidence)")
	}
	var b *suggestEntry
	for i := range entries {
		if entries[i].text == "b.example.com:443" {
			b = &entries[i]
		}
	}
	if b == nil {
		t.Fatalf("entries = %+v, want a merged b.example.com:443 entry", entries)
	}
	if b.count != 5 {
		t.Errorf("merged count = %d, want 5 (3+2)", b.count)
	}
}
