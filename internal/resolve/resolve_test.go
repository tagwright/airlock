// SPDX-License-Identifier: GPL-3.0-or-later

package resolve

import (
	"strings"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/discovery"
	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/core/runtime"
)

// testConfig builds a *config.Config with sane, always-valid defaults
// applied (mirroring what config.Load would produce after applyDefaults),
// so tests can override only the fields they care about.
func testConfig() *config.Config {
	return &config.Config{
		Defaults: config.Defaults{
			Observe:        "all",
			DefaultMode:    "alert",
			DefaultScope:   "external",
			AlertWindow:    "1h",
			AlertFlood:     30,
			DigestSchedule: "0 0 * * *",
		},
	}
}

func boolFlag(b bool) *config.BoolFlag {
	f := config.BoolFlag(b)
	return &f
}

func mode(m policy.Mode) *policy.Mode    { return &m }
func scope(s policy.Scope) *policy.Scope { return &s }
func dur(d time.Duration) *time.Duration { return &d }

func entries(t *testing.T, raw ...string) []policy.Entry {
	t.Helper()
	out := make([]policy.Entry, 0, len(raw))
	for _, r := range raw {
		e, err := policy.ParseEntry(r)
		if err != nil {
			t.Fatalf("ParseEntry(%q): %v", r, err)
		}
		out = append(out, e)
	}
	return out
}

func names(entries []policy.Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.String()
	}
	return out
}

func containsAll(t *testing.T, got []string, want ...string) {
	t.Helper()
	set := make(map[string]bool, len(got))
	for _, g := range got {
		set[g] = true
	}
	for _, w := range want {
		if !set[w] {
			t.Errorf("expected entries to contain %q, got %v", w, got)
		}
	}
}

func hasErrorDiag(diags []discovery.Diagnostic, substr string) bool {
	for _, d := range diags {
		if d.Level == discovery.Error && strings.Contains(d.Message, substr) {
			return true
		}
	}
	return false
}

// --- Basic arming and label-only cases ------------------------------------

func TestResolve_LabelOnlyArmedAllowlist(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "renovate", Service: "renovate"}
	lp := discovery.LabelPolicy{
		Enable:    true,
		EnableSet: true,
		Allow:     entries(t, "api.github.com:443", "*.githubusercontent.com:443"),
	}
	cfg := testConfig()

	got, diags := Resolve(c, lp, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if !got.Armed {
		t.Fatal("expected Armed=true")
	}
	if got.Policy.Mode != policy.Alert {
		t.Errorf("expected default mode alert, got %v", got.Policy.Mode)
	}
	if got.Policy.Scope != policy.External {
		t.Errorf("expected default scope external, got %v", got.Policy.Scope)
	}
	containsAll(t, names(got.Policy.Allow), "api.github.com:443", "*.githubusercontent.com:443")
	if got.Policy.Name != "renovate" {
		t.Errorf("expected name renovate, got %q", got.Policy.Name)
	}
}

func TestResolve_NoLabelsNoGroupMatchIsUnarmed(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "plain", Project: "unrelated"}
	lp := discovery.LabelPolicy{}
	cfg := testConfig()

	got, diags := Resolve(c, lp, cfg)
	if got.Armed {
		t.Fatal("expected Armed=false")
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
}

// --- Group arming ----------------------------------------------------------

func TestResolve_GroupArmsUnlabeledContainer(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "sonarr", Project: "mediastack"}
	lp := discovery.LabelPolicy{}
	cfg := testConfig()
	cfg.Groups = []config.Group{
		{
			Name:   "media-stack",
			Match:  config.Match{ComposeProject: "mediastack"},
			Enable: boolFlag(true),
			Allow:  config.EntryList{Entries: []string{"api.themoviedb.org:443"}},
		},
	}

	got, diags := Resolve(c, lp, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if !got.Armed {
		t.Fatal("expected group to arm the container")
	}
	containsAll(t, names(got.Policy.Allow), "api.themoviedb.org:443")
	if len(got.MatchedGroups) != 1 || got.MatchedGroups[0] != "media-stack" {
		t.Errorf("expected MatchedGroups=[media-stack], got %v", got.MatchedGroups)
	}
}

func TestResolve_PerContainerDisableOptsOutOfGroup(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "qbittorrent", Project: "mediastack"}
	lp := discovery.LabelPolicy{Enable: false, EnableSet: true} // airlock.enable=false
	cfg := testConfig()
	cfg.Groups = []config.Group{
		{
			Name:   "media-stack",
			Match:  config.Match{ComposeProject: "mediastack"},
			Enable: boolFlag(true),
		},
	}

	got, _ := Resolve(c, lp, cfg)
	if got.Armed {
		t.Fatal("expected the per-container enable=false label to opt out of the armed group")
	}
}

// --- Match dimensions --------------------------------------------------------

func TestResolve_NetworkMatchGroup(t *testing.T) {
	c := runtime.Container{
		ID: "c1", Name: "db",
		Networks: []runtime.ContainerNetwork{{Name: "backend_net"}},
	}
	other := runtime.Container{ID: "c2", Name: "other", Networks: []runtime.ContainerNetwork{{Name: "frontend_net"}}}

	cfg := testConfig()
	cfg.Groups = []config.Group{
		{Name: "backend-db-net", Match: config.Match{Network: "backend_net"}, Enable: boolFlag(true), Allow: config.EntryList{None: true}},
	}

	got, diags := Resolve(c, discovery.LabelPolicy{}, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if !got.Armed {
		t.Fatal("expected network-matched container to be armed")
	}
	if len(got.Policy.Allow) != 0 {
		t.Errorf("expected zero-egress allow list, got %v", got.Policy.Allow)
	}

	gotOther, _ := Resolve(other, discovery.LabelPolicy{}, cfg)
	if gotOther.Armed {
		t.Fatal("expected non-matching network container to remain unarmed")
	}
}

func TestResolve_LabelSelectorGroup(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "app", Labels: map[string]string{"tier": "media"}}
	notMatching := runtime.Container{ID: "c2", Name: "other", Labels: map[string]string{"tier": "backend"}}

	cfg := testConfig()
	cfg.Groups = []config.Group{
		{Name: "media-tier", Match: config.Match{Labels: map[string]string{"tier": "media"}}, Enable: boolFlag(true)},
	}

	got, _ := Resolve(c, discovery.LabelPolicy{}, cfg)
	if !got.Armed {
		t.Fatal("expected label-selector match to arm the container")
	}
	gotOther, _ := Resolve(notMatching, discovery.LabelPolicy{}, cfg)
	if gotOther.Armed {
		t.Fatal("expected non-matching labels to leave the container unarmed")
	}
}

func TestResolve_CatchAllGroup(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "anything", Project: "whatever"}
	cfg := testConfig()
	cfg.Groups = []config.Group{
		{Name: "fleet-wide", Enable: boolFlag(true), Mode: "audit"},
	}

	got, diags := Resolve(c, discovery.LabelPolicy{}, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if !got.Armed {
		t.Fatal("expected the catch-all group to arm every container")
	}
	if got.Policy.Mode != policy.Audit {
		t.Errorf("expected mode audit from the catch-all group, got %v", got.Policy.Mode)
	}
}

// --- Multi-group union and same-tier conflict -------------------------------

func TestResolve_MultiGroupUnionsAllowLists(t *testing.T) {
	c := runtime.Container{
		ID: "c1", Name: "app",
		Networks: []runtime.ContainerNetwork{{Name: "net-a"}, {Name: "net-b"}},
	}
	cfg := testConfig()
	cfg.Groups = []config.Group{
		{Name: "group-a", Match: config.Match{Network: "net-a"}, Enable: boolFlag(true), Allow: config.EntryList{Entries: []string{"a.example.com:443"}}},
		{Name: "group-b", Match: config.Match{Network: "net-b"}, Enable: boolFlag(true), Allow: config.EntryList{Entries: []string{"b.example.com:443"}}},
	}

	got, diags := Resolve(c, discovery.LabelPolicy{}, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	containsAll(t, names(got.Policy.Allow), "a.example.com:443", "b.example.com:443")
}

func TestResolve_SameTierScalarConflictIsError(t *testing.T) {
	c := runtime.Container{
		ID: "c1", Name: "app",
		Networks: []runtime.ContainerNetwork{{Name: "net-a"}, {Name: "net-b"}},
	}
	cfg := testConfig()
	cfg.Groups = []config.Group{
		{Name: "group-a", Match: config.Match{Network: "net-a"}, Enable: boolFlag(true), Mode: "audit"},
		{Name: "group-b", Match: config.Match{Network: "net-b"}, Enable: boolFlag(true), Mode: "alert"},
	}

	_, diags := Resolve(c, discovery.LabelPolicy{}, cfg)
	if !hasErrorDiag(diags, "mode: conflicting values") {
		t.Fatalf("expected a same-tier mode conflict diagnostic, got %+v", diags)
	}
}

// --- Specificity ordering ----------------------------------------------------

func TestResolve_LabelModeBeatsGroupMode(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "app", Project: "stack"}
	lp := discovery.LabelPolicy{Enable: true, EnableSet: true, Mode: mode(policy.Alert)}
	cfg := testConfig()
	cfg.Groups = []config.Group{
		{Name: "g", Match: config.Match{ComposeProject: "stack"}, Mode: "audit"},
	}

	got, diags := Resolve(c, lp, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if got.Policy.Mode != policy.Alert {
		t.Errorf("expected the per-container label mode to win, got %v", got.Policy.Mode)
	}
}

func TestResolve_ComposeProjectGroupBeatsNetworkGroup(t *testing.T) {
	c := runtime.Container{
		ID: "c1", Name: "app", Project: "stack",
		Networks: []runtime.ContainerNetwork{{Name: "net-a"}},
	}
	cfg := testConfig()
	cfg.Groups = []config.Group{
		{Name: "project-group", Match: config.Match{ComposeProject: "stack"}, Enable: boolFlag(true), Mode: "alert"},
		{Name: "network-group", Match: config.Match{Network: "net-a"}, Mode: "audit"},
	}

	got, diags := Resolve(c, discovery.LabelPolicy{}, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if got.Policy.Mode != policy.Alert {
		t.Errorf("expected the compose_project group's mode to beat the network group's, got %v", got.Policy.Mode)
	}
}

// --- Named policy sets -------------------------------------------------------

func TestResolve_ReferencedPolicySetUnionsAllow(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "wordpress"}
	lp := discovery.LabelPolicy{
		Enable:     true,
		EnableSet:  true,
		PolicyRefs: []string{"debian-updates", "wordpress-core"},
		Allow:      entries(t, "smtp.purelymail.com:465"),
	}
	cfg := testConfig()
	cfg.Policies = map[string]config.PolicySet{
		"debian-updates": {Allow: config.EntryList{Entries: []string{"deb.debian.org:443"}}},
		"wordpress-core": {Allow: config.EntryList{Entries: []string{"api.wordpress.org:443"}}},
	}

	got, diags := Resolve(c, lp, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	containsAll(t, names(got.Policy.Allow), "deb.debian.org:443", "api.wordpress.org:443", "smtp.purelymail.com:465")
}

func TestResolve_UnknownPolicySetIsError(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "app"}
	lp := discovery.LabelPolicy{Enable: true, EnableSet: true, PolicyRefs: []string{"does-not-exist"}}
	cfg := testConfig()

	_, diags := Resolve(c, lp, cfg)
	if !hasErrorDiag(diags, `unknown policy set "does-not-exist"`) {
		t.Fatalf("expected an unknown-policy-set diagnostic, got %+v", diags)
	}
}

func TestResolve_ConflictingReferencedSetsIsError(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "app"}
	lp := discovery.LabelPolicy{Enable: true, EnableSet: true, PolicyRefs: []string{"set-a", "set-b"}}
	cfg := testConfig()
	cfg.Policies = map[string]config.PolicySet{
		"set-a": {Mode: "audit"},
		"set-b": {Mode: "alert"},
	}

	_, diags := Resolve(c, lp, cfg)
	if !hasErrorDiag(diags, "mode: conflicting values") {
		t.Fatalf("expected a conflicting-sets diagnostic, got %+v", diags)
	}
}

// --- allow=none contradiction -------------------------------------------------

func TestResolve_AllowNoneContradictsGroupAllow(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "app", Project: "stack"}
	lp := discovery.LabelPolicy{Enable: true, EnableSet: true, AllowNone: true}
	cfg := testConfig()
	cfg.Groups = []config.Group{
		{Name: "g", Match: config.Match{ComposeProject: "stack"}, Allow: config.EntryList{Entries: []string{"example.com:443"}}},
	}

	got, diags := Resolve(c, lp, cfg)
	if !hasErrorDiag(diags, `"none" is a declaration, not a filter`) {
		t.Fatalf("expected an allow=none contradiction diagnostic, got %+v", diags)
	}
	if len(got.Policy.Allow) != 0 {
		t.Errorf("expected the none declaration to still win (zero allow entries), got %v", got.Policy.Allow)
	}
}

func TestResolve_AllowNoneWithNothingElseIsClean(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "firefly-db"}
	lp := discovery.LabelPolicy{Enable: true, EnableSet: true, AllowNone: true}
	cfg := testConfig()

	got, diags := Resolve(c, lp, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if len(got.Policy.Allow) != 0 {
		t.Errorf("expected zero-egress allow list, got %v", got.Policy.Allow)
	}
}

// --- Skipped label policy: group coverage survives ---------------------------

func TestResolve_SkippedLabelStillCoveredByGroup(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "app", Project: "stack"}
	// A broken label (conflict/parse error) sets Skipped, per
	// discovery.ReadLabels' contract: the rest of LabelPolicy must be
	// discarded, but a matching group is a separate, valid source.
	lp := discovery.LabelPolicy{Skipped: true, Enable: true, EnableSet: true, Allow: entries(t, "should-be-ignored.example.com")}
	cfg := testConfig()
	cfg.Groups = []config.Group{
		{Name: "g", Match: config.Match{ComposeProject: "stack"}, Enable: boolFlag(true), Allow: config.EntryList{Entries: []string{"group-allowed.example.com:443"}}},
	}

	got, diags := Resolve(c, lp, cfg)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if !got.Armed {
		t.Fatal("expected the group to still arm the container despite the skipped label")
	}
	got2 := names(got.Policy.Allow)
	containsAll(t, got2, "group-allowed.example.com:443")
	for _, n := range got2 {
		if n == "should-be-ignored.example.com" {
			t.Errorf("expected the skipped label's own allow entries to be discarded, got %v", got2)
		}
	}
}

// --- Name resolution order ----------------------------------------------------

func TestResolve_NameResolutionOrder(t *testing.T) {
	cfg := testConfig()

	// label override beats everything.
	c1 := runtime.Container{Name: "container-name", Service: "compose-service"}
	lp1 := discovery.LabelPolicy{Enable: true, EnableSet: true, Name: "label-name"}
	got1, _ := Resolve(c1, lp1, cfg)
	if got1.Policy.Name != "label-name" {
		t.Errorf("expected label name to win, got %q", got1.Policy.Name)
	}

	// compose service beats container name when no label override.
	c2 := runtime.Container{Name: "container-name", Service: "compose-service"}
	got2, _ := Resolve(c2, discovery.LabelPolicy{Enable: true, EnableSet: true}, cfg)
	if got2.Policy.Name != "compose-service" {
		t.Errorf("expected compose service name to win, got %q", got2.Policy.Name)
	}

	// container name is the last resort.
	c3 := runtime.Container{Name: "container-name"}
	got3, _ := Resolve(c3, discovery.LabelPolicy{Enable: true, EnableSet: true}, cfg)
	if got3.Policy.Name != "container-name" {
		t.Errorf("expected container name to win, got %q", got3.Policy.Name)
	}
}

// --- Alert window scalar merge ------------------------------------------------

func TestResolve_AlertWindowFallsBackToDefault(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "app"}
	lp := discovery.LabelPolicy{Enable: true, EnableSet: true}
	cfg := testConfig()
	cfg.Defaults.AlertWindow = "2h"

	got, _ := Resolve(c, lp, cfg)
	if got.Policy.AlertWindow != 2*time.Hour {
		t.Errorf("expected default alert window 2h, got %v", got.Policy.AlertWindow)
	}
}

func TestResolve_LabelAlertWindowOverridesDefault(t *testing.T) {
	c := runtime.Container{ID: "c1", Name: "app"}
	lp := discovery.LabelPolicy{Enable: true, EnableSet: true, AlertWindow: dur(30 * time.Minute)}
	cfg := testConfig()

	got, _ := Resolve(c, lp, cfg)
	if got.Policy.AlertWindow != 30*time.Minute {
		t.Errorf("expected label alert window 30m, got %v", got.Policy.AlertWindow)
	}
}
