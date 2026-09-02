// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfig writes contents to a temp airlock.yml and returns its path.
func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "airlock.yml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadValid(t *testing.T) {
	tests := []struct {
		name  string
		yaml  string
		check func(t *testing.T, c *Config)
	}{
		{
			name: "empty file loads with defaults",
			yaml: ``,
			check: func(t *testing.T, c *Config) {
				if c.Defaults.Observe != "all" {
					t.Errorf("Defaults.Observe = %q, want all", c.Defaults.Observe)
				}
				if c.Defaults.DefaultMode != "alert" {
					t.Errorf("Defaults.DefaultMode = %q, want alert", c.Defaults.DefaultMode)
				}
				if c.Defaults.DefaultScope != "external" {
					t.Errorf("Defaults.DefaultScope = %q, want external", c.Defaults.DefaultScope)
				}
				if c.Defaults.AlertWindow != "1h" {
					t.Errorf("Defaults.AlertWindow = %q, want 1h", c.Defaults.AlertWindow)
				}
				if c.Defaults.AlertFlood != 30 {
					t.Errorf("Defaults.AlertFlood = %d, want 30", c.Defaults.AlertFlood)
				}
				if c.Defaults.DigestSchedule != "0 0 * * *" {
					t.Errorf("Defaults.DigestSchedule = %q, want 0 0 * * *", c.Defaults.DigestSchedule)
				}
				if c.Defaults.UnpoliciedDigest {
					t.Errorf("Defaults.UnpoliciedDigest = true, want false")
				}
			},
		},
		{
			name: "named policy sets, fleet pattern",
			yaml: `
policies:
  debian-updates:
    allow:
      - "deb.debian.org:443"
      - "security.debian.org:443"
  wordpress-core:
    allow:
      - "api.wordpress.org:443"
      - "*.gravatar.com:443"
`,
			check: func(t *testing.T, c *Config) {
				if len(c.Policies) != 2 {
					t.Fatalf("len(Policies) = %d, want 2", len(c.Policies))
				}
				got := c.Policies["debian-updates"].Allow.Entries
				want := []string{"deb.debian.org:443", "security.debian.org:443"}
				if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
					t.Errorf("debian-updates allow = %v, want %v", got, want)
				}
			},
		},
		{
			name: "media stack group, scope all with self token",
			yaml: `
groups:
  - name: media-stack
    match:
      compose_project: mediastack
    enable: "true"
    scope: "all"
    allow:
      - "@self"
      - "api.themoviedb.org:443"
      - "*.servarr.com:443"
`,
			check: func(t *testing.T, c *Config) {
				if len(c.Groups) != 1 {
					t.Fatalf("len(Groups) = %d, want 1", len(c.Groups))
				}
				g := c.Groups[0]
				if g.Match.ComposeProject != "mediastack" {
					t.Errorf("Match.ComposeProject = %q, want mediastack", g.Match.ComposeProject)
				}
				if g.Enable == nil || !*g.Enable {
					t.Errorf("Enable = %v, want true", g.Enable)
				}
				if len(c.Warnings) != 0 {
					t.Errorf("Warnings = %v, want none (scope is all)", c.Warnings)
				}
			},
		},
		{
			name: "db-only network group with allow none",
			yaml: `
groups:
  - name: backend-db-net
    match:
      network: mediastack_backend
    enable: "true"
    allow: "none"
`,
			check: func(t *testing.T, c *Config) {
				g := c.Groups[0]
				if g.Match.Network != "mediastack_backend" {
					t.Errorf("Match.Network = %q, want mediastack_backend", g.Match.Network)
				}
				if !g.Allow.None {
					t.Errorf("Allow.None = false, want true (allow: \"none\")")
				}
			},
		},
		{
			name: "catch-all group with no match block matches everything",
			yaml: `
groups:
  - name: catch-all
    mode: "audit"
`,
			check: func(t *testing.T, c *Config) {
				if !c.Groups[0].Match.Empty() {
					t.Errorf("Match.Empty() = false, want true for a group with no match block")
				}
			},
		},
		{
			name: "label selector group, csv scalar policy reference",
			yaml: `
policies:
  media-updates:
    allow:
      - "api.themoviedb.org:443"
groups:
  - name: media-tier
    match:
      label: "tier=media"
    enable: "true"
    policy: "media-updates"
`,
			check: func(t *testing.T, c *Config) {
				g := c.Groups[0]
				if got := g.Match.Labels["tier"]; got != "media" {
					t.Errorf("Match.Labels[tier] = %q, want media", got)
				}
				if len(g.Policy) != 1 || g.Policy[0] != "media-updates" {
					t.Errorf("Policy = %v, want [media-updates]", g.Policy)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.yaml)
			c, err := Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tt.check(t, c)
		})
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string // substring expected in the error message
	}{
		{
			name: "bad entry syntax in policy set",
			yaml: `
policies:
  broken:
    allow:
      - "api.*.example.com"
`,
			wantErr: "leftmost",
		},
		{
			name: "bad entry syntax in group allow",
			yaml: `
groups:
  - name: bad-group
    allow:
      - "example.com/udp"
`,
			wantErr: "/udp",
		},
		{
			name: "unknown policy-set reference from a group",
			yaml: `
groups:
  - name: media-tier
    match:
      label: "tier=media"
    policy: "does-not-exist"
`,
			wantErr: "unknown policy set",
		},
		{
			name: "group match combines two dimensions",
			yaml: `
groups:
  - name: two-dims
    match:
      compose_project: mediastack
      network: mediastack_backend
`,
			wantErr: "more than one targeting dimension",
		},
		{
			name: "group with no name",
			yaml: `
groups:
  - match:
      network: mediastack_backend
`,
			wantErr: "name is required",
		},
		{
			name: "invalid mode on a group",
			yaml: `
groups:
  - name: bad-mode
    mode: "block"
`,
			wantErr: "reserved",
		},
		{
			name: "invalid scope on a policy set",
			yaml: `
policies:
  bad-scope:
    scope: "internal"
`,
			wantErr: "invalid scope",
		},
		{
			name: "allow none contradicts a referenced policy set that allows something",
			yaml: `
policies:
  wide-open:
    allow:
      - "example.com:443"
groups:
  - name: contradiction
    match:
      network: some-net
    policy: "wide-open"
    allow: "none"
`,
			wantErr: "contradictory",
		},
		{
			name: "duplicate group name",
			yaml: `
groups:
  - name: dup
    match:
      network: net-a
  - name: dup
    match:
      network: net-b
`,
			wantErr: "duplicate group name",
		},
		{
			name: "invalid policy set name",
			yaml: `
policies:
  "Not Valid Name":
    allow:
      - "example.com:443"
`,
			wantErr: "lowercase identifier",
		},
		{
			name: "invalid alert.window duration",
			yaml: `
groups:
  - name: bad-window
    match:
      network: net-a
    alert.window: "not-a-duration"
`,
			wantErr: "invalid duration",
		},
		{
			name: "notification channel missing type",
			yaml: `
notifications:
  channels:
    - min_level: "warn"
`,
			wantErr: "missing type",
		},
		{
			name: "unknown observe gadget name",
			yaml: `
observe:
  images:
    trace_udp: "example/image:latest"
`,
			wantErr: "unknown gadget",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfig(t, tt.yaml)
			_, err := Load(path)
			if err == nil {
				t.Fatalf("Load: got nil error, want one containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Load error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestSelfTokenUnderExternalScopeWarns(t *testing.T) {
	path := writeConfig(t, `
groups:
  - name: leaky
    match:
      network: appstack_default
    scope: "external"
    allow:
      - "@self"
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v (expected a warning, not an error)", err)
	}
	if len(c.Warnings) == 0 {
		t.Fatalf("Warnings is empty, want a warning about @self under scope=external")
	}
	found := false
	for _, w := range c.Warnings {
		if strings.Contains(w, "@self") {
			found = true
		}
	}
	if !found {
		t.Errorf("Warnings = %v, want one mentioning @self", c.Warnings)
	}
}

func TestNoOpWildcardAllowWarns(t *testing.T) {
	path := writeConfig(t, `
policies:
  everything:
    allow:
      - "*"
`)
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.Warnings) == 0 {
		t.Fatalf("Warnings is empty, want a warning about the no-op allow: \"*\" policy")
	}
}

func TestEnvOverlayOverridesFile(t *testing.T) {
	path := writeConfig(t, `
defaults:
  default_mode: alert
  alert_flood: 30
`)
	t.Setenv("AIRLOCK_DEFAULT_MODE", "audit")
	t.Setenv("AIRLOCK_ALERT_FLOOD", "50")
	t.Setenv("AIRLOCK_OBSERVE", "enabled")
	t.Setenv("AIRLOCK_IMPLICIT_ALLOW", "resolver.home.lan:53")

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Defaults.DefaultMode != "audit" {
		t.Errorf("DefaultMode = %q, want audit (env should override file's alert)", c.Defaults.DefaultMode)
	}
	if c.Defaults.AlertFlood != 50 {
		t.Errorf("AlertFlood = %d, want 50 (env should override file's 30)", c.Defaults.AlertFlood)
	}
	if c.Defaults.Observe != "enabled" {
		t.Errorf("Observe = %q, want enabled", c.Defaults.Observe)
	}
	if len(c.Defaults.ImplicitAllow.Entries) != 1 || c.Defaults.ImplicitAllow.Entries[0] != "resolver.home.lan:53" {
		t.Errorf("ImplicitAllow = %+v, want one entry resolver.home.lan:53", c.Defaults.ImplicitAllow)
	}
}

func TestEnvImplicitAllowNoneSentinel(t *testing.T) {
	path := writeConfig(t, ``)
	t.Setenv("AIRLOCK_IMPLICIT_ALLOW", "none")

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.Defaults.ImplicitAllow.None {
		t.Errorf("ImplicitAllow.None = false, want true for env value \"none\"")
	}
}

func TestLoadMissingFileIsNotError(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("Load: %v, want nil error for a missing (optional) file", err)
	}
	if c.Defaults.DefaultMode != "alert" {
		t.Errorf("DefaultMode = %q, want default alert", c.Defaults.DefaultMode)
	}
}

func TestLoadEmptyPathIsNotError(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v, want nil error for an empty path", err)
	}
	if c.Defaults.AlertWindow != "1h" {
		t.Errorf("AlertWindow = %q, want default 1h", c.Defaults.AlertWindow)
	}
}

func TestDefaultsAlertWindowDurationParses(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	d, err := time.ParseDuration(c.Defaults.AlertWindow)
	if err != nil {
		t.Fatalf("Defaults.AlertWindow %q does not parse: %v", c.Defaults.AlertWindow, err)
	}
	if d != time.Hour {
		t.Errorf("Defaults.AlertWindow = %v, want 1h", d)
	}
}

func TestExampleFileLoads(t *testing.T) {
	data, err := os.ReadFile("../../airlock.example.yml")
	if err != nil {
		t.Skipf("airlock.example.yml not found relative to test: %v", err)
	}
	path := writeConfig(t, string(data))
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load(airlock.example.yml): %v", err)
	}
	if len(c.Warnings) != 0 {
		t.Errorf("airlock.example.yml produced warnings, want none: %v", c.Warnings)
	}
	if len(c.Groups) != 2 {
		t.Errorf("len(Groups) = %d, want 2", len(c.Groups))
	}
	if len(c.Policies) != 2 {
		t.Errorf("len(Policies) = %d, want 2", len(c.Policies))
	}
}
