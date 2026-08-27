// SPDX-License-Identifier: GPL-3.0-or-later

package discovery

import (
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/policy"
)

// hasLevel reports whether diags contains a diagnostic of the given
// level.
func hasLevel(diags []Diagnostic, lvl DiagLevel) bool {
	for _, d := range diags {
		if d.Level == lvl {
			return true
		}
	}
	return false
}

// allSticky reports whether every diagnostic in diags has Sticky set.
// Every Error this package produces, and the declared-but-unarmed
// Warning, must be sticky -- airlock's security-tool hardening of the
// house rule never lets an unprotected or unarmed container go quiet.
func allSticky(diags []Diagnostic) bool {
	for _, d := range diags {
		if !d.Sticky {
			return false
		}
	}
	return true
}

func entryStrings(entries []policy.Entry) map[string]bool {
	out := make(map[string]bool, len(entries))
	for _, e := range entries {
		out[e.String()] = true
	}
	return out
}

// TestCleanArmedAllowlist covers the ordinary case: enable=true plus a
// tight allowlist, no diagnostics at all.
func TestCleanArmedAllowlist(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{
		"airlock.enable": "true",
		"airlock.allow":  "api.github.com:443,*.githubusercontent.com:443",
	})
	if lp.Skipped {
		t.Fatalf("clean allowlist must not be skipped, diags=%v", diags)
	}
	if !lp.Enable || !lp.EnableSet {
		t.Errorf("Enable=%v EnableSet=%v, want true/true", lp.Enable, lp.EnableSet)
	}
	got := entryStrings(lp.Allow)
	if !got["api.github.com:443"] || !got["*.githubusercontent.com:443"] {
		t.Errorf("Allow = %v, want both entries", lp.Allow)
	}
	if len(diags) != 0 {
		t.Errorf("diags = %v, want none", diags)
	}
}

// TestDualPrefixAlias proves the tagwright.egress.* alias produces an
// identical result to the airlock.* primary, on its own and mixed with
// the primary on identical values.
func TestDualPrefixAlias(t *testing.T) {
	t.Run("alias only", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"tagwright.egress.enable": "true",
			"tagwright.egress.allow":  "example.com:443",
		})
		if lp.Skipped {
			t.Fatalf("alias-only labels must not be skipped, diags=%v", diags)
		}
		if !lp.Enable {
			t.Errorf("Enable = false, want true via the alias")
		}
		if !entryStrings(lp.Allow)["example.com:443"] {
			t.Errorf("Allow = %v, want example.com:443", lp.Allow)
		}
	})

	t.Run("alias matches primary", func(t *testing.T) {
		primary, _ := ReadLabels(map[string]string{
			"airlock.enable": "true",
			"airlock.allow":  "example.com:443",
			"airlock.mode":   "audit",
		})
		alias, _ := ReadLabels(map[string]string{
			"tagwright.egress.enable": "true",
			"tagwright.egress.allow":  "example.com:443",
			"tagwright.egress.mode":   "audit",
		})
		if primary.Enable != alias.Enable || *primary.Mode != *alias.Mode {
			t.Errorf("primary and alias diverged: primary=%+v alias=%+v", primary, alias)
		}
		if entryStrings(primary.Allow)["example.com:443"] != entryStrings(alias.Allow)["example.com:443"] {
			t.Errorf("Allow diverged between primary and alias")
		}
	})
}

// TestConflictRule proves the dual-prefix conflict rule: the same
// canonical suffix under both prefixes with different values is a sticky
// error and skips the container; the same value under both is harmless.
func TestConflictRule(t *testing.T) {
	t.Run("different values error and skip", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"airlock.enable":         "true",
			"airlock.allow":          "example.com:443",
			"tagwright.egress.allow": "other.com:443",
		})
		if !lp.Skipped {
			t.Fatalf("conflicting labels must skip the container")
		}
		if !hasLevel(diags, Error) {
			t.Fatalf("want an error diagnostic, got %v", diags)
		}
		if !allSticky(diags) {
			t.Errorf("all diagnostics must be sticky, got %v", diags)
		}
	})

	t.Run("same value harmless", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"airlock.enable":         "true",
			"airlock.allow":          "example.com:443",
			"tagwright.egress.allow": "example.com:443",
		})
		if lp.Skipped {
			t.Fatalf("identical values under both prefixes must not skip, diags=%v", diags)
		}
		if !entryStrings(lp.Allow)["example.com:443"] {
			t.Errorf("Allow = %v, want example.com:443", lp.Allow)
		}
		if hasLevel(diags, Error) {
			t.Errorf("identical values must not error, got %v", diags)
		}
	})

	t.Run("enable itself conflicts", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"airlock.enable":          "true",
			"tagwright.egress.enable": "false",
		})
		if !lp.Skipped {
			t.Fatalf("conflicting enable values must skip the container")
		}
		if !hasLevel(diags, Error) {
			t.Fatalf("want an error diagnostic, got %v", diags)
		}
	})
}

// TestUnknownSuffix proves a typo'd suffix (airlock.alow instead of
// airlock.allow) is a sticky validation error that skips the container,
// per the frozen grammar's "unknown suffixes are validation errors, not
// ignored" rule -- the whole point being that a typo must surface, not
// silently disable the policy it was meant to declare.
func TestUnknownSuffix(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{
		"airlock.enable": "true",
		"airlock.alow":   "example.com:443",
	})
	if !lp.Skipped {
		t.Fatalf("unknown suffix must skip the container")
	}
	if !hasLevel(diags, Error) {
		t.Fatalf("want an error diagnostic, got %v", diags)
	}
	if !allSticky(diags) {
		t.Errorf("all diagnostics must be sticky, got %v", diags)
	}

	t.Run("via the alias prefix too", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"tagwright.egress.enable": "true",
			"tagwright.egress.alow":   "example.com:443",
		})
		if !lp.Skipped {
			t.Fatalf("unknown suffix under the alias must also skip the container")
		}
		if !hasLevel(diags, Error) {
			t.Fatalf("want an error diagnostic, got %v", diags)
		}
	})
}

// TestIndexedAndCSVAllowUnion proves the csv value and the indexed
// allow.<n> escape hatch union together, de-duplicated, and that a
// duplicate entry appearing in both the csv and an indexed slot collapses
// to one.
func TestIndexedAndCSVAllowUnion(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{
		"airlock.enable":  "true",
		"airlock.allow":   "a.example.com:443,b.example.com:443",
		"airlock.allow.0": "b.example.com:443",
		"airlock.allow.1": "c.example.com:443",
	})
	if lp.Skipped {
		t.Fatalf("valid union must not skip, diags=%v", diags)
	}
	got := entryStrings(lp.Allow)
	for _, want := range []string{"a.example.com:443", "b.example.com:443", "c.example.com:443"} {
		if !got[want] {
			t.Errorf("Allow = %v, missing %q", lp.Allow, want)
		}
	}
	if len(lp.Allow) != 3 {
		t.Errorf("Allow has %d entries, want exactly 3 (csv + two indexed, b.example.com:443 de-duplicated)", len(lp.Allow))
	}
}

// TestIndexedEntryNotCommaSplit proves the indexed allow.<n> escape hatch
// treats its whole value as ONE entry, never splitting it on commas --
// the entire reason the escape hatch exists is for an entry-shaped value
// that itself must not be comma-split. A value that is not a valid single
// entry (because it contains a comma) is therefore a bad-entry error.
func TestIndexedEntryNotCommaSplit(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{
		"airlock.enable":  "true",
		"airlock.allow.0": "a.example.com:443,b.example.com:443",
	})
	if !lp.Skipped {
		t.Fatalf("a comma inside one indexed slot must not silently split, want a skip")
	}
	if !hasLevel(diags, Error) {
		t.Fatalf("want an error diagnostic, got %v", diags)
	}
}

// TestAllowNoneSentinel covers the zero-egress sentinel: alone it is a
// valid, distinct declaration (AllowNone true, Allow nil); combined with
// an indexed entry it is a validation error.
func TestAllowNoneSentinel(t *testing.T) {
	t.Run("none alone", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"airlock.enable": "true",
			"airlock.allow":  "none",
		})
		if lp.Skipped {
			t.Fatalf("allow=none must not skip, diags=%v", diags)
		}
		if !lp.AllowNone {
			t.Errorf("AllowNone = false, want true")
		}
		if len(lp.Allow) != 0 {
			t.Errorf("Allow = %v, want empty", lp.Allow)
		}
		if len(diags) != 0 {
			t.Errorf("diags = %v, want none", diags)
		}
	})

	t.Run("none combined with indexed entry errors", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"airlock.enable":  "true",
			"airlock.allow":   "none",
			"airlock.allow.0": "example.com:443",
		})
		if !lp.Skipped {
			t.Fatalf("none combined with an indexed entry must skip")
		}
		if !hasLevel(diags, Error) {
			t.Fatalf("want an error diagnostic, got %v", diags)
		}
	})

	t.Run("none combined with other csv entries errors", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"airlock.enable": "true",
			"airlock.allow":  "none,example.com:443",
		})
		if !lp.Skipped {
			t.Fatalf("none combined with another csv entry must skip")
		}
		if !hasLevel(diags, Error) {
			t.Fatalf("want an error diagnostic, got %v", diags)
		}
	})

	t.Run("deny=none is recorded distinctly", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"airlock.enable": "true",
			"airlock.deny":   "none",
		})
		if lp.Skipped {
			t.Fatalf("deny=none must not skip, diags=%v", diags)
		}
		if !lp.DenyNone {
			t.Errorf("DenyNone = false, want true")
		}
	})
}

// TestBadEntrySkips proves a malformed entry is a sticky error and skips
// the container.
func TestBadEntrySkips(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{
		"airlock.enable": "true",
		"airlock.allow":  "api.*.example.com", // non-leftmost wildcard, rejected by policy.ParseEntry
	})
	if !lp.Skipped {
		t.Fatalf("a bad entry must skip the container")
	}
	if !hasLevel(diags, Error) {
		t.Fatalf("want an error diagnostic, got %v", diags)
	}
	if !allSticky(diags) {
		t.Errorf("all diagnostics must be sticky, got %v", diags)
	}
}

// TestModeBlockReserved proves mode=block is the reserved-and-rejected
// value: always a sticky validation error in v1, never silently
// downgraded to alert.
func TestModeBlockReserved(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{
		"airlock.enable": "true",
		"airlock.mode":   "block",
	})
	if !lp.Skipped {
		t.Fatalf("mode=block must skip the container")
	}
	if lp.Mode != nil {
		t.Errorf("Mode = %v, want nil (block must never be recorded as a usable mode)", *lp.Mode)
	}
	if !hasLevel(diags, Error) {
		t.Fatalf("want an error diagnostic, got %v", diags)
	}
}

// TestDeclaredButUnarmedWarning proves the sticky arming-gate warning:
// any policy-bearing label present with enable absent, or explicitly
// false, is a warning even though the rest parses cleanly. enable=false
// is identical to absent in v1 for this purpose.
func TestDeclaredButUnarmedWarning(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
	}{
		{"enable absent", map[string]string{"airlock.allow": "example.com:443"}},
		{"enable false", map[string]string{"airlock.enable": "false", "airlock.allow": "example.com:443"}},
		{"mode only, no allow", map[string]string{"airlock.mode": "audit"}},
		{"allow=none still counts as declared", map[string]string{"airlock.allow": "none"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lp, diags := ReadLabels(tc.labels)
			if lp.Skipped {
				t.Fatalf("a clean declared-but-unarmed container must not skip, diags=%v", diags)
			}
			if !hasLevel(diags, Warning) {
				t.Fatalf("want a warning diagnostic, got %v", diags)
			}
			for _, d := range diags {
				if d.Level == Warning && !d.Sticky {
					t.Errorf("declared-but-unarmed warning must be sticky: %+v", d)
				}
			}
		})
	}

	t.Run("no policy labels at all, no warning", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{"airlock.enable": "false"})
		if lp.Skipped {
			t.Fatalf("bare enable=false must not skip, diags=%v", diags)
		}
		if hasLevel(diags, Warning) {
			t.Errorf("no policy declared, want no warning, got %v", diags)
		}
	})

	t.Run("name only, no enable, no warning", func(t *testing.T) {
		// name is pure identity metadata, not a policy declaration: a
		// container that sets only airlock.name while unarmed makes no
		// claim about its egress and must draw no diagnostics at all.
		lp, diags := ReadLabels(map[string]string{"airlock.name": "renovate"})
		if lp.Skipped {
			t.Fatalf("name-only labels must not skip, diags=%v", diags)
		}
		if len(diags) != 0 {
			t.Errorf("name alone is not a policy declaration, want no diagnostics, got %v", diags)
		}
	})

	t.Run("name plus alias name only, no enable, no warning", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{"tagwright.egress.name": "renovate"})
		if lp.Skipped {
			t.Fatalf("name-only labels via the alias must not skip, diags=%v", diags)
		}
		if len(diags) != 0 {
			t.Errorf("name alone is not a policy declaration, want no diagnostics, got %v", diags)
		}
	})

	t.Run("armed, no warning", func(t *testing.T) {
		_, diags := ReadLabels(map[string]string{"airlock.enable": "true", "airlock.allow": "example.com:443"})
		if hasLevel(diags, Warning) {
			t.Errorf("armed container should not draw the unarmed warning, got %v", diags)
		}
	})
}

// TestEnableFalseEqualsAbsent proves enable=false and enable absent
// produce the same Enable value, differing only in EnableSet.
func TestEnableFalseEqualsAbsent(t *testing.T) {
	absent, _ := ReadLabels(map[string]string{})
	explicit, _ := ReadLabels(map[string]string{"airlock.enable": "false"})

	if absent.Enable != false || explicit.Enable != false {
		t.Fatalf("Enable = %v/%v, want false/false", absent.Enable, explicit.Enable)
	}
	if absent.EnableSet {
		t.Errorf("EnableSet = true for absent enable, want false")
	}
	if !explicit.EnableSet {
		t.Errorf("EnableSet = false for explicit enable=false, want true")
	}
}

// TestEnableInvalidValue proves a boolean value outside "true"/"false" is
// a sticky validation error, matching the grammar's strict boolean house
// style.
func TestEnableInvalidValue(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{"airlock.enable": "yes"})
	if !lp.Skipped {
		t.Fatalf("an invalid enable value must skip the container")
	}
	if !hasLevel(diags, Error) {
		t.Fatalf("want an error diagnostic, got %v", diags)
	}
}

// TestAlertWindow covers a valid duration parse and a bad-duration error.
func TestAlertWindow(t *testing.T) {
	t.Run("valid duration", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"airlock.enable":       "true",
			"airlock.alert.window": "90m",
		})
		if lp.Skipped {
			t.Fatalf("valid duration must not skip, diags=%v", diags)
		}
		if lp.AlertWindow == nil || *lp.AlertWindow != 90*time.Minute {
			t.Errorf("AlertWindow = %v, want 90m", lp.AlertWindow)
		}
	})

	t.Run("bad duration errors", func(t *testing.T) {
		lp, diags := ReadLabels(map[string]string{
			"airlock.enable":       "true",
			"airlock.alert.window": "ninety minutes",
		})
		if !lp.Skipped {
			t.Fatalf("a bad duration must skip the container")
		}
		if !hasLevel(diags, Error) {
			t.Fatalf("want an error diagnostic, got %v", diags)
		}
	})

	t.Run("unset stays nil", func(t *testing.T) {
		lp, _ := ReadLabels(map[string]string{"airlock.enable": "true"})
		if lp.AlertWindow != nil {
			t.Errorf("AlertWindow = %v, want nil", lp.AlertWindow)
		}
	})
}

// TestModeAndScopeUnset proves Mode and Scope stay nil when the container
// never set them, and are non-nil pointers to the parsed value when it
// did.
func TestModeAndScopeUnset(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{"airlock.enable": "true"})
	if lp.Skipped {
		t.Fatalf("bare enable must not skip, diags=%v", diags)
	}
	if lp.Mode != nil {
		t.Errorf("Mode = %v, want nil (unset)", lp.Mode)
	}
	if lp.Scope != nil {
		t.Errorf("Scope = %v, want nil (unset)", lp.Scope)
	}

	lp2, diags2 := ReadLabels(map[string]string{
		"airlock.enable": "true",
		"airlock.mode":   "audit",
		"airlock.scope":  "all",
	})
	if lp2.Skipped {
		t.Fatalf("valid mode/scope must not skip, diags=%v", diags2)
	}
	if lp2.Mode == nil || *lp2.Mode != policy.Audit {
		t.Errorf("Mode = %v, want Audit", lp2.Mode)
	}
	if lp2.Scope == nil || *lp2.Scope != policy.All {
		t.Errorf("Scope = %v, want All", lp2.Scope)
	}
}

// TestPolicyRefs covers the csv-of-names collection, with existence
// validation explicitly deferred to a later layer.
func TestPolicyRefs(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{
		"airlock.enable": "true",
		"airlock.policy": "debian-updates,wordpress-core",
	})
	if lp.Skipped {
		t.Fatalf("valid policy refs must not skip, diags=%v", diags)
	}
	if len(lp.PolicyRefs) != 2 || lp.PolicyRefs[0] != "debian-updates" || lp.PolicyRefs[1] != "wordpress-core" {
		t.Errorf("PolicyRefs = %v, want [debian-updates wordpress-core]", lp.PolicyRefs)
	}
}

// TestNameCopiedThrough proves airlock.name is copied verbatim with no
// validation.
func TestNameCopiedThrough(t *testing.T) {
	lp, _ := ReadLabels(map[string]string{"airlock.enable": "true", "airlock.name": "renovate"})
	if lp.Name != "renovate" {
		t.Errorf("Name = %q, want renovate", lp.Name)
	}
}

// TestZeroEgressOneLabel proves the strongest declaration in the
// grammar: enable=true with nothing else is a clean, valid,
// zero-diagnostic parse (default-deny floor, no allow rules at all).
func TestZeroEgressOneLabel(t *testing.T) {
	lp, diags := ReadLabels(map[string]string{"airlock.enable": "true"})
	if lp.Skipped {
		t.Fatalf("bare enable=true must not skip, diags=%v", diags)
	}
	if !lp.Enable {
		t.Errorf("Enable = false, want true")
	}
	if len(lp.Allow) != 0 || lp.AllowNone {
		t.Errorf("Allow = %v AllowNone = %v, want empty/false (implicit default-deny, not the explicit none sentinel)", lp.Allow, lp.AllowNone)
	}
	if len(diags) != 0 {
		t.Errorf("diags = %v, want none", diags)
	}
}
