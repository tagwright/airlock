// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package config

import (
	"fmt"
	"regexp"
	"time"

	"github.com/tagwright/airlock/internal/policy"
)

// PolicySet is one named, reusable policy fragment from airlock.yml's
// "policies" map (Fork 5). A container references one or more by name via
// its airlock.policy label csv; a group references them the same way via
// groups[].policy. It carries the same fields a container's own labels
// can: Allow and Deny union across every referenced set plus the
// container's own entries, and the scalar fields resolve label over
// policy set over global default, per the frozen merge rule.
//
// Building a container's or group's RESOLVED policy.Policy by merging a
// PolicySet into it is the evaluation layer's job, not this package's --
// this type only holds what airlock.yml declared.
type PolicySet struct {
	Allow EntryList `yaml:"allow,omitempty"`
	Deny  EntryList `yaml:"deny,omitempty"`

	// Scope, Mode, and AlertWindow are optional scalar overrides. Empty
	// means "this set does not weigh in on this axis" -- resolution
	// against other sets and the container's own labels happens at
	// evaluation time; Validate here only checks that a set value, when
	// given, is one this grammar recognizes.
	Scope string `yaml:"scope,omitempty"`
	Mode  string `yaml:"mode,omitempty"`

	// AlertWindow mirrors the label suffix name exactly
	// (airlock.alert.window), per the frozen grammar's "identical field
	// names" rule for structure that mirrors a label one-to-one.
	AlertWindow string `yaml:"alert.window,omitempty"`
}

// policySetNameRE is the "ballast destination-name rule" the frozen
// grammar cites for policy set names: lowercase, no commas. Enforced here
// as lowercase identifier characters only (letters, digits, hyphen,
// underscore), starting with a letter or digit, which is stricter than
// "no commas" but stays inside it and matches every named example in the
// grammar (debian-updates, github-api, media-tier, wordpress-core).
var policySetNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// validate checks one named PolicySet in isolation (not against any
// container or group that might reference it). name is the map key it was
// declared under. It appends problems to errs and warnings to warns
// rather than returning early, so a bad config surfaces every fault at
// once.
func (p PolicySet) validate(name string, errs *[]error, warns *[]string) {
	if !policySetNameRE.MatchString(name) {
		*errs = append(*errs, fmt.Errorf("policies[%q]: name must be lowercase identifier characters only (letters, digits, hyphen, underscore), no commas", name))
	}

	validateEntryList(fmt.Sprintf("policies[%q].allow", name), p.Allow, errs)
	validateEntryList(fmt.Sprintf("policies[%q].deny", name), p.Deny, errs)

	if p.Scope != "" {
		if _, err := policy.ParseScope(p.Scope); err != nil {
			*errs = append(*errs, fmt.Errorf("policies[%q].scope: %w", name, err))
		}
	}
	if p.Mode != "" {
		if _, err := policy.ParseMode(p.Mode); err != nil {
			*errs = append(*errs, fmt.Errorf("policies[%q].mode: %w", name, err))
		}
	}
	if p.AlertWindow != "" {
		if _, err := time.ParseDuration(p.AlertWindow); err != nil {
			*errs = append(*errs, fmt.Errorf("policies[%q].alert.window: invalid duration %q: %w", name, p.AlertWindow, err))
		}
	}

	if noOpWildcardAllow(p.Allow, p.Deny) {
		*warns = append(*warns, fmt.Sprintf(`policies[%q]: allow: "*" with no deny rules can never fire a violation, this is almost certainly a mistake`, name))
	}
}

// validateEntryList parses every entry in an EntryList with
// policy.ParseEntry, skipping the "none" sentinel (which is not an entry
// at all -- see EntryList and policy.ErrNoneSentinel).
func validateEntryList(field string, l EntryList, errs *[]error) {
	if l.None {
		return
	}
	for _, raw := range l.Entries {
		if raw == "none" {
			*errs = append(*errs, fmt.Errorf(`%s: "none" may only appear alone as the whole value, not mixed into a list with other entries`, field))
			continue
		}
		if _, err := policy.ParseEntry(raw); err != nil {
			*errs = append(*errs, fmt.Errorf("%s: %w", field, err))
		}
	}
}

// noOpWildcardAllow reports the Fork 2 no-op-policy shape: an explicit
// "*" allow entry with no deny rules to carve anything back out, an armed
// policy that can never fire a violation.
func noOpWildcardAllow(allow, deny EntryList) bool {
	if allow.None || !deny.Empty() {
		return false
	}
	for _, raw := range allow.Entries {
		if raw == "*" {
			return true
		}
	}
	return false
}
