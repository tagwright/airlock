// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/tagwright/airlock/internal/policy"
)

// Match is a Group's targeting block (Fork 8). Exactly one of
// ComposeProject, Network, or Label may be set: they are co-equal
// dimensions and combining more than one in a single group is a
// validation error, expressed instead as two groups unioned by the merge
// rule. An entirely empty Match (the zero value) is legal and matches
// every container, the wildcard/catch-all tier in the specificity ladder.
type Match struct {
	// ComposeProject matches com.docker.compose.project. The only
	// dimension that reaches a network_mode: service:X container, which
	// has no independent network attachment of its own.
	ComposeProject string `yaml:"compose_project,omitempty"`

	// Network matches containers attached to the named Docker or Podman
	// network.
	Network string `yaml:"network,omitempty"`

	// Label is the raw "key=value,key=value" selector as written in
	// airlock.yml. Labels holds it parsed into a map after Validate
	// runs; Label is kept alongside it for diagnostics and
	// round-tripping.
	Label  CSVList           `yaml:"label,omitempty"`
	Labels map[string]string `yaml:"-"`
}

// dimensions reports how many of the three targeting dimensions are set.
func (m Match) dimensions() int {
	n := 0
	if m.ComposeProject != "" {
		n++
	}
	if m.Network != "" {
		n++
	}
	if len(m.Label) > 0 {
		n++
	}
	return n
}

// Empty reports whether m has no dimension set at all -- the catch-all
// tier that matches every container.
func (m Match) Empty() bool {
	return m.dimensions() == 0
}

// Group is one named group-scoped policy rule from airlock.yml's "groups"
// list (Fork 8). It arms every container its Match selects without
// requiring a per-container airlock.enable label, and accepts every field
// a container's own labels can, under the identical field names.
type Group struct {
	// Name is required, an identifier for diagnostics: lowercase, no
	// commas, the same rule policy set names follow. Unlike a policy
	// set, a group has no other identity a container references by
	// name, but a stable name is still required for alerts and
	// diagnostics to name which group armed or misconfigured a
	// container.
	Name string `yaml:"name"`

	Match Match `yaml:"match,omitempty"`

	// Enable is a pointer so "unset" (inherit whatever a higher- or
	// lower-specificity source decides) is distinguishable from an
	// explicit "false" (which, in a group context, is not meaningful --
	// per-container airlock.enable=false is how a container opts OUT of
	// a group, a group itself has no symmetrical "never arm" value
	// worth writing). Accepted for schema completeness and forward
	// compatibility with the label grammar's own Enable pointer shape;
	// Validate does not reject Enable set to false on a group, since
	// that is functionally identical to omitting the group entirely
	// and is the author's call.
	//
	// The type is BoolFlag, not a native bool, because the frozen
	// grammar's own worked examples always write this value quoted
	// (`enable: "true"`), matching the label grammar's "every label
	// value is a string" convention carried over into the group body's
	// identically-named fields. BoolFlag accepts that quoted-string
	// spelling and a native YAML bool equally.
	Enable *BoolFlag `yaml:"enable,omitempty"`

	Mode   string    `yaml:"mode,omitempty"`
	Scope  string    `yaml:"scope,omitempty"`
	Policy CSVList   `yaml:"policy,omitempty"`
	Allow  EntryList `yaml:"allow,omitempty"`
	Deny   EntryList `yaml:"deny,omitempty"`

	// AlertWindow mirrors airlock.alert.window exactly, per the frozen
	// grammar's "identical field names" rule.
	AlertWindow string `yaml:"alert.window,omitempty"`
}

// validate checks one Group in isolation against the set of policy set
// names declared elsewhere in the same Config (policyNames), appending
// problems to errs and warnings to warns. It takes a pointer receiver
// because it populates g.Match.Labels as a side effect (parsed from
// g.Match.Label), and that parse result needs to survive the call.
func (g *Group) validate(idx int, policyNames map[string]struct{}, errs *[]error, warns *[]string) {
	label := fmt.Sprintf("groups[%d]", idx)
	if g.Name != "" {
		label = fmt.Sprintf("groups[%q]", g.Name)
	}

	if g.Name == "" {
		*errs = append(*errs, fmt.Errorf("%s: name is required", label))
	} else if !policySetNameRE.MatchString(g.Name) {
		*errs = append(*errs, fmt.Errorf("%s: name must be lowercase identifier characters only (letters, digits, hyphen, underscore), no commas", label))
	}

	if d := g.Match.dimensions(); d > 1 {
		*errs = append(*errs, fmt.Errorf("%s: match combines more than one targeting dimension (compose_project, network, label); express the combination as two groups instead, unioned by the merge rule", label))
	}

	labels, err := parseLabelSelector(g.Match.Label)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s.match: %w", label, err))
	}
	g.Match.Labels = labels

	for _, name := range g.Policy {
		if _, ok := policyNames[name]; !ok {
			*errs = append(*errs, fmt.Errorf("%s.policy: unknown policy set %q", label, name))
		}
	}

	if g.Mode != "" {
		if _, err := policy.ParseMode(g.Mode); err != nil {
			*errs = append(*errs, fmt.Errorf("%s.mode: %w", label, err))
		}
	}
	scopeIsAll := false
	if g.Scope != "" {
		s, err := policy.ParseScope(g.Scope)
		if err != nil {
			*errs = append(*errs, fmt.Errorf("%s.scope: %w", label, err))
		} else {
			scopeIsAll = s == policy.All
		}
	}

	validateEntryList(label+".allow", g.Allow, errs)
	validateEntryList(label+".deny", g.Deny, errs)

	if !scopeIsAll {
		if tok, ok := firstGroupToken(g.Allow, g.Deny); ok {
			*warns = append(*warns, fmt.Sprintf(
				"%s: entry %q has no effect unless scope is \"all\" (this group's scope is %q); @self, @project, and net:<name> only judge traffic that scope=all brings into scope",
				label, tok, effectiveScopeLabel(g.Scope)))
		}
	}

	if noOpWildcardAllow(g.Allow, g.Deny) {
		*warns = append(*warns, fmt.Sprintf(`%s: allow: "*" with no deny rules can never fire a violation, this is almost certainly a mistake`, label))
	}

	// The airlock.allow=none-versus-referenced-policy-set contradiction
	// (Fork 5) needs the resolved Policies map, which this method does
	// not have; it is checked by Config.Validate's
	// checkAllowNoneContradiction instead, after every group and policy
	// set here has already been validated in isolation.

	if g.AlertWindow != "" {
		if _, err := time.ParseDuration(g.AlertWindow); err != nil {
			*errs = append(*errs, fmt.Errorf("%s.alert.window: invalid duration %q: %w", label, g.AlertWindow, err))
		}
	}
}

// effectiveScopeLabel renders a group's own Scope field for a warning
// message, naming the value that will actually apply if nothing else
// overrides it. An empty Scope means the group did not set it here, so
// the eventual effective scope depends on the global default and any
// higher-specificity source, unknowable at config-load time -- the
// warning is phrased to stay honest about that.
func effectiveScopeLabel(scope string) string {
	if scope == "" {
		return "unset here, resolves from a higher-specificity source or the global default"
	}
	return scope
}

// firstGroupToken reports the first @self, @project, or net:<name> entry
// found across allow and deny, if any.
func firstGroupToken(allow, deny EntryList) (string, bool) {
	for _, raw := range allow.Entries {
		if isGroupToken(raw) {
			return raw, true
		}
	}
	for _, raw := range deny.Entries {
		if isGroupToken(raw) {
			return raw, true
		}
	}
	return "", false
}

// isGroupToken reports whether raw is one of the Fork 8 self-reference
// entry tokens: @self, @project, or net:<name>. It is a syntactic check
// only (used for the scope=all inertness warning before or regardless of
// whether the entry otherwise parses), not a substitute for
// policy.ParseEntry.
func isGroupToken(raw string) bool {
	return raw == "@self" || raw == "@project" || strings.HasPrefix(raw, "net:")
}
