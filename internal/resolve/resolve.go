// SPDX-License-Identifier: GPL-3.0-or-later

// Package resolve is the merge heart of airlock: it takes one container's
// own declared label policy (internal/discovery), the airlock.yml groups
// (Fork 8) that match that container, and the named policy sets (Fork 5)
// the label and those groups reference, and merges them into ONE resolved
// per-container policy plus diagnostics.
//
// Resolve is a pure function of its three inputs -- a runtime.Container, a
// discovery.LabelPolicy, and a *config.Config -- with no socket, no
// network I/O, and no clock dependency, so it is unit-testable with
// nothing but in-code fixtures.
//
// The specificity ladder, highest to lowest, follows the frozen "Airlock
// Label Grammar (Draft)"'s Fork 8 section exactly where it speaks:
//
//  1. The container's own labels (tierLabel). A referenced policy set
//     (airlock.policy) travels at this SAME tier, since referencing a set
//     is itself a per-container act (Fork 5); the label's own direct
//     value wins over its referenced sets when both are present, and an
//     unresolved conflict between two referenced sets with no label
//     override is a sticky Error.
//  2. A group matched by compose_project or by a label selector
//     (tierIdentityGroup). The frozen doc explicitly ties these two
//     dimensions at one tier: "both identity-based, naming a specific
//     known set of containers." A group's own referenced policy sets
//     travel at the group's tier by the same label-over-set logic as (1).
//  3. A group matched by network (tierNetworkGroup): "structural only, no
//     identity signal."
//  4. A group with an empty match block, the catch-all/wildcard tier
//     (tierCatchAllGroup).
//  5. Fleet-wide defaults (cfg.Defaults), used only when nothing above
//     contributed a value at all.
//
// Two sources at the SAME tier disagreeing on a scalar is a sticky Error
// diagnostic, never silent last-writer-wins, per the frozen doc's
// "specificity ladder" and "same-tier conflict is a config-load error"
// language (Fork 8) and Fork 5's inter-set conflict rule.
//
// List fields (Allow, Deny) are a pure union across every applicable
// source -- the container's own label entries, every matching group's
// entries, and every referenced policy set (by the label and by every
// matching group) -- with no precedence, per Fork 8's "list-valued fields
// union across every source that applies."
//
// Tokens (@self, @project, net:<name>) are carried through symbolically in
// the resolved Allow/Deny lists. Resolving them against live network data
// belongs to the later policy engine, not here.
//
// See "Airlock Label Grammar (Draft)" (ratified 2026-08-27) for the frozen
// contract this package implements. Several judgment calls this package
// makes where that document is silent, or where it settles the shape but
// not a mechanical procedure, are called out on the relevant function or
// type below.
package resolve

import (
	"fmt"
	"strings"
	"time"

	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/discovery"
	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/core/runtime"
)

// Specificity tiers, lowest number wins. See the package doc comment for
// the full reasoning. tierDefaults is a fallback only: it never
// participates in same-tier conflict detection, since cfg.Defaults is
// always a single value, never multiple competing sources.
const (
	tierLabel = iota
	tierIdentityGroup
	tierNetworkGroup
	tierCatchAllGroup
	tierDefaults
)

// Resolved is the outcome of merging one container's label policy, the
// airlock.yml groups that match it, and the policy sets those reference.
type Resolved struct {
	// Armed reports whether this container's policy is evaluated and
	// alerted on at all: the winning value of the Enable axis, resolved
	// by the same specificity ladder as every other scalar. Policy is
	// meaningful only when Armed is true; an unarmed container is still
	// observed (per the global observation scope), just never
	// policy-alerted.
	Armed bool

	// Policy is the fully resolved egress policy. Zero value when Armed
	// is false.
	Policy policy.Policy

	// MatchedGroups names every airlock.yml group whose Match selected
	// this container, in cfg.Groups order, regardless of whether that
	// group ultimately contributed a winning value to anything (a group
	// can match and still lose every scalar tie to a higher-specificity
	// source). This is a debugging/trace aid for a future `airlock
	// status`, not part of the merge result itself.
	MatchedGroups []string
}

// matchedGroup pairs one matching config.Group with the specificity tier
// its Match dimension places it at.
type matchedGroup struct {
	group config.Group
	tier  int
}

// Resolve merges c's own declared label policy lp with every airlock.yml
// group in cfg that matches c, and every named policy set the label or a
// matching group references, into one Resolved outcome plus every
// diagnostic produced along the way.
//
// JUDGMENT CALL (flagged for doc reconciliation): when the resolved Enable
// axis is false, Resolve returns immediately without computing Mode,
// Scope, AlertWindow, Allow, or Deny, and therefore without validating an
// unarmed container's policy-shaped labels or group references at all
// (an unknown policy-set name, say, goes unreported). The frozen doc does
// not say whether an unarmed container's broken policy declaration should
// still surface a diagnostic. This mirrors discovery.ReadLabels' own
// shape (the declared-but-unarmed warning is the one thing that always
// fires regardless of arming; everything else about the declaration is
// moot once unarmed) and keeps an unarmed container cheap to resolve, but
// it means a typo'd airlock.policy reference on a never-armed container is
// currently silent beyond the existing "declared but unarmed" warning
// discovery.ReadLabels already produced.
func Resolve(c runtime.Container, lp discovery.LabelPolicy, cfg *config.Config) (Resolved, []discovery.Diagnostic) {
	var diags []discovery.Diagnostic

	var matched []matchedGroup
	var matchedNames []string
	for _, g := range cfg.Groups {
		if groupMatches(g, c) {
			matched = append(matched, matchedGroup{group: g, tier: groupTier(g)})
			matchedNames = append(matchedNames, g.Name)
		}
	}

	// --- Enable / arming ---------------------------------------------
	//
	// JUDGMENT CALL: PolicySet carries no Enable field at all (arming is
	// never a reusable-set concern in the frozen doc's schema), so unlike
	// Mode/Scope/AlertWindow below, Enable has no set-derived
	// contributions to gather -- only the label's own airlock.enable and
	// each matching group's own Enable field.
	var enableContribs []tierValue[bool]
	if !lp.Skipped && lp.EnableSet {
		enableContribs = append(enableContribs, tierValue[bool]{tierLabel, "container label airlock.enable", lp.Enable})
	}
	for _, mg := range matched {
		if mg.group.Enable != nil {
			enableContribs = append(enableContribs, tierValue[bool]{mg.tier, groupSource(mg.group), bool(*mg.group.Enable)})
		}
	}
	armed, _, enableDiag := resolveScalar("enable", enableContribs)
	if enableDiag != nil {
		diags = append(diags, *enableDiag)
	}
	if !armed {
		return Resolved{Armed: false, MatchedGroups: matchedNames}, diags
	}

	// --- Mode -----------------------------------------------------------
	var modeContribs []tierValue[policy.Mode]
	if !lp.Skipped {
		if lp.Mode != nil {
			modeContribs = append(modeContribs, tierValue[policy.Mode]{tierLabel, "container label airlock.mode", *lp.Mode})
		} else {
			for _, ns := range lookupSets(lp.PolicyRefs, cfg, "container label airlock.policy", &diags) {
				if ns.set.Mode == "" {
					continue
				}
				m, err := policy.ParseMode(ns.set.Mode)
				if err != nil {
					diags = append(diags, errDiag(fmt.Sprintf("policy set %q mode: %v", ns.name, err)))
					continue
				}
				modeContribs = append(modeContribs, tierValue[policy.Mode]{tierLabel, setSource(ns.name, "label"), m})
			}
		}
	}
	for _, mg := range matched {
		if mg.group.Mode != "" {
			m, err := policy.ParseMode(mg.group.Mode)
			if err != nil {
				diags = append(diags, errDiag(fmt.Sprintf("%s mode: %v", groupSource(mg.group), err)))
				continue
			}
			modeContribs = append(modeContribs, tierValue[policy.Mode]{mg.tier, groupSource(mg.group), m})
			continue
		}
		for _, ns := range lookupSets(mg.group.Policy, cfg, fmt.Sprintf("%s policy", groupSource(mg.group)), &diags) {
			if ns.set.Mode == "" {
				continue
			}
			m, err := policy.ParseMode(ns.set.Mode)
			if err != nil {
				diags = append(diags, errDiag(fmt.Sprintf("policy set %q mode: %v", ns.name, err)))
				continue
			}
			modeContribs = append(modeContribs, tierValue[policy.Mode]{mg.tier, setSource(ns.name, groupSource(mg.group)), m})
		}
	}
	mode, modeOK, modeDiag := resolveScalar("mode", modeContribs)
	if modeDiag != nil {
		diags = append(diags, *modeDiag)
	}
	if !modeOK {
		mode = defaultMode(cfg, &diags)
	}

	// --- Scope ------------------------------------------------------------
	var scopeContribs []tierValue[policy.Scope]
	if !lp.Skipped {
		if lp.Scope != nil {
			scopeContribs = append(scopeContribs, tierValue[policy.Scope]{tierLabel, "container label airlock.scope", *lp.Scope})
		} else {
			for _, ns := range lookupSets(lp.PolicyRefs, cfg, "container label airlock.policy", &diags) {
				if ns.set.Scope == "" {
					continue
				}
				sc, err := policy.ParseScope(ns.set.Scope)
				if err != nil {
					diags = append(diags, errDiag(fmt.Sprintf("policy set %q scope: %v", ns.name, err)))
					continue
				}
				scopeContribs = append(scopeContribs, tierValue[policy.Scope]{tierLabel, setSource(ns.name, "label"), sc})
			}
		}
	}
	for _, mg := range matched {
		if mg.group.Scope != "" {
			sc, err := policy.ParseScope(mg.group.Scope)
			if err != nil {
				diags = append(diags, errDiag(fmt.Sprintf("%s scope: %v", groupSource(mg.group), err)))
				continue
			}
			scopeContribs = append(scopeContribs, tierValue[policy.Scope]{mg.tier, groupSource(mg.group), sc})
			continue
		}
		for _, ns := range lookupSets(mg.group.Policy, cfg, fmt.Sprintf("%s policy", groupSource(mg.group)), &diags) {
			if ns.set.Scope == "" {
				continue
			}
			sc, err := policy.ParseScope(ns.set.Scope)
			if err != nil {
				diags = append(diags, errDiag(fmt.Sprintf("policy set %q scope: %v", ns.name, err)))
				continue
			}
			scopeContribs = append(scopeContribs, tierValue[policy.Scope]{mg.tier, setSource(ns.name, groupSource(mg.group)), sc})
		}
	}
	scope, scopeOK, scopeDiag := resolveScalar("scope", scopeContribs)
	if scopeDiag != nil {
		diags = append(diags, *scopeDiag)
	}
	if !scopeOK {
		scope = defaultScope(cfg, &diags)
	}

	// --- AlertWindow --------------------------------------------------
	var windowContribs []tierValue[time.Duration]
	if !lp.Skipped {
		if lp.AlertWindow != nil {
			windowContribs = append(windowContribs, tierValue[time.Duration]{tierLabel, "container label airlock.alert.window", *lp.AlertWindow})
		} else {
			for _, ns := range lookupSets(lp.PolicyRefs, cfg, "container label airlock.policy", &diags) {
				if ns.set.AlertWindow == "" {
					continue
				}
				d, err := time.ParseDuration(ns.set.AlertWindow)
				if err != nil {
					diags = append(diags, errDiag(fmt.Sprintf("policy set %q alert.window: %v", ns.name, err)))
					continue
				}
				windowContribs = append(windowContribs, tierValue[time.Duration]{tierLabel, setSource(ns.name, "label"), d})
			}
		}
	}
	for _, mg := range matched {
		if mg.group.AlertWindow != "" {
			d, err := time.ParseDuration(mg.group.AlertWindow)
			if err != nil {
				diags = append(diags, errDiag(fmt.Sprintf("%s alert.window: %v", groupSource(mg.group), err)))
				continue
			}
			windowContribs = append(windowContribs, tierValue[time.Duration]{mg.tier, groupSource(mg.group), d})
			continue
		}
		for _, ns := range lookupSets(mg.group.Policy, cfg, fmt.Sprintf("%s policy", groupSource(mg.group)), &diags) {
			if ns.set.AlertWindow == "" {
				continue
			}
			d, err := time.ParseDuration(ns.set.AlertWindow)
			if err != nil {
				diags = append(diags, errDiag(fmt.Sprintf("policy set %q alert.window: %v", ns.name, err)))
				continue
			}
			windowContribs = append(windowContribs, tierValue[time.Duration]{mg.tier, setSource(ns.name, groupSource(mg.group)), d})
		}
	}
	window, windowOK, windowDiag := resolveScalar("alert.window", windowContribs)
	if windowDiag != nil {
		diags = append(diags, *windowDiag)
	}
	if !windowOK {
		window = defaultAlertWindow(cfg, &diags)
	}

	// --- Name -----------------------------------------------------------
	//
	// Service identity per the frozen doc: "each container gets a stable
	// service name, defaulting to the compose service label
	// (com.docker.compose.service), falling back to container name,
	// overridable with airlock.name." So the override (the label) is
	// checked FIRST, and the compose-service/container-name pair is the
	// fallback CHAIN behind it, compose service before container name.
	name := c.Service
	if name == "" {
		name = c.Name
	}
	if !lp.Skipped && lp.Name != "" {
		name = lp.Name
	}

	// --- Allow / Deny union, and the allow=none contradiction ------------
	allow, allowNone := collectEntries("allow", lp.Allow, lp.AllowNone, lp.Skipped, lp.PolicyRefs, cfg, matched, &diags)
	deny, _ := collectEntries("deny", lp.Deny, lp.DenyNone, lp.Skipped, lp.PolicyRefs, cfg, matched, &diags)

	if allowNone {
		if len(allow) > 0 {
			diags = append(diags, discovery.Diagnostic{
				Level:  discovery.Error,
				Sticky: true,
				Message: fmt.Sprintf(
					`allow=none declares zero egress, but %d allow entry(ies) are also contributed by a container label, a matching group, or a referenced policy set -- "none" is a declaration, not a filter, so this is contradictory, not a suppression`,
					len(allow)),
			})
		}
		// JUDGMENT CALL: the contradiction is surfaced via the sticky
		// Error diagnostic above, but the resolved Allow list still
		// honors the "none" declaration (zero entries) rather than the
		// union that contradicts it. This keeps the fail-safe,
		// default-deny character of the grammar: a broken merge should
		// never accidentally WIDEN what a container may reach, it should
		// narrow to the safer of the two conflicting declarations while
		// loudly saying so.
		allow = nil
	}

	return Resolved{
		Armed:         true,
		MatchedGroups: matchedNames,
		Policy: policy.Policy{
			Name:        name,
			Enable:      true,
			Mode:        mode,
			Scope:       scope,
			Allow:       allow,
			Deny:        deny,
			AlertWindow: window,
		},
	}, diags
}

// groupMatches reports whether c is selected by g's Match block, per the
// three co-equal targeting dimensions (Fork 8): compose_project, network,
// or a label selector, and the catch-all empty-Match tier. config.Group's
// own Validate already guarantees at most one dimension is set.
func groupMatches(g config.Group, c runtime.Container) bool {
	switch {
	case g.Match.ComposeProject != "":
		return c.Project == g.Match.ComposeProject
	case g.Match.Network != "":
		for _, n := range c.Networks {
			if n.Name == g.Match.Network {
				return true
			}
		}
		return false
	case len(g.Match.Labels) > 0:
		for k, v := range g.Match.Labels {
			if c.Labels[k] != v {
				return false
			}
		}
		return true
	default:
		// Empty Match: the wildcard/catch-all tier, matches every
		// container.
		return true
	}
}

// groupTier reports the specificity tier g's Match dimension places it at.
//
// JUDGMENT CALL, flagged for doc-sync: the frozen doc's Fork 8 specificity
// ladder ties compose_project- and label-selector-matched groups at ONE
// tier ("both identity-based, naming a specific known set of containers"),
// distinct from and above a network-matched group. This is what is
// implemented here. It does not create a separate tier for label-selector
// groups above compose_project groups.
func groupTier(g config.Group) int {
	switch {
	case g.Match.ComposeProject != "", len(g.Match.Labels) > 0:
		return tierIdentityGroup
	case g.Match.Network != "":
		return tierNetworkGroup
	default:
		return tierCatchAllGroup
	}
}

// groupSource renders a stable, human-readable name for a group, used in
// diagnostic messages.
func groupSource(g config.Group) string {
	return fmt.Sprintf("group %q", g.Name)
}

// setSource renders a stable, human-readable name for a policy set
// reference, naming both the set and what referenced it.
func setSource(setName, via string) string {
	return fmt.Sprintf("policy set %q (via %s)", setName, via)
}

// errDiag builds a sticky Error diagnostic, airlock's house rule for any
// validation problem that leaves part of a policy unevaluated: a skipped
// or misresolved declaration means a gap in coverage, which must re-fire
// in every digest until fixed.
func errDiag(msg string) discovery.Diagnostic {
	return discovery.Diagnostic{Level: discovery.Error, Sticky: true, Message: msg}
}

// tierValue is one candidate value for a scalar axis, tagged with the
// specificity tier its source occupies and a human-readable name for
// diagnostics.
type tierValue[T comparable] struct {
	tier   int
	source string
	val    T
}

// resolveScalar implements the specificity-ladder merge for one scalar
// axis: the value comes from the highest-specificity (lowest tier number)
// source(s) that set it at all. Two sources at the SAME winning tier
// disagreeing is a sticky Error diagnostic, per the frozen doc's "same-tier
// conflict is a config-load error" rule -- never silent last-writer-wins.
// ok is false when contribs is empty, so the caller knows to fall through
// to a global default.
func resolveScalar[T comparable](axis string, contribs []tierValue[T]) (val T, ok bool, diag *discovery.Diagnostic) {
	if len(contribs) == 0 {
		return val, false, nil
	}

	minTier := contribs[0].tier
	for _, c := range contribs[1:] {
		if c.tier < minTier {
			minTier = c.tier
		}
	}

	var sources []string
	for _, c := range contribs {
		if c.tier != minTier {
			continue
		}
		sources = append(sources, c.source)
		if !ok {
			val, ok = c.val, true
			continue
		}
		if c.val != val {
			return val, false, &discovery.Diagnostic{
				Level:   discovery.Error,
				Sticky:  true,
				Message: fmt.Sprintf("%s: conflicting values at the same specificity tier among %s", axis, strings.Join(sources, ", ")),
			}
		}
	}
	return val, ok, nil
}

// namedSet pairs a resolved config.PolicySet with the name it was
// referenced by, so callers can name it in a diagnostic.
type namedSet struct {
	name string
	set  config.PolicySet
}

// lookupSets resolves each name in policyNames against cfg.Policies,
// reporting a sticky Error diagnostic for any name that does not exist
// (Fork 5: "unknown set name is a validation error ... sticky"). Unknown
// names are skipped, not fatal to the rest of the merge.
func lookupSets(policyNames []string, cfg *config.Config, source string, diags *[]discovery.Diagnostic) []namedSet {
	var out []namedSet
	for _, name := range policyNames {
		ps, ok := cfg.Policies[name]
		if !ok {
			*diags = append(*diags, errDiag(fmt.Sprintf("%s references unknown policy set %q", source, name)))
			continue
		}
		out = append(out, namedSet{name: name, set: ps})
	}
	return out
}

// parseEntries parses every raw entry string with policy.ParseEntry,
// reporting a sticky Error diagnostic for any that fails rather than
// aborting the rest of the merge. airlock.yml's own Validate already
// parses group and policy-set entries at config-load time, so a failure
// here is defensive (config was somehow not validated), not the expected
// path.
func parseEntries(raw []string, source string, diags *[]discovery.Diagnostic) []policy.Entry {
	var out []policy.Entry
	for _, r := range raw {
		e, err := policy.ParseEntry(r)
		if err != nil {
			*diags = append(*diags, errDiag(fmt.Sprintf("%s: entry %q: %v", source, r, err)))
			continue
		}
		out = append(out, e)
	}
	return out
}

// entryListOf selects a config.Group's or config.PolicySet's Allow or Deny
// field by name, since collectEntries drives both fields through one code
// path.
func groupEntryList(g config.Group, field string) config.EntryList {
	if field == "allow" {
		return g.Allow
	}
	return g.Deny
}

func setEntryList(ps config.PolicySet, field string) config.EntryList {
	if field == "allow" {
		return ps.Allow
	}
	return ps.Deny
}

// collectEntries unions every source's entries for one list field ("allow"
// or "deny"): the container's own label entries, every matching group's
// direct entries, and every referenced policy set (by the label and by
// each matching group), de-duplicated by canonical string form. No
// precedence, pure union, per Fork 8's list-merge rule.
//
// none reports whether ANY source declared the "none" zero-egress
// sentinel for this field: the label itself, or any matching group, or
// any referenced policy set. Only the caller (for the "allow" field) acts
// on this to detect and report the Fork 5 none-vs-allow contradiction;
// "deny" has no such contradiction in the frozen grammar (deny=none has no
// defined meaning beyond an empty deny list) and callers may ignore the
// returned bool for that field.
func collectEntries(field string, lpEntries []policy.Entry, lpNone bool, lpSkipped bool, lpRefs []string, cfg *config.Config, matched []matchedGroup, diags *[]discovery.Diagnostic) (entries []policy.Entry, none bool) {
	seen := make(map[string]struct{})
	add := func(list []policy.Entry) {
		for _, e := range list {
			k := e.String()
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			entries = append(entries, e)
		}
	}

	if !lpSkipped {
		if lpNone {
			none = true
		} else {
			add(lpEntries)
		}
		for _, ns := range lookupSets(lpRefs, cfg, fmt.Sprintf("container label airlock.policy (%s)", field), diags) {
			el := setEntryList(ns.set, field)
			if el.None {
				none = true
				continue
			}
			add(parseEntries(el.Entries, fmt.Sprintf("policy set %q (via label)", ns.name), diags))
		}
	}

	for _, mg := range matched {
		gEntries := groupEntryList(mg.group, field)
		if gEntries.None {
			none = true
		} else {
			add(parseEntries(gEntries.Entries, groupSource(mg.group), diags))
		}
		for _, ns := range lookupSets(mg.group.Policy, cfg, fmt.Sprintf("%s policy (%s)", groupSource(mg.group), field), diags) {
			el := setEntryList(ns.set, field)
			if el.None {
				none = true
				continue
			}
			add(parseEntries(el.Entries, setSource(ns.name, groupSource(mg.group)), diags))
		}
	}

	return entries, none
}

// defaultMode parses cfg.Defaults.DefaultMode, which config.Load's own
// Validate already guarantees is one of "audit"/"alert". A parse failure
// here is defensive only (an unvalidated *config.Config was passed
// directly, bypassing config.Load) and falls back to Alert, the frozen
// doc's documented default posture, rather than propagating the error and
// leaving mode unset.
func defaultMode(cfg *config.Config, diags *[]discovery.Diagnostic) policy.Mode {
	m, err := policy.ParseMode(cfg.Defaults.DefaultMode)
	if err != nil {
		*diags = append(*diags, errDiag(fmt.Sprintf("defaults.default_mode: %v (falling back to alert)", err)))
		return policy.Alert
	}
	return m
}

// defaultScope mirrors defaultMode for cfg.Defaults.DefaultScope, falling
// back to External on a defensive parse failure.
func defaultScope(cfg *config.Config, diags *[]discovery.Diagnostic) policy.Scope {
	s, err := policy.ParseScope(cfg.Defaults.DefaultScope)
	if err != nil {
		*diags = append(*diags, errDiag(fmt.Sprintf("defaults.default_scope: %v (falling back to external)", err)))
		return policy.External
	}
	return s
}

// defaultAlertWindow mirrors defaultMode for cfg.Defaults.AlertWindow,
// falling back to one hour (the frozen doc's documented default) on a
// defensive parse failure.
func defaultAlertWindow(cfg *config.Config, diags *[]discovery.Diagnostic) time.Duration {
	d, err := time.ParseDuration(cfg.Defaults.AlertWindow)
	if err != nil {
		*diags = append(*diags, errDiag(fmt.Sprintf("defaults.alert_window: %v (falling back to 1h)", err)))
		return time.Hour
	}
	return d
}
