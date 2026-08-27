// SPDX-License-Identifier: GPL-3.0-or-later

package discovery

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tagwright/airlock/internal/policy"
)

// LabelPolicy is one container's OWN declared egress policy, parsed from
// its labels alone, before any group-scoped policy (Fork 8) or named
// policy-set (Fork 5) merge is applied. That merge -- folding in a
// matching group's rules and any referenced policy sets, resolving
// scalars by specificity and unioning lists -- is later "resolve" layer's
// job, built on top of this type; LabelPolicy only ever reflects what
// this one container's own labels say.
//
// Every optional field's zero value ("unset") is deliberately
// distinguishable from an explicit empty declaration, so a later merge
// step knows whether to fall through to a group or policy-set default:
//   - Mode and Scope are nil pointers when the container's labels did
//     not set them at all, non-nil when they did (even a value that maps
//     to the same underlying int as the zero enum member is still
//     distinguishable through the pointer).
//   - Allow and Deny are nil when no allow/deny label was present at
//     all, non-nil (possibly empty, see AllowNone/DenyNone) once one
//     was.
//   - AllowNone and DenyNone record the explicit "none" sentinel
//     (airlock.allow=none), which declares zero egress -- a real,
//     positive declaration -- distinctly from Allow being nil because no
//     allow label was present at all. A later merge must never let a
//     group or policy-set allowlist quietly override a container's own
//     explicit "none".
//   - AlertWindow is a nil pointer when unset.
type LabelPolicy struct {
	// Enable reports whether this container's own labels arm policy
	// evaluation (airlock.enable=true). It does not account for a
	// matching group's arming (Fork 8); that is the later resolve
	// layer's job.
	Enable bool
	// EnableSet reports whether an airlock.enable label was present at
	// all (true or false), as opposed to absent. It exists to drive the
	// declared-but-unarmed diagnostic and any later group-opt-out logic
	// (airlock.enable=false opts a container OUT of an armed group),
	// which both need to distinguish "explicitly false" from "never
	// set" even though Enable itself is false in both cases.
	EnableSet bool

	// Name is the container's declared service identity override
	// (airlock.name), copied through verbatim. Empty means the
	// container did not set one; the compose-service/container-name
	// fallback chain is the caller's job, this package does not see
	// compose metadata.
	Name string

	// Mode is the container's declared action-on-violation
	// (airlock.mode), or nil when unset. mode=block is always a
	// validation Error (reserved-and-rejected in v1, see policy.Mode)
	// and never reaches this field.
	Mode *policy.Mode
	// Scope is the container's declared observation scope
	// (airlock.scope), or nil when unset.
	Scope *policy.Scope

	// Allow is the container's own allow entries: the union of the
	// airlock.allow csv and the airlock.allow.<n> indexed escape hatch,
	// de-duplicated by canonical form. Nil when no allow label was
	// present, empty (still non-nil semantically via AllowNone) when
	// the "none" sentinel was used.
	Allow []policy.Entry
	// AllowNone reports whether airlock.allow was the explicit "none"
	// sentinel: a positive declaration of zero egress, not merely an
	// absent allow list.
	AllowNone bool

	// Deny is the container's own deny entries, same shape as Allow.
	Deny []policy.Entry
	// DenyNone reports whether airlock.deny was the explicit "none"
	// sentinel. The frozen grammar defines no behavioral meaning for
	// deny=none beyond "no explicit denies" (already Deny's zero
	// value), but the sentinel is still recognized and recorded here
	// rather than rejected, for symmetry and so a later layer can
	// distinguish "wrote deny=none on purpose" from "never wrote deny"
	// if it ever needs to.
	DenyNone bool

	// PolicyRefs is the csv of named policy-set names from
	// airlock.policy, collected but not yet validated against
	// airlock.yml -- confirming each name actually exists is the later
	// resolve layer's job, since this package never sees config.
	PolicyRefs []string

	// AlertWindow is the parsed airlock.alert.window duration, or nil
	// when unset.
	AlertWindow *time.Duration

	// Skipped is true when a conflict, an unknown suffix, or any other
	// hard parse error means this container's declared policy could not
	// be validated. A caller MUST discard the rest of this LabelPolicy's
	// fields when Skipped is true -- they are best-effort only, filled
	// in as far as parsing got, and must never be partially applied.
	// Every reason Skipped went true has a matching sticky Error
	// Diagnostic explaining why.
	Skipped bool
}

// ReadLabels is the pure, socket-free heart of this package: it parses
// one container's raw label map into a LabelPolicy plus every Diagnostic
// found along the way. It never mutates labels and never fails outright
// -- a validation problem is always a Diagnostic plus LabelPolicy.Skipped,
// never a returned error, so a caller processing a whole fleet can keep
// going through every other container regardless of what one container's
// labels contain.
//
// ReadLabels does not know or care whether the container is armed by a
// matching group elsewhere in airlock.yml (Fork 8); it reports only what
// this container's own labels declare, plus the declared-but-unarmed
// warning that applies to the per-container case specifically.
func ReadLabels(labels map[string]string) (LabelPolicy, []Diagnostic) {
	norm, diags, skip := normalizeLabels(labels)

	var lp LabelPolicy

	// enable: strict "true"/"false" per the grammar's boolean house
	// style. A present-but-invalid value is a validation error like any
	// other, sticky, and skips the container -- a malformed arming
	// label is exactly the kind of ambiguity this suite refuses to
	// guess through.
	if v, ok := norm["enable"]; ok && v != "" {
		switch v {
		case "true":
			lp.Enable, lp.EnableSet = true, true
		case "false":
			lp.Enable, lp.EnableSet = false, true
		default:
			diags = append(diags, Diagnostic{
				Level:   Error,
				Sticky:  true,
				Message: fmt.Sprintf("label %q: invalid boolean %q, want \"true\" or \"false\"", "enable", v),
			})
			skip = true
		}
	}
	// Absent leaves Enable=false, EnableSet=false: airlock.enable=false
	// is identical to absent in v1 for arming purposes, differing only
	// in EnableSet (a later group-opt-out layer needs to tell "silent"
	// from "explicitly declined" apart).

	// name: copied through verbatim, no validation.
	lp.Name = norm["name"]

	// mode: mode=block surfaces here as policy.ParseMode's own
	// reserved-value error, sticky and skipping, never silently
	// downgraded.
	if v, ok := norm["mode"]; ok && v != "" {
		m, err := policy.ParseMode(v)
		if err != nil {
			diags = append(diags, Diagnostic{Level: Error, Sticky: true, Message: fmt.Sprintf("label %q: %v", "mode", err)})
			skip = true
		} else {
			lp.Mode = &m
		}
	}

	// scope
	if v, ok := norm["scope"]; ok && v != "" {
		sc, err := policy.ParseScope(v)
		if err != nil {
			diags = append(diags, Diagnostic{Level: Error, Sticky: true, Message: fmt.Sprintf("label %q: %v", "scope", err)})
			skip = true
		} else {
			lp.Scope = &sc
		}
	}

	// policy: csv of policy-set names. Existence against airlock.yml is
	// validated later; splitCSV already drops empty tokens, so a stray
	// comma produces no bogus empty name.
	if v, ok := norm["policy"]; ok && v != "" {
		lp.PolicyRefs = splitCSV(v)
	}

	// alert.window
	if v, ok := norm["alert.window"]; ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			diags = append(diags, Diagnostic{Level: Error, Sticky: true, Message: fmt.Sprintf("label %q: invalid duration %q: %v", "alert.window", v, err)})
			skip = true
		} else {
			lp.AlertWindow = &d
		}
	}

	// allow / deny: csv plus the indexed escape hatch, unioned, with the
	// whole-value "none" sentinel handled before any comma splitting.
	allow, allowNone, aerr := parseEntryList(norm, "allow")
	if aerr != nil {
		diags = append(diags, Diagnostic{Level: Error, Sticky: true, Message: aerr.Error()})
		skip = true
	} else {
		lp.Allow, lp.AllowNone = allow, allowNone
	}

	deny, denyNone, derr := parseEntryList(norm, "deny")
	if derr != nil {
		diags = append(diags, Diagnostic{Level: Error, Sticky: true, Message: derr.Error()})
		skip = true
	} else {
		lp.Deny, lp.DenyNone = deny, denyNone
	}

	// Arming gate: a policy-bearing label present without enable=true is
	// a sticky warning, and fires independently of every other outcome
	// above -- even a container whose policy also failed to validate for
	// an unrelated reason is still, separately, declared-but-unarmed if
	// it never armed in the first place. Silence about an unprotected
	// container is unacceptable for a security tool.
	if policyBearingPresent(norm) && !lp.Enable {
		diags = append(diags, Diagnostic{
			Level:   Warning,
			Sticky:  true,
			Message: "policy declared but airlock.enable is not true, this container is observed but never policy-alerted",
		})
	}

	lp.Skipped = skip
	return lp, diags
}

// parseEntryList resolves one of "allow"/"deny" off the normalized label
// map: the whole-value "none" sentinel, the csv value, and the indexed
// "<key>.<n>" escape hatch, unioned and de-duplicated by canonical string
// form in stable order (csv entries first, then indexed entries in
// ascending index order).
//
// "none" declares the zero-egress sentinel and must appear ALONE: combined
// with any indexed entry for the same key, or as one entry among several
// comma-separated values, it is a validation error rather than a silent
// suppression, per policy.ErrNoneSentinel's contract and the frozen
// grammar's "none is a declaration, not a filter" rule.
func parseEntryList(norm map[string]string, key string) (entries []policy.Entry, isNone bool, err error) {
	raw := strings.TrimSpace(norm[key])
	indexed := indexedValues(norm, key)

	if raw == "none" {
		if len(indexed) > 0 {
			return nil, false, fmt.Errorf("label %q: the %q sentinel cannot be combined with %s.<n> entries", key, "none", key)
		}
		return nil, true, nil
	}

	var items []string
	items = append(items, splitCSV(norm[key])...)
	items = append(items, indexed...)
	if len(items) == 0 {
		return nil, false, nil
	}

	seen := make(map[string]struct{}, len(items))
	out := make([]policy.Entry, 0, len(items))
	for _, item := range items {
		e, perr := policy.ParseEntry(item)
		if perr != nil {
			if errors.Is(perr, policy.ErrNoneSentinel) {
				return nil, false, fmt.Errorf("label %q: entry %q: %q is the zero-egress sentinel and must appear alone, not combined with other entries", key, item, "none")
			}
			return nil, false, fmt.Errorf("label %q: %w", key, perr)
		}
		canon := e.String()
		if _, dup := seen[canon]; dup {
			continue
		}
		seen[canon] = struct{}{}
		out = append(out, e)
	}
	return out, false, nil
}
