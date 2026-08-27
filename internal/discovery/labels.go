// SPDX-License-Identifier: GPL-3.0-or-later

package discovery

import (
	"fmt"
	"sort"
	"strings"
)

// Recognized label prefixes. airlockPrefix is primary and leads all
// documentation and examples; tagwrightPrefix is the org-namespaced
// alias. Both carry the identical suffix grammar; see the Namespace
// section of the label grammar. This mirrors ballast's and bilgeline's
// two-doorways-one-grammar pattern.
const (
	airlockPrefix   = "airlock."
	tagwrightPrefix = "tagwright.egress."
)

// knownSuffixes is the v1 known-suffix set, the single source of truth
// for which scalar/csv canonical suffixes ReadLabels recognizes. Extend
// this map, not scattered switch statements elsewhere, when a new label
// is added to the grammar.
//
// "allow" and "deny" are recognized here as their csv form; the indexed
// "allow.<n>" / "deny.<n>" escape hatch is recognized separately by
// isIndexedListSuffix, since the set of valid indices is unbounded.
var knownSuffixes = map[string]bool{
	"enable":       true,
	"name":         true,
	"mode":         true,
	"scope":        true,
	"policy":       true,
	"allow":        true,
	"deny":         true,
	"alert.window": true,
}

// policyBearingSuffixes is the subset of knownSuffixes whose presence
// means a container has DECLARED a policy of some kind. Their presence
// without airlock.enable=true (or, later, a matching armed group) is the
// sticky "declared but unarmed" warning the grammar mandates. "enable"
// itself is deliberately excluded: it is the gate, not a declaration.
var policyBearingSuffixes = map[string]bool{
	"name":         true,
	"mode":         true,
	"scope":        true,
	"policy":       true,
	"allow":        true,
	"deny":         true,
	"alert.window": true,
}

// stripPrefix removes whichever recognized prefix key carries, returning
// the canonical suffix (e.g. "enable", "allow", "allow.0") and whether
// key was recognized at all. A key under a recognized prefix with an
// empty suffix (bare "airlock." itself) is not recognized.
func stripPrefix(key string) (string, bool) {
	if suffix, ok := strings.CutPrefix(key, airlockPrefix); ok && suffix != "" {
		return suffix, true
	}
	if suffix, ok := strings.CutPrefix(key, tagwrightPrefix); ok && suffix != "" {
		return suffix, true
	}
	return "", false
}

// splitIndexed reports whether suffix has the shape "<base>.<n>" for a
// non-negative integer n, returning base when it does. It is used both to
// recognize the allow.<n>/deny.<n> escape hatch as a known suffix and to
// collect their values in index order.
func splitIndexed(suffix string) (base string, ok bool) {
	idx := strings.LastIndexByte(suffix, '.')
	if idx < 0 {
		return "", false
	}
	base, numPart := suffix[:idx], suffix[idx+1:]
	if numPart == "" {
		return "", false
	}
	for _, r := range numPart {
		if r < '0' || r > '9' {
			return "", false
		}
	}
	return base, true
}

// isIndexedListSuffix reports whether suffix is the indexed escape hatch
// for one of the two list-valued fields, allow.<n> or deny.<n>.
func isIndexedListSuffix(suffix string) bool {
	base, ok := splitIndexed(suffix)
	return ok && (base == "allow" || base == "deny")
}

// isKnownSuffix reports whether suffix is a recognized v1 canonical
// suffix: a member of knownSuffixes, or the indexed allow/deny escape
// hatch. Any other suffix is a validation error per the frozen grammar's
// "unknown airlock.* suffixes are validation errors, not ignored" rule --
// this is what makes a typo like "airlock.alow" surface instead of
// silently disabling policy.
func isKnownSuffix(suffix string) bool {
	return knownSuffixes[suffix] || isIndexedListSuffix(suffix)
}

// normalizeLabels strips the two recognized prefixes off a container's
// labels and folds them into a single canonical-suffix -> value map,
// applying the frozen grammar's two structural rules as it goes:
//
//   - Conflict rule (inherited verbatim from ballast/bilgeline): the same
//     canonical suffix appearing under both airlock.* and
//     tagwright.egress.* with DIFFERENT values is a sticky Error
//     diagnostic, and the whole container's declared policy must be
//     skipped -- there is no silent precedence between the two prefixes.
//     The same value under both is harmless and folds in normally.
//   - Unknown-suffix rule: any recognized-prefix key whose suffix is not
//     in the v1 known set is a sticky Error diagnostic, and likewise
//     forces a skip, per the grammar's explicit "unknown airlock.*
//     suffixes are validation errors, not ignored" language -- a typo'd
//     key must never quietly disable the policy it was meant to declare.
//
// Keys are walked in sorted order so a conflict's error message (which
// names both label keys) is deterministic regardless of Go's randomized
// map iteration. The returned map is populated best-effort even when skip
// is true, so a caller inspecting a skipped container's diagnostics still
// has whatever could be read.
func normalizeLabels(labels map[string]string) (norm map[string]string, diags []Diagnostic, skip bool) {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	norm = make(map[string]string, len(keys))
	firstKey := make(map[string]string, len(keys))

	for _, k := range keys {
		suffix, ok := stripPrefix(k)
		if !ok {
			continue
		}

		if !isKnownSuffix(suffix) {
			diags = append(diags, Diagnostic{
				Level:   Error,
				Sticky:  true,
				Message: fmt.Sprintf("label %q: %q is not a recognized airlock.* suffix in v1, container's policy skipped", k, suffix),
			})
			skip = true
			continue
		}

		v := labels[k]
		if existingKey, seen := firstKey[suffix]; seen {
			if norm[suffix] != v {
				diags = append(diags, Diagnostic{
					Level:   Error,
					Sticky:  true,
					Message: fmt.Sprintf("label %q conflicts with %q: %q != %q, container's policy skipped", existingKey, k, norm[suffix], v),
				})
				skip = true
			}
			continue
		}

		norm[suffix] = v
		firstKey[suffix] = k
	}

	return norm, diags, skip
}

// policyBearingPresent reports whether norm carries any non-empty
// policy-bearing suffix: a plain member of policyBearingSuffixes, or an
// indexed allow.<n>/deny.<n> entry. It drives the declared-but-unarmed
// warning, which must fire regardless of whether the rest of the label
// set parses cleanly.
func policyBearingPresent(norm map[string]string) bool {
	for suffix, v := range norm {
		if v == "" {
			continue
		}
		if policyBearingSuffixes[suffix] || isIndexedListSuffix(suffix) {
			return true
		}
	}
	return false
}

// splitCSV splits a comma-separated label value, trimming whitespace and
// dropping empty elements. An absent or empty value yields nil.
func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	fields := strings.Split(v, ",")
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// indexedValues collects the "<prefix>.<n>" escape-hatch labels (e.g.
// allow.0, allow.1, ...) off norm, in ascending index order. norm here is
// already the folded suffix->value map, so this looks for keys of the
// exact shape "<prefix>.<n>", not raw label keys.
func indexedValues(norm map[string]string, prefix string) []string {
	type kv struct {
		idx int
		val string
	}
	var items []kv

	want := prefix + "."
	for k, v := range norm {
		rest, ok := strings.CutPrefix(k, want)
		if !ok {
			continue
		}
		n := 0
		for _, r := range rest {
			if r < '0' || r > '9' {
				n = -1
				break
			}
			n = n*10 + int(r-'0')
		}
		if n < 0 || rest == "" {
			continue
		}
		items = append(items, kv{n, v})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].idx < items[j].idx })

	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.val)
	}
	return out
}
