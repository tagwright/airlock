// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// splitCSV splits a comma-separated value, trimming whitespace and
// dropping empty elements. Mirrors the label grammar's own comma
// shorthand (see policy.ParseEntry's callers) so airlock.yml and a
// container's labels read the same way.
func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	fields := strings.Split(v, ",")
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// CSVList decodes an airlock.yml value that names a comma-separated list of
// identifiers -- groups[].policy (policy-set names) and match.label
// (key=value pairs) -- exactly the way the label grammar itself writes a
// csv value (see airlock.policy). It accepts either a bare scalar
// ("a,b,c", or a single "a" with no comma at all) or a native YAML
// sequence of strings, so an airlock.yml author can use whichever reads
// more naturally; the frozen grammar's own worked examples use the scalar
// form (`policy: "media-updates"`), so that stays canonical and is what
// MarshalYAML produces.
type CSVList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (c *CSVList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		*c = splitCSV(s)
		return nil
	}
	var list []string
	if err := value.Decode(&list); err != nil {
		return fmt.Errorf("expected a comma-separated string or a list of strings: %w", err)
	}
	*c = list
	return nil
}

// MarshalYAML implements yaml.Marshaler, always producing the canonical
// scalar csv form.
func (c CSVList) MarshalYAML() (any, error) {
	return strings.Join(c, ","), nil
}

// EntryList is an allow/deny value from airlock.yml: normally a YAML
// sequence of destination-entry-grammar strings (policy.ParseEntry parses
// each one), but the frozen grammar's own worked examples also write the
// literal scalar "none" in this exact position
// (`groups[].allow: "none"`), the zero-egress sentinel identical to the
// label grammar's `airlock.allow=none`. A plain []string cannot decode
// both shapes, so this type special-cases the "none" scalar and otherwise
// behaves like a normal string list.
//
// "none" is a property of the whole value, never one entry among others:
// UnmarshalYAML rejects any other bare scalar rather than silently
// treating it as a one-element list, the same non-negotiable rule
// policy.ParseEntry documents for ErrNoneSentinel.
type EntryList struct {
	// None is true when the value was the literal sentinel "none".
	None bool
	// Entries holds the raw entry strings when None is false. Each is
	// parsed with policy.ParseEntry at Validate time, not here --this
	// type only captures the YAML shape.
	Entries []string
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (e *EntryList) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		var s string
		if err := value.Decode(&s); err != nil {
			return err
		}
		if s == "none" {
			*e = EntryList{None: true}
			return nil
		}
		return fmt.Errorf(`allow/deny: scalar value %q is not valid here, only the literal "none" sentinel may appear as a scalar -- a real entry list must be a YAML list`, s)
	}
	var list []string
	if err := value.Decode(&list); err != nil {
		return fmt.Errorf("expected a list of entries, or the literal scalar \"none\": %w", err)
	}
	*e = EntryList{Entries: list}
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (e EntryList) MarshalYAML() (any, error) {
	if e.None {
		return "none", nil
	}
	return e.Entries, nil
}

// Empty reports whether the value carries no entries and is not the "none"
// sentinel either -- i.e. the field was left unset.
func (e EntryList) Empty() bool {
	return !e.None && len(e.Entries) == 0
}

// BoolFlag is a boolean value that decodes from either a native YAML bool
// (enable: true) or the quoted string spelling the frozen grammar's own
// worked examples use throughout airlock.yml (enable: "true"), matching
// the label grammar's "every label value is a string" convention that
// carries over into the group body's identically-named fields. A *BoolFlag
// field (see Group.Enable) keeps a nil pointer distinguishable from an
// explicit false, exactly like a native *bool would.
type BoolFlag bool

// UnmarshalYAML implements yaml.Unmarshaler.
func (b *BoolFlag) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode && value.Tag == "!!bool" {
		var v bool
		if err := value.Decode(&v); err != nil {
			return err
		}
		*b = BoolFlag(v)
		return nil
	}
	var raw string
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("expected true or false: %w", err)
	}
	switch raw {
	case "true":
		*b = true
	case "false":
		*b = false
	default:
		return fmt.Errorf("invalid boolean value %q: must be true or false", raw)
	}
	return nil
}

// MarshalYAML implements yaml.Marshaler, always producing the canonical
// quoted-string form the frozen grammar's own examples use.
func (b BoolFlag) MarshalYAML() (any, error) {
	if b {
		return "true", nil
	}
	return "false", nil
}

// parseLabelSelector parses a match.label csv value's "key=value" pairs
// into a map, per the frozen grammar: "a csv of key=value pairs is a
// logical AND across all of them."
func parseLabelSelector(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(pairs))
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("match.label: %q is not a valid key=value pair", p)
		}
		out[k] = v
	}
	return out, nil
}
