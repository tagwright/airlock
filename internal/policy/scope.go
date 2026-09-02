// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package policy

import "fmt"

// Scope selects which observed connections a policy judges at all: the
// question of what counts as egress in the first place, independent of
// which destinations are allowed.
type Scope int

const (
	// External judges connections leaving the runtime's own container
	// networks (the LAN included) and excludes loopback, which is never
	// egress. This is the default: it keeps a container's first
	// allowlist about the outside world.
	External Scope = iota
	// All additionally judges container-to-container connections on the
	// runtime's own networks, the lateral-movement declaration. It is
	// opt-in per container because it demands enumerating every internal
	// link a container legitimately makes.
	All
)

// String returns the lowercase label used in labels and airlock.yml.
func (s Scope) String() string {
	switch s {
	case External:
		return "external"
	case All:
		return "all"
	default:
		return "unknown"
	}
}

// ParseScope parses the airlock.scope / groups[].scope enum value. Any
// value other than "external" or "all" is a validation error -- unknown
// enum values are never ignored in this grammar.
func ParseScope(s string) (Scope, error) {
	switch s {
	case "external":
		return External, nil
	case "all":
		return All, nil
	default:
		return 0, fmt.Errorf("invalid scope %q: must be one of external, all", s)
	}
}
