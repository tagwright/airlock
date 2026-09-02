// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package policy

import "time"

// Policy is a single container's fully RESOLVED egress policy: the shape
// later layers produce after merging a container's own labels, any named
// policy sets it references (airlock.yml, Fork 5), and every matching
// group's rules (airlock.yml, Fork 8), per that merge's rules -- list
// fields union across every applicable source, scalar fields resolve by
// specificity, and a same-tier scalar conflict is a validation error
// raised during merge, not representable in this struct.
//
// This package defines the struct only; building one from labels, policy
// sets, and groups belongs to the config/label-reading layer built on top
// of this vocabulary.
type Policy struct {
	// Name is the stable service identity used in alerts and dedup:
	// airlock.name, else the compose service label, else the container
	// name.
	Name string

	// Enable reports whether this container's policy is armed for
	// evaluation and alerting, whether by its own airlock.enable=true or
	// by a matching group that was not opted out of. A resolved Policy
	// with Enable false is never evaluated.
	Enable bool

	Mode  Mode
	Scope Scope

	// Allow and Deny are the union of every applicable source's entries.
	// Deny beats Allow beats the default-deny floor.
	Allow []Entry
	Deny  []Entry

	// AlertWindow is the dedup window per alert identity (service,
	// destination, port, class). The only per-container alert tunable in
	// v1 (airlock.alert.window).
	AlertWindow time.Duration
}
