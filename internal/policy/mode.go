// SPDX-License-Identifier: GPL-3.0-or-later

package policy

import "fmt"

// Mode is the action airlock takes on a policy violation: what it DOES,
// never what egress is legitimate (that is Policy's Allow/Deny/Scope). This
// separation is deliberate -- it is what lets a future enforcement backend
// flip a container from observe-only to blocking without any change to the
// declared policy itself.
type Mode int

const (
	// Audit evaluates the policy exactly as Alert does, but routes every
	// would-be violation to the digest only. No immediate alerts fire.
	// This is the onboarding state for a newly enabled container.
	Audit Mode = iota
	// Alert evaluates the policy and fires immediate alerts on the first
	// occurrence of a new violation identity, with windowed suppression
	// of repeats. This is the default posture for an armed container.
	Alert
	// Block is RESERVED in v1. It names the future enforcement action,
	// but ParseMode always rejects it: no backend available to airlock
	// today can enforce a block, and a mode that silently fell back to
	// Alert would misrepresent what the tool is actually doing to an
	// operator who explicitly asked for enforcement. Block becomes
	// selectable only when an enforcement-capable backend exists, and
	// even then it is never valid on an Inspektor-Gadget-only install.
	Block
)

// String returns the lowercase label used in labels and airlock.yml. It is
// meant for logging and error messages, not for parsing; use ParseMode for
// that direction. Block still stringifies (rather than panicking or
// returning "unknown") so error messages that need to name the rejected
// value can do so, even though ParseMode never returns Block on success.
func (m Mode) String() string {
	switch m {
	case Audit:
		return "audit"
	case Alert:
		return "alert"
	case Block:
		return "block"
	default:
		return "unknown"
	}
}

// ParseMode parses the airlock.mode / groups[].mode enum value. "block" is
// syntactically recognized but always rejected: it is reserved for a future
// enforcement-capable backend and must never be silently downgraded to
// Alert, so ParseMode reports it as a validation error rather than
// returning Block. Any other unrecognized value is likewise an error --
// unknown enum values are validation errors throughout this grammar, never
// ignored.
func ParseMode(s string) (Mode, error) {
	switch s {
	case "audit":
		return Audit, nil
	case "alert":
		return Alert, nil
	case "block":
		return 0, fmt.Errorf("mode %q is reserved for a future enforcement-capable backend and is not valid in v1: airlock only observes and alerts, it never blocks traffic, and this is never silently downgraded to alert", s)
	default:
		return 0, fmt.Errorf("invalid mode %q: must be one of audit, alert, block", s)
	}
}
