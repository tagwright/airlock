// SPDX-License-Identifier: GPL-3.0-or-later

// Package discovery turns one container's labels into a validated,
// per-container declaration of its egress policy: the dual-doorway label
// reader that realizes the frozen Airlock Label Grammar.
//
// It recognizes two label prefixes, "airlock." (primary) and
// "tagwright.egress." (org-namespaced alias), holding one canonical suffix
// grammar with two accepted spellings on the outside -- the same
// two-doorways-one-grammar shape ballast and bilgeline use, inherited
// verbatim per the grammar's Namespace section. ReadLabels is the pure
// entry point: it takes a plain label map and returns a LabelPolicy plus
// any Diagnostics, reading no state, executing no commands, and touching
// no socket, so it is unit-testable with nothing but a map literal.
//
// LabelPolicy is deliberately narrow: it is one container's OWN declared
// policy, parsed from its own labels only, before any group- or
// policy-set merge. Fields left unset (nil pointers, empty slices) mean
// "this container's labels did not weigh in on this axis," so a later
// resolve step can layer in a matching group's rules, a referenced named
// policy set, or a fleet-wide default without this package needing to
// know any of that exists. Building the fully resolved policy.Policy from
// a LabelPolicy plus airlock.yml's groups and policy sets is that later
// layer's job, not this package's.
//
// Diagnostic is airlock's validation-finding shape. It mirrors bilgeline's
// discovery.Diagnostic in spirit (a Level and a human Message) but adds a
// Sticky flag: airlock is a security tool, so a validation error that
// leaves a container's policy unevaluated -- meaning that container is
// unprotected -- must re-fire in every digest until fixed, not report
// once and go quiet the way a one-shot bilgeline provisioning error does.
// The "declared but unarmed" warning is sticky for the identical reason:
// silence about an unprotected container is unacceptable in this suite.
// Container identity (which container a Diagnostic is about) is stamped
// by the caller once it has one; this package's Diagnostics are
// per-invocation only.
//
// See "Airlock Label Grammar (Draft)" (ratified 2026-08-27) for the frozen
// contract this package implements. The conflict rule, the unknown-suffix
// rule, and the "none" sentinel are all inherited from that grammar's
// suite-wide house style; nothing here may accept syntax that document
// does not define.
package discovery

// DiagLevel classifies a Diagnostic. Error means the affected container's
// declared policy could not be validated and must be skipped by the
// caller (LabelPolicy.Skipped will be true); Warning is a non-fatal
// notice that still leaves the rest of the parse usable.
type DiagLevel int

const (
	// Error marks a validation failure: a prefix conflict, an unknown
	// suffix, a bad entry, a reserved-and-rejected value, or any other
	// hard parse error. The whole container's declared policy must be
	// skipped, never partially applied.
	Error DiagLevel = iota
	// Warning marks a non-fatal notice, most notably the declared-but-
	// unarmed case: the rest of the parse is still usable.
	Warning
)

// String returns a stable lowercase name for the level, for logging and
// error messages, not for parsing.
func (l DiagLevel) String() string {
	switch l {
	case Error:
		return "error"
	case Warning:
		return "warning"
	default:
		return "unknown"
	}
}

// Diagnostic is one finding produced while reading a container's labels.
// It carries no container identity: the caller (which knows the
// container id and name) stamps that on before routing the finding to
// alerting.
type Diagnostic struct {
	// Level is Error (the policy must be skipped) or Warning (a notice).
	Level DiagLevel
	// Message is the human-readable explanation.
	Message string
	// Sticky marks a finding that must re-fire in every digest until
	// resolved, rather than being reported once. Every policy-affecting
	// validation Error and the declared-but-unarmed Warning are sticky:
	// a skipped or unarmed policy means an unprotected container, and
	// this suite's security-tool hardening of the house rule says that
	// is never allowed to go quiet.
	Sticky bool
}
