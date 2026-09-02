// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package engine

import (
	"net/netip"
	"time"

	"github.com/tagwright/airlock/internal/policy"
)

// Class is the violation classification the frozen "Airlock Label Grammar
// (Draft)" defines under Fork 6: the third element of the alert identity
// tuple. It exists to tell "this was explicitly denied," "this simply
// wasn't declared," and "this is the exfiltration shape (a bare IP with no
// name evidence at all)" apart, since an operator reads those three very
// differently even though all three are, mechanically, "not allowed."
type Class int

const (
	// ClassDeny is a connection that matched an explicit deny rule. Deny
	// beats allow beats the default-deny floor, so this class always wins
	// when it applies.
	ClassDeny Class = iota
	// ClassNoMatch is a connection that fell through the default-deny
	// floor (no deny matched, no allow matched) but DID carry name
	// evidence (a DNS or SNI correlation existed for it). The
	// destination was simply never declared.
	ClassNoMatch
	// ClassUnresolvedIP is a connection that fell through the
	// default-deny floor with NO name evidence at all: no DNS answer in
	// this container's cache for the destination IP, and no SNI observed
	// for this container within the correlation window. This is the
	// exfiltration shape called out in the frozen doc's honesty section,
	// and it is deliberately its own class rather than folded into
	// no-match: there is no "ignore unresolved" knob, the escape is to
	// allowlist the IP or CIDR explicitly.
	ClassUnresolvedIP
)

// String returns the exact lowercase, hyphenated spelling the frozen doc
// uses for each class ("deny", "no-match", "unresolved-ip"). Alert text and
// the digest should use this spelling verbatim so operators can grep for it
// against the docs.
func (c Class) String() string {
	switch c {
	case ClassDeny:
		return "deny"
	case ClassNoMatch:
		return "no-match"
	case ClassUnresolvedIP:
		return "unresolved-ip"
	default:
		return "unknown"
	}
}

// Identity is the alert dedup tuple defined by Fork 6: (service name,
// destination identity, destination port, violation class). Ephemeral
// source ports never appear in it. It is a plain comparable struct so an
// alert layer can use it directly as a map key for windowed suppression
// and counting.
type Identity struct {
	Service     string
	Destination string
	Port        uint16
	Class       Class
}

// Violation is one classified policy deviation produced by evaluating a
// single observed Connection event. The engine emits at most one Violation
// per Connection (evaluation is at connect time only, per the frozen doc),
// never a stream of them for one connection.
type Violation struct {
	// Service is the policy's declared service identity
	// (policy.Policy.Name): airlock.name, else the compose service label,
	// else the container name. This is the first element of Identity.
	Service string

	// Destination is the best available HUMAN-FACING identity for where
	// the connection went: SNI when present (it is evidence on the
	// connection itself, and the more specific of the two for display),
	// else the DNS-cache name, else the literal destination IP string.
	// This is purely a display/dedup label -- it is NOT the name evidence
	// that decided this connection's allow/deny outcome, which is always
	// the DNS-cache correlation alone (see match.go's fail-closed-on-SNI
	// doc comment); DNSName/SNIName below carry the two sources
	// separately for a reader who wants to see exactly what was known.
	// This is the second element of Identity, and what an alert reads as
	// "connected to X."
	Destination string

	// Port is the connection's destination port. Third element of
	// Identity.
	Port uint16

	// Class is the violation classification. Fourth element of Identity.
	Class Class

	// DstIP is the raw destination address of the underlying connection,
	// always populated regardless of Destination (which may be a name).
	DstIP netip.Addr

	// ContainerID and ContainerName identify the container that made the
	// connection, carried straight through from the triggering
	// observe.Event so alerts can disambiguate replicas that share one
	// Service identity.
	ContainerID   string
	ContainerName string

	// Timestamp is the connection's observed time, carried through from
	// the triggering observe.Event.
	Timestamp time.Time

	// Mode is the container's resolved policy.Mode (Audit or Alert) at
	// evaluation time. The engine evaluates identically regardless of
	// mode; Mode exists on Violation purely so the alert layer knows
	// whether this one routes to an immediate alert or to the digest
	// only, per Fork 2 -- that routing decision is that layer's job, not
	// this package's.
	Mode policy.Mode

	// DNSName and SNIName are the raw name evidence found for this
	// connection, independently, even when only one of them (or neither)
	// contributed to Destination. Kept so an alert can show "SNI said X,
	// DNS said Y" on a disagreement, per the frozen doc's honesty
	// section. Empty when that source had no evidence.
	DNSName string
	SNIName string
}

// Identity returns the alert dedup tuple for this violation.
func (v Violation) Identity() Identity {
	return Identity{
		Service:     v.Service,
		Destination: v.Destination,
		Port:        v.Port,
		Class:       v.Class,
	}
}
