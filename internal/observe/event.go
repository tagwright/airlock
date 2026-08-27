// SPDX-License-Identifier: GPL-3.0-or-later

// Package observe defines a backend-neutral model for observing container
// egress activity: outbound connections, DNS answers, and TLS ClientHello
// SNI names. Concrete backends (for example an Inspektor Gadget adapter, or
// a future Rust/aya-based probe) implement Backend and emit a normalized
// stream of Event values.
//
// Nothing in this file, and nothing exported from this package, may
// reference a specific backend's vocabulary. That keeps airlock's
// correlation and policy layers usable against any backend that can be
// adapted to the Backend interface, including one that lives behind a
// process boundary this package never has to know about.
package observe

import (
	"net/netip"
	"time"
)

// EventKind discriminates which of Event's per-kind fields are populated.
type EventKind int

const (
	// Connection reports an outbound network connection attempt.
	Connection EventKind = iota
	// DNSAnswer reports a resolved DNS response carrying at least one
	// address answer.
	DNSAnswer
	// TLSHello reports a TLS ClientHello, most notably its SNI server
	// name.
	TLSHello
)

// String returns a lowercase, stable name for the kind. It is meant for
// logging and metrics labels, not for parsing.
func (k EventKind) String() string {
	switch k {
	case Connection:
		return "connection"
	case DNSAnswer:
		return "dns_answer"
	case TLSHello:
		return "tls_hello"
	default:
		return "unknown"
	}
}

// Event is a single normalized observation. Only the fields relevant to
// Kind are meaningful; fields belonging to other kinds are left at their
// zero value.
//
// Event intentionally carries no backend-specific raw payload: a backend
// adapter must translate everything airlock's correlation layer needs into
// these fields at parse time, so that a second backend (for example a
// future Rust/aya probe) can populate exactly the same struct without this
// package or its consumers knowing anything changed underneath.
type Event struct {
	Kind EventKind

	// ContainerID and ContainerName identify the container the observed
	// activity is attributed to. ContainerID should be the container
	// runtime's native identifier (e.g. Docker's long container ID).
	// Correlating a container ID to policy labels is out of scope for
	// this package; that is airlock's job, done against the runtime
	// directly.
	ContainerID   string
	ContainerName string

	// Timestamp is when the observation occurred, per the backend. It is
	// the zero time.Time if the backend could not determine it.
	Timestamp time.Time

	// -- Connection fields (Kind == Connection) --

	// DstIP and DstPort are the destination of an outbound connection
	// attempt. Proto names the transport, e.g. "tcp".
	DstIP   netip.Addr
	DstPort uint16
	Proto   string

	// -- DNSAnswer fields (Kind == DNSAnswer) --

	// QName is the domain name that was queried. Answers holds the
	// resolved addresses carried by the response. TTL and Nameserver are
	// best-effort and may be zero/empty if the backend does not surface
	// them.
	QName      string
	Answers    []netip.Addr
	TTL        time.Duration
	Nameserver string

	// -- TLSHello fields (Kind == TLSHello) --

	// SNIName is the server name from the TLS ClientHello. DstIP/DstPort
	// above are populated too when the backend's source for this event
	// exposes the connection's destination alongside the SNI name;
	// otherwise they are left zero.
	SNIName string
}

// Stat surfaces backend health and loss signals, independent of the
// observation stream itself. A backend should emit a Stat whenever it
// detects lost events on one of its sources, and whenever it restarts a
// crashed source, so that a consumer can treat sustained loss as a
// tamper/DoS signal rather than a silent gap in visibility.
type Stat struct {
	// Source identifies which underlying source of the backend this stat
	// concerns (a backend-defined label, e.g. the name of one of several
	// sources it multiplexes). It carries no meaning outside the
	// producing backend.
	Source string

	Time time.Time

	// DroppedEvents is the number of events known to have been lost on
	// this source since the backend started. Zero means either "none
	// lost" or "the backend cannot detect loss for this source" -- see
	// the backend's own documentation for which applies.
	DroppedEvents uint64

	// Restarts counts how many times this source's underlying process or
	// connection has been restarted after crashing or exiting
	// unexpectedly.
	Restarts uint64

	// Message is an optional human-readable note, e.g. why a restart
	// happened.
	Message string
}
