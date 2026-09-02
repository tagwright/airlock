// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

// Package engine is airlock's policy-evaluation engine: the security-
// critical core that turns the normalized observation stream
// (internal/observe) into classified Violations, against a resolved
// per-container policy (internal/policy) read live from a World.
//
// The engine does three jobs, in order of how the frozen "Airlock Label
// Grammar (Draft)" (ratified 2026-08-27) describes the observable surface:
//
//  1. Correlation: trace_tcp's Connection events are ground truth (a
//     destination IP, port, and TCP, at connect time), but trace_dns and
//     trace_sni are best-effort enrichment that no gadget joins to the
//     connection that used them. The engine does that join itself, per
//     container, with a DNS answer cache (dns.go) and a recent-SNI window
//     (sni.go), because a shared cross-container cache would let one
//     container's lookups launder another container's connections.
//  2. Scope classification: which connections a policy judges at all
//     (loopback never; the runtime's own container networks only under
//     Scope All; everything else, LAN included, under both scopes), plus
//     the implicit resolver-on-53 baseline.
//  3. Matching: resolving @self/@project/net:<name> tokens against live
//     World data and testing a connection's destination and name evidence
//     against a policy's Allow and Deny lists, deny beats allow beats the
//     default-deny floor, and classifying the result (deny, no-match, or
//     the exfiltration-shaped unresolved-ip when there was no trustworthy
//     name evidence at all).
//
// See world.go, violation.go, dns.go, sni.go, scope.go, and match.go for
// each piece, and the frozen doc's "What a rule can honestly promise"
// section for the reasoning this package is built against.
//
// # SNI is fail-closed: enrichment only, never a match input
//
// An earlier version of this package let a recent same-container SNI
// observation satisfy a Domain/DomainWildcard allow or deny entry,
// preferring it over a DNS-cache correlation on disagreement, and even
// briefly deferred a would-be violation's verdict to give a same-container
// SNI observed just after the connect a chance to rescue it (see git
// history for pending.go, since removed). A real integration pass
// reproduced why that is unsafe: trace_sni carries no destination IP at
// all, so it can only be tied to a Connection by same-container-plus-
// timing, and that timing-only join reproducibly misattributed one
// connection's SNI to a DIFFERENT, unrelated connection from the same
// container fired moments later -- concretely, a container's TWO rapid
// connections (one with a real SNI, one bare-IP with none) resulted in the
// bare-IP one being classified ALLOWED, because the first connection's SNI
// was still the temporally-closest record in the store when the second was
// evaluated. That is a false negative in a security tool: a genuinely
// disallowed connection silently marked allowed. See docs/TESTING.md for
// the full reproduction.
//
// Nate ratified fail-closed on SNI as the fix: a Domain/DomainWildcard
// entry -- allow or deny alike -- now matches a connection ONLY via a
// DNS-cache correlation for THIS container's own recent answers (a hard
// IP-to-name lookup, no timing involved). SNI is never consulted by
// matchEntry and can therefore never change a verdict, in either
// direction. sniStore and the TLSHello Process path still exist, and
// still matter: the observed SNI name, when there is one, is carried
// through on both Violation (DNSName/SNIName) and ObservedDest
// (Name/SNIName) purely as enrichment for a human reading an alert or a
// suggest line -- see buildViolation and observed.go's recordObserved.
// IP/CIDR/token/AnyDest entries are unaffected: they were never SNI-
// dependent to begin with, since they match ground-truth connection facts
// (the destination address) or live World data, not a name.
//
// UPDATE (integration pass 2): the no-match/unresolved-ip CLASSIFICATION
// of an already-produced default-deny-floor violation was, until this
// pass, still allowed to consider sniOK -- reasoned as harmless because
// classification never gates allow/deny. A live regression run proved
// that reasoning wrong: trace_sni's ClientHello for a connection always
// arrives strictly after that connection's own TCP handshake, which is
// strictly after the very Connection event evaluateConnection reacts to
// synchronously -- so an SNI record already in the store at that instant
// can only ever belong to an earlier connection from the same container,
// never the one being evaluated. That let one connection's real SNI
// silently downgrade an unrelated, immediately-following bare-IP
// connection from unresolved-ip (the frozen doc's named exfiltration
// shape) to the less-alarming no-match. Classification is now fail-closed
// on dnsOK alone, for the same reason dnsOK alone decides the match: see
// evaluateConnection's step (f) for the full account.
//
// One consequence: deferring a verdict to wait for a same-container SNI
// no longer has anything to accomplish (DNS precedes the connect, so
// DNS-based name matching is already available at connect time), so
// Process(Connection) now always returns its final verdict synchronously,
// at most one Violation, with no pending queue and no Flush call for a
// daemon to make.
//
// Concurrency: Engine is designed to be fed by exactly one goroutine
// calling Process in the order events were observed -- the daemon is
// expected to serialize its observation stream before handing events to
// the engine. Process still takes an internal lock so that a second
// goroutine may safely call the observed-egress recorder's
// ObservedSnapshot/Observed (see observed.go) concurrently with the single
// feeder goroutine.
package engine

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/airlock/internal/policy"
)

// Engine evaluates the observation stream against live policy state read
// from a World. The zero value is not usable; construct with New.
type Engine struct {
	world World

	mu  sync.Mutex
	dns map[string]*dnsCache
	sni map[string]*sniStore

	// observed is the bounded per-container observed-egress recorder (see
	// observed.go): every external, in-scope destination seen from a
	// container, armed or not, with the best name evidence available at
	// observation time. It is guarded by the SAME mu as the correlation
	// state above, not a dedicated mutex: recordObserved is only ever
	// called from within evaluateConnection, itself only ever reached from
	// Process, which already holds mu for its entire body, so folding the
	// recorder under the existing lock costs nothing on the hot path and
	// avoids a second lock a reader would otherwise need to acquire in the
	// right order relative to Process. ObservedSnapshot and Observed take
	// mu themselves for a reader on any other goroutine (a daemon's
	// periodic status-snapshot writer, in practice).
	observed map[string]*observedContainer
}

// New constructs an Engine reading live state from world.
func New(world World) *Engine {
	return &Engine{
		world:    world,
		dns:      make(map[string]*dnsCache),
		sni:      make(map[string]*sniStore),
		observed: make(map[string]*observedContainer),
	}
}

// Process consumes one normalized observation and returns the Violation(s)
// it produced: none for a DNSAnswer or TLSHello (they only update
// correlation state -- see the package doc comment's note on SNI being
// enrichment-only), and zero or one for a Connection, decided synchronously
// and finally right here (evaluation is at connect time only, per the
// frozen doc, so a Connection is judged exactly once, ever). An event of an
// unrecognized Kind is ignored.
//
// See the package doc comment for the single-feeder-goroutine assumption
// this method relies on for correlation ordering.
func (e *Engine) Process(ev observe.Event) []Violation {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch ev.Kind {
	case observe.DNSAnswer:
		e.recordDNS(ev)
		return nil
	case observe.TLSHello:
		// Enrichment only: recordSNI feeds sniStoreLookup's later reads
		// for the Violation/ObservedDest display fields, and never
		// anything matchEntry consults -- see the package doc comment.
		e.recordSNI(ev)
		return nil
	case observe.Connection:
		if v := e.evaluateConnection(ev); v != nil {
			return []Violation{*v}
		}
		return nil
	default:
		return nil
	}
}

// Forget releases a container's correlation state: its DNS cache, its SNI
// window, and its observed-egress recorder entries. A daemon should call
// this when the runtime reports a container removed, so long-lived fleets
// do not accumulate state for containers that no longer exist. Calling it
// for an unknown or already-forgotten container is a harmless no-op.
func (e *Engine) Forget(containerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.dns, containerID)
	delete(e.sni, containerID)
	delete(e.observed, containerID)
}

// recordDNS updates the answering container's DNS cache from ev. Answers
// with no qname or no addresses carry nothing to correlate and are
// ignored.
//
// BUG FIX (integration pass 2): a real trace_dns capture's "name" field is
// the wire-format QNAME, which always carries a trailing "." for a
// fully-qualified name (confirmed live: "example.com.", "www.wikipedia.org.").
// policy.ParseEntry's isValidDomain rejects any domain with a trailing dot
// (a trailing "." produces an empty final label), so no Domain/
// DomainWildcard entry a human can actually write in airlock.yml or a
// label ever carries one. Before this fix, dnsCache stored ev.QName
// verbatim, so ctx.dnsName in match.go always carried the trailing dot
// while every entry it was compared against never did -- strings.EqualFold
// then never matched, for ANY domain-based allow or deny, ever. This was
// invisible to every existing unit test (their qname fixtures are all
// hand-written without a trailing dot) and, before the fail-closed-on-SNI
// change, was masked entirely in practice: SNI (which never carries a
// trailing dot) still won a match on disagreement, so a real deployment's
// domain allow rules kept working by accident. Once SNI became
// enrichment-only, DNS-cache correlation became the ONLY path a
// Domain/DomainWildcard entry can match through, and this pass's
// regression re-run of run-detect.sh caught it immediately: the
// example.com connection, allowed by a real DNS answer and a real SNI
// ClientHello, was misclassified no-match instead of producing zero
// violations. Fixed by normalizing the qname once, here, at the single
// write path into the cache -- strings.TrimSuffix(_, ".") for the single
// trailing dot a wire-format FQDN carries, never more than one.
func (e *Engine) recordDNS(ev observe.Event) {
	qname := strings.TrimSuffix(ev.QName, ".")
	if qname == "" || len(ev.Answers) == 0 {
		return
	}
	ttl := ev.TTL
	if ttl < dnsTTLFloor {
		ttl = dnsTTLFloor
	}
	expiry := ev.Timestamp.Add(ttl)

	c := e.dns[ev.ContainerID]
	if c == nil {
		c = newDNSCache()
		e.dns[ev.ContainerID] = c
	}
	for _, a := range ev.Answers {
		c.put(a.Unmap(), qname, expiry)
	}
}

// recordSNI updates the container's recent-SNI window from ev. An event
// with no SNI name carries nothing to correlate and is ignored. See the
// package doc comment: this feeds enrichment display only, never a match
// decision.
func (e *Engine) recordSNI(ev observe.Event) {
	if ev.SNIName == "" {
		return
	}
	s := e.sni[ev.ContainerID]
	if s == nil {
		s = &sniStore{}
		e.sni[ev.ContainerID] = s
	}
	s.record(ev.SNIName, ev.Timestamp)
}

// dnsCacheLookup is a nil-safe read of one container's DNS cache: a
// container the engine has never seen a DNSAnswer for simply has no
// cache yet, which is "no name evidence," not an error.
func (e *Engine) dnsCacheLookup(containerID string, addr netip.Addr, now time.Time) (string, bool) {
	c := e.dns[containerID]
	if c == nil {
		return "", false
	}
	return c.lookup(addr, now)
}

// sniStoreLookup is a nil-safe read of one container's recent-SNI window.
// Its result is enrichment material for a Violation/ObservedDest's display
// fields ONLY -- see the package doc comment -- never an input to
// matchEntry.
func (e *Engine) sniStoreLookup(containerID string, now time.Time) (string, bool) {
	s := e.sni[containerID]
	if s == nil {
		return "", false
	}
	return s.lookup(now)
}

// evaluateConnection implements the crux of the engine: evaluation of one
// observed Connection against the container's resolved policy. The
// lettered steps below match the implementation brief's evaluation order
// exactly. It returns nil for an allowed, unarmed, or out-of-scope
// connection, or a single, final Violation for a deny match or a
// default-deny-floor violation. See the package doc comment for why SNI
// never influences this outcome.
func (e *Engine) evaluateConnection(ev observe.Event) *Violation {
	// (a) Resolve the container's policy. Unarmed or unknown means
	// observed but never policy-judged -- the connection may still be
	// worth recording for the observed-egress recorder below, just never
	// matched against Allow/Deny.
	pol, armed := e.world.ResolvedPolicy(ev.ContainerID)

	dst := ev.DstIP.Unmap()

	// (b) Scope classification: loopback is never egress; the runtime's
	// own container networks are out of scope under External and in
	// scope under All; everything else (the LAN included) is in scope
	// under both. An unarmed container has no resolved Scope of its own,
	// so the recorder uses the frozen doc's fleet-wide default (External)
	// for the same "keep the first allowlist about the outside world"
	// reason Scope defaults to External for an armed one -- see
	// recordObserved's callers below.
	if dst.IsLoopback() {
		return nil
	}
	nets := e.world.Networks()
	own := inOwnNetworks(nets, dst)
	scope := policy.External
	if armed {
		scope = pol.Scope
	}
	if own && scope == policy.External {
		return nil
	}

	// (c) Implicit resolver-on-53 baseline.
	if isImplicitResolver(e.world.ResolverIPs(), dst, ev.DstPort) {
		return nil
	}

	// (d) Name evidence. dnsName/dnsOK is a DNS-cache correlation for this
	// container's own recent answers: a hard IP-to-name lookup, and the
	// ONLY name evidence matchEntry ever consults (see the package doc
	// comment on fail-closed SNI). sniName/sniOK is looked up purely so it
	// can be carried through as enrichment on the Violation/ObservedDest
	// this connection produces; it never participates in matching. display
	// prefers SNI when both exist (it is evidence on the connection
	// itself, and the more specific of the two for a human reading the
	// alert), but that preference affects ONLY the human-facing
	// Destination/ObservedDest.Name label -- never the allow/deny outcome
	// or the no-match/unresolved-ip classification, both of which are
	// computed from dnsName/dnsOK alone below.
	dnsName, dnsOK := e.dnsCacheLookup(ev.ContainerID, dst, ev.Timestamp)
	sniName, sniOK := e.sniStoreLookup(ev.ContainerID, ev.Timestamp)
	display := dnsName
	if sniOK {
		display = sniName
	}

	if !armed {
		e.recordObserved(ev.ContainerID, ev.ContainerName, dst, ev.DstPort, ev.Proto, dnsName, sniName, ev.Timestamp, "observed")
		return nil
	}

	// (e) Match against the policy: deny beats allow beats the
	// default-deny floor. ctx.dnsName/hasDNSName is the ONLY name
	// evidence a Domain/DomainWildcard entry can match against -- see
	// match.go and the package doc comment. Tokens are resolved against
	// live World data only when the policy actually references them,
	// since those World calls may walk the runtime's container list.
	needsSelf, needsProject := policyNeedsTokens(pol)
	ctx := matchContext{
		dstIP:      dst,
		dstPort:    ev.DstPort,
		dnsName:    strings.ToLower(dnsName),
		hasDNSName: dnsOK,
		networks:   nets,
	}
	if needsSelf {
		ctx.selfSubnets = selfSubnets(nets, e.world.ContainerNetworks(ev.ContainerID))
	}
	if needsProject {
		ctx.projectPeers = e.world.ProjectPeerIPs(e.world.ContainerProject(ev.ContainerID))
	}

	for _, d := range pol.Deny {
		if matchEntry(d, ctx) {
			e.recordObserved(ev.ContainerID, ev.ContainerName, dst, ev.DstPort, ev.Proto, dnsName, sniName, ev.Timestamp, ClassDeny.String())
			return e.buildViolation(pol, ev, dst, display, dnsName, sniName, ClassDeny)
		}
	}
	for _, a := range pol.Allow {
		if matchEntry(a, ctx) {
			e.recordObserved(ev.ContainerID, ev.ContainerName, dst, ev.DstPort, ev.Proto, dnsName, sniName, ev.Timestamp, "allowed")
			return nil
		}
	}

	// (f) Default-deny floor. The no-match/unresolved-ip split is a
	// classification of an ALREADY-produced violation, not a match
	// decision -- it never determines whether this connection is
	// permitted, only how alarming the resulting alert reads.
	//
	// BUG FIX (integration pass 2): this split is now fail-closed on
	// dnsOK alone, the same direction as the matching fix above and for
	// the identical structural reason. sniOK/sniName at THIS call site
	// can never legitimately describe the connection currently being
	// evaluated: trace_sni's ClientHello for a connection is only ever
	// sent after that connection's own TCP handshake completes, which is
	// strictly after the very Connection event this function is
	// synchronously reacting to right now -- so any record already
	// sitting in the SNI store at this instant was necessarily produced
	// by an EARLIER connection from this same container, not this one.
	// A live, back-to-back-connections regression run (see
	// docs/TESTING.md) reproduced the consequence concretely: a bare-IP
	// connection with zero name evidence of its own was silently
	// downgraded from unresolved-ip (the frozen doc's named exfiltration
	// shape) to the less-alarming no-match, because the immediately
	// preceding connection's real SNI observation -- recorded a moment
	// after that PRIOR connection had already been evaluated and
	// returned, so nothing had consumed it yet -- was still sitting in
	// the store when this unrelated connection asked. sniStore's
	// consume-on-lookup fix (sni.go) bounds a record to at most one use,
	// but cannot fix this specific case: the record's true owner never
	// looked it up at all, because it hadn't been recorded yet at the
	// time that owner was evaluated. dnsOK has no such structural
	// timing hole (DNS precedes the connect it will be used for, always
	// available at evaluation time), so it alone decides severity here.
	// sniName is still carried through on the Violation/ObservedDest
	// below purely as human-facing display -- unaffected by this fix,
	// still exactly as racy and enrichment-only as the package doc
	// comment already describes.
	class := ClassNoMatch
	if !dnsOK {
		class = ClassUnresolvedIP
	}
	e.recordObserved(ev.ContainerID, ev.ContainerName, dst, ev.DstPort, ev.Proto, dnsName, sniName, ev.Timestamp, class.String())
	return e.buildViolation(pol, ev, dst, display, dnsName, sniName, class)
}

// buildViolation assembles the Violation for a classified connection.
// destination is the best available evidence for a human-readable label
// (display, computed by the caller: SNI preferred when present, else DNS,
// else empty) -- used ONLY for Destination/dedup identity, never for the
// match decision that already happened. dnsName and sniName are carried
// through independently as the raw enrichment fields.
func (e *Engine) buildViolation(pol policy.Policy, ev observe.Event, dst netip.Addr, display, dnsName, sniName string, class Class) *Violation {
	destination := dst.String()
	if display != "" {
		destination = strings.ToLower(display)
	}
	return &Violation{
		Service:       pol.Name,
		Destination:   destination,
		Port:          ev.DstPort,
		Class:         class,
		DstIP:         dst,
		ContainerID:   ev.ContainerID,
		ContainerName: ev.ContainerName,
		Timestamp:     ev.Timestamp,
		Mode:          pol.Mode,
		DNSName:       dnsName,
		SNIName:       sniName,
	}
}
