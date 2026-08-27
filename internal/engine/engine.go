// SPDX-License-Identifier: GPL-3.0-or-later

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
//     the exfiltration-shaped unresolved-ip when there was no name
//     evidence at all).
//
// See world.go, violation.go, dns.go, sni.go, scope.go, and match.go for
// each piece, and the frozen doc's "What a rule can honestly promise"
// section for the reasoning this package is built against.
//
// Concurrency: Engine is designed to be fed by exactly one goroutine
// calling Process in the order events were observed -- the daemon is
// expected to serialize its observation stream before handing events to
// the engine, since evaluation order matters (a DNSAnswer or TLSHello must
// be processed before the Connection it is meant to inform, or it simply
// arrives too late to help that one connection, which is the ordinary
// case for SNI: a TLS ClientHello is emitted after the TCP connect it
// rides on, so it usually reaches Process strictly after the Connection
// event it should inform). pending.go's deferred verdicts exist
// specifically to absorb that ordinary case for the one situation it can
// change an answer: a would-be default-deny-floor violation against a
// policy with a name-based allow entry is held briefly (see sniWindow) so
// a same-container SNI that lands just after the connect can still
// resolve it. Process still takes an internal lock so that a second
// goroutine may safely call Flush, or the observed-egress recorder's
// ObservedSnapshot/Observed (see observed.go), concurrently with the
// single feeder goroutine; that lock is not a
// substitute for feeding events out of order and expecting correct
// correlation, and it is not a substitute for actually calling Flush --
// see Flush's doc comment.
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

	mu      sync.Mutex
	dns     map[string]*dnsCache
	sni     map[string]*sniStore
	pending map[string][]*pendingConn

	// observed is the bounded per-container observed-egress recorder (see
	// observed.go): every external, in-scope destination seen from a
	// container, armed or not, with the best name evidence available at
	// observation time. It is guarded by the SAME mu as the correlation
	// state above, not a dedicated mutex: recordObserved is only ever
	// called from within evaluateConnection, itself only ever reached from
	// Process, which already holds mu for its entire body, so folding the
	// recorder under the existing lock costs nothing on the hot path and
	// avoids a second lock a reader would otherwise need to acquire in the
	// right order relative to Process/Flush. ObservedSnapshot and Observed
	// take mu themselves for a reader on any other goroutine (a daemon's
	// periodic status-snapshot writer, in practice).
	observed map[string]*observedContainer
}

// New constructs an Engine reading live state from world.
func New(world World) *Engine {
	return &Engine{
		world:    world,
		dns:      make(map[string]*dnsCache),
		sni:      make(map[string]*sniStore),
		pending:  make(map[string][]*pendingConn),
		observed: make(map[string]*observedContainer),
	}
}

// Process consumes one normalized observation and returns the Violations
// it produced immediately: none for a DNSAnswer (it only updates
// correlation state); none for a TLSHello beyond what it drops from
// pending (it updates the SNI store and may clear a deferred verdict, but
// never itself returns a violation); and for a Connection, zero, one, or
// -- only when a full pending queue forces an unrelated earlier
// connection out early, see deferPending -- two: the triggering
// connection's own immediate verdict (deny, an immediate default-deny
// floor violation, or none if allowed or deferred) plus, rarely, the
// forced-out one. Evaluation of a Connection is still at connect time
// only in the sense that it is judged exactly once here or, for the
// narrow deferred case, once more at Flush; it is never re-judged twice
// with two different outcomes. An event of an unrecognized Kind is
// ignored.
//
// See the package doc comment for the single-feeder-goroutine assumption
// this method relies on for correlation ordering, and Flush's doc comment
// for what makes a deferred verdict actually surface.
func (e *Engine) Process(ev observe.Event) []Violation {
	e.mu.Lock()
	defer e.mu.Unlock()

	switch ev.Kind {
	case observe.DNSAnswer:
		e.recordDNS(ev)
		return nil
	case observe.TLSHello:
		e.recordSNI(ev)
		e.recheckPendingOnSNI(ev.ContainerID)
		return nil
	case observe.Connection:
		return e.evaluateConnection(ev)
	default:
		return nil
	}
}

// Forget releases a container's correlation state: its DNS cache, its SNI
// window, and any connections still awaiting a deferred verdict (which
// are dropped outright here, never flushed -- a container being forgotten
// is gone, so there is nothing left to alert about it). A daemon should
// call this when the runtime reports a container removed, so long-lived
// fleets do not accumulate state for containers that no longer exist.
// Calling it for an unknown or already-forgotten container is a harmless
// no-op.
func (e *Engine) Forget(containerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.dns, containerID)
	delete(e.sni, containerID)
	delete(e.pending, containerID)
	delete(e.observed, containerID)
}

// recordDNS updates the answering container's DNS cache from ev. Answers
// with no qname or no addresses carry nothing to correlate and are
// ignored.
func (e *Engine) recordDNS(ev observe.Event) {
	if ev.QName == "" || len(ev.Answers) == 0 {
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
		c.put(a.Unmap(), ev.QName, expiry)
	}
}

// recordSNI updates the container's recent-SNI window from ev. An event
// with no SNI name carries nothing to correlate and is ignored.
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
// exactly. It returns nil for an allowed or out-of-scope connection, a
// single immediate Violation for a deny match or an undeferrable
// default-deny-floor violation, or the result of deferPending (nil, or
// one violation forced out by a full pending queue) for a deferrable
// default-deny-floor violation -- see the package doc comment and
// hasNameBasedAllow.
func (e *Engine) evaluateConnection(ev observe.Event) []Violation {
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

	// (d) Name evidence: DNS cache and recent SNI, SNI wins on
	// disagreement, both are kept for the violation message.
	dnsName, dnsOK := e.dnsCacheLookup(ev.ContainerID, dst, ev.Timestamp)
	sniName, sniOK := e.sniStoreLookup(ev.ContainerID, ev.Timestamp)
	hasName := dnsOK || sniOK
	name := dnsName
	if sniOK {
		name = sniName
	}

	if !armed {
		e.recordObserved(ev.ContainerID, ev.ContainerName, dst, ev.DstPort, ev.Proto, name, ev.Timestamp, "observed")
		return nil
	}

	// (e) Match against the policy: deny beats allow beats the
	// default-deny floor. Tokens are resolved against live World data
	// only when the policy actually references them, since those World
	// calls may walk the runtime's container list.
	needsSelf, needsProject := policyNeedsTokens(pol)
	ctx := matchContext{
		dstIP:    dst,
		dstPort:  ev.DstPort,
		name:     strings.ToLower(name),
		hasName:  hasName,
		networks: nets,
	}
	if needsSelf {
		ctx.selfSubnets = selfSubnets(nets, e.world.ContainerNetworks(ev.ContainerID))
	}
	if needsProject {
		ctx.projectPeers = e.world.ProjectPeerIPs(e.world.ContainerProject(ev.ContainerID))
	}

	for _, d := range pol.Deny {
		if matchEntry(d, ctx) {
			// Deny is definitive at connect time: never deferred,
			// regardless of what a later SNI might say.
			e.recordObserved(ev.ContainerID, ev.ContainerName, dst, ev.DstPort, ev.Proto, name, ev.Timestamp, ClassDeny.String())
			return []Violation{*e.buildViolation(pol, ev, dst, name, dnsName, sniName, ClassDeny)}
		}
	}
	for _, a := range pol.Allow {
		if matchEntry(a, ctx) {
			e.recordObserved(ev.ContainerID, ev.ContainerName, dst, ev.DstPort, ev.Proto, name, ev.Timestamp, "allowed")
			return nil
		}
	}

	// (f) Default-deny floor: unresolved-ip when there was no name
	// evidence at all, no-match otherwise.
	class := ClassNoMatch
	if !hasName {
		class = ClassUnresolvedIP
	}

	// Before returning it as an immediate violation, consider deferral:
	// a late SNI arriving just after this connect can only ever change
	// this verdict if (1) this container has no SNI evidence for this
	// connection yet -- if it already does, SNI already won at step (d)
	// and nothing more can arrive to help -- and (2) the policy actually
	// has a name-based (Domain or DomainWildcard) allow entry for a late
	// SNI to satisfy in the first place. A pure-IP-and-token policy can
	// never be rescued by a name, so it is never worth the delay. Either
	// way the recorder gets this connection's verdict as of right now:
	// the class it would carry if a late SNI does not go on to rescue it.
	// The recorder is a best-effort suggest/status aid, not a security
	// verdict, so a rare case where a deferred connection is later
	// rescued into an allow leaves a slightly stale "no-match"/
	// "unresolved-ip" entry rather than "allowed" -- harmless, since the
	// destination was reached either way and is exactly what an operator
	// building an allowlist wants to see.
	e.recordObserved(ev.ContainerID, ev.ContainerName, dst, ev.DstPort, ev.Proto, name, ev.Timestamp, class.String())

	if !sniOK && hasNameBasedAllow(pol) {
		return e.deferPending(ev, pol, dst, ctx)
	}

	return []Violation{*e.buildViolation(pol, ev, dst, name, dnsName, sniName, class)}
}

// buildViolation assembles the Violation for a classified connection.
// destination is the winning name evidence (already resolved by the
// caller), or the literal destination IP when there was none.
func (e *Engine) buildViolation(pol policy.Policy, ev observe.Event, dst netip.Addr, name, dnsName, sniName string, class Class) *Violation {
	destination := dst.String()
	if name != "" {
		destination = strings.ToLower(name)
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
