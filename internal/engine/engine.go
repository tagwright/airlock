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
// arrives too late to help that one connection, which is a known
// correlation limitation, not a bug -- see the implementation report's
// note on SNI ordering). Process still takes an internal lock so that a
// second goroutine may safely call an exported read method (for example a
// future status/suggest snapshot) concurrently with the single feeder
// goroutine; that lock is not a substitute for feeding events out of order
// and expecting correct correlation.
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
}

// New constructs an Engine reading live state from world.
func New(world World) *Engine {
	return &Engine{
		world: world,
		dns:   make(map[string]*dnsCache),
		sni:   make(map[string]*sniStore),
	}
}

// Process consumes one normalized observation and returns the Violations
// it produced: none for a DNSAnswer or TLSHello (they only update
// correlation state), and zero or one for a Connection (evaluation is at
// connect time only, per the frozen doc, so a Connection is judged exactly
// once, here). An event of an unrecognized Kind is ignored.
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

// Forget releases a container's correlation state (its DNS cache and SNI
// window). A daemon should call this when the runtime reports a container
// removed, so long-lived fleets do not accumulate state for containers
// that no longer exist. Calling it for an unknown or already-forgotten
// container is a harmless no-op.
func (e *Engine) Forget(containerID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.dns, containerID)
	delete(e.sni, containerID)
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
// exactly.
func (e *Engine) evaluateConnection(ev observe.Event) *Violation {
	// (a) Resolve the container's policy. Unarmed or unknown means
	// observed but never policy-judged.
	pol, armed := e.world.ResolvedPolicy(ev.ContainerID)
	if !armed {
		return nil
	}

	dst := ev.DstIP.Unmap()

	// (b) Scope classification: loopback is never egress; the runtime's
	// own container networks are out of scope under External and in
	// scope under All; everything else (the LAN included) is in scope
	// under both.
	if dst.IsLoopback() {
		return nil
	}
	nets := e.world.Networks()
	own := inOwnNetworks(nets, dst)
	if own && pol.Scope == policy.External {
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
			return e.buildViolation(pol, ev, dst, name, dnsName, sniName, ClassDeny)
		}
	}
	for _, a := range pol.Allow {
		if matchEntry(a, ctx) {
			return nil
		}
	}

	// (f) Default-deny floor: unresolved-ip when there was no name
	// evidence at all, no-match otherwise.
	class := ClassNoMatch
	if !hasName {
		class = ClassUnresolvedIP
	}
	return e.buildViolation(pol, ev, dst, name, dnsName, sniName, class)
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
