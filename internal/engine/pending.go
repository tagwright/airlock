// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net/netip"
	"strings"
	"time"

	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/airlock/internal/policy"
)

// pendingCapPerContainer bounds how many deferred connections one
// container may have outstanding at once (see pendingConn). Only
// would-be default-deny-floor violations that could still turn into an
// allow via a late SNI are ever deferred, and each lives for at most
// sniWindow, so this cap only matters under a flood of distinct,
// unmatched destinations from one container within that short span. On
// overflow the oldest entry is evaluated and, if still a violation,
// emitted immediately rather than dropped -- see deferPending.
const pendingCapPerContainer = 64

// pendingConn is a would-be default-deny-floor violation whose final
// verdict is deferred briefly in case a same-container SNI observed just
// after the connect still resolves it to an allowed name (see the
// package doc comment's note on SNI-after-connect ordering). Only a
// connection reachable by a name-based allow entry is ever deferred: a
// deny match and a pure-IP-policy violation are both definitive at
// connect time and never appear here.
type pendingConn struct {
	// ev is the original Connection event, kept so a final Violation can
	// be rebuilt with the right container identity, port, and timestamp.
	ev  observe.Event
	pol policy.Policy // resolved policy snapshot at connect time
	dst netip.Addr    // unmapped destination address

	// ctx is the matching context fixed at connect time: dstIP, dstPort,
	// and any resolved @self/@project/net: material. Its name/hasName
	// fields are stale by construction and are recomputed fresh from the
	// correlation stores on every re-evaluation (freshEvidence), never
	// read directly off this copy.
	ctx matchContext

	deadline time.Time // ev.Timestamp + sniWindow
}

// deferPending queues a would-be default-deny-floor violation instead of
// returning it immediately. It returns any Violation forced out by
// pendingCapPerContainer: rather than silently dropping the oldest
// deferred connection when a container's queue is full, that entry is
// evaluated with whatever evidence exists right now and, if it is still
// a violation, returned here so the caller still surfaces it. A forced
// early verdict is preferable to a lost one.
func (e *Engine) deferPending(ev observe.Event, pol policy.Policy, dst netip.Addr, ctx matchContext) []Violation {
	p := &pendingConn{
		ev:       ev,
		pol:      pol,
		dst:      dst,
		ctx:      ctx,
		deadline: ev.Timestamp.Add(sniWindow),
	}

	queue := e.pending[ev.ContainerID]
	var forced []Violation
	if len(queue) >= pendingCapPerContainer {
		oldest := queue[0]
		queue = queue[1:]
		if v := e.reevaluatePendingFinal(oldest); v != nil {
			forced = append(forced, *v)
		}
	}
	e.pending[ev.ContainerID] = append(queue, p)
	return forced
}

// recheckPendingOnSNI is called after every TLSHello update: a freshly
// observed SNI name may resolve one or more of this container's deferred
// connections to an allowed name, in which case they are dropped
// immediately instead of waiting out the rest of their deadline. A
// deferred connection that still matches no allow entry is left pending
// exactly as it was -- even if the new SNI would now also satisfy a deny
// entry, that full re-determination is Flush's job (or the cap-eviction
// path's), not this quick early-drop check's.
func (e *Engine) recheckPendingOnSNI(containerID string) {
	queue := e.pending[containerID]
	if len(queue) == 0 {
		return
	}
	kept := queue[:0]
	for _, p := range queue {
		if e.pendingMatchesAllow(p) {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == 0 {
		delete(e.pending, containerID)
		return
	}
	e.pending[containerID] = kept
}

// pendingMatchesAllow reports whether p's destination now matches any
// entry in its policy's Allow list, using the freshest available name
// evidence.
func (e *Engine) pendingMatchesAllow(p *pendingConn) bool {
	ctx, _, _ := e.freshEvidence(p)
	for _, a := range p.pol.Allow {
		if matchEntry(a, ctx) {
			return true
		}
	}
	return false
}

// reevaluatePendingFinal fully re-determines p's verdict -- deny beats
// allow beats the default-deny floor, exactly as evaluateConnection's
// step (e)/(f) -- using the freshest available name evidence. It returns
// the Violation to emit, or nil when p is now allowed.
func (e *Engine) reevaluatePendingFinal(p *pendingConn) *Violation {
	ctx, dnsName, sniName := e.freshEvidence(p)

	for _, d := range p.pol.Deny {
		if matchEntry(d, ctx) {
			return e.buildViolation(p.pol, p.ev, p.dst, ctx.name, dnsName, sniName, ClassDeny)
		}
	}
	for _, a := range p.pol.Allow {
		if matchEntry(a, ctx) {
			return nil
		}
	}
	class := ClassNoMatch
	if !ctx.hasName {
		class = ClassUnresolvedIP
	}
	return e.buildViolation(p.pol, p.ev, p.dst, ctx.name, dnsName, sniName, class)
}

// freshEvidence returns p's fixed matching context with name/hasName
// recomputed from the correlation stores as they stand right now, along
// with the raw DNS and SNI evidence found (for a rebuilt Violation's
// DNSName/SNIName fields). The correlation anchor is always
// p.ev.Timestamp, the connection's own observed time -- the SNI window
// is centered on when the connection happened, not on whenever it
// happens to be re-checked, exactly as it was at the original connect-
// time evaluation.
func (e *Engine) freshEvidence(p *pendingConn) (ctx matchContext, dnsName, sniName string) {
	var dnsOK, sniOK bool
	dnsName, dnsOK = e.dnsCacheLookup(p.ev.ContainerID, p.dst, p.ev.Timestamp)
	sniName, sniOK = e.sniStoreLookup(p.ev.ContainerID, p.ev.Timestamp)

	name := dnsName
	if sniOK {
		name = sniName
	}

	ctx = p.ctx
	ctx.name = strings.ToLower(name)
	ctx.hasName = dnsOK || sniOK
	return ctx, dnsName, sniName
}

// Flush re-evaluates every pending connection whose deferral deadline has
// passed as of now, emitting a Violation for any that still violate and
// silently dropping any a late SNI has since resolved to an allow.
//
// The engine itself runs no timer. A daemon must call Flush on a short,
// steady cadence -- a few hundred milliseconds is a reasonable default,
// comfortably finer than sniWindow -- from the same goroutine that calls
// Process, or from a goroutine it coordinates with Process under this
// Engine's own mutex (Flush takes that lock itself, so calling it
// concurrently with Process is safe; it is the ORDERING relative to the
// event stream, not the locking, that the daemon must get right). A
// deferred violation never surfaces on its own: if Flush is never called,
// it simply never fires, and Engine.Forget on a removed container drops
// its pending entries outright rather than flushing them. This is the
// deliberate trade behind deferral being narrowly scoped: only would-be
// violations with a live chance of turning into an allow are ever
// deferred, and only for sniWindow's short duration, so a missed or late
// Flush call costs at most a slightly delayed alert, never a lost one,
// provided Flush is called at all before the daemon cares about that
// container's alerts.
func (e *Engine) Flush(now time.Time) []Violation {
	e.mu.Lock()
	defer e.mu.Unlock()

	var out []Violation
	for containerID, queue := range e.pending {
		var kept []*pendingConn
		for _, p := range queue {
			if now.Before(p.deadline) {
				kept = append(kept, p)
				continue
			}
			if v := e.reevaluatePendingFinal(p); v != nil {
				out = append(out, *v)
			}
		}
		if len(kept) == 0 {
			delete(e.pending, containerID)
		} else {
			e.pending[containerID] = kept
		}
	}
	return out
}
