// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net/netip"

	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/core/runtime"
)

// inOwnNetworks reports whether dst falls within any subnet of any of the
// runtime's own managed container networks. This is the Fork 4 boundary:
// "own container network" is defined against the runtime's networks as a
// whole, independent of which networks the connecting container itself is
// attached to (that narrower question is @self, resolved by
// selfSubnets below).
func inOwnNetworks(nets []runtime.Network, dst netip.Addr) bool {
	for _, n := range nets {
		for _, pfx := range n.Subnets {
			if pfx.Contains(dst) {
				return true
			}
		}
	}
	return false
}

// isImplicitResolver reports whether a connection to dst:port is covered
// by the Fork 4 implicit baseline: a configured DNS resolver on port 53.
// The resolver list itself, including the AIRLOCK_IMPLICIT_ALLOW=none
// disable knob, is World's responsibility (World.ResolverIPs); this
// function only applies the port-53 and address-membership test.
func isImplicitResolver(resolvers []netip.Addr, dst netip.Addr, port uint16) bool {
	if port != 53 {
		return false
	}
	for _, r := range resolvers {
		if r.Unmap() == dst {
			return true
		}
	}
	return false
}

// selfSubnets resolves the "@self" token for one container: the subnet(s)
// of every network that container is attached to. World.ContainerNetworks
// gives the container's attachments by network name/ID and its OWN IPs on
// each; @self means the container's wire, not its address, so this cross-
// references each attachment against World.Networks() (already fetched by
// the caller as nets) to recover the network's subnet CIDRs. An
// attachment World doesn't recognize as one of the runtime's own networks
// (should not normally happen) contributes nothing rather than erroring,
// since a missing subnet only makes @self match less, never more, which
// fails safe for a security engine.
func selfSubnets(nets []runtime.Network, attachments []runtime.ContainerNetwork) []netip.Prefix {
	if len(attachments) == 0 {
		return nil
	}
	var out []netip.Prefix
	for _, a := range attachments {
		for _, n := range nets {
			matched := (a.ID != "" && a.ID == n.ID) || (a.ID == "" && a.Name != "" && a.Name == n.Name)
			if matched {
				out = append(out, n.Subnets...)
				break
			}
		}
	}
	return out
}

// policyNeedsTokens reports whether pol's Allow or Deny lists reference the
// @self or @project tokens at all. The engine uses this to skip calling
// World.ContainerNetworks / World.ContainerProject / World.ProjectPeerIPs
// on the hot path for the common policy that names no group token,
// since those World methods may walk the runtime's container list and
// should not be paid for unconditionally on every connection.
// net:<name> needs no such gate: its resolution only consults
// World.Networks(), already fetched unconditionally for Scope
// classification.
func policyNeedsTokens(pol policy.Policy) (needsSelf, needsProject bool) {
	for _, list := range [2][]policy.Entry{pol.Allow, pol.Deny} {
		for _, e := range list {
			switch e.Kind {
			case policy.SelfNetworks:
				needsSelf = true
			case policy.ProjectPeers:
				needsProject = true
			}
		}
		if needsSelf && needsProject {
			return
		}
	}
	return
}

// hasNameBasedAllow reports whether pol's Allow list contains at least
// one Domain or DomainWildcard entry. This is the trigger condition for
// deferring a default-deny-floor verdict (pending.go's deferPending): a
// late SNI can only ever rescue a connection into an allow if some name
// rule exists for it to satisfy. It deliberately does not check whether
// a candidate entry's port would even match this connection's -- keeping
// the trigger a simple "does the policy have any name-based allow at
// all" question, rather than trying to predict whether a specific future
// SNI could satisfy a specific entry, is the "keep it tight, don't
// over-engineer" tradeoff: at most it defers a handful of connections
// that a late SNI could never actually rescue (a name-based allow entry
// exists but pinned to a different port), for at most sniWindow, which
// costs a small delay, never a wrong verdict.
func hasNameBasedAllow(pol policy.Policy) bool {
	for _, a := range pol.Allow {
		if a.Kind == policy.Domain || a.Kind == policy.DomainWildcard {
			return true
		}
	}
	return false
}
