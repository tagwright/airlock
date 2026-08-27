// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net/netip"
	"strings"

	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/core/runtime"
)

// matchContext is everything matchEntry needs to test one policy.Entry
// against one observed connection, assembled once per Connection
// evaluation and reused across every entry in a policy's Allow and Deny
// lists.
type matchContext struct {
	dstIP   netip.Addr
	dstPort uint16

	// dnsName/hasDNSName is the ONLY name evidence a Domain or
	// DomainWildcard entry may match against: a DNS-cache correlation for
	// this container's own recent answers (a hard IP-to-name lookup),
	// lowercased. hasDNSName is false when this container's DNS cache has
	// no entry for dstIP, in which case dnsName is always "".
	//
	// Deliberately NOT influenced by SNI. An earlier version of this
	// context carried a single "best evidence, SNI preferred on
	// disagreement" name field consulted here; a real integration pass
	// reproduced that trace_sni's lack of a destination IP lets one
	// connection's SNI misattribute to a DIFFERENT, unrelated connection
	// from the same container fired moments later, which could mark a
	// disallowed connection allowed -- a false negative a security tool
	// must not have. SNI is now enrichment-only: still looked up, still
	// carried through on Violation/ObservedDest for a human to read, but
	// never passed into this struct or consulted by matchEntry. See
	// engine.go's package doc comment for the full story.
	dnsName    string
	hasDNSName bool

	// selfSubnets and projectPeers resolve @self and @project; both are
	// left nil when the policy being evaluated uses neither token (see
	// policyNeedsTokens), which is harmless since a nil slice simply
	// never matches.
	selfSubnets  []netip.Prefix
	projectPeers []netip.Addr

	// networks is the runtime's own managed networks, used to resolve
	// net:<name> tokens by name.
	networks []runtime.Network
}

// matchEntry reports whether one parsed policy.Entry matches the
// connection described by ctx, per the frozen entry grammar (Fork 3) and
// the group tokens (Fork 8). A port on the entry constrains the match to
// that destination port; no port means any port. Domain/DomainWildcard
// matching is fail-closed on SNI: see ctx.dnsName's doc comment.
func matchEntry(e policy.Entry, ctx matchContext) bool {
	if e.HasPort && e.Port != ctx.dstPort {
		return false
	}
	switch e.Kind {
	case policy.AnyDest:
		return true
	case policy.IP:
		return e.Addr.Unmap() == ctx.dstIP
	case policy.CIDR:
		return e.Prefix.Contains(ctx.dstIP)
	case policy.Domain:
		return ctx.hasDNSName && strings.EqualFold(ctx.dnsName, e.Domain)
	case policy.DomainWildcard:
		return ctx.hasDNSName && matchWildcardDomain(ctx.dnsName, e.Domain)
	case policy.SelfNetworks:
		return prefixesContain(ctx.selfSubnets, ctx.dstIP)
	case policy.ProjectPeers:
		return addrsContain(ctx.projectPeers, ctx.dstIP)
	case policy.NamedNetwork:
		return namedNetworkContains(ctx.networks, e.NetworkName, ctx.dstIP)
	default:
		return false
	}
}

// matchWildcardDomain reports whether name is matched by the
// DomainWildcard suffix "*.suffix": one or more leading labels, never the
// apex itself. Comparison is case-insensitive, per ordinary DNS name
// semantics.
func matchWildcardDomain(name, suffix string) bool {
	name = strings.ToLower(name)
	suffix = strings.ToLower(suffix)
	// name must end in ".suffix" -- this simultaneously requires at
	// least one leading label and excludes the bare apex, since the
	// apex itself has no leading "." before it in this comparison.
	return len(name) > len(suffix)+1 && strings.HasSuffix(name, "."+suffix)
}

func prefixesContain(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func addrsContain(addrs []netip.Addr, addr netip.Addr) bool {
	for _, a := range addrs {
		if a.Unmap() == addr {
			return true
		}
	}
	return false
}

func namedNetworkContains(nets []runtime.Network, name string, addr netip.Addr) bool {
	for _, n := range nets {
		if n.Name != name {
			continue
		}
		for _, p := range n.Subnets {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}
