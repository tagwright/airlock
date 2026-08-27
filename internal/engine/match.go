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

	// name is the winning name evidence for this connection (SNI when it
	// exists, else DNS, per the frozen doc's "SNI wins on disagreement"
	// rule), lowercased. hasName is false when neither source had
	// anything, in which case name is always "".
	name    string
	hasName bool

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
// that destination port; no port means any port.
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
		return ctx.hasName && strings.EqualFold(ctx.name, e.Domain)
	case policy.DomainWildcard:
		return ctx.hasName && matchWildcardDomain(ctx.name, e.Domain)
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
