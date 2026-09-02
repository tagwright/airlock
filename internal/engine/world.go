// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package engine

import (
	"net/netip"

	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/core/runtime"
)

// World is everything the engine reads about live system state to evaluate
// one observed connection. It is the engine's only window onto the outside
// world: the engine never opens a socket, never talks to Inspektor Gadget,
// and never talks to the container runtime directly. A daemon built on top
// of this package implements World once, wiring it to the real runtime,
// discovery, and resolve layers; tests implement it with an in-memory fake
// and no I/O at all.
//
// Every method here is a pure lookup: World must not block on the network
// or the container runtime's socket for longer than an in-memory cache
// read, since Process calls these synchronously on the hot path (every
// observed connection). A daemon implementation should keep its own
// caches warm (container networks, resolved policy, resolver IPs) and
// refresh them off the discovery/watch loop, not on demand here.
type World interface {
	// ResolvedPolicy returns the fully merged policy.Policy for a
	// container (the outcome of internal/resolve's label + policy-set +
	// group merge), and whether that container is armed at all. ok is
	// false when the container is unarmed (no airlock.enable and no
	// matching armed group) or simply unknown to the daemon (observed
	// before discovery caught up, or already removed) -- both cases mean
	// the same thing to the engine: this connection is observed but not
	// policy-judged.
	ResolvedPolicy(containerID string) (policy.Policy, bool)

	// Networks returns the runtime's own managed container networks
	// (Docker/Podman bridge, macvlan-as-managed-by-the-runtime, compose
	// networks, ...), each with its subnet CIDRs. This is the boundary
	// "own container network" is defined against for Scope classification
	// (step b) and is also what a "net:<name>" token (Fork 8) resolves
	// against.
	Networks() []runtime.Network

	// ContainerNetworks returns the networks a specific container is
	// attached to, along with the IPs it holds on each. This is the raw
	// material for the "@self" token: the engine cross-references each
	// entry's Name/ID against Networks() to recover that network's
	// subnet(s), since "@self" means "my own wire," not "my own address."
	ContainerNetworks(containerID string) []runtime.ContainerNetwork

	// ContainerProject returns the container's compose project
	// (com.docker.compose.project), or "" if it is not a compose service.
	// Used only to look up ProjectPeerIPs for the "@project" token.
	ContainerProject(containerID string) string

	// ProjectPeerIPs returns the IP addresses of every container sharing
	// the given compose project (including, harmlessly, the querying
	// container's own addresses). This is the "@project" token's
	// resolution: membership is by address equality, not by subnet
	// containment, since project siblings can span more than one network.
	// An empty or unknown project returns nil.
	ProjectPeerIPs(project string) []netip.Addr

	// ResolverIPs returns the configured DNS resolver addresses the
	// implicit resolver-on-53 baseline (Fork 4) is evaluated against.
	// A World implementation is responsible for folding in the
	// AIRLOCK_IMPLICIT_ALLOW=none knob: when the baseline is disabled
	// fleet-wide, ResolverIPs returns nil and no connection is ever
	// implicitly allowed on this path.
	ResolverIPs() []netip.Addr
}
