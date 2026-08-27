// SPDX-License-Identifier: GPL-3.0-or-later

package daemon

import (
	"net/netip"
	"sort"
	"time"

	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/discovery"
	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/airlock/internal/resolve"
	"github.com/tagwright/core/runtime"
)

// world is this daemon's implementation of engine.World: a live snapshot
// of everything the policy engine needs to read about the fleet, rebuilt
// wholesale by reconcile on every pass.
//
// Concurrency: world is deliberately NOT safe for concurrent access. The
// daemon's single event-loop goroutine is the only caller of both the
// engine's Process (which reads a world through the engine.World
// interface) and reconcile (which rewrites one via replace), so there is
// never a second goroutine touching these fields. This is the "simplest
// correct design" the architecture calls for: no RWMutex, no atomic
// pointer swap, just ordinary field access serialized by construction.
// If a future change ever needs a second goroutine to reconcile
// concurrently with the event loop, this type must grow a RWMutex (a
// read lock around every accessor below, a write lock around replace)
// before that change ships.
type world struct {
	// policies holds the fully resolved policy for every ARMED
	// container, keyed by container id. An unarmed or unknown container
	// is simply absent, which is exactly what ResolvedPolicy's ok=false
	// contract wants.
	policies map[string]policy.Policy

	// networks is the runtime's own managed network inventory.
	networks []runtime.Network

	// containerNetworks and containerProjects hold EVERY container's
	// attachments and compose project, not just armed ones: @self and
	// @project resolution, and the project peer index below, need this
	// for any container a policy might reference, regardless of whether
	// the referencing container itself is armed. (In practice the
	// engine only ever asks about the container it is currently
	// evaluating, which is always the one that owns the policy, but
	// keeping this unconditional matches Networks() below in also being
	// arming-independent live runtime data.)
	containerNetworks map[string][]runtime.ContainerNetwork
	containerProjects map[string]string

	// projectPeers maps a compose project name to the union of every IP
	// address every container sharing that project holds, across all of
	// their networks. Built once per reconcile by walking every
	// container, not computed lazily per query.
	projectPeers map[string][]netip.Addr

	// resolverIPs is the implicit resolver-on-53 baseline's address
	// list: best-effort host resolv.conf nameservers, unioned with any
	// bare-IP AIRLOCK_IMPLICIT_ALLOW entries, or nil outright when the
	// baseline is disabled (AIRLOCK_IMPLICIT_ALLOW=none). See
	// resolverIPsFor's doc comment.
	resolverIPs []netip.Addr
}

// newWorld returns an empty, ready-to-use world.
func newWorld() *world {
	return &world{
		policies:          make(map[string]policy.Policy),
		containerNetworks: make(map[string][]runtime.ContainerNetwork),
		containerProjects: make(map[string]string),
		projectPeers:      make(map[string][]netip.Addr),
	}
}

// replace overwrites w's fields with other's, in place, preserving w's
// identity (and therefore the engine's reference to it). Only reconcile
// calls this, from the daemon's single event-loop goroutine -- see the
// type doc comment.
func (w *world) replace(other *world) {
	w.policies = other.policies
	w.networks = other.networks
	w.containerNetworks = other.containerNetworks
	w.containerProjects = other.containerProjects
	w.projectPeers = other.projectPeers
	w.resolverIPs = other.resolverIPs
}

// ResolvedPolicy implements engine.World.
func (w *world) ResolvedPolicy(containerID string) (policy.Policy, bool) {
	p, ok := w.policies[containerID]
	return p, ok
}

// Networks implements engine.World.
func (w *world) Networks() []runtime.Network {
	return w.networks
}

// ContainerNetworks implements engine.World.
func (w *world) ContainerNetworks(containerID string) []runtime.ContainerNetwork {
	return w.containerNetworks[containerID]
}

// ContainerProject implements engine.World.
func (w *world) ContainerProject(containerID string) string {
	return w.containerProjects[containerID]
}

// ProjectPeerIPs implements engine.World.
func (w *world) ProjectPeerIPs(project string) []netip.Addr {
	if project == "" {
		return nil
	}
	return w.projectPeers[project]
}

// ResolverIPs implements engine.World.
func (w *world) ResolverIPs() []netip.Addr {
	return w.resolverIPs
}

// containerDiagnostic pairs one discovery.Diagnostic with the container it
// concerns, since discovery.Diagnostic itself carries no container
// identity (see discovery's package doc). buildWorld collects these for
// the caller to route through alert.Diagnostic; it never talks to the
// alerter itself, keeping buildWorld a pure function of its inputs and
// therefore unit-testable with no beacon/alert dependency at all.
type containerDiagnostic struct {
	containerID   string
	containerName string
	diag          discovery.Diagnostic
}

// armedContainerMeta is the status-worthy slice of one armed container's
// resolved state, carried alongside (not inside) world's own policy map so
// the state-snapshot writer (state.go) can read a plain, thread-safe
// snapshot of it via Daemon.armedMeta without touching world at all -- see
// world's own "deliberately NOT safe for concurrent access" type doc
// comment for why that boundary matters.
type armedContainerMeta struct {
	id            string
	name          string
	service       string
	mode          string
	scope         string
	matchedGroups []string
}

// buildResult is buildWorld's return value: the freshly built world, every
// diagnostic produced while resolving the fleet's policies, the
// per-service alert window every armed container's resolved policy
// carries (for the caller to feed to alert.Alerter.SetWindow), and the
// status-worthy metadata for every armed container, sorted by id for a
// stable snapshot (for the caller to store on Daemon.armedMeta).
type buildResult struct {
	world       *world
	diagnostics []containerDiagnostic
	windows     map[string]time.Duration
	armed       []armedContainerMeta
}

// buildWorld is the pure heart of a reconcile pass: given a fresh listing
// of containers and networks, cfg, and a best-effort base resolver list
// (normally parseResolvConf's result), it produces the complete world
// snapshot for this pass plus every diagnostic and per-service alert
// window discovered along the way. It performs no I/O itself and touches
// no alerter, so it is unit-testable against nothing but in-code
// fixtures.
func buildWorld(containers []runtime.Container, networks []runtime.Network, cfg *config.Config, resolverBase []netip.Addr) buildResult {
	w := newWorld()
	w.networks = networks

	implicitEntries := implicitAllowEntries(cfg)
	w.resolverIPs = resolverIPsFor(cfg, resolverBase, implicitEntries)

	// Every container's attachments, project, and (if it has one) peer
	// contribution are recorded regardless of arming: @self, @project,
	// and the project peer index are live runtime facts, not
	// policy-gated ones.
	peers := make(map[string][]netip.Addr)
	for _, c := range containers {
		w.containerNetworks[c.ID] = c.Networks
		w.containerProjects[c.ID] = c.Project
		if c.Project == "" {
			continue
		}
		for _, cn := range c.Networks {
			peers[c.Project] = append(peers[c.Project], cn.IPs...)
		}
	}
	w.projectPeers = peers

	var diags []containerDiagnostic
	windows := make(map[string]time.Duration)
	var armed []armedContainerMeta

	for _, c := range containers {
		lp, ldiags := discovery.ReadLabels(c.Labels)
		for _, d := range ldiags {
			diags = append(diags, containerDiagnostic{c.ID, c.Name, d})
		}

		resolved, rdiags := resolve.Resolve(c, lp, cfg)
		for _, d := range rdiags {
			diags = append(diags, containerDiagnostic{c.ID, c.Name, d})
		}

		if !resolved.Armed {
			continue
		}

		armed = append(armed, armedContainerMeta{
			id:            c.ID,
			name:          c.Name,
			service:       resolved.Policy.Name,
			mode:          resolved.Policy.Mode.String(),
			scope:         resolved.Policy.Scope.String(),
			matchedGroups: append([]string(nil), resolved.MatchedGroups...),
		})

		// JUDGMENT CALL: the AIRLOCK_IMPLICIT_ALLOW extension entries
		// (the non-resolver-shaped ones -- domains, CIDRs, tokens, or
		// bare IPs with a port) are folded into every armed policy's
		// Allow list here, at snapshot build time, rather than in the
		// engine. This is the "daemon owns it" call the engine chunk
		// flagged: the engine's World interface has no notion of a
		// fleet-wide allow extension, so the daemon absorbs it into
		// the one place the engine already knows how to read, a
		// container's own resolved Allow list. Appended, not merged
		// with de-duplication: a duplicate entry is harmless (matching
		// is a linear scan, never keyed), and skipping de-dup keeps
		// this hot-reconcile path simple.
		pol := resolved.Policy
		if len(implicitEntries) > 0 {
			merged := make([]policy.Entry, 0, len(pol.Allow)+len(implicitEntries))
			merged = append(merged, pol.Allow...)
			merged = append(merged, implicitEntries...)
			pol.Allow = merged
		}

		w.policies[c.ID] = pol
		if pol.Name != "" {
			windows[pol.Name] = pol.AlertWindow
		}
	}

	sort.Slice(armed, func(i, j int) bool { return armed[i].id < armed[j].id })

	return buildResult{world: w, diagnostics: diags, windows: windows, armed: armed}
}

// implicitAllowEntries parses cfg.Defaults.ImplicitAllow's raw entries
// with policy.ParseEntry, for folding into every armed policy's Allow
// list (see buildWorld). Returns nil when the baseline is disabled
// (ImplicitAllow.None) or simply empty. A raw entry that fails to parse
// is skipped rather than erroring here: config.Load's own Validate
// (validateEntryList) already rejects an unparsable entry at config-load
// time, so reaching an invalid one here would mean an unvalidated
// *config.Config was constructed by hand, bypassing config.Load -- a
// defensive case, not the expected path.
func implicitAllowEntries(cfg *config.Config) []policy.Entry {
	ia := cfg.Defaults.ImplicitAllow
	if ia.None || len(ia.Entries) == 0 {
		return nil
	}
	out := make([]policy.Entry, 0, len(ia.Entries))
	for _, raw := range ia.Entries {
		e, err := policy.ParseEntry(raw)
		if err != nil {
			continue
		}
		out = append(out, e)
	}
	return out
}

// resolverIPsFor computes the implicit resolver-on-53 baseline's address
// list: base (normally the host's own /etc/resolv.conf nameservers, see
// parseResolvConf) unioned with every bare-IP-no-port entry among
// implicitEntries.
//
// JUDGMENT CALL: the frozen doc and this chunk's brief both describe
// AIRLOCK_IMPLICIT_ALLOW as extending "the fixed resolver-on-port-53
// baseline with additional entries," but the grammar it accepts is the
// full destination-entry grammar (domains, CIDRs, tokens, ported
// literals), not a resolver-shaped sub-grammar of its own. This function
// resolves that by treating a bare IP literal with no port suffix as the
// "this names an additional resolver" case (a resolver is identified by
// its address alone, never by a port, since 53 is implied) and folding
// exactly those into the port-53 baseline, while every entry (bare IP
// included) still separately reaches every armed policy's general Allow
// list via implicitAllowEntries/buildWorld regardless of shape. A domain,
// CIDR, or ported entry never contributes to the resolver baseline itself
// -- only to the general Allow fold -- since none of those name a single
// resolver address the way a bare IP does.
//
// Returns nil when the baseline is disabled entirely
// (AIRLOCK_IMPLICIT_ALLOW=none), regardless of what base or
// implicitEntries carry: "none" means no connection is ever implicitly
// allowed on this path, host resolv.conf included.
func resolverIPsFor(cfg *config.Config, base []netip.Addr, implicitEntries []policy.Entry) []netip.Addr {
	if cfg.Defaults.ImplicitAllow.None {
		return nil
	}

	seen := make(map[netip.Addr]bool, len(base)+len(implicitEntries))
	var out []netip.Addr
	add := func(a netip.Addr) {
		a = a.Unmap()
		if seen[a] {
			return
		}
		seen[a] = true
		out = append(out, a)
	}

	for _, a := range base {
		add(a)
	}
	for _, e := range implicitEntries {
		if e.Kind == policy.IP && !e.HasPort {
			add(e.Addr)
		}
	}
	return out
}
