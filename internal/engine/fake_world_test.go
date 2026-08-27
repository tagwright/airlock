// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net/netip"

	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/core/runtime"
)

// fakeWorld is an in-memory World for tests: no sockets, no runtime, no
// clock dependency beyond whatever the test itself passes as event
// timestamps.
type fakeWorld struct {
	policies  map[string]policy.Policy // containerID -> resolved policy; absent means unarmed/unknown
	networks  []runtime.Network
	attach    map[string][]runtime.ContainerNetwork // containerID -> attachments
	project   map[string]string                     // containerID -> compose project
	peers     map[string][]netip.Addr               // project -> peer IPs
	resolvers []netip.Addr
}

func newFakeWorld() *fakeWorld {
	return &fakeWorld{
		policies: make(map[string]policy.Policy),
		attach:   make(map[string][]runtime.ContainerNetwork),
		project:  make(map[string]string),
		peers:    make(map[string][]netip.Addr),
	}
}

func (w *fakeWorld) ResolvedPolicy(containerID string) (policy.Policy, bool) {
	p, ok := w.policies[containerID]
	return p, ok
}

func (w *fakeWorld) Networks() []runtime.Network {
	return w.networks
}

func (w *fakeWorld) ContainerNetworks(containerID string) []runtime.ContainerNetwork {
	return w.attach[containerID]
}

func (w *fakeWorld) ContainerProject(containerID string) string {
	return w.project[containerID]
}

func (w *fakeWorld) ProjectPeerIPs(project string) []netip.Addr {
	return w.peers[project]
}

func (w *fakeWorld) ResolverIPs() []netip.Addr {
	return w.resolvers
}

// mustPrefix parses s as a netip.Prefix, panicking on a malformed test
// fixture (a bug in the test, never a runtime condition).
func mustPrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

func mustEntry(s string) policy.Entry {
	e, err := policy.ParseEntry(s)
	if err != nil {
		panic(err)
	}
	return e
}
