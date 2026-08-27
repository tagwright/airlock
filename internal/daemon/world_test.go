// SPDX-License-Identifier: GPL-3.0-or-later

package daemon

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/config"
	"github.com/tagwright/airlock/internal/engine"
	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/core/runtime"
)

// newTestConfig returns a defaulted, validated *config.Config the way
// config.Load("") would in a clean environment, so tests don't need to
// hand-construct every Defaults field applyDefaults would otherwise fill
// in.
func newTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load(\"\"): %v", err)
	}
	return cfg
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return a
}

// armedContainer builds a runtime.Container declaring an armed policy via
// labels: airlock.enable=true plus whatever extra labels are given.
func armedContainer(id, name string, extra map[string]string) runtime.Container {
	labels := map[string]string{"airlock.enable": "true"}
	for k, v := range extra {
		labels[k] = v
	}
	return runtime.Container{ID: id, Name: name, Labels: labels}
}

func TestBuildWorld_UnarmedContainerYieldsNotOK(t *testing.T) {
	cfg := newTestConfig(t)
	c := runtime.Container{ID: "c1", Name: "plain", Labels: map[string]string{}}

	result := buildWorld([]runtime.Container{c}, nil, cfg, nil)

	if _, ok := result.world.ResolvedPolicy("c1"); ok {
		t.Errorf("ResolvedPolicy(unarmed) ok = true, want false")
	}
}

func TestBuildWorld_ArmedPolicyAndWindow(t *testing.T) {
	cfg := newTestConfig(t)
	c := armedContainer("c1", "web", map[string]string{
		"airlock.allow":        "example.com",
		"airlock.alert.window": "5m",
	})

	result := buildWorld([]runtime.Container{c}, nil, cfg, nil)

	pol, ok := result.world.ResolvedPolicy("c1")
	if !ok {
		t.Fatalf("ResolvedPolicy(armed) ok = false, want true")
	}
	if pol.AlertWindow != 5*time.Minute {
		t.Errorf("AlertWindow = %v, want 5m", pol.AlertWindow)
	}
	if w, ok := result.windows[pol.Name]; !ok || w != 5*time.Minute {
		t.Errorf("windows[%q] = %v, %v, want 5m, true", pol.Name, w, ok)
	}

	foundExample := false
	for _, e := range pol.Allow {
		if e.Kind == policy.Domain && e.Domain == "example.com" {
			foundExample = true
		}
	}
	if !foundExample {
		t.Errorf("resolved Allow %+v missing example.com", pol.Allow)
	}
}

func TestBuildWorld_NetworkInventory(t *testing.T) {
	cfg := newTestConfig(t)
	nets := []runtime.Network{
		{Name: "bridge", ID: "net1", Subnets: []netip.Prefix{netip.MustParsePrefix("172.17.0.0/16")}},
	}

	result := buildWorld(nil, nets, cfg, nil)

	got := result.world.Networks()
	if len(got) != 1 || got[0].Name != "bridge" {
		t.Errorf("Networks() = %+v, want one network named bridge", got)
	}
}

func TestBuildWorld_ProjectPeerIndex(t *testing.T) {
	cfg := newTestConfig(t)
	c1 := armedContainer("c1", "web", nil)
	c1.Project = "myproj"
	c1.Networks = []runtime.ContainerNetwork{{Name: "bridge", IPs: []netip.Addr{mustAddr(t, "10.0.0.2")}}}

	c2 := runtime.Container{ID: "c2", Name: "db", Labels: map[string]string{}, Project: "myproj",
		Networks: []runtime.ContainerNetwork{{Name: "bridge", IPs: []netip.Addr{mustAddr(t, "10.0.0.3")}}}}

	result := buildWorld([]runtime.Container{c1, c2}, nil, cfg, nil)

	peers := result.world.ProjectPeerIPs("myproj")
	if len(peers) != 2 {
		t.Fatalf("ProjectPeerIPs(myproj) = %v, want 2 addrs", peers)
	}

	if got := result.world.ContainerProject("c1"); got != "myproj" {
		t.Errorf("ContainerProject(c1) = %q, want myproj", got)
	}
	if got := result.world.ProjectPeerIPs(""); got != nil {
		t.Errorf("ProjectPeerIPs(\"\") = %v, want nil", got)
	}
}

func TestBuildWorld_ResolverIPsFromResolvConf(t *testing.T) {
	cfg := newTestConfig(t)
	base := []netip.Addr{mustAddr(t, "192.0.2.53")}

	result := buildWorld(nil, nil, cfg, base)

	got := result.world.ResolverIPs()
	if len(got) != 1 || got[0] != mustAddr(t, "192.0.2.53") {
		t.Errorf("ResolverIPs() = %v, want [192.0.2.53]", got)
	}
}

func TestBuildWorld_ImplicitAllowFoldedIntoArmedPolicy(t *testing.T) {
	t.Setenv("AIRLOCK_IMPLICIT_ALLOW", "198.51.100.9,*.updates.example")
	cfg := newTestConfig(t)

	c := armedContainer("c1", "web", map[string]string{"airlock.allow": "example.com"})
	base := []netip.Addr{mustAddr(t, "192.0.2.53")}

	result := buildWorld([]runtime.Container{c}, nil, cfg, base)

	pol, ok := result.world.ResolvedPolicy("c1")
	if !ok {
		t.Fatalf("ResolvedPolicy: ok = false")
	}

	var haveIP, haveWildcard bool
	for _, e := range pol.Allow {
		if e.Kind == policy.IP && e.Addr == mustAddr(t, "198.51.100.9") {
			haveIP = true
		}
		if e.Kind == policy.DomainWildcard && e.Domain == "updates.example" {
			haveWildcard = true
		}
	}
	if !haveIP {
		t.Errorf("armed policy Allow %+v missing implicit-allow IP entry", pol.Allow)
	}
	if !haveWildcard {
		t.Errorf("armed policy Allow %+v missing implicit-allow wildcard entry", pol.Allow)
	}

	// The bare-IP implicit-allow entry is also folded into the resolver
	// baseline (see resolverIPsFor's doc comment), unioned with the
	// resolv.conf-derived base.
	resolvers := result.world.ResolverIPs()
	wantAddrs := map[netip.Addr]bool{
		mustAddr(t, "192.0.2.53"):   true,
		mustAddr(t, "198.51.100.9"): true,
	}
	if len(resolvers) != len(wantAddrs) {
		t.Fatalf("ResolverIPs() = %v, want %v", resolvers, wantAddrs)
	}
	for _, a := range resolvers {
		if !wantAddrs[a] {
			t.Errorf("ResolverIPs() contains unexpected address %v", a)
		}
	}
}

func TestBuildWorld_ImplicitAllowNoneDisablesResolverBaseline(t *testing.T) {
	t.Setenv("AIRLOCK_IMPLICIT_ALLOW", "none")
	cfg := newTestConfig(t)

	c := armedContainer("c1", "web", map[string]string{"airlock.allow": "example.com"})
	base := []netip.Addr{mustAddr(t, "192.0.2.53")}

	result := buildWorld([]runtime.Container{c}, nil, cfg, base)

	if got := result.world.ResolverIPs(); got != nil {
		t.Errorf("ResolverIPs() = %v, want nil (baseline disabled)", got)
	}

	pol, ok := result.world.ResolvedPolicy("c1")
	if !ok {
		t.Fatalf("ResolvedPolicy: ok = false")
	}
	if len(pol.Allow) != 1 {
		t.Errorf("armed policy Allow = %+v, want exactly the container's own example.com entry", pol.Allow)
	}
}

func TestParseResolvConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	contents := "# comment\nnameserver 192.0.2.1\n; another comment\nnameserver 2001:db8::1\nsearch example.com\nnameserver not-an-ip\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write resolv.conf fixture: %v", err)
	}

	got := parseResolvConf(path)
	want := []netip.Addr{mustAddr(t, "192.0.2.1"), mustAddr(t, "2001:db8::1")}
	if len(got) != len(want) {
		t.Fatalf("parseResolvConf() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("parseResolvConf()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestParseResolvConf_MissingFile(t *testing.T) {
	got := parseResolvConf(filepath.Join(t.TempDir(), "does-not-exist"))
	if got != nil {
		t.Errorf("parseResolvConf(missing) = %v, want nil", got)
	}
}

// TestResolvConfPath_HonorsEnvOverride covers the actual deployment
// scenario the packaging chunk relies on: a host-network container's own
// /etc/resolv.conf is Docker's embedded 127.0.0.11 stub, not the real LAN
// resolver, so the daemon must read AIRLOCK_RESOLV_CONF (typically
// pointed at a bind-mounted /host/etc/resolv.conf) instead when it is
// set, and fall back to the conventional default when it is not.
func TestResolvConfPath_HonorsEnvOverride(t *testing.T) {
	dir := t.TempDir()
	fixture := filepath.Join(dir, "host-resolv.conf")
	if err := os.WriteFile(fixture, []byte("nameserver 203.0.113.53\n"), 0o600); err != nil {
		t.Fatalf("write resolv.conf fixture: %v", err)
	}

	t.Setenv("AIRLOCK_RESOLV_CONF", fixture)
	if got := resolvConfPath(); got != fixture {
		t.Fatalf("resolvConfPath() = %q, want %q", got, fixture)
	}
	if got := parseResolvConf(resolvConfPath()); len(got) != 1 || got[0] != mustAddr(t, "203.0.113.53") {
		t.Errorf("parseResolvConf(resolvConfPath()) = %v, want [203.0.113.53]", got)
	}
}

// TestResolvConfPath_UnsetFallsBackToDefault covers the other half: with
// AIRLOCK_RESOLV_CONF unset, resolvConfPath must fall back to
// defaultResolvConfPath, and parsing a path that does not exist there (as
// in a test sandbox with no real /etc/resolv.conf-shaped file at that
// exact path) must degrade gracefully to an empty resolver set, never an
// error.
func TestResolvConfPath_UnsetFallsBackToDefault(t *testing.T) {
	t.Setenv("AIRLOCK_RESOLV_CONF", "")
	if got := resolvConfPath(); got != defaultResolvConfPath {
		t.Fatalf("resolvConfPath() = %q, want default %q", got, defaultResolvConfPath)
	}

	// Exercise the graceful-degradation path directly against a path
	// guaranteed not to exist, rather than assuming something about the
	// test host's real /etc/resolv.conf.
	got := parseResolvConf(filepath.Join(t.TempDir(), "etc", "resolv.conf"))
	if got != nil {
		t.Errorf("parseResolvConf(missing default-shaped path) = %v, want nil", got)
	}
}

// TestEngineAndWorldEndToEnd proves the wiring, not the engine's own
// matching logic (already covered by internal/engine's tests): a
// buildWorld snapshot fed into a real engine.Engine allows a connection
// matching an armed policy's Allow entry and classifies an unmatched,
// name-evidence-free connection as unresolved-ip.
func TestEngineAndWorldEndToEnd(t *testing.T) {
	cfg := newTestConfig(t)
	c := armedContainer("c1", "web", map[string]string{"airlock.allow": "203.0.113.10:80"})

	result := buildWorld([]runtime.Container{c}, nil, cfg, nil)
	eng := engine.New(result.world)

	now := time.Now()

	allowed := eng.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "web",
		DstIP: mustAddr(t, "203.0.113.10"), DstPort: 80, Timestamp: now,
	})
	if len(allowed) != 0 {
		t.Errorf("Process(allowed conn) = %+v, want no violations", allowed)
	}

	denied := eng.Process(observe.Event{
		Kind: observe.Connection, ContainerID: "c1", ContainerName: "web",
		DstIP: mustAddr(t, "198.51.100.20"), DstPort: 80, Timestamp: now,
	})
	if len(denied) != 1 {
		t.Fatalf("Process(unmatched conn) = %+v, want exactly one violation", denied)
	}
}
