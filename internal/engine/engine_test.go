// SPDX-License-Identifier: GPL-3.0-or-later

package engine

import (
	"net/netip"
	"testing"
	"time"

	"github.com/tagwright/airlock/internal/observe"
	"github.com/tagwright/airlock/internal/policy"
	"github.com/tagwright/core/runtime"
)

// -- test fixtures and helpers --

func testPolicy(name string, scope policy.Scope, mode policy.Mode, allow, deny []string) policy.Policy {
	var a, d []policy.Entry
	for _, s := range allow {
		a = append(a, mustEntry(s))
	}
	for _, s := range deny {
		d = append(d, mustEntry(s))
	}
	return policy.Policy{
		Name:        name,
		Enable:      true,
		Mode:        mode,
		Scope:       scope,
		Allow:       a,
		Deny:        d,
		AlertWindow: time.Hour,
	}
}

func connEvent(containerID string, ip netip.Addr, port uint16, ts time.Time) observe.Event {
	return observe.Event{
		Kind:        observe.Connection,
		ContainerID: containerID,
		DstIP:       ip,
		DstPort:     port,
		Proto:       "tcp",
		Timestamp:   ts,
	}
}

func dnsEvent(containerID, qname string, ttl time.Duration, ts time.Time, answers ...netip.Addr) observe.Event {
	return observe.Event{
		Kind:        observe.DNSAnswer,
		ContainerID: containerID,
		QName:       qname,
		Answers:     answers,
		TTL:         ttl,
		Timestamp:   ts,
	}
}

func sniEvent(containerID, name string, ts time.Time) observe.Event {
	return observe.Event{
		Kind:        observe.TLSHello,
		ContainerID: containerID,
		SNIName:     name,
		Timestamp:   ts,
	}
}

func wantNoViolation(t *testing.T, got []Violation) {
	t.Helper()
	if len(got) != 0 {
		t.Fatalf("expected no violation, got %+v", got)
	}
}

func wantOneViolation(t *testing.T, got []Violation, class Class) Violation {
	t.Helper()
	if len(got) != 1 {
		t.Fatalf("expected exactly one violation, got %d: %+v", len(got), got)
	}
	if got[0].Class != class {
		t.Fatalf("expected class %v, got %v (%+v)", class, got[0].Class, got[0])
	}
	return got[0]
}

// -- allow scenarios --

func TestAllowedByIPRule(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"203.0.113.7:443"}, nil)
	e := New(w)

	got := e.Process(connEvent("c1", mustAddr("203.0.113.7"), 443, time.Now()))
	wantNoViolation(t, got)
}

func TestAllowedByCIDRRule(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"203.0.113.0/24"}, nil)
	e := New(w)

	got := e.Process(connEvent("c1", mustAddr("203.0.113.42"), 8080, time.Now()))
	wantNoViolation(t, got)
}

func TestAllowedByExactDomainAfterDNS(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"example.com:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("93.184.216.34")
	wantNoViolation(t, e.Process(dnsEvent("c1", "example.com", 300*time.Second, now, ip)))
	got := e.Process(connEvent("c1", ip, 443, now.Add(time.Second)))
	wantNoViolation(t, got)
}

func TestAllowedByWildcardDomain(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"*.example.com:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("93.184.216.34")
	e.Process(dnsEvent("c1", "api.example.com", 300*time.Second, now, ip))
	got := e.Process(connEvent("c1", ip, 443, now.Add(time.Second)))
	wantNoViolation(t, got)
}

func TestWildcardDomainDoesNotMatchApex(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"*.example.com:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("93.184.216.34")
	e.Process(dnsEvent("c1", "example.com", 300*time.Second, now, ip))
	// The apex resolved but *.example.com must not match it: this falls
	// through to the default-deny floor, immediately (evaluation is
	// synchronous and final at connect time). It HAD DNS name evidence
	// throughout, so no-match rather than unresolved-ip.
	got := e.Process(connEvent("c1", ip, 443, now.Add(time.Second)))
	wantOneViolation(t, got, ClassNoMatch)
}

// -- fail-closed on SNI: SNI is enrichment only, never a match input --
//
// See engine.go's package doc comment for why: trace_sni carries no
// destination IP, so it can only be tied to a connection by
// same-container-plus-timing, and a real integration pass reproduced that
// timing-only join misattributing one connection's SNI to a different,
// unrelated connection -- a false negative a security tool must not have.
// A Domain/DomainWildcard entry, allow or deny alike, now matches ONLY via
// a DNS-cache correlation.

// TestFailClosedSNIOnlyDoesNotMatchAllow proves the core fix: an SNI name
// that matches an allow entry does NOT rescue a connection whose
// destination IP is absent from this container's DNS cache. It also
// proves SNI is still carried through as enrichment on the resulting
// Violation.
func TestFailClosedSNIOnlyDoesNotMatchAllow(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"example.com:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("93.184.216.34")
	e.Process(sniEvent("c1", "example.com", now))
	got := e.Process(connEvent("c1", ip, 443, now.Add(time.Second)))

	v := wantOneViolation(t, got, ClassNoMatch)
	if v.SNIName != "example.com" {
		t.Errorf("Violation.SNIName = %q, want the observed SNI carried through as enrichment", v.SNIName)
	}
	if v.DNSName != "" {
		t.Errorf("Violation.DNSName = %q, want empty (no DNS answer was ever recorded)", v.DNSName)
	}
}

// TestFailClosedSNIDoesNotOverrideDNSMismatch proves DNS-cache correlation
// alone decides the match, even when a same-container SNI names a
// destination that IS on the allowlist: an earlier version of this engine
// let SNI win on disagreement and would have allowed this connection.
func TestFailClosedSNIDoesNotOverrideDNSMismatch(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"good.example:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("198.51.100.9")
	// DNS says this IP resolved from a name NOT in the allowlist; SNI on
	// the connection itself names the allowed host. DNS decides: this is
	// still a violation.
	e.Process(dnsEvent("c1", "bad.example", 300*time.Second, now, ip))
	e.Process(sniEvent("c1", "good.example", now.Add(time.Second)))
	got := e.Process(connEvent("c1", ip, 443, now.Add(2*time.Second)))

	v := wantOneViolation(t, got, ClassNoMatch)
	if v.DNSName != "bad.example" || v.SNIName != "good.example" {
		t.Errorf("evidence fields = dns=%q sni=%q, want both carried through even though only DNS decided the match", v.DNSName, v.SNIName)
	}
}

// TestDNSCorrelationAllowStillWorks proves the DNS-cache correlation path
// -- the ONLY name-matching path under fail-closed -- still allows a
// destination correctly. Companion to TestAllowedByExactDomainAfterDNS,
// stated explicitly here for the fail-closed proof set.
func TestDNSCorrelationAllowStillWorks(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"good.example:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("198.51.100.9")
	e.Process(dnsEvent("c1", "good.example", 300*time.Second, now, ip))
	got := e.Process(connEvent("c1", ip, 443, now.Add(time.Second)))
	wantNoViolation(t, got)
}

// -- deny and default-deny --

func TestDenyBeatsAllow(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"*"}, []string{"bad.example:443"})
	e := New(w)

	now := time.Now()
	ip := mustAddr("198.51.100.9")
	e.Process(dnsEvent("c1", "bad.example", 300*time.Second, now, ip))
	got := e.Process(connEvent("c1", ip, 443, now.Add(time.Second)))
	wantOneViolation(t, got, ClassDeny)
}

func TestDefaultDenyNoMatchWithName(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"other.example:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("198.51.100.9")
	e.Process(dnsEvent("c1", "unknown.example", 300*time.Second, now, ip))
	got := e.Process(connEvent("c1", ip, 443, now.Add(time.Second)))
	wantOneViolation(t, got, ClassNoMatch)
}

func TestDefaultDenyUnresolvedIPWithNoNameEvidence(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"other.example:443"}, nil)
	e := New(w)

	got := e.Process(connEvent("c1", mustAddr("198.51.100.9"), 443, time.Now()))
	wantOneViolation(t, got, ClassUnresolvedIP)
}

// -- scope and tokens --

func networkWorldFixture() (*fakeWorld, netip.Prefix) {
	w := newFakeWorld()
	subnet := mustPrefix("10.10.0.0/24")
	w.networks = []runtime.Network{
		{Name: "mediastack", ID: "net1", Subnets: []netip.Prefix{subnet}},
	}
	w.attach["c1"] = []runtime.ContainerNetwork{
		{Name: "mediastack", ID: "net1", IPs: []netip.Addr{mustAddr("10.10.0.5")}},
	}
	w.project["c1"] = "proj1"
	w.peers["proj1"] = []netip.Addr{mustAddr("10.10.0.6")}
	return w, subnet
}

func TestScopeExternalDoesNotJudgeOwnNetwork(t *testing.T) {
	w, _ := networkWorldFixture()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, nil, nil)
	e := New(w)

	got := e.Process(connEvent("c1", mustAddr("10.10.0.6"), 80, time.Now()))
	wantNoViolation(t, got)
}

func TestScopeAllJudgesOwnNetworkAndSelfAllows(t *testing.T) {
	w, _ := networkWorldFixture()
	w.policies["c1"] = testPolicy("svc", policy.All, policy.Alert, []string{"@self"}, nil)
	e := New(w)

	// Some other address on the same network (not the exact peer IP):
	// @self resolves to the whole subnet, so this must match.
	got := e.Process(connEvent("c1", mustAddr("10.10.0.99"), 80, time.Now()))
	wantNoViolation(t, got)
}

func TestScopeAllWithoutAllowIsViolation(t *testing.T) {
	w, _ := networkWorldFixture()
	w.policies["c1"] = testPolicy("svc", policy.All, policy.Alert, nil, nil)
	e := New(w)

	got := e.Process(connEvent("c1", mustAddr("10.10.0.6"), 80, time.Now()))
	wantOneViolation(t, got, ClassUnresolvedIP)
}

func TestProjectTokenMatchesPeerExactlyNotSubnet(t *testing.T) {
	w, _ := networkWorldFixture()
	w.policies["c1"] = testPolicy("svc", policy.All, policy.Alert, []string{"@project"}, nil)
	e := New(w)

	// The declared peer IP matches.
	wantNoViolation(t, e.Process(connEvent("c1", mustAddr("10.10.0.6"), 80, time.Now())))

	// A different address on the same subnet that is NOT a declared
	// project peer does not match @project (unlike @self, which is
	// subnet-based).
	got := e.Process(connEvent("c1", mustAddr("10.10.0.42"), 80, time.Now()))
	wantOneViolation(t, got, ClassUnresolvedIP)
}

func TestNamedNetworkTokenAllows(t *testing.T) {
	w, _ := networkWorldFixture()
	w.policies["c1"] = testPolicy("svc", policy.All, policy.Alert, []string{"net:mediastack"}, nil)
	e := New(w)

	got := e.Process(connEvent("c1", mustAddr("10.10.0.200"), 80, time.Now()))
	wantNoViolation(t, got)
}

// -- loopback and the implicit resolver baseline --

func TestLoopbackNeverJudged(t *testing.T) {
	w := newFakeWorld()
	// A wide-open deny would fire on anything else, proving loopback was
	// excluded rather than incidentally allowed.
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, nil, []string{"*"})
	e := New(w)

	wantNoViolation(t, e.Process(connEvent("c1", mustAddr("127.0.0.1"), 80, time.Now())))
	wantNoViolation(t, e.Process(connEvent("c1", mustAddr("::1"), 80, time.Now())))
}

func TestResolverOn53ImplicitlyAllowed(t *testing.T) {
	w := newFakeWorld()
	w.resolvers = []netip.Addr{mustAddr("172.20.0.1")}
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, nil, nil)
	e := New(w)

	wantNoViolation(t, e.Process(connEvent("c1", mustAddr("172.20.0.1"), 53, time.Now())))
}

func TestResolverIPOnOtherPortIsNotImplicitlyAllowed(t *testing.T) {
	w := newFakeWorld()
	w.resolvers = []netip.Addr{mustAddr("172.20.0.1")}
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, nil, nil)
	e := New(w)

	got := e.Process(connEvent("c1", mustAddr("172.20.0.1"), 8080, time.Now()))
	wantOneViolation(t, got, ClassUnresolvedIP)
}

// -- port constraints --

func TestAllowedPortDoesNotPermitOtherPort(t *testing.T) {
	w := newFakeWorld()
	w.policies["c1"] = testPolicy("svc", policy.External, policy.Alert, []string{"host.example:443"}, nil)
	e := New(w)

	now := time.Now()
	ip := mustAddr("198.51.100.9")
	e.Process(dnsEvent("c1", "host.example", 300*time.Second, now, ip))

	wantNoViolation(t, e.Process(connEvent("c1", ip, 443, now.Add(time.Second))))

	// The port-8080 connection still fails to match (the allow entry is
	// pinned to 443), immediately: the same name evidence that matched on
	// 443 is simply the wrong port here.
	got := e.Process(connEvent("c1", ip, 8080, now.Add(time.Second)))
	wantOneViolation(t, got, ClassNoMatch)
}

// -- unarmed containers --

func TestUnarmedContainerNeverViolates(t *testing.T) {
	w := newFakeWorld()
	// No policy registered for c1 at all: ResolvedPolicy returns ok=false.
	e := New(w)

	got := e.Process(connEvent("c1", mustAddr("203.0.113.7"), 443, time.Now()))
	wantNoViolation(t, got)
}
