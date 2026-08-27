// SPDX-License-Identifier: GPL-3.0-or-later

package policy

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("test setup: bad address %q: %v", s, err)
	}
	return a
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("test setup: bad prefix %q: %v", s, err)
	}
	return p
}

// TestParseEntryValid covers every valid destination-entry form the frozen
// grammar defines, and asserts the parsed field values, not just success.
func TestParseEntryValid(t *testing.T) {
	type want struct {
		kind        DestKind
		domain      string
		addr        string // parsed against netip.ParseAddr for comparison
		prefix      string // parsed against netip.ParsePrefix for comparison
		networkName string
		port        uint16
		hasPort     bool
	}
	cases := []struct {
		name string
		in   string
		want want
	}{
		{"exact domain", "example.com", want{kind: Domain, domain: "example.com"}},
		{"exact domain with port", "example.com:443", want{kind: Domain, domain: "example.com", port: 443, hasPort: true}},
		{"exact domain, single label", "localhost", want{kind: Domain, domain: "localhost"}},

		{"wildcard domain", "*.example.com", want{kind: DomainWildcard, domain: "example.com"}},
		{"wildcard domain with port", "*.example.com:443", want{kind: DomainWildcard, domain: "example.com", port: 443, hasPort: true}},
		{"wildcard domain, worked example", "*.githubusercontent.com:443", want{kind: DomainWildcard, domain: "githubusercontent.com", port: 443, hasPort: true}},
		{"wildcard, deeper subdomain matches leftmost only", "*.a.example.com", want{kind: DomainWildcard, domain: "a.example.com"}},

		{"ipv4 literal", "203.0.113.7", want{kind: IP, addr: "203.0.113.7"}},
		{"ipv4 literal with port", "203.0.113.7:443", want{kind: IP, addr: "203.0.113.7", port: 443, hasPort: true}},

		{"ipv6 literal bare, no port", "2606:4700::1111", want{kind: IP, addr: "2606:4700::1111"}},
		{"ipv6 literal bracketed, no port", "[2606:4700::1111]", want{kind: IP, addr: "2606:4700::1111"}},
		{"ipv6 literal bracketed with port", "[2606:4700::1111]:443", want{kind: IP, addr: "2606:4700::1111", port: 443, hasPort: true}},
		{
			// Documented ambiguity resolution: a bare, unbracketed IPv6
			// literal with a trailing colon-digits group that is itself a
			// valid hex group parses as part of the address, not as a
			// dest:port split.
			"ipv6 literal, trailing colon-digits parses as part of the address",
			"2606:4700::1111:443",
			want{kind: IP, addr: "2606:4700::1111:443"},
		},

		{"ipv4 cidr", "10.0.0.0/8", want{kind: CIDR, prefix: "10.0.0.0/8"}},
		{"ipv4 cidr with port", "10.0.0.0/8:8443", want{kind: CIDR, prefix: "10.0.0.0/8", port: 8443, hasPort: true}},
		{"ipv6 cidr, no port", "2606:4700::/32", want{kind: CIDR, prefix: "2606:4700::/32"}},
		{"ipv6 cidr bracketed with port", "[2606:4700::/32]:443", want{kind: CIDR, prefix: "2606:4700::/32", port: 443, hasPort: true}},

		{"any dest", "*", want{kind: AnyDest}},
		{"any dest with port", "*:443", want{kind: AnyDest, port: 443, hasPort: true}},

		{"self networks token", "@self", want{kind: SelfNetworks}},
		{"project peers token", "@project", want{kind: ProjectPeers}},
		{"named network token", "net:mediastack_backend", want{kind: NamedNetwork, networkName: "mediastack_backend"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := ParseEntry(c.in)
			if err != nil {
				t.Fatalf("ParseEntry(%q): unexpected error: %v", c.in, err)
			}
			if e.Kind != c.want.kind {
				t.Errorf("ParseEntry(%q).Kind = %v, want %v", c.in, e.Kind, c.want.kind)
			}
			if e.Domain != c.want.domain {
				t.Errorf("ParseEntry(%q).Domain = %q, want %q", c.in, e.Domain, c.want.domain)
			}
			if c.want.addr != "" {
				want := mustAddr(t, c.want.addr)
				if e.Addr != want {
					t.Errorf("ParseEntry(%q).Addr = %v, want %v", c.in, e.Addr, want)
				}
			}
			if c.want.prefix != "" {
				want := mustPrefix(t, c.want.prefix)
				if e.Prefix != want {
					t.Errorf("ParseEntry(%q).Prefix = %v, want %v", c.in, e.Prefix, want)
				}
			}
			if e.NetworkName != c.want.networkName {
				t.Errorf("ParseEntry(%q).NetworkName = %q, want %q", c.in, e.NetworkName, c.want.networkName)
			}
			if e.HasPort != c.want.hasPort {
				t.Errorf("ParseEntry(%q).HasPort = %v, want %v", c.in, e.HasPort, c.want.hasPort)
			}
			if e.HasPort && e.Port != c.want.port {
				t.Errorf("ParseEntry(%q).Port = %d, want %d", c.in, e.Port, c.want.port)
			}
			if e.Raw != c.in {
				t.Errorf("ParseEntry(%q).Raw = %q, want %q", c.in, e.Raw, c.in)
			}
		})
	}
}

// TestParseEntryNamedNetworkTakesWholeRemainder documents a deliberate edge
// decision: "net:<name>" has no port position in the grammar at all (unlike
// "dest [ \":\" port ]"), so ParseEntry takes everything after "net:" as
// the literal network name, including any colons, rather than guessing that
// a trailing ":NNN" was meant as a port.
func TestParseEntryNamedNetworkTakesWholeRemainder(t *testing.T) {
	e, err := ParseEntry("net:foo:443")
	if err != nil {
		t.Fatalf("ParseEntry: unexpected error: %v", err)
	}
	if e.Kind != NamedNetwork {
		t.Fatalf("Kind = %v, want NamedNetwork", e.Kind)
	}
	if e.NetworkName != "foo:443" {
		t.Fatalf("NetworkName = %q, want %q", e.NetworkName, "foo:443")
	}
	if e.HasPort {
		t.Fatalf("HasPort = true, want false: net: tokens carry no port suffix in v1")
	}
}

// TestParseEntryRejections covers every required rejection: bad wildcard
// shapes, reserved-and-rejected syntax, and malformed ports.
func TestParseEntryRejections(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"bare wildcard dot", "*."},
		{"non-leftmost wildcard", "api.*.example.com"},
		{"double wildcard", "*.example.*.com"},
		{"udp suffix with port", "example.com:443/udp"},
		{"udp suffix without port", "example.com/udp"},
		{"udp suffix on ip", "203.0.113.7:443/udp"},
		{"port range", "example.com:1000-2000"},
		{"port range on bracketed ipv6", "[2606:4700::1]:1000-2000"},
		{"port zero", "example.com:0"},
		{"port too large", "example.com:70000"},
		{"port non-numeric", "example.com:https"},
		{"empty port", "example.com:"},
		{"self with port", "@self:443"},
		{"project with port", "@project:443"},
		{"self with trailing garbage", "@selfish"},
		{"unknown at-token", "@unknown"},
		{"net with empty name", "net:"},
		{"unbracketed ipv6 with unparseable trailing port", "2606:4700::1:99999"},
		{"brackets around ipv4 rejected", "[203.0.113.7]:443"},
		{"unterminated bracket", "[2606:4700::1"},
		{"garbage after bracket", "[2606:4700::1]x"},
		{"invalid domain characters", "exa mple.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := ParseEntry(c.in)
			if err == nil {
				t.Fatalf("ParseEntry(%q) = %+v, want error", c.in, e)
			}
		})
	}
}

// TestParseEntryNoneSentinel asserts that ParseEntry rejects the bare
// "none" sentinel distinctly, so a caller can special-case a whole
// allow/deny value of "none" via errors.Is rather than pattern-matching an
// error string.
func TestParseEntryNoneSentinel(t *testing.T) {
	_, err := ParseEntry("none")
	if !errors.Is(err, ErrNoneSentinel) {
		t.Fatalf("ParseEntry(%q) error = %v, want errors.Is(err, ErrNoneSentinel)", "none", err)
	}
}

// TestEntryStringRoundTrip asserts String() renders a canonical form that
// re-parses to an equal Entry, for every canonical valid form.
func TestEntryStringRoundTrip(t *testing.T) {
	inputs := []string{
		"example.com",
		"example.com:443",
		"*.example.com",
		"*.example.com:443",
		"203.0.113.7",
		"203.0.113.7:443",
		"2606:4700::1111",
		"[2606:4700::1111]:443",
		"10.0.0.0/8",
		"10.0.0.0/8:8443",
		"2606:4700::/32",
		"[2606:4700::/32]:443",
		"*",
		"*:443",
		"@self",
		"@project",
		"net:mediastack_backend",
	}
	for _, in := range inputs {
		t.Run(in, func(t *testing.T) {
			e1, err := ParseEntry(in)
			if err != nil {
				t.Fatalf("ParseEntry(%q): %v", in, err)
			}
			canon := e1.String()
			e2, err := ParseEntry(canon)
			if err != nil {
				t.Fatalf("ParseEntry(%q) [canonical form of %q]: %v", canon, in, err)
			}
			// Compare everything except Raw, which is expected to differ
			// (e1.Raw is the original input, e2.Raw is the canonical form).
			e1.Raw, e2.Raw = "", ""
			if e1 != e2 {
				t.Errorf("round trip mismatch for %q: parsed %+v, canonical %q reparsed as %+v", in, e1, canon, e2)
			}
		})
	}
}

func TestDestKindString(t *testing.T) {
	kinds := []DestKind{Domain, DomainWildcard, IP, CIDR, AnyDest, SelfNetworks, ProjectPeers, NamedNetwork}
	seen := map[string]bool{}
	for _, k := range kinds {
		s := k.String()
		if s == "" || s == "unknown" {
			t.Errorf("DestKind(%d).String() = %q, want a stable non-empty name", k, s)
		}
		if seen[s] {
			t.Errorf("DestKind(%d).String() = %q, duplicate name", k, s)
		}
		seen[s] = true
	}
}

// TestParseEntryErrorMentionsBrackets checks the ambiguous-IPv6-with-port
// error actually names the bracket fix, since that is the one piece of
// grammar guidance an operator hitting this error most needs.
func TestParseEntryErrorMentionsBrackets(t *testing.T) {
	_, err := ParseEntry("2606:4700::1:99999")
	if err == nil || !strings.Contains(err.Error(), "[") {
		t.Fatalf("expected an error mentioning the bracket fix, got: %v", err)
	}
}
