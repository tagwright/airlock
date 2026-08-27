// SPDX-License-Identifier: GPL-3.0-or-later

// Package policy defines airlock's core policy vocabulary: the destination
// entry grammar shared by allow/deny lists everywhere they appear (labels,
// named policy sets, and groups), the Mode and Scope enums, and the
// resolved per-container Policy shape later layers (label reading,
// airlock.yml, group merging) produce.
//
// This package parses and validates syntax only. It has no knowledge of
// containers, networks, or the observe package's event stream -- matching
// a parsed Entry against an observed connection is the policy engine's job,
// built on top of this vocabulary.
//
// The grammar implemented here is frozen: see "Airlock Label Grammar
// (Draft)" (ratified 2026-08-27). Nothing here may accept syntax that
// document does not define, and nothing it marks reserved-and-rejected may
// be relaxed.
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// DestKind discriminates which of Entry's payload fields are populated.
type DestKind int

const (
	// Domain matches an exact name: "example.com".
	Domain DestKind = iota
	// DomainWildcard matches one or more leading labels of a suffix, but
	// never the apex itself: "*.example.com" matches "api.example.com"
	// but not "example.com". Entry.Domain holds the suffix without the
	// leading "*.".
	DomainWildcard
	// IP matches a single IPv4 or IPv6 literal.
	IP
	// CIDR matches an IPv4 or IPv6 address range.
	CIDR
	// AnyDest is the bare "*" entry: matches any destination. This is
	// the explicit denylist-escape posture (Fork 2), never an inferred
	// default.
	AnyDest
	// SelfNetworks is the "@self" token: every network this specific
	// container is attached to, resolved per container at evaluation
	// time. Meaningful only under Scope All.
	SelfNetworks
	// ProjectPeers is the "@project" token: every container sharing this
	// container's compose project. Meaningful only under Scope All.
	ProjectPeers
	// NamedNetwork is the "net:<name>" token: a specific runtime
	// network's CIDR(s), resolved live by name. Entry.NetworkName holds
	// the name after "net:".
	NamedNetwork
)

// String returns a stable lowercase name for the kind, for logging and
// error messages, not for parsing.
func (k DestKind) String() string {
	switch k {
	case Domain:
		return "domain"
	case DomainWildcard:
		return "domain_wildcard"
	case IP:
		return "ip"
	case CIDR:
		return "cidr"
	case AnyDest:
		return "any"
	case SelfNetworks:
		return "self_networks"
	case ProjectPeers:
		return "project_peers"
	case NamedNetwork:
		return "named_network"
	default:
		return "unknown"
	}
}

// Entry is one parsed destination-entry grammar term, as it appears in an
// allow or deny list. Only the payload field(s) matching Kind are
// meaningful; the rest are left at their zero value.
type Entry struct {
	// Raw is the original entry string exactly as given, kept for error
	// messages and for round-tripping through tools like `airlock
	// suggest` even if String's canonical form differs cosmetically.
	Raw string

	Kind DestKind

	// Domain holds the name for Kind Domain (the exact name) and Kind
	// DomainWildcard (the suffix, without the leading "*.").
	Domain string

	// Addr holds the literal for Kind IP.
	Addr netip.Addr

	// Prefix holds the range for Kind CIDR.
	Prefix netip.Prefix

	// NetworkName holds the name for Kind NamedNetwork.
	NetworkName string

	// Port is the destination port, meaningful only when HasPort is
	// true. HasPort false (the common case) means any port.
	Port    uint16
	HasPort bool
}

// ErrNoneSentinel is returned by ParseEntry for the literal string "none".
//
// "none" is the zero-egress sentinel (airlock.allow=none), but it is a
// property of a whole allow/deny *value*, not a destination entry in its
// own right -- it can only appear alone, never alongside other entries in
// a csv list, and it means something different depending on which list it
// appears in (allow=none declares zero egress; the grammar has no defined
// meaning for deny=none beyond "no explicit denies", which is already the
// zero value of an empty list). Deciding that here, per-entry, would be the
// wrong layer: it is the caller (label/config parsing, which sees the whole
// raw value before splitting on commas) that must recognize a bare "none"
// value and special-case it, rather than calling ParseEntry on it and
// papering over a non-entry with a successful-looking parse. ParseEntry
// therefore rejects "none" outright, and returns this sentinel so the
// caller can detect the specific case (via errors.Is) and produce a
// tailored message instead of a generic parse failure.
var ErrNoneSentinel = errors.New(`"none" is the zero-egress sentinel, not a destination entry; the caller must recognize a whole allow/deny value of "none" before splitting into entries`)

// portRangeRE matches a reserved port-range suffix such as ":1000-2000",
// including when it trails a bracketed literal such as "[::1]:1000-2000".
// It is checked before any other parsing so that reserved syntax is always
// reported as reserved, never misread as some other kind of error.
var portRangeRE = regexp.MustCompile(`:[0-9]+-[0-9]+$`)

// ParseEntry parses one destination-entry grammar term:
//
//	entry := dest [ ":" port ] | "@self" | "@project" | "net:" name
//	dest  := domain | "*." domain | ipv4 | "[" ipv6 "]" | ipv6 | cidr | "*"
//	port  := integer 1-65535
//
// Notable rules, matching the frozen grammar exactly:
//
//   - "*.example.com" matches one or more leading labels and never the
//     apex; a bare "*.", a non-leftmost wildcard ("api.*.example.com"),
//     and more than one "*" are all validation errors.
//   - An IPv6 literal or CIDR that carries a port must be bracketed,
//     "[2606:4700::1]:443" -- a bare, unbracketed IPv6 literal with a
//     trailing ":NNN" is ambiguous with the address's own colons, so it is
//     parsed as part of the address when that succeeds, and reported as an
//     invalid literal (naming the bracket fix) when it does not. Bare IPv6
//     with no port is valid unbracketed.
//   - "@self", "@project", and "net:<name>" are, by the grammar above,
//     alternatives to "dest [ \":\" port ]", not part of it: they never
//     carry a port suffix in v1, any-port only. A port or any trailing
//     content after one of these tokens is a validation error, not a
//     silently-accepted extension.
//   - The "/udp" suffix and port ranges ("1000-2000") are reserved and
//     rejected in v1 with a descriptive error, never accepted inertly.
//   - "none" is rejected; see ErrNoneSentinel.
//
// ParseEntry does no I/O and no network/container lookups: "@self",
// "@project", and "net:<name>" are recorded as tokens only, resolved later
// by the policy engine.
func ParseEntry(s string) (Entry, error) {
	raw := s
	s = strings.TrimSpace(s)

	if s == "" {
		return Entry{}, errors.New("entry is empty")
	}
	if s == "none" {
		return Entry{}, ErrNoneSentinel
	}

	// Reserved-and-rejected syntax is checked first, on the whole entry,
	// so it is always reported as reserved rather than being misread as
	// some other class of error further down.
	if strings.HasSuffix(strings.ToLower(s), "/udp") {
		return Entry{}, fmt.Errorf("entry %q: the /udp suffix is reserved for a future version and is rejected in v1 -- airlock v1 evaluates TCP only", raw)
	}
	if portRangeRE.MatchString(s) {
		return Entry{}, fmt.Errorf("entry %q: port ranges are reserved for a future version and are rejected in v1", raw)
	}

	switch {
	case s == "@self":
		return Entry{Raw: raw, Kind: SelfNetworks}, nil
	case s == "@project":
		return Entry{Raw: raw, Kind: ProjectPeers}, nil
	case strings.HasPrefix(s, "@self"), strings.HasPrefix(s, "@project"):
		return Entry{}, fmt.Errorf("entry %q: @self and @project accept no port suffix or trailing characters in v1, any-port only", raw)
	case strings.HasPrefix(s, "@"):
		return Entry{}, fmt.Errorf("entry %q: unknown token, expected @self or @project", raw)
	case strings.HasPrefix(s, "net:"):
		name := s[len("net:"):]
		if name == "" {
			return Entry{}, fmt.Errorf("entry %q: net: requires a network name", raw)
		}
		return Entry{Raw: raw, Kind: NamedNetwork, NetworkName: name}, nil
	}

	if strings.HasPrefix(s, "[") {
		e, err := parseBracketedDest(s)
		if err != nil {
			return Entry{}, fmt.Errorf("entry %q: %w", raw, err)
		}
		e.Raw = raw
		return e, nil
	}

	// Whole-string address or prefix, no port: covers bare IPv4, bare
	// IPv6 (including one with trailing colon-digits that is valid as
	// part of the address itself -- the documented ambiguity resolution),
	// and any CIDR.
	if addr, err := netip.ParseAddr(s); err == nil {
		return Entry{Raw: raw, Kind: IP, Addr: addr}, nil
	}
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return Entry{Raw: raw, Kind: CIDR, Prefix: pfx}, nil
	}

	// Not a bare address/prefix: look for a trailing ":port".
	if idx := strings.LastIndexByte(s, ':'); idx >= 0 {
		left, portStr := s[:idx], s[idx+1:]
		if strings.Contains(left, ":") {
			// More than one colon before the split point means this
			// was an attempt at an unbracketed IPv6-with-port, which
			// failed to parse as a plain address above. That is
			// ambiguous syntax the grammar does not accept.
			return Entry{}, fmt.Errorf("entry %q: %q is not a valid IPv6 literal; if a port was intended it must be bracketed, e.g. [%s]:port", raw, s, left)
		}
		port, err := parsePort(portStr)
		if err != nil {
			return Entry{}, fmt.Errorf("entry %q: %w", raw, err)
		}
		e, err := classifyDest(left)
		if err != nil {
			return Entry{}, fmt.Errorf("entry %q: %w", raw, err)
		}
		e.Raw = raw
		e.Port = port
		e.HasPort = true
		return e, nil
	}

	// No colon at all: a bare dest with no port.
	e, err := classifyDest(s)
	if err != nil {
		return Entry{}, fmt.Errorf("entry %q: %w", raw, err)
	}
	e.Raw = raw
	return e, nil
}

// parseBracketedDest parses a "[" ipv6 "]" [ ":" port ] dest, s starting
// with "[". Brackets are only ever valid around an IPv6 literal or IPv6
// CIDR (the frozen grammar defines the bracket form for ipv6 only; IPv4
// never needs it since it has no colons to disambiguate).
func parseBracketedDest(s string) (Entry, error) {
	idx := strings.IndexByte(s, ']')
	if idx < 0 {
		return Entry{}, fmt.Errorf("unterminated '[' bracket in %q", s)
	}
	inner := s[1:idx]
	rest := s[idx+1:]

	var port uint16
	var hasPort bool
	if rest != "" {
		if !strings.HasPrefix(rest, ":") {
			return Entry{}, fmt.Errorf("unexpected characters after ']' in %q: %q", s, rest)
		}
		p, err := parsePort(rest[1:])
		if err != nil {
			return Entry{}, err
		}
		port, hasPort = p, true
	}

	if strings.Contains(inner, "/") {
		pfx, err := netip.ParsePrefix(inner)
		if err != nil {
			return Entry{}, fmt.Errorf("invalid bracketed CIDR %q: %w", inner, err)
		}
		if !pfx.Addr().Is6() {
			return Entry{}, fmt.Errorf("brackets are only valid around IPv6, got %q", inner)
		}
		return Entry{Kind: CIDR, Prefix: pfx, Port: port, HasPort: hasPort}, nil
	}

	addr, err := netip.ParseAddr(inner)
	if err != nil {
		return Entry{}, fmt.Errorf("invalid bracketed IPv6 literal %q: %w", inner, err)
	}
	if !addr.Is6() {
		return Entry{}, fmt.Errorf("brackets are only valid around IPv6, got %q", inner)
	}
	return Entry{Kind: IP, Addr: addr, Port: port, HasPort: hasPort}, nil
}

// classifyDest classifies a bare dest term with no port component: a
// domain, a wildcard domain, an IP literal, a CIDR, or the bare "*". It is
// used both for a dest with no port at all and, after splitting off a
// trailing ":port", for the dest portion left over.
func classifyDest(base string) (Entry, error) {
	if base == "*" {
		return Entry{Kind: AnyDest}, nil
	}
	if strings.HasPrefix(base, "*.") {
		suffix := base[2:]
		if suffix == "" {
			return Entry{}, fmt.Errorf("wildcard %q requires a non-empty domain suffix after '*.'", base)
		}
		if strings.Contains(suffix, "*") {
			return Entry{}, fmt.Errorf("wildcard %q: only one leftmost '*.' wildcard is permitted", base)
		}
		if !isValidDomain(suffix) {
			return Entry{}, fmt.Errorf("wildcard %q: %q is not a valid domain", base, suffix)
		}
		return Entry{Kind: DomainWildcard, Domain: suffix}, nil
	}
	if strings.Contains(base, "*") {
		return Entry{}, fmt.Errorf("%q: '*' must appear only as a leftmost '*.' label, or alone", base)
	}
	if addr, err := netip.ParseAddr(base); err == nil {
		return Entry{Kind: IP, Addr: addr}, nil
	}
	if pfx, err := netip.ParsePrefix(base); err == nil {
		return Entry{Kind: CIDR, Prefix: pfx}, nil
	}
	if isValidDomain(base) {
		return Entry{Kind: Domain, Domain: base}, nil
	}
	return Entry{}, fmt.Errorf("%q is not a valid destination (domain, IP, CIDR, or '*')", base)
}

// parsePort parses a port string per "port := integer 1-65535".
func parsePort(s string) (uint16, error) {
	if s == "" {
		return 0, errors.New("port is empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid port %q: must be numeric", s)
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return 0, fmt.Errorf("invalid port %q: must be 1-65535", s)
	}
	return uint16(n), nil
}

// isValidDomain reports whether d is a syntactically plausible domain name:
// one or more dot-separated labels, each 1-63 characters of letters,
// digits, or interior hyphens.
func isValidDomain(d string) bool {
	if d == "" {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if !isValidDomainLabel(label) {
			return false
		}
	}
	return true
}

func isValidDomainLabel(l string) bool {
	if l == "" || len(l) > 63 {
		return false
	}
	for i, r := range l {
		switch {
		case r == '-':
			if i == 0 || i == len(l)-1 {
				return false
			}
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			// ok
		default:
			return false
		}
	}
	return true
}

// String renders Entry back to its canonical textual form. This is not
// guaranteed to equal Raw byte-for-byte (e.g. it always renders IPv6
// literals via netip's canonical form), but it always round-trips through
// ParseEntry to an equal Entry. It is used by `airlock suggest` and by
// tests.
func (e Entry) String() string {
	var base string
	switch e.Kind {
	case Domain:
		base = e.Domain
	case DomainWildcard:
		base = "*." + e.Domain
	case IP:
		if e.HasPort && e.Addr.Is6() {
			return "[" + e.Addr.String() + "]:" + strconv.Itoa(int(e.Port))
		}
		base = e.Addr.String()
	case CIDR:
		if e.HasPort && e.Prefix.Addr().Is6() {
			return "[" + e.Prefix.String() + "]:" + strconv.Itoa(int(e.Port))
		}
		base = e.Prefix.String()
	case AnyDest:
		base = "*"
	case SelfNetworks:
		return "@self"
	case ProjectPeers:
		return "@project"
	case NamedNetwork:
		return "net:" + e.NetworkName
	default:
		return e.Raw
	}
	if e.HasPort {
		return base + ":" + strconv.Itoa(int(e.Port))
	}
	return base
}
