// SPDX-License-Identifier: GPL-3.0-or-later

package ig

import (
	"encoding/json"
	"net/netip"
	"strings"
	"time"

	"github.com/tagwright/airlock/internal/observe"
)

// The structs and parse functions in this file are the only place in this
// package (and in airlock as a whole) that know Inspektor Gadget's JSON
// field names. Everything downstream, starting with the observe.Event
// values these functions return, is backend-neutral.
//
// Field names below are taken from each gadget's documented schema
// (gadget.yaml) as of IG v0.55.1: trace_tcp, trace_dns, trace_sni. See the
// research brief this adapter was built against for field-by-field
// sourcing.
//
// One field's real shape diverged from that research brief's best-effort
// reconstruction and was corrected against a live v0.55.1 capture: see
// flexNameserver's doc comment below. Every other field name, nesting, and
// discriminator value checked against that same live capture (dst/src
// endpoints, runtime.containerId/containerName, trace_tcp's "connect"
// type, trace_dns's "addresses" comma-separated string, trace_sni's bare
// "name") matched what this file already expected. See docs/TESTING.md for
// the full comparison and the real captured lines it was checked against.

// runtimeInfo is IG's common container-attribution enrichment block,
// present on all three gadgets' events.
type runtimeInfo struct {
	ContainerID   string `json:"containerId"`
	ContainerName string `json:"containerName"`
}

// endpoint is IG's common src/dst shape on networking gadgets.
type endpoint struct {
	Addr string `json:"addr"`
	Port uint16 `json:"port"`
}

// flexStringList unmarshals a field that IG may render as either a JSON
// array of strings or a single (possibly comma-separated) string. The
// published trace_dns schema does not pin down the on-the-wire JSON shape
// of its "addresses" field beyond "resolved IP(s)", so this accepts both
// rather than guessing wrong and dropping every DNS answer.
//
// Confirmed against a real v0.55.1 capture (see docs/TESTING.md): IG
// actually renders "addresses" as a single comma-separated string (e.g.
// "104.20.23.154,172.66.147.243"), never a JSON array, for every response
// this adapter has observed live. The array branch is kept regardless,
// both because the published schema does not rule it out for some other
// answer shape and because accepting a second, unobserved-but-plausible
// wire shape costs nothing.
type flexStringList []string

func (f *flexStringList) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*f = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if strings.TrimSpace(s) == "" {
		*f = nil
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	*f = out
	return nil
}

// flexNameserver unmarshals trace_dns's "nameserver" field. A real v0.55.1
// capture (see docs/TESTING.md) showed this is an OBJECT
// ({"addr":"127.0.0.11","version":4}), not the bare "ip:port" or "ip"
// string the published schema text ("the resolver being talked to") had
// implied and this adapter was originally built against. That mismatch
// was not cosmetic: encoding/json.Unmarshal returns a non-nil error when
// a JSON object lands on a string-typed struct field, and parseDNSLine
// treats any Unmarshal error as "drop this line" -- so every single
// trace_dns response event was being silently discarded before this
// fix, regardless of how well-formed the rest of the line was. This type
// accepts the real object shape (extracting just Addr) and falls back to
// a plain string for resilience against a future schema reverting to one,
// rather than special-casing just the shape observed today.
type flexNameserver string

func (f *flexNameserver) UnmarshalJSON(data []byte) error {
	var obj struct {
		Addr string `json:"addr"`
	}
	if err := json.Unmarshal(data, &obj); err == nil {
		*f = flexNameserver(obj.Addr)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*f = flexNameserver(s)
	return nil
}

// parseTimestamp best-effort parses IG's timestamp string. It returns the
// zero time.Time if ts is empty or unparseable -- a bad or missing
// timestamp is not a reason to drop an otherwise-valid event.
func parseTimestamp(ts string) time.Time {
	if ts == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, ts); err == nil {
		return t
	}
	return time.Time{}
}

// -- trace_tcp --

// tcpMsg mirrors trace_tcp's JSON event shape: src/dst endpoints, a
// connect/accept/close type discriminator, and the common runtime
// enrichment block.
type tcpMsg struct {
	Timestamp string      `json:"timestamp"`
	Type      string      `json:"type"`
	Dst       endpoint    `json:"dst"`
	Runtime   runtimeInfo `json:"runtime"`
}

// parseTCPLine parses one line of trace_tcp NDJSON. It emits an event only
// for outbound connection attempts (type=="connect"); accept and close
// events, and any line that fails to parse or carries no usable
// destination address, are silently skipped rather than treated as fatal.
func parseTCPLine(line []byte) (observe.Event, bool) {
	var m tcpMsg
	if err := json.Unmarshal(line, &m); err != nil {
		return observe.Event{}, false
	}
	if m.Type != "connect" {
		return observe.Event{}, false
	}
	addr, err := netip.ParseAddr(m.Dst.Addr)
	if err != nil {
		return observe.Event{}, false
	}
	return observe.Event{
		Kind:          observe.Connection,
		ContainerID:   m.Runtime.ContainerID,
		ContainerName: m.Runtime.ContainerName,
		Timestamp:     parseTimestamp(m.Timestamp),
		DstIP:         addr,
		DstPort:       m.Dst.Port,
		Proto:         "tcp",
	}, true
}

// -- trace_dns --

// dnsMsg mirrors trace_dns's JSON event shape. qr distinguishes query (Q)
// from response (R) events; addresses and rcode are only meaningful on
// responses. trace_dns does not document a per-answer TTL field (only
// latency_ns, the query-to-response latency, and num_answers, a count) --
// so observe.Event.TTL is left zero for this backend. See the TODO in
// ig.go's package doc for the dropped-events signal, which is a separate
// concern from this per-message parsing.
type dnsMsg struct {
	Timestamp  string         `json:"timestamp"`
	QR         string         `json:"qr"`
	Name       string         `json:"name"`
	Nameserver flexNameserver `json:"nameserver"`
	Addresses  flexStringList `json:"addresses"`
	Runtime    runtimeInfo    `json:"runtime"`
}

// parseDNSLine parses one line of trace_dns NDJSON. It emits an event only
// for response events (qr=="R") that carry at least one address that
// parses as a valid IP (i.e. an A/AAAA answer). Queries (qr=="Q"),
// answer-less responses (e.g. NXDOMAIN), and unparseable lines produce no
// event.
func parseDNSLine(line []byte) (observe.Event, bool) {
	var m dnsMsg
	if err := json.Unmarshal(line, &m); err != nil {
		return observe.Event{}, false
	}
	if m.QR != "R" {
		return observe.Event{}, false
	}
	answers := make([]netip.Addr, 0, len(m.Addresses))
	for _, a := range m.Addresses {
		if addr, err := netip.ParseAddr(a); err == nil {
			answers = append(answers, addr)
		}
	}
	if len(answers) == 0 {
		return observe.Event{}, false
	}
	return observe.Event{
		Kind:          observe.DNSAnswer,
		ContainerID:   m.Runtime.ContainerID,
		ContainerName: m.Runtime.ContainerName,
		Timestamp:     parseTimestamp(m.Timestamp),
		QName:         m.Name,
		Answers:       answers,
		Nameserver:    string(m.Nameserver),
	}, true
}

// -- trace_sni --

// sniMsg mirrors trace_sni's JSON event shape. trace_sni's documented
// schema carries only the SNI name plus process/container attribution --
// no destination IP/port -- so observe.Event.DstIP/DstPort are left zero
// for events from this source.
type sniMsg struct {
	Timestamp string      `json:"timestamp"`
	Name      string      `json:"name"`
	Runtime   runtimeInfo `json:"runtime"`
}

// parseSNILine parses one line of trace_sni NDJSON. It emits an event for
// any line that parses and carries a non-empty SNI name.
func parseSNILine(line []byte) (observe.Event, bool) {
	var m sniMsg
	if err := json.Unmarshal(line, &m); err != nil {
		return observe.Event{}, false
	}
	if m.Name == "" {
		return observe.Event{}, false
	}
	return observe.Event{
		Kind:          observe.TLSHello,
		ContainerID:   m.Runtime.ContainerID,
		ContainerName: m.Runtime.ContainerName,
		Timestamp:     parseTimestamp(m.Timestamp),
		SNIName:       m.Name,
	}, true
}
