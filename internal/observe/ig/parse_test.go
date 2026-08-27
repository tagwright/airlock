// SPDX-License-Identifier: GPL-3.0-or-later

package ig

import (
	"net/netip"
	"testing"

	"github.com/tagwright/airlock/internal/observe"
)

func TestParseTCPLine(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantEvent bool
		check     func(t *testing.T, ev observe.Event)
	}{
		{
			name:      "connect event emits a Connection",
			line:      `{"timestamp":"2026-08-27T12:00:00.000000Z","type":"connect","src":{"addr":"172.17.0.2","port":60552},"dst":{"addr":"172.67.196.142","port":443},"comm":"wget","pid":750625,"runtime":{"containerId":"abc123","containerName":"bb"}}`,
			wantEvent: true,
			check: func(t *testing.T, ev observe.Event) {
				if ev.Kind != observe.Connection {
					t.Errorf("Kind = %v, want Connection", ev.Kind)
				}
				want := netip.MustParseAddr("172.67.196.142")
				if ev.DstIP != want {
					t.Errorf("DstIP = %v, want %v", ev.DstIP, want)
				}
				if ev.DstPort != 443 {
					t.Errorf("DstPort = %d, want 443", ev.DstPort)
				}
				if ev.Proto != "tcp" {
					t.Errorf("Proto = %q, want tcp", ev.Proto)
				}
				if ev.ContainerID != "abc123" || ev.ContainerName != "bb" {
					t.Errorf("container attribution = %q/%q, want abc123/bb", ev.ContainerID, ev.ContainerName)
				}
			},
		},
		{
			name:      "accept event is skipped",
			line:      `{"type":"accept","dst":{"addr":"10.0.0.1","port":8080},"runtime":{"containerId":"c1"}}`,
			wantEvent: false,
		},
		{
			name:      "close event is skipped",
			line:      `{"type":"close","dst":{"addr":"10.0.0.1","port":8080},"runtime":{"containerId":"c1"}}`,
			wantEvent: false,
		},
		{
			name:      "connect event with unparseable dst address is skipped",
			line:      `{"type":"connect","dst":{"addr":"not-an-ip","port":443},"runtime":{"containerId":"c1"}}`,
			wantEvent: false,
		},
		{
			// Captured live against a real trace_tcp:latest v0.55.1
			// gadget run (--containername airlock-itest-target) while
			// the target curled https://example.com; containerId,
			// containerImageDigest, pid/tid, and timestamps are
			// sanitized/replaced, every field name and nesting is
			// verbatim. See docs/TESTING.md. This line already parsed
			// correctly against the pre-fix adapter -- trace_tcp's real
			// shape matched the research brief's assumption exactly --
			// it is kept here as a real-world fixture, not a regression
			// case.
			name:      "real captured connect event (sanitized)",
			line:      `{"accept_fd":-1,"dst":{"addr":"104.20.23.154","port":443,"proto":"TCP","proto_raw":6,"version":4},"error":"","error_raw":0,"fd":4,"k8s":{"containerName":"","hostnetwork":false,"namespace":"","node":"","owner":{"kind":"","name":""},"podLabels":"","podName":""},"netns_id":4026541349,"proc":{"comm":"curl","creds":{"gid":0,"group":"root","uid":0,"user":"root"},"mntns_id":4026541344,"parent":{"comm":"sh","pid":1,"tid":1},"pid":2,"tid":2},"runtime":{"containerId":"deadbeef0000000000000000000000000000000000000000000000000000ff","containerImageDigest":"sha256:0000000000000000000000000000000000000000000000000000000000ff","containerImageName":"example/image","containerName":"airlock-itest-target","containerPid":3,"containerStartedAt":0,"runtimeName":"docker"},"src":{"addr":"192.168.16.2","port":39420,"proto":"TCP","proto_raw":6,"version":4},"timestamp":"2026-08-27T07:42:41.640251531Z","timestamp_raw":1787816561640251531,"type":"connect","type_raw":0}`,
			wantEvent: true,
			check: func(t *testing.T, ev observe.Event) {
				want := netip.MustParseAddr("104.20.23.154")
				if ev.DstIP != want || ev.DstPort != 443 {
					t.Errorf("DstIP/DstPort = %v/%d, want %v/443", ev.DstIP, ev.DstPort, want)
				}
				if ev.ContainerName != "airlock-itest-target" {
					t.Errorf("ContainerName = %q, want airlock-itest-target", ev.ContainerName)
				}
			},
		},
		{
			name:      "malformed JSON is skipped, not fatal",
			line:      `{"type":"connect", this is not json`,
			wantEvent: false,
		},
		{
			name:      "empty line is skipped",
			line:      ``,
			wantEvent: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := parseTCPLine([]byte(tc.line))
			if ok != tc.wantEvent {
				t.Fatalf("parseTCPLine() ok = %v, want %v", ok, tc.wantEvent)
			}
			if ok && tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

func TestParseDNSLine(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantEvent bool
		check     func(t *testing.T, ev observe.Event)
	}{
		{
			name:      "query event is skipped (qr=Q)",
			line:      `{"timestamp":"2026-08-27T12:00:00.000000Z","qr":"Q","name":"inspektor-gadget.io.","qtype":"A","src":{"addr":"172.17.0.2","port":36282},"dst":{"addr":"192.168.0.1","port":53},"nameserver":"192.168.0.1","runtime":{"containerId":"c1","containerName":"test-trace-dns"}}`,
			wantEvent: false,
		},
		{
			name:      "response event with A answers emits a DNSAnswer, array form",
			line:      `{"timestamp":"2026-08-27T12:00:00.100000Z","qr":"R","name":"inspektor-gadget.io.","qtype":"A","nameserver":"192.168.0.1:53","addresses":["104.21.11.16","172.67.75.15"],"rcode":"Success","num_answers":2,"runtime":{"containerId":"c1","containerName":"test-trace-dns"}}`,
			wantEvent: true,
			check: func(t *testing.T, ev observe.Event) {
				if ev.Kind != observe.DNSAnswer {
					t.Errorf("Kind = %v, want DNSAnswer", ev.Kind)
				}
				if ev.QName != "inspektor-gadget.io." {
					t.Errorf("QName = %q, want inspektor-gadget.io.", ev.QName)
				}
				want := []netip.Addr{
					netip.MustParseAddr("104.21.11.16"),
					netip.MustParseAddr("172.67.75.15"),
				}
				if len(ev.Answers) != len(want) {
					t.Fatalf("Answers = %v, want %v", ev.Answers, want)
				}
				for i := range want {
					if ev.Answers[i] != want[i] {
						t.Errorf("Answers[%d] = %v, want %v", i, ev.Answers[i], want[i])
					}
				}
				if ev.Nameserver != "192.168.0.1:53" {
					t.Errorf("Nameserver = %q, want 192.168.0.1:53", ev.Nameserver)
				}
				if ev.ContainerID != "c1" || ev.ContainerName != "test-trace-dns" {
					t.Errorf("container attribution = %q/%q, want c1/test-trace-dns", ev.ContainerID, ev.ContainerName)
				}
			},
		},
		{
			name:      "response event with A answers emits a DNSAnswer, comma-separated string form",
			line:      `{"qr":"R","name":"example.com.","addresses":"93.184.216.34, 93.184.216.35","runtime":{"containerId":"c1"}}`,
			wantEvent: true,
			check: func(t *testing.T, ev observe.Event) {
				if len(ev.Answers) != 2 {
					t.Fatalf("Answers = %v, want 2 entries", ev.Answers)
				}
			},
		},
		{
			name:      "response event with no answers (e.g. NXDOMAIN) emits nothing",
			line:      `{"qr":"R","name":"doesnotexist.example.","qtype":"A","rcode":"NameError","num_answers":0,"runtime":{"containerId":"c1"}}`,
			wantEvent: false,
		},
		{
			name:      "response event with only unparseable addresses emits nothing",
			line:      `{"qr":"R","name":"example.com.","addresses":["not-an-ip"],"runtime":{"containerId":"c1"}}`,
			wantEvent: false,
		},
		{
			// REGRESSION for the real bug this integration pass found:
			// IG's actual trace_dns "nameserver" field is an OBJECT
			// ({"addr":...,"version":4}), not the "ip:port"/"ip" string
			// the research brief's reconstructed example had assumed.
			// Before flexNameserver, unmarshaling this exact shape into
			// a string field made json.Unmarshal return a non-nil
			// error, and parseDNSLine treated ANY Unmarshal error as
			// "drop the line" -- so every real trace_dns response event
			// was silently discarded, regardless of how well-formed the
			// rest of the line was. This line, sanitized from a live
			// v0.55.1 capture (--containername airlock-itest-target,
			// resolving example.com), must parse successfully with the
			// nameserver's addr extracted. See docs/TESTING.md.
			name:      "real captured DNS response, object-shaped nameserver (regression)",
			line:      `{"addresses":"104.20.23.154,172.66.147.243","cwd":"","dst":{"addr":"127.0.0.1","port":51206,"proto":"UDP","proto_raw":17,"version":4},"exepath":"","id":"2dc2","k8s":{"containerName":"","hostnetwork":false,"namespace":"","node":"","owner":{"kind":"","name":""},"podLabels":"","podName":""},"latency_ns":"0ns","latency_ns_raw":0,"name":"example.com.","nameserver":{"addr":"127.0.0.11","version":4},"netns_id":4026541349,"num_answers":2,"pkt_type":"HOST","pkt_type_raw":0,"proc":{"comm":"curl","creds":{"gid":0,"group":"root","uid":0,"user":"root"},"mntns_id":4026541344,"parent":{"comm":"sh","pid":1,"tid":1},"pid":2,"tid":2},"qr":"R","qr_raw":true,"qtype":"A","qtype_raw":1,"ra":true,"rcode":"Success","rcode_raw":0,"rd":true,"runtime":{"containerId":"deadbeef0000000000000000000000000000000000000000000000000000ff","containerImageDigest":"sha256:0000000000000000000000000000000000000000000000000000000000ff","containerImageName":"example/image","containerName":"airlock-itest-target","containerPid":3,"containerStartedAt":0,"runtimeName":"docker"},"src":{"addr":"127.0.0.11","port":53,"proto":"UDP","proto_raw":17,"version":4},"tc":false,"timestamp":"2026-08-27T07:42:41.615944438Z","timestamp_raw":1787816561615944438}`,
			wantEvent: true,
			check: func(t *testing.T, ev observe.Event) {
				if ev.QName != "example.com." {
					t.Errorf("QName = %q, want example.com.", ev.QName)
				}
				want := []netip.Addr{
					netip.MustParseAddr("104.20.23.154"),
					netip.MustParseAddr("172.66.147.243"),
				}
				if len(ev.Answers) != len(want) {
					t.Fatalf("Answers = %v, want %v", ev.Answers, want)
				}
				for i := range want {
					if ev.Answers[i] != want[i] {
						t.Errorf("Answers[%d] = %v, want %v", i, ev.Answers[i], want[i])
					}
				}
				if ev.Nameserver != "127.0.0.11" {
					t.Errorf("Nameserver = %q, want 127.0.0.11 (extracted from the real object-shaped field)", ev.Nameserver)
				}
				if ev.ContainerName != "airlock-itest-target" {
					t.Errorf("ContainerName = %q, want airlock-itest-target", ev.ContainerName)
				}
			},
		},
		{
			name:      "malformed JSON is skipped, not fatal",
			line:      `{"qr":"R","name":`,
			wantEvent: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := parseDNSLine([]byte(tc.line))
			if ok != tc.wantEvent {
				t.Fatalf("parseDNSLine() ok = %v, want %v", ok, tc.wantEvent)
			}
			if ok && tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}

func TestParseSNILine(t *testing.T) {
	cases := []struct {
		name      string
		line      string
		wantEvent bool
		check     func(t *testing.T, ev observe.Event)
	}{
		{
			name:      "sni event emits a TLSHello",
			line:      `{"comm":"wget","pid":693742,"tid":693742,"name":"wikimedia.org","runtime":{"containerId":"c1","containerName":"ubuntu"}}`,
			wantEvent: true,
			check: func(t *testing.T, ev observe.Event) {
				if ev.Kind != observe.TLSHello {
					t.Errorf("Kind = %v, want TLSHello", ev.Kind)
				}
				if ev.SNIName != "wikimedia.org" {
					t.Errorf("SNIName = %q, want wikimedia.org", ev.SNIName)
				}
				if ev.ContainerID != "c1" || ev.ContainerName != "ubuntu" {
					t.Errorf("container attribution = %q/%q, want c1/ubuntu", ev.ContainerID, ev.ContainerName)
				}
			},
		},
		{
			name:      "event with empty name is skipped",
			line:      `{"comm":"wget","name":"","runtime":{"containerId":"c1"}}`,
			wantEvent: false,
		},
		{
			// Captured live against a real trace_sni:latest v0.55.1
			// gadget run (--containername airlock-itest-target) while
			// the target curled https://example.com. This line already
			// parsed correctly against the pre-fix adapter -- trace_sni's
			// real shape matched what this file expected -- kept here as
			// a real-world fixture. See docs/TESTING.md.
			name:      "real captured SNI event (sanitized)",
			line:      `{"k8s":{"containerName":"","hostnetwork":false,"namespace":"","node":"","owner":{"kind":"","name":""},"podLabels":"","podName":""},"name":"example.com","netns_id":4026541349,"proc":{"comm":"curl","creds":{"gid":0,"group":"root","uid":0,"user":"root"},"mntns_id":4026541344,"parent":{"comm":"sh","pid":1,"tid":1},"pid":2,"tid":2},"runtime":{"containerId":"deadbeef0000000000000000000000000000000000000000000000000000ff","containerImageDigest":"sha256:0000000000000000000000000000000000000000000000000000000000ff","containerImageName":"example/image","containerName":"airlock-itest-target","containerPid":3,"containerStartedAt":0,"runtimeName":"docker"},"timestamp":"2026-08-27T07:42:41.643250876Z","timestamp_raw":1787816561643250876}`,
			wantEvent: true,
			check: func(t *testing.T, ev observe.Event) {
				if ev.SNIName != "example.com" {
					t.Errorf("SNIName = %q, want example.com", ev.SNIName)
				}
				if ev.ContainerName != "airlock-itest-target" {
					t.Errorf("ContainerName = %q, want airlock-itest-target", ev.ContainerName)
				}
			},
		},
		{
			name:      "malformed JSON is skipped, not fatal",
			line:      `not json at all`,
			wantEvent: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, ok := parseSNILine([]byte(tc.line))
			if ok != tc.wantEvent {
				t.Fatalf("parseSNILine() ok = %v, want %v", ok, tc.wantEvent)
			}
			if ok && tc.check != nil {
				tc.check(t, ev)
			}
		})
	}
}
