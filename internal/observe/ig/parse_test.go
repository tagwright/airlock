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
