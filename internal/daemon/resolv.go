// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 techgaud

package daemon

import (
	"net/netip"
	"os"
	"strings"
)

// defaultResolvConfPath is the conventional location of the host's
// resolver configuration, bind-mounted into airlock's container per the
// frozen architecture's "-v /:/host" deployment shape. AIRLOCK_RESOLV_CONF
// overrides it, mostly for tests and for an operator running airlock
// somewhere resolv.conf lives elsewhere.
const defaultResolvConfPath = "/etc/resolv.conf"

// parseResolvConf returns every "nameserver" address named in the
// resolv.conf-format file at path, or nil if the file cannot be read.
//
// JUDGMENT CALL: this is deliberately best-effort in every direction the
// frozen doc's "best-effort from the host resolv.conf" language allows:
// a missing or unreadable file is silently treated as "no resolvers
// known" (never an error a caller must handle), a malformed nameserver
// line is skipped rather than aborting the rest of the file, and no
// attempt is made to honor resolv.conf's other directives (search,
// options, sortlist) or systemd-resolved's stub-resolver indirection --
// this only ever reads literal "nameserver <addr>" lines. On a host where
// resolv.conf points at 127.0.0.53 (systemd-resolved's stub), that
// literal stub address is exactly what gets returned; airlock has no way
// to peer through it to whatever upstream resolver systemd-resolved
// itself uses, and does not try to. The engine's own loopback check
// already excludes 127.0.0.0/8 as never-egress, so a stub-resolver
// address recorded here as a "resolver" contributes nothing in that case
// -- it only matters, per the frozen doc's own framing, for a
// host-network container hitting a real, non-loopback LAN resolver.
func parseResolvConf(path string) []netip.Addr {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var out []netip.Addr
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(fields[1]))
		if err != nil {
			continue
		}
		out = append(out, addr.Unmap())
	}
	return out
}
