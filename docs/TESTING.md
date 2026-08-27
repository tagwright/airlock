# Testing

This is airlock's test methodology and an honest accounting of what has
actually been proven to work against a real Docker socket and a real
Inspektor Gadget (`ig`), as opposed to what merely compiles or passes
against fakes.

## How we test

Three layers, in increasing order of how much they actually prove:

1. **Unit tests, in-tree** (`go test ./...`, no Docker socket, no `ig`).
   Pure-function coverage: label parsing (`internal/discovery`), policy
   resolution (`internal/resolve`), entry/mode/scope grammar
   (`internal/policy`), the correlation and matching engine
   (`internal/engine`), and `internal/observe/ig`'s parser against
   hand-written AND real-captured NDJSON fixtures (see below). Fast,
   narrow by design.

2. **`test/integration/` harness, against a live Docker socket and a
   real, privileged `ig`.** This is where airlock is actually proven end
   to end: build the real image from the real Dockerfile, run real
   throwaway containers, drive real Inspektor Gadget gadgets against
   them, and assert on the daemon's own state snapshot and real alert
   delivery. Every object these scripts create is named
   `airlock-itest-*` (or tagged `airlock-itest:latest`), never touches
   anything else on the host, and is torn down in a trap on exit
   (success, failure, or interrupt). Four scripts today:

   - `run-capture.sh` -- the environment probe plus a real NDJSON capture
     of trace_tcp/trace_dns/trace_sni against a throwaway target
     container making known connections, scoped with `--containername`
     so only that container's events are captured. Does not build or run
     airlock itself; this is purely "does `ig` work here, and what does
     its real output actually look like."
   - `run-detect.sh` -- the full pipeline: builds `airlock-itest:latest`
     from the real `Dockerfile`, runs it `--privileged` against the real
     Docker socket with no `--containername` scoping (the real,
     fleet-wide invocation airlock always issues), labels a target
     container with a real policy, drives three real connections fired
     back to back (no deliberate spacing -- see "RESOLVED" below for why
     that's safe now), and asserts the resulting `state.json` violation
     tally and a real ntfy delivery.
   - `run-groups.sh` (pass 2) -- everything `run-detect.sh` does not
     exercise: a real `deny` rule beating `allow: "*"`, a Fork 8 group
     arming two containers with NO `airlock.*` label at all (matched by
     Docker network), `@self` under `scope: all` resolved against REAL
     core network data (core's `ListNetworks`/`Container.Networks`, not
     unit-test fakes) permitting a container-to-container connection
     while an external one from the same container still violates, and
     `mode: audit` tallying a violation without alerting on it
     immediately. See "Pass 2" below.
   - `run-pass3.sh` (pass 3) -- the two remaining group tokens and the
     alert flood breaker, still against real Docker/core data and a real
     `ig`: `@project` resolved from a real compose-project pair of
     containers (`internal/daemon/world.go`'s `ProjectPeerIPs`), `net:<name>`
     resolved from a second, entirely separate real named network
     (`internal/engine/match.go`'s `namedNetworkContains` walking core's
     real `ListNetworks`), and `internal/alert`'s flood breaker collapsing
     a real burst of distinct-destination violations into one "flooding"
     alert. See "Pass 3" below.

3. **Deliberately manual / needs Nate's resources.** A few things are
   exercised by hand or not at all here, listed under "What remains"
   below -- mostly because they need a real external account, a
   non-Docker runtime, or a host in a specific state this repo-local
   harness cannot construct safely.

## Environment probe

**Result: privileged `ig` runs cleanly on this host.** Linux 6.8.0-136,
BTF present at `/sys/kernel/btf/vmlinux`, Docker 29.1.3, no rootless/
Docker-Desktop layer in the way.

```
docker run --rm --privileged -v /:/host --pid=host \
  ghcr.io/inspektor-gadget/ig:v0.55.1 version
# -> v0.55.1
```

A minimal `trace_exec` probe against the live host loaded eBPF and
streamed real events immediately. The offline fallback this section
would otherwise document (validate the parser against whatever real JSON
can be scraped up, document what needs Nate's host) was not needed --
every claim below was checked against this exact host, live.

## Real ig output vs. the parser's assumptions

`internal/observe/ig/parse.go` was built from a research brief
(`gadget.yaml` docs and reconstructed examples), not from real captured
output. `test/integration/run-capture.sh` captures real NDJSON for all
three gadgets against a target container making three known connections
(`https://example.com`, `https://1.1.1.1` -- a bare IP, no DNS lookup --
and `https://www.wikipedia.org`).

**What matched the research brief exactly**, confirmed against real
lines:

- `trace_tcp`: `dst.addr`/`dst.port`, `type` (`"connect"`/`"close"`
  observed live; `"accept"` not exercised by this harness but unchanged
  in shape), `runtime.containerId`/`runtime.containerName`, `timestamp`
  (RFC3339Nano, 9 fractional digits -- `time.Parse(time.RFC3339Nano, ...)`
  handles it).
- `trace_dns`: `qr`, `name`, `addresses` as a **comma-separated string**
  (confirmed, not a JSON array -- `flexStringList`'s array branch remains
  untested against reality but costs nothing to keep), `runtime.*`.
- `trace_sni`: bare top-level `name`, `runtime.*`, `timestamp`. No
  destination IP/port on this gadget at all, exactly as documented.

**What diverged, found and fixed (`internal/observe/ig/parse.go`):**

`trace_dns`'s `nameserver` field is a real JSON **object**
(`{"addr":"127.0.0.11","version":4}`), not the `"ip"`/`"ip:port"` string
the research brief's reconstructed example had assumed. This was not
cosmetic: `encoding/json.Unmarshal` returns a non-nil error when an
object lands on a string-typed struct field, and `parseDNSLine` treated
*any* Unmarshal error as "drop this line" -- so **every real trace_dns
response event was being silently discarded**, before this fix,
regardless of how well-formed the rest of the line was. DNS-based
correlation would never have worked against real `ig` output. Fixed with
a `flexNameserver` type that extracts `addr` from the real object shape
and falls back to a plain string for resilience. `parse_test.go` now
carries real captured lines (container id/image sanitized, every field
name and nesting verbatim) for all three gadgets, including a dedicated
regression case for the object-shaped `nameserver`.

## The real `ig run` invocation: three more real bugs

Getting a real `ig run` to actually work *inside airlock's own packaged
image*, exactly as `docker-compose.yml` and the `Dockerfile` document,
surfaced three further bugs -- none of them in the parser, all in how
airlock drives `ig` or packages it. Each was confirmed broken, then
confirmed fixed, against this real host:

1. **`ig.DefaultRuntimes` was fatal on a plain-Docker-only host.** It
   mirrored `ig`'s own CLI default, `-r docker,containerd,cri-o,podman`.
   Confirmed live: with no containerd/cri-o/podman API socket present
   (the exact target deployment this project is built for), `ig` does
   not skip a listed runtime whose socket is missing -- it fails its
   **entire startup** ("`pre-starting operator "LocalManager":
   container-collection isn't available`") the moment any runtime other
   than `docker` has no live socket. Fixed: `ig.DefaultRuntimes` is now
   just `"docker"`, and `internal/daemon`'s new
   `observeRuntimes`/`resolvedRuntimeName` scope ig's runtime flag to
   whichever single runtime `AIRLOCK_RUNTIME` actually selects, so a
   Podman deployment gets `-r podman` instead of silently inheriting the
   Docker-shaped default.

2. **`ig run` needs `--auto-mount-filesystems`, and nothing passed it.**
   Confirmed live inside `airlock-itest:latest`: every gadget failed with
   `"filesystems debugfs, tracefs not mounted (did you try
   --auto-mount-filesystems?)"`. Nothing in this image's own startup
   mounts them (unlike, apparently, upstream's own
   `ghcr.io/inspektor-gadget/ig` container image, validated separately
   during this pass, which does not hit this). Fixed by always passing
   `--auto-mount-filesystems` in `defaultCommandBuilder` -- unconditional,
   not an `Options` field, since airlock always runs `ig` as a dedicated
   already-privileged subprocess with no reason to ever decline this.

3. **The packaged image has no `runc`, and `ig`'s container-collection
   needs one present.** Even with (1) and (2) fixed, `ig run` still
   failed fleet-wide with `"no container runtime can be monitored with
   fanotify. The following paths were tested: /bin/runc, /usr/bin/runc,
   ..."`. `ig`'s container-collection watches for container start/stop
   by fanotify-monitoring a container runtime **binary on its own
   filesystem** (the image `ig` runs in, not the host's) at one of a
   fixed list of well-known paths. airlock's `debian:stable-slim` final
   stage shipped nothing but the raw `ig` release binary,
   `ca-certificates`, and `tzdata` -- no reason to have suspected it
   needed a runtime binary of its own, since airlock never launches a
   container. Fixed by installing `runc` alongside `ig` in the
   `Dockerfile`. This was the most fundamental of the three: without it,
   *nothing else in this list mattered* -- container-collection never
   came up at all, on any gadget, scoped or not.

   One thing checked and found **not** required: mounting the host's
   `/run/containerd` into the container. Its absence produces per-container
   `"OCIConfig enricher: failed to get OCI config"` error-level log lines
   for containers whose containerd task state that path would have
   supplied, but does not stop container-collection from initializing --
   confirmed by a clean, fleet-wide run with `runc` installed and no such
   mount. Not added to `docker-compose.yml`.

With all three fixed, a single, real, unscoped `ig run` (the actual
invocation `internal/observe/ig` issues in production -- no
`--containername`, fleet-wide) started cleanly inside
`airlock-itest:latest` on this host and correctly attributed events from
every real container running on it at the time (a genuinely busy host:
dozens of unrelated production containers), not just the itest target.

## A fourth real bug, found only by running the whole daemon

`run-detect.sh` runs the actual `airlock daemon` binary, not just the
`ig` adapter in isolation. Doing so surfaced a bug neither the parser
fixes nor any existing unit test could have caught, because it lives at
the point where `internal/daemon.Run` wires `internal/engine` to
`internal/alert`:

**Deferred (flushed) violations were alerted but never tallied.**
`internal/engine`'s deferral mechanism (`pending.go`) exists specifically
because a TLS ClientHello's SNI name arrives *after* the TCP connect it
belongs to -- so a would-be default-deny-floor violation against a
policy with any domain-based allow entry is held for up to `sniWindow`
(5s) in case a same-container SNI still resolves it to an allow. `Run`'s
`flush` case correctly called `d.alerter.Violation(ctx, v)` for every
violation `engine.Flush` produced, but never called
`d.violations.Record(...)` -- only `handleObserveEvent`'s *immediate*
path (`engine.Process`'s verdicts) did that. Since deferral triggers for
*any* connection with no SNI evidence yet, regardless of its eventual
verdict, and any realistic domain-based policy has at least one
name-based allow entry, this is not a rare corner: it is the common case.

Confirmed live: a real connection to a bare IP with no DNS or SNI
evidence at all (`ClassUnresolvedIP`, always deferred since any
name-based allow entry qualifies for deferral) alerted correctly --
visible in the daemon's own logs and delivered to a real ntfy topic --
but never appeared in `state.json`'s `violations_by_class`, meaning
`airlock status` would have silently undercounted, often all the way to
zero, exactly the violation class most worth watching closely. Fixed by
extracting the tally-then-alert sequence into
`Daemon.recordAndAlertViolation` and routing both `Run` call sites
(`handleObserveEvent` and the `flush` case) through it, so they cannot
drift apart again silently.

UPDATE (fail-closed-on-SNI pass): the deferral mechanism this bug lived in
(`pending.go`, `engine.Flush`, `Run`'s `flush` case) has since been
removed entirely -- see "RESOLVED" below -- so there is no longer a second
call site for `recordAndAlertViolation` to guard against drifting from.
The helper itself is kept (now with a single caller,
`handleObserveEvent`) purely so tallying and alerting can never drift
apart if a second call site is ever added again.

## A documentation-only bug, found while wiring a real alert channel

Standing up a real ntfy channel for the detect-and-alert proof below
surfaced that `airlock.example.yml`'s `notifications.channels` examples
used the wrong settings keys: `ntfy`'s block said `token`, `discord`'s
said `webhook_url`. beacon's real backends
(`github.com/tagwright/beacon`'s `ntfy.go`/`discord.go`) read
`token_secret` and `webhook_secret` respectively. Neither is validated at
airlock's config-load layer (`internal/config` only checks `Type` is
non-empty; the settings map passes through to beacon verbatim), so a
deployment copying the example literally would silently never resolve a
token/webhook secret and never send an authenticated notification, with
no error anywhere. Fixed in `airlock.example.yml`. (`gatus`'s telemetry
example was checked too and was already correct.)

## End-to-end detect-and-alert: what was proven live

`test/integration/run-detect.sh` builds the real image, runs the real
daemon `--privileged` against the real Docker socket with a real `ig`,
labels a throwaway target container `airlock.enable=true
airlock.allow=example.com:443`, and drives three real connections.

HISTORICAL NOTE: at the time of this run, the engine still let SNI win a
match on disagreement with DNS and deliberately spaced the three
connections 8 seconds apart to dodge the correlation risk documented
below (which this very run's evidence field incidentally illustrates).
Both of those things are gone: matching is now fail-closed on DNS-cache
correlation only (see "RESOLVED" below), and the script fires all three
connections back to back. The table is kept as the historical record of
what this pass proved; a reader should not infer "SNI wins on
disagreement" is still true.

| Connection | Name evidence | Expected verdict | Confirmed |
|---|---|---|---|
| `https://example.com` | Real DNS answer + real SNI ClientHello, both `example.com` | allowed, **no violation** | Yes -- zero violations attributed to it; the only two violations tallied are the other two connections below |
| `https://1.1.1.1` (bare IP) | None -- curl sends no SNI for a literal IP host, and no DNS lookup happens for one | `unresolved-ip` | Yes -- `violations_by_class.unresolved-ip == 1`, and a real log line + real ntfy message with the right container/service/destination/class |
| `https://www.wikipedia.org` | Real DNS + real SNI, both `www.wikipedia.org`, not allow-listed | `no-match` | Yes -- `violations_by_class.no-match == 1`, and a real log line + real ntfy message; the log's evidence field also showed real DNS/SNI disagreement on the same name (`dns=www.wikipedia.org.` vs `sni=www.wikipedia.org`, a trailing-dot difference) -- under the matching rule of the time this meant "SNI wins," now it means only that DNS decided the match and SNI is shown alongside as enrichment |

`state.json`'s `backend.events_flowing` was `true` throughout, and the
same run's `suggestions` (the `airlock suggest` data source) correctly
recorded egress from *every other real container on the host at the
time* -- unrelated production services this itest never touched, proving
the fleet-wide, unscoped observation path works on a genuinely busy host,
not just a clean lab container.

Alert delivery was proven twice: once through beacon's built-in `log`
fallback (every run-detect.sh log shows real, correctly formatted
violation lines), and once through a real, throwaway `binwiederhier/ntfy`
server on the same Docker network, with both real messages confirmed via
ntfy's own JSON poll API, correct title/body/priority/tags included.

### A note on `suggestions` staleness (historical, no longer applicable)

At the time this was written, the `example.com` connection was deferred
at connect time (its own SNI had not arrived yet) and correctly resolved
to "allowed" moments later once the real SNI event landed -- confirmed by
zero violations ever being tallied for it. But the *`airlock suggest`
recorder's* entry for that same destination still showed
`"verdict": "no-match"`, the verdict it would have carried had the later
SNI never rescued it, a deliberate, documented limitation of the
deferred-verdict design of that time.

**This entire code path no longer exists.** The deferral mechanism
(`pending.go`, `Engine.Flush`) that made a "rescued" verdict possible was
removed as part of the fail-closed-on-SNI fix below: every verdict is now
decided synchronously and finally at connect time, so there is no
"deferred-then-rescued" state left to go stale in `suggestions`. Kept here
for the historical record of what this integration pass observed.

## RESOLVED: SNI correlation could misattribute across close-together connections

Firing all three connections **close together** (a fraction of a second
apart, as a first, naive version of this harness did) reproducibly
misattributed SNI evidence across unrelated connections from the same
container, with a real security consequence: **a genuinely disallowed
connection could be classified as allowed.**

Mechanism, confirmed by direct inspection of the resulting `state.json`
and cross-referenced against the real captured NDJSON timestamps:
`internal/engine/sni.go`'s `sniStore.lookup` finds the SNI record
**temporally closest** (by absolute time difference, either direction) to
a connection's own timestamp within `sniWindow` (5s) -- by design, and
covered by an existing unit test
(`TestSNIStorePicksClosestOnMultipleRecent`) that pins exactly this
"closest wins" behavior. Nothing marked a record "consumed" once it
resolved one connection, so the *same* SNI observation could be matched
to a *second*, unrelated connection that never had any SNI evidence of
its own. In the reproduced case: `example.com`'s SNI (recorded first) was
still the closest entry in the store when the very next connection (to
`1.1.1.1`, which sends no SNI at all) was evaluated moments later, and
was found allowed using someone else's name. The same thing happened to
the `www.wikipedia.org` connection in the three-way race. Both were
immediate, final verdicts -- a real false negative a security tool must
not have, not a display quirk.

**Nate's ratified design decision: fail-closed on SNI.** SNI no longer
participates in ANY match decision, allow or deny. A Domain/DomainWildcard
entry now matches a connection ONLY via a DNS-cache correlation for that
container's own recent answers -- a hard IP-to-name lookup, with no timing
or cross-connection ambiguity possible, since DNS precedes the connect and
is looked up by the connection's own destination IP, not by proximity.
`sniStore` and the `TLSHello` observation path still exist and still
matter, but purely as enrichment: the observed SNI name, when there is
one, is carried through on `engine.Violation` (`DNSName`/`SNIName`) and
`engine.ObservedDest` (`Name`/`SNIName`) for a human reading an alert or a
suggest line, and can never change a verdict in either direction. See
`internal/engine/engine.go`'s package doc comment for the full rationale
and `internal/engine/match.go`'s `matchContext.dnsName` doc comment for
the mechanics.

One consequence: since DNS-based name matching is already available at
connect time (DNS precedes the connect), there was no longer anything for
a "wait briefly for a late SNI" deferral to accomplish. The deferred-
verdict machinery this section's mechanism analysis above referenced
(`pending.go`, `Engine.Flush`, the daemon's flush ticker) was removed
entirely: `engine.Process` now returns a Connection's final verdict
synchronously, always. `run-detect.sh` no longer needs to space its three
connections 8 seconds apart to dodge this risk -- fail-closed matching
makes the close-together case behave identically to the spaced-out case,
so the script now fires them back to back and that is itself part of the
proof this is fixed.

Covered by `internal/engine`'s unit tests
(`TestFailClosedSNIOnlyDoesNotMatchAllow`,
`TestFailClosedSNIDoesNotOverrideDNSMismatch`,
`TestDNSCorrelationAllowStillWorks`), and by
`test/integration/run-detect.sh`'s connections now firing without the
former spacing workaround.

## Pass 2: groups, `@self`, `scope: all`, deny, and audit mode -- against real Docker network data

Phase 5 pass 2's job was the group-scoped surface Fork 8 defines: things
that had only ever been proven against `internal/resolve`'s and
`internal/engine`'s own fake-`World`/fake-`Config` unit tests, never
against a live `ig`, a live Docker daemon, or real `core.ListNetworks`/
`Container.Networks` data. This pass also re-ran `run-detect.sh` as a
regression guard, unchanged, immediately after the fail-closed-on-SNI
change (`548fcd7`) landed -- and it did not pass on the first try.

### Two more real bugs, found by the regression re-run

Both were invisible to every existing unit test (their fixtures are all
hand-written and never happened to hit either gap) and were only exposed
because `run-detect.sh` fires its three connections back to back, with no
deliberate spacing, specifically because fail-closed-on-SNI was supposed
to have made that safe.

1. **A real DNS answer's qname carries a trailing dot; no policy entry
   ever can.** `internal/observe/ig`'s real trace_dns capture confirms
   the `name` field is the wire-format QNAME, always trailing-dot
   terminated for a fully-qualified name (`"example.com."`, not the
   dotless `"example.com"`). `policy.ParseEntry`'s `isValidDomain`
   rejects any domain ending in `.` outright (a trailing dot produces an
   empty final label), so no `airlock.allow`/`airlock.deny` entry a human
   writes can ever carry one. `recordDNS` cached the real qname verbatim,
   so `matchEntry`'s `strings.EqualFold` comparison against a policy
   entry's dotless domain never matched -- for **any** domain-based allow
   or deny, once SNI could no longer win a match on disagreement. Before
   fail-closed-on-SNI this was completely masked: SNI (which never
   carries a trailing dot) kept winning by accident, so a real
   deployment's domain rules worked anyway, for the wrong reason. Fixed
   in `recordDNS` (`internal/engine/engine.go`), which now normalizes the
   qname once at the cache's single write path. Confirmed live: the
   `example.com` connection in `run-detect.sh`, previously misclassified
   `no-match` after the fail-closed change landed, is now correctly
   `allowed` with zero violations.

2. **A stray SNI observation could still downgrade a violation's
   severity label.** The no-match/unresolved-ip split was reasoned to be
   safe to keep reading `sniOK` even after fail-closed-on-SNI, since it
   only affects how alarming an alert reads, never the allow/deny
   decision. A live run proved that reasoning wrong: `trace_sni`'s
   ClientHello for a connection is only ever sent after that
   connection's own TCP handshake completes, which is strictly *after*
   the very `Connection` event `evaluateConnection` reacts to
   synchronously -- so any SNI record already sitting in the store at
   that instant can only belong to an **earlier** connection from the
   same container, never the one currently being evaluated. Confirmed
   live: a bare-IP connection with zero name evidence of its own
   (`1.1.1.1`, fired moments after the `example.com` connection) was
   classified `no-match` instead of `unresolved-ip` -- the frozen doc's
   named exfiltration shape, silently softened -- because the
   `example.com` connection's real SNI observation, recorded a moment
   *after* that connection had already been evaluated and returned, was
   still sitting unconsumed in the store when the unrelated `1.1.1.1`
   connection asked. Fixed by making the classification fail-closed on
   `dnsOK` alone, same direction as the matching fix (`internal/engine`'s
   package doc comment and `evaluateConnection`'s step (f) have the full
   account). `sniStore.lookup` also now consumes the record it returns,
   closing a related but distinct reuse risk, though it was not the
   cause of this specific bug -- the record's true owner never looked it
   up at all, since it hadn't been recorded yet at that connection's own
   evaluation time.

Both fixed in the same commit as this pass, covered by
`TestAllowedByExactDomainAfterDNSWithTrailingDot`,
`TestFailClosedSNIOnlyDoesNotMatchAllow` (updated expected class), and
`TestSNIStoreLookupConsumesRecord`. `run-detect.sh` passes end to end
after both fixes, still firing all three connections back to back.

### The four distinctive features: all proven live, on the first clean run

With the regression fixed, `test/integration/run-groups.sh` proved every
Fork 8 surface this pass targeted, all in one daemon/config/network
setup, no further bugs found:

| Feature | Proof | Confirmed |
|---|---|---|
| `deny` beats `allow: "*"` | `airlock-itest-denytarget`: `allow: "*"` + `deny: 1.1.1.1:443`. A connection to `1.1.1.1:443` produced `violations_by_class.deny == 1`; a connection to `example.com` (falling through to the `allow: "*"` denylist posture) produced zero additional violations. | Yes, plus a real ntfy delivery naming the container and `(deny)`. |
| Group arms containers with NO `airlock.*` label | `airlock-itest-a` and `airlock-itest-b`, no labels at all, attached to `airlock-itest-groupnet`. `groups.itest.yml`'s `itest-groupnet` group (`match: {network: airlock-itest-groupnet}`, `enable: "true"`, `scope: "all"`, `allow: ["@self"]`) armed both: `state.json` lists both with `matched_groups: ["itest-groupnet"]` and `scope: "all"`, with no per-container label ever set. | Yes. |
| `@self` + `scope: all` against **real** core network data | `a -> b` (both on `airlock-itest-groupnet`): `@self` resolved `b`'s IP as within the group members' own network subnet -- allowed, zero violations. `a -> 1.1.1.1` (external): `scope: all` brought it into scope, `@self` does not cover it -- `violations_by_class.unresolved-ip == 1` on `a`. This is core's network-introspection extension's (`f6cd8da`, `ListNetworks` + `Container.Networks`) **first live exercise**: every prior proof of `@self`/`scope`/group-matching was against `internal/resolve`'s and `internal/engine`'s fake `World`/`Config` fixtures only. | Yes, plus a real ntfy delivery for `a`'s `unresolved-ip` violation. |
| `mode: audit` suppresses the immediate alert but still tallies | `airlock-itest-audittarget`: `airlock.mode=audit`, `airlock.allow=example.com:443`. A connection to `www.wikipedia.org` (not allow-listed) produced `violations_by_class.no-match == 1` in `state.json` -- tallied -- but no message naming `airlock-itest-audittarget` ever reached the real ntfy topic. | Yes. |

No bug was found in `internal/resolve`'s group-matching, `internal/engine/scope.go`'s `selfSubnets`/`inOwnNetworks`, or the daemon's `world.go` wiring of `core.Network`/`ContainerNetwork` into the engine's `World` interface -- the exact surface flagged as highest-risk going into this pass (group matching + `@self` had only ever been unit-tested against fakes). All of it worked correctly against a real Docker bridge network, real container IPs, and a real `ig` on the first clean run after the regression fixes above landed.

## Pass 3: `@project`, `net:<name>`, and the alert flood breaker at scale

Phase 5 pass 3's job was the last group-token surface pass 2 did not drive
live (`@self` was pass 2's only live token proof) plus the alert flood
breaker, which had only ever been exercised with `alert_test.go`'s
synthetic, time-injected counts. `test/integration/run-pass3.sh` builds
the real image, runs the real daemon `--privileged` against the real
Docker socket with a real `ig`, and proves all three in one
daemon/config/network setup:

| Feature | Proof | Confirmed |
|---|---|---|
| `@project` against **real** `ProjectPeerIPs` | `airlock-itest-pa` and `airlock-itest-pb`, both labeled `com.docker.compose.project=airlock-itest-proj`, no other `airlock.*` label, armed by `pass3.itest.yml`'s `compose_project`-matched group (`allow: "@project"`, `scope: all`). `pa -> pb` (same project, different container) produced zero violations; `pa -> 1.1.1.1` (external) produced `violations_by_class.unresolved-ip == 1`. This is `internal/daemon/world.go`'s `ProjectPeerIPs` index's first live exercise -- built by walking every real container's real IPs grouped by compose project, distinct code from `@self`'s `selfSubnets` path pass 2 already proved. | Yes, plus a real ntfy delivery naming `airlock-itest-pa`. |
| `net:<name>` against **real** `ListNetworks` | `airlock-itest-neta-c` (on `airlock-itest-neta`, armed by a network-matched group with `allow: "net:airlock-itest-netb"`, `scope: all`) and `airlock-itest-netb-t` (on the entirely separate `airlock-itest-netb`, no policy of its own). `neta-c -> netb-t` (a real IP on a network `neta-c` is not itself attached to) produced zero violations; `neta-c -> 1.1.1.1` (external) produced `violations_by_class.unresolved-ip == 1`. Proves `internal/engine/match.go`'s `namedNetworkContains` resolves a named network's subnet by walking core's real `ListNetworks` inventory, independent of the connecting container's own attachments -- the thing `@self` deliberately does NOT cover. | Yes, plus a real ntfy delivery naming `airlock-itest-neta-c`. |
| Alert flood breaker at real scale | `airlock-itest-flood`, bare `airlock.enable=true` (default-deny), fired at 15 distinct real external IPs in parallel. `pass3.itest.yml` lowers `alert_flood` to 5 for a fast, small proof. `state.json` tallied all 15 as `unresolved-ip` (tallying is unconditional, independent of the flood breaker). The real ntfy topic received exactly 5 individual per-destination alerts (identities 1-5, under the cap) followed by exactly ONE `"airlock: airlock-itest-flood (...) flooding"` alert (identity 6 crossing the cap) -- identities 7-15 produced zero further messages, confirmed by counting `event: message` lines naming the container in the real ntfy JSON poll response. | Yes, run twice for determinism; both runs produced exactly 6 total messages (5 + 1) and exactly 1 "flooding" title, never 15 separate alerts. |

No bug was found in `internal/daemon/world.go`'s `ProjectPeerIPs`,
`internal/engine/match.go`'s `namedNetworkContains`, or
`internal/alert`'s `countFlood`/`sendFlood` -- the exact surfaces flagged
as highest-risk going into this pass (both tokens and the flood breaker
had only ever been exercised against fakes or synthetic counts). All of
it worked correctly against real Docker networks, a real compose-project
label pair, and a real `ig`, on the first clean run, reproduced on a
second run with identical results.

## Coverage matrix

| Capability / path | Status | Notes |
|---|---|---|
| Privileged `ig` on this host | **Integration-proven** | `run-capture.sh`'s environment probe; also every real `ig run` throughout this pass. |
| `trace_tcp`/`trace_dns`/`trace_sni` real JSON shape vs. parser | **Integration-proven** | `run-capture.sh` + `parse_test.go`'s real-captured fixtures. One real divergence found and fixed (`nameserver`). |
| Real `ig run` invocation (image ref, flags, socket) | **Integration-proven** | Three real bugs found and fixed (runtime default, `--auto-mount-filesystems`, missing `runc`); confirmed working fleet-wide (no `--containername`) against a genuinely busy real host afterward. |
| Fleet-wide (unscoped) observation on a busy host | **Integration-proven** | `run-detect.sh`'s `suggestions` output recorded real egress from multiple unrelated real production containers during the same run. |
| DNS-based allow correlation | **Integration-proven** | `example.com`: real DNS answer, real SNI, resolved to allowed, zero violations. |
| SNI-based allow correlation | **Superseded, historical only** | At the time of this run SNI could win a match on disagreement with DNS; that path no longer exists (see "RESOLVED" above) -- SNI is enrichment-only now, and matching is DNS-cache correlation alone. |
| `unresolved-ip` classification | **Integration-proven** | `1.1.1.1`: real bare-IP connection, no name evidence, correctly classified, tallied, alerted, and delivered to a real ntfy server. |
| `no-match` classification | **Integration-proven** | `www.wikipedia.org`: real name evidence, not allow-listed, correctly classified, tallied, alerted, delivered. |
| `deny` classification | **Integration-proven (pass 2)** | `run-groups.sh`: `airlock-itest-denytarget`'s `deny: 1.1.1.1:443` beat its own `allow: "*"`, real connection, real tally, real ntfy delivery. |
| Violation tallying (`state.json`) | **Integration-proven, and a real bug fixed** | See "A fourth real bug" above. The original bug was specific to the (now-removed) deferred/flush path; tallying is unit-tested end to end on the current synchronous path (`daemon_test.go`'s `TestRecordAndAlertViolation_Tallies`). |
| Real alert delivery, log channel | **Integration-proven** | Every `run-detect.sh` run's daemon log. |
| Real alert delivery, ntfy | **Integration-proven** | `run-detect.sh`'s ntfy assertion, via ntfy's own JSON poll API. |
| Real alert delivery, discord/smtp/webhook | **Not yet tested** | Same boundary ballast documents for its own notification backends: these live in `github.com/tagwright/beacon` and need a live external endpoint/account this repo-local harness doesn't have. |
| Gatus telemetry sink | **Not yet tested** | No itest configures `telemetry`; needs a real Gatus push-URL target. |
| SNI correlation across close-together connections | **RESOLVED (fail-closed on SNI)** | See the dedicated section above. Nate ratified fail-closed on SNI as the fix; the deferral machinery this risk depended on is removed entirely. `run-detect.sh` now fires its three connections back to back rather than spaced, as part of the proof. |
| Podman backend, IG-side | **Not yet tested** | This pass only exercised the Docker runtime end to end. `internal/daemon`'s `resolvedRuntimeName`/`observeRuntimes` fix is unit-tested (`TestObserveRuntimes_TracksAirlockRuntime`) for the `AIRLOCK_RUNTIME=podman` case, but no itest here stands up a real Podman socket the way `ballast`'s `run-podman.sh` does. |
| Digest pinning (`Options.Images`) | **Not exercised** | Every capture/detect run in this and pass 2 used `:latest` gadget images (this suite's own default). Digest pinning is a packaging-time decision documented as a TODO in `internal/observe/ig`'s package doc; not itself a behavior this harness can meaningfully test differently. |
| Group matching by network (Fork 8), no per-container label | **Integration-proven (pass 2)** | `run-groups.sh`: `airlock-itest-a`/`-b`, zero `airlock.*` labels, armed entirely by a `match: {network: ...}` group. `state.json`'s `matched_groups` confirms the match. |
| `@self` under `scope: all`, against real core network data | **Integration-proven (pass 2)** | `run-groups.sh`: `a -> b` on the same group network allowed via `@self`; `a -> 1.1.1.1` (external) violated. First live exercise of core's `ListNetworks`/`Container.Networks` extension (`f6cd8da`) -- previously fake-`World`-only. |
| `mode: audit` | **Integration-proven (pass 2)** | `run-groups.sh`: a real violation was tallied into `state.json` but never reached the real ntfy topic. |
| `@project` token | **Integration-proven (pass 3)** | `run-pass3.sh`: `pa -> pb` (same `com.docker.compose.project`) allowed via `@project`; `pa -> 1.1.1.1` (external) violated. First live exercise of `internal/daemon/world.go`'s `ProjectPeerIPs` index. |
| `net:<name>` token | **Integration-proven (pass 3)** | `run-pass3.sh`: `neta-c -> netb-t` (a real IP on a *different* named network, resolved by name) allowed via `net:airlock-itest-netb`; `neta-c -> 1.1.1.1` (external) violated. First live exercise of `internal/engine/match.go`'s `namedNetworkContains` against real `core.ListNetworks` data. |
| Alert flood breaker at scale | **Integration-proven (pass 3)** | `run-pass3.sh`: 15 distinct real external destinations against a lowered `alert_flood: 5` cap collapsed to 5 individual alerts + exactly 1 "flooding" alert, confirmed via the real ntfy JSON poll response, run twice for determinism. |
| Digest cron timing | **Not yet tested** | `defaults.digest_schedule` and the periodic digest fire are unit-tested (cron parsing, `runDigest`'s wiring) but never observed live across a real schedule boundary -- this harness's runs are too short-lived to wait for one. |

## What remains for later integration passes

As of pass 3 (`run-detect.sh`, `run-groups.sh`, `run-pass3.sh`): `deny`,
group-by-network and group-by-compose_project arming, `@self`, `@project`,
`net:<name>`, `scope: all` against real core network data, `mode: audit`,
and the alert flood breaker at scale are all integration-proven. Still
open:

- **Podman**, end to end, the way these passes did Docker: a real Podman
  socket, `AIRLOCK_RUNTIME=podman`, confirming `observeRuntimes` actually
  points `ig` at `-r podman` in a live run, not just in a unit test.
- **Digest cron timing** -- observing a real `defaults.digest_schedule`
  fire across an actual schedule boundary; this harness's runs are too
  short-lived to wait for one honestly, so this needs either a
  long-running itest or a schedule set to fire within the run window.
- **Digest-pinned gadget images** (`Options.Images`) -- every itest run
  so far, across all three passes, only ever ran `:latest`.
- **Discord/SMTP/webhook notification delivery and the Gatus telemetry
  sink** -- need a live external endpoint or account this repo-local
  harness doesn't have, mirroring the identical boundary ballast's own
  `TESTING.md` documents for its notification backends.
- **Group-vs-label specificity conflicts, live** -- `internal/resolve`'s
  specificity-ladder tiering (label beats identity-group beats
  network-group beats catch-all, same-tier conflict is a sticky error) is
  thoroughly unit-tested, but no itest here has yet driven a real
  container where a label AND a matching group disagree on the same
  scalar, to confirm the resolved winner end to end against a live
  daemon reconcile rather than a direct `resolve.Resolve` call.
