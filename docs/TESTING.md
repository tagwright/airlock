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
   (success, failure, or interrupt). Two scripts today:

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
     container with a real policy, drives three real, deliberately
     spaced connections through it, and asserts the resulting
     `state.json` violation tally and a real ntfy delivery.

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
airlock.allow=example.com:443`, and drives three real connections,
deliberately spaced 8 seconds apart (see the SNI-correlation finding
below for exactly why they are not fired back to back):

| Connection | Name evidence | Expected verdict | Confirmed |
|---|---|---|---|
| `https://example.com` | Real DNS answer + real SNI ClientHello, both `example.com` | allowed, **no violation** | Yes -- zero violations attributed to it; the only two violations tallied are the other two connections below |
| `https://1.1.1.1` (bare IP) | None -- curl sends no SNI for a literal IP host, and no DNS lookup happens for one | `unresolved-ip` | Yes -- `violations_by_class.unresolved-ip == 1`, and a real log line + real ntfy message with the right container/service/destination/class |
| `https://www.wikipedia.org` | Real DNS + real SNI, both `www.wikipedia.org`, not allow-listed | `no-match` | Yes -- `violations_by_class.no-match == 1`, and a real log line + real ntfy message; the log's evidence field also proves the DNS/SNI disagreement-resolution rule ("SNI wins on disagreement") firing on real data (`dns=www.wikipedia.org.` vs `sni=www.wikipedia.org`, the trailing-dot difference being exactly why DNS and SNI evidence for the same real name "disagree" byte-for-byte) |

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

### A note on `suggestions` staleness (not a bug)

The `example.com` connection is deferred at connect time (its own SNI
has not arrived yet) and correctly resolved to "allowed" moments later
once the real SNI event lands -- confirmed by zero violations ever being
tallied for it. But the *`airlock suggest` recorder's* entry for that
same destination still shows `"verdict": "no-match"`, the verdict it
would have carried had the later SNI never rescued it. This is
`evaluateConnection`'s own documented behavior (see its comment on
`recordObserved`): the recorder is a best-effort suggest/status aid, not
the security verdict, and a rescued deferred connection deliberately
leaves a stale entry there rather than being updated after the fact.
Confirmed harmless: the real, security-relevant verdict (whether a
Violation is ever tallied or alerted) is correct; only the informational
suggest-list entry lags.

## A real, reproduced correlation risk -- not fixed, needs a design decision

Firing all three connections **close together** (a fraction of a second
apart, as a first, naive version of this harness did) reproducibly
misattributes SNI evidence across unrelated connections from the same
container, with a real security consequence: **a genuinely disallowed
connection can be classified as allowed.**

Mechanism, confirmed by direct inspection of the resulting `state.json`
and cross-referenced against the real captured NDJSON timestamps:
`internal/engine/sni.go`'s `sniStore.lookup` finds the SNI record
**temporally closest** (by absolute time difference, either direction) to
a connection's own timestamp within `sniWindow` (5s) -- by design, and
covered by an existing unit test
(`TestSNIStorePicksClosestOnMultipleRecent`) that pins exactly this
"closest wins" behavior. Nothing marks a record "consumed" once it
resolves one connection, so the *same* SNI observation can be matched to
a *second*, unrelated connection that never had any SNI evidence of its
own. In the reproduced case: `example.com`'s SNI (recorded first) was
still the closest entry in the store when the very next connection (to
`1.1.1.1`, which sends no SNI at all) was evaluated moments later --
`evaluateConnection`'s initial synchronous check found `sniOK == true`
using someone else's name, skipped deferral entirely (deferral only
triggers `if !sniOK`), and immediately, definitively classified the
`1.1.1.1` connection as **allowed**. The same thing happened to the
`www.wikipedia.org` connection in the three-way race. Both are immediate,
final verdicts -- not the merely-cosmetic `suggestions`-staleness case
documented above -- so this is a real false negative a security tool
must not have, not a display quirk.

This is **not** being mechanically patched in this pass. The engine's own
package doc is explicit that `trace_sni` carries no destination IP at all
and correlation is deliberately "same-container plus temporal proximity"
as a *documented, tested* approximation, not an oversight -- fixing the
double-use specifically (e.g. consume-once semantics) touches
security-critical, already-unit-tested correlation logic
(`sni.go`/`pending.go`) shared by every deferred-verdict code path, and
deserves the same kind of deliberate design call this suite's own history
gives this class of problem (see e.g. ballast's `Splay` field, left
undecided for a full pass before being resolved), not a rushed change
under an integration pass's time box. **Recommendation for a dedicated
follow-up:** decide whether SNI records should be single-use once they
resolve a connection's verdict, whether the window should be direction-
aware (only accept an SNI recorded no earlier than the connection itself,
since a ClientHello cannot precede its own TCP connect), or whether the
risk is accepted and should instead be stated plainly in
user-facing docs as a known limitation of any container making several
concurrent/rapid TLS connections. `run-detect.sh` deliberately spaces its
three connections 8 seconds apart specifically to avoid tripping this,
so it does not regress silently if a future fix changes the behavior;
a dedicated reproduction lives in this section for whoever picks it up.

## Coverage matrix

| Capability / path | Status | Notes |
|---|---|---|
| Privileged `ig` on this host | **Integration-proven** | `run-capture.sh`'s environment probe; also every real `ig run` throughout this pass. |
| `trace_tcp`/`trace_dns`/`trace_sni` real JSON shape vs. parser | **Integration-proven** | `run-capture.sh` + `parse_test.go`'s real-captured fixtures. One real divergence found and fixed (`nameserver`). |
| Real `ig run` invocation (image ref, flags, socket) | **Integration-proven** | Three real bugs found and fixed (runtime default, `--auto-mount-filesystems`, missing `runc`); confirmed working fleet-wide (no `--containername`) against a genuinely busy real host afterward. |
| Fleet-wide (unscoped) observation on a busy host | **Integration-proven** | `run-detect.sh`'s `suggestions` output recorded real egress from multiple unrelated real production containers during the same run. |
| DNS-based allow correlation | **Integration-proven** | `example.com`: real DNS answer, real SNI, resolved to allowed, zero violations. |
| SNI-based allow correlation | **Integration-proven** | Same connection; the daemon's own log line shows SNI winning the disagreement rule against DNS's trailing-dot-qualified name. |
| `unresolved-ip` classification | **Integration-proven** | `1.1.1.1`: real bare-IP connection, no name evidence, correctly classified, tallied, alerted, and delivered to a real ntfy server. |
| `no-match` classification | **Integration-proven** | `www.wikipedia.org`: real name evidence, not allow-listed, correctly classified, tallied, alerted, delivered. |
| `deny` classification | **Not exercised this pass** | No deny rule in this pass's policy fixture; the class is well covered at the unit level (`engine_test.go`'s `TestDenyBeatsAllow` and others) but never driven by a real deny-matching connection here. Natural next `run-detect.sh` addition. |
| Deferred-violation tallying (`state.json`) | **Integration-proven, and a real bug fixed** | See "A fourth real bug" above. |
| Real alert delivery, log channel | **Integration-proven** | Every `run-detect.sh` run's daemon log. |
| Real alert delivery, ntfy | **Integration-proven** | `run-detect.sh`'s ntfy assertion, via ntfy's own JSON poll API. |
| Real alert delivery, discord/smtp/webhook | **Not yet tested** | Same boundary ballast documents for its own notification backends: these live in `github.com/tagwright/beacon` and need a live external endpoint/account this repo-local harness doesn't have. |
| Gatus telemetry sink | **Not yet tested** | No itest configures `telemetry`; needs a real Gatus push-URL target. |
| SNI correlation across close-together connections | **Reproduced live, NOT fixed** | See the dedicated section above. A real, security-relevant finding for a maintainer decision, not a bug this pass patched. |
| Podman backend, IG-side | **Not yet tested** | This pass only exercised the Docker runtime end to end. `internal/daemon`'s `resolvedRuntimeName`/`observeRuntimes` fix is unit-tested (`TestObserveRuntimes_TracksAirlockRuntime`) for the `AIRLOCK_RUNTIME=podman` case, but no itest here stands up a real Podman socket the way `ballast`'s `run-podman.sh` does. |
| Digest pinning (`Options.Images`) | **Not exercised** | Every capture/detect run in this pass used `:latest` gadget images (this pass's own default). Digest pinning is a packaging-time decision documented as a TODO in `internal/observe/ig`'s package doc; not itself a behavior this harness can meaningfully test differently. |
| `groups`/`@self`/`scope`/flood/audit modes | **Out of scope for this pass** | Per the phase plan: later integration passes. |

## What remains for later integration passes

- **The SNI cross-connection correlation risk** above needs a design
  decision before (or alongside) a fix -- the highest-priority item this
  pass surfaces.
- **A real `deny` rule** driven end to end (currently only unit-tested).
- **Podman**, end to end, the way this pass did Docker: a real Podman
  socket, `AIRLOCK_RUNTIME=podman`, confirming `observeRuntimes` actually
  points `ig` at `-r podman` in a live run, not just in a unit test.
- **Groups (Fork 8), `@self`/`@project`/`net:<name>` tokens, `scope:
  all`, the alert flood breaker, and audit mode** -- explicitly deferred
  to later passes per the phase plan, and each has real live-traffic
  edge cases (e.g. does `@self` really resolve against real compose-
  project peers on a real network) worth the same "run it for real"
  treatment this pass gave the base pipeline.
- **Digest-pinned gadget images** (`Options.Images`) -- this pass only
  ever ran `:latest`.
- **Discord/SMTP/webhook notification delivery and the Gatus telemetry
  sink** -- need a live external endpoint or account this repo-local
  harness doesn't have, mirroring the identical boundary ballast's own
  `TESTING.md` documents for its notification backends.
