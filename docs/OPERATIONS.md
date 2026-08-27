# Operations

Running airlock day to day: the onboarding workflow, the three read-only
CLI commands, alert tuning, the observation-scope model, and
troubleshooting. See [docs/DEPLOY.md](DEPLOY.md) for the initial deploy and
the privilege trade-off, and [docs/LABELS.md](LABELS.md) for the full label
and `airlock.yml` reference.

## The CLI, and how it talks to the daemon

`airlock` has five subcommands: `daemon`, `validate`, `status`, `suggest`,
and `version`. `--config` (default `/etc/airlock/airlock.yml`) and
`--log-level` (`debug`/`info`/`warn`/`error`, default `info`) are
persistent flags on every command.

`status` and `suggest` never talk to a running daemon directly — there is
no IPC server in this architecture. Instead, the daemon periodically
(every `AIRLOCK_STATE_INTERVAL`, default `5s`) writes a JSON state
snapshot to `AIRLOCK_STATE_PATH` (default `/run/airlock/state.json`), and
both commands read that file. This keeps the CLI a plain, offline-capable
binary at the cost of seeing a value that can be up to one interval stale
— a fine trade for a status surface that is a debugging aid, not a control
plane. Both commands warn when the snapshot is older than
`StateStaleAfter` (four times the write interval, 20s at the default),
since that usually means the daemon is stuck or stopped rather than just
between writes.

## The audit onboarding workflow

Default-deny against an undeclared container is noisy the moment it's
armed. The onramp:

1. Arm the container with an empty or partial allowlist, and set audit
   mode:

   ```yaml
   labels:
     airlock.enable: "true"
     airlock.mode: "audit"
   ```

   In audit mode the policy evaluates exactly as `alert` mode would, but
   every would-be violation routes to the digest only — nothing alerts
   immediately while you're still watching this container settle.

2. Recreate the container so the label takes effect, and let it run long
   enough to make its normal connections — ideally a full day, so any
   daily or weekly job (a cron-triggered update check, a backup) shows up
   too.

3. Render what it actually reached:

   ```
   airlock suggest <container>
   ```

   This reads the state snapshot and prints every distinct in-scope
   destination observed from that container, matched by name or id, as a
   ready-to-paste `airlock.allow` value: `name:port` when DNS-cache
   correlation had a name for that destination, `ip:port` when it didn't.
   Each line is annotated with its connection count, last-seen time, and
   the verdict the engine actually recorded for it. An entry with no
   DNS-correlated name is called out separately (`NO NAME EVIDENCE —
   review before trusting`) — review those before trusting them, since an
   IP-only entry is exactly the shape a name rule can't protect you from
   if the destination changes address later. If the destination happened
   to carry an observed SNI name too, it's shown as an aside on that line,
   but it is never rendered as the entry's name: an SNI-only name is not
   guaranteed to match again if pasted back in (matching is DNS-cache
   correlation only — see the README's "What a rule can honestly
   promise").

   Add `--yaml` to also print a ready-to-paste `airlock.yml` policy-set
   block, useful when several containers should share the same suggested
   list.

4. Prune the list down to what actually belongs, paste it into
   `airlock.allow` (or into an `airlock.yml` policy set the container
   references via `airlock.policy`), delete the `airlock.mode: audit`
   label so the container falls back to the default `alert` mode, and
   recreate it once more.

5. Confirm the loop closed: make the container connect somewhere **not**
   on its new allowlist (or wait for it to happen naturally). You should
   see an alert within one dedup window — the very first occurrence of a
   new violation identity always fires immediately, regardless of the
   window.

If step 3 shows nothing at all, check `airlock status`'s backend line
before assuming the container made no connections — see Troubleshooting
below.

## `airlock validate`

```
airlock validate
```

Loads `airlock.yml`, checks it for internal consistency (policy sets,
groups, defaults, notification and telemetry config), and prints `OK` or
every error found, one aggregated report rather than stopping at the
first problem. Exits nonzero on an invalid config. This is entirely
offline: no socket, no container discovery, so it's safe to run in CI
against a candidate `airlock.yml` before deploying it. Non-fatal warnings
(an `allow: "*"` policy with no `deny` rules — a no-op policy that can
never fire — or a `@self`/`@project`/`net:<name>` entry used without
`scope: all`) print but don't fail the check.

## `airlock status`

```
airlock status
```

Prints, from the state snapshot:

- **Backend health**: the observation backend's name, whether events are
  currently flowing, restart count, and dropped-event count.
- **Every currently armed container**: name, short id, service identity,
  mode, scope, which `airlock.yml` groups matched it (if any), a
  per-class violation tally, and its current suppressed-repeat count.

`events_flowing: yes` with `restarts: 0` and `dropped_events: 0` is the
sign everything downstream of `ig` is healthy. A nonzero `dropped_events`
means the observation backend's kernel ring buffer overflowed — treat this
as a possible tamper-or-loss signal, not routine noise, since it means
airlock may have missed connections without anyone otherwise knowing.

## `airlock suggest <container>`

Covered above under the onboarding workflow. Matches by container name,
full id, or id prefix. Shows **every** in-scope destination the container
was observed reaching, regardless of the verdict the engine recorded for
it at the time (allowed, a specific violation class, or `observed` for a
container that wasn't armed yet) — the point of `suggest` is building the
first allowlist, and filtering out anything already "allowed" would hide
a destination an operator has every reason to want to see and confirm.

## Alert tuning

- **`airlock.alert.window`** (per container or per group, a Go duration
  string, default `1h` / `AIRLOCK_ALERT_WINDOW`): how long a repeat of the
  same alert identity (service, destination, port, class) is suppressed
  before it alerts again. The first occurrence of a new identity always
  alerts immediately, regardless of this window. A single chatty-but-
  legitimate container (a crawler hitting many hosts) is the usual reason
  to widen this for one container rather than fleet-wide.
- **`AIRLOCK_ALERT_FLOOD`** (default `30`): once a single container
  crosses this many *distinct* violation identities within a rolling hour,
  airlock collapses it to one "flooding" alert and absorbs further
  individual violations into the digest until the rate falls. This exists
  because per-identity dedup alone can't cap an unbounded stream of
  never-seen-before identities (a port scan, a domain-cycling compromise),
  and drowning the operator in that case serves the attacker, not the
  defender. Violations are still tallied in `state.json` throughout a
  flood episode — only the individual alerts are collapsed.
- **`AIRLOCK_DIGEST_SCHEDULE`** (default `0 0 * * *`, daily at midnight, a
  plain 5-field cron expression): how often the one periodic digest fires,
  carrying suppressed-repeat counts, audit-mode tallies, sticky validation
  diagnostics, flood episodes, and the unpolicied first-seen summary (if
  enabled).
- **`AIRLOCK_IMPLICIT_ALLOW`** and the resolver-on-53 baseline: airlock
  always implicitly allows a container's own configured DNS resolvers on
  port 53, so every fleet's allowlist doesn't need to open with the same
  resolver entry. `AIRLOCK_IMPLICIT_ALLOW` extends that baseline with more
  entries (the full destination-entry grammar), and `AIRLOCK_IMPLICIT_ALLOW=none`
  disables even the resolver baseline outright, for a hardened fleet that
  wants every DNS query declared explicitly. A bare IP with no port among
  the extension entries is treated as naming an additional resolver
  address (folded into the port-53 baseline); every entry, resolver-shaped
  or not, also separately reaches every armed container's own allow list.

## Observation scope

`AIRLOCK_OBSERVE` (default `all`) controls who airlock *watches*, which is
a separate question from who it *alerts on*:

- `all` — airlock observes every container's egress, armed or not. This
  feeds `airlock status`, `airlock suggest`, and the optional unpolicied
  digest below, regardless of arming. A container that never opted in is
  exactly the one worth being able to look at.
- `enabled` — airlock only observes containers with a resolved policy
  (armed by a label or a matching group). Use this on a fleet where
  observing unarmed containers at all is unwanted.

**`AIRLOCK_UNPOLICIED_DIGEST`** (default `false`) opts in to a
first-seen-destination-per-day summary line, in the periodic digest, for
every container with no declared policy at all. This is inventory, not
alerting: without a declared policy there is no deviation to alert on,
only visibility into what an undeclared container is quietly doing.

## Troubleshooting

**No events at all (`events_flowing: no` in `airlock status`).** Before
assuming a policy problem, check the daemon's own logs and the container's
privilege:

- airlock execs `ig run` as a subprocess, and `ig` needs `CAP_SYS_ADMIN`
  to load eBPF programs. Confirm the container is actually running
  `--privileged` (or the compose `privileged: true` equivalent) — a
  non-privileged airlock container will fail to load any gadget at all,
  usually loudly in the daemon log.
- `ig`'s container-collection subsystem needs `runc` present in the
  *airlock image itself* (not the host) to fanotify-monitor for container
  start/stop — a missing `runc` fails with `"no container runtime can be
  monitored with fanotify"` fleet-wide, on every gadget, even with
  privilege correctly granted. This is baked into the packaged image; if
  you're running a custom build, confirm `runc` is installed alongside
  `ig`.
- `ig` needs `debugfs`/`tracefs` mounted and needs BTF (`/sys/kernel/btf/vmlinux`
  or equivalent) present on the host kernel. A missing mount fails with
  `"filesystems debugfs, tracefs not mounted"`; airlock's packaged image
  always passes `--auto-mount-filesystems` to work around the mount side
  of this, but BTF availability is a host-kernel property airlock can't
  paper over. Most modern distro kernels ship it; a stripped-down or very
  old kernel may not.
- Confirm `pid: host` and the read-only `-v /:/host` mount are both
  present — `ig`'s container-collection enrichment reads the host's
  container-runtime rootfs and `config.json` through `/host`, and without
  it events may arrive with no container identity attached at all.

**The daemon starts but the first gadget never comes up.** Every gadget
(`trace_tcp`, `trace_dns`, `trace_sni`) is an OCI image pulled from
`ghcr.io/inspektor-gadget/gadget/<name>` by `ig` itself, lazily, the first
time that gadget's subprocess starts — not baked into airlock's own image,
and not pre-pulled at container start. The airlock container needs
outbound network access to `ghcr.io` the first time it starts (or after a
pinned gadget image changes); a network policy or egress rule that blocks
`ghcr.io` will leave airlock running blind on whichever gadget hasn't
finished pulling. Once pulled, the image is cached in the named volume
mounted at `/var/lib/ig`, so this is a one-time cost across restarts as
long as that volume persists.

**Domain-based DNS correlation never seems to work on host-network or
custom-DNS setups.** airlock reads the host's real `/etc/resolv.conf`
(via the `-v /:/host` mount, at `/host/etc/resolv.conf`) to build the
implicit resolver-on-53 baseline, not this container's own
Docker-embedded-DNS stub — `AIRLOCK_RESOLV_CONF` overrides that path if
your deployment keeps resolv.conf somewhere else. This only affects the
port-53 baseline exemption, not DNS-cache correlation itself (which reads
`trace_dns` events regardless of where the resolver lives), so a
correlation problem is more likely a TTL/timing issue (a very short-lived
DNS answer, or a connection made well after the cached answer's grace
window expired) than a resolv.conf path issue.

**The backend keeps restarting.** `airlock status`'s `restarts` count
tracks this. The daemon retries a failed observation backend with
exponential backoff (up to 5 attempts before giving up and exiting,
letting your container orchestrator restart the whole daemon). A backend
that restarts repeatedly under otherwise-normal conditions, rather than
once at startup, usually points back at one of the privilege/runtime
issues above rather than a transient fluke — check the daemon log
immediately preceding each restart for `ig`'s own error text.
