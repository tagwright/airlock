# airlock

Label-driven network-egress visibility for Docker and Podman. airlock reads
`airlock.*` labels (or the `tagwright.egress.*` alias) off your running
containers, drives Inspektor Gadget's eBPF tracing to watch what those
containers actually connect to, and alerts when a container's egress
deviates from what its labels declared.

airlock does not do its own packet tracing. It execs
[Inspektor Gadget](https://inspektor-gadget.io/) (`ig`) as a subprocess and
reads its JSON event stream. That backend sits behind a backend-neutral
interface inside airlock, so a second observation backend can be added
later without reworking the policy or alerting layers.

airlock is part of the tagwright suite: a set of label-driven,
config-as-code companion tools for Docker and Podman.

## Scope in v1: detect and alert only

airlock does not block traffic and is not a firewall. It observes egress
and raises alerts when a connection does not match the declared policy;
nothing it does ever drops or rejects a packet.

Inline blocking is deferred to a later release, and it will arrive with
tagwright's own eBPF backend (`bathyscaphe`), not with Inspektor Gadget.
IG's own third-party security audit states plainly that it "functions as
pure observability... provides no enforcement or blocking capabilities,"
and there is no eBPF egress-drop gadget on IG's roadmap. `airlock.mode:
block` is reserved syntax and is always a validation error in v1: it is
never silently downgraded to `alert`, because an operator who wrote
`block` believes traffic is being stopped.

## What a rule can honestly promise

Read this before writing your first label. It shapes what "allow" and
"deny" actually mean:

- An IP or CIDR entry is a hard match against the connection's own
  destination address. This is ground truth, always available.
- A domain or wildcard-domain entry (`example.com`, `*.example.com`)
  matches only through **DNS-cache correlation**: airlock watches this
  container's own DNS answers and checks whether the connection's
  destination IP showed up in a recent answer for a matching name. This is
  per container, never shared across containers.
- TLS SNI is observed too, but it is **enrichment only**. It is shown
  alongside DNS evidence in an alert so a human has more context, but it
  never decides whether a connection matches a rule, in either direction.
  (An earlier build let SNI settle disagreements with DNS; a real
  integration pass showed that misattributes one connection's SNI to a
  different, unrelated connection from the same container, which can turn
  a real violation into a false negative. airlock is fail-closed on SNI
  because of that.)
- A connection to a bare IP with no DNS evidence at all cannot match any
  name-based rule. It either matches an IP/CIDR rule directly or it falls
  through as its own violation class, `unresolved-ip`, distinct from an
  ordinary undeclared destination (`no-match`). There is no "ignore
  unresolved" knob; the escape is to allowlist the IP or CIDR explicitly.
- Evaluation happens once, at connect time. A policy change never
  re-judges a connection that already happened.

The full grammar (every label, every entry shape, the reserved surface) is
in [docs/LABELS.md](docs/LABELS.md).

## Quick start

Arm a container and declare it makes no outbound connections at all, the
strongest and cheapest policy in the grammar:

```yaml
services:
  firefly-db:
    image: postgres:16
    labels:
      airlock.enable: "true"
```

Nothing alerts on an armed container until it deviates: every armed
container is default-deny, and what you did not declare is a violation.
A tight allowlist looks like this:

```yaml
services:
  renovate:
    image: renovate/renovate
    labels:
      airlock.enable: "true"
      airlock.allow: "api.github.com:443,*.githubusercontent.com:443,registry.npmjs.org:443"
```

Default-deny against an undeclared container is noisy at first, so there
is a first-class onboarding state. Set `airlock.mode: audit` and airlock
evaluates the policy exactly as it would in `alert` mode, but tallies
would-be violations into the digest instead of firing individual alerts:

```yaml
services:
  legacy:
    image: example/mystery
    labels:
      airlock.enable: "true"
      airlock.mode: "audit"
```

Let it run for a representative period, then:

```
airlock suggest legacy
```

renders every destination that container actually reached as a
ready-to-paste `airlock.allow` value (a name when DNS correlation had
evidence, an IP when it did not). Prune what does not belong, paste the
rest into `airlock.allow`, delete `airlock.mode`, and the container is on
default-deny alert mode.

### Group policy: arm a whole class of containers with no per-container label

`airlock.yml` can arm every container in a compose project or on a network
at once, with no `airlock.*` label anywhere in the compose file:

```yaml
# airlock.yml
groups:
  - name: media-stack
    match:
      compose_project: mediastack
    enable: "true"
    scope: "all"
    allow:
      - "@self"
      - "api.themoviedb.org:443"
      - "*.servarr.com:443"
```

Every container in the `mediastack` project is armed, default-deny, may
reach each other freely (`@self`, meaningful because `scope: all` also
judges container-to-container traffic), plus TheMovieDB and the servarr
update surface. Anything else alerts.

## The two-file model

airlock's policy comes from two places, and both are optional
independently:

- **Container labels** (`airlock.*`, or the `tagwright.egress.*` alias)
  declare one container's own policy: `airlock.enable`, `airlock.allow`/
  `airlock.deny`, right on the container they govern. Both prefixes carry
  the identical suffix grammar; the same key under both with different
  values is a validation error, and the container's policy is skipped
  until it's fixed.
- **`airlock.yml`** is where fleet-wide concerns live that do not belong
  on any one container: named, reusable policy sets a label can reference
  by name, group-scoped policy that arms a whole class of containers
  automatically, fleet-wide defaults, notification channels, and
  telemetry sinks. It is optional too: every `defaults` field mirrors an
  `AIRLOCK_*` environment variable, and the env var wins when both are
  set, so an env-only deployment with no file at all is valid.

See [airlock.example.yml](airlock.example.yml) for a fully annotated
config, [docs/LABELS.md](docs/LABELS.md) for the complete label reference,
and [docs/DEPLOY.md](docs/DEPLOY.md) for the privileged deploy this needs
(read that before deploying anywhere you care about) and the secrets
recipe. Day-to-day operation, the audit onramp, alert tuning, and
troubleshooting are in [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Verify it worked

Offline, no daemon required:

```
airlock validate
```

Loads and checks `airlock.yml` for internal consistency, reports `OK` or
every error found.

With the daemon running:

```
airlock status
```

Shows backend health (is `ig` restarting, dropping events, or has it gone
quiet) and every currently armed container's mode, scope, matched
`airlock.yml` groups, and violation counts.

To confirm the whole loop end to end: label a container `airlock.enable:
"true"` and `airlock.mode: audit`, let it run long enough to make a normal
connection, then run `airlock suggest <container>` and check that it
lists what you expect. Prune the result into `airlock.allow`, drop the
`mode` label, and make that container connect somewhere not on its new
allowlist (or wait for it to happen naturally) — you should see an alert
land on whichever beacon channel you configured, within one dedup window
(`airlock.alert.window`, default `1h`). The very first occurrence of a new
violation identity fires immediately regardless of the window.

## License

Licensed under GPL-3.0-or-later. See [LICENSE](LICENSE) for the full text.
Each source file carries an `SPDX-License-Identifier: GPL-3.0-or-later`
header.
