# Label reference

The authoritative reference for airlock's v1 label grammar and
`airlock.yml` schema, derived from the code (`internal/discovery`,
`internal/policy`, `internal/config`, `internal/resolve`). Where this
disagrees with the wiki's draft grammar, this file is the one that tracks
the running code.

## Namespace

Every key below exists under two prefixes, identical suffix grammar,
different spelling:

- `airlock.<suffix>` — the primary, tool-branded form. Leads every example
  in this doc.
- `tagwright.egress.<suffix>` — the org-namespaced alias.

The same suffix under both prefixes with the **same value** is harmless.
The same suffix under both prefixes with **different values** is a
validation error: the container's whole declared policy is skipped, and a
sticky diagnostic fires until it is fixed. There is no silent precedence
between the two prefixes.

Any key under either prefix whose suffix is not in the known set below
(including a typo like `airlock.alow`) is itself a validation error and
skips the container's policy — unknown suffixes are never silently
ignored.

## Core labels

| Label | Type | Default | Meaning |
|---|---|---|---|
| `airlock.enable` | `"true"` \| `"false"` | absent | Arms this container's policy for evaluation and alerting. Absent (with no matching armed `airlock.yml` group) means the container is still observed per the fleet-wide observation scope, but never policy-alerted. A present-but-invalid value (anything other than the literal strings `true`/`false`) is a validation error. In a group context, `"false"` additionally opts this specific container **out** of a group that would otherwise arm it. |
| `airlock.name` | string | compose service label (`com.docker.compose.service`), else the container name | Overrides the stable service identity used in alert dedup and alert text. Copied through verbatim, no validation. Duplicate names are legal — replicas of one service share one policy and one dedup identity, and alerts still carry the container name and short id to disambiguate. |
| `airlock.mode` | enum | `alert` (or `AIRLOCK_DEFAULT_MODE`) | `audit` — evaluate the policy exactly as `alert` would, but route every would-be violation to the digest only, never an immediate alert. `alert` — evaluate and alert immediately on the first occurrence of a new violation identity, with windowed suppression of repeats. `block` — **reserved**, always a validation error in v1 (see Reserved surface below). |
| `airlock.scope` | enum | `external` (or `AIRLOCK_DEFAULT_SCOPE`) | `external` — judge every connection leaving the runtime's own container networks (the LAN included), excluding loopback. `all` — additionally judge container-to-container connections on the runtime's own networks. `@self`, `@project`, and `net:<name>` entries only have any effect under `scope: all` (see Destination entry grammar below). |
| `airlock.policy` | csv of names | none | References one or more named policy sets from `airlock.yml`'s `policies:` map. Every referenced set's `allow`/`deny` union into this container's lists; an unknown name is a validation error. See Policy sets below. |

## Policy (destination) labels

| Label | Type | Default | Meaning |
|---|---|---|---|
| `airlock.allow` | csv of entries, or the literal `none` | none (default-deny) | Destinations this container may reach. `none` is the explicit zero-egress sentinel: it must appear alone, never combined with other entries or with `airlock.allow.<n>`, and it is a validation error if it's combined with anything (including a referenced policy set that itself allows something). |
| `airlock.allow.<n>` | entry | none | Indexed escape hatch (`airlock.allow.0`, `airlock.allow.1`, ...) for an entry that itself contains a comma. Unioned with the `airlock.allow` csv, in ascending index order, de-duplicated by canonical form. |
| `airlock.deny` | csv of entries | none | Destinations that always violate, beating any allow. Deny has no `none` sentinel of its own — an empty deny list is already its zero value. Combined with `airlock.allow: "*"`, this is the explicit denylist posture. |
| `airlock.deny.<n>` | entry | none | Indexed escape hatch, same shape as `airlock.allow.<n>`. |

## Alerting labels

| Label | Type | Default | Meaning |
|---|---|---|---|
| `airlock.alert.window` | Go duration string | `1h` (or `AIRLOCK_ALERT_WINDOW`) | Dedup window per alert identity (service, destination, port, class). The first occurrence of a new identity always alerts immediately regardless of this window; repeats within the window are suppressed and counted toward the next digest and the next window-rolled alert. This is the only per-container alert tunable in v1. |

## Destination entry grammar

One entry syntax, shared by `allow` and `deny` everywhere they appear
(labels, `airlock.yml` policy sets, and `airlock.yml` groups):

```
entry := dest [ ":" port ] | "@self" | "@project" | "net:" name
dest  := domain | "*." domain | ipv4 | "[" ipv6 "]" | ipv6 | cidr | "*"
port  := integer 1-65535
```

- **`example.com`** matches that exact name. Domain matching is **DNS-cache
  correlation only**: the connection's destination IP must appear among
  this container's own recent DNS answers for that exact name. TLS SNI is
  never consulted for matching (see the README's "What a rule can
  honestly promise").
- **`*.example.com`** matches one or more leading labels
  (`api.example.com`, `a.b.example.com`) and never matches the bare apex
  `example.com` — write both entries if you mean both. Only one wildcard,
  leftmost only: `api.*.example.com` is a validation error, as is a bare
  `*.` with nothing after it, or more than one `*` anywhere in the entry.
- **IPv4/IPv6 literals and CIDRs** (`203.0.113.7`, `10.0.0.0/8`,
  `2606:4700::/32`) match the connection's raw destination address
  directly — a hard match, no name evidence involved. An **IPv6 literal or
  an IPv6 CIDR that carries a port must be bracketed**:
  `[2606:4700::1111]:443`. A bare, unbracketed IPv6 literal followed by
  `:NNN` is ambiguous with the address's own colons, so it parses as part
  of the address when that succeeds and is otherwise rejected with a
  message naming the bracket fix. IPv4 never needs brackets.
- **`*`** alone matches any destination — the explicit denylist-escape
  posture (pair it with `deny` entries to carve exceptions back out). Like
  any other `dest`, a bare `*` may carry a port: `*:443` matches any host
  on port 443.
- **`@self`**, **`@project`**, and **`net:<name>`** are the group
  self-reference tokens (see Groups below). All three carry **no port
  suffix at all** in v1 — any-port only. A port, or any other trailing
  content, after one of these tokens is a validation error, not a
  silently-accepted extension. For `net:<name>`, everything after the
  literal `net:` is taken as the network name verbatim, including any
  colon it might itself contain — there is no separate port position to
  parse out of it.
- **No port** on an entry means any port. A port means exactly that port.
- **Protocol: TCP only.** The `/udp` suffix is reserved syntax and is
  rejected in v1 with a validation error — never accepted inertly. It
  starts validating once a backend that observes UDP exists.
- **Port ranges** (`:1000-2000`) are likewise reserved and rejected in v1.
- **`none`** is the zero-egress sentinel, valid only as the entire value
  of `airlock.allow` (or a policy set's/group's `allow:`), never as one
  entry among several.

### The `@self` / `@project` / `net:<name>` tokens

- **`@self`** resolves, per container, to every network subnet that
  specific container is attached to.
- **`@project`** resolves to every container sharing this container's
  compose project (`com.docker.compose.project`), identity-based rather
  than network-based.
- **`net:<name>`** names one of the runtime's own networks by name,
  resolved live against the runtime's current network inventory. It
  behaves like a literal CIDR entry once resolved.

All three tokens are legal anywhere an entry is legal, but **they only
have any effect under `scope: all`.** Under the default `scope: external`,
the traffic they would cover (container-to-container, on the runtime's own
networks) is already out of scope, so a token entry there is a no-op and
draws a validation warning.

## Reserved-and-rejected surface

These are recognized syntax, not typos, and are rejected on purpose — none
of them are silently downgraded to something that works:

| Surface | Status |
|---|---|
| `airlock.mode: block` | Reserved for a future enforcement-capable backend (`bathyscaphe`). Always a validation error in v1: airlock only observes and alerts, it never blocks traffic, and this is never silently downgraded to `alert`. |
| Entry suffix `/udp` | Reserved for a future UDP-observing backend. Validation error in v1 — airlock evaluates TCP only. |
| Entry port ranges (`a-b`) | Reserved for a future release. Validation error in v1. |
| `airlock.enable: "false"` | Not itself an error — it is a real, meaningful value (opts a container out of an armed group, or is simply identical to "absent" outside a group context). Listed here because it is easy to assume it does something it doesn't: it never opts a container into observation exemption, and it never disables anything a matching group didn't already grant. |

Any `airlock.*`/`tagwright.egress.*` suffix outside the known set above
(`enable`, `name`, `mode`, `scope`, `policy`, `allow`, `allow.<n>`, `deny`,
`deny.<n>`, `alert.window`) is likewise a validation error, never ignored.

## `airlock.yml`: policy sets and groups

`airlock.yml` is optional, and every field in it is optional independently.
See [airlock.example.yml](../airlock.example.yml) for a complete, annotated
file.

### Named policy sets (`policies:`)

A named, reusable fragment of policy, referenced by `airlock.policy` (a
container label) or `groups[].policy` (a group), by csv of names:

```yaml
policies:
  debian-updates:
    allow:
      - "deb.debian.org:443"
      - "security.debian.org:443"
  github-api:
    allow:
      - "api.github.com:443"
      - "*.githubusercontent.com:443"
```

A `PolicySet` carries `allow`, `deny`, `scope`, `mode`, and `alert.window`
— the same fields a container's own labels can set. Set names are
lowercase identifier characters only (letters, digits, hyphen,
underscore), no commas.

**Merge rule:**

- `allow` and `deny` **union** across every referenced set plus the
  container's own label entries (or the group's own entries, for a group
  reference). Referencing two sets means both allowlists apply; there is
  no precedence among them.
- Scalar fields (`mode`, `scope`, `alert.window`) resolve **label over
  policy set over global default**. Two referenced sets that disagree on a
  scalar, with no label override to settle it, is a validation error —
  never silent last-one-wins.
- `allow: "none"` (on the label or the group) combined with a referenced
  policy set that itself has allow entries is a contradiction, not a
  suppression, and is a validation error: `"none"` is a declaration, not a
  filter.

### Groups (`groups:`)

A group arms every container its `match:` block selects, with **no
per-container `airlock.*` label required at all**. A group accepts every
field a container's own labels can, under the identical field names
(`enable`, `mode`, `scope`, `policy`, `allow`, `deny`, `alert.window`),
plus its own `match:` block. There is no `name` field on the container
side of a group — a group covers many containers, and each keeps its own
per-container service identity.

```yaml
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

  - name: backend-db-net
    match:
      network: mediastack_backend
    enable: "true"
    allow: "none"
```

**Targeting (`match:`)** picks exactly one of three co-equal dimensions —
combining more than one in a single group's `match:` block is a validation
error (express it as two groups instead, unioned by the merge rule below):

| Dimension | Matches | Notes |
|---|---|---|
| `match.compose_project` | `com.docker.compose.project` | The only dimension that reaches a `network_mode: service:X` container, which has no independent network attachment of its own. |
| `match.network` | Containers attached to the named runtime network | The flagship dimension for a true network-boundary group. |
| `match.label` | A csv of `key=value` pairs, logical AND across all of them | The power-user escape hatch for anything the other two dimensions miss. |

An **empty (or absent) `match:` block matches every container** — the
catch-all/wildcard tier below.

**Multi-group membership and specificity.** A container can be matched by
more than one group, plus carry its own labels:

- **List-valued fields** (`allow`, `deny`) **union across every applicable
  source**: the container's own label entries, every matching group's
  entries, and every policy set referenced by the label or by any matching
  group. No precedence — a second matching rule can only grant more, never
  silently remove an allowance another source granted.
- **Scalar fields** (`enable`, `mode`, `scope`, `alert.window`) resolve by
  a specificity ladder, most specific wins:
  1. The container's own labels (a policy set the label references travels
     at this same tier — referencing a set is itself a per-container act).
  2. A group matched by `compose_project` or by a label selector (both
     identity-based, naming a specific known set of containers).
  3. A group matched by `network` (structural only, no identity signal).
  4. A group with an empty `match:` block (the catch-all tier).
  5. The fleet-wide `defaults:` block, used only when nothing above
     contributed a value at all.

  Two sources at the **same** winning tier disagreeing on a scalar is a
  validation error — never silent last-writer-wins.

### Fleet-wide defaults (`defaults:`)

An optional `defaults:` block in `airlock.yml` mirrors the surviving
`AIRLOCK_*` environment globals field-for-field. Setting a field here is
equivalent to setting the matching environment variable, except the
environment variable always wins when both are set:

| `defaults:` field | Env var | Default | Meaning |
|---|---|---|---|
| `observe` | `AIRLOCK_OBSERVE` | `all` | `all` watches every container's egress regardless of arming; `enabled` watches only armed containers. |
| `default_mode` | `AIRLOCK_DEFAULT_MODE` | `alert` | Fleet-wide fallback for `airlock.mode` / `groups[].mode` when unset. Never `block`. |
| `default_scope` | `AIRLOCK_DEFAULT_SCOPE` | `external` | Fleet-wide fallback for `airlock.scope` / `groups[].scope` when unset. |
| `alert_window` | `AIRLOCK_ALERT_WINDOW` | `1h` | Fleet-wide fallback dedup window when a container or group leaves `alert.window` unset. |
| `alert_flood` | `AIRLOCK_ALERT_FLOOD` | `30` | Distinct-identity alerts per container per hour before the flood breaker collapses that container to one summary alert. |
| `digest_schedule` | `AIRLOCK_DIGEST_SCHEDULE` | `0 0 * * *` | Plain 5-field cron schedule for the one digest per period. |
| `implicit_allow` | `AIRLOCK_IMPLICIT_ALLOW` | empty (baseline only) | Extends the implicit resolver-on-port-53 baseline with more entries (full entry-grammar csv), or the literal `none` to disable even the baseline. |
| `unpolicied_digest` | `AIRLOCK_UNPOLICIED_DIGEST` | `false` | Opts in to a first-seen-destination-per-day digest summary for containers with no declared policy at all. |

There is deliberately no fleet-wide `allow`/`deny` field: a fleet-wide
allow is what `implicit_allow` is for (small, and named as a baseline
extension), and a fleet-wide deny hiding in `defaults:` while labels claim
the whole story would make `docker inspect` lie about what alerts. Policy
that needs real structure belongs in a group, not a default.
