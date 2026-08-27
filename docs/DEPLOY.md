# Deploying airlock

airlock runs as a single privileged container: itself plus the Inspektor
Gadget (`ig`) binary it drives as a subprocess. There is no sidecar, no
second service to wire up. What makes this deployment different from the
rest of the suite is the privilege it needs to do that, so this guide leads
with that trade-off before covering the ordinary parts: the two-file policy
model, secrets, the gadget-image pull behavior, and how to check it worked.

## The privilege trade-off

Read this before you deploy airlock anywhere you care about. It is not a
formality.

airlock evaluates policy in its own process, but it does not see network
traffic itself. It execs `ig run <gadget-image> -o json` as a subprocess for
each of three gadgets (`trace_tcp`, `trace_dns`, `trace_sni`), and `ig` is
the thing that actually loads eBPF programs into the kernel. Loading eBPF
programs needs `CAP_SYS_ADMIN`, and as of the `ig` version this image pins
(v0.55.1), Inspektor Gadget has not invested in a fine-grained capability
set for non-Kubernetes use: every documented deployment example, without
exception, uses Docker's `--privileged` flag rather than an enumerated
capability list. `docker-compose.yml` in this repository sets exactly the
four grants the frozen architecture calls for, no more:

- **`privileged: true`.** Grants `CAP_SYS_ADMIN` and, in practice, every
  other capability, because that is the only grant `ig` has been tested
  against. This is the one that actually matters for eBPF loading. The
  other three exist to make the events `ig` produces meaningful.
- **`pid: host`.** Shares the host's PID namespace. Inspektor Gadget's own
  docs mark this required on Docker Desktop and optional on native Linux,
  but airlock's compose sets it unconditionally rather than branching on
  host type, since it costs nothing extra once `--privileged` is already
  granted.
- **`-v /:/host:ro`.** The whole host filesystem, read-only, mounted at
  `/host`. This is what lets `ig`'s container-collection layer enrich a raw
  eBPF event (mount namespace, net namespace, PID) with a real container
  identity by reading the container runtime's own rootfs and
  `config.json`. It is also how airlock's own resolver-baseline check
  reaches the host's real `/etc/resolv.conf` (at `/host/etc/resolv.conf`,
  wired through `AIRLOCK_RESOLV_CONF` in the compose file) rather than this
  container's own Docker-embedded-DNS stub. Read-only because nothing
  either process does here ever needs to write to the host.
- **The container socket, read-only.** `tagwright/core`'s runtime
  abstraction (container listing, inspection, network membership) and
  `ig`'s own container-collection enrichment both only ever read it. Never
  mount it read-write for airlock. Nothing in this codebase creates,
  stops, or signals a container through it.

None of this is a design defect being smoothed over. It is Inspektor
Gadget's actual, current privilege floor, stated plainly by its own docs,
and it is why the frozen architecture treats "detect, never block" as a
permanent v1 scope boundary rather than a missing feature: a tool that
already needs full host privilege to *observe* is not a tool you also want
making inline blocking decisions on today's capability story.

**What this means for you:** airlock's container can read every other
container's identity, every host file (read-only), and load arbitrary eBPF
programs. Treat the airlock container itself as one of the most sensitive
things on the host it runs on. It is also, deliberately, not exempt from
its own policy: per the frozen architecture, airlock's own container is
observed like any other, and its own `airlock.yml` policy (or lack of one)
is your choice to write, same as any other container. It must allow
whatever your beacon notification channels need to reach.

**Documented TODO, not solved here:** a tighter, enumerated capability set
(`CAP_BPF` + `CAP_PERFMON` + `CAP_NET_ADMIN`, roughly, once Inspektor Gadget
documents that it works) is the natural hardening step for a later version,
once upstream has actually validated non-`--privileged` operation. Nothing
in today's `ig` release makes that a supported configuration, so this
release does not pretend otherwise with an unverified `cap_add:` list.

## The two-file model

airlock's policy comes from two places, and both are optional independently:

- **Container labels** (`airlock.*`, or the `tagwright.egress.*` alias) are
  the normal, per-container way to declare a policy: `airlock.enable=true`
  plus `airlock.allow`/`airlock.deny` entries, right on the container that
  policy governs. See "Airlock Label Grammar" for the full grammar.
- **`airlock.yml`** (mounted read-only at `/etc/airlock/airlock.yml`) is
  where fleet-wide concerns live that do not belong on any one container:
  named, reusable policy sets a label can reference by name, group-scoped
  policy that arms a whole class of containers automatically (by compose
  project, network, or label selector, with no per-container label
  required at all), fleet-wide defaults, notification channels, and
  telemetry sinks.

Neither file is required. A container with no `airlock.*` labels and no
matching group is simply unpolicied: airlock still observes it (fleet-wide
observation is the default, see `AIRLOCK_OBSERVE`), but never alerts on
it. `airlock.yml` itself is optional too. Every `defaults` field mirrors an
`AIRLOCK_*` environment variable, and the env var always wins when both are
set, so an env-only deployment with no file at all is valid.

To use the turnkey stack:

1. Copy `docker-compose.yml`, `airlock.example.yml`, and
   `airlock.env.example` to your deploy directory.
2. Copy `airlock.example.yml` to `airlock.yml` and edit it: name your
   policy sets, declare any groups, set your notification channels and
   telemetry sinks. The schema is documented inline in the example.
3. Label the containers you want policy on (see the grammar doc), or rely
   entirely on `airlock.yml` groups if you would rather arm whole classes
   of containers with no label at all.
4. Provision secrets (next section).
5. `docker compose up -d`.

## Secrets

airlock holds exactly one class of secret: the credentials its own
`notifications` and `telemetry` channels need to reach beacon's delivery
backends (an ntfy token, a Discord webhook URL, a Gatus push token). There
is no other secret-shaped field anywhere in `airlock.yml` or the label
grammar. A destination or policy value is never a credential.

Every credential value in `airlock.yml` is a secret NAME, never a literal
token:

```yaml
notifications:
  channels:
    - type: ntfy
      settings:
        topic: airlock-alerts
        token: ntfy-airlock-token   # a NAME, not the token itself
```

`internal/secret`'s resolver looks up a name in this order:

1. A file at `<secrets_dir>/<name>` (default `/run/airlock/secrets`,
   overridable by `secrets_dir` in `airlock.yml` or `AIRLOCK_SECRETS_DIR`).
2. The environment variable `AIRLOCK_SECRET_<NAME>`, where `<NAME>` is
   `<name>` uppercased with `-` replaced by `_`.
3. Neither found: the send fails loudly and is logged, rather than going
   out with an empty credential.

`docker-compose.yml` wires up both paths: a read-only bind mount of
`./secrets` at `/run/airlock/secrets`, and an optional `./airlock.env`
env-file. Use whichever fits your deploy tooling better. A mounted file
keeps the value out of the container's environment (which anything that
can exec into this privileged container, or read its `/proc/1/environ`,
can otherwise see), an env var is simpler to generate from a single
decrypt step. Both are optional and the stack boots fine with neither.

### SOPS with age

The recipe this suite uses everywhere else, adapted to airlock's
one-file-per-secret model. If you already have an age key for the rest of
your fleet, skip to step 3.

1. Generate an age key pair, and keep the private key off the host it
   protects:

   ```
   age-keygen -o airlock-age-key.txt
   ```

   This prints the matching public key (`age1...`) to stderr. Keep both.

2. Point SOPS at that public key with a `.sops.yaml` next to your secrets
   source:

   ```yaml
   creation_rules:
     - path_regex: \.sops\.yaml$
       age: age1exampleexampleexampleexampleexampleexampleexampleexamplex
   ```

3. Write your secret values as a plain name-to-value mapping, then encrypt
   in place. Names here are exactly the secret names your `airlock.yml`
   channels reference:

   ```
   cat > airlock.secrets.sops.yaml <<'EOF'
   ntfy-airlock-token: <your ntfy access token>
   discord-airlock-webhook: <your discord webhook url>
   EOF

   sops -e -i airlock.secrets.sops.yaml
   ```

   `airlock.secrets.sops.yaml` now holds ciphertext and is safe to commit.

4. At deploy time, decrypt and fan the values out to one file per secret
   under `./secrets/`, matching what the resolver expects:

   ```sh
   mkdir -p secrets
   sops -d airlock.secrets.sops.yaml \
     | python3 -c '
   import sys, yaml
   for name, value in yaml.safe_load(sys.stdin).items():
       with open(f"secrets/{name}", "w") as f:
           f.write(str(value))
   '
   chmod 600 secrets/*
   docker compose up -d
   ```

   If you would rather avoid decrypted files sitting on the host disk at
   all, decrypt straight into the running container's own tmpfs instead:
   bring the stack up first, then `docker compose exec -T airlock sh -c
   'umask 077; cat > /run/airlock/secrets/<name>'` once per secret, piping
   in the decrypted value. Either way, the plaintext never needs to survive
   past the container's own read of it.

   The simpler env-var path is the same shape as bilgeline's and ballast's
   own recipes: a `NAME=value` `.sops.env` file, `sops -d` into
   `airlock.env`, `docker compose up -d`.

## The gadget-image pull behavior

Every gadget airlock drives (`trace_tcp`, `trace_dns`, `trace_sni`) is an
OCI image pulled from `ghcr.io/inspektor-gadget/gadget/<name>` by `ig`
itself, not something baked into this image. `ig run`'s own default
(`--pull=missing`) means each gadget image is pulled **lazily, on first
use**, the first time the daemon starts that gadget's subprocess: not
pre-pulled at image build time, and not pre-pulled at container start
before observation begins. Concretely this means:

- The airlock container needs outbound network access to `ghcr.io` the
  first time it starts (or the first time after a gadget image changes),
  and every restart before that first pull completes runs briefly blind on
  whichever gadget hasn't finished pulling.
- `docker-compose.yml` mounts a named volume at `/var/lib/ig` (`ig`'s own
  image store and auth config) specifically so this pull only happens
  once: a later restart or recreate reuses the already-pulled images
  instead of re-pulling from ghcr on every boot.
- `airlock.yml`'s `observe.images` map lets you pin every gadget to a
  specific digest (`ghcr.io/inspektor-gadget/gadget/trace_tcp@sha256:...`)
  instead of floating on `:latest`. Do this before relying on airlock in
  production: each gadget's own JSON schema can change on that gadget's
  own release cadence, independent of the `ig` binary's version, so
  `:latest` is not schema-stable and a silent upstream schema change is a
  silent correlation break for airlock. Pinning by digest is a
  packaging-time decision you make once per gadget version, not a runtime
  one.

## Verify it worked

Offline, no daemon required:

```
docker compose exec airlock airlock validate
```

Loads and checks `airlock.yml` for internal consistency (policy sets,
groups, defaults, notification and telemetry config) and reports `OK` or
every error found, nonzero exit on invalid config. This never touches the
socket or does container discovery.

With the daemon running:

```
docker compose exec airlock airlock status
```

Shows backend health (is `ig` restarting, dropping events, or has it gone
quiet), and every currently armed container's mode, scope, matched
`airlock.yml` groups, and violation counts. This reads a periodically
written state snapshot, so it can be up to `AIRLOCK_STATE_INTERVAL`
(default 5s) stale, but a healthy `events_flowing: yes` with `restarts: 0`
and `dropped_events: 0` is the sign everything downstream of `ig` is
working.

To confirm the whole loop end to end, label a real container and watch for
an alert:

1. Pick a container that talks to somewhere predictable (a container that
   hits `deb.debian.org` for updates, for instance), and set:

   ```yaml
   labels:
     airlock.enable: "true"
     airlock.mode: audit
   ```

   Audit mode evaluates the policy exactly as alert mode would, but only
   counts would-be violations into the digest instead of firing individual
   alerts, so this step is safe to try on something already running.

2. Recreate that container so the label takes effect, let it run long
   enough to make a normal connection, then:

   ```
   docker compose exec airlock airlock suggest <container>
   ```

   This reads the same state snapshot and renders every distinct
   destination that container reached as a ready-to-paste `airlock.allow`
   entry (a name when SNI or DNS correlation had evidence, an IP when it
   did not).

3. Prune the suggested list down to what actually belongs, paste it into
   that container's `airlock.allow` label (or into an `airlock.yml` policy
   set it references), delete `airlock.mode: audit` so it falls back to
   the default `alert` mode, and recreate the container once more.

4. Make that container connect somewhere NOT on its new allowlist (or wait
   for it to happen naturally). You should see an alert land on whichever
   beacon channel you configured within one dedup window
   (`airlock.alert.window`, default 1h for the first hit). The very first
   occurrence of a new violation identity fires immediately regardless of
   the window.

If step 4 never fires, check `airlock status`'s backend line first
(`events_flowing`, `dropped_events`) before assuming the policy is wrong:
a quiet backend means airlock never saw the connection at all, which is a
privilege or `ig` problem, not a policy problem.

## Scope: detect-only in v1

airlock never blocks a connection in this release, and that is a permanent
architectural boundary for as long as Inspektor Gadget is its only
observation backend, not a "not yet built" gap: IG's own third-party
security audit states plainly that it "functions as pure observability...
provides no enforcement or blocking capabilities," and there is no
eBPF-based egress-drop gadget on IG's roadmap. `airlock.mode=block` is
reserved syntax and is always a validation error in v1, on purpose, never
silently downgraded to `alert`.

Blocking arrives only with `bathyscaphe`, tagwright's own eBPF backend,
built specifically to add it, joining behind the same observation-backend
interface airlock already uses for IG. Until then, treat airlock as
exactly what its name in this release means: visibility and alerting on
egress drift, not a firewall.
