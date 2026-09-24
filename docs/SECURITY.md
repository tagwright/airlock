<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Security

airlock is a visibility tool, so the most important thing this document does is
be clear about what it sees and what it cannot stop. A tool that watches egress
and alerts is easy to mistake for a tool that enforces it, and that mistake is
exactly the kind that gets a container trusted more than it should be. Every
claim here is checkable against the code and the honest coverage accounting in
[TESTING.md](TESTING.md).

## It observes, it does not enforce

airlock does not block traffic and is not a firewall. It watches what a container
connects to and raises an alert when a connection does not match the policy the
container's labels declared. Nothing airlock does ever drops or rejects a packet.

This is a deliberate v1 boundary, not a gap being smoothed over. airlock execs
Inspektor Gadget (`ig`) to load eBPF tracers and reads the event stream, and
Inspektor Gadget's own third-party audit states that it functions as pure
observability with no enforcement or blocking. `airlock.mode: block` is reserved
syntax that is always a validation error. It is never silently downgraded to
`alert`, because an operator who wrote `block` believes traffic is being stopped,
and shipping them a quiet downgrade would be worse than refusing the label.

An alert is after the fact. The connection airlock alerts on already happened. A
policy in airlock is a tripwire that tells you a container reached somewhere it
should not have, so you can investigate and cut it off yourself. It is not a wall
that holds the connection back. Deploy it as detection, and pair it with actual
network controls if you need traffic stopped.

## What a policy match actually means

The strength of an alert depends on how the destination was matched, and the
matching is honest about its own limits:

- An IP or CIDR entry is a hard match against the connection's real destination
  address. This is ground truth and always available.
- A domain entry (`example.com`, `*.example.com`) matches only through DNS-cache
  correlation. airlock watches that container's own DNS answers and checks
  whether the connection's destination IP showed up in a recent answer for a
  matching name. The correlation is per container and never shared across
  containers.
- TLS SNI is observed but is enrichment only. It rides alongside the DNS evidence
  in an alert to give a human more context, and it never decides whether a
  connection matches, in either direction. An earlier build let SNI settle
  disagreements with DNS, and a real integration pass showed that path
  misattributing one connection's SNI to a different connection from the same
  container, which turns a real violation into a false negative. airlock is
  fail-closed on SNI because of that.
- A connection to a bare IP with no DNS evidence cannot match any name-based
  rule. It either matches an IP or CIDR rule directly or falls through as its own
  violation class, `unresolved-ip`, kept distinct from an ordinary undeclared
  destination. There is no "ignore unresolved" knob. The escape is to allowlist
  the IP or CIDR explicitly.

Two consequences follow from the DNS-cache basis, and they are worth stating so
nobody over-trusts a name-based allowlist. A container that resolves names over
encrypted DNS (DoH or DoT) gives airlock no plaintext answer to correlate, so its
connections carry no DNS evidence and fall through as `unresolved-ip` rather than
matching a name. And where several names share one IP behind a CDN, a
correlation cannot tell which name a connection was for. Evaluation also happens
once, at connect time, so a policy change never re-judges a connection that
already completed. For anything you need to pin hard, use an IP or CIDR entry.

## The privilege it runs with

airlock's own deployment is the largest thing to weigh, and it is covered in full
in [DEPLOY.md](DEPLOY.md). The short version: loading eBPF needs `CAP_SYS_ADMIN`,
and as of the `ig` version this image pins, Inspektor Gadget documents no
fine-grained capability set for non-Kubernetes use, so airlock's container runs
`privileged: true` with `pid: host`, the host filesystem mounted read-only at
`/host`, and the container socket read-only.

That means the airlock container can read every other container's identity, read
every host file, and load arbitrary eBPF programs. Treat it as one of the most
sensitive containers on the host it runs on. A compromise of airlock is close to
a compromise of the host. The socket is read-only inspection only, and no code
path in airlock creates, stops, or signals a container through it, but the
privilege grants above are the real exposure, not the socket. A tighter
enumerated capability set is the natural hardening step once Inspektor Gadget
validates non-privileged operation upstream, and this release does not pretend
that day has arrived with an untested `cap_add:` list.

airlock's only secret domain is its own alerting-channel credentials, such as an
ntfy token or a webhook URL. There is no policy secret. The egress grammar has no
secret-shaped field at all. Those alerting secrets resolve from a file under the
secrets directory or an `AIRLOCK_SECRET_<NAME>` variable, and no secret value is
logged. A mounted file keeps the value out of the container environment, which
anything able to exec into this privileged container could otherwise read.

## What airlock does not defend against

- **It does not stop exfiltration.** A container that is already reaching out to
  somewhere it should not will finish doing so. The alert lands after, so
  determined exfiltration completes regardless. airlock tells you it happened.
- **It is not a firewall.** A compromised container can still reach anything the
  host network lets it reach. airlock changes what you know, not what is
  reachable.
- **Missing events are not proof of no egress.** If `ig` is down, restarting, or
  dropping events, airlock cannot see traffic during that window. `airlock
  status` surfaces backend health so a quiet backend does not read as a quiet
  network. A gap in observation is a gap, not an all-clear.
- **It does not defend against the operator.** Whoever writes the labels and
  `airlock.yml` writes the policy, and airlock's own container is observed under
  its own policy like any other. An operator who omits a policy gets no alerts,
  by their own choice.

## Reporting a vulnerability

Report a suspected vulnerability through GitHub's private vulnerability reporting
on this repository: open the Security tab and choose "Report a vulnerability".
That opens a private advisory visible only to the maintainers, which keeps the
report out of public issues while it is being worked. Fixes are coordinated
there, and public disclosure follows a fix rather than preceding it. The Security
tab is the channel for this.
