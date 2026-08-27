# airlock

Status: early scaffold, under construction. There is no working code yet,
just the repo layout, license, and a placeholder entrypoint.

airlock is a Go tool that gives per-container network-egress visibility for
Docker and Podman containers. You declare an egress policy in container
labels (`airlock.*` / `tagwright.egress.*`), and airlock watches actual
outbound traffic against that policy and alerts when a container's egress
deviates from what was declared.

airlock does not do its own packet tracing. It drives
[Inspektor Gadget](https://inspektor-gadget.io/) as its observation
backend, using IG's existing eBPF tracing rather than reimplementing any of
it. That backend is accessed through a backend-neutral interface inside
airlock, so a second observation backend can be added later without
reworking the policy or alerting layers.

airlock is part of the tagwright suite: a set of label-driven,
config-as-code companion tools for Docker and Podman.

## Scope in v1

v1 is detect and alert only. airlock observes egress traffic and raises
alerts when it does not match the declared policy. It does not block or
drop any traffic, and it is not a firewall.

Inline blocking/enforcement is deferred. It's planned for a later release,
arriving together with tagwright's own eBPF observation backend (a
future Rust probe), once that backend exists as an alternative to driving
Inspektor Gadget.

## License

Licensed under GPL-3.0-or-later. See [LICENSE](LICENSE) for the full text.
