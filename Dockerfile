# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build from the airlock repository root (single context):
#
#   docker build -t ghcr.io/tagwright/airlock:dev .
#
# core and beacon are consumed as published modules
# (github.com/tagwright/core, github.com/tagwright/beacon). GOPRIVATE makes
# the build fetch tagwright's own modules directly from their source rather
# than through the public module proxy. go.sum still verifies their integrity.

FROM golang:1.25 AS build

# Fetch tagwright's own modules (core, beacon) directly from source, not the
# proxy.
ENV GOPRIVATE=github.com/tagwright/*
ENV GOFLAGS=-buildvcs=false

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Static, VCS-stamp-free build. The version is stamped from the VERSION file
# into main.version, matching what `airlock version` prints.
RUN CGO_ENABLED=0 go build -buildvcs=false \
    -ldflags "-s -w -X main.version=$(cat VERSION)" \
    -o /out/airlock ./cmd/airlock

# -----------------------------------------------------------------------------
# Final image. NOT distroless-nonroot, unlike bilgeline: airlock is a
# privileged eBPF-driving tool, not a label-and-socket reader. It execs `ig`
# (Inspektor Gadget) as a subprocess to load eBPF tracers, which needs
# CAP_SYS_ADMIN -- in practice --privileged -- plus host filesystem and
# PID-namespace access AT RUNTIME (see docker-compose.yml and
# docs/DEPLOY.md), and `ig` itself pulls gadget OCI images from ghcr.io over
# the network on first use, which needs ca-certificates for TLS. A nonroot
# distroless base buys nothing here: the privilege boundary this tool needs
# is a compose/runtime concern, not a container-user concern, and eBPF
# loading requires root regardless of what UID a distroless:nonroot base
# would otherwise set. This image runs as root. The container MUST be run
# --privileged (see docs/DEPLOY.md for exactly what each flag and mount is
# for and why).
#
# debian:stable-slim, not alpine: it has ca-certificates and a normal glibc
# userland ig's own tooling assumes (its packaged .deb/.rpm releases target
# glibc distros), and it is the safer, better-trodden base for a privileged
# security tool an operator may need to exec into for troubleshooting. The
# `ig` release binary itself is statically linked either way, so this choice
# is about operability, not binary compatibility.
# -----------------------------------------------------------------------------
FROM debian:stable-slim

# Pinned Inspektor Gadget `ig` release binary. airlock DRIVES ig as a
# subprocess (internal/observe/ig spawns "ig run <gadget-image> -o json"), so
# the ig binary ships in the SAME image airlock runs in, not a sidecar.
#
# Pinned to v0.55.1 (published 2026-08-21, the current stable release as of
# packaging time). The checksum below is verified against the release's own
# SHA256SUMS file (https://github.com/inspektor-gadget/inspektor-gadget/
# releases/download/v0.55.1/SHA256SUMS) and independently re-verified by
# downloading the asset and hashing it directly during packaging.
#
# amd64 only for now. arm64 is a TODO: the v0.55.1 release also publishes
# ig-linux-arm64-v0.55.1.tar.gz (sha256
# e21c44cccb6e3c47044a53d54627ca2fcdb8a32e46a8d8d29fb94baa650a1cc1). Wiring a
# TARGETARCH build-arg through to pick between the two checksums is the
# natural follow-up once this image needs to run on an arm64 host.
ARG IG_VERSION=0.55.1
ARG IG_SHA256=6fda46b7c973fc063f1ea0b9ef61327e8bd1c0c5ce2383d6b9710d3dcfd3ca39

#
# runc is NOT here to run anything: airlock never launches a container of
# its own. It is here because ig's container-collection subsystem watches
# for container start/stop by fanotify-monitoring a container runtime
# BINARY on ITS OWN filesystem (this image's, not the host's) at one of a
# fixed list of well-known paths (/usr/bin/runc, /usr/sbin/runc, and a
# dozen others -- see RUNTIME_PATH in `ig`'s own error text). BUG FIX
# (this integration pass): confirmed against a real v0.55.1 `ig run`
# inside this exact image, with every other documented mount and flag
# already correct (--privileged, --pid=host, the docker socket, the
# runtime flag, --auto-mount-filesystems): without a runc binary present
# at one of those paths, container-collection's fanotify setup fails
# ("no container runtime can be monitored with fanotify"), which fails
# container-collection ENTIRELY, which fails ig's whole startup -- on
# EVERY gadget, every time, with zero events ever produced. This is
# independent of, and more fundamental than, the --auto-mount-filesystems
# and ig.DefaultRuntimes fixes elsewhere in this pass: even with both of
# those correct, this image could not observe anything at all without
# runc physically present in it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl runc \
    && curl -fsSL -o /tmp/ig.tar.gz "https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v${IG_VERSION}/ig-linux-amd64-v${IG_VERSION}.tar.gz" \
    && echo "${IG_SHA256}  /tmp/ig.tar.gz" | sha256sum -c - \
    && tar -xzf /tmp/ig.tar.gz -C /usr/local/bin ig \
    && chmod +x /usr/local/bin/ig \
    && rm -f /tmp/ig.tar.gz \
    && ig version \
    && apt-get purge -y --auto-remove curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/airlock /usr/local/bin/airlock

ENTRYPOINT ["/usr/local/bin/airlock"]
CMD ["daemon"]
