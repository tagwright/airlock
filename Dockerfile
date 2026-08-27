# SPDX-License-Identifier: GPL-3.0-or-later
#
# Build context note (read before you build):
#
# airlock's go.mod carries `replace github.com/tagwright/core => ../core`
# because core is not published yet (airlock requires core v0.3.0, still
# unreleased). The build therefore needs BOTH the core/ and airlock/ module
# trees in the build context, so the context is the PARENT directory that
# holds them as siblings, not the airlock/ directory itself:
#
#   docker build -f airlock/Dockerfile -t ghcr.io/tagwright/airlock:dev .
#
# run from the parent of core/ and airlock/ (the tagwright monorepo root, or
# a clean checkout with both repos cloned as siblings). CI cannot do this
# yet at all -- see .github/workflows/ci.yml and release.yml's own notes.
#
# On a large working tree where core/ and airlock/ are not the only things
# under that parent (this deployment's actual /mnt/md0/docker is a
# multi-terabyte tree of unrelated projects), do NOT hand Docker that whole
# directory as the build context -- it tars the entire tree before the
# daemon ever reads a .dockerignore rule, .dockerignore or not. Build from a
# virtual context piped over stdin instead, which only tars the two
# directories actually named:
#
#   tar -cf - -C /mnt/md0/docker core airlock \
#     | docker build -f airlock/Dockerfile -t ghcr.io/tagwright/airlock:dev -
#
# beacon is a different story: it is published and public
# (github.com/tagwright/beacon), so it is fetched over the network like any
# other module. GOPRIVATE points go at tagwright's own source for direct
# fetches rather than the public proxy. go.sum still verifies integrity.
#
# ONCE core is published and tagged, this simplifies to a single-context
# build, exactly like bilgeline did after core was published: drop the
# `replace` line from go.mod, drop the core COPY below, set the context back
# to airlock/, and restore the ballast-style `COPY go.mod go.sum ./ && go mod
# download && COPY .` layering for a better dependency cache.

FROM golang:1.25 AS build

# Fetch tagwright's own modules (beacon) directly from source, not the proxy.
ENV GOPRIVATE=github.com/tagwright/*
ENV GOFLAGS=-buildvcs=false

WORKDIR /src

# core/ must sit beside airlock/ so the `replace => ../core` resolves. Copy
# core first: it changes far less often than airlock, so it caches well.
COPY core/ ./core/
COPY airlock/ ./airlock/

WORKDIR /src/airlock

# Download the network deps (beacon and the transitive set) up front. core is
# a local replace, so nothing is fetched for it.
RUN go mod download

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

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
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
