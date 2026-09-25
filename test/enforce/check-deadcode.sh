#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 techgaud
#
# Dead-code gate (Testing Standard enforceability layer, task #552).
#
# Runs golang.org/x/tools/cmd/deadcode (pinned) rooted at the real main, and
# fails on any function unreachable from the production entrypoint. This
# machine-checks the built-but-not-wired class directly (the Billet lesson).
# Zero tolerance: ballast has zero dead code and this keeps it that way.
#
# Needs the Go toolchain and network for the pinned tool; runs in golang:1.25.
set -euo pipefail

# Pin the analyzer version. Bump deliberately, never float, so a toolchain or
# analyzer change is a reviewed edit and not a silent behavior shift.
DEADCODE_VERSION="v0.38.0"

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
cd "$repo"

# Capture findings (stdout) separately from download noise and real errors
# (stderr). On a cold module cache the analyzer prints "go: downloading ..." to
# stderr, so folding stderr into the findings would false-fail a clean tree.
# A nonzero exit is a real analyzer failure, distinct from a clean run.
errf="$(mktemp)"
if out="$(go run "golang.org/x/tools/cmd/deadcode@${DEADCODE_VERSION}" ./... 2>"$errf")"; then rc=0; else rc=$?; fi
if [ "$rc" -ne 0 ]; then
  echo "FAIL: deadcode analyzer failed to run (exit $rc):" >&2
  cat "$errf" >&2
  rm -f "$errf"
  exit 1
fi
rm -f "$errf"
if [ -n "$out" ]; then
  echo "FAIL: deadcode found unreachable production code:" >&2
  printf '%s\n' "$out" >&2
  echo "      Wire it in, delete it, or if it is a deliberate exported API surface" >&2
  echo "      reachable only by an out-of-module consumer, document why here." >&2
  exit 1
fi
echo "deadcode: OK (no unreachable code)"
