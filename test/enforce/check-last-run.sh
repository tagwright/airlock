#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 techgaud
#
# Enforces the live-harness LAST-RUN attestation (tagwright Testing Standard,
# task #548). Two modes:
#
#   check-last-run.sh              (enforce leg, every CI)
#       LAST-RUN must exist and be well-formed. If it names any operator-run
#       scenarios, `sha` must be a real 40-hex commit (not the unattested
#       placeholder). Does NOT require sha == HEAD: LAST-RUN is regenerated at
#       release time, not every push.
#
#   check-last-run.sh --release <sha>   (release job, at the tag)
#       Everything above, PLUS: if there are operator-run scenarios, `sha` must
#       equal <sha> exactly (the tag being published), no tolerance. This is the
#       standard's "must match the tagged sha exactly" gate. With operator_run
#       == none, there is nothing that can go stale, so it passes.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"
lastrun="$repo_root/test/integration/LAST-RUN"

release_sha=""
if [ "${1:-}" = "--release" ]; then
  release_sha="${2:-}"
  if [ -z "$release_sha" ]; then
    echo "check-last-run: --release needs a sha" >&2
    exit 2
  fi
fi

if [ ! -f "$lastrun" ]; then
  echo "check-last-run: FAIL: $lastrun missing" >&2
  exit 1
fi

get() { grep -E "^$1:" "$lastrun" | head -1 | sed -E "s/^$1:[[:space:]]*//"; }

sha="$(get sha)"
operator_run="$(get operator_run)"

if [ -z "$operator_run" ]; then
  echo "check-last-run: FAIL: no operator_run line in LAST-RUN" >&2
  exit 1
fi

if [ "$operator_run" = "none" ]; then
  echo "check-last-run: OK (operator_run: none; all scenarios are CI-gated)"
  exit 0
fi

# There are operator-run scenarios: the attestation must be real. The all-zeros
# placeholder is valid 40-hex but means "unattested", so reject it explicitly.
if ! printf '%s' "$sha" | grep -qE '^[0-9a-f]{40}$' || [ "$sha" = "0000000000000000000000000000000000000000" ]; then
  echo "check-last-run: FAIL: operator_run scenarios present but sha is unattested/not a real commit ($sha); run gen-last-run.sh" >&2
  exit 1
fi

if [ -n "$release_sha" ] && [ "$sha" != "$release_sha" ]; then
  echo "check-last-run: FAIL: LAST-RUN sha $sha != release sha $release_sha; re-run the operator-run scenarios at the tag and gen-last-run.sh" >&2
  exit 1
fi

echo "check-last-run: OK (operator_run attested at $sha)"
