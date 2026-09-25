#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 techgaud
#
# The live integration harness aggregator (tagwright Testing Standard, task
# #548). Runs every scenario script in sequence against a live Docker socket and
# a real, privileged Inspektor Gadget, and fails on the first failure so one CI
# run surfaces the break. This is the single entry point the self-hosted CI leg
# (ci-selfhosted.yml) and the release gate (release.yml) both call, so "the
# harness" means one thing in one place rather than a drifting list per caller.
#
# All scenarios here drive throwaway containers (a real ig, a throwaway ntfy,
# netshoot/target containers) over the runner's ISOLATED privileged dind socket,
# never the production socket: every one is CI-reachable, so every one is a CI
# gate, not operator-run. There is no operator-run bucket for airlock (see
# LAST-RUN); every scenario stands up its own real backend inside the dind.
#
# Ordered cheapest-first: run-capture.sh is the environment probe (does not build
# airlock at all -- it only proves privileged ig loads and what its real NDJSON
# looks like), so it fails fast if the kernel/ig surface is unavailable before
# any expensive image build. run-detect.sh (pass 1) then builds the real image
# and proves the base detect-and-alert pipeline; run-groups.sh (pass 2) and
# run-pass3.sh (pass 3) prove the distinctive group/token/flood surfaces on top.
#
# Usage: test/integration/run-all.sh [--keep]
#   --keep  pass through to each scenario (skip cleanup, for debugging)
set -uo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KEEP=""
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP="--keep" ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# run-capture.sh is the environment probe (no image build) and must pass first;
# the rest are the three integration passes in order, each building the real
# image and driving it against real backends over the isolated socket.
SCENARIOS=(
  run-capture.sh
  run-detect.sh
  run-groups.sh
  run-pass3.sh
)

fail=0
failed_list=""
for scen in "${SCENARIOS[@]}"; do
  printf '\n########## harness: %s ##########\n' "$scen"
  if ! "$HARNESS_DIR/$scen" $KEEP; then
    echo "harness: SCENARIO FAILED: $scen" >&2
    fail=1
    failed_list="$failed_list $scen"
    # keep going so one run reports every break
  fi
done

echo
if [ "$fail" -ne 0 ]; then
  echo "harness: FAIL (scenarios:$failed_list)" >&2
  exit 1
fi
echo "harness: all ${#SCENARIOS[@]} scenarios passed"
