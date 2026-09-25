#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 techgaud
#
# Skip-budget gate (Testing Standard enforceability layer, task #552).
#
# Counts t.Skip / t.Skipf / t.SkipNow calls across the test tree, split into
# two buckets by build tag, and enforces:
#
#   - NON-integration test files (the always-run `go test ./...` leg): 0 skips
#     allowed, no ratchet. That leg has no absent resource, so a skip there is
#     skip-to-get-green.
#   - //go:build integration test files (the harness / operator leg): at most
#     INTEGRATION_SKIP_BUDGET skips, a ratchet read from skip-budget.txt.
#
# Needs no Go toolchain: pure text over the source tree.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
budget_file="$here/skip-budget.txt"

# Read the committed integration budget without IFS='=' read (the fleet-wide
# dash-truncation trap): take everything after the first '=' by expansion.
budget=""
while IFS= read -r line; do
  case "$line" in
    INTEGRATION_SKIP_BUDGET=*) budget="${line#*=}" ;;
  esac
done < "$budget_file"
if ! printf '%s' "$budget" | grep -qE '^[0-9]+$'; then
  echo "skip-budget: could not read INTEGRATION_SKIP_BUDGET from $budget_file" >&2
  exit 2
fi

skip_re='\.(Skip|Skipf|SkipNow)\('

unit_total=0
int_total=0
unit_hits=""
int_hits=""

# Enumerate with find, not git ls-files: the repo runs its checks inside a
# root container over a uid-1000 bind mount, where git refuses the tree as
# "dubious ownership" and would silently yield no files (a fail-open the
# standard forbids). find is ownership-agnostic. .git is pruned.
seen=0
while IFS= read -r f; do
  seen=$((seen + 1))
  n="$(grep -cE "$skip_re" "$f" || true)"
  [ "$n" -eq 0 ] && continue
  rel="${f#"$repo"/}"
  if grep -qE '^//go:build integration' "$f"; then
    int_total=$((int_total + n))
    int_hits="${int_hits}  ${rel}: ${n}"$'\n'
  else
    unit_total=$((unit_total + n))
    unit_hits="${unit_hits}  ${rel}: ${n}"$'\n'
  fi
done < <(find "$repo" -name .git -prune -o -type f -name '*_test.go' -print)

# Fail closed: a ballast checkout always has test files. Zero means the scan
# found nothing (wrong cwd, a broken enumerator), not a clean tree.
if [ "$seen" -eq 0 ]; then
  echo "skip-budget: found no *_test.go files under $repo (scan is broken)" >&2
  exit 2
fi

fail=0

echo "skip-budget: always-run leg (banned, budget 0): $unit_total"
if [ "$unit_total" -ne 0 ]; then
  echo "FAIL: $unit_total skip(s) in always-run test files. That leg has no absent" >&2
  echo "      resource to justify a skip; a skip here is skip-to-get-green. Remove it" >&2
  echo "      or move the test behind //go:build integration if it is resource-gated:" >&2
  printf '%s' "$unit_hits" >&2
  fail=1
fi

echo "skip-budget: integration leg: $int_total (budget $budget)"
if [ "$int_total" -gt "$budget" ]; then
  echo "FAIL: $int_total integration-leg skip(s) exceeds budget $budget. Either the new" >&2
  echo "      skip is not resource-absent (forbidden), or bump INTEGRATION_SKIP_BUDGET in" >&2
  echo "      skip-budget.txt and name the resource-absent skip it admits:" >&2
  printf '%s' "$int_hits" >&2
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "skip-budget: OK"
fi
exit "$fail"
