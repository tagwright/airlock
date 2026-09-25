#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 techgaud
#
# Runs every enforceability-layer check (Testing Standard, task #552) and
# reports a single pass/fail. Runs all of them even if an earlier one fails, so
# one CI run surfaces every problem at once. The Go-dependent checks (coverage,
# deadcode) need the toolchain; the text checks (skip budget, TESTING.md,
# LAST-RUN) do not, but running them all together in the repo golang:1.25 is
# simplest.
set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
fail=0

for check in check-skip-budget.sh check-wiring-coverage.sh check-deadcode.sh check-testing-doc.sh check-last-run.sh; do
  echo "=== ${check} ==="
  if ! "$here/$check"; then
    fail=1
  fi
  echo
done

if [ "$fail" -ne 0 ]; then
  echo "enforce: FAIL (see above)"
  exit 1
fi
echo "enforce: all checks passed"
