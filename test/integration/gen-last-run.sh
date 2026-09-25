#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 techgaud
#
# Regenerates test/integration/LAST-RUN (tagwright Testing Standard, task #548).
# The operator runs the harness (or at least the operator-run bucket) and then
# runs this to stamp the attestation with the current HEAD sha and today's date.
# The release job's check-last-run.sh asserts that sha equals the tag being
# published, so run this at the exact commit you will tag.
#
# It does NOT run the harness itself: it records that you did. Run the harness
# first (test/integration/run-all.sh), and for the operator-run bucket run those
# scenarios by hand against the real service, then edit the operator_run rows
# below to the results you observed. airlock has no operator-run bucket today
# (operator_run: none), so a stamp is all that is needed.
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/../.." && pwd)"
OUT="$HARNESS_DIR/LAST-RUN"

sha="$(git -C "$REPO_ROOT" rev-parse HEAD)"
date="$(date -u +%Y-%m-%d)"

# Preserve the human-authored header and operator_run rows; only refresh sha/date.
# The operator edits operator_run by hand (this script cannot observe a real
# external-service run), so a naive rewrite would clobber it. We rewrite only the
# sha and date lines in place.
tmp="$(mktemp)"
sed -e "s/^sha: .*/sha: $sha/" -e "s/^date: .*/date: $date/" "$OUT" > "$tmp"
mv "$tmp" "$OUT"
echo "LAST-RUN stamped: sha=$sha date=$date"
echo "Confirm operator_run rows are current for this sha before committing."
