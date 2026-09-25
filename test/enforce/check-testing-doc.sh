#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 techgaud
#
# docs/TESTING.md gate-check (Testing Standard enforceability layer, #552).
#
# Asserts every test name and file path docs/TESTING.md cites actually exists
# in the tree, so the honest-reporting doc cannot rot into citing renamed
# tests or moved files.
#
# Citation grammar. A citation is a backtick-quoted code span. Only spans that
# are unambiguously file or test references are checked:
#
#   PATH citation  — a span ending in .sh, .go, or .itest.yml, or ending in
#                    .md while containing a "/". Config-example names such as
#                    `ballast.yml` (a plain .yml, not .itest.yml) are generic
#                    prose, not tree references, and are not checked.
#                    Existence is an exact-or-suffix match against tracked
#                    files, so the doc's leading-path shorthand
#                    (`daemon/registry.go` for internal/daemon/registry.go,
#                    bare `run.sh` for test/integration/run.sh) resolves.
#   TEST citation  — a span matching Test<Name>, optionally with a trailing "*"
#                    prefix glob (`TestSplayFalse*`). Existence is a matching
#                    `func Test...` definition in any *.go, integration-tagged
#                    files included.
#
# Cross-module citations (any span containing "github.com/") are skipped: they
# name code in another module (for example github.com/tagwright/core/runtime),
# whose existence this repo's tree cannot and should not attest.
#
# Needs no Go toolchain: pure text over the doc and the tracked file list.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
doc="$repo/docs/TESTING.md"
cd "$repo"

if [ ! -f "$doc" ]; then
  echo "testing-doc: $doc not found" >&2
  exit 2
fi

# Enumerate with find, not git ls-files: inside the repo's root container over
# a uid-1000 bind mount git refuses the tree as "dubious ownership". find is
# ownership-agnostic. Paths are made repo-relative (leading "./" stripped) so
# the exact-or-suffix match below behaves the same as a tracked-path match.
files="$(find . -name .git -prune -o -type f -print | sed 's#^\./##')"
if [ -z "$files" ]; then
  echo "testing-doc: found no files under $repo (scan is broken)" >&2
  exit 2
fi
missing=""
path_n=0
test_n=0

# Pull every backtick span, one per line, backticks stripped.
spans="$(grep -oE '`[^`]+`' "$doc" | sed 's/^`//; s/`$//' | sort -u)"

while IFS= read -r tok; do
  [ -z "$tok" ] && continue
  case "$tok" in *"github.com/"*) continue ;; esac  # cross-module, out of scope

  # --- TEST citation ---
  if printf '%s' "$tok" | grep -qE '^Test[A-Za-z0-9_]+\*?$'; then
    test_n=$((test_n + 1))
    if printf '%s' "$tok" | grep -q '\*$'; then
      prefix="${tok%\*}"
      pat="func ${prefix}[A-Za-z0-9_]*"
    else
      pat="func ${tok}[[:space:]]*\\("
    fi
    if ! grep -rqE "$pat" --include='*.go' .; then
      missing="${missing}  test:  ${tok}"$'\n'
    fi
    continue
  fi

  # --- PATH citation ---
  is_path=0
  case "$tok" in
    *.sh|*.go|*.itest.yml) is_path=1 ;;
    *.md) case "$tok" in */*) is_path=1 ;; esac ;;
  esac
  [ "$is_path" -eq 0 ] && continue
  path_n=$((path_n + 1))

  # Escape regex-special dots, then treat a literal "*" in the citation as a
  # within-a-single-path-segment glob so directory-glob citations
  # (`internal/discovery/*_test.go`) resolve against the tracked file list.
  esc="$(printf '%s' "$tok" | sed -e 's/\./\\./g' -e 's#\*#[^/]*#g')"
  if ! printf '%s\n' "$files" | grep -qE "(^|/)${esc}$"; then
    missing="${missing}  path:  ${tok}"$'\n'
  fi
done <<EOF
$spans
EOF

echo "testing-doc: checked $path_n path citation(s) and $test_n test citation(s)"
if [ -n "$missing" ]; then
  echo "FAIL: docs/TESTING.md cites the following, none found in the tree:" >&2
  printf '%s' "$missing" >&2
  echo "      Fix the citation (rename/move) or repoint it at its module if the code" >&2
  echo "      now lives in another repo (github.com/tagwright/...)." >&2
  exit 1
fi
echo "testing-doc: OK"
