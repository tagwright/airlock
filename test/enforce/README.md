# Enforceability layer

These are the CI-enforceable checks the [tagwright Testing Standard][std]
calls its enforceability layer (task #552). They turn five of the standard's
rules from prose into gates that re-run on every CI, so the rule fails the
build the moment it stops being true rather than living in someone's memory.

All of them run on the **hosted** CI leg (`.github/workflows/ci.yml`), not the
self-hosted runner. None needs a Docker socket or kernel privilege: they are
static analysis and `go test`-level, so they belong beside `go build` / `go
vet` / `go test`, and the self-hosted runner stays reserved for the live
integration harness (`test/integration/`).

Run them all locally the same way CI does, inside the repo's `golang:1.25`
container (there is no host Go):

    docker run --rm -v "$PWD":/w -v airlock-gomodcache:/go/pkg/mod -w /w \
      -e GOPRIVATE=github.com/tagwright/* -e GOFLAGS=-buildvcs=false golang:1.25 \
      sh -c 'test/enforce/run-all.sh'

## The checks

### `check-skip-budget.sh` — the skip budget

A `t.Skip` is how a test goes green without proving anything, so the standard
caps them. This check splits skips into two buckets by build tag:

- **Always-run leg** (test files with no `//go:build integration` tag, the
  ones `go test ./...` compiles and runs on every CI): skips are banned
  outright, budget **0**, no ratchet. That leg runs in plain CI where every
  resource a test needs is present, so a skip there can only be
  skip-to-get-green.
- **Integration leg** (`//go:build integration` files, run by the live
  harness on the self-hosted runner or by the operator): skips are the
  *allowed* resource-absent kind — they skip cleanly when a live external
  service or a Docker socket is missing and run for real where those are
  present. Their count is capped at the committed budget in `skip-budget.txt`,
  a **ratchet**: removing a skip never breaks the build, and raising the budget
  is a reviewed change that must name the new resource-absent skip it admits.

airlock has **no** `//go:build integration` Go test files: its live integration
proofs are the shell harness under `test/integration/`, not Go integration-tagged
tests, so the integration skip budget is **0**.

### `check-wiring-coverage.sh` — the wiring-package coverage floor

A per-package statement-coverage floor, committed in `coverage-floor.txt`,
scoped to the **wiring** packages only (`internal/observe/ig`,
`internal/discovery`, `internal/resolve`, `internal/engine`,
`internal/daemon`) — the kernel/socket-event-to-effect path where this suite's
confirmed bugs actually live. It is deliberately not a global percentage: a
global number rewards testing the cheap pure core and is satisfied while the
wiring stays untouched. The floor is a ratchet: it may only rise. Edit a
number upward when coverage climbs; never downward to make a regression pass.

### `check-deadcode.sh` — the built-but-not-wired analyzer

Runs `golang.org/x/tools/cmd/deadcode` (pinned) rooted at the real `main`
(airlock is a daemon module, `cmd/airlock`, so `deadcode ./...` roots at
`main`, never `-test`). Any function unreachable from the production entrypoint
is reported and fails the build. This machine-checks the built-but-not-wired
class directly — the Billet dead-code lesson that every unit test passed over.
Zero tolerance. (The test-only injection airlock does need — a capturing beacon
for the notifier wiring test, a controllable clock for the flood/window tests —
is wired through real config channels and same-package field-sets, not through
production-file test seams, exactly so this gate stays honest.)

### `check-testing-doc.sh` — the docs/TESTING.md gate-check

Asserts every test name and file path `docs/TESTING.md` cites actually exists
in the tree, so the honest-reporting doc cannot rot into citing tests that
were renamed or files that moved. Citations are the backtick-quoted code
spans in the doc. See the script header for the exact citation grammar and
the cross-module rule.

### `check-last-run.sh` — the live-harness LAST-RUN attestation

Asserts `test/integration/LAST-RUN` exists and is well-formed, and that any
operator-run scenarios it names carry a real (non-placeholder) attestation sha.
The release job invokes it with `--release <sha>` to additionally require the
attestation match the tag being published exactly. airlock's `operator_run` is
`none` (every scenario stands up its own throwaway backend against the isolated
dind), so there is nothing that can go stale, but the gate stays in place for
the day a real external-service scenario is added.

## The committed data files

- `skip-budget.txt` — the integration-leg skip ceiling.
- `coverage-floor.txt` — per-wiring-package floors, `<package> <percent>`.

Bumping either is a normal reviewed edit. Lowering a floor, or raising the
skip budget without naming the skip it admits, is the move the standard's
"never weaken a gate to make code pass" rule forbids.

[std]: the tagwright Testing Standard (wiki, tagwright/operating/Testing Standard)
