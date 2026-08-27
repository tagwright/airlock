#!/usr/bin/env bash
# End-to-end detect-and-alert proof: builds the REAL airlock image from the
# REAL Dockerfile, runs it --privileged against the real Docker socket with
# a real Inspektor Gadget (ig v0.55.1) driving real trace_tcp/trace_dns/
# trace_sni gadgets, and proves the whole pipeline on a real, labeled
# target container:
#
#   - airlock SEES real egress (Connection events attributed to the
#     target container with correct dst IP/port).
#   - an allowed-by-domain destination (resolved via a real DNS lookup
#     and/or a real TLS SNI ClientHello) produces NO violation.
#   - a bare-IP connection with no name evidence at all produces an
#     unresolved-ip violation.
#   - a name-evidenced connection that is not allow-listed produces a
#     no-match violation.
#   - the violation is both tallied into the daemon's own state snapshot
#     (state.json, what `airlock status` reads) and actually delivered to
#     a real notification channel (a throwaway ntfy server on the same
#     network).
#
# The three connections fire back to back with no deliberate spacing. An
# earlier version of this script spaced them SNI_GAP_SECONDS apart to dodge
# a real SNI-correlation risk (see docs/TESTING.md's "RESOLVED: SNI
# correlation could misattribute across close-together connections"
# finding): airlock has since gone fail-closed on SNI (SNI is enrichment
# only and never participates in a match decision; only a DNS-cache
# correlation can satisfy a name rule), which makes that risk moot
# regardless of connection timing -- firing them close together now is
# itself part of this proof, not something to avoid.
#
# Every Docker object this script creates (containers, the network, the
# built image) is named/tagged with the prefix "airlock-itest" and is torn
# down in a trap on exit (success, failure, or interrupt). It never
# touches any other container, network, volume, or image on the host, and
# it never prunes ig's own gadget-image store.
#
# Usage: test/integration/run-detect.sh [--keep]
#   --keep  skip cleanup at the end (for inspecting state.json/logs)

set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HARNESS_DIR/../.." && pwd)"
PARENT="$(cd "$REPO_ROOT/.." && pwd)"

KEEP=0
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

NET=airlock-itest-net
TARGET=airlock-itest-target
DAEMON=airlock-itest-daemon
NTFY=airlock-itest-ntfy
IMAGE=airlock-itest:latest
STATE_DIR="$HARNESS_DIR/.detect-state-$$"
CFG="$HARNESS_DIR/detect.itest.yml"

STATE_WAIT_SECONDS=8 # poll ceiling: comfortably past a state-write cycle (AIRLOCK_STATE_INTERVAL=1s below)

log() { printf '\n=== %s ===\n' "$1"; }

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    log "skipping cleanup (--keep); remove airlock-itest-* by hand when done"
    echo "state.json left at: $STATE_DIR/state.json"
    return
  fi
  log "cleanup"
  docker rm -f "$DAEMON" "$TARGET" "$NTFY" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR"
}
trap cleanup EXIT

# --- build -------------------------------------------------------------

log "building $IMAGE (parent-mounted context, see Dockerfile's own note)"
tar -cf - -C "$PARENT" core airlock | docker build -f airlock/Dockerfile -t "$IMAGE" -

# --- network + throwaway ntfy -------------------------------------------

log "creating $NET and $NTFY"
docker network create "$NET" >/dev/null
docker run -d --name "$NTFY" --network "$NET" binwiederhier/ntfy serve >/dev/null
sleep 2

# --- target container with a real policy declared entirely via labels ---

log "creating $TARGET (airlock.enable=true, airlock.allow=example.com:443)"
docker run -d --name "$TARGET" --network "$NET" \
  --label airlock.enable=true \
  --label airlock.allow=example.com:443 \
  nicolaka/netshoot sleep infinity >/dev/null
sleep 1

# --- daemon --------------------------------------------------------------

mkdir -p "$STATE_DIR"

log "starting $DAEMON (privileged, real docker socket, real ig)"
docker run -d --name "$DAEMON" \
  --privileged --pid=host \
  --network "$NET" \
  -e AIRLOCK_STATE_INTERVAL=1s \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /:/host:ro \
  -v "$CFG:/etc/airlock/airlock.yml:ro" \
  -v "$STATE_DIR:/run/airlock" \
  "$IMAGE" daemon >/dev/null

sleep 6
echo "--- daemon startup log ---"
docker logs "$DAEMON" 2>&1 | tail -20
if docker logs "$DAEMON" 2>&1 | grep -q "restarting"; then
  echo "FAIL: observe backend is restart-looping at startup -- ig never came up cleanly." >&2
  exit 1
fi

# --- drive real, known connections ---------------------------------------

log "connection 1/3: example.com (allowed by policy)"
docker exec "$TARGET" sh -c 'curl -s -o /dev/null -w "example.com -> %{http_code}\n" --max-time 5 https://example.com'

log "connection 2/3: 1.1.1.1 bare IP (no DNS, no SNI -- expect unresolved-ip)"
docker exec "$TARGET" sh -c 'curl -s -o /dev/null -w "1.1.1.1 -> %{http_code}\n" --max-time 5 -k https://1.1.1.1'

log "connection 3/3: www.wikipedia.org (has name evidence, not allow-listed -- expect no-match)"
docker exec "$TARGET" sh -c 'curl -s -o /dev/null -w "wikipedia -> %{http_code}\n" --max-time 5 https://www.wikipedia.org'

log "waiting for the daemon's verdicts to land in state.json"
echo "(polls state.json up to ${STATE_WAIT_SECONDS}s: verdicts are synchronous and final at connect" \
     "time, so this only needs to cover a state-write cycle, not any correlation window)"

# --- assertions ------------------------------------------------------------

python3 - "$STATE_DIR/state.json" "$STATE_WAIT_SECONDS" <<'PYEOF'
import json, sys, time

path, timeout_s = sys.argv[1], float(sys.argv[2])
deadline = time.monotonic() + timeout_s

last_snap = None
last_failures = None
while time.monotonic() < deadline:
    try:
        with open(path) as f:
            snap = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        time.sleep(0.5)
        continue
    last_snap = snap

    failures = []
    if not snap["backend"]["events_flowing"]:
        failures.append("backend.events_flowing is false -- airlock never saw a real event")

    target = next((c for c in snap["containers"] if c["name"] == "airlock-itest-target"), None)
    if target is None:
        failures.append("airlock-itest-target is not in state.json's armed containers at all")
    else:
        classes = target.get("violations_by_class", {})
        if classes.get("unresolved-ip", 0) != 1:
            failures.append(f"violations_by_class[unresolved-ip] = {classes.get('unresolved-ip', 0)}, want 1 (the 1.1.1.1 connection)")
        if classes.get("no-match", 0) != 1:
            failures.append(f"violations_by_class[no-match] = {classes.get('no-match', 0)}, want 1 (the wikipedia connection)")
        if classes.get("deny", 0) != 0:
            failures.append(f"violations_by_class[deny] = {classes.get('deny', 0)}, want 0 (no deny rule in this policy)")
        total = sum(classes.values())
        if total != 2:
            failures.append(f"total violations = {total}, want exactly 2 (example.com must produce none)")

    if not failures:
        print("PASS: events flowing, exactly one unresolved-ip and one no-match violation, example.com produced none.")
        sys.exit(0)
    last_failures = failures
    time.sleep(0.5)

print(f"FAIL (after {timeout_s}s):")
for f in last_failures or ["state.json was never written"]:
    print(f"  - {f}")
print()
if last_snap is not None:
    print(json.dumps(last_snap, indent=2))
sys.exit(1)
PYEOF

log "assertion: real ntfy delivery"
NTFY_BODY="$(docker exec "$TARGET" sh -c 'curl -s "http://airlock-itest-ntfy:80/airlock-itest/json?poll=1"')"
echo "$NTFY_BODY"
if ! echo "$NTFY_BODY" | grep -q '"topic":"airlock-itest"'; then
  echo "FAIL: no message found on the airlock-itest ntfy topic" >&2
  exit 1
fi
if ! echo "$NTFY_BODY" | grep -q 'unresolved-ip'; then
  echo "FAIL: ntfy message does not mention the unresolved-ip violation" >&2
  exit 1
fi
echo "PASS: a real violation notification was delivered to a real ntfy server."

log "ALL ASSERTIONS PASSED"
