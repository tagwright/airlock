#!/usr/bin/env bash
# Pass 2: proves airlock's DISTINCTIVE features live against a real Docker
# socket and a real, privileged Inspektor Gadget (ig v0.55.1) -- everything
# run-detect.sh's pass-1 pipeline does NOT exercise:
#
#   - a real DENY rule beating an allow: "*" denylist posture end to end.
#   - a Fork 8 GROUP arming two containers with NO airlock.* label at all,
#     matched purely by which Docker network they are attached to.
#   - the @self token resolving against REAL core network data (core's
#     ListNetworks subnets + Container.Networks IPs), under scope: all,
#     to permit a container-to-container connection on the group's own
#     network while an external connection from the SAME container still
#     violates. This is the first live exercise of core's network
#     introspection extension (f6cd8da): every other proof of @self/scope
#     before this pass was unit-tested against fake World data only.
#   - AUDIT mode: a violation is tallied into state.json but never
#     delivered as an immediate alert.
#
# Every Docker object this script creates (containers, networks, the built
# image) is named/tagged with the prefix "airlock-itest" and is torn down
# in a trap on exit (success, failure, or interrupt). It never touches any
# other container, network, volume, or image on the host, and never prunes
# ig's own gadget-image store.
#
# Usage: test/integration/run-groups.sh [--keep]
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

GROUPNET=airlock-itest-groupnet
SVCNET=airlock-itest-svcnet
NTFY=airlock-itest-ntfy
DAEMON=airlock-itest-daemon2
DENYTARGET=airlock-itest-denytarget
AUDITTARGET=airlock-itest-audittarget
A=airlock-itest-a
B=airlock-itest-b
IMAGE=airlock-itest:latest
STATE_DIR="$HARNESS_DIR/.groups-state-$$"
CFG="$HARNESS_DIR/groups.itest.yml"

STATE_WAIT_SECONDS=8

log() { printf '\n=== %s ===\n' "$1"; }

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    log "skipping cleanup (--keep); remove airlock-itest-* by hand when done"
    echo "state.json left at: $STATE_DIR/state.json"
    return
  fi
  log "cleanup"
  docker rm -f "$DAEMON" "$DENYTARGET" "$AUDITTARGET" "$A" "$B" "$NTFY" >/dev/null 2>&1 || true
  docker network rm "$GROUPNET" "$SVCNET" >/dev/null 2>&1 || true
  docker rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR"
}
trap cleanup EXIT

# --- build -------------------------------------------------------------

log "building $IMAGE (parent-mounted context, see Dockerfile's own note)"
tar -cf - -C "$PARENT" core airlock | docker build -f airlock/Dockerfile -t "$IMAGE" -

# --- networks + throwaway ntfy ------------------------------------------

log "creating $GROUPNET (the group's match target) and $SVCNET (+ntfy)"
docker network create "$GROUPNET" >/dev/null
docker network create "$SVCNET" >/dev/null
docker run -d --name "$NTFY" --network "$SVCNET" binwiederhier/ntfy serve >/dev/null
sleep 2

# --- targets -------------------------------------------------------------
#
# denytarget: allow: "*" (denylist posture) + a deny rule naming a specific
# IP:port. Deny-by-IP is used deliberately (not a domain) since a domain
# deny requires the destination IP to already be in this container's own
# DNS cache under that name, and 1.1.1.1 needs no DNS lookup at all -- the
# most reliable way to drive a deny match against fail-closed name
# matching.
log "creating $DENYTARGET (allow: *, deny: 1.1.1.1:443)"
docker run -d --name "$DENYTARGET" --network "$SVCNET" \
  --label airlock.enable=true \
  --label 'airlock.allow=*' \
  --label airlock.deny=1.1.1.1:443 \
  nicolaka/netshoot sleep infinity >/dev/null

# audittarget: mode=audit + a policy it will violate. Audit mode evaluates
# identically to alert mode but must never alert immediately -- only tally.
log "creating $AUDITTARGET (mode=audit, allow: example.com:443 only)"
docker run -d --name "$AUDITTARGET" --network "$SVCNET" \
  --label airlock.enable=true \
  --label airlock.mode=audit \
  --label airlock.allow=example.com:443 \
  nicolaka/netshoot sleep infinity >/dev/null

# a and b: NO airlock.* labels at all. Armed entirely by the network-matched
# group in groups.itest.yml (see that file's comment).
log "creating $A and $B on $GROUPNET with NO airlock.* labels (group-armed)"
docker run -d --name "$A" --network "$GROUPNET" nicolaka/netshoot sleep infinity >/dev/null
docker run -d --name "$B" --network "$GROUPNET" nicolaka/netshoot sleep infinity >/dev/null
sleep 1

B_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$GROUPNET\").IPAddress}}" "$B")"
if [ -z "$B_IP" ]; then
  echo "FAIL: could not determine $B's IP on $GROUPNET" >&2
  exit 1
fi
echo "$B's IP on $GROUPNET: $B_IP"

# --- daemon --------------------------------------------------------------

mkdir -p "$STATE_DIR"

log "starting $DAEMON (privileged, real docker socket, real ig)"
docker run -d --name "$DAEMON" \
  --privileged --pid=host \
  --network "$SVCNET" \
  -e AIRLOCK_STATE_INTERVAL=1s \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /:/host:ro \
  -v "$CFG:/etc/airlock/airlock.yml:ro" \
  -v "$STATE_DIR:/run/airlock" \
  "$IMAGE" daemon >/dev/null

sleep 6
echo "--- daemon startup log ---"
docker logs "$DAEMON" 2>&1 | tail -30
if docker logs "$DAEMON" 2>&1 | grep -q "restarting"; then
  echo "FAIL: observe backend is restart-looping at startup -- ig never came up cleanly." >&2
  exit 1
fi

# --- drive real, known connections ---------------------------------------

log "denytarget 1/2: 1.1.1.1:443 (explicit deny -- must beat allow: *)"
docker exec "$DENYTARGET" sh -c 'curl -s -o /dev/null -w "1.1.1.1 -> %{http_code}\n" --max-time 5 -k https://1.1.1.1' || true

log "denytarget 2/2: example.com (falls through to allow: * -- must be allowed)"
docker exec "$DENYTARGET" sh -c 'curl -s -o /dev/null -w "example.com -> %{http_code}\n" --max-time 5 https://example.com' || true

log "audittarget: www.wikipedia.org (not allow-listed -- violates, but mode=audit must not alert immediately)"
docker exec "$AUDITTARGET" sh -c 'curl -s -o /dev/null -w "wikipedia -> %{http_code}\n" --max-time 5 https://www.wikipedia.org' || true

log "a -> b ($B_IP), same group network -- @self must allow this, NO violation"
docker exec "$A" sh -c "curl -s -o /dev/null -w 'a->b -> %{http_code}\n' --max-time 3 http://$B_IP:80" || true

log "a -> 1.1.1.1, external -- scope: all brings this into scope, @self does not cover it -- VIOLATION"
docker exec "$A" sh -c 'curl -s -o /dev/null -w "a->1.1.1.1 -> %{http_code}\n" --max-time 5 -k https://1.1.1.1' || true

log "waiting for the daemon's verdicts to land in state.json"

# --- assertions ------------------------------------------------------------

python3 - "$STATE_DIR/state.json" "$STATE_WAIT_SECONDS" <<'PYEOF'
import json, sys, time

path, timeout_s = sys.argv[1], float(sys.argv[2])
deadline = time.monotonic() + timeout_s

def get(snap, name):
    return next((c for c in snap["containers"] if c["name"] == name), None)

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

    # --- test 2: deny beats allow ---
    deny = get(snap, "airlock-itest-denytarget")
    if deny is None:
        failures.append("airlock-itest-denytarget is not armed in state.json at all")
    else:
        classes = deny.get("violations_by_class", {})
        if classes.get("deny", 0) != 1:
            failures.append(f"denytarget violations_by_class[deny] = {classes.get('deny', 0)}, want 1 (the 1.1.1.1 connection)")
        total = sum(classes.values())
        if total != 1:
            failures.append(f"denytarget total violations = {total}, want exactly 1 (example.com must fall through to allow: * with no violation)")

    # --- test 5: audit mode tallies but the daemon must not have crashed ---
    audit = get(snap, "airlock-itest-audittarget")
    if audit is None:
        failures.append("airlock-itest-audittarget is not armed in state.json at all")
    else:
        classes = audit.get("violations_by_class", {})
        if classes.get("no-match", 0) != 1:
            failures.append(f"audittarget violations_by_class[no-match] = {classes.get('no-match', 0)}, want 1 (tallied even though mode=audit suppresses the immediate alert)")

    # --- test 3: group arming with no per-container label ---
    a = get(snap, "airlock-itest-a")
    b = get(snap, "airlock-itest-b")
    if a is None:
        failures.append("airlock-itest-a (no airlock.* labels) is not armed in state.json -- group matching by network failed")
    elif "itest-groupnet" not in a.get("matched_groups", []):
        failures.append(f"airlock-itest-a's matched_groups = {a.get('matched_groups')}, want to include 'itest-groupnet'")
    elif a.get("scope") != "all":
        failures.append(f"airlock-itest-a's resolved scope = {a.get('scope')!r}, want 'all' (from the group)")
    if b is None:
        failures.append("airlock-itest-b (no airlock.* labels) is not armed in state.json -- group matching by network failed")
    elif "itest-groupnet" not in b.get("matched_groups", []):
        failures.append(f"airlock-itest-b's matched_groups = {b.get('matched_groups')}, want to include 'itest-groupnet'")

    # --- test 4: @self + scope=all against REAL core network data ---
    if a is not None:
        aclasses = a.get("violations_by_class", {})
        if aclasses.get("unresolved-ip", 0) != 1:
            failures.append(f"a's violations_by_class[unresolved-ip] = {aclasses.get('unresolved-ip', 0)}, want 1 (the a->1.1.1.1 external connection)")
        atotal = sum(aclasses.values())
        if atotal != 1:
            failures.append(f"a's total violations = {atotal}, want exactly 1 (a->b over @self must produce ZERO violations)")

    if not failures:
        print("PASS: deny beats allow, group arming with no labels works, @self+scope=all resolved correctly against real Docker network data, audit mode tallied without alerting.")
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

log "assertion: real ntfy delivery -- deny and a's unresolved-ip alert fired, audit did NOT"
NTFY_BODY="$(docker exec "$DENYTARGET" sh -c 'curl -s "http://airlock-itest-ntfy:80/airlock-itest-p2/json?poll=1"')"
echo "$NTFY_BODY"

if ! echo "$NTFY_BODY" | grep -q "airlock-itest-denytarget"; then
  echo "FAIL: no alert delivered for denytarget's deny violation" >&2
  exit 1
fi
if ! echo "$NTFY_BODY" | grep -q 'deny)'; then
  echo "FAIL: denytarget's alert does not read as a deny-class violation" >&2
  exit 1
fi
if ! echo "$NTFY_BODY" | grep -q "airlock-itest-a "; then
  echo "FAIL: no alert delivered for a's unresolved-ip violation (a->1.1.1.1)" >&2
  exit 1
fi
if echo "$NTFY_BODY" | grep -q "airlock-itest-audittarget"; then
  echo "FAIL: audittarget's mode=audit violation was delivered as an immediate alert -- audit mode must suppress this" >&2
  exit 1
fi
echo "PASS: deny and @self/scope=all violations alerted for real; audit-mode violation did not."

log "ALL ASSERTIONS PASSED"
