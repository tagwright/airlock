#!/usr/bin/env bash
# Pass 3: proves the two remaining token-resolution paths and the alert
# flood breaker live against a real Docker socket and a real, privileged
# Inspektor Gadget (ig v0.55.1) -- everything pass 1 (run-detect.sh) and
# pass 2 (run-groups.sh) did NOT exercise:
#
#   - the @project token, resolved against REAL core data: TWO containers
#     sharing one com.docker.compose.project label, armed by a
#     compose_project-matched group with allow: "@project". This is the
#     first live exercise of internal/daemon/world.go's ProjectPeerIPs
#     index (built by walking every real container's real IPs grouped by
#     project) -- distinct code from @self's selfSubnets path, which pass
#     2 already proved live.
#   - the net:<name> token, resolved against REAL core data: a container
#     on one named network allowed to reach a second, entirely different
#     named network by name -- proves NamedNetwork resolution
#     (internal/engine/match.go's namedNetworkContains) walks core's real
#     ListNetworks inventory to find a network's subnet by name, not just
#     the connecting container's own attachments.
#   - the alert flood breaker (internal/alert/alert.go's countFlood/
#     sendFlood), driven by a REAL volume of live violations rather than
#     alert_test.go's synthetic time-injected counts: one default-deny
#     armed container firing at more distinct external destinations than
#     a (deliberately lowered) alert_flood cap, asserting the breaker
#     collapses the tail into a single "flooding" notification instead of
#     one alert per destination.
#
# Every Docker object this script creates (containers, networks, the
# built image) is named/tagged with the prefix "airlock-itest" and is torn
# down in a trap on exit (success, failure, or interrupt). It never
# touches any other container, network, volume, or image on the host, and
# never prunes ig's own gadget-image store.
#
# Usage: test/integration/run-pass3.sh [--keep]
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

PROJNET=airlock-itest-projnet
NETA=airlock-itest-neta
NETB=airlock-itest-netb
SVCNET=airlock-itest-svcnet
NTFY=airlock-itest-ntfy
DAEMON=airlock-itest-daemon3
PA=airlock-itest-pa
PB=airlock-itest-pb
NETAC=airlock-itest-neta-c
NETBT=airlock-itest-netb-t
FLOOD=airlock-itest-flood
IMAGE=airlock-itest:latest
STATE_DIR="$HARNESS_DIR/.pass3-state-$$"
CFG="$HARNESS_DIR/pass3.itest.yml"

STATE_WAIT_SECONDS=10

# 15 distinct, real, well-known public IPs (public DNS resolvers) used
# purely as distinct destination IDENTITIES for the flood test -- none of
# them need to actually serve HTTPS, since a bare TCP connect() is all
# trace_tcp needs to observe to attribute a Connection event; a refused
# or timed-out handshake past that point is irrelevant to what airlock
# measures. alert_flood is set to 5 in pass3.itest.yml, so the 6th
# distinct identity must trigger the flood collapse and identities 7-15
# must be absorbed silently.
FLOOD_IPS=(1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9 9.9.9.10 149.112.112.112 \
  208.67.222.222 208.67.220.220 64.6.64.6 64.6.65.6 77.88.8.8 84.200.69.80 \
  84.200.70.40 94.140.14.14)
FLOOD_CAP=5

log() { printf '\n=== %s ===\n' "$1"; }

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    log "skipping cleanup (--keep); remove airlock-itest-* by hand when done"
    echo "state.json left at: $STATE_DIR/state.json"
    return
  fi
  log "cleanup"
  docker rm -f "$DAEMON" "$PA" "$PB" "$NETAC" "$NETBT" "$FLOOD" "$NTFY" >/dev/null 2>&1 || true
  docker network rm "$PROJNET" "$NETA" "$NETB" "$SVCNET" >/dev/null 2>&1 || true
  docker rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -rf "$STATE_DIR"
}
trap cleanup EXIT

# --- build -------------------------------------------------------------

log "building $IMAGE (parent-mounted context, see Dockerfile's own note)"
tar -cf - -C "$PARENT" core airlock | docker build -f airlock/Dockerfile -t "$IMAGE" -

# --- networks + throwaway ntfy ------------------------------------------

log "creating $PROJNET, $NETA, $NETB (match targets) and $SVCNET (+ntfy)"
docker network create "$PROJNET" >/dev/null
docker network create "$NETA" >/dev/null
docker network create "$NETB" >/dev/null
docker network create "$SVCNET" >/dev/null
docker run -d --name "$NTFY" --network "$SVCNET" binwiederhier/ntfy serve >/dev/null
sleep 2

# --- targets -------------------------------------------------------------
#
# pa/pb: SAME com.docker.compose.project label, no other airlock.* labels
# at all. Armed entirely by pass3.itest.yml's compose_project-matched
# group ("itest-project"), the same "no per-container label" shape pass 2
# proved for network-matched groups -- this is the identity-dimension
# counterpart.
log "creating $PA and $PB, both com.docker.compose.project=airlock-itest-proj, on $PROJNET"
docker run -d --name "$PA" --network "$PROJNET" \
  --label com.docker.compose.project=airlock-itest-proj \
  nicolaka/netshoot sleep infinity >/dev/null
docker run -d --name "$PB" --network "$PROJNET" \
  --label com.docker.compose.project=airlock-itest-proj \
  nicolaka/netshoot sleep infinity >/dev/null

# neta-c: armed by pass3.itest.yml's network-matched group ("itest-neta"),
# allow: net:airlock-itest-netb. netb-t: no policy of its own, exists
# purely as a real, known IP on $NETB for net:<name> to resolve against --
# it does NOT sit on $NETA, proving net:<name> is resolved from core's
# network inventory by NAME, independent of the connecting container's
# own attachments (the thing @self already covers).
log "creating $NETAC on $NETA and $NETBT on $NETB (net:<name> targets)"
docker run -d --name "$NETAC" --network "$NETA" nicolaka/netshoot sleep infinity >/dev/null
docker run -d --name "$NETBT" --network "$NETB" nicolaka/netshoot sleep infinity >/dev/null

# flood: bare enable=true, no allow at all -- default-deny floor. Attached
# to $SVCNET for real internet egress (same NAT path any other bridge
# network on this host gets) and so it can also reach the throwaway ntfy
# server to poll results.
log "creating $FLOOD (bare enable=true, default-deny) on $SVCNET"
docker run -d --name "$FLOOD" --network "$SVCNET" \
  --label airlock.enable=true \
  nicolaka/netshoot sleep infinity >/dev/null

sleep 1

PB_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$PROJNET\").IPAddress}}" "$PB")"
NETBT_IP="$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NETB\").IPAddress}}" "$NETBT")"
if [ -z "$PB_IP" ]; then
  echo "FAIL: could not determine $PB's IP on $PROJNET" >&2
  exit 1
fi
if [ -z "$NETBT_IP" ]; then
  echo "FAIL: could not determine $NETBT's IP on $NETB" >&2
  exit 1
fi
echo "$PB's IP on $PROJNET: $PB_IP"
echo "$NETBT's IP on $NETB: $NETBT_IP"

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

log "pa -> pb ($PB_IP), same compose project -- @project must allow this, NO violation"
docker exec "$PA" sh -c "curl -s -o /dev/null -w 'pa->pb -> %{http_code}\n' --max-time 3 http://$PB_IP:80" || true

log "pa -> 1.1.1.1, external -- scope: all brings this into scope, @project does not cover it -- VIOLATION"
docker exec "$PA" sh -c 'curl -s -o /dev/null -w "pa->1.1.1.1 -> %{http_code}\n" --max-time 5 -k https://1.1.1.1' || true

log "neta-c -> netb-t ($NETBT_IP), on a DIFFERENT named network -- net:airlock-itest-netb must allow this, NO violation"
docker exec "$NETAC" sh -c "curl -s -o /dev/null -w 'neta-c->netb-t -> %{http_code}\n' --max-time 3 http://$NETBT_IP:80" || true

log "neta-c -> 1.1.1.1, external -- scope: all brings this into scope, net:airlock-itest-netb does not cover it -- VIOLATION"
docker exec "$NETAC" sh -c 'curl -s -o /dev/null -w "neta-c->1.1.1.1 -> %{http_code}\n" --max-time 5 -k https://1.1.1.1' || true

log "flood: ${#FLOOD_IPS[@]} distinct external destinations, fired in parallel (alert_flood cap = $FLOOD_CAP)"
for ip in "${FLOOD_IPS[@]}"; do
  docker exec "$FLOOD" sh -c "curl -s -o /dev/null --max-time 2 -k https://$ip" &
done
wait

log "waiting for the daemon's verdicts to land in state.json"

# --- assertions ------------------------------------------------------------

python3 - "$STATE_DIR/state.json" "$STATE_WAIT_SECONDS" "${#FLOOD_IPS[@]}" <<'PYEOF'
import json, sys, time

path, timeout_s, n_flood_ips = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
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

    # --- test 1: @project ---
    pa = get(snap, "airlock-itest-pa")
    pb = get(snap, "airlock-itest-pb")
    if pa is None:
        failures.append("airlock-itest-pa is not armed in state.json -- compose_project group matching failed")
    else:
        if "itest-project" not in pa.get("matched_groups", []):
            failures.append(f"pa's matched_groups = {pa.get('matched_groups')}, want to include 'itest-project'")
        classes = pa.get("violations_by_class", {})
        total = sum(classes.values())
        if total != 1:
            failures.append(f"pa's total violations = {total}, want exactly 1 (pa->pb over @project must produce ZERO violations)")
        if classes.get("unresolved-ip", 0) != 1:
            failures.append(f"pa's violations_by_class[unresolved-ip] = {classes.get('unresolved-ip', 0)}, want 1 (the pa->1.1.1.1 external connection)")
    if pb is None:
        failures.append("airlock-itest-pb is not armed in state.json -- compose_project group matching failed")

    # --- test 2: net:<name> ---
    netac = get(snap, "airlock-itest-neta-c")
    if netac is None:
        failures.append("airlock-itest-neta-c is not armed in state.json -- network group matching failed")
    else:
        if "itest-neta" not in netac.get("matched_groups", []):
            failures.append(f"neta-c's matched_groups = {netac.get('matched_groups')}, want to include 'itest-neta'")
        classes = netac.get("violations_by_class", {})
        total = sum(classes.values())
        if total != 1:
            failures.append(f"neta-c's total violations = {total}, want exactly 1 (neta-c->netb-t over net:<name> must produce ZERO violations)")
        if classes.get("unresolved-ip", 0) != 1:
            failures.append(f"neta-c's violations_by_class[unresolved-ip] = {classes.get('unresolved-ip', 0)}, want 1 (the neta-c->1.1.1.1 external connection)")

    # --- test 3: flood breaker tally (alert delivery asserted separately via ntfy) ---
    flood = get(snap, "airlock-itest-flood")
    if flood is None:
        failures.append("airlock-itest-flood is not armed in state.json at all")
    else:
        classes = flood.get("violations_by_class", {})
        total = sum(classes.values())
        if total != n_flood_ips:
            failures.append(f"flood's total violations = {total}, want {n_flood_ips} (every distinct destination is tallied regardless of the flood breaker collapsing alerts)")

    if not failures:
        print("PASS: @project and net:<name> resolved correctly against real Docker data; flood target's every distinct destination was tallied.")
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

log "assertion: real ntfy delivery -- @project and net:<name> violations alerted"
NTFY_BODY="$(docker exec "$FLOOD" sh -c 'curl -s "http://airlock-itest-ntfy:80/airlock-itest-p3/json?poll=1"')"
echo "$NTFY_BODY"

if ! echo "$NTFY_BODY" | grep -q "airlock-itest-pa"; then
  echo "FAIL: no alert delivered for pa's @project-scoped unresolved-ip violation" >&2
  exit 1
fi
if ! echo "$NTFY_BODY" | grep -q "airlock-itest-neta-c"; then
  echo "FAIL: no alert delivered for neta-c's net:<name>-scoped unresolved-ip violation" >&2
  exit 1
fi

log "assertion: flood breaker collapsed ${#FLOOD_IPS[@]} distinct destinations (cap $FLOOD_CAP) into $FLOOD_CAP individual alerts + 1 flood alert, not ${#FLOOD_IPS[@]} separate alerts"
FLOOD_MSG_COUNT="$(echo "$NTFY_BODY" | python3 -c '
import json, sys
n = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    if obj.get("event") != "message":
        continue
    if "airlock-itest-flood" in (obj.get("title", "") + obj.get("message", "")):
        n += 1
print(n)
')"
FLOODING_MSG_COUNT="$(echo "$NTFY_BODY" | python3 -c '
import json, sys
n = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        continue
    if obj.get("event") != "message":
        continue
    if "flooding" in obj.get("title", ""):
        n += 1
print(n)
')"

echo "flood-labeled messages: $FLOOD_MSG_COUNT (want exactly $((FLOOD_CAP + 1)): $FLOOD_CAP individual pre-cap alerts + 1 collapse alert)"
echo "'flooding' collapse messages: $FLOODING_MSG_COUNT (want exactly 1)"

if [ "$FLOODING_MSG_COUNT" -ne 1 ]; then
  echo "FAIL: expected exactly 1 'flooding' collapse alert, got $FLOODING_MSG_COUNT" >&2
  exit 1
fi
if [ "$FLOOD_MSG_COUNT" -ne "$((FLOOD_CAP + 1))" ]; then
  echo "FAIL: expected exactly $((FLOOD_CAP + 1)) total alerts for the flood target ($FLOOD_CAP individual + 1 collapse), got $FLOOD_MSG_COUNT -- the breaker did not collapse the tail as designed" >&2
  exit 1
fi

echo "PASS: flood breaker collapsed ${#FLOOD_IPS[@]} distinct violation identities into $FLOOD_CAP individual alerts + exactly 1 'flooding' alert, not ${#FLOOD_IPS[@]} separate alerts."

log "ALL ASSERTIONS PASSED"
