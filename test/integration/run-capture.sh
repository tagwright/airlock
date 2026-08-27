#!/usr/bin/env bash
# Captures REAL Inspektor Gadget (ig v0.55.1) NDJSON for trace_tcp,
# trace_dns, and trace_sni against a throwaway target container making
# known outbound connections, and reports what each event's real field
# names/shapes actually are -- so a human (or a future integration pass)
# can re-verify internal/observe/ig/parse.go's expectations against
# reality without re-deriving the whole setup by hand.
#
# This does NOT build or run the airlock binary at all: it drives the
# upstream ghcr.io/inspektor-gadget/ig image directly, exactly the
# invocation shape docs/TESTING.md's "Environment probe" section
# describes. See run-detect.sh for the full daemon-in-the-loop proof.
#
# Every Docker object this script creates is named with the prefix
# "airlock-itest-" and is torn down in a trap on exit (success, failure,
# or interrupt). It never touches any other container, network, volume,
# or image, and it never prunes or removes the shared
# ghcr.io/inspektor-gadget/ig image or ig's own internal gadget-image
# store -- those are left as reusable cache, per the suite's house rule
# for this exact class of tool.
#
# Usage: test/integration/run-capture.sh [--keep]
#   --keep  skip cleanup at the end (for inspecting the captured NDJSON)

set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

KEEP=0
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

NET=airlock-itest-net
TARGET=airlock-itest-target
IG_IMAGE=ghcr.io/inspektor-gadget/ig:v0.55.1
CAPTURE_DIR="$HARNESS_DIR/.capture-$(date +%s)"

log() { printf '\n=== %s ===\n' "$1"; }

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    log "skipping cleanup (--keep); remove airlock-itest-* by hand when done"
    echo "captured NDJSON left at: $CAPTURE_DIR"
    return
  fi
  log "cleanup"
  docker rm -f "$TARGET" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

log "environment probe: can privileged ig run here at all"
if ! docker run --rm --privileged -v /:/host --pid=host "$IG_IMAGE" version; then
  echo "privileged ig did NOT run -- see docs/TESTING.md's offline fallback." >&2
  exit 1
fi

log "creating $NET and $TARGET"
docker network create "$NET" >/dev/null
docker run -d --name "$TARGET" --network "$NET" nicolaka/netshoot sleep infinity >/dev/null
sleep 1

mkdir -p "$CAPTURE_DIR"

log "starting real ig captures (trace_tcp, trace_dns, trace_sni), scoped to $TARGET"
for gadget in trace_tcp trace_dns trace_sni; do
  docker run --rm --privileged -v /:/host -v /var/run/docker.sock:/var/run/docker.sock --pid=host \
    "$IG_IMAGE" run "ghcr.io/inspektor-gadget/gadget/${gadget}:latest" -o json --containername "$TARGET" \
    > "$CAPTURE_DIR/${gadget}.ndjson" 2> "$CAPTURE_DIR/${gadget}.stderr" &
  eval "${gadget}_PID=\$!"
done

sleep 5

log "making known connections from $TARGET"
docker exec "$TARGET" sh -c 'curl -s -o /dev/null -w "example.com -> %{http_code}\n" --max-time 5 https://example.com' || true
docker exec "$TARGET" sh -c 'curl -s -o /dev/null -w "1.1.1.1 (bare IP, no DNS) -> %{http_code}\n" --max-time 5 -k https://1.1.1.1' || true
docker exec "$TARGET" sh -c 'curl -s -o /dev/null -w "www.wikipedia.org -> %{http_code}\n" --max-time 5 https://www.wikipedia.org' || true

sleep 4

log "stopping captures"
kill "$trace_tcp_PID" "$trace_dns_PID" "$trace_sni_PID" 2>/dev/null || true
wait "$trace_tcp_PID" "$trace_dns_PID" "$trace_sni_PID" 2>/dev/null || true

log "summary"
for gadget in trace_tcp trace_dns trace_sni; do
  f="$CAPTURE_DIR/${gadget}.ndjson"
  n=$(wc -l < "$f" | tr -d ' ')
  echo "$gadget: $n line(s) captured -> $f"
done

echo
echo "Compare these real lines against internal/observe/ig/parse.go's"
echo "expected field names/shapes. docs/TESTING.md records the last"
echo "comparison done this way and every divergence found."
