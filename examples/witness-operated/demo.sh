#!/usr/bin/env bash
# Live operated-witness E2E:
#   1. start the packaged signer / publisher / monitor split over Postgres;
#   2. write one event through the demo writer;
#   3. wait until the head is signed, published, and monitor-verifiable;
#   4. delete the event log and prove the monitor exits on ROLLBACK.
#
# From the repository root:
#   ./examples/witness-operated/demo.sh
#
# Optional:
#   DENT8_WITNESS_BUILD=0   # skip build; requires images for COMPOSE_PROJECT_NAME
#   DENT8_WITNESS_KEEP=1    # leave containers/volumes behind for inspection
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/compose.yml"
PROJECT="${COMPOSE_PROJECT_NAME:-dent8witnessdemo$RANDOM$$}"
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
VERIFY_OUT="$(mktemp -t dent8-operated-witness-verify.XXXXXX)"

export DENT8_WITNESS_DB_PORT="${DENT8_WITNESS_DB_PORT:-55432}"
export SIGN_INTERVAL_SECONDS="${SIGN_INTERVAL_SECONDS:-1}"
export PUBLISH_INTERVAL_SECONDS="${PUBLISH_INTERVAL_SECONDS:-1}"
export MONITOR_INTERVAL_SECONDS="${MONITOR_INTERVAL_SECONDS:-1}"

cleanup() {
  rm -f "$VERIFY_OUT"
  if [ "${DENT8_WITNESS_KEEP:-0}" = "1" ]; then
    echo "# keeping compose project $PROJECT for inspection"
  else
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

fail() {
  echo "demo: $*" >&2
  echo >&2
  "${COMPOSE[@]}" ps >&2 || true
  echo >&2
  "${COMPOSE[@]}" logs --no-color --tail=120 signer publisher monitor db >&2 || true
  exit 1
}

verify_from_monitor() {
  # shellcheck disable=SC2016 # Expand PUBLISHED_* inside the monitor container.
  "${COMPOSE[@]}" exec -T monitor sh -c '
    if [ -f "$PUBLISHED_GRANTS" ]; then
      dent8 --output json witness verify-published "$PUBLISHED_HEADS" --grants "$PUBLISHED_GRANTS"
    else
      dent8 --output json witness verify-published "$PUBLISHED_HEADS"
    fi
  ' >"$VERIFY_OUT" 2>&1
}

wait_for_published_head() {
  local deadline=$((SECONDS + 90))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if verify_from_monitor \
      && grep -Eq '"latest_published_count"[[:space:]]*:[[:space:]]*1' "$VERIFY_OUT" \
      && grep -Eq '"coverage"[[:space:]]*:[[:space:]]*"complete"' "$VERIFY_OUT"; then
      cat "$VERIFY_OUT"
      return
    fi
    sleep 1
  done
  cat "$VERIFY_OUT" >&2 || true
  fail "timed out waiting for a complete published head at count 1"
}

wait_for_monitor_alarm() {
  local monitor_id state logs
  monitor_id="$("${COMPOSE[@]}" ps -q monitor)"
  [ -n "$monitor_id" ] || fail "monitor container is missing"

  local deadline=$((SECONDS + 90))
  while [ "$SECONDS" -lt "$deadline" ]; do
    state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$monitor_id")"
    case "$state" in
      "exited 1")
        logs="$("${COMPOSE[@]}" logs --no-color monitor)"
        echo "$logs"
        echo "$logs" | grep -q "monitor: ALARM" || fail "monitor exited 1 without ALARM log"
        echo "$logs" | grep -q "ROLLBACK" || fail "monitor exited 1 without ROLLBACK log"
        return
        ;;
      exited\ *)
        fail "monitor exited unexpectedly: $state"
        ;;
    esac
    sleep 1
  done
  fail "timed out waiting for monitor rollback alarm"
}

docker compose version >/dev/null

up_args=(up -d)
if [ "${DENT8_WITNESS_BUILD:-1}" != "0" ]; then
  up_args+=(--build)
fi
up_args+=(db signer publisher monitor)

echo "# 1. Start operated witness split (project=$PROJECT, db port=$DENT8_WITNESS_DB_PORT)"
"${COMPOSE[@]}" "${up_args[@]}"

echo
echo "# 2. Write one trusted event through the demo writer"
"${COMPOSE[@]}" --profile demo run --rm demo-writer

echo
echo "# 3. Wait for signer -> publisher -> monitor coverage"
wait_for_published_head

echo
echo "# 4. Simulate a writer-side rollback of the event log"
"${COMPOSE[@]}" exec -T db \
  psql -U postgres -d dent8 -v ON_ERROR_STOP=1 \
  -c "DELETE FROM dent8_event_log;" >/dev/null

echo
echo "# 5. Monitor should alarm and exit non-zero"
wait_for_monitor_alarm

echo
echo "OK: operated witness compose demo detected rollback"
