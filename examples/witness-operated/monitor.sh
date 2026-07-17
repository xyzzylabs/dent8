#!/bin/sh
# Monitor loop: re-verify every externally published head against the live log, using only
# the store and the PUBLIC key. Exit semantics are the alert hook:
#   status ok            -> keep looping (coverage may lag; that is a warn, not an alarm)
#   tamper / rollback    -> exit 1  (history rewritten or truncated below a witnessed count)
#   cannot_verify        -> exit 2  (check could not run — investigate)
#   failed               -> retry   (setup/transient: store unreachable, no heads yet)
#
# On tamper/rollback/cannot_verify the monitor writes ALERT.jsonl under the published channel
# (host-visible when that volume is bind-mounted) and optionally POSTs DENT8_WITNESS_ALERT_WEBHOOK.
set -u

published_heads="${PUBLISHED_HEADS:-/published/heads.jsonl}"
published_grants="${PUBLISHED_GRANTS:-/published/grant-heads.jsonl}"
alert_file="${DENT8_WITNESS_ALERT_FILE:-/published/ALERT.jsonl}"
webhook="${DENT8_WITNESS_ALERT_WEBHOOK:-}"

verify_published() {
  if [ -f "$published_grants" ]; then
    dent8 --output json witness verify-published "$published_heads" --grants "$published_grants"
  else
    dent8 --output json witness verify-published "$published_heads"
  fi
}

# Write one NDJSON alert line. Prefer jq when present; otherwise a minimal escaped line.
emit_alert() {
  status="$1"
  body="$2"
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date)"
  mkdir -p "$(dirname "$alert_file")" 2>/dev/null || true
  if command -v jq >/dev/null 2>&1; then
    printf '%s\n' "$body" | jq -c -n \
      --arg ts "$ts" \
      --arg status "$status" \
      --arg component "dent8-witness-monitor" \
      --rawfile detail /dev/stdin \
      '{ts:$ts,status:$status,component:$component,detail:$detail}' \
      >>"$alert_file" 2>/dev/null || printf '%s status=%s\n' "$ts" "$status" >>"$alert_file"
  else
    # Minimal one-line record without full body (avoid fragile shell JSON).
    printf '{"ts":"%s","status":"%s","component":"dent8-witness-monitor"}\n' "$ts" "$status" \
      >>"$alert_file"
    # Also drop the full JSON verdict next to the alert for operators.
    printf '%s\n' "$body" >"${alert_file%.jsonl}.last.json" 2>/dev/null || true
  fi
  echo "monitor: ALERT written to $alert_file ($status)"

  if [ -n "$webhook" ] && command -v curl >/dev/null 2>&1; then
    if command -v jq >/dev/null 2>&1; then
      payload=$(printf '%s\n' "$body" | jq -c -n \
        --arg status "$status" \
        --arg text "dent8 witness ALARM: $status" \
        --rawfile body /dev/stdin \
        '{text:$text,status:$status,body:$body}')
    else
      payload="{\"text\":\"dent8 witness ALARM: $status\",\"status\":\"$status\"}"
    fi
    if curl -fsS -X POST -H 'Content-Type: application/json' -d "$payload" "$webhook" >/dev/null 2>&1; then
      echo "monitor: webhook notified"
    else
      echo "monitor: webhook notify failed (alarm still raised)"
    fi
  fi
}

until verify_published 2>&1 | grep -q '"status"'; do
  echo "monitor: waiting for the first published head"
  sleep "${MONITOR_INTERVAL_SECONDS:-15}"
done

while true; do
  out=$(verify_published 2>&1)
  code=$?
  if [ "$code" -eq 0 ]; then
    echo "$out"
  else
    case "$out" in
      *'"status": "tamper"'*)
        echo "monitor: ALARM"
        echo "$out"
        emit_alert "tamper" "$out"
        exit 1
        ;;
      *'"status": "rollback"'*)
        echo "monitor: ALARM"
        echo "$out"
        emit_alert "rollback" "$out"
        exit 1
        ;;
      *'"status": "cannot_verify"'*)
        echo "monitor: check could not run"
        echo "$out"
        emit_alert "cannot_verify" "$out"
        exit 2
        ;;
      *)
        echo "monitor: transient failure (will retry): $out"
        ;;
    esac
  fi
  sleep "${MONITOR_INTERVAL_SECONDS:-15}"
done
