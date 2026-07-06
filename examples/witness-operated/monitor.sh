#!/bin/sh
# Monitor loop: re-verify every externally published head against the live log, using only
# the store and the PUBLIC key. Exit semantics are the alert hook:
#   status ok            -> keep looping (coverage may lag; that is a warn, not an alarm)
#   tamper / rollback    -> exit 1  (history rewritten or truncated below a witnessed count)
#   cannot_verify        -> exit 2  (check could not run — investigate)
#   failed               -> retry   (setup/transient: store unreachable, no heads yet)
# The machine-readable verdict is the JSON `status` field (docs/witness.md).
set -u

published_heads="${PUBLISHED_HEADS:-/published/heads.jsonl}"
published_grants="${PUBLISHED_GRANTS:-/published/grant-heads.jsonl}"

verify_published() {
  if [ -f "$published_grants" ]; then
    dent8 --output json witness verify-published "$published_heads" --grants "$published_grants"
  else
    dent8 --output json witness verify-published "$published_heads"
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
      *'"status": "tamper"'* | *'"status": "rollback"'*)
        echo "monitor: ALARM"
        echo "$out"
        exit 1
        ;;
      *'"status": "cannot_verify"'*)
        echo "monitor: check could not run"
        echo "$out"
        exit 2
        ;;
      *)
        echo "monitor: transient failure (will retry): $out"
        ;;
    esac
  fi
  sleep "${MONITOR_INTERVAL_SECONDS:-15}"
done
