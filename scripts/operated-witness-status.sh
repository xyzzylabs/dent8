#!/usr/bin/env bash
# Status of the operated-witness compose project + published-head coverage / alerts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$ROOT/examples/witness-operated"
PROJECT="${COMPOSE_PROJECT_NAME:-dent8-ops}"
PUBLISHED_DIR="${DENT8_WITNESS_PUBLISHED_DIR:-$COMPOSE_DIR/published}"
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_DIR/compose.yml")

echo "=== compose ps -a ($PROJECT) ==="
"${COMPOSE[@]}" ps -a || true
echo

echo "=== published channel ($PUBLISHED_DIR) ==="
if [ -d "$PUBLISHED_DIR" ]; then
  ls -la "$PUBLISHED_DIR" || true
  if [ -f "$PUBLISHED_DIR/ALERT.jsonl" ]; then
    echo
    echo "=== ALERTS (last 5) ==="
    tail -n 5 "$PUBLISHED_DIR/ALERT.jsonl" || true
  else
    echo "(no ALERT.jsonl — good if monitor is still running)"
  fi
else
  echo "published dir missing (stack not up?)"
fi
echo

echo "=== verify-published (via monitor container if up) ==="
monitor_id="$("${COMPOSE[@]}" ps -aq monitor 2>/dev/null || true)"
if [ -n "$monitor_id" ]; then
  state="$(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}}' "$monitor_id" 2>/dev/null || true)"
  echo "monitor state: $state"
  if echo "$state" | grep -q '^running'; then
    "${COMPOSE[@]}" exec -T monitor sh -c \
      'dent8 --output json witness verify-published "$PUBLISHED_HEADS"' \
      || true
  elif echo "$state" | grep -q 'exit=1'; then
    echo "monitor ALARMED (exit 1) — check logs and ALERT.jsonl"
    "${COMPOSE[@]}" logs --no-color --tail=40 monitor || true
    exit 1
  elif echo "$state" | grep -q 'exited'; then
    echo "monitor exited: $state"
    "${COMPOSE[@]}" logs --no-color --tail=20 monitor || true
  fi
else
  echo "monitor container not found"
fi
echo
echo "=== recent monitor logs ==="
"${COMPOSE[@]}" logs --no-color --tail=15 monitor 2>/dev/null || true
