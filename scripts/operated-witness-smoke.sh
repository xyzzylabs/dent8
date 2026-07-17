#!/usr/bin/env bash
# Smoke the *running* operated-witness stack:
#   1. writer assert (postgres-capable binary)
#   2. wait until published coverage includes the new head
#   3. confirm no ALARM
#
# Requires: scripts/operated-witness-up.sh already ran.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$ROOT/examples/witness-operated"
PROJECT="${COMPOSE_PROJECT_NAME:-dent8-ops}"
WRITER_ENV="${DENT8_OPERATED_WRITER_ENV:-$ROOT/.dent8/operated-witness.env}"
PUBLISHED_DIR="${DENT8_WITNESS_PUBLISHED_DIR:-$COMPOSE_DIR/published}"
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_DIR/compose.yml")

if [ -n "${DENT8_BIN:-}" ]; then
  BIN="$DENT8_BIN"
elif [ -x "$ROOT/target/debug/dent8" ]; then
  BIN="$ROOT/target/debug/dent8"
else
  echo "smoke: building dent8-cli with postgres feature..."
  cargo build -q -p dent8-cli --features postgres,sqlite
  BIN="$ROOT/target/debug/dent8"
fi

[ -f "$WRITER_ENV" ] || {
  echo "missing $WRITER_ENV — run scripts/operated-witness-up.sh first" >&2
  exit 1
}

# shellcheck source=/dev/null
set -a
. "$WRITER_ENV"
set +a

# Local authority for the smoke writer (file path must not pre-exist as empty).
AUTH_DIR="$(mktemp -d -t dent8-ops-auth.XXXXXX)"
AUTH="$AUTH_DIR/authority.json"
export DENT8_AUTHORITY="$AUTH"
export DENT8_REQUIRE_AUTHORITY=1
# shellcheck disable=SC2064
trap 'rm -rf "$AUTH_DIR"' EXIT

# Agent-tier write (no signed identity required); ceiling grant is enough for the smoke.
"$BIN" authority add source:owner low >/dev/null
"$BIN" witness doctor writer

pre_count=0
if out=$("${COMPOSE[@]}" exec -T monitor sh -c \
    'dent8 --output json witness verify-published "$PUBLISHED_HEADS"' 2>/dev/null); then
  pre_count="$(printf '%s' "$out" | python3 -c 'import sys,json; print(int(json.load(sys.stdin).get("latest_published_count") or 0))' 2>/dev/null || echo 0)"
fi

echo "smoke: writing event through writer env (no private key)"
"$BIN" assert repo:ops smoke "ok-$(date -u +%Y%m%dT%H%M%SZ)" \
  --authority low --source source:owner

echo "smoke: waiting for published coverage beyond count $pre_count..."
deadline=$((SECONDS + 120))
while [ "$SECONDS" -lt "$deadline" ]; do
  if out=$("${COMPOSE[@]}" exec -T monitor sh -c \
      'dent8 --output json witness verify-published "$PUBLISHED_HEADS"' 2>/dev/null); then
    if printf '%s' "$out" | PRE="$pre_count" python3 -c "
import sys, json, os
doc = json.load(sys.stdin)
cur = int(doc.get('current_event_count') or 0)
pub = int(doc.get('latest_published_count') or 0)
pre = int(os.environ.get('PRE') or 0)
cov = doc.get('coverage')
ok = cur >= 1 and pub >= 1 and pub >= pre and cov in ('complete', 'trailing')
sys.exit(0 if ok else 1)
"; then
      echo "$out"
      if [ -f "$PUBLISHED_DIR/ALERT.jsonl" ]; then
        echo "smoke: FAIL unexpected ALERT.jsonl" >&2
        cat "$PUBLISHED_DIR/ALERT.jsonl" >&2
        exit 1
      fi
      echo "smoke: PASS (published coverage ok, no alert)"
      exit 0
    fi
  fi
  sleep 2
done
echo "smoke: timed out waiting for published coverage" >&2
"${COMPOSE[@]}" logs --no-color --tail=40 signer publisher monitor >&2 || true
exit 1
