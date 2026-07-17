#!/usr/bin/env bash
# Production-integrity gate for dent8.
#
# Runs the integrity claims that can be checked without a live multi-user deployment:
#   1. designed adversarial + legitimate corpora (dent8 eval)
#   2. every shipped reviewed legitimate-traffic trace under evals/traces/
#   3. optional local store verify + witness coverage (when DENT8_* env is set)
#   4. optional operated-witness Docker demo (--operated-witness)
#
# Exit non-zero on any false positive, integrity issue, or missing binary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OPERATED_WITNESS=0
LOCAL_STORE=0
for arg in "$@"; do
  case "$arg" in
    --operated-witness) OPERATED_WITNESS=1 ;;
    --local-store) LOCAL_STORE=1 ;;
    -h|--help)
      cat <<'HELP'
Usage: scripts/integrity-check.sh [--local-store] [--operated-witness]

  (default)     dent8 eval + all evals/traces/*.{redacted,example}.json
  --local-store also run verify (+ witness verify when DENT8_WITNESS_* is set)
  --operated-witness  run examples/witness-operated/demo.sh (Docker required)
HELP
      exit 0
      ;;
    *)
      echo "unknown flag: $arg (try --help)" >&2
      exit 2
      ;;
  esac
done

if [ -n "${DENT8_BIN:-}" ]; then
  BIN="$DENT8_BIN"
elif [ -x "$ROOT/target/debug/dent8" ]; then
  BIN="$ROOT/target/debug/dent8"
elif command -v dent8 >/dev/null 2>&1; then
  BIN="$(command -v dent8)"
else
  echo "integrity-check: building dent8-cli..." >&2
  cargo build -q -p dent8-cli
  BIN="$ROOT/target/debug/dent8"
fi

note() { echo "integrity-check: $*"; }
fail() { echo "integrity-check: FAIL: $*" >&2; exit 1; }

note "binary: $BIN ($("$BIN" --version 2>/dev/null || echo unknown))"

# --- 1+2: corpora + shipped traces -------------------------------------------------
TRACE_ARGS=()
TRACE_FILES=0
shopt -s nullglob
for f in evals/traces/*.redacted.json evals/traces/*.example.json; do
  TRACE_ARGS+=(--trace "$f")
  TRACE_FILES=$((TRACE_FILES + 1))
done
shopt -u nullglob
if [ "$TRACE_FILES" -eq 0 ]; then
  fail "no evals/traces/*.redacted.json or *.example.json found"
fi

note "running dent8 eval with $TRACE_FILES shipped trace file(s)"
EVAL_JSON="$("$BIN" eval "${TRACE_ARGS[@]}" --output json)" || {
  echo "$EVAL_JSON" >&2
  fail "dent8 eval exited non-zero (corpus or reviewed-trace regression)"
}

printf '%s\n' "$EVAL_JSON" | python3 -c '
import json, sys
payload = json.load(sys.stdin)
traffic = payload.get("reviewed_legitimate_traffic") or {}
fp = traffic.get("false_positives", 0)
captured_fp = traffic.get("captured_false_positives", 0)
legit = payload.get("legitimate_traffic") or {}
designed_fp = legit.get("false_positives")
if designed_fp is None:
    designed_fp = payload.get("legitimate_false_positives")
print(
    "integrity-check: eval ok; designed_fp=%r trace_fp=%s captured_fp=%s traces=%s ops=%s"
    % (
        designed_fp,
        fp,
        captured_fp,
        traffic.get("trace_count"),
        traffic.get("operation_count"),
    )
)
if fp not in (0, None) or captured_fp not in (0, None):
    raise SystemExit("reviewed legitimate-traffic false positives detected")
if designed_fp not in (0, None):
    raise SystemExit("designed legitimate corpus false positives: %s" % designed_fp)
'

# --- 3: local store (optional) -----------------------------------------------------
if [ "$LOCAL_STORE" -eq 1 ]; then
  if [ -z "${DENT8_LOG:-}" ] && [ -z "${DENT8_STORE_URL:-}" ]; then
    if [ -f .dent8/env ]; then
      note "loading .dent8/env for local-store checks"
      set -a
      # shellcheck source=/dev/null
      . .dent8/env
      set +a
    else
      fail "--local-store requires DENT8_LOG/DENT8_STORE_URL or .dent8/env"
    fi
  fi
  note "local verify"
  "$BIN" verify
  if [ -n "${DENT8_WITNESS_LOG:-}" ] || [ -n "${DENT8_WITNESS_PUBKEY:-}" ]; then
    note "local witness verify"
    if ! "$BIN" witness verify; then
      fail "witness verify failed (sign lag with: DENT8_WITNESS_KEY=… dent8 witness sign)"
    fi
  else
    note "witness not configured (skip); operated witness is the production shape"
  fi
fi

# --- 4: operated witness demo (optional) ------------------------------------------
if [ "$OPERATED_WITNESS" -eq 1 ]; then
  note "operated witness demo (Docker)"
  if ! command -v docker >/dev/null 2>&1; then
    fail "docker required for --operated-witness"
  fi
  ./examples/witness-operated/demo.sh
fi

note "PASS"
