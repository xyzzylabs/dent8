#!/usr/bin/env bash
# Bounded legitimate-traffic capture helper.
#
# Enables DENT8_EVAL_CAPTURE for a single command (or an interactive shell), then prints
# the prepare → review → finalize path. Does not auto-classify — human review is required.
#
# Usage:
#   scripts/capture-legitimate-session.sh --agent codex --session session:my-001 -- dent8 assert …
#   scripts/capture-legitimate-session.sh --agent grok-build --session session:my-002 --shell
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AGENT=""
SESSION=""
MODE=cmd
OUT_DIR="${DENT8_CAPTURE_DIR:-$ROOT/.dent8/evals}"

while [ $# -gt 0 ]; do
  case "$1" in
    --agent) AGENT="${2:-}"; shift 2 ;;
    --session) SESSION="${2:-}"; shift 2 ;;
    --out-dir) OUT_DIR="${2:-}"; shift 2 ;;
    --shell) MODE=shell; shift ;;
    --) shift; break ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) break ;;
  esac
done

if [ -z "$AGENT" ] || [ -z "$SESSION" ]; then
  echo "required: --agent <name> --session <session:id>" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SAFE_AGENT="$(printf '%s' "$AGENT" | tr -c 'A-Za-z0-9._-' '_')"
CAPTURE="$OUT_DIR/${SAFE_AGENT}-${STAMP}.jsonl"
export DENT8_EVAL_CAPTURE="$CAPTURE"
export DENT8_EVAL_AGENT="$AGENT"
export DENT8_EVAL_SESSION="$SESSION"

echo "capture: $CAPTURE"
echo "agent=$AGENT session=$SESSION"
echo "stop recording: unset DENT8_EVAL_CAPTURE DENT8_EVAL_AGENT DENT8_EVAL_SESSION"

if [ "$MODE" = shell ]; then
  echo "starting shell with capture enabled; exit when the benign session is done"
  "${SHELL:-bash}" || true
else
  if [ $# -eq 0 ]; then
    echo "no command given; use --shell or -- <cmd…>" >&2
    exit 2
  fi
  "$@"
fi

unset DENT8_EVAL_CAPTURE DENT8_EVAL_AGENT DENT8_EVAL_SESSION
if [ ! -s "$CAPTURE" ]; then
  echo "capture file empty or missing: $CAPTURE" >&2
  exit 1
fi

DRAFT="$OUT_DIR/${SAFE_AGENT}-${STAMP}.review.json"
echo
echo "next:"
echo "  dent8 eval prepare $CAPTURE --out $DRAFT"
echo "  # classify every operation as legitimate|exclude; set review.reviewer + basis;"
echo "  # redact values; set privacy.content=redacted"
echo "  dent8 eval finalize $DRAFT --out $OUT_DIR/${SAFE_AGENT}-${STAMP}.trace.json"
echo "  dent8 eval --trace $OUT_DIR/${SAFE_AGENT}-${STAMP}.trace.json"
echo "  scripts/integrity-check.sh"
