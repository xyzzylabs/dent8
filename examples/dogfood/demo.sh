#!/usr/bin/env bash
# Runs this repository's local dogfood path against the ignored .dent8 bundle.
#
# The script is intentionally not hermetic: it validates the real shared store, signed source
# identity, MCP install, native-memory guard posture, and witness coverage used by local agents.
# It writes only diagnostic facts, which dent8 hides from normal fact browsing by default.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DIR="${DENT8_DOGFOOD_DIR:-$ROOT/.dent8}"
AGENT="${DENT8_DOGFOOD_AGENT:-codex}"
SOURCE="${DENT8_DOGFOOD_SOURCE:-$AGENT}"
IDENTITY_ENV="$DIR/identity-$SOURCE.env"

if [ ! -f "$DIR/env" ]; then
  echo "missing $DIR/env; run dent8 init --agent $AGENT --store sqlite --install-mcp first" >&2
  exit 1
fi

if [ ! -f "$IDENTITY_ENV" ]; then
  echo "missing $IDENTITY_ENV; run dent8 agent add --agent $AGENT or set DENT8_DOGFOOD_SOURCE" >&2
  exit 1
fi

if [ -n "${DENT8:-}" ]; then
  DENT8_CMD=(sh -c 'exec "$@"' sh $DENT8)
elif [ -x "$DIR/bin/dent8" ]; then
  DENT8_CMD=("$DIR/bin/dent8")
else
  DENT8_CMD=(cargo run -q -p dent8-cli --)
fi

run_dent8() {
  "${DENT8_CMD[@]}" "$@"
}

run_advisory() {
  if ! run_dent8 "$@"; then
    echo "NOTE: advisory command reported warnings/failures; inspect the output above: dent8 $*" >&2
  fi
}

sign_witness_if_possible() {
  if [ -f "$DIR/witness.key" ]; then
    DENT8_WITNESS_KEY="$DIR/witness.key" run_dent8 witness sign >/dev/null
  fi
}

set -a
# shellcheck source=/dev/null
. "$DIR/env"
# shellcheck source=/dev/null
. "$IDENTITY_ENV"
set +a

if [ -z "${DENT8_WITNESS_GRANTS_LOG:-}" ] && [ -f "$DIR/grant-log.jsonl" ]; then
  export DENT8_WITNESS_GRANTS_LOG="$DIR/witness-grants.jsonl"
fi

cd "$ROOT"

echo "# 1. List durable project facts from the real dogfood store"
run_dent8 facts list

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
subject="diagnostic:dogfood-$run_id"
predicate="dent8.write_check"

echo
echo "# 2. Assert a high-authority diagnostic fact"
run_dent8 assert "$subject" "$predicate" ok

echo
echo "# 3. Prove the firewall rejects a low-authority override"
if run_dent8 supersede "$subject" "$predicate" tampered --authority low; then
  echo "unexpected: low-authority dogfood override was accepted" >&2
  exit 1
fi

echo
echo "# 4. Explain still returns the trusted value"
run_dent8 explain "$subject" "$predicate"

echo
echo "# 5. Verify store integrity"
run_dent8 verify

echo
echo "# 6. Sign a fresh local witness head when the private key is present"
sign_witness_if_possible
run_dent8 witness verify

echo
echo "# 7. Smoke every installed agent profile through its configured MCP server"
run_advisory doctor --agent all --dir "$DIR"

echo
echo "# 8. Prove the selected agent's installed MCP write path"
run_dent8 doctor --agent "$AGENT" --dir "$DIR" --write-check

echo
echo "# 9. Keep witness coverage current after doctor write probes"
sign_witness_if_possible
run_advisory doctor --agent all --dir "$DIR"
