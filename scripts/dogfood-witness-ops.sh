#!/usr/bin/env bash
# Operate the local monorepo dogfood witness with a writer/signer split posture.
#
# - Writer env (.dent8/env) must NOT contain DENT8_WITNESS_KEY.
# - Signing uses DENT8_WITNESS_KEY=.dent8/witness.key only for this script.
# - Publishes heads to .dent8/published-heads.jsonl (channel the writer should not rewrite).
# - Verifies coverage + published heads.
#
# Usage:
#   scripts/dogfood-witness-ops.sh              # sign + publish + verify
#   scripts/dogfood-witness-ops.sh --status     # doctor + verify only
#   scripts/dogfood-witness-ops.sh --doctor     # role doctor writer/signer
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DIR="${DENT8_DOGFOOD_DIR:-$ROOT/.dent8}"
ENV_FILE="$DIR/env"
MODE=ops

for arg in "$@"; do
  case "$arg" in
    --status) MODE=status ;;
    --doctor) MODE=doctor ;;
    -h|--help)
      sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

if [ -x "$DIR/bin/dent8" ]; then
  BIN="$DIR/bin/dent8"
elif [ -n "${DENT8_BIN:-}" ]; then
  BIN="$DENT8_BIN"
elif [ -x "$ROOT/target/debug/dent8" ]; then
  BIN="$ROOT/target/debug/dent8"
else
  cargo build -q -p dent8-cli --features sqlite
  BIN="$ROOT/target/debug/dent8"
fi

[ -f "$ENV_FILE" ] || { echo "missing $ENV_FILE; run scripts/dogfood-seed.sh or dent8 init --witness" >&2; exit 1; }

set -a
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a

# Never export the signing key into the writer environment permanently.
KEY="${DENT8_WITNESS_KEY_FILE:-$DIR/witness.key}"
PUB="${DENT8_WITNESS_PUBKEY:-$DIR/witness.key.pub}"
LOG="${DENT8_WITNESS_LOG:-$DIR/witness.jsonl}"
PUBLISHED="${DENT8_WITNESS_PUBLISHED:-$DIR/published-heads.jsonl}"

export DENT8_WITNESS_LOG="$LOG"
export DENT8_WITNESS_PUBKEY="$PUB"
# Ensure writer-key is not set from env file
unset DENT8_WITNESS_KEY || true

note() { echo "dogfood-witness: $*"; }
fail() { echo "dogfood-witness: FAIL: $*" >&2; exit 1; }

if [ ! -f "$PUB" ]; then
  fail "missing public key $PUB (init --witness + keygen)"
fi

if [ "$MODE" = doctor ] || [ "$MODE" = ops ]; then
  note "role doctor: writer (must not have private key in env)"
  "$BIN" witness doctor writer
fi

if [ "$MODE" = doctor ]; then
  if [ -f "$KEY" ]; then
    note "role doctor: signer"
    DENT8_WITNESS_KEY="$KEY" "$BIN" witness doctor signer
  else
    fail "missing $KEY for signer doctor"
  fi
  exit 0
fi

if [ "$MODE" = status ]; then
  "$BIN" verify
  "$BIN" witness verify
  if [ -f "$PUBLISHED" ]; then
    "$BIN" witness verify-published "$PUBLISHED"
  else
    note "no published heads yet at $PUBLISHED"
  fi
  exit 0
fi

# ops: sign + publish + verify
[ -f "$KEY" ] || fail "missing $KEY (generate once: DENT8_WITNESS_KEY=$KEY dent8 witness keygen)"

note "sign current head (key only on this invocation)"
DENT8_WITNESS_KEY="$KEY" "$BIN" witness sign

note "verify local coverage"
"$BIN" witness verify

note "publish heads -> $PUBLISHED"
"$BIN" witness publish "$PUBLISHED"

note "verify published heads"
"$BIN" witness verify-published "$PUBLISHED"

note "PASS (local operated posture: key not in writer env; published sequence at $PUBLISHED)"
