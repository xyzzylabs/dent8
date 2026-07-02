#!/usr/bin/env bash
# Runs a local version of the intended operated witness split:
# - writer env has the event log, witness log, and witness public key;
# - signer env has the event log, witness log, and private signing key;
# - monitor env verifies externally published heads using only the event log and public key.
#
# Requires a dent8 binary built with the witness feature. From a clone:
#   DENT8="cargo run -q -p dent8-cli --features witness --" ./examples/witness/demo.sh
set -euo pipefail

# Split intentionally so callers can pass `DENT8="cargo run -q -p dent8-cli --features witness --"`.
read -r -a DENT8_CMD <<<"${DENT8:-dent8}"
DENT8_ENV=(
  env
  -u DENT8_STORE_URL
  -u DENT8_LOG
  -u DENT8_AUTHORITY
  -u DENT8_REQUIRE_AUTHORITY
  -u DENT8_TRUST
  -u DENT8_ACTIVE_GRANTS
  -u DENT8_REQUIRE_IDENTITY
  -u DENT8_GRANT
  -u DENT8_IDENTITY_KEY
  -u DENT8_ISSUER_KEY
  -u DENT8_WITNESS_LOG
  -u DENT8_WITNESS_PUBKEY
  -u DENT8_WITNESS_KEY
)

run_dent8() {
  local env_args=()
  while (($# > 0)); do
    case "$1" in
      *=*)
        env_args+=("$1")
        shift
        ;;
      *)
        break
        ;;
    esac
  done
  "${DENT8_ENV[@]}" "${env_args[@]}" "${DENT8_CMD[@]}" "$@"
}

WORK="$(mktemp -d -t dent8-witness-demo.XXXXXX)"
SHARED="$WORK/shared"
SECURE="$WORK/secure"
EXTERNAL="$WORK/external"
LOG="$SHARED/memory.jsonl"
WITNESS_LOG="$SHARED/witness.jsonl"
WITNESS_KEY="$SECURE/witness.key"
WITNESS_PUBKEY="$SHARED/witness.key.pub"
PUBLISHED="$EXTERNAL/published-heads.jsonl"
WRITER_ENV="$WORK/writer.env"
SIGNER_ENV="$WORK/signer.env"
MONITOR_ENV="$WORK/monitor.env"
ROLLBACK_LOG="$SHARED/rolled-back-memory.jsonl"
ROLLBACK_OUT="$WORK/rollback.out"

mkdir -p "$SHARED" "$SECURE" "$EXTERNAL"
trap 'rm -rf "$WORK"' EXIT

cat >"$WRITER_ENV" <<EOF
export DENT8_LOG='$LOG'
export DENT8_WITNESS_LOG='$WITNESS_LOG'
export DENT8_WITNESS_PUBKEY='$WITNESS_PUBKEY'
EOF

cat >"$SIGNER_ENV" <<EOF
export DENT8_LOG='$LOG'
export DENT8_WITNESS_LOG='$WITNESS_LOG'
export DENT8_WITNESS_KEY='$WITNESS_KEY'
EOF

cat >"$MONITOR_ENV" <<EOF
export DENT8_LOG='$LOG'
export DENT8_WITNESS_PUBKEY='$WITNESS_PUBKEY'
EOF

echo "# 1. Generate the witness key on the signer side"
run_dent8 DENT8_WITNESS_KEY="$WITNESS_KEY" witness keygen
cp "$WITNESS_KEY.pub" "$WITNESS_PUBKEY"

echo
echo "# 2. Check the intended role split"
run_dent8 \
  DENT8_LOG="$LOG" \
  DENT8_WITNESS_LOG="$WITNESS_LOG" \
  DENT8_WITNESS_PUBKEY="$WITNESS_PUBKEY" \
  witness doctor writer
run_dent8 \
  DENT8_LOG="$LOG" \
  DENT8_WITNESS_LOG="$WITNESS_LOG" \
  DENT8_WITNESS_KEY="$WITNESS_KEY" \
  witness doctor signer

echo
echo "# 3. Writer appends an event; signer signs the current tree head"
run_dent8 DENT8_LOG="$LOG" \
  assert person:alice favorite_drink tea --authority high --source user:alice
run_dent8 \
  DENT8_LOG="$LOG" \
  DENT8_WITNESS_LOG="$WITNESS_LOG" \
  DENT8_WITNESS_KEY="$WITNESS_KEY" \
  witness sign

echo
echo "# 4. Writer verifies local witness coverage"
run_dent8 \
  DENT8_LOG="$LOG" \
  DENT8_WITNESS_LOG="$WITNESS_LOG" \
  DENT8_WITNESS_PUBKEY="$WITNESS_PUBKEY" \
  witness verify

echo
echo "# 5. Publish the signed head outside the writer-controlled witness log"
run_dent8 \
  DENT8_LOG="$LOG" \
  DENT8_WITNESS_LOG="$WITNESS_LOG" \
  DENT8_WITNESS_PUBKEY="$WITNESS_PUBKEY" \
  witness publish "$PUBLISHED"

echo
echo "# 6. Monitor verifies the externally published head"
run_dent8 \
  DENT8_LOG="$LOG" \
  DENT8_WITNESS_PUBKEY="$WITNESS_PUBKEY" \
  witness verify-published "$PUBLISHED"

echo
echo "# 7. A rolled-back event log is rejected against the externally published head"
: >"$ROLLBACK_LOG"
if run_dent8 \
  DENT8_LOG="$ROLLBACK_LOG" \
  DENT8_WITNESS_PUBKEY="$WITNESS_PUBKEY" \
  witness verify-published "$PUBLISHED" >"$ROLLBACK_OUT" 2>&1; then
  cat "$ROLLBACK_OUT"
  echo "expected verify-published to reject the rolled-back event log" >&2
  exit 1
fi
if ! grep -q "ROLLBACK" "$ROLLBACK_OUT"; then
  cat "$ROLLBACK_OUT"
  echo "expected rollback diagnostic from verify-published" >&2
  exit 1
fi
echo "OK: externally published head detects event-log rollback"

echo
echo "# temporary env files used by this run:"
echo "#   writer:  $WRITER_ENV"
echo "#   signer:  $SIGNER_ENV"
echo "#   monitor: $MONITOR_ENV"
echo "OK: witness demo complete"
