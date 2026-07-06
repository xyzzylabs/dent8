#!/usr/bin/env bash
# Runs the firewall path through the real CLI and stock SQLite backend: initialize a temporary
# dent8 belief base, assert a trusted everyday fact, reject a low-authority override, then
# explain and verify the retained fact.
#
# Requires the `dent8` binary. Either install it (`cargo install dent8 --locked`) and run
# `./demo.sh`, or from a clone:
#   DENT8="cargo run -q -p dent8 --" ./examples/firewall/demo.sh
# For recordings, set `DENT8_DEMO_PAUSE=0.8` to add short reader pauses.
set -euo pipefail

DENT8="${DENT8:-dent8}"
WORK="$(mktemp -d -t dent8-firewall-demo.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

pause_for_reader() {
  if [ -n "${DENT8_DEMO_PAUSE:-}" ] && [ "${DENT8_DEMO_PAUSE:-0}" != "0" ]; then
    sleep "$DENT8_DEMO_PAUSE"
  fi
}

# Keep the walkthrough hermetic if the caller's shell is already dogfooding dent8.
unset DENT8_STORE_URL \
  DENT8_LOG \
  DENT8_AUTHORITY \
  DENT8_REQUIRE_AUTHORITY \
  DENT8_TRUST \
  DENT8_ACTIVE_GRANTS \
  DENT8_REQUIRE_IDENTITY \
  DENT8_GRANT \
  DENT8_IDENTITY_KEY \
  DENT8_ISSUER_KEY \
  DENT8_WITNESS_KEY \
  DENT8_WITNESS_PUBKEY \
  DENT8_WITNESS_LOG

echo "dent8 firewall demo: a trusted fact survives a weaker overwrite"
echo
pause_for_reader

echo "# 1. Initialize a temporary dent8 belief base"
$DENT8 init --dir "$WORK/.dent8" --store sqlite --source source:owner >/dev/null
set -a
# shellcheck source=/dev/null
. "$WORK/.dent8/env"
set +a
pause_for_reader

echo "# 2. Grant a low-authority source so the rejection is about arbitration, not missing authz"
$DENT8 authority add source:web-scrape low >/dev/null
pause_for_reader

echo "# 3. Assert a trusted fact"
$DENT8 assert person:alice favorite_drink tea --authority high --source source:owner
pause_for_reader

echo
echo "# 4. Try a low-authority override; dent8 rejects it"
if $DENT8 supersede person:alice favorite_drink coffee --authority low --source source:web-scrape; then
  echo "unexpected: low-authority override was accepted" >&2
  exit 1
fi
pause_for_reader

echo
echo "# 5. Explain shows the trusted fact is still believed, with an integrity receipt"
$DENT8 explain person:alice favorite_drink
pause_for_reader

echo
echo "# 6. Verify the event log and hash chain"
verify_report="$($DENT8 verify)"
witness_note=" (Tamper-resistance needs an external operated witness.)"
if [[ "$verify_report" == *"$witness_note" ]]; then
  printf '%s\n' "${verify_report%"$witness_note"}"
  printf 'NOTE: tamper-resistance needs an external operated witness.\n'
else
  printf '%s\n' "$verify_report"
fi
