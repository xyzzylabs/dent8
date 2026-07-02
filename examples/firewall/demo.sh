#!/usr/bin/env bash
# Runs the firewall path through the real CLI and file-backed dev store: initialize a temporary
# dent8 belief base, assert a trusted everyday fact, reject a low-authority override, then
# explain and verify the retained fact.
#
# Requires the `dent8` binary. Either install it (`cargo install --git
# https://github.com/xyzzylabs/dent8 dent8-cli`) and run `./demo.sh`, or from a clone:
#   DENT8="cargo run -q -p dent8-cli --" ./examples/firewall/demo.sh
set -euo pipefail

DENT8="${DENT8:-dent8}"
WORK="$(mktemp -d -t dent8-firewall-demo.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

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

echo "# 1. Initialize a temporary dent8 belief base"
$DENT8 init --dir "$WORK/.dent8" --source source:owner >/dev/null
set -a
. "$WORK/.dent8/env"
set +a

echo "# 2. Grant a low-authority source so the rejection is about arbitration, not missing authz"
$DENT8 authority add source:web-scrape low >/dev/null

echo "# 3. Assert a trusted fact"
$DENT8 assert person:alice favorite_drink tea --authority high --source source:owner

echo
echo "# 4. Try a low-authority override; dent8 rejects it"
if $DENT8 supersede person:alice favorite_drink coffee --authority low --source source:web-scrape; then
  echo "unexpected: low-authority override was accepted" >&2
  exit 1
fi

echo
echo "# 5. Explain shows the trusted fact is still believed, with an integrity receipt"
$DENT8 explain person:alice favorite_drink

echo
echo "# 6. Verify the event log and hash chain"
$DENT8 verify
