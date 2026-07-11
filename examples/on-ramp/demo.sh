#!/usr/bin/env bash
# Timed on-ramp: init → first assert → explain in a throwaway git repo.
# Requires the `dent8` binary. Either install it and run `./examples/on-ramp/demo.sh`,
# or from a clone:
#   DENT8="cargo run -q -p dent8-cli --" ./examples/on-ramp/demo.sh
# Exit 0 only when the path completes under 120 seconds wall time.
set -euo pipefail

DENT8="${DENT8:-dent8}"
# Resolve a relative binary path before we cd into the throwaway repo.
if [[ "$DENT8" == ./* || "$DENT8" == ../* ]]; then
  DENT8="$(cd "$(dirname "$DENT8")" && pwd)/$(basename "$DENT8")"
fi

# Keep the path hermetic if the caller's shell is already dogfooding dent8.
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

ROOT="$(mktemp -d "${TMPDIR:-/tmp}/dent8-on-ramp.XXXXXX")"
cleanup() { rm -rf "$ROOT"; }
trap cleanup EXIT

cd "$ROOT"
git init -q
git config user.email "on-ramp@dent8.local"
git config user.name "dent8 on-ramp"
echo "# on-ramp" > README.md
git add README.md
git commit -qm "on-ramp seed"

START=$(date +%s)

# Unquoted $DENT8 so wrappers like `cargo run -q -p dent8-cli --` work.
$DENT8 init --source source:owner
set -a
# shellcheck disable=SC1091
. .dent8/env
set +a

$DENT8 assert repo:demo deploy_target production --authority high --source source:owner
EXPLAIN=$($DENT8 explain repo:demo deploy_target)
echo "$EXPLAIN" | grep -q 'production' || {
  echo "explain did not show production:" >&2
  echo "$EXPLAIN" >&2
  exit 1
}

END=$(date +%s)
ELAPSED=$((END - START))

echo "on-ramp ok: init → assert → explain in ${ELAPSED}s (budget 120s)"
if [ "$ELAPSED" -gt 120 ]; then
  echo "on-ramp exceeded 2-minute budget" >&2
  exit 1
fi
