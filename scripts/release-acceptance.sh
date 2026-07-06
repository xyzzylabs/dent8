#!/usr/bin/env bash
# Fresh-install acceptance path for a dent8 release.
#
# By default this builds the stock `dent8` package and tests the installed-user shape in a
# temporary project. Set DENT8_BIN=/path/to/dent8 to test an already installed/release binary.
# The witness is a stock command, so its smoke always runs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -n "${DENT8_BIN:-}" ]; then
  BIN="$DENT8_BIN"
else
  cargo build -p dent8
  TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
  case "$TARGET_DIR" in
    /*) ;;
    *) TARGET_DIR="$ROOT/$TARGET_DIR" ;;
  esac
  BIN="$TARGET_DIR/debug/dent8"
fi

case "$BIN" in
  /*) ;;
  *) BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" ;;
esac

if [ ! -x "$BIN" ]; then
  echo "release acceptance: dent8 binary is not executable: $BIN" >&2
  exit 127
fi

WORK="$(mktemp -d -t dent8-release-acceptance.XXXXXX)"
PROJECT="$WORK/project"
OUT="$WORK/out"
mkdir -p "$PROJECT"
mkdir -p "$OUT"

cleanup() {
  status=$?
  if [ "$status" -eq 0 ]; then
    rm -rf "$WORK"
    return
  fi

  echo "release acceptance failed; artifacts left in $WORK" >&2
  if [ -d "$OUT" ]; then
    for file in "$OUT"/*; do
      [ -f "$file" ] || continue
      echo "----- $file -----" >&2
      sed -n '1,200p' "$file" >&2 || true
    done
  fi
}
trap cleanup EXIT

cd "$PROJECT"

# Keep the acceptance path hermetic if the caller's shell is already dogfooding dent8.
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
  DENT8_WITNESS_LOG \
  DENT8_WITNESS_PUBKEY \
  DENT8_WITNESS_KEY

ISSUER_KEY="$WORK/issuer.key"

echo "# init: Codex profile, signed identity, stock SQLite backend, MCP config"
"$BIN" init \
  --agent codex \
  --store sqlite \
  --issuer-key "$ISSUER_KEY" \
  --install-mcp \
  --mcp-command "$BIN" \
  --output json >"$OUT/init.json"

echo "# doctor: installed MCP smoke + trusted write check"
"$BIN" doctor \
  --agent codex \
  --dir .dent8 \
  --mcp-command "$BIN" \
  --write-check \
  --output json >"$OUT/doctor.json"

echo "# doctor: aggregate installed-agent gate"
"$BIN" doctor \
  --all-agents \
  --dir .dent8 \
  --write-check \
  --output json >"$OUT/doctor-all-agents.json"

set -a
. .dent8/env
. .dent8/identity-codex.env
set +a

echo "# CLI: assert, list, explain, verify over the generated bundle"
"$BIN" assert person:alice favorite_drink tea --authority high --source source:codex
"$BIN" facts list
"$BIN" --output json facts list >"$OUT/facts.json"
"$BIN" explain person:alice favorite_drink
"$BIN" verify

echo "# witness: smoke (the witness is a stock command)"
"$BIN" --output json witness head >"$OUT/witness-probe.json"
WITNESS_KEY="$WORK/witness.key"
WITNESS_LOG="$PROJECT/.dent8/witness.jsonl"
PUBLISHED="$WORK/published-heads.jsonl"
DENT8_WITNESS_KEY="$WITNESS_KEY" "$BIN" witness keygen
DENT8_WITNESS_KEY="$WITNESS_KEY" \
  DENT8_WITNESS_LOG="$WITNESS_LOG" \
  "$BIN" witness sign
DENT8_WITNESS_PUBKEY="$WITNESS_KEY.pub" \
  DENT8_WITNESS_LOG="$WITNESS_LOG" \
  "$BIN" --output json witness verify >"$OUT/witness-verify.json"
DENT8_WITNESS_PUBKEY="$WITNESS_KEY.pub" \
  DENT8_WITNESS_LOG="$WITNESS_LOG" \
  "$BIN" --output json witness publish "$PUBLISHED" >"$OUT/witness-publish.json"
DENT8_WITNESS_PUBKEY="$WITNESS_KEY.pub" \
  "$BIN" --output json witness verify-published "$PUBLISHED" >"$OUT/witness-published.json"

echo "OK: dent8 release acceptance path passed"
