#!/usr/bin/env bash
# Fresh-install acceptance path for v0.1.0.
#
# By default this builds the stock `dent8` package and tests the installed-user shape in a
# temporary project. Set DENT8_BIN=/path/to/dent8 to test an already installed/release binary.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [ -n "${DENT8_BIN:-}" ]; then
  BIN="$DENT8_BIN"
else
  cargo build -p dent8
  BIN="$ROOT/target/debug/dent8"
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
trap 'rm -rf "$WORK"' EXIT
PROJECT="$WORK/project"
OUT="$WORK/out"
mkdir -p "$PROJECT"
mkdir -p "$OUT"
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

MCP_CONFIG="$PROJECT/codex-config.toml"
ISSUER_KEY="$WORK/issuer.key"

echo "# init: Codex profile, signed identity, stock SQLite backend, MCP config"
"$BIN" init \
  --agent codex \
  --store sqlite \
  --issuer-key "$ISSUER_KEY" \
  --install-mcp \
  --mcp-config "$MCP_CONFIG" \
  --mcp-command "$BIN" \
  --output json >"$OUT/init.json"

echo "# doctor: installed MCP smoke + trusted write check"
"$BIN" doctor \
  --agent codex \
  --dir .dent8 \
  --mcp-config "$MCP_CONFIG" \
  --mcp-command "$BIN" \
  --write-check \
  --output json >"$OUT/doctor.json"

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

echo "# witness: smoke if this binary was built with --features witness"
if "$BIN" --output json witness head >"$OUT/witness-probe.json" 2>"$OUT/witness-probe.err"; then
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
else
  echo "witness smoke skipped: binary does not include --features witness"
fi

echo "OK: dent8 release acceptance path passed"
