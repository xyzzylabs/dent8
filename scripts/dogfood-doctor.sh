#!/usr/bin/env bash
# Validate this repo's ignored .dent8 dogfood bundle before agents trust it.
#
# This is deliberately read-only. It does not rebuild or reseed the store; it fails with
# concrete repair hints when the local wrapper is stale, the env points at an empty/wrong
# store, or the committed seed facts are not visible through `dent8 context`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DIR="${DENT8_DOGFOOD_DIR:-$ROOT/.dent8}"
ENV_FILE="$DIR/env"
EXPECTED_VERSION="$(
  sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1
)"
EXPECTED_FACTS="$(
  grep -cv '^[[:space:]]*$' scripts/dogfood-facts.jsonl
)"

fail() {
  echo "dogfood doctor: FAIL: $*" >&2
  exit 1
}

note() {
  echo "dogfood doctor: $*"
}

if [ ! -f "$ENV_FILE" ]; then
  fail "missing $ENV_FILE; run scripts/dogfood-seed.sh or dent8 init"
fi

if [ -n "${DENT8:-}" ]; then
  # shellcheck disable=SC2206
  DENT8_CMD=($DENT8)
elif [ -x "$DIR/bin/dent8" ]; then
  DENT8_CMD=("$DIR/bin/dent8")
elif [ -x "$ROOT/target/debug/dent8" ]; then
  DENT8_CMD=("$ROOT/target/debug/dent8")
else
  DENT8_CMD=(cargo run -q -p dent8-cli --)
fi

run_dent8() {
  "${DENT8_CMD[@]}" "$@"
}

version_line="$(run_dent8 --version)"
actual_version="${version_line##* }"
if [ "$actual_version" != "$EXPECTED_VERSION" ]; then
  fail "dent8 command is $version_line, expected dent8 $EXPECTED_VERSION. Rebuild with: CARGO_TARGET_DIR=.dent8/target-sqlite cargo build -p dent8-cli --features sqlite"
fi
note "binary version ok: $version_line"

if [ -x "$DIR/bin/dent8" ]; then
  wrapper_version="$("$DIR/bin/dent8" --version)"
  wrapper_actual="${wrapper_version##* }"
  if [ "$wrapper_actual" != "$EXPECTED_VERSION" ]; then
    fail "$DIR/bin/dent8 is $wrapper_version, expected dent8 $EXPECTED_VERSION. Rebuild with: CARGO_TARGET_DIR=.dent8/target-sqlite cargo build -p dent8-cli --features sqlite"
  fi
  note "local MCP wrapper ok: $wrapper_version"
fi

set -a
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a

if [ -z "${DENT8_LOG:-}" ] && [ -z "${DENT8_STORE_URL:-}" ]; then
  fail "$ENV_FILE sets neither DENT8_LOG nor DENT8_STORE_URL"
fi

context_json="$(run_dent8 context -o json)"
count="$(
  printf '%s\n' "$context_json" | sed -n 's/.*"count"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' | head -n 1
)"
if [ -z "$count" ]; then
  fail "could not parse fact count from dent8 context -o json"
fi
if [ "$count" -lt "$EXPECTED_FACTS" ]; then
  store_hint="${DENT8_STORE_URL:-${DENT8_LOG:-unknown store}}"
  fail "context returned $count fact(s), expected at least $EXPECTED_FACTS from scripts/dogfood-facts.jsonl; check $ENV_FILE and store $store_hint"
fi
note "context ok: $count fact(s)"

run_dent8 verify >/dev/null
note "verify ok"
