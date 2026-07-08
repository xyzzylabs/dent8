#!/usr/bin/env bash
# Rebuild this repo's dent8 fact base (the shared, verified facts agents read).
#
# The .dent8/ store is gitignored (machine-local paths, grants, local log), so
# it is NOT committed. This script plus scripts/dogfood-facts.jsonl are the
# committed source of truth that reproduces it deterministically. Idempotent:
# it does a clean rebuild of the local store on each run.
#
# Usage: scripts/dogfood-seed.sh          (builds dent8 if not on PATH)
#        DENT8_BIN=/path/to/dent8 scripts/dogfood-seed.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DENT8_BIN="${DENT8_BIN:-}"
if [ -z "$DENT8_BIN" ]; then
  if command -v dent8 >/dev/null 2>&1; then
    DENT8_BIN="dent8"
  else
    echo "dent8 not on PATH; building it (cargo build -p dent8)..." >&2
    cargo build -p dent8 >/dev/null
    DENT8_BIN="$PWD/target/debug/dent8"
  fi
fi

# Clean rebuild: the store is machine-local and fully reproduced below.
rm -rf .dent8

# 1. Initialize the local store (authority.json, env, memory.jsonl).
"$DENT8_BIN" init --force

# 2. Load machine-local env: authority registry path, event log, require-authority.
set -a
# shellcheck disable=SC1091
. .dent8/env
set +a

# 3. Seed the human > CI > agent trust profile into that registry.
"$DENT8_BIN" authority defaults

# 4. Capture this repo's human-authored facts as source:human at high authority.
"$DENT8_BIN" capture scripts/dogfood-facts.jsonl --source source:human --authority high

# 5. Create the proposals queue the SessionEnd hook drains (agents append here).
touch .dent8/proposals.jsonl

echo
echo "Fact base rebuilt. Inspect it with:  $DENT8_BIN context"
