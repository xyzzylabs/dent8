#!/usr/bin/env bash
# Hermetic multi-agent integrity gate.
#
# Builds a temporary shared SQLite store with signed identities for the primary
# coding-agent profiles, installs project MCP configs, then runs:
#   dent8 doctor --agent all --write-check
#
# This does not touch the repo's machine-local .dent8 dogfood state. Safe for CI.
#
# Usage:
#   scripts/integrity-multi-agent.sh
#   DENT8_BIN=/path/to/dent8 scripts/integrity-multi-agent.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -n "${DENT8_BIN:-}" ]; then
  BIN="$DENT8_BIN"
elif [ -x "$ROOT/target/debug/dent8" ]; then
  BIN="$ROOT/target/debug/dent8"
elif command -v dent8 >/dev/null 2>&1; then
  BIN="$(command -v dent8)"
else
  echo "integrity-multi-agent: building dent8-cli..." >&2
  cargo build -q -p dent8-cli
  BIN="$ROOT/target/debug/dent8"
fi

case "$BIN" in
  /*) ;;
  *) BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" ;;
esac

AGENTS=(codex claude-code cursor grok-build)

WORK="$(mktemp -d -t dent8-integrity-multi-agent.XXXXXX)"
PROJECT="$WORK/project"
OUT="$WORK/out"
mkdir -p "$PROJECT" "$OUT"
ISSUER_KEY="$WORK/issuer.key"

cleanup() {
  status=$?
  if [ "$status" -eq 0 ]; then
    rm -rf "$WORK"
    return
  fi
  echo "integrity-multi-agent: FAIL (artifacts left in $WORK)" >&2
  if [ -d "$OUT" ]; then
    for f in "$OUT"/*; do
      [ -f "$f" ] || continue
      echo "----- $f -----" >&2
      sed -n '1,120p' "$f" >&2 || true
    done
  fi
}
trap cleanup EXIT

cd "$PROJECT"

# Hermetic: ignore ambient dogfood env from the parent shell.
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
  DENT8_WITNESS_KEY \
  DENT8_WITNESS_GRANTS_LOG

note() { echo "integrity-multi-agent: $*"; }

note "binary: $BIN ($("$BIN" --version))"
note "init primary agent codex (sqlite + identity + mcp)"
"$BIN" init \
  --agent codex \
  --store sqlite \
  --issuer-key "$ISSUER_KEY" \
  --install-mcp \
  --mcp-command "$BIN" \
  --force \
  --output json >"$OUT/init-codex.json"

for agent in "${AGENTS[@]}"; do
  if [ "$agent" = "codex" ]; then
    continue
  fi
  note "agent add $agent"
  "$BIN" agent add \
    --agent "$agent" \
    --dir .dent8 \
    --issuer-key "$ISSUER_KEY" \
    --mcp-command "$BIN" \
    --output json >"$OUT/add-${agent}.json"
done

# Per-agent doctor: `--agent all` cannot take `--mcp-command` (each profile has its own
# installed command). Install used --mcp-command "$BIN", so pin the same binary here.
note "doctor --write-check for each installed agent"
FAILED_AGENTS=()
for agent in "${AGENTS[@]}"; do
  note "  doctor --agent $agent --write-check"
  if ! "$BIN" doctor \
    --agent "$agent" \
    --dir .dent8 \
    --mcp-command "$BIN" \
    --write-check \
    --output json >"$OUT/doctor-${agent}.json"; then
    FAILED_AGENTS+=("$agent")
    continue
  fi
  if ! python3 - "$OUT/doctor-${agent}.json" "$agent" <<'PY'; then
import json, sys
doc = json.load(open(sys.argv[1]))
agent = sys.argv[2]
status = doc.get("status")
ok = doc.get("ok")
if status in ("failed", "fail") or ok is False:
    raise SystemExit(f"{agent}: doctor status={status!r} ok={ok!r}")
print(f"integrity-multi-agent: {agent}: ok")
PY
    FAILED_AGENTS+=("$agent")
  fi
done

if [ "${#FAILED_AGENTS[@]}" -ne 0 ]; then
  echo "integrity-multi-agent: FAIL write-check for: ${FAILED_AGENTS[*]}" >&2
  exit 1
fi

# Aggregate view without --mcp-command (reads each installed config as-is).
note "doctor --agent all --write-check (aggregate)"
"$BIN" doctor \
  --agent all \
  --dir .dent8 \
  --write-check \
  --output json >"$OUT/doctor-all.json"
python3 - "$OUT/doctor-all.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
agents = doc.get("agents") or []
if agents:
    failed = [
        a for a in agents
        if a.get("status") in ("failed", "fail") or a.get("failed") is True or a.get("ok") is False
    ]
    for a in agents:
        name = a.get("agent") or a.get("profile") or "?"
        st = a.get("status") or ("ok" if a.get("ok") else "?")
        print(f"  - {name}: {st}")
    if failed:
        raise SystemExit("aggregate doctor reported failed agents")
elif doc.get("status") in ("failed", "fail") or doc.get("ok") is False:
    raise SystemExit(f"aggregate doctor failed: status={doc.get('status')!r}")
print("integrity-multi-agent: aggregate doctor ok")
PY

# Lightweight local role-split witness (no Docker): writer/signer/publish/monitor/rollback.
note "local role-split witness demo (examples/witness/demo.sh)"
DENT8="$BIN" "$ROOT/examples/witness/demo.sh" >"$OUT/witness-demo.log"

note "PASS"
