#!/usr/bin/env bash
# Drives `dent8 mcp serve` over stdio with a handful of JSON-RPC 2.0 calls — the firewall an
# agent sees through MCP: runtime status is inspectable, facts can be listed, a trusted fact is
# asserted, a low-authority override is REJECTED, `explain` replays the believed fact, and
# `verify` checks integrity.
#
# Requires the `dent8` binary. Either install it (`cargo install dent8-cli --locked`) and run
# `./demo.sh`, or from a clone:
#   DENT8="cargo run -q -p dent8-cli --" ./examples/mcp/demo.sh
set -euo pipefail

DENT8="${DENT8:-dent8}"
unset DENT8_STORE_URL DENT8_DAEMON_SOCKET
unset DENT8_AUTHORITY DENT8_REQUIRE_AUTHORITY
unset DENT8_TRUST DENT8_REQUIRE_IDENTITY DENT8_GRANT DENT8_ACTIVE_GRANTS DENT8_IDENTITY_KEY
unset DENT8_WITNESS_LOG DENT8_WITNESS_PUBKEY DENT8_WITNESS_KEY
# A run-scoped temp dir holds the log, the authority registry, and a signed-identity bundle.
WORK="$(mktemp -d -t dent8-mcp-demo.XXXXXX)"
DENT8_LOG="$WORK/log.jsonl"
DENT8_AUTHORITY="$WORK/authority.json"
export DENT8_LOG
cat >"$DENT8_AUTHORITY" <<'JSON'
{"sources":{"source:owner":{"max_authority":"high"}}}
JSON
export DENT8_AUTHORITY DENT8_REQUIRE_AUTHORITY=1
trap 'rm -rf "$WORK"' EXIT

# v0.8.0 requires a valid signed identity for any write above the agent tier, so provision one
# for the trusted source; without it the `high` assert below is rejected. The low override is
# the *same* source dropping to `low`, so the firewall rejects it on authority ranking (low may
# not override an incumbent high) — the point of the demo — not on an identity mismatch.
$DENT8 identity bootstrap --source source:owner --dir "$WORK/.dent8" >/dev/null
export DENT8_TRUST="$WORK/.dent8/trust.json"
export DENT8_ACTIVE_GRANTS="$WORK/.dent8/active-grants.json"
export DENT8_GRANT="$WORK/.dent8/grants/source_owner.grant.json"
export DENT8_IDENTITY_KEY="$WORK/.dent8/identities/source_owner.key"
export DENT8_REQUIRE_IDENTITY=1

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"runtime_status","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_facts","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"assert","arguments":{"subject":"repo:myproj","predicate":"database","value":"postgres","authority":"high","source":"source:owner"}}}' \
  '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"supersede","arguments":{"subject":"repo:myproj","predicate":"database","value":"mysql","authority":"low","source":"source:owner"}}}' \
  '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"explain","arguments":{"subject":"repo:myproj","predicate":"database"}}}' \
  '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"verify","arguments":{}}}' \
  | $DENT8 mcp serve
