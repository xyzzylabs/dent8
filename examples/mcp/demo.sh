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
DENT8_LOG="$(mktemp -t dent8-mcp-demo.XXXXXX)"
DENT8_AUTHORITY="$(mktemp -t dent8-mcp-authority.XXXXXX)"
export DENT8_LOG
cat >"$DENT8_AUTHORITY" <<'JSON'
{"sources":{"owner":{"max_authority":"high"},"web-scrape":{"max_authority":"low"}}}
JSON
export DENT8_AUTHORITY DENT8_REQUIRE_AUTHORITY=1
trap 'rm -f "$DENT8_LOG" "$DENT8_AUTHORITY"' EXIT

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"runtime_status","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"list_facts","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"assert","arguments":{"subject":"repo:myproj","predicate":"database","value":"postgres","authority":"high","source":"owner"}}}' \
  '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"supersede","arguments":{"subject":"repo:myproj","predicate":"database","value":"mysql","authority":"low","source":"web-scrape"}}}' \
  '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"explain","arguments":{"subject":"repo:myproj","predicate":"database"}}}' \
  '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"verify","arguments":{}}}' \
  | $DENT8 mcp serve
