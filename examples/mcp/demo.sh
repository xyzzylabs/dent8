#!/usr/bin/env bash
# Drives `dent8 mcp serve` over stdio with a handful of JSON-RPC 2.0 calls — the firewall an
# agent sees through MCP: facts can be listed, a trusted fact is asserted, a low-authority
# override is REJECTED, `explain` replays the believed fact, and `verify` checks integrity.
#
# Requires the `dent8` binary. Either install it (`cargo install --git
# https://github.com/xyzzylabs/dent8 dent8-cli`) and run `./demo.sh`, or from a clone:
#   DENT8="cargo run -q -p dent8-cli --" ./examples/mcp/demo.sh
set -euo pipefail

DENT8="${DENT8:-dent8}"
DENT8_LOG="$(mktemp -t dent8-mcp-demo.XXXXXX)"
export DENT8_LOG
trap 'rm -f "$DENT8_LOG"' EXIT

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_facts","arguments":{}}}' \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"assert","arguments":{"subject_kind":"repo","subject_key":"myproj","predicate":"database","value":"postgres","authority":"high","source":"owner"}}}' \
  '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"supersede","arguments":{"subject_kind":"repo","subject_key":"myproj","predicate":"database","value":"mysql","authority":"low","source":"web-scrape"}}}' \
  '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"explain","arguments":{"subject_kind":"repo","subject_key":"myproj","predicate":"database"}}}' \
  '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"verify","arguments":{}}}' \
  | $DENT8 mcp serve
