#!/bin/sh
# One write for the compose demo lane. Authority is deny-by-default for unlisted sources.
# Use agent-tier authority so the demo does not need a signed identity bootstrap.
set -eu
reg="${DENT8_AUTHORITY:-/tmp/authority.json}"
rm -f "$reg"
export DENT8_AUTHORITY="$reg"
export DENT8_REQUIRE_AUTHORITY=1
dent8 authority add source:owner low
exec dent8 assert repo:operated-demo database postgres \
  --authority low --source source:owner
