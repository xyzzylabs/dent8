#!/usr/bin/env sh
# dent8 generic pre-session adapter: emit the believed-facts context pack to stdout.
#
# This is the universal "prepend to your prompt / system message" primitive. Any agent
# framework that can run a command and capture its stdout can inject dent8's shared fact base
# with it. Flags are passed through, e.g.:
#
#   ./pre-session.sh                 # markdown pack (default)
#   ./pre-session.sh -o json         # machine-readable pack
#   ./pre-session.sh --kind repo     # only repo:* facts
#
# Mirrors the hardened Claude Code SessionStart hook (.claude/settings.json): no-op silently
# when dent8 is absent, source .dent8/env when present.
command -v dent8 >/dev/null 2>&1 || exit 0
if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi

exec dent8 context "$@"
