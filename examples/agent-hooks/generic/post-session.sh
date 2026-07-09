#!/usr/bin/env sh
# dent8 generic post-session adapter: flush the agent's queued fact proposals through the
# firewall at session end.
#
# The agent (or a wrapper) appends JSON-line proposals to $DENT8_PROPOSALS during the session;
# this drains that queue through the same authority/policy/content-check funnel as every other
# dent8 write. `--consume` truncates the file so it is not replayed next session;
# `--keep-failed` retains rejected/malformed lines (accepted lines are still removed) so they
# can be inspected or retried instead of surviving only in hook logs.
#
# Override the queue path with DENT8_PROPOSALS (default .dent8/proposals.jsonl — matching the
# live Claude Code SessionEnd hook in .claude/settings.json).
#
# Mirrors the hardened Claude Code hook: no-op silently when dent8 is absent, source
# .dent8/env when present.
command -v dent8 >/dev/null 2>&1 || exit 0
if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi

exec dent8 capture "${DENT8_PROPOSALS:-.dent8/proposals.jsonl}" --consume --keep-failed
