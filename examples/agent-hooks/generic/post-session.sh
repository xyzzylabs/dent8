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
# EXIT CODE: `dent8 capture --keep-failed` exits non-zero (2) when it kept invalid lines — that
# is a NORMAL outcome ("invalid lines kept for retry"), not a hook failure. A generic lifecycle
# hook may treat any non-zero exit as a HOOK error and surface it (or, worse, abort the
# session). Following the hardened hooks' "seatbelt, never break the session" philosophy, this
# adapter logs capture's outcome to stderr and then exits 0, swallowing the benign non-zero.
# Set DENT8_STRICT=1 (or true/on/yes) to opt into strict propagation of capture's exit code
# instead.
#
# Mirrors the hardened Claude Code hook: no-op silently when dent8 is absent, source
# .dent8/env when present.
command -v dent8 >/dev/null 2>&1 || exit 0
# shellcheck source=/dev/null
if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi

dent8 capture "${DENT8_PROPOSALS:-.dent8/proposals.jsonl}" --consume --keep-failed
status=$?

if [ "$status" -ne 0 ]; then
  echo "post-session.sh: dent8 capture exited $status (kept-invalid-lines is normal; not a hook failure)" >&2
  strict="$(printf '%s' "${DENT8_STRICT:-}" | tr '[:upper:]' '[:lower:]')"
  case "$strict" in
    1 | true | on | yes) exit "$status" ;;
  esac
fi
exit 0
