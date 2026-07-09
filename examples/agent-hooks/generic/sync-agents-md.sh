#!/usr/bin/env sh
# dent8 generic AGENTS.md adapter: inject / refresh a managed block of the currently-believed
# facts into a static instructions file that many agents read.
#
#   ./sync-agents-md.sh                    # writes/refreshes AGENTS.md
#   ./sync-agents-md.sh .cursor/rules/dent8.mdc
#
# AGENTS.md is honored by Codex, Cursor, Windsurf, Cline, Zed, and aider, so a single managed
# block reaches all of them. The splice is delegated to core's `dent8 export --target`, which
# writes a receipt-bearing dent8-managed block delimited by:
#
#   <!-- BEGIN dent8 managed block ... -->
#   ...currently-believed facts, each with a dent8:// receipt (fact id + event hash) ...
#   <!-- END dent8 managed block -->
#
# Delegating to `dent8 export --target` (rather than splicing with awk here) reuses core's
# hardened, FENCE-AWARE block logic: a fenced literal example of the markers inside a ```code
# block``` in the target file is left untouched — only the real managed block is rewritten. The
# operation is IDEMPOTENT: run it repeatedly and the block is refreshed in place, never
# duplicated; prose outside the markers is preserved; a missing file (or block) is created.
#
# Mirrors the hardened Claude Code hook: no-op silently when dent8 is absent, source
# .dent8/env when present.
command -v dent8 >/dev/null 2>&1 || exit 0
# shellcheck source=/dev/null
if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi

target="${1:-AGENTS.md}"

# `dent8 export --target` writes the file (and refreshes the block) but does not create missing
# parent directories, so create them here for paths like .cursor/rules/dent8.mdc.
dir="$(dirname "$target")"
[ -d "$dir" ] || mkdir -p "$dir"

exec dent8 export --target "$target"
