#!/usr/bin/env sh
# dent8 generic AGENTS.md adapter: inject / refresh a managed block of `dent8 context` output
# into a static instructions file that many agents read.
#
#   ./sync-agents-md.sh                    # writes/refreshes AGENTS.md
#   ./sync-agents-md.sh .cursor/rules/dent8.mdc
#
# AGENTS.md is honored by Codex, Cursor, Windsurf, Cline, Zed, and aider, so a single managed
# block reaches all of them. The block is delimited by:
#
#   <!-- dent8:begin -->
#   ...currently-believed facts from `dent8 context`...
#   <!-- dent8:end -->
#
# The script is IDEMPOTENT: run it repeatedly and the block is replaced in place, never
# duplicated. If the target (or the block) does not exist it is created. Prose outside the
# markers is preserved untouched.
#
# Mirrors the hardened Claude Code hook: no-op silently when dent8 is absent, source
# .dent8/env when present.
command -v dent8 >/dev/null 2>&1 || exit 0
if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi

target="${1:-AGENTS.md}"

# Build the managed block (markers + fresh context pack) in a temp file.
block="$(mktemp "${TMPDIR:-/tmp}/dent8-block.XXXXXX")" || exit 1
trap 'rm -f "$block"' EXIT
{
  printf '%s\n' '<!-- dent8:begin -->'
  dent8 context
  printf '%s\n' '<!-- dent8:end -->'
} >"$block"

# First run against a missing file: create it from the block alone.
if [ ! -f "$target" ]; then
  dir="$(dirname "$target")"
  [ -d "$dir" ] || mkdir -p "$dir"
  cp "$block" "$target"
  exit 0
fi

# Otherwise splice: replace the existing block in place, or append one if absent. awk reads
# the whole target; when it meets the begin marker it emits the new block and skips through
# the old end marker. If no begin marker is present, the block is appended at EOF.
tmp="$(mktemp "${TMPDIR:-/tmp}/dent8-target.XXXXXX")" || exit 1
awk -v blockfile="$block" '
  BEGIN { begin = "<!-- dent8:begin -->"; end = "<!-- dent8:end -->"; inblock = 0; done = 0 }
  {
    if ($0 == begin && !done) {
      while ((getline line < blockfile) > 0) print line
      close(blockfile)
      inblock = 1; done = 1
      next
    }
    if (inblock) {
      if ($0 == end) inblock = 0
      next
    }
    print
  }
  END {
    if (!done) {
      if (NR > 0) print ""
      while ((getline line < blockfile) > 0) print line
      close(blockfile)
    }
  }
' "$target" >"$tmp"

mv "$tmp" "$target"
