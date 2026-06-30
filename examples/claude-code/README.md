# dent8 with Claude Code

Claude Code supports local stdio MCP servers. dent8 exposes `dent8 mcp serve`, so Claude Code
can use dent8 as a project memory firewall.

## Local scope

From the target project:

```sh
dent8 init --agent claude-code

claude mcp add \
  --env DENT8_LOG="$PWD/.dent8/claude-memory.jsonl" \
  --env DENT8_AUTHORITY="$PWD/.dent8/authority.json" \
  --env DENT8_REQUIRE_AUTHORITY=1 \
  --env DENT8_TRUST="$PWD/.dent8/trust.json" \
  --env DENT8_REQUIRE_IDENTITY=1 \
  --env DENT8_GRANT="$PWD/.dent8/grants/source_claude-code.grant.json" \
  --env DENT8_IDENTITY_KEY="$PWD/.dent8/identities/source_claude-code.key" \
  --transport stdio \
  dent8 -- dent8 mcp serve
```

Check it inside Claude Code with:

```text
/mcp
```

## Project scope

For a team-shared setup, copy [`mcp.sample.json`](mcp.sample.json) to `.mcp.json` in the
target project. Claude Code supports `${VAR:-default}` expansion in `.mcp.json`, so the sample
keeps the log and authority file under `${CLAUDE_PROJECT_DIR:-.}` (the project root) and
launches `${DENT8_BIN:-dent8}` — set `DENT8_BIN` to point at a specific build (e.g. a local
checkout's `target/debug/dent8`), or leave it unset to use `dent8` from `PATH`.

```sh
cp /path/to/dent8/examples/claude-code/mcp.sample.json .mcp.json
dent8 init --agent claude-code
```

Claude Code prompts before using project-scoped MCP servers from `.mcp.json`; approve dent8
when it asks.

## Prompt Claude Code

```text
Before relying on durable project facts, inspect dent8 with list_facts or explain.
Record stable project facts in dent8 using source:claude-code and the lowest adequate authority.
Use contradict for uncertain conflicts and supersede only when replacing a believed fact.
Run verify before making broad changes that depend on remembered facts.
```

Useful first facts:

```text
repo:<project> database
repo:<project> test_command
dependency:<package> version
branch:<branch> status
user:<name> preference
```

## Optional hook guard

After MCP works, merge
[`../agent-hooks/claude-code/settings.sample.json`](../agent-hooks/claude-code/settings.sample.json)
into `.claude/settings.json` or another Claude Code settings scope. The sample blocks direct
edits to `CLAUDE.md`, `MEMORY.md`, and `AGENTS.md` unless you explicitly set
`DENT8_ALLOW_NATIVE_MEMORY_WRITE=1`.
