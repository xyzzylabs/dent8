# dent8 with Claude Code

Claude Code supports local stdio MCP servers. dent8 exposes `dent8 mcp serve`, so Claude Code
can use dent8 as a project memory firewall.

## Local scope

From the target project:

```sh
mkdir -p .dent8
DENT8_AUTHORITY="$PWD/.dent8/authority.json" dent8 authority add source:claude-code high

claude mcp add \
  --env DENT8_LOG="$PWD/.dent8/claude-memory.jsonl" \
  --env DENT8_AUTHORITY="$PWD/.dent8/authority.json" \
  --env DENT8_REQUIRE_AUTHORITY=1 \
  --transport stdio \
  dent8 -- dent8 mcp serve
```

Check it inside Claude Code with:

```text
/mcp
```

## Project scope

For a team-shared setup, copy [`mcp.sample.json`](mcp.sample.json) to `.mcp.json` in the
target project. Claude Code supports `${CLAUDE_PROJECT_DIR:-.}` expansion in `.mcp.json`, so
the sample keeps the log and authority file under the project root.

```sh
cp /path/to/dent8/examples/claude-code/mcp.sample.json .mcp.json
mkdir -p .dent8
DENT8_AUTHORITY="$PWD/.dent8/authority.json" dent8 authority add source:claude-code high
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
