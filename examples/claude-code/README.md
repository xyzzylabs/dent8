# dent8 with Claude Code

Claude Code supports local stdio MCP servers. dent8 exposes `dent8 mcp serve`, so Claude Code
can use dent8 as a project memory firewall.

## Local scope

From the target project:

```sh
dent8 init --agent claude-code --install-mcp
```

This patches project `.mcp.json`, preserves unrelated MCP servers, and prints the resulting
file. Check it inside Claude Code with:

```text
/mcp
```

## Project scope

For a local project-scoped setup, run the same install command from the target project. The
installer is idempotent for an existing `.mcp.json`:

```sh
dent8 mcp install --agent claude-code
```

For a team-shared checked-in `.mcp.json`, start from [`mcp.sample.json`](mcp.sample.json)
instead. It uses `${CLAUDE_PROJECT_DIR:-.}` and `${DENT8_BIN:-dent8}` placeholders so one
developer's absolute `.dent8` paths are not committed for everyone else.

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
