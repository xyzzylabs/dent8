# dent8 with Claude Code

Claude Code supports local stdio MCP servers. dent8 exposes `dent8 mcp serve`, so Claude Code
can use dent8 as a project memory firewall.

## Project scope

From the target project:

```sh
dent8 init --agent claude-code --install-mcp
```

This patches **project** `.mcp.json` (not Claude user-global MCP settings), preserves
unrelated MCP servers, and prints the resulting file. Re-run
`dent8 mcp install --agent claude-code` later; the installer is idempotent. Prefer project
scope so other repos do not inherit this store. Check it inside Claude Code with:

```text
/mcp
```

For a team-shared checked-in `.mcp.json`, start from [`mcp.sample.json`](mcp.sample.json)
instead. It uses `${CLAUDE_PROJECT_DIR:-.}` and `${DENT8_BIN:-dent8}` placeholders so one
developer's absolute `.dent8` paths are not committed for everyone else.

Claude Code prompts before using project-scoped MCP servers from `.mcp.json`; approve dent8
when it asks.

## Prompt Claude Code

```text
Before relying on durable project facts, inspect dent8 with `runtime_status`, then
`list_facts` or `explain`.
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

## Native-memory guard (installed by default)

`dent8 init --agent claude-code` already wires an **enforced** `PreToolUse` native-memory guard
into `.claude/settings.json`, so direct edits to `CLAUDE.md`, `MEMORY.md`, and `AGENTS.md` are
blocked out of the box (opt out with `dent8 init --no-native-memory-guard`; per write,
`DENT8_ALLOW_NATIVE_MEMORY_WRITE=1` is the sanctioned bypass and `DENT8_HOOK_ENFORCE=0` softens
it to advisory). To customize the guard or layer the fuller session loop on top, merge
[`../agent-hooks/claude-code/settings.sample.json`](../agent-hooks/claude-code/settings.sample.json)
into `.claude/settings.json` or another Claude Code settings scope.
