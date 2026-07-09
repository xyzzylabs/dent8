# dent8 with Cursor

Cursor supports local MCP servers through `mcp.json`. dent8 exposes `dent8 mcp serve`,
so Cursor can use dent8 as a project memory firewall while it works in a repository.

## Project scope

From the target project:

```sh
dent8 init --agent cursor --install-mcp
```

This patches `.cursor/mcp.json`, preserves unrelated MCP servers, and prints the resulting
file. Re-run `dent8 mcp install --agent cursor` to regenerate it later.

## Scope note

Prefer **project** `.cursor/mcp.json` so the server only attaches in this repository.
Avoid `~/.cursor/mcp.json` for a single-repo dogfood or team store — a user-global entry
loads that store in every Cursor workspace. If you intentionally run one personal global
store, keep its paths distinct from any project `.dent8` bundle.

## Prompt Cursor

```text
Before relying on durable project facts, inspect dent8 with `runtime_status`, then
`list_facts` or `explain`.
Record stable project facts in dent8 using source:cursor and the lowest adequate authority.
Use contradict for uncertain conflicts and supersede only when replacing a believed fact.
Run verify before broad edits that depend on remembered facts.
```

Useful first facts:

```text
repo:<project> database
repo:<project> test_command
dependency:<package> version
branch:<branch> status
user:<name> preference
```

## Optional hook/rules guard

Cursor should use dent8 through MCP first. Install the project hook profile from
[`../agent-hooks/cursor/hooks.sample.json`](../agent-hooks/cursor/hooks.sample.json) into
`.cursor/hooks.json` for an enforced native-memory `preToolUse` guard and `stop` capture
(Cursor 1.7+). Prefer project scope over `~/.cursor/hooks.json` for a single-repo store.
