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

## Global scope

Use the same JSON shape in `~/.cursor/mcp.json` when you want one global dent8 server entry.
Prefer per-project logs (`DENT8_LOG`) and authority registries (`DENT8_AUTHORITY`) so one
workspace cannot accidentally inherit another workspace's facts.

## Prompt Cursor

```text
Before relying on durable project facts, inspect dent8 with list_facts or explain.
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

Cursor should use dent8 through MCP first. See [`../agent-hooks/cursor/`](../agent-hooks/cursor/)
for the current hook stance: guard `.cursor/rules/` and `AGENTS.md` only after confirming the
hook schema for the Cursor version your team runs.
