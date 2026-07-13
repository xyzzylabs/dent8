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

## Native-memory guard (installed by default)

`dent8 init --agent cursor` already wires an **enforced** native-memory `preToolUse` guard into
`.cursor/hooks.json` (Cursor 1.7+) by default (opt out with `dent8 init
--no-native-memory-guard`). To customize it or add the `stop` capture, merge the project hook
profile from
[`../agent-hooks/cursor/hooks.sample.json`](../agent-hooks/cursor/hooks.sample.json) into
`.cursor/hooks.json`; prefer project scope over `~/.cursor/hooks.json` for a single-repo store.
