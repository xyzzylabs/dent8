# dent8 with Cursor

Cursor supports local MCP servers through `mcp.json`. dent8 exposes `dent8 mcp serve`,
so Cursor can use dent8 as a project memory firewall while it works in a repository.

## Project scope

From the target project:

```sh
mkdir -p .cursor .dent8
DENT8_AUTHORITY="$PWD/.dent8/authority.json" dent8 authority add source:cursor high
cp /path/to/dent8/examples/cursor/mcp.sample.json .cursor/mcp.json
```

Then edit `.cursor/mcp.json` and replace `/abs/path/to/project` with the project root.

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
