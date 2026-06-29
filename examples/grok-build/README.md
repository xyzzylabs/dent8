# dent8 with Grok Build

dent8 exposes a plain stdio MCP server (`dent8 mcp serve`). Grok Build is **Claude Code
compatible**: it reads a project-root `.mcp.json`, so the sample `mcpServers` block works
as-is via that path.

If a Grok Build environment only accepts remote MCP servers, dent8 needs an MCP HTTP bridge
or a future HTTP transport; v0 is stdio.

## Local MCP profile

Easiest: drop [`mcp.sample.json`](mcp.sample.json) at the project root as `.mcp.json` (Grok
Build reads Claude Code's `.mcp.json`), or paste the `dent8` entry into an existing
`mcpServers` block. Replace `/abs/path/to/project` with the target repository root.

Grok Build also has a **native** config — `[mcp_servers.dent8]` in `~/.grok/config.toml`
(global) or `.grok/config.toml` (project), the same TOML shape as the
[Codex example](../codex/config.sample.toml) — or add it via
`grok mcp add dent8 --command dent8 --args "mcp serve"`.

```sh
mkdir -p /abs/path/to/project/.dent8
DENT8_AUTHORITY=/abs/path/to/project/.dent8/authority.json \
  dent8 authority add source:grok-build high
```

## Prompt Grok Build

```text
Before relying on durable project facts, inspect dent8 with list_facts or explain.
Record stable project facts in dent8 using source:grok-build and the lowest adequate authority.
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
