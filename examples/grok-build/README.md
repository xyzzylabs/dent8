# dent8 with Grok Build

dent8 exposes a plain stdio MCP server (`dent8 mcp serve`). Use the sample `mcpServers`
block anywhere Grok Build asks for local MCP server configuration.

Public MCP setup details for Grok Build are less stable/visible than Codex, Claude Code, or
Cursor at the time of writing, so this example intentionally stays client-neutral: it is the
server profile dent8 expects the host to launch. If a Grok Build environment only accepts
remote MCP servers, dent8 needs an MCP HTTP bridge or a future HTTP transport; v0 is stdio.

## Local MCP profile

Copy [`mcp.sample.json`](mcp.sample.json) into the Grok Build MCP configuration location, or
paste the `dent8` entry into an existing `mcpServers` block. Replace `/abs/path/to/project`
with the target repository root.

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
