# dent8 with Grok Build

dent8 exposes a plain stdio MCP server (`dent8 mcp serve`). Grok Build is **Claude Code
compatible**: it reads a project-root `.mcp.json`, so the sample `mcpServers` block works
as-is via that path.

If a Grok Build environment only accepts remote MCP servers, dent8 needs an MCP HTTP bridge
or a future HTTP transport; v0 is stdio.

## Local MCP profile

Grok Build accepts Claude Code's project-root `.mcp.json`, **and** a native config —
`[mcp_servers.dent8]` in `~/.grok/config.toml` (user) or `.grok/config.toml` (project),
the same TOML shape as the [Codex example](../codex/config.sample.toml) — or
`grok mcp add dent8 -- …`.

When this repo already dogfoods Claude Code on `.mcp.json` (bound to
`source:claude-code`), **do not** overwrite that file for Grok. Add Grok as a second
agent and keep its MCP entry separate:

```sh
cd /abs/path/to/project
# Shared store already exists:
dent8 agent add --agent grok-build --mcp-local-bin \
  --mcp-config .dent8/mcp-grok-build.json
# Wire Grok's native config from the generated env (user or project scope):
grok mcp add dent8 --scope project \
  -e DENT8_STORE_URL=… -e DENT8_GRANT=… -e DENT8_IDENTITY_KEY=… \
  -- .dent8/bin/dent8 mcp serve
```

Fresh project (no Claude `.mcp.json` yet):

```sh
dent8 init --agent grok-build --install-mcp --mcp-local-bin
```

Re-run `dent8 mcp install --agent grok-build` (or `agent add` with the same
`--mcp-config`) to regenerate later. Doctor:

```sh
dent8 doctor --agent grok-build --dir .dent8 \
  --mcp-config .dent8/mcp-grok-build.json --write-check
```

## Prompt Grok Build

```text
Before relying on durable project facts, inspect dent8 with `runtime_status`, then
`list_facts` or `explain`.
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

## Optional hook guard

If your Grok Build host exposes Claude-compatible hooks, adapt the Claude Code sample in
[`../agent-hooks/claude-code/settings.sample.json`](../agent-hooks/claude-code/settings.sample.json).
If Grok Build is supervised through Hecate, put the hook policy at the Hecate or child-agent
profile layer instead. See [`../agent-hooks/grok-build/`](../agent-hooks/grok-build/).
