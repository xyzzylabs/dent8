# dent8 with Grok Build

dent8 exposes a plain stdio MCP server (`dent8 mcp serve`). Grok Build is **Claude Code
compatible**: it reads a project-root `.mcp.json`, so the sample `mcpServers` block works
as-is via that path.

If a Grok Build environment only accepts remote MCP servers, dent8 needs an MCP HTTP bridge
or a future HTTP transport; v0 is stdio.

## Local MCP profile

Easiest: run the installer from the target project. Grok Build reads Claude Code's
project-root `.mcp.json`, so dent8 patches that file, preserves unrelated MCP servers, and
prints the result.

Grok Build also has a **native** config — `[mcp_servers.dent8]` in `~/.grok/config.toml`
(global) or `.grok/config.toml` (project), the same TOML shape as the
[Codex example](../codex/config.sample.toml) — or add it via
`grok mcp add dent8 --command dent8 --args "mcp serve"`.

```sh
cd /abs/path/to/project
dent8 init --agent grok-build --install-mcp
```

Re-run `dent8 mcp install --agent grok-build` to regenerate the config later.

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

## Optional hook guard

If your Grok Build host exposes Claude-compatible hooks, adapt the Claude Code sample in
[`../agent-hooks/claude-code/settings.sample.json`](../agent-hooks/claude-code/settings.sample.json).
If Grok Build is supervised through Hecate, put the hook policy at the Hecate or child-agent
profile layer instead. See [`../agent-hooks/grok-build/`](../agent-hooks/grok-build/).
