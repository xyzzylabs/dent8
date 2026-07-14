# dent8 with Grok Build

dent8 exposes a plain stdio MCP server (`dent8 mcp serve`). Grok Build is **Claude Code
compatible**: it reads a project-root `.mcp.json`, so the sample `mcpServers` block works
as-is via that path.

If a Grok Build environment only accepts remote MCP servers, dent8 needs an MCP HTTP bridge
or a future HTTP transport; v0 is stdio.

## Local MCP profile

Grok Build accepts Claude Code's project-root `.mcp.json`, **and** a native config —
`[mcp_servers.dent8]` in project `.grok/config.toml` (preferred for dogfood) or
`~/.grok/config.toml` (user-global; avoid for a single-repo store), the same TOML
shape as the [Codex example](../codex/config.sample.toml) — or `grok mcp add dent8 -- …`.

When this repo already dogfoods Claude Code on `.mcp.json` (bound to
`source:claude-code`), **do not** overwrite that file for Grok. Add Grok as a second
agent; dent8 writes Grok's native **project-scoped** `.grok/config.toml` by default so
other Grok sessions do not attach this store:

```sh
cd /abs/path/to/project
# Shared store already exists:
dent8 agent add --agent grok-build --mcp-local-bin
# Do not use --scope user for a repo dogfood store.
```

Fresh project (no Claude `.mcp.json` yet):

```sh
dent8 init --agent grok-build --install-mcp --mcp-local-bin
```

Re-run `dent8 mcp install --agent grok-build` (or `agent add`) to regenerate later.
Use `--mcp-config .mcp.json` only when you intentionally want Grok's Claude-compatible JSON
path. Doctor:

```sh
dent8 doctor --agent grok-build --dir .dent8 --write-check
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

## Native-memory guard (installed by default)

`dent8 init --agent grok-build` already wires an **enforced** native-memory guard into
`.grok/hooks/dent8.json` by default (opt out with `dent8 init --no-native-memory-guard`). To
customize it, overwrite that file with the project hook sample (not `~/.grok/hooks/`):

```sh
mkdir -p .grok/hooks
cp examples/agent-hooks/grok-build/hooks.sample.json .grok/hooks/dent8.json
```

Trust the project (`/hooks-trust`) so Grok loads project hooks. See
[`../agent-hooks/grok-build/`](../agent-hooks/grok-build/). If Grok is supervised through
Hecate, prefer the supervisor-layer policy instead.
