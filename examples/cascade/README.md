# dent8 with Devin/Cascade

Cascade can use local MCP servers through its MCP config. dent8 exposes
`dent8 mcp serve`, so Cascade can use dent8 as a memory firewall while `.devin/rules`,
`.windsurf/rules`, `.windsurfrules`, and `AGENTS.md` remain native guidance surfaces.

## MCP config

From the target project:

```sh
dent8 init --agent cascade --install-mcp
```

This patches `.windsurf/mcp_config.json`, preserves unrelated MCP servers, and prints the
resulting file. For the desktop app's global config, pass an explicit path:

```sh
dent8 mcp install --agent cascade --config "$HOME/.codeium/windsurf/mcp_config.json"
```

For a team-shared setup, add `dent8` to the workspace MCP allowlist if your Cascade policy
requires explicit MCP server approval.

## Prompt Cascade

```text
Before relying on durable project facts, inspect dent8 with list_facts or explain.
Record stable project facts in dent8 using source:cascade and the lowest adequate authority.
Use contradict for uncertain conflicts and supersede only when replacing a believed fact.
Run verify before broad edits that depend on remembered facts.
Treat .devin/rules, .windsurf/rules, .windsurfrules, and AGENTS.md as native guidance files, not the source of truth for stable project facts.
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

After MCP works, copy
[`../agent-hooks/cascade/hooks.sample.json`](../agent-hooks/cascade/hooks.sample.json) to
`.windsurf/hooks.json` or merge its `pre_write_code` / `post_write_code` entries into your
existing hooks. The guard blocks direct native memory/rules writes when
`DENT8_HOOK_ENFORCE=1` and runs `dent8 verify` after relevant writes.
