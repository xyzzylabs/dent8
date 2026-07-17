# Cursor hook profile

Cursor is the one non-Claude tool today that can use **all three** dent8 surfaces: MCP for
live tool-mediated writes, a rules file for context injection, and a lifecycle **hook** that
auto-closes the capture loop. The regular Cursor MCP profile lives at [`../../cursor/`](../../cursor/)
(the authoritative dent8 write path, installed with `dent8 init --agent cursor --install-mcp`);
this directory is about the *wiring* of the three surfaces together.

| Surface | File | dent8 does |
| --- | --- | --- |
| MCP server | [`mcp.sample.json`](mcp.sample.json) → `.cursor/mcp.json` | live `assert`/`explain`/… over stdio |
| Context injection | [`rules/dent8.mdc`](rules/dent8.mdc) → `.cursor/rules/dent8.mdc` | a managed block of `dent8 context` |
| Guard + capture | [`hooks.sample.json`](hooks.sample.json) → `.cursor/hooks.json` | `preToolUse` native-memory guard, `postToolUse` audit, `stop` capture |

## MCP — `.cursor/mcp.json`

```json
{
  "mcpServers": {
    "dent8": {
      "command": "dent8",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

This bare shape is the wiring; for a hardened, per-project profile with `DENT8_LOG` /
`DENT8_AUTHORITY` / signed-identity env vars, use [`../../cursor/mcp.sample.json`](../../cursor/mcp.sample.json)
or let `dent8 init --agent cursor --install-mcp` patch it. Don't ship both blocks in one
`.cursor/mcp.json` — pick the profile version once identity is set up.

## Guard + capture — `.cursor/hooks.json`

Cursor added lifecycle hooks in **Cursor 1.7** (Oct 2025). Prefer **project**
`.cursor/hooks.json` (not `~/.cursor/hooks.json`) so the guard only runs in this repo.

Copy the sample:

```sh
cp examples/agent-hooks/cursor/hooks.sample.json .cursor/hooks.json
```

The sample wires:

- **`preToolUse`** — enforced `dent8 hook native-memory-guard` (blocks direct native-memory writes)
- **`postToolUse`** — post-write audit when those tools run
- **`stop`** — `dent8 capture … --consume --keep-failed` to flush proposals

`dent8 doctor --agent cursor` looks for that file and the same enforce markers as Codex/Claude.

**Context does NOT ride on a hook.** Cursor's `beforeSubmitPrompt` hook is informational per
Cursor's docs — it cannot mutate the outgoing prompt — so context injection must go through the
rules file (below) or MCP, not a hook.

## Context — `.cursor/rules/dent8.mdc`

A rule file with MDC frontmatter (`alwaysApply: true`) carrying a `dent8 context` managed block:

```markdown
---
description: dent8 shared fact base — currently-believed project conventions and decisions
globs:
alwaysApply: true
---

<!-- dent8:begin -->
...currently-believed facts from `dent8 context`...
<!-- dent8:end -->
```

Regenerate the block with the generic adapter — it replaces the block idempotently and never
touches the frontmatter or prose outside the markers:

```sh
../generic/sync-agents-md.sh .cursor/rules/dent8.mdc
```

Cursor's rules system has two generations — flat `.mdc` files (shown here) and newer
`.cursor/rules/<name>/RULE.md` **folders** — both with the same `description` / `globs` /
`alwaysApply` frontmatter. Cursor **also natively reads `AGENTS.md`** as a simpler alternative
to `.cursor/rules`, so `../generic/sync-agents-md.sh AGENTS.md` reaches Cursor too (and every
other AGENTS.md-aware tool at once). See [`../generic/`](../generic/).

## Verified vs Documented

**Verified locally in this repo** (re-run against the built `dent8 0.8.0` binary):

- The dent8 MCP server stdio handshake — `initialize` (protocolVersion `2025-06-18`) returns
  `serverInfo {"name":"dent8","version":"0.8.0"}` and `tools/list` returns all 18 tools. Full
  transcript in [`docs/mcp-clients.md`](../../../docs/mcp-clients.md#verify-it-yourself).
- `dent8 capture … --consume --keep-failed` accepts good proposals and keeps failed lines for
  retry (the `stop`-hook command).
- `dent8 context` and the idempotent `sync-agents-md.sh` block writer that maintains
  `rules/dent8.mdc` — see [`../generic/`](../generic/).

**Documented per Cursor's docs — NOT exercised in this environment** (no Cursor install, and
Cursor's first-party doc hosts were egress-blocked, so syntax follows public docs): Cursor
picking up `.cursor/mcp.json`, running `.cursor/hooks.json` `preToolUse`/`stop` hooks, and applying
`.cursor/rules/*.mdc`. Verify against the Cursor version your team runs:

- MCP: <https://cursor.com/docs/mcp>
- Hooks (shipped 1.7): <https://cursor.com/docs/hooks>
- Rules: <https://cursor.com/docs/context/rules>
