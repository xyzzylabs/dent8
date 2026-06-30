# Agent Adapters

dent8 should meet agents where they already keep durable context, but it should not become a
provider-specific memory provider. The invariant is simple:

> Native memory/rules files are projection and integration surfaces. The source of truth is
> still the dent8 claim-event log.

## Adapter layers

1. **MCP write path, built.** Agents call `dent8 mcp serve` and write candidate facts through
   the same firewall as the CLI.
2. **Hook guard profiles, runnable helper + example profiles.** Hooks call
   `dent8 hook native-memory-guard` to run `dent8 verify` and block direct native
   memory/rules writes that would bypass dent8. Provider profiles live in
   [`examples/agent-hooks/`](../examples/agent-hooks/).
3. **Signed source identity, default build.** Use `dent8 init --agent <profile>` or
   `dent8 init --identity --source <source>` to give each agent a distinct source key and
   issuer-signed grant (`DENT8_GRANT` + `DENT8_IDENTITY_KEY`). Several agents can use the
   same globally installed `dent8` binary and the same backend store, but stdio MCP clients
   typically launch one subprocess per client/profile. Run one `dent8 mcp serve` process per
   agent identity when per-agent provenance matters; a shared MCP process can only prove the
   identity whose key it holds. A future HTTP/daemon transport should authenticate the source
   per request instead of relying on one process-wide identity env.
4. **Native import, design-only.** Read `CLAUDE.md`, Claude `MEMORY.md`, `GEMINI.md`,
   `.cursor/rules`, `.devin/rules`, `.windsurf/rules`, and `AGENTS.md` as low/medium
   authority candidate events. Imported facts need provenance and review.
5. **Native export, design-only.** Generate provider-native Markdown/rules files from dent8
   receipts. Exported files should carry dent8 claim ids and hash receipts in comments.
6. **Reconcile, design-only.** Compare native files with dent8 projections and report stale,
   superseded, unverified, or low-authority facts that are still visible to an agent.

## Provider stance

| Provider | v0 integration | Hook stance |
| --- | --- | --- |
| Codex | MCP through `config.toml`; `AGENTS.md` for durable repo guidance | Good fit: session, pre-tool, post-tool, stop hooks |
| Claude Code | MCP through `.mcp.json`; `CLAUDE.md` and auto memory are native surfaces | Good fit: session/tool/stop hooks |
| Gemini CLI | MCP plus `GEMINI.md`/`/memory`; Auto Memory has review semantics | Good fit: session, before/after tool, session end hooks |
| Cursor | MCP through `.cursor/mcp.json`; `.cursor/rules` and `AGENTS.md` as native surfaces | MCP-first; hook config should be version-checked before team use |
| Devin/Cascade | MCP plus `.devin/rules`/`.windsurf/rules` and auto memories | Good fit: pre/post write hooks |
| Grok Build | MCP profile; often Claude-compatible or supervisor-driven | Reuse Claude/Hecate hook profile when the host exposes hooks |
| Hecate | MCP server in task config; supervised external agents | Use Hecate to distribute MCP and child-agent hook policy |

## v0 rule

Do not auto-write provider native memory from dent8 until export/reconcile exists. A generated
native file can make a stale fact look authoritative to the agent, so exports must be
receipt-bearing and auditable.

The first production-worthy adapter flow is:

```text
agent -> dent8 MCP assert/supersede/retract -> claim-event log
native memory/rules hook -> guard bypasses and run verify
operator -> review explain/replay/conflicts
future export -> regenerate native rules with receipts
```
