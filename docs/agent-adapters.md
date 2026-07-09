# Agent Adapters

dent8 should meet agents where they already keep durable context, but it should not become a
provider-specific memory provider. The invariant is simple:

> Native memory/rules files are projection and integration surfaces. The source of truth is
> still the dent8 fact-event log.

## Bypass boundary

dent8 prevents silent corruption on write paths it controls: CLI, MCP, daemon, and store
adapters that call `EventStore::append`. It does not sandbox a same-user agent. If an agent can
write provider-native memory/rules files directly, mutate the dev file log, or use raw database
write credentials, it can bypass dent8's policy layer.

For local dogfood this is acceptable only with guardrails: install the native-memory hook guard
for every agent profile that supports hooks, keep provider-native memory files as generated or
reviewed surfaces rather than truth, run `dent8 doctor --agent <profile> --write-check`, and use
`dent8 verify` plus witness heads to detect raw-store tampering. For shared or production use,
make a dent8 daemon/service the only writer and give agents no raw `INSERT`/`UPDATE`/`DELETE`
access to the event tables.

## Adapter layers

1. **MCP write path, built.** Agents call `dent8 mcp serve` and write candidate facts through
   the same firewall as the CLI.
2. **Hook guard profiles, runnable helper + example profiles.** Hooks call
   `dent8 hook native-memory-guard` to run `dent8 verify` and block direct native
   memory/rules writes that would bypass dent8. Provider profiles live in
   [`examples/agent-hooks/`](../examples/agent-hooks/).
3. **Native scan/reconcile, built.** `dent8 native scan --agent <profile>` inventories
   provider-native memory/rules files, hashes them, reports dent8 receipt markers, and includes
   the selected profile's guard posture. `dent8 native reconcile --agent <profile>` verifies
   explicit `dent8://<kind>/<key>/<predicate>` references against current dent8 receipts and
   flags stale, contested, no-longer-believed, missing, or malformed references. The same
   diagnostics/audits are exposed to agents over MCP as read-only `runtime_status`,
   `native_scan`, and `native_reconcile`;
   `doctor --agent` runs the read-only scan. This is audit, not import.
4. **Signed source identity, default build.** Use `dent8 init --agent <profile>` or
   `dent8 init --identity --source <source>` to give each agent a distinct source key and
   issuer-signed grant (`DENT8_GRANT` + `DENT8_IDENTITY_KEY`). Several agents can use the
   same globally installed `dent8` binary and the same backend store, but stdio MCP clients
   typically launch one subprocess per client/profile. Run one `dent8 mcp serve` process per
   agent identity when per-agent provenance matters. The local daemon supports
   session-challenge writes, and `dent8 mcp proxy` lets stdio-only MCP clients use that daemon,
   but each daemon process still proves the single source identity whose key it holds; use
   `dent8 mcp install --agent <profile> --use-daemon` (or `--daemon-socket PATH`) to patch a
   known agent config to proxy mode, and use separate daemon instances for distinct local source
   identities.
   Future remote HTTP transport should authenticate the source per request without requiring
   the service to hold user source keys.
5. **Native import, built.** `dent8 import <file>` reads durable facts from `CLAUDE.md`,
   Claude `MEMORY.md`, `GEMINI.md`, `.cursor/rules`, `.devin/rules`, `.windsurf/rules`, and
   `AGENTS.md` with deterministic, documented rules (dent8 managed block, inline `dent8://`
   receipt markers, and fenced `dent8` proposal blocks) and routes every recovered proposal
   through the same firewall funnel as `dent8 capture` — authority, policy, and the content
   check all apply, and free prose is skipped, never invented. See
   [native-memory.md](native-memory.md).
6. **Native export, built.** `dent8 export --target <file>` generates provider-native
   Markdown/rules files from dent8 receipts: it splices a receipt-bearing **managed block**
   (each line carrying a `dent8://` reference plus the believed event's id and hash) into the
   target file idempotently, preserving human prose outside the block, and writes the file from
   the CLI process — the channel the write-time guard does not intercept. See
   [native-memory.md](native-memory.md).
7. **Native rewrite/reconcile loop, design-only.** Go beyond explicit receipt references:
   compare native prose with dent8 projections, propose import candidates, and regenerate
   receipt-bearing provider-native files.

## Provider stance

| Provider | v0 integration (prefer **project** MCP config) | Hook stance |
| --- | --- | --- |
| Codex | MCP through project `.codex/config.toml`; `AGENTS.md` for durable repo guidance | Good fit: session, pre-tool, post-tool, stop hooks |
| Claude Code | MCP through project `.mcp.json`; `CLAUDE.md` and auto memory are native surfaces | Good fit: session/tool/stop hooks |
| Gemini CLI | MCP plus `GEMINI.md`/`/memory`; Auto Memory has review semantics | Good fit: session, before/after tool, session end hooks |
| Cursor | MCP through project `.cursor/mcp.json`; `.cursor/rules` and `AGENTS.md` as native surfaces | Project `.cursor/hooks.json` (`preToolUse` guard + `stop` capture); schema is Cursor 1.7+ |
| Devin/Cascade | MCP plus `.devin/rules`/`.windsurf/rules` and auto memories | Good fit: pre/post write hooks |
| Grok Build | MCP via project `.grok/config.toml` (or `.mcp.json` when not shared with Claude) | Project `.grok/hooks/dent8.json` (Claude-compatible events); folder must be trusted |
| Hecate | MCP server in task config; supervised external agents | Use Hecate to distribute MCP and child-agent hook policy |

## v0 rule

A generated native file can make a stale fact look authoritative to the agent, so exports must
be receipt-bearing and auditable — which `dent8 export --target` is: it only emits currently
believed facts, each carrying a `dent8://` reference plus its event id and hash, and never
writes a redacted value. Regenerate the managed block rather than hand-editing it; the
`PreToolUse` guard blocks direct edits so `dent8 export` stays the source of truth.

The first production-worthy adapter flow is:

```text
agent -> dent8 MCP assert/supersede/retract -> fact-event log
native memory/rules hook -> guard blocks direct edits and runs verify
operator -> review explain/replay/conflicts
dent8 import -> pull durable facts out of an existing/stale native file (through the firewall)
dent8 export --target -> regenerate native rules with receipts
native reconcile -> verify generated receipt references stay current
```
