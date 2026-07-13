# Connect any MCP client

dent8 speaks **JSON-RPC 2.0 over newline-delimited stdio** via `dent8 mcp serve`. Any
MCP-capable client — Cursor, Windsurf, Cline, Claude Desktop/Code, Zed, Codex CLI, or your own
— can connect and use the shared fact base as a memory firewall: a low-authority or stale write
can't silently override a trusted fact, a contradiction surfaces instead of overwriting, and
every believed fact is replayable with an integrity receipt.

This is the canonical, client-agnostic guide. For the belief model and env-var reference see
[`examples/mcp/README.md`](../examples/mcp/README.md); for per-agent installers see the
`examples/<agent>/` profiles.

**Scope:** install the server in the **project** agent config (repo-local `.mcp.json`,
`.codex/config.toml`, `.cursor/mcp.json`, `.grok/config.toml`, and so on) when the store is
that project's belief base. User-global MCP config attaches the same store in every
workspace — fine for one intentional personal store, wrong for multi-agent repo dogfood.

## Tools and access

The server exposes **17 tools** plus readable `dent8://{kind}/{key}/{predicate}` resources.
**7 are write tools** and are gated off under read-only access (an unauthenticated daemon
connection): `assert`, `supersede`, `retract`, `contradict`, `derive`, `reinforce`, `expire`.
The other 10 are read/audit and always available: `runtime_status`, `snapshot`, `list_facts`,
`verify`, `conflicts`, `native_scan`, `native_reconcile`, `explain`, `replay`, `whatif`. A stdio server
(the configs below) runs with full access; a rejected write comes back as a tool **error with
the reason**, so the agent learns *why*.

## Verify it yourself

**Verified locally** — the following was run against the built `dent8 0.8.0` binary in a fresh
`git init` directory (no pre-existing `.dent8` store is needed; `initialize`/`tools/list` work
against an empty dev store). Copy-paste one-liner:

```sh
printf '%s\n' \
 '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"manual","version":"0"}}}' \
 '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
 '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
 | dent8 mcp serve
```

The `initialize` response (id 1) — verbatim, pretty-printed:

```json
{
  "id": 1,
  "jsonrpc": "2.0",
  "result": {
    "capabilities": {
      "resources": {},
      "tools": { "listChanged": false }
    },
    "instructions": "dent8 is a memory integrity firewall for durable agent facts. Before relying on project facts, call snapshot (or runtime_status/list_facts for narrower checks), then explain as needed. Record stable facts with assert using truthful source and authority. When the connection has a signed source grant, write tools may omit source and authority. Use supersede for corrections, contradict for disputes, derive for facts based on other facts. Use native_scan/native_reconcile to audit provider-native memory/rules files when available. Treat rejected writes as safety signals; do not silently overwrite.",
    "protocolVersion": "2025-06-18",
    "serverInfo": { "name": "dent8", "version": "0.8.0" }
  }
}
```

The `notifications/initialized` notification produces no response, as expected. The `tools/list`
response (id 2) returns all **17** tools, in this order:

```text
runtime_status  snapshot  list_facts  verify  conflicts  native_scan  native_reconcile
assert  supersede  retract  contradict  reinforce  expire  derive  explain  replay  whatif
```

Each tool carries an `inputSchema` and an `outputSchema`. The server prefers protocol version
`2025-11-25` and also speaks `2025-06-18` (echoing back the client's requested version when
supported). For a scripted round-trip that also asserts a fact and watches the firewall reject
a low-authority override, run [`examples/mcp/demo.sh`](../examples/mcp/demo.sh).

## Client config matrix

Each block below is **config per that client's docs; the dent8 server side verified above is
what's exercised here — the client picking up the config is not exercised in this environment**
(no client installs; first-party doc hosts were egress-blocked, so syntax follows public docs).
Verify against the client version your team runs.

### 1. Standard `mcpServers` JSON — Cursor, Windsurf, Cline, Claude Desktop/Code

The canonical, most-widely-copied shape. File location differs per client: `.cursor/mcp.json`
(Cursor), `~/.codeium/windsurf/mcp_config.json` (Windsurf), `cline_mcp_settings.json` in VS
Code global storage (Cline), the client's MCP config (Claude Desktop/Code).

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

Cline adds two optional keys per entry — `"alwaysAllow": []` and `"disabled": false`.
Docs: [Cursor](https://cursor.com/docs/mcp) ·
[Windsurf](https://docs.windsurf.com/windsurf/cascade/mcp) ·
[Cline](https://docs.cline.bot/mcp/configuring-mcp-servers).

### 2. Zed — top-level `context_servers` (NOT `mcpServers`)

Zed **diverges**: the top-level key is `context_servers`, and each entry adds `enabled` and
`source`. File: `~/.config/zed/settings.json` (global) or `.zed/settings.json` (project).

```json
{
  "context_servers": {
    "dent8": {
      "enabled": true,
      "source": "custom",
      "command": "dent8",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

Docs: <https://zed.dev/docs/ai/mcp>. Zed's project context otherwise rides on `AGENTS.md` (see
below), which the generic adapter maintains.

### 3. Codex CLI — `[mcp_servers.dent8]` TOML (NOT JSON)

Codex **diverges**: config is **TOML** in `.codex/config.toml` in a trusted project
(preferred for a repo store) or `~/.codex/config.toml` (user-global), and the table is
`mcp_servers` (underscore).

```toml
[mcp_servers.dent8]
command = "dent8"
args = ["mcp", "serve"]
# optional:
# startup_timeout_sec = 10
# tool_timeout_sec = 60
```

Env for a Codex server splits into `env_vars = ["NAME", …]` (passthrough names) and an explicit
`[mcp_servers.dent8.env]` sub-table. Docs:
<https://developers.openai.com/codex/mcp>. See also [`examples/codex/`](../examples/codex/).

> **Two shapes to remember:** everyone else uses `mcpServers` JSON; **Zed** uses
> `context_servers` JSON and **Codex** uses `mcp_servers` TOML. aider has no MCP support as of
> mid-2026 — reach it through `AGENTS.md` / `--read` instead (see
> [`examples/agent-hooks/generic/`](../examples/agent-hooks/generic/)).

## Environment the server honors

The stock `env: {}` above works against the discovered `.dent8/` store. For a hardened,
signed-identity setup the server honors `DENT8_LOG`, `DENT8_AUTHORITY`,
`DENT8_REQUIRE_AUTHORITY`, `DENT8_TRUST`, `DENT8_REQUIRE_IDENTITY`, `DENT8_GRANT`, and
`DENT8_IDENTITY_KEY` — documented with a full example block in
[`examples/mcp/README.md`](../examples/mcp/README.md). Set `DENT8_STORE_URL` for an operational
backend (`sqlite://` in the stock build; `postgres://` needs a `--features postgres` build).

## See also

- [`examples/mcp/`](../examples/mcp/) — belief model, env-var reference, and `demo.sh`.
- Per-agent profiles: [Codex](../examples/codex/), [Claude Code](../examples/claude-code/),
  [Cursor](../examples/cursor/), [Gemini](../examples/gemini/), [Cascade](../examples/cascade/),
  [Grok Build](../examples/grok-build/), [Hecate](../examples/hecate/).
- [`examples/agent-hooks/generic/`](../examples/agent-hooks/generic/) — the static-file /
  wrapper path for tools without an MCP client.
- [`docs/agent-adapters.md`](agent-adapters.md) — the adapter layers and bypass boundary.
