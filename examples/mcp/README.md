# dent8 as an agent's memory firewall (MCP)

`dent8 mcp serve` is a stdio **JSON-RPC 2.0 MCP server** that exposes dent8's full belief
surface as tools. Point any MCP client at it and the agent's project memory is *firewalled*:
a low-authority or stale write can't silently override a trusted fact, a contradiction
surfaces instead of overwriting, and every believed fact is replayable with an integrity
receipt.

## Wire it into an MCP client

For a known agent, initialize a protected local profile and let dent8 patch the MCP config:

```sh
dent8 init --agent codex --install-mcp
dent8 doctor --agent codex --write-check
```

Use `dent8 mcp install --agent <profile>` to regenerate the config later. Add `--dry-run` to
preview the file without writing, `--check` to fail when a setup is stale, or `--command
/abs/path/to/dent8` when the globally installed binary is not on the agent host's `PATH`.
If your dent8 bundle directory is not named `.dent8`, pass `--config` because dent8 cannot
infer the client config location safely.
For a custom MCP client, initialize a custom source and add the equivalent server block manually:

```sh
dent8 init --identity --source source:assistant
```

```json
{
  "mcpServers": {
    "dent8": {
      "command": "dent8",
      "args": ["mcp", "serve"],
      "env": {
        "DENT8_LOG": "/abs/path/to/project/.dent8/agent-memory.jsonl",
        "DENT8_AUTHORITY": "/abs/path/to/project/.dent8/authority.json",
        "DENT8_REQUIRE_AUTHORITY": "1",
        "DENT8_TRUST": "/abs/path/to/project/.dent8/trust.json",
        "DENT8_REQUIRE_IDENTITY": "1",
        "DENT8_GRANT": "/abs/path/to/project/.dent8/grants/source_assistant.grant.json",
        "DENT8_IDENTITY_KEY": "/abs/path/to/project/.dent8/identities/source_assistant.key"
      }
    }
  }
}
```

The agent then gets these tools — `list_facts`, `verify`, `conflicts`, `assert`,
`supersede`, `retract`, `contradict`, `reinforce`, `expire`, `derive`, `explain`,
`replay` — plus readable `dent8://{kind}/{key}/{predicate}` resources. A rejected write
comes back as a tool **error with the reason**, so the agent learns *why* (e.g.
"repo.database requires authority High, got Low"). For an operational backend, set
`DENT8_STORE_URL` and run a `--features postgres` (or `--features sqlite`) build.

The installed stdio config reuses one `dent8` binary, but each MCP client usually launches its
own server subprocess. To share memory across Codex, Claude Code, Cursor, Gemini, Grok Build,
Cascade, and Hecate, point those subprocesses at the same backend and authority/trust
registries, while keeping distinct per-agent `DENT8_GRANT` and `DENT8_IDENTITY_KEY` values.
For production multi-agent concurrency, prefer Postgres over the file dev store. A single
long-lived local or remote HTTP MCP server is a future transport, not part of v0.

Client-specific examples:

- [Codex](../codex/) — `config.toml` stdio MCP setup.
- [Claude Code](../claude-code/) — `claude mcp add` and project `.mcp.json` setup.
- [Gemini CLI](../gemini/) — project `.gemini/settings.json` / `gemini mcp add` setup.
- [Devin/Cascade](../cascade/) — Cascade MCP config + rules/memory guard stance.
- [Cursor](../cursor/) — project/global `mcp.json` setup.
- [Grok Build](../grok-build/) — client-neutral stdio MCP profile for Grok Build hosts.
- [Hecate](../hecate/) — Hecate task / external-agent MCP server config.
- [LangChain / in-process Python·TS](../langchain/) — use dent8 as a memory firewall from a
  framework over MCP.
- [Vercel AI SDK](../vercel-ai-sdk/) — discover dent8 MCP tools with `@ai-sdk/mcp` and pass
  them to `generateText`.

Optional hook guards for native memory/rules files live in
[`../agent-hooks/`](../agent-hooks/). Install MCP first; hooks only catch bypasses.

## Try it without a client

[`demo.sh`](demo.sh) drives the server over stdio with raw JSON-RPC — a trusted fact is
asserted, a low-authority override is rejected by the firewall, and `explain` replays the
believed fact:

```text
$ ./demo.sh
{... "result": { "serverInfo": { "name": "dent8", ... } } }          # initialize
{... "result": { "tools": [ {"name":"list_facts"}, {"name":"assert"}, ... ] } } # tools/list
{... "no dent8 facts recorded yet" ... }                              # list_facts
{... "structuredContent": {"status":"accepted","accepted_events":[...],"receipt":{...}} ... } # assert
{... "structuredContent": {"status":"rejected","rejection_reason":"..."} ... "isError": true } # supersede
{... "value : \"postgres\" ... lifecycle : Active ..." }             # explain — the trusted fact stood
{... "STRUCTURAL integrity holds" ... }                               # verify
```

From a clone, point it at the workspace binary:

```sh
DENT8="cargo run -q -p dent8-cli --" ./examples/mcp/demo.sh
```
