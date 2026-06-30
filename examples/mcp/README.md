# dent8 as an agent's memory firewall (MCP)

`dent8 mcp serve` is a stdio **JSON-RPC 2.0 MCP server** that exposes dent8's full belief
surface as tools. Point any MCP client at it and the agent's project memory is *firewalled*:
a low-authority or stale write can't silently override a trusted fact, a contradiction
surfaces instead of overwriting, and every believed fact is replayable with an integrity
receipt.

## Wire it into an MCP client

Add dent8 to your client's MCP server config (e.g. an agent's `mcpServers` block):

```json
{
  "mcpServers": {
    "dent8": {
      "command": "dent8",
      "args": ["mcp", "serve"],
      "env": { "DENT8_LOG": "/abs/path/to/agent-memory.jsonl" }
    }
  }
}
```

The agent then gets these tools — `list_facts`, `verify`, `conflicts`, `assert`,
`supersede`, `retract`, `contradict`, `reinforce`, `expire`, `derive`, `explain`,
`replay` — plus readable `dent8://{kind}/{key}/{predicate}` resources. A rejected write
comes back as a tool **error with the reason**, so the agent learns *why* (e.g.
"repo.database requires authority High, got Low"). For the operational backend, set
`DENT8_STORE_URL` and run a `--features postgres` (or `--features sqlite`) build; to cap what a
source may assert, configure `dent8 authority`.

Client-specific examples:

- [Codex](../codex/) — `config.toml` stdio MCP setup.
- [Claude Code](../claude-code/) — `claude mcp add` and project `.mcp.json` setup.
- [Gemini CLI](../gemini/) — project `.gemini/settings.json` / `gemini mcp add` setup.
- [Devin/Cascade](../cascade/) — Cascade MCP config + rules/memory guard stance.
- [Cursor](../cursor/) — project/global `mcp.json` setup.
- [Grok Build](../grok-build/) — client-neutral stdio MCP profile for Grok Build hosts.
- [Hecate](../hecate/) — Hecate task / external-agent MCP server config.
- [LangChain / in-process Python·TS](../langchain/) — use dent8 as a memory firewall from a
  framework (LangChain, LlamaIndex, Vercel AI SDK, Mastra) over MCP.

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
{... "ACCEPTED  repo:myproj database = \"postgres\"  (authority=High) ..." }   # assert
{... "REJECTED: repo.database requires authority High, got Low" ... "isError": true }  # supersede
{... "value : \"postgres\" ... lifecycle : Active ..." }             # explain — the trusted fact stood
{... "STRUCTURAL integrity holds" ... }                               # verify
```

From a clone, point it at the workspace binary:

```sh
DENT8="cargo run -q -p dent8-cli --" ./examples/mcp/demo.sh
```
