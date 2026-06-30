# dent8 with Hecate

Hecate can use dent8 in two useful ways:

- **Native Hecate agent-loop tasks:** add dent8 to the task's `mcp_servers` list so the
  Hecate-managed model can call dent8 tools directly.
- **Supervised External Agents:** Hecate's ACP adapter path supports passing stdio/HTTP MCP
  server config to Codex, Claude Code, Cursor Agent, and Grok Build sessions. Use the same
  dent8 server block when creating or configuring that external-agent session.

The important part is that dent8 remains the memory-integrity boundary: writes go through
`dent8 mcp serve`, then through the same authority ceiling and firewall as the CLI.

## Hecate task payload

Start Hecate, then create an `agent_loop` task with dent8 mounted as an MCP server:

```sh
PROJECT=/abs/path/to/project
mkdir -p "$PROJECT/.dent8"
DENT8_AUTHORITY="$PROJECT/.dent8/authority.json" dent8 authority add source:hecate high

curl -sS \
  -H 'content-type: application/json' \
  -X POST http://127.0.0.1:8765/hecate/v1/tasks \
  -d @examples/hecate/task-with-dent8.sample.json
```

Edit the sample first: replace `/abs/path/to/project` with the workspace root and set
`requested_provider` / `requested_model` to the LLM Hecate should drive (leave them empty to
use the gateway default). The sample sets `workspace_mode: "in_place"` so Hecate operates on
that directory rather than a fresh clone. If your Hecate runtime requires
`HECATE_RUNTIME_TOKEN`, add the matching `X-Hecate-Runtime-Token` header to the `curl` call.

## Hecate UI

In Hecate's "New task -> Agent loop -> MCP servers" form, add:

```json
{
  "name": "dent8",
  "command": "dent8",
  "args": ["mcp", "serve"],
  "env": {
    "DENT8_LOG": "/abs/path/to/project/.dent8/hecate-memory.jsonl",
    "DENT8_AUTHORITY": "/abs/path/to/project/.dent8/authority.json",
    "DENT8_REQUIRE_AUTHORITY": "1"
  },
  "approval_policy": "require_approval"
}
```

`require_approval` is a good first posture because dent8 exposes mutating tools. Use `auto`
only when the authority registry is provisioned and the task is expected to write memory.

## Prompt Hecate or the supervised agent

```text
Before relying on durable project facts, inspect dent8 with list_facts or explain.
Record stable project facts in dent8 using source:hecate and the lowest adequate authority.
Use contradict for uncertain conflicts and supersede only when replacing a believed fact.
Run verify before broad edits that depend on remembered facts.
```

For Hecate-supervised Codex, Claude Code, Cursor Agent, or Grok Build sessions, change the
source id to the supervised agent (`source:codex`, `source:claude-code`, `source:cursor`, or
`source:grok-build`) and grant that source in `dent8 authority`.

## Optional hook guard

Use Hecate as the policy distributor: mount the same dent8 MCP server and pass the matching
hook profile to the supervised agent. See [`../agent-hooks/hecate/`](../agent-hooks/hecate/).
