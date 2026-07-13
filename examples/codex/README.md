# dent8 with Codex

Codex supports local stdio MCP servers through `config.toml`. dent8 exposes exactly that via
`dent8 mcp serve`, so Codex can use dent8 as a project memory firewall.

## Installed binary

From the target project:

```sh
dent8 init --agent codex --install-mcp
```

This patches the **trusted project's** `.codex/config.toml` (not `~/.codex/config.toml`) and
prints the resulting file. Prefer project scope so other repos do not inherit this store.
The generated entry is equivalent to:

```toml
[mcp_servers.dent8]
command = "dent8"
args = ["mcp", "serve"]
startup_timeout_sec = 20
tool_timeout_sec = 60

[mcp_servers.dent8.env]
DENT8_LOG = "/abs/path/to/project/.dent8/codex-memory.jsonl"
DENT8_AUTHORITY = "/abs/path/to/project/.dent8/authority.json"
DENT8_REQUIRE_AUTHORITY = "1"
DENT8_TRUST = "/abs/path/to/project/.dent8/trust.json"
DENT8_REQUIRE_IDENTITY = "1"
DENT8_GRANT = "/abs/path/to/project/.dent8/grants/source_codex.grant.json"
DENT8_IDENTITY_KEY = "/abs/path/to/project/.dent8/identities/source_codex.key"
```

## From a dent8 checkout

Use this while developing dent8 itself:

```toml
[mcp_servers.dent8]
command = "cargo"
args = ["run", "-q", "-p", "dent8", "--", "mcp", "serve"]
cwd = "/abs/path/to/dent8"
startup_timeout_sec = 30
tool_timeout_sec = 60

[mcp_servers.dent8.env]
DENT8_LOG = "/abs/path/to/project/.dent8/codex-memory.jsonl"
DENT8_AUTHORITY = "/abs/path/to/project/.dent8/authority.json"
DENT8_REQUIRE_AUTHORITY = "1"
DENT8_TRUST = "/abs/path/to/project/.dent8/trust.json"
DENT8_REQUIRE_IDENTITY = "1"
DENT8_GRANT = "/abs/path/to/project/.dent8/grants/source_codex.grant.json"
DENT8_IDENTITY_KEY = "/abs/path/to/project/.dent8/identities/source_codex.key"
```

`dent8 init --agent codex --install-mcp` creates the profile log, authority registry, signed
source identity bundle, and Codex MCP config referenced above. It keeps the issuer key outside
`.dent8`. Re-run `dent8 mcp install --agent codex` to patch/show the MCP config later.

Then ask Codex to use dent8:

```text
Before relying on durable project facts, inspect dent8 with `runtime_status`, then
`list_facts` or `explain`.
Record stable project facts in dent8 using source:codex and the lowest adequate authority.
Use contradict for uncertain conflicts and supersede only when replacing a believed fact.
Run verify before making broad changes that depend on remembered facts.
```

Useful first facts:

```text
repo:<project> database
repo:<project> test_command
dependency:<crate-or-package> version
branch:<branch> status
user:<name> preference
```

## Native-memory guard (installed by default)

`dent8 init --agent codex` already wires an **enforced** native-memory guard into
`.codex/hooks.json`, blocking direct edits to native memory/rules files such as `AGENTS.md` and
forcing durable facts through dent8 instead (opt out with `dent8 init --no-native-memory-guard`).
To customize it or add the fuller profile that also runs `dent8 verify` on session boundaries,
merge [`../agent-hooks/codex/hooks.sample.json`](../agent-hooks/codex/hooks.sample.json) into
your Codex hook config.
