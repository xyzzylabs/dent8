# dent8 with Codex

Codex supports local stdio MCP servers through `config.toml`. dent8 exposes exactly that via
`dent8 mcp serve`, so Codex can use dent8 as a project memory firewall.

## Installed binary

From the target project:

```sh
dent8 init --agent codex
```

Add this to `~/.codex/config.toml`, or to a trusted project's `.codex/config.toml`:

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
args = ["run", "-q", "-p", "dent8-cli", "--", "mcp", "serve"]
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

`dent8 init --agent codex` creates the profile log, authority registry, and signed source
identity bundle referenced above. It keeps the issuer key outside `.dent8`.

Then ask Codex to use dent8:

```text
Before relying on durable project facts, inspect dent8 with list_facts or explain.
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

## Optional hook guard

After MCP works, you can add [`../agent-hooks/codex/hooks.sample.json`](../agent-hooks/codex/hooks.sample.json)
to a trusted `.codex/hooks.json` or merge it into your Codex hook config. It runs `dent8
verify` on session boundaries and blocks direct edits to native memory/rules files such as
`AGENTS.md`, forcing durable facts through dent8 instead.
