# dent8 with Codex

Codex supports local stdio MCP servers through `config.toml`. dent8 exposes exactly that via
`dent8 mcp serve`, so Codex can use dent8 as a project memory firewall.

## Installed binary

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
```

## From a dent8 checkout

Use this while developing dent8 itself:

```toml
[mcp_servers.dent8]
command = "cargo"
args = ["run", "-q", "-p", "dent8-cli", "--", "mcp", "serve"]
cwd = "/Users/chicoxyzzy/dev/opensource/dent8"
startup_timeout_sec = 30
tool_timeout_sec = 60

[mcp_servers.dent8.env]
DENT8_LOG = "/abs/path/to/project/.dent8/codex-memory.jsonl"
DENT8_AUTHORITY = "/abs/path/to/project/.dent8/authority.json"
DENT8_REQUIRE_AUTHORITY = "1"
```

Before enabling fail-closed mode, create the registry:

```sh
mkdir -p /abs/path/to/project/.dent8
DENT8_AUTHORITY=/abs/path/to/project/.dent8/authority.json \
  dent8 authority add source:codex high
```

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
