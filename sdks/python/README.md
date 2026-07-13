# dent8 (Python)

A memory firewall for coding agents — the thin Python SDK.

Every call runs the [`dent8`](https://github.com/xyzzylabs/dent8) binary with
`--output json` and returns the parsed payload as a `dict`. The wire contract is
the product: each payload carries `schema_version`; every error carries a stable
`status` plus a machine-readable `code` (`insufficient-authority`,
`authority-ceiling`, `content-rejected`, …), raised as `Dent8Rejected` /
`Dent8Invalid` so you branch on `error.code`, never on prose.

Because the CLI resolves the store itself (repo-confined `.dent8/` discovery,
`DENT8_LOG` / `DENT8_STORE_URL`), routes writes through a local daemon when
`DENT8_DAEMON_SOCKET` is set, and defaults `--source`/`--authority` from the
active signed grant, the SDK inherits all of it with zero configuration.

Writes **above the agent tier** (`medium` / `high` / `canonical` authority) require a
valid signed identity: run `dent8 init` (which provisions one by default) and let the SDK
inherit its `DENT8_TRUST` / `DENT8_GRANT` / `DENT8_IDENTITY_KEY` env, then write as that
`source:*` identity. Agent-tier writes (`low`) need no identity.

## Install

```sh
pip install dent8
cargo install dent8-cli --locked   # the binary the SDK drives
```

## Use

```python
from dent8 import Dent8, Dent8Rejected

d8 = Dent8()  # finds `dent8` on PATH; Dent8(binary=..., env={"DENT8_LOG": ...}) to pin

# A high-authority write is signed as the active `source:*` identity (from `dent8 init`).
d8.assert_fact("repo:myproj", "database", "postgres",
               authority="high", source="source:alice")

try:
    d8.supersede("repo:myproj", "database", "mysql",
                 authority="low", source="web:scrape")
except Dent8Rejected as rejection:
    assert rejection.code == "insufficient-authority"   # branch on the code

fact = d8.explain("repo:myproj", "database")
assert fact["value"]["text"] == "postgres"              # the firewall held

report = d8.verify()          # findings are a result: status ok | integrity_issues
disputes = d8.conflicts()     # status contested when live disputes exist
```

The belief surface maps 1:1 onto the CLI: `assert_fact` (Python keyword), `supersede`,
`contradict`, `retract`, `reinforce`, `expire`, `derive(basis=(subject, predicate))`,
`explain`, `replay`, `facts`, `verify`, `conflicts`. Temporal keywords accept the CLI's
whole grammar — unix millis, `"now"`, `"-7d"`, RFC 3339, or a bare UTC date.

## Framework tools

First-class tools for the two big Python agent frameworks — native tool objects over the
belief surface, no MCP subprocess. Both expose *what* to record (subject, predicate, value);
**source and authority are your configuration, not LLM arguments**, so the agent cannot
escalate its own authority, and a refused write returns as a tool result it reads and adapts
to, not an exception.

**LangChain** — `pip install "dent8[langchain]"`:

```python
from dent8.langchain import dent8_tools
from langgraph.prebuilt import create_react_agent

tools = dent8_tools(source="source:agent", authority="low")
agent = create_react_agent(model, tools)
```

**LlamaIndex** — `pip install "dent8[llamaindex]"`:

```python
from dent8.llamaindex import dent8_tools
from llama_index.core.agent.workflow import FunctionAgent

tools = dent8_tools(source="source:agent", authority="low")
agent = FunctionAgent(tools=tools, llm=llm)
```

Both give you `dent8_record_fact` / `dent8_revise_fact` / `dent8_dispute_fact` /
`dent8_explain_fact` / `dent8_list_facts` / `dent8_verify`. See
[examples/langchain](https://github.com/xyzzylabs/dent8/tree/main/examples/langchain) and
[examples/llamaindex](https://github.com/xyzzylabs/dent8/tree/main/examples/llamaindex).

For any other framework or an MCP client, use the MCP server (`dent8 mcp serve`, over stdio /
daemon / HTTP). This SDK core stays zero-dependency and is for *programmatic* access from
Python code.

## Test

```sh
cargo build -p dent8-cli
DENT8_BIN=../../target/debug/dent8 python -m pytest
```
