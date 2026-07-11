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

## Install

```sh
pip install dent8
cargo install dent8-cli --locked   # the binary the SDK drives
```

## Use

```python
from dent8 import Dent8, Dent8Rejected

d8 = Dent8()  # finds `dent8` on PATH; Dent8(binary=..., env={"DENT8_LOG": ...}) to pin

d8.assert_fact("repo:myproj", "database", "postgres",
               authority="high", source="user:alice")

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

For LLM tool-calling agents, prefer the MCP server (`dent8 mcp serve`) — see
[examples/langchain](https://github.com/xyzzylabs/dent8/tree/main/examples/langchain) and
[examples/vercel-ai-sdk](https://github.com/xyzzylabs/dent8/tree/main/examples/vercel-ai-sdk). This SDK is for
*programmatic* access from Python code.

## Test

```sh
cargo build -p dent8-cli
DENT8_BIN=../../target/debug/dent8 python -m pytest
```
