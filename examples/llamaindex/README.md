# dent8 as a LlamaIndex agent's memory firewall

Give a [LlamaIndex](https://docs.llamaindex.ai) agent a memory firewall: it records and reads
project facts through the same fact-event firewall the CLI uses — low-authority overrides are
rejected, stale facts are flagged, contradictions stay explainable, and every accepted write
has replayable provenance.

Two ways to wire it, both firewalled:

## First-class tools (recommended)

`dent8.llamaindex` gives native LlamaIndex `FunctionTool`s built on the `pip install dent8`
SDK — no MCP subprocess to keep in sync, typed arguments, and firewall refusals surfaced to
the model *as tool results* it reads and adapts to. [`dent8_tools_agent.py`](dent8_tools_agent.py):

```python
from dent8.llamaindex import dent8_tools            # pip install "dent8[llamaindex]"
from llama_index.core.agent.workflow import FunctionAgent
from llama_index.llms.openai import OpenAI

tools = dent8_tools(source="source:agent", authority="low")
agent = FunctionAgent(tools=tools, llm=OpenAI(model="gpt-4o-mini"))
```

The tools expose *what* to record (subject, predicate, value); the **source and authority are
your configuration, not LLM arguments**, so the agent can't escalate its own authority — a
`authority="low"` agent proposes facts but never overrides a human's. A refused write comes
back as a tool result the agent reads, not an exception.

Agent-tier (`low`) writes need no signed identity. To let the agent write above the agent tier
(`medium`/`high`/`canonical`), provision a signing identity first — `dent8 init --source
source:agent`, then load `.dent8/env` — since above-agent writes must be signed.

## Over MCP

The language-agnostic path: point [`llama-index-tools-mcp`](https://pypi.org/project/llama-index-tools-mcp/)
at `dent8 mcp serve` and it discovers dent8's tools as LlamaIndex tools:

```python
from llama_index.tools.mcp import BasicMCPClient, McpToolSpec

mcp = BasicMCPClient("dent8", args=["mcp", "serve"])
tools = McpToolSpec(client=mcp).to_tool_list()
```

## Which to use

- **First-class tools** own the identity in your process: `source`/`authority` are code, the
  agent can't touch them, and there is no subprocess. Simplest for a Python app you control.
- **MCP** is the choice when you want the signed-identity envelope (`dent8 init --identity`),
  a `dent8 mcp serve` sidecar shared across processes, or one integration path across many
  languages.

## Notes

- The same six tools ship for LangChain (`dent8.langchain`, see [`../langchain/`](../langchain/))
  and, in TypeScript, for the Vercel AI SDK (`dent8/ai`) and LangChain.js (`dent8/langchain`).
- For operational persistence, run dent8 with `DENT8_STORE_URL`. `sqlite://` works in the
  stock build; `postgres://` needs a `--features postgres` build. dent8 stays the firewall;
  the framework just calls it.
