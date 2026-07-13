# dent8 as a LangChain agent's memory firewall

A Python or TypeScript app — LangChain, LlamaIndex, the Vercel AI SDK, Mastra — doesn't exec
provider hooks, so the [native-memory hook guard](../agent-hooks/) doesn't apply: *you* own
every memory write. Wire dent8 in as a **memory firewall**. The agent records and reads
project facts through dent8's fact-event firewall, so a low-authority or stale write can't
silently override a trusted fact, contradictions surface instead of overwriting, and every
fact is replayable with an integrity receipt.

Two ways to wire it, both firewalled:

- **First-class tools (recommended for LangChain/Python)** — `dent8.langchain` gives native
  LangChain `StructuredTool`s over the belief surface, built on the `dent8` SDK, no MCP
  subprocess:

  ```python
  from dent8.langchain import dent8_tools          # pip install "dent8[langchain]"
  from langgraph.prebuilt import create_react_agent

  tools = dent8_tools(source="source:agent", authority="low")
  agent = create_react_agent("openai:gpt-4o-mini", tools)
  ```

  The tools expose *what* to record (subject, predicate, value); the **source and authority
  are your configuration, not LLM arguments**, so the agent can't escalate its own authority —
  a low-authority agent can propose facts but never override a human's. A refused write comes
  back as a tool result the agent reads and adapts to, not an exception. See
  [`dent8_tools_agent.py`](dent8_tools_agent.py).

- **Over MCP** — the language-agnostic path (below), for LlamaIndex / Vercel AI SDK / any
  MCP-speaking client, or a shared `dent8 mcp serve` your team already runs.

dent8 ships the server already: `dent8 mcp serve` (stdio JSON-RPC) exposes the full belief
surface as MCP tools — `runtime_status`, `assert`, `supersede`, `retract`, `contradict`,
`reinforce`, `expire`, `derive`, `verify`, `conflicts`, `list_facts`, `explain`, `replay`.
See [`../mcp/`](../mcp/)
for the protocol and a no-LLM `demo.sh`.

## LangChain (Python)

[`dent8_memory_agent.py`](dent8_memory_agent.py) connects a LangGraph ReAct agent to
`dent8 mcp serve` with
[`langchain-mcp-adapters`](https://github.com/langchain-ai/langchain-mcp-adapters):

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent

client = MultiServerMCPClient({
    "dent8": {"command": "dent8", "args": ["mcp", "serve"], "transport": "stdio"},
})
tools = await client.get_tools()           # dent8's firewall tools, as LangChain tools
agent = create_react_agent("openai:gpt-4o-mini", tools)
```

```sh
pip install langchain-mcp-adapters langgraph "langchain[openai]"
export OPENAI_API_KEY=...          # any LangChain-supported model works
python dent8_memory_agent.py
```

A rejected write comes back as a tool **error with the reason** (e.g. "repo.database requires
authority high, got low"), so the model learns *why* instead of silently overwriting trusted
memory.

## LangChain.js (TypeScript)

[`dent8_memory_agent.ts`](dent8_memory_agent.ts) is the same agent in TypeScript, using
[`@langchain/mcp-adapters`](https://github.com/langchain-ai/langchainjs/tree/main/libs/langchain-mcp-adapters)
— the JS twin of the Python adapter:

```ts
import { MultiServerMCPClient } from "@langchain/mcp-adapters";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { ChatOpenAI } from "@langchain/openai";

const client = new MultiServerMCPClient({
  mcpServers: {
    dent8: { transport: "stdio", command: "dent8", args: ["mcp", "serve"] },
  },
});
const tools = await client.getTools();      // dent8's firewall tools, as LangChain tools
const agent = createReactAgent({ llm: new ChatOpenAI({ model: "gpt-4o-mini" }), tools });
```

```sh
npm i @langchain/mcp-adapters @langchain/langgraph @langchain/openai
export OPENAI_API_KEY=...          # any LangChain-supported model works
npx tsx dent8_memory_agent.ts
```

## Other frameworks

The same `dent8 mcp serve` server is framework- and language-agnostic — any MCP client works.
Point each at `{ command: "dent8", args: ["mcp", "serve"] }`:

- **LlamaIndex** (Python): `llama-index-tools-mcp`.
- **Vercel AI SDK** (TypeScript): see [`../vercel-ai-sdk/`](../vercel-ai-sdk/).
- **Mastra** (TypeScript): its `MCPClient` MCP tools.

## Notes

- MCP-client APIs move fast; if `MultiServerMCPClient` / `get_tools()` has shifted, check the
  langchain-mcp-adapters README — the dent8 side (`dent8 mcp serve`) is stable.
- For a protected local setup, run `dent8 init --identity --source <source>` and pass the
  generated `.dent8/env` + `.dent8/identity-<source>.env` variables into the process that launches
  `dent8 mcp serve`. For an operational backend, set `DENT8_STORE_URL` (a `postgres://…` /
  `sqlite://…` build). dent8 stays the firewall; the framework just calls it.
- An ergonomic native client (`pip install dent8` / `npm i dent8` with first-class framework
  adapters) is on the [roadmap](../../docs/roadmap.md#later); today MCP is the integration path.
