# dent8 as a LangChain.js agent's memory firewall

Give a [LangChain.js](https://js.langchain.com) agent a memory firewall: it records and reads
project facts through the same fact-event firewall the CLI uses — low-authority overrides are
rejected, stale facts are flagged, contradictions stay explainable, and every accepted write
has replayable provenance.

Two ways to wire it, both firewalled:

## First-class tools (recommended)

`dent8/langchain` gives native LangChain.js structured tools built on the `npm i dent8` SDK —
no MCP subprocess to keep in sync, typed arguments, and firewall refusals surfaced to the
model *as tool results* it reads and adapts to. [`dent8_tools_agent.ts`](dent8_tools_agent.ts):

```ts
import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { dent8Tools } from "dent8/langchain";

const agent = createReactAgent({
  llm: new ChatOpenAI({ model: "gpt-4o-mini" }),
  tools: dent8Tools({ source: "source:agent", authority: "low" }),
});
```

```sh
npm i dent8 @langchain/core @langchain/langgraph @langchain/openai tsx
export OPENAI_API_KEY=...
export DENT8_LOG=.dent8/agent-memory.jsonl   # or a DENT8_STORE_URL backend
npx tsx dent8_tools_agent.ts
```

The tools expose *what* to record (subject, predicate, value); the **source and authority are
your configuration, not LLM arguments**, so the agent can't escalate its own authority — a
`authority: "low"` agent proposes facts but never overrides a human's. A refused write comes
back as a tool result the agent reads, not an exception. Without `OPENAI_API_KEY` the sample
prints the wired tool set and exits — a quick local wiring check.

## Over MCP

The language-agnostic path: point `@langchain/mcp-adapters` at `dent8 mcp serve` and it
discovers dent8's tools as LangChain tools. See
[`../langchain/`](../langchain/#langchainjs-typescript) for the MCP-adapters variant
(`dent8_memory_agent.ts` there).

## Which to use

- **First-class tools** own the identity in your process: `source`/`authority` are code, the
  agent can't touch them, and there is no subprocess. Simplest for a TypeScript app you
  control.
- **MCP** is the choice when you want the signed-identity envelope (`dent8 init --identity`),
  a `dent8 mcp serve` sidecar shared across processes, or one integration path across many
  languages.

## Notes

- The same six tools ship for the Vercel AI SDK (`dent8/ai`, see
  [`../vercel-ai-sdk/`](../vercel-ai-sdk/)) and, in Python, for LangChain
  (`dent8.langchain`, see [`../langchain/`](../langchain/)).
- For operational persistence, run dent8 with `DENT8_STORE_URL`. `sqlite://` works in the
  stock build; `postgres://` needs a `--features postgres` build. dent8 stays the firewall;
  the framework just calls it.
