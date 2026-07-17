# dent8 as a Vercel AI SDK memory firewall

Give a [Vercel AI SDK](https://ai-sdk.dev) agent a memory firewall: it records and reads
project facts through the same fact-event firewall the CLI uses — low-authority overrides are
rejected, stale facts are flagged, contradictions stay explainable, and every accepted write
has replayable provenance.

Two ways to wire it, both firewalled:

## First-class tools (recommended)

`dent8/ai` gives native AI SDK tools built on the `npm i dent8` SDK — no MCP subprocess to
keep in sync, typed arguments, and firewall refusals surfaced to the model *as tool results*
it reads and adapts to. [`dent8_tools_agent.ts`](dent8_tools_agent.ts):

This adapter requires AI SDK 7.0.31+ and Node.js 22+.

```ts
import { openai } from "@ai-sdk/openai";
import { generateText, stepCountIs } from "ai";
import { dent8Tools } from "dent8/ai";

const { text } = await generateText({
  model: openai("gpt-4o-mini"),
  tools: dent8Tools({ source: "source:agent", authority: "low" }),
  stopWhen: stepCountIs(8),
  prompt: "Record that repo:myproj uses postgres, then read it back and say why it is believed.",
});
```

```sh
npm i dent8 ai @ai-sdk/openai tsx
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

The language-agnostic path: expose `dent8 mcp serve` as an MCP tool source and let the AI SDK
discover dent8's tools. [`dent8_memory_agent.ts`](dent8_memory_agent.ts) uses the AI SDK's MCP
client for local stdio development:

```ts
import { createMCPClient } from "@ai-sdk/mcp";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const mcpClient = await createMCPClient({
  transport: new StdioClientTransport({
    command: "dent8",
    args: ["mcp", "serve"],
    env: {
      ...process.env,
      DENT8_LOG: ".dent8/vercel-ai-sdk-memory.jsonl",
      DENT8_AUTHORITY: ".dent8/authority.json",
      DENT8_REQUIRE_AUTHORITY: "1",
      DENT8_TRUST: ".dent8/trust.json",
      DENT8_REQUIRE_IDENTITY: "1",
      DENT8_GRANT: ".dent8/grants/source_vercel-ai-sdk.grant.json",
      DENT8_IDENTITY_KEY: ".dent8/identities/source_vercel-ai-sdk.key",
    },
  }),
});

const tools = await mcpClient.tools();
```

```sh
npm i ai @ai-sdk/mcp @ai-sdk/openai @modelcontextprotocol/sdk tsx
export OPENAI_API_KEY=...
dent8 init --identity --source source:vercel-ai-sdk
npx tsx dent8_memory_agent.ts
```

If `OPENAI_API_KEY` is not set, the sample still connects to dent8, lists the MCP tools, and
exits before calling a model.

## Which to use

- **First-class tools** own the identity in your process: `source`/`authority` are code, the
  agent can't touch them, and there is no subprocess. Simplest for a TypeScript app you
  control.
- **MCP** is the choice when you want the signed-identity envelope (`dent8 init --identity`),
  a `dent8 mcp serve` sidecar shared across processes, or one integration path across many
  languages.

## Notes

- Stdio MCP is local-development only in the AI SDK docs. For production, keep dent8 as a
  trusted sidecar in the same runtime boundary, or use the first-class tools in-process.
- For operational persistence, run dent8 with `DENT8_STORE_URL`. `sqlite://` works in the
  stock build; `postgres://` needs a `--features postgres` build. Either way dent8 remains the
  memory firewall; the AI SDK integration is just a caller.
