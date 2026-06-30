# dent8 as a Vercel AI SDK memory firewall

Use dent8 from a TypeScript app built with the Vercel AI SDK by exposing
`dent8 mcp serve` as an MCP tool source. The AI SDK discovers dent8's tools, then the model
records and reads facts through the same claim-event firewall used by the CLI: low-authority
overrides are rejected, stale facts are flagged, contradictions remain explainable, and every
accepted write has replayable provenance.

The sample app is [`dent8_memory_agent.ts`](dent8_memory_agent.ts). It uses the AI SDK's MCP
client for local stdio development:

```ts
import { createMCPClient } from "@ai-sdk/mcp";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const mcpClient = await createMCPClient({
  transport: new StdioClientTransport({
    command: "dent8",
    args: ["mcp", "serve"],
    env: { ...process.env, DENT8_LOG: ".dent8/vercel-ai-sdk-memory.jsonl" },
  }),
});

const tools = await mcpClient.tools();
```

## Run

```sh
npm i ai @ai-sdk/mcp @ai-sdk/openai @modelcontextprotocol/sdk tsx
export OPENAI_API_KEY=...

# optional but recommended once you want fail-closed source authority:
mkdir -p .dent8
DENT8_AUTHORITY=.dent8/authority.json dent8 authority add source:vercel-ai-sdk high

npx tsx dent8_memory_agent.ts
```

If `OPENAI_API_KEY` is not set, the sample still connects to dent8, lists the MCP tools, and
exits before calling a model. That gives you a quick local wiring check.

## Notes

- Stdio MCP is local-development only in the AI SDK docs. For production, expose dent8 through
  a remote MCP transport when dent8 grows one, or keep it as a trusted sidecar in the same
  runtime boundary.
- The source id used by the prompt is `source:vercel-ai-sdk`. If you enable
  `DENT8_REQUIRE_AUTHORITY=1`, grant that source first with `dent8 authority add`.
- For operational persistence, run dent8 with `DENT8_STORE_URL` and a `--features postgres`
  or `--features sqlite` build. The AI SDK integration remains just a caller; dent8 remains
  the memory firewall.
