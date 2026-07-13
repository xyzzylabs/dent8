#!/usr/bin/env -S npx tsx
/**
 * Use dent8 as a LangChain.js agent's memory firewall, over MCP.
 *
 * dent8 exposes its full belief surface (assert / supersede / retract / verify /
 * runtime_status / conflicts / list_facts / ...) as MCP tools via `dent8 mcp serve`.
 * This wires that server into a LangGraph.js ReAct agent with `@langchain/mcp-adapters`, so the agent
 * records and reads project facts *through the firewall*: a low-authority or stale
 * write is rejected, contradictions surface, and every fact is replayable.
 *
 * Requires:
 *   npm i @langchain/mcp-adapters @langchain/langgraph @langchain/openai
 *   export OPENAI_API_KEY=...          # any LangChain-supported model works
 *   # the `dent8` binary on PATH (e.g. cargo install dent8-cli --locked)
 *
 * Run:
 *   npx tsx dent8_memory_agent.ts
 *
 * Note: MCP-client APIs move fast. If MultiServerMCPClient / getTools() has shifted,
 * check the @langchain/mcp-adapters README — the dent8 side (`dent8 mcp serve`) is stable.
 */

import { MultiServerMCPClient } from "@langchain/mcp-adapters";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { ChatOpenAI } from "@langchain/openai";
import { resolve } from "node:path";

async function main(): Promise<void> {
  // Spawn `dent8 mcp serve` (stdio JSON-RPC) and expose its tools to LangChain.js.
  // DENT8_LOG points the firewall at this agent's memory log; set DENT8_STORE_URL
  // instead for an operational postgres://… / sqlite://… backend. The signed-identity
  // vars carry the source grant this server writes under — v0.8.0 rejects any write above
  // the agent tier without one, so the high-authority write below needs it. Provision the
  // bundle once with `dent8 init --identity --source source:langchain` (see README). The env
  // replaces the child environment, so spread process.env to keep PATH et al.
  const client = new MultiServerMCPClient({
    mcpServers: {
      dent8: {
        transport: "stdio",
        command: "dent8",
        args: ["mcp", "serve"],
        env: {
          ...process.env,
          DENT8_LOG: resolve("agent-memory.jsonl"),
          DENT8_AUTHORITY: process.env.DENT8_AUTHORITY ?? resolve(".dent8/authority.json"),
          DENT8_REQUIRE_AUTHORITY: process.env.DENT8_REQUIRE_AUTHORITY ?? "1",
          DENT8_TRUST: process.env.DENT8_TRUST ?? resolve(".dent8/trust.json"),
          DENT8_REQUIRE_IDENTITY: process.env.DENT8_REQUIRE_IDENTITY ?? "1",
          DENT8_GRANT:
            process.env.DENT8_GRANT ?? resolve(".dent8/grants/source_langchain.grant.json"),
          DENT8_IDENTITY_KEY:
            process.env.DENT8_IDENTITY_KEY ?? resolve(".dent8/identities/source_langchain.key"),
        } as Record<string, string>,
      },
    },
  });

  const tools = await client.getTools();
  console.log(
    `dent8 exposed ${tools.length} firewall tools: ${tools.map((tool) => tool.name).join(", ")}`,
  );

  const agent = createReactAgent({
    llm: new ChatOpenAI({ model: "gpt-4o-mini" }),
    tools,
  });

  // The agent records a fact through the firewall, then verifies integrity. A later
  // low-authority attempt to change it would be *rejected* by dent8, surfaced to the
  // model as a tool error with the reason — not silently applied.
  const result = await agent.invoke({
    messages: [
      {
        role: "user",
        content:
          "Record that this repo's database is postgres (subject repo:myproj, predicate " +
          "database, authority high, source source:langchain) through dent8, then run a dent8 " +
          "verify and tell me the integrity result.",
      },
    ],
  });

  const messages = result.messages;
  console.log(messages[messages.length - 1].content);
  await client.close();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
