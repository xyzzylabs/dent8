#!/usr/bin/env -S npx tsx
/**
 * Use dent8 as a Vercel AI SDK agent's memory firewall, over MCP.
 *
 * Requires:
 *   npm i ai @ai-sdk/mcp @ai-sdk/openai @modelcontextprotocol/sdk tsx
 *   export OPENAI_API_KEY=...          # only needed for the model call
 *   # the `dent8` binary on PATH (e.g. cargo install --path crates/dent8-cli)
 *
 * Run:
 *   npx tsx dent8_memory_agent.ts
 *
 * The script always does a no-LLM wiring check by listing dent8's MCP tools. If
 * OPENAI_API_KEY is set, it asks a model to assert, reject-test, explain, and verify a
 * small fact through dent8.
 */

import { createMCPClient } from "@ai-sdk/mcp";
import { openai } from "@ai-sdk/openai";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { generateText, stepCountIs } from "ai";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";

const dent8Dir = resolve(".dent8");
const dent8Log = resolve(dent8Dir, "vercel-ai-sdk-memory.jsonl");
const dent8Authority = resolve(dent8Dir, "authority.json");

async function main(): Promise<void> {
  mkdirSync(dent8Dir, { recursive: true });

  const mcpClient = await createMCPClient({
    transport: new StdioClientTransport({
      command: "dent8",
      args: ["mcp", "serve"],
      env: {
        ...process.env,
        DENT8_LOG: dent8Log,
        DENT8_AUTHORITY: process.env.DENT8_AUTHORITY ?? dent8Authority,
      } as Record<string, string>,
    }),
  });

  try {
    const tools = await mcpClient.tools();
    console.log(
      `dent8 exposed ${Object.keys(tools).length} MCP tools: ${Object.keys(tools).join(", ")}`,
    );

    if (!process.env.OPENAI_API_KEY) {
      console.log("OPENAI_API_KEY is not set; wiring check complete, skipping model call.");
      console.log("Set OPENAI_API_KEY and rerun to let the Vercel AI SDK call dent8 tools.");
      return;
    }

    const { text } = await generateText({
      model: openai("gpt-4o-mini"),
      tools,
      stopWhen: stepCountIs(8),
      system:
        "You are a careful developer assistant. Use dent8 tools for durable facts. " +
        "Use source source:vercel-ai-sdk for writes. Treat dent8 tool errors as safety signals.",
      prompt:
        "Through dent8, assert that person:alice favorite_drink is tea with authority high. " +
        "Then try to supersede it to coffee with authority low from source:note-old; this should be rejected. " +
        "Finally explain person:alice favorite_drink and run verify. Summarize the integrity result.",
    });

    console.log(text);
  } finally {
    await mcpClient.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
