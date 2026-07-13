#!/usr/bin/env -S npx tsx
/**
 * A Vercel AI SDK agent with dent8's belief surface as first-class tools.
 *
 * Unlike `dent8_memory_agent.ts` (which wires dent8 in over MCP), this uses the native
 * `dent8/ai` adapter — AI SDK tools built directly on the `dent8` SDK, no MCP subprocess to
 * keep in sync. The agent records and reads project facts *through the firewall*: a write it
 * is not authorized to make comes back as a tool result it can read and adapt to, and it
 * cannot pick its own authority (that is configuration, below).
 *
 * Requires:
 *   npm i dent8 ai @ai-sdk/openai tsx
 *   export OPENAI_API_KEY=...                    # any AI SDK model works
 *   export DENT8_LOG=.dent8/agent-memory.jsonl   # or a DENT8_STORE_URL backend
 *   # the `dent8` binary on PATH (cargo install dent8-cli --locked)
 *
 * Run:
 *   npx tsx dent8_tools_agent.ts
 *
 * Without OPENAI_API_KEY it prints the wired tool set and exits — a quick local wiring check.
 */

import { openai } from "@ai-sdk/openai";
import { generateText, stepCountIs } from "ai";
import { dent8Tools } from "dent8/ai";

// The agent writes as a *low-authority* source: it can propose facts, but the firewall will
// not let it override a human- or CI-asserted one. source/authority are set here, not chosen
// by the model — that is the point.
const tools = dent8Tools({ source: "source:agent", authority: "low" });

async function main(): Promise<void> {
  if (!process.env.OPENAI_API_KEY) {
    console.log("dent8 tools wired:", Object.keys(tools).join(", "));
    console.log("Set OPENAI_API_KEY to run the agent.");
    return;
  }

  const { text } = await generateText({
    model: openai("gpt-4o-mini"),
    tools,
    stopWhen: stepCountIs(8),
    prompt:
      "Record that repo:myproj uses postgres as its database, then read it back and tell me why it is believed.",
  });
  console.log(text);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
