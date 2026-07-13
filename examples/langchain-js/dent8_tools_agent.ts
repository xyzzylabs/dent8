#!/usr/bin/env -S npx tsx
/**
 * A LangChain.js agent with dent8's belief surface as first-class tools.
 *
 * Uses the native `dent8/langchain` adapter — LangChain.js structured tools built directly on
 * the `dent8` SDK, no MCP subprocess to keep in sync. The agent records and reads project
 * facts *through the firewall*: a write it is not authorized to make comes back as a tool
 * result it can read and adapt to, and it cannot pick its own authority (that is
 * configuration, below).
 *
 * Requires:
 *   npm i dent8 @langchain/core @langchain/langgraph @langchain/openai tsx
 *   export OPENAI_API_KEY=...                    # any LangChain-supported model works
 *   export DENT8_LOG=.dent8/agent-memory.jsonl   # or a DENT8_STORE_URL backend
 *   # the `dent8` binary on PATH (cargo install dent8-cli --locked)
 *
 * Run:
 *   npx tsx dent8_tools_agent.ts
 *
 * Without OPENAI_API_KEY it prints the wired tool set and exits — a quick local wiring check.
 */

import { ChatOpenAI } from "@langchain/openai";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { dent8Tools } from "dent8/langchain";

// The agent writes as a *low-authority* source: it can propose facts, but the firewall will
// not let it override a human- or CI-asserted one. source/authority are set here, not chosen
// by the model — that is the point.
const tools = dent8Tools({ source: "source:agent", authority: "low" });

async function main(): Promise<void> {
  if (!process.env.OPENAI_API_KEY) {
    console.log("dent8 tools wired:", tools.map((tool) => tool.name).join(", "));
    console.log("Set OPENAI_API_KEY to run the agent.");
    return;
  }

  const agent = createReactAgent({ llm: new ChatOpenAI({ model: "gpt-4o-mini" }), tools });
  const result = await agent.invoke({
    messages: [
      [
        "user",
        "Record that repo:myproj uses postgres as its database, then read it back and tell me why it is believed.",
      ],
    ],
  });
  console.log(result.messages.at(-1)?.content);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
