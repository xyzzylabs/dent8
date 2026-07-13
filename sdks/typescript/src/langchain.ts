/**
 * First-class dent8 tools for [LangChain.js](https://js.langchain.com).
 *
 * Unlike wiring dent8 in over MCP, these are **native LangChain tools** built directly on the
 * {@link Dent8} SDK — no MCP subprocess client to keep in sync, and firewall refusals
 * surfaced to the model *as tool results* so it learns and adapts instead of overwriting.
 *
 * ```ts
 * import { ChatOpenAI } from "@langchain/openai";
 * import { createReactAgent } from "@langchain/langgraph/prebuilt";
 * import { dent8Tools } from "dent8/langchain";
 *
 * const agent = createReactAgent({
 *   llm: new ChatOpenAI({ model: "gpt-4o" }),
 *   tools: dent8Tools({ source: "source:agent", authority: "low" }),
 * });
 * ```
 *
 * Needs the peer dependency: `npm i @langchain/core`. The *source* and *authority* every write
 * carries are your configuration, never LLM arguments — see {@link Dent8ToolsOptions}.
 */

import { tool, type StructuredToolInterface } from "@langchain/core/tools";

import { dent8ToolSpecs, type Dent8ToolsOptions } from "./tools.js";

export type { Dent8ToolsOptions } from "./tools.js";

/**
 * Build the dent8 belief-surface as LangChain.js structured tools, ready to hand to an agent
 * (e.g. `createReactAgent({ llm, tools })`).
 *
 * @returns `dent8_record_fact`, `dent8_revise_fact`, `dent8_dispute_fact`,
 *   `dent8_explain_fact`, `dent8_list_facts`, `dent8_verify`.
 */
export function dent8Tools(options: Dent8ToolsOptions = {}): StructuredToolInterface[] {
  return dent8ToolSpecs(options).map((spec) =>
    tool((args) => spec.execute(args as Record<string, unknown>), {
      name: spec.name,
      description: spec.description,
      // JSON Schema, not zod — so the SDK does not require zod as a dependency.
      schema: spec.inputSchema,
    }),
  );
}
