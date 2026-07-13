/**
 * First-class dent8 tools for the [Vercel AI SDK](https://ai-sdk.dev).
 *
 * Unlike wiring dent8 in over MCP (`examples/vercel-ai-sdk/`), these are **native AI SDK
 * tools** built directly on the {@link Dent8} SDK — no MCP subprocess client to keep in sync,
 * and firewall refusals surfaced to the model *as tool results* so it learns and adapts
 * instead of overwriting.
 *
 * ```ts
 * import { generateText } from "ai";
 * import { openai } from "@ai-sdk/openai";
 * import { dent8Tools } from "dent8/ai";
 *
 * const { text } = await generateText({
 *   model: openai("gpt-4o"),
 *   tools: dent8Tools({ source: "source:agent", authority: "low" }),
 *   prompt: "Record that repo:acme deploys to fly.io, then read it back.",
 * });
 * ```
 *
 * Needs the peer dependency: `npm i ai`. The *source* and *authority* every write carries are
 * your configuration, never LLM arguments — see {@link Dent8ToolsOptions}.
 */

import { tool, jsonSchema, type Tool } from "ai";

import { dent8ToolSpecs, type Dent8ToolsOptions } from "./tools.js";

export type { Dent8ToolsOptions } from "./tools.js";

/**
 * Build the dent8 belief-surface as Vercel AI SDK tools, keyed by tool name and ready to pass
 * straight to `generateText` / `streamText`'s `tools`.
 *
 * @returns a record of `dent8_record_fact`, `dent8_revise_fact`, `dent8_dispute_fact`,
 *   `dent8_explain_fact`, `dent8_list_facts`, `dent8_verify`.
 */
export function dent8Tools(options: Dent8ToolsOptions = {}): Record<string, Tool> {
  const tools: Record<string, Tool> = {};
  for (const spec of dent8ToolSpecs(options)) {
    tools[spec.name] = tool({
      description: spec.description,
      // JSON Schema, not zod — so the SDK does not require zod as a dependency.
      inputSchema: jsonSchema<Record<string, unknown>>(spec.inputSchema),
      execute: async (args: Record<string, unknown>) => spec.execute(args),
    });
  }
  return tools;
}
