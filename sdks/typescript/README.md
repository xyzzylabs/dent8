# dent8 (TypeScript)

A memory firewall for coding agents — the thin TypeScript SDK.

Every call runs the [`dent8`](https://github.com/xyzzylabs/dent8) binary with
`--output json` and returns the parsed payload. The wire contract is the product:
each payload carries `schema_version`; every error carries a stable `status` plus a
machine-readable `code` (`insufficient-authority`, `authority-ceiling`,
`content-rejected`, …), thrown as `Dent8Rejected` / `Dent8Invalid` so you branch on
`error.code`, never on prose.

Because the CLI resolves the store itself (repo-confined `.dent8/` discovery,
`DENT8_LOG` / `DENT8_STORE_URL`), routes writes through a local daemon when
`DENT8_DAEMON_SOCKET` is set, and defaults `source`/`authority` from the active
signed grant, the SDK inherits all of it with zero configuration.

Writes **above the agent tier** (`medium` / `high` / `canonical` authority) require a
valid signed identity: run `dent8 init` (which provisions one by default) and let the SDK
inherit its `DENT8_TRUST` / `DENT8_GRANT` / `DENT8_IDENTITY_KEY` env, then write as that
`source:*` identity. Agent-tier writes (`low`) need no identity.

## Install

```sh
npm install dent8
cargo install dent8-cli --locked   # the binary the SDK drives
```

## Use

```ts
import { Dent8, Dent8Rejected } from "dent8";

const d8 = new Dent8(); // finds `dent8` on PATH; new Dent8({ binary, env }) to pin

// A high-authority write is signed as the active `source:*` identity (`source:local` from
// `dent8 init`; pass `dent8 init --source source:<name>` to provision a different one).
d8.assertFact("repo:myproj", "database", "postgres",
              { authority: "high", source: "source:local" });

try {
  d8.supersede("repo:myproj", "database", "mysql",
               { authority: "low", source: "web:scrape" });
} catch (rejection) {
  if (rejection instanceof Dent8Rejected) {
    console.log(rejection.code); // "insufficient-authority" — branch on the code
  }
}

const fact = d8.explain("repo:myproj", "database");
// fact.value.text === "postgres" — the firewall held

const report = d8.verify();      // findings are a result: status ok | integrity_issues
const disputes = d8.conflicts(); // status contested when live disputes exist
```

The belief surface maps 1:1 onto the CLI: `assertFact`, `supersede`, `contradict`,
`retract`, `reinforce`, `expire`, `derive(subject, predicate, value, { basis })`,
`explain`, `replay`, `facts`, `verify`, `conflicts`. Temporal options accept the
CLI's whole grammar — unix millis, `"now"`, `"-7d"`, RFC 3339, or a bare UTC date.

## Framework tools

For LLM tool-calling agents, the package ships **first-class tools** for the two big
TypeScript frameworks — native tool objects built on this SDK (no MCP subprocess to keep in
sync), with typed arguments and firewall refusals surfaced to the model *as tool results* it
reads and adapts to.

**Vercel AI SDK** — `npm i ai`:

```ts
import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";
import { dent8Tools } from "dent8/ai";

const { text } = await generateText({
  model: openai("gpt-4o"),
  tools: dent8Tools({ source: "source:agent", authority: "low" }),
  prompt: "Record that repo:acme deploys to fly.io, then read it back.",
});
```

**LangChain.js** — `npm i @langchain/core`:

```ts
import { dent8Tools } from "dent8/langchain";
import { createReactAgent } from "@langchain/langgraph/prebuilt";

const agent = createReactAgent({
  llm,
  tools: dent8Tools({ source: "source:agent", authority: "low" }),
});
```

Both give you `dent8_record_fact` / `dent8_revise_fact` / `dent8_dispute_fact` /
`dent8_explain_fact` / `dent8_list_facts` / `dent8_verify`. They expose *what* to record
(subject, predicate, value); **source and authority are your configuration, not LLM
arguments**, so the agent cannot escalate its own authority. See
[examples/vercel-ai-sdk](https://github.com/xyzzylabs/dent8/tree/main/examples/vercel-ai-sdk)
and [examples/langchain-js](https://github.com/xyzzylabs/dent8/tree/main/examples/langchain-js).

For another framework (LlamaIndex-TS, Mastra, your own), `import { dent8ToolSpecs } from
"dent8/tools"` gives the same six tools as framework-agnostic specs (name, description,
JSON-Schema, `execute`) with zero extra dependencies — wrap each in your framework's tool
object. Or connect any MCP client to `dent8 mcp serve` (over stdio / the local daemon / HTTP).

## Test

```sh
cargo build -p dent8-cli
DENT8_BIN=../../target/debug/dent8 npm test
```
