// Independent MCP contract coverage against the real dent8 binary. The official SDK owns
// protocol decoding and schema validation here, so this catches wire incompatibilities that
// dent8's Rust-side assertions can accidentally agree with themselves about.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { CallToolResultSchema, ListToolsResultSchema } from "@modelcontextprotocol/sdk/types.js";

const RAW = process.env.DENT8_BIN;
const BINARY = RAW
  ? RAW.includes("/")
    ? resolve(RAW)
    : RAW
  : spawnSync("dent8", ["--version"], { encoding: "utf8" }).status === 0
    ? "dent8"
    : undefined;
const skip = BINARY ? false : "no dent8 binary (set DENT8_BIN or install dent8-cli)";

function isolatedEnvironment(dir) {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key, value]) => !key.startsWith("DENT8_") && value !== undefined),
  );
  return {
    ...env,
    DENT8_LOG: join(dir, "memory.jsonl"),
    DENT8_AUTHORITY: join(dir, "authority.json"),
  };
}

test("official MCP SDK accepts dent8 tools and structured output", { skip, timeout: 20_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "dent8-mcp-conformance-"));
  const transport = new StdioClientTransport({
    command: BINARY,
    args: ["mcp", "serve"],
    cwd: dir,
    env: isolatedEnvironment(dir),
    stderr: "pipe",
  });
  const client = new Client({ name: "dent8-conformance-test", version: "1.0.0" });

  try {
    await client.connect(transport);

    // listTools() already parses with ListToolsResultSchema. Parse explicitly too so the
    // independent contract under test stays visible and reviewable at this call site.
    const listed = await client.listTools();
    ListToolsResultSchema.parse(listed);
    assert.equal(listed.tools.length, 17);
    assert.ok(listed.tools.every((tool) => tool.inputSchema.type === "object"));
    assert.ok(listed.tools.every((tool) => tool.outputSchema?.type === "object"));

    // The SDK also compiles each advertised output schema after tools/list and validates the
    // structured result returned by callTool(). This exercises both halves of the contract.
    const status = await client.callTool({ name: "runtime_status", arguments: {} });
    CallToolResultSchema.parse(status);
    assert.equal(status.isError, false);
    assert.equal(status.structuredContent?.status, "ok");
    assert.equal(status.structuredContent?.server?.protocol_version, "2025-11-25");
  } finally {
    try {
      await client.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }
});
