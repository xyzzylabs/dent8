// First-class LangChain.js tools, tested against the real dent8 binary + `@langchain/core`.
// The tool set builds with no binary; the round-trip / refusal tests drive the firewall, so
// they skip cleanly when no binary is present:
//
//   cargo build -p dent8-cli
//   DENT8_BIN=../../target/debug/dent8 npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

import { dent8Tools } from "../dist/langchain.js";
import { Dent8 } from "../dist/index.js";

// Resolve a relative DENT8_BIN to absolute — the tests set `cwd` to a tmp store, so a
// relative binary path would no longer resolve from there (a bare PATH name is left alone).
const RAW = process.env.DENT8_BIN;
const BINARY = RAW
  ? RAW.includes("/")
    ? resolve(RAW)
    : RAW
  : spawnSync("dent8", ["--version"], { encoding: "utf8" }).status === 0
    ? "dent8"
    : undefined;
const skip = BINARY ? false : "no dent8 binary (set DENT8_BIN or install dent8-cli)";

const NAMES = [
  "dent8_dispute_fact",
  "dent8_explain_fact",
  "dent8_list_facts",
  "dent8_record_fact",
  "dent8_revise_fact",
  "dent8_verify",
];

/** A throwaway store in permissive dev mode (ambient DENT8_* scrubbed, paths pinned). */
function store() {
  const dir = mkdtempSync(join(tmpdir(), "dent8-lc-"));
  const env = { DENT8_LOG: join(dir, "memory.jsonl"), DENT8_AUTHORITY: join(dir, "authority.json") };
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("DENT8_") && key !== "DENT8_BIN") delete process.env[key];
  }
  return { cwd: dir, env };
}

const byName = (tools, name) => tools.find((t) => t.name === name);

test("exposes the six belief-surface tools", () => {
  const tools = dent8Tools();
  assert.deepEqual(tools.map((t) => t.name).sort(), NAMES);
});

test("write tools expose only subject/predicate/value — never source/authority", () => {
  const tools = dent8Tools({ source: "source:agent", authority: "low" });
  const props = Object.keys(byName(tools, "dent8_record_fact").schema.properties).sort();
  // The agent picks *what* to record; source and authority are deployment config, so it
  // cannot escalate its own authority through a tool argument.
  assert.deepEqual(props, ["predicate", "subject", "value"]);
});

test("record then explain round-trips through the firewall", { skip }, async () => {
  const tools = dent8Tools({ binary: BINARY, ...store(), source: "source:agent", authority: "high" });
  const recorded = await byName(tools, "dent8_record_fact").invoke({
    subject: "repo:acme",
    predicate: "deploy_target",
    value: "fly.io",
  });
  assert.match(recorded, /^recorded:/);
  const explained = await byName(tools, "dent8_explain_fact").invoke({
    subject: "repo:acme",
    predicate: "deploy_target",
  });
  assert.match(explained, /fly\.io/);
});

test("a refused write comes back as a tool result, not a throw", { skip }, async () => {
  const shared = store();
  // A human writes the incumbent at high authority, out of band.
  new Dent8({ binary: BINARY, ...shared }).assertFact("repo:acme", "database", "postgres", {
    authority: "high",
    source: "user:alice",
  });
  // The agent is wired low: it can propose but cannot override.
  const tools = dent8Tools({ binary: BINARY, ...shared, source: "source:agent", authority: "low" });
  const refusal = await byName(tools, "dent8_revise_fact").invoke({
    subject: "repo:acme",
    predicate: "database",
    value: "mysql",
  });
  assert.match(refusal, /refused by the firewall/);
  // and the firewall held:
  const explained = await byName(tools, "dent8_explain_fact").invoke({
    subject: "repo:acme",
    predicate: "database",
  });
  assert.match(explained, /postgres/);
});
