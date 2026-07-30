// First-class Vercel AI SDK tools, tested against the real dent8 binary + `ai`. The tool
// set builds with no binary; the round-trip / refusal tests drive the firewall, so they
// skip cleanly when no binary is present:
//
//   cargo build -p dent8-cli
//   DENT8_BIN=../../target/debug/dent8 npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";

import { dent8Tools } from "../dist/ai.js";
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
  const dir = mkdtempSync(join(tmpdir(), "dent8-ai-"));
  const env = { DENT8_LOG: join(dir, "memory.jsonl"), DENT8_AUTHORITY: join(dir, "authority.json") };
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("DENT8_") && key !== "DENT8_BIN") delete process.env[key];
  }
  return { cwd: dir, env };
}

/** A signed human writer on `shared`'s store. Above-agent authority (medium/high/canonical) now
 * requires a valid signed identity, so an out-of-band human high write bootstraps a `source:*`
 * identity (up to Canonical) and threads its signing env in. The agent tools stay on the plain
 * store env, so their low writes are judged by the firewall's authority arbitration. */
function humanWriter(shared, source = "source:alice") {
  const slug = source.replace(/[^A-Za-z0-9._-]/g, "_");
  const bundle = join(shared.cwd, `id-${slug}`);
  execFileSync(
    BINARY,
    ["identity", "bootstrap", "--dir", bundle, "--source", source, "--max", "canonical", "--issuer-key", join(shared.cwd, `issuer-${slug}.key`)],
    { encoding: "utf8" },
  );
  const signing = {
    DENT8_TRUST: join(bundle, "trust.json"),
    DENT8_GRANT: join(bundle, "grants", `${slug}.grant.json`),
    DENT8_IDENTITY_KEY: join(bundle, "identities", `${slug}.key`),
    DENT8_ACTIVE_GRANTS: join(bundle, "active-grants.json"),
    DENT8_REQUIRE_IDENTITY: "1",
  };
  return new Dent8({ binary: BINARY, cwd: shared.cwd, env: { ...shared.env, ...signing } });
}

test("exposes the six belief-surface tools keyed by name", () => {
  const tools = dent8Tools();
  assert.deepEqual(Object.keys(tools).sort(), NAMES);
});

test("write tools expose only subject/predicate/value — never source/authority", () => {
  const tools = dent8Tools({ source: "source:agent", authority: "low" });
  const props = Object.keys(tools.dent8_record_fact.inputSchema.jsonSchema.properties).sort();
  // The agent picks *what* to record; source and authority are deployment config, so it
  // cannot escalate its own authority through a tool argument.
  assert.deepEqual(props, ["predicate", "subject", "value"]);
});

test("record then explain round-trips through the firewall", { skip }, async () => {
  // The agent is wired at the agent tier (low) — it cannot escalate its own authority, and an
  // agent-tier write needs no signed identity. `deploy_target` is unregistered (no floor).
  const tools = dent8Tools({ binary: BINARY, ...store(), source: "source:agent", authority: "low" });
  const recorded = await tools.dent8_record_fact.execute(
    { subject: "repo:acme", predicate: "deploy_target", value: "fly.io" },
    {},
  );
  assert.match(recorded, /^recorded:/);
  const explained = await tools.dent8_explain_fact.execute(
    { subject: "repo:acme", predicate: "deploy_target" },
    {},
  );
  assert.match(explained, /fly\.io/);
});

test("a hyphen-leading value survives the tool boundary", { skip }, async () => {
  // What an LLM records is often flag-shaped (`-Werror`, `--strict`); the value must reach the
  // firewall as a value rather than tripping the CLI's option parser.
  const tools = dent8Tools({ binary: BINARY, ...store(), source: "source:agent", authority: "low" });
  const recorded = await tools.dent8_record_fact.execute(
    { subject: "repo:acme", predicate: "build_flag", value: "-Werror" },
    {},
  );
  assert.match(recorded, /^recorded:/);
  const explained = await tools.dent8_explain_fact.execute(
    { subject: "repo:acme", predicate: "build_flag" },
    {},
  );
  assert.match(explained, /-Werror/);
});

test("a malformed call reads as invalid arguments, not a refusal", { skip }, async () => {
  // Exit 2 is the model's own argument bug, not a firewall decision — telling it the firewall
  // refused would teach the wrong lesson about a mistake it can simply fix.
  const tools = dent8Tools({ binary: BINARY, ...store(), source: "source:agent", authority: "low" });
  const invalid = await tools.dent8_record_fact.execute(
    { subject: "no-colon", predicate: "deploy_target", value: "fly.io" },
    {},
  );
  assert.match(invalid, /^invalid arguments:/);
  assert.doesNotMatch(invalid, /refused by the firewall/);
});

test("a refused write comes back as a tool result, not a throw", { skip }, async () => {
  const shared = store();
  // A signed human writes the incumbent at high authority, out of band.
  humanWriter(shared, "source:alice").assertFact("repo:acme", "database", "postgres", {
    authority: "high",
    source: "source:alice",
  });
  // The agent is wired low: it can propose but cannot override.
  const tools = dent8Tools({ binary: BINARY, ...shared, source: "source:agent", authority: "low" });
  const refusal = await tools.dent8_revise_fact.execute(
    { subject: "repo:acme", predicate: "database", value: "mysql" },
    {},
  );
  assert.match(refusal, /refused by the firewall/);
  // and the firewall held:
  const explained = await tools.dent8_explain_fact.execute(
    { subject: "repo:acme", predicate: "database" },
    {},
  );
  assert.match(explained, /postgres/);
});
