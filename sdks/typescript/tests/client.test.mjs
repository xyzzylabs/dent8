// End-to-end tests against the real dent8 binary (the SDK is a thin wrapper, so the
// binary IS the unit under test). Point DENT8_BIN at a built binary, or have `dent8`
// on PATH; the suite skips cleanly otherwise:
//
//   cargo build -p dent8-cli
//   DENT8_BIN=../../target/debug/dent8 npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

import { Dent8, Dent8Invalid, Dent8Rejected, SCHEMA_VERSION } from "../dist/index.js";

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

/** A client pinned to a throwaway store in permissive dev mode: every ambient DENT8_*
 * variable is scrubbed (the developer's shell may carry a dogfood store with identity
 * enforcement), then the store paths are pinned to a tmp dir. */
function client() {
  const dir = mkdtempSync(join(tmpdir(), "dent8-sdk-"));
  const env = { DENT8_LOG: join(dir, "memory.jsonl"), DENT8_AUTHORITY: join(dir, "authority.json") };
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("DENT8_") && key !== "DENT8_BIN") delete process.env[key];
  }
  return new Dent8({ binary: BINARY, cwd: dir, env });
}

test("assert/explain round trip", { skip }, () => {
  const d8 = client();
  const written = d8.assertFact("repo:myproj", "database", "postgres", {
    authority: "high",
    source: "user:alice",
  });
  assert.equal(written.schema_version, SCHEMA_VERSION);
  assert.equal(written.status, "accepted");
  assert.equal(written.accepted, true);

  const fact = d8.explain("repo:myproj", "database");
  assert.equal(fact.status, "ok");
  assert.equal(fact.value.text, "postgres");
  assert.equal(fact.authority, "high");
});

test("firewall rejections carry the code", { skip }, () => {
  const d8 = client();
  // An unregistered predicate exercises pure arbitration: low cannot displace high.
  d8.assertFact("person:alice", "favorite_drink", "tea", { authority: "high", source: "user:alice" });
  assert.throws(
    () => d8.supersede("person:alice", "favorite_drink", "coffee", { authority: "low", source: "note:old" }),
    (error) => {
      assert.ok(error instanceof Dent8Rejected);
      assert.equal(error.status, "rejected");
      assert.equal(error.code, "insufficient-authority");
      assert.equal(error.payload.schema_version, SCHEMA_VERSION);
      return true;
    },
  );

  // A registered predicate (`database` has a floor) is refused by the policy gate first.
  d8.assertFact("repo:myproj", "database", "postgres", { authority: "high", source: "user:alice" });
  assert.throws(
    () => d8.supersede("repo:myproj", "database", "mysql", { authority: "low", source: "web:scrape" }),
    (error) => error instanceof Dent8Rejected && error.code === "below-authority-floor",
  );

  // The incumbents survived both challenges.
  assert.equal(d8.explain("person:alice", "favorite_drink").value.text, "tea");
  assert.equal(d8.explain("repo:myproj", "database").value.text, "postgres");
});

test("invalid input is invalid, not rejected", { skip }, () => {
  const d8 = client();
  assert.throws(
    () => d8.assertFact("no-colon", "p", "v", { authority: "high", source: "user:alice" }),
    (error) => error instanceof Dent8Invalid,
  );
});

test("derive -> retract -> taint flow", { skip }, () => {
  const d8 = client();
  d8.assertFact("repo:myproj", "database", "postgres", { authority: "high", source: "user:alice" });
  const derived = d8.derive("service:api", "datastore", "postgres", {
    basis: ["repo:myproj", "database"],
    authority: "high",
    source: "user:alice",
  });
  assert.equal(derived.status, "accepted");

  d8.retract("repo:myproj", "database", { authority: "high", source: "user:alice" });
  const report = d8.verify();
  assert.equal(report.status, "integrity_issues");
  assert.equal(report.ok, false);
});

test("reads, human time grammar, and conflicts", { skip }, () => {
  const d8 = client();
  d8.assertFact("repo:myproj", "database", "postgres", {
    authority: "high",
    source: "user:alice",
    validTo: "2036-01-01",
  });
  assert.equal(d8.facts().count, 1);
  assert.equal(d8.replay("repo:myproj", "database").events[0].kind, "fact.asserted");

  // A week ago the fact did not exist.
  assert.throws(() => d8.explain("repo:myproj", "database", { asOf: "-7d" }));

  assert.equal(d8.conflicts().status, "ok");
  d8.contradict("repo:myproj", "database", "mysql", { authority: "high", source: "user:bob" });
  const contested = d8.conflicts();
  assert.equal(contested.status, "contested");
  assert.equal(contested.count, 1);
});

test("a missing binary reports clearly", () => {
  const ghost = new Dent8({ binary: "/definitely/not/dent8" });
  assert.throws(
    () => ghost.facts(),
    (error) => error.code === "ENOENT",
  );
});
