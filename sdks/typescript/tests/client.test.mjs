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
import { execFileSync, spawnSync } from "node:child_process";

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

/** Bootstrap a self-contained signed identity authorizing `source` (a `source:*` id) up to
 * Canonical in its own bundle under `dir`, and return the DENT8_* signing vars. Above-agent
 * authority (medium/high/canonical) now requires a valid signed identity, so a client that makes
 * such a write threads these in; a plain (agent-tier) client omits them so the firewall's authority
 * arbitration — not the identity gate — judges its low writes. */
function signingEnv(dir, source) {
  const slug = source.replace(/[^A-Za-z0-9._-]/g, "_");
  const bundle = join(dir, `id-${slug}`);
  execFileSync(
    BINARY,
    ["identity", "bootstrap", "--dir", bundle, "--source", source, "--max", "canonical", "--issuer-key", join(dir, `issuer-${slug}.key`)],
    { encoding: "utf8" },
  );
  return {
    DENT8_TRUST: join(bundle, "trust.json"),
    DENT8_GRANT: join(bundle, "grants", `${slug}.grant.json`),
    DENT8_IDENTITY_KEY: join(bundle, "identities", `${slug}.key`),
    DENT8_ACTIVE_GRANTS: join(bundle, "active-grants.json"),
    DENT8_REQUIRE_IDENTITY: "1",
  };
}

/** A throwaway store in permissive dev mode: every ambient DENT8_* variable is scrubbed (the
 * developer's shell may carry a dogfood store with identity enforcement), then the store paths are
 * pinned to a tmp dir. `signed(source)` returns a client that signs above-agent writes as that
 * `source:*` identity; `plain()` returns an unsigned agent-tier client on the same store. */
function store() {
  const dir = mkdtempSync(join(tmpdir(), "dent8-sdk-"));
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("DENT8_") && key !== "DENT8_BIN") delete process.env[key];
  }
  const base = { DENT8_LOG: join(dir, "memory.jsonl"), DENT8_AUTHORITY: join(dir, "authority.json") };
  return {
    dir,
    plain: () => new Dent8({ binary: BINARY, cwd: dir, env: { ...base } }),
    signed: (source) => new Dent8({ binary: BINARY, cwd: dir, env: { ...base, ...signingEnv(dir, source) } }),
  };
}

test("assert/explain round trip", { skip }, () => {
  // `repo.database` has a High authority floor, so the assertion is an above-agent write — it
  // must be signed. Signed identities are `source:*`-scoped, so the writer is `source:alice`.
  const d8 = store().signed("source:alice");
  const written = d8.assertFact("repo:myproj", "database", "postgres", {
    authority: "high",
    source: "source:alice",
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
  // A signed human writes the high incumbents; an unsigned agent-tier challenger (no grant, so the
  // firewall's *authority* arbitration — not the identity gate — judges it) tries to override.
  const st = store();
  const human = st.signed("source:alice");
  const agent = st.plain();

  // A high fact challenged by a low supersession: pure arbitration — low cannot displace high.
  human.assertFact("person:alice", "favorite_drink", "tea", { authority: "high", source: "source:alice" });
  assert.throws(
    () => agent.supersede("person:alice", "favorite_drink", "coffee", { authority: "low", source: "note:old" }),
    (error) => {
      assert.ok(error instanceof Dent8Rejected);
      assert.equal(error.status, "rejected");
      assert.equal(error.code, "insufficient-authority");
      assert.equal(error.payload.schema_version, SCHEMA_VERSION);
      return true;
    },
  );

  // A registered predicate (`database` has a floor) is refused by the policy gate first.
  human.assertFact("repo:myproj", "database", "postgres", { authority: "high", source: "source:alice" });
  assert.throws(
    () => agent.supersede("repo:myproj", "database", "mysql", { authority: "low", source: "web:scrape" }),
    (error) => error instanceof Dent8Rejected && error.code === "below-authority-floor",
  );

  // The incumbents survived both challenges.
  assert.equal(human.explain("person:alice", "favorite_drink").value.text, "tea");
  assert.equal(human.explain("repo:myproj", "database").value.text, "postgres");
});

test("invalid input is invalid, not rejected", { skip }, () => {
  // A well-formed agent-tier write with a malformed subject: the invalid-input gate (exit 2) must
  // fire on the subject, distinct from a firewall rejection (exit 1).
  const d8 = store().plain();
  assert.throws(
    () => d8.assertFact("no-colon", "p", "v", { authority: "low", source: "source:agent" }),
    (error) => error instanceof Dent8Invalid,
  );
});

test("a value beginning with a hyphen is a value, not a flag", { skip }, () => {
  // The SDK emits the option flags before `--`, so a compiler-flag-shaped value reaches the
  // CLI's positional as text; without the separator clap reads it as an unknown flag (exit 2)
  // and nothing is written.
  const d8 = store().plain();
  const written = d8.assertFact("repo:acme", "build_flag", "-Werror", {
    authority: "low",
    source: "source:agent",
  });
  assert.equal(written.status, "accepted");
  assert.equal(d8.explain("repo:acme", "build_flag").value.text, "-Werror");

  d8.supersede("repo:acme", "build_flag", "--strict", { authority: "low", source: "source:agent" });
  assert.equal(d8.explain("repo:acme", "build_flag").value.text, "--strict");
});

test("derive -> retract -> taint flow", { skip }, () => {
  // `repo.database` is High-floored, so every write here is an above-agent signed write.
  const d8 = store().signed("source:alice");
  d8.assertFact("repo:myproj", "database", "postgres", { authority: "high", source: "source:alice" });
  const derived = d8.derive("service:api", "datastore", "postgres", {
    basis: ["repo:myproj", "database"],
    authority: "high",
    source: "source:alice",
  });
  assert.equal(derived.status, "accepted");

  d8.retract("repo:myproj", "database", { authority: "high", source: "source:alice" });
  const report = d8.verify();
  assert.equal(report.status, "integrity_issues");
  assert.equal(report.ok, false);
});

test("reads, human time grammar, and conflicts", { skip }, () => {
  // Two signed humans disagree at High over a High-floored predicate: alice asserts, bob dissents.
  const st = store();
  const alice = st.signed("source:alice");
  const bob = st.signed("source:bob");
  // A bare UTC date is one of the human time grammars; it is computed 30 days out so the
  // freshness it claims stays inside `repo.database`'s retention ceiling (a far-future
  // valid_to reaches too far and is rejected, not clamped).
  const validTo = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  alice.assertFact("repo:myproj", "database", "postgres", {
    authority: "high",
    source: "source:alice",
    validTo,
  });
  assert.equal(alice.facts().count, 1);
  assert.equal(alice.replay("repo:myproj", "database").events[0].kind, "fact.asserted");

  // A week ago the fact did not exist.
  assert.throws(() => alice.explain("repo:myproj", "database", { asOf: "-7d" }));

  assert.equal(alice.conflicts().status, "ok");
  bob.contradict("repo:myproj", "database", "mysql", { authority: "high", source: "source:bob" });
  const contested = alice.conflicts();
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
