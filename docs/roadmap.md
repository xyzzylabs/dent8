# Roadmap

The target user is a coding agent or long-running developer assistant that must
remember project facts without silently retaining stale or contradicted context.
The failure modes dent8 attacks: **stale project facts, hidden contradiction,
poisoned summaries, and unexplained context retrieval.**

This roadmap is dependency-ordered: each item unlocks the next, and each is
annotated with the integrity invariant it makes real. It supersedes the older
phase-list MVP plan.

## Where the code actually is

See **[STATUS.md](STATUS.md)** for the authoritative tier list. In summary, the loop
now *runs* end to end in memory:

- **The firewall is enforced at the write boundary** (`EventStore::append` via
  `arbitrate`): authority-weighted supersession, the LFI canonical hard-alarm, and
  entity-aware anti-laundering — runnable via `dent8 demo`.
- serde + `canonical_bytes` + `event_hash`/`hash_chain` (M0) are wired into the
  in-memory store's append + `verify_chain`.
- The **coding-agent predicate registry** (M3) drives the firewall: per-predicate
  authority floor, default TTL, and uniqueness.
- `dent8 demo` exercises all of the above, and **`dent8 assert`/`dent8 explain` persist
  across invocations** via a local file-backed log (a second `EventStore` backend behind
  the same contract — `from_trusted_events` is the trusted-reload path).

What remains to make it a *product*, not a demo:

- The file log is a **dev store** — single-writer, non-transactional, single-user. The
  **operational** backend with atomic append + isolation is Postgres (§2 / M2b): the v0
  `PostgresEventStore` is **DB-verified** (advisory-lock-serialized transactional append,
  firewall via the shared `arbitrate_events`, JSONB event log + materialized projection/edge
  graph) — the `DATABASE_URL`-gated tests pass against a live `postgres:16`. Sharing the pure
  `arbitrate_events` means the firewall decision is the same tested code on both backends.
  The CLI/MCP **run on it** (`DENT8_DATABASE_URL`, a `--features postgres` build), each
  multi-event operation committed transactionally (`append_many`). What remains for a
  multi-user product is cryptographic caller identity (an authority *ceiling* per source is
  built — `dent8 authority`) and an *operated* witness service (the signed-tree-head witness
  *primitive* is built and runnable — `dent8 witness`).
- `assert`/`supersede`/`retract`/`contradict`/`explain`/`replay` are built (retract
  authority-gated per [ADR 0008](decisions/0008-retraction-authority.md); contradict +
  uniqueness-vs-contestation per [ADR 0009](decisions/0009-uniqueness-and-contestation.md));
  a v0 **MCP server** (`dent8 mcp serve`) exposes `assert`/`explain`/`replay` over stdio
  JSON-RPC. The full belief lifecycle is runnable.
- The **`dent8-evals` adversarial corpus** is built (firewall vs recency-only baseline:
  0/4 attacks succeed against the firewall, 4/4 against the baseline). Remaining eval work:
  property tests (`proptest`), fuzzing (`cargo-fuzz`), and golden replay fixtures.

Closing the remaining gap — *operational* persistence (Postgres) — turns the tool into a
product.

## 0. Core fold work (mostly done — arbitration, LFI, freshness, policy replay landed)

These are pure-`dent8-core` changes that make the integrity thesis true in the fold
itself, independent of storage. They are cheap and they are what makes dent8 more
than event-sourcing-with-nicer-words. They are also the prerequisite for *every*
defensible novelty direction ([research/novelty.md](research/novelty.md)): the
verified non-resurrection theorem proves a property of authority arbitration,
policy-counterfactual replay varies it, and earned entrenchment feeds it.

- **[DONE] Authority-as-entrenchment resolution.** `apply_event` rejects a
  `Superseded` event whose challenger authority is strictly below the incumbent's
  (`InsufficientAuthority`), confidence kept separate. Tested directly and
  exhaustively over the 5×5 authority lattice, with a `#[cfg(kani)]` non-resurrection
  harness. *([belief-revision.md](belief-revision.md) §Adopt-2.)*
- **[DONE] Earned entrenchment v0 (novelty rank 3).** `ClaimState` tracks
  authority-weighted `corroborating_sources` (`corroboration_at_or_above`, Sybil-
  resistant); `EntityProjection::unearned_supersessions` audits each supersession
  against the replacing claim's *actual* authority/corroboration, flagging
  `AuthorityDowngrade` and `WeakerCorroboration`. Still future: recording *rejected*
  supersession attempts (the "survived-challenge" half, a write-path feature) and
  turning the audit into a write-time gate.
  *([research/novelty.md](research/novelty.md) rank 3.)*
- **[DONE] LFI "gentle-explosion" tier.** `apply_event`'s `Contradicted` arm returns
  `CanonicalContradiction` for a contradiction against an `AuthorityLevel::Canonical`
  claim; ordinary contradictions still localize to `Contested`. Future: uniqueness-
  constrained predicates (no such flag in the model yet).
  *([belief-revision.md](belief-revision.md) §Adopt-3.)*
- **[DONE] Read-time freshness evaluator + read surface.** `ClaimState::is_expired_at(now)`
  evaluates TTL against the claim's `freshness_anchor` (`valid_from` → `observed_at` →
  `recorded_at`), kept separate from the lifecycle, and `explain` (CLI + the MCP `explain`
  tool + `resources/read`) now **applies** it: a still-`Active` fact past its TTL is
  headline-flagged `[stale — TTL elapsed]` and the receipt carries `fresh` + `expires_at`.
  *(Invariant T4 in [threat-model.md](threat-model.md); remaining residuals tracked there.)*
- **[DONE] Policy-counterfactual replay (novelty rank 2).** `EpistemicPolicy`
  (distrusted sources, authority floor, confidence floor) + `replay_claim_with_policy`
  + `diff_states` re-fold the same log under different trust assumptions, with zero
  model calls. *([research/novelty.md](research/novelty.md) rank 2.)*
- **[DONE] Cross-stream lineage check.** `replay_entity` folds all of an entity's
  claim streams into an `EntityProjection`; `lineage_issues()` flags dangling
  supersession, supersession-by-an-invalidated-claim, and supersession cycles
  (including self-supersession). Still pending: the `explain` CLI that surfaces it.
  Contradiction-edge integrity is deliberately out of scope (a contradictor may live
  in another entity).

## 1. [DONE in core] Serde + canonical serialization feeding the hash-chain (keystone)

**Status.** Built and tested in [`dent8-core/src/hash.rs`](../crates/dent8-core/src/hash.rs):
serde derives on the `ClaimEvent` graph; `canonical_bytes` (sorted-key `serde_json`
form — **not** JCS); `event_hash`/`hash_chain` (SHA-256, injective length-framed leaf,
`0x00` RFC 6962 domain separation); `CANON_VERSION` as the schema version. Tests cover
key-order independence, round-trip stability, injective genesis/`previous`, and
tamper-cascade. The migration's DB-generated `recorded_at`/edge `created_at` are
dropped. See [storage.md](storage.md) §Canonicalization and
[ADR 0004](decisions/0004-canonicalization-and-hash-chain.md).

**Crates.** `serde`, `serde_json`, `sha2`, `hex` (no `serde_jcs` — JCS interop is not
needed yet).

**Remaining (rolls into §2):** wire `hash_chain` into the transactional Postgres append
to populate `event_hash`/`previous_event_hash` and reverify on replay. (`ClaimValue::Json`
canonicalization — ADR 0004 item 6 — is **done**: the `CanonicalJson` newtype is canonical
by construction and on deserialize.)

## 2. dent8-store-postgres: sqlx adapter with transactional append + projection

**Why.** The crate is today only `INITIAL_SCHEMA_SQL`, `Migration`, and
`validate_identifier` — no async, no adapter. This is where dent8 becomes a store of
record.

**Invariant.** `projection == fold(events)` and append-atomicity.

**Concretely.** Implement `EventStore::append` in one transaction following
[storage.md](storage.md) §"Append transaction shape". Resolve the **sync-vs-async
trait decision** up front. Map `StoreError::Conflict` to unique-violation on
`event_id`/`event_hash`. Drop the `recorded_at DEFAULT now()` so the appender-supplied
timestamp is authoritative (the Rust core already reads it as such).

**Crates.** `sqlx`, `tokio`, reuse `sha2`.

## 3. Replay / explain CLI

**Why.** `dent8 replay`/`dent8 explain` are stubs returning exit code 2; only
`schema postgres` works. These are the demoable surface of the integrity thesis.

**Invariant.** Deterministic replay and auditability.

**Concretely.** `replay <claim_id|--all>` folds events by `global_sequence`,
re-derives each `event_hash`, asserts chain continuity, and records a `replay_runs`
row with a signed tree head. `explain <claim_id>` walks `dent8_claim_edges` +
provenance to print lineage, including the cross-stream lineage check from §0. Add
`--as-of <transaction-time>` and `--valid-at <valid-time>` to exercise both
bitemporal axes. Replace the hand-rolled arg match with `clap`.

**Crates.** `clap`, `serde_json`, `anyhow`.

## 4. Evals harness: golden fixtures + proptest + cargo-fuzz (start now, against the pure core)

**Why.** Integrity claims are only credible if measured.

**Status.** Started. The `dent8-evals` adversarial corpus exists, and two `proptest` suites
cover invariants (a): [`proptest_invariants.rs`](../crates/dent8-core/tests/proptest_invariants.rs)
(canonicalization/hash/anchor — idempotency + reload-stability over arbitrary JSON, serde
round-trips, tamper localization, anchor accept/reject) and
[`proptest_fold.rs`](../crates/dent8-core/tests/proptest_fold.rs) (the stateful `apply_event`
fold vs an independent reference model: accept/reject + reason + lifecycle, terminal
absorption, value immutability, replay determinism, claim isolation). **Golden replay
fixtures** are built too: [`golden_replay.rs`](../crates/dent8-core/tests/golden_replay.rs)
freezes named event streams ([`tests/golden/replay/`](../crates/dent8-core/tests/golden/replay))
as canonical `.events.jsonl` + an `.expected.json` (chain head + replayed-state summary), so
an encoding/hash/fold change is caught as a snapshot mismatch (regenerate with
`UPDATE_GOLDEN=1`). Remaining: `cargo-fuzz` over the deserialize→apply→canonicalize path.

**Invariant.** All stated invariants, mechanized — see the property list in
[formal-verification.md](formal-verification.md) §(a).

**Concretely.** A stateful/model-based harness with an independent reference model
generating random `ClaimEvent` streams. Seed `evals/fixtures` and `evals/replay`
with the families in [evals.md](evals.md), including the supersession scenario
("beginner-in-January → senior-in-November") and a `consistency_required` family for
the LFI tier. Add `cargo-fuzz` targets over the deserialize→apply→canonicalize path.
Optionally escalate terminal-immutability and fold-determinism to Kani via `bolero`
(documented as **bounded**, not universal).

**Crates.** `proptest`, `proptest-stateful`, `cargo-fuzz` + `libfuzzer-sys`,
optionally `bolero`.

## 5. MCP adapter (v0 built)

**Why late.** Pure orchestration over the store — it adds no integrity guarantee, so it
shipped after replay/explain proved the loop. A **v0 is built**: `dent8 mcp serve` runs a
synchronous, newline-delimited JSON-RPC 2.0 server over stdio (no async runtime, no new
heavy deps), handling `initialize` / `tools/list` / `tools/call` for the full belief
surface (`assert` / `supersede` / `retract` / `contradict` / `explain` / `replay`), plus
`resources/list` / `resources/read` (each fact stream as a `dent8://` resource) and
JSON-RPC batch requests. The tools dispatch to the shared `op_*` firewall path, so the same
arbitration applies over MCP as on the CLI (a low-authority write is refused, surfaced as a
tool error).

**Role.** *Enforce* the firewall at write time: it already rejects missing-provenance /
sub-floor / non-unique writes (T1) via `op_*`, across the full belief surface
(`assert`/`supersede`/`retract`/`contradict`/`explain`/`replay`), plus `resources/list` /
`resources/read` and JSON-RPC batch requests. The freshness filter on reads (T4) is applied
— `explain` headline-flags a stale fact and the receipt carries `fresh` + `expires_at`.
Still to add: the official `rmcp` SDK / richer transports.
See [interfaces.md](interfaces.md).

**Crate.** v0 is hand-rolled on `serde_json` (zero new deps); the official Rust MCP SDK
(`rmcp`) is the upgrade path if richer protocol features (resources, sampling, batch) are
needed.

## Dependency summary

```
§0 core arbitration (cheap, parallel)
§1 serde + JCS + hash  ->  §2 sqlx adapter  ->  §3 replay/explain CLI  ->  §5 MCP
§4 evals: start now against the pure core, grow with §1-3
```

§1 is the keystone (blocks §2/§3 and the canonicalization fixtures in §4). §0 is
cheap and parallel. §4 can begin immediately against the pure core. §5 is strictly
last. Two decisions to resolve before coding the adapter:
(a) `recorded_at` appender-supplied vs `DEFAULT now()` (resolved: drop the default);
(b) sync-vs-async `EventStore` trait (open).

## Later

Postgres multi-tenant partitioning · DuckDB replay/forensics over exported Parquet ·
ATMS-style assumption-environment replay for the debugger ·
[valid-time intervals (`valid_to`)](decisions/0005-belief-base-revision-semantics.md) ·
predicate-level volatility policy · HTTP API and SDKs · adapters for existing memory
providers · an external witness (published signed tree head) for non-repudiation.
