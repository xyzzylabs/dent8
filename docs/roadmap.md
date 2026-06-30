# Roadmap

The target user is a coding agent or long-running developer assistant that must
remember project facts without silently retaining stale or contradicted context.
The failure modes dent8 attacks: **stale project facts, hidden contradiction,
poisoned summaries, and unexplained context retrieval.**

This roadmap is dependency-ordered: each item unlocks the next, and each is
annotated with the integrity invariant it makes real. It supersedes the older
MVP checklist.

## Where the code actually is

See **[STATUS.md](STATUS.md)** for the authoritative tier list. In summary, the MVP loop
now runs end to end through the CLI and MCP surfaces:

- **The firewall is enforced at the write boundary** (`EventStore::append` via
  `arbitrate`): authority-weighted supersession, the LFI canonical hard-alarm, and
  entity-aware anti-laundering — runnable via `dent8 demo`, the lifecycle CLI commands,
  and `dent8 mcp serve`.
- serde + `canonical_bytes` + `event_hash`/`hash_chain` are wired into append and
  verification; the Postgres adapter stores and re-verifies the global chain.
- The **coding-agent predicate registry** drives the firewall: per-predicate
  authority floor, default TTL, and uniqueness.
- The full lifecycle is runnable and persistent:
  `assert`/`supersede`/`retract`/`contradict`/`reinforce`/`expire`/`derive`/`explain`/
  `replay`/`verify`/`conflicts`/`eval`/`export`, plus MCP tools for the same belief
  surface.
- Persistence runs over the local file dev store by default, or over the transactional
  async backends selected by `DENT8_STORE_URL`: Postgres (`--features postgres`) and
  embedded SQLite (`--features sqlite`).

What remains to make it a hardened multi-user product:

- **Cryptographic caller identity (authn).** `dent8 authority` provides source→authority
  ceilings (authz), but the caller's source id is still asserted rather than proven by a
  signed grant/token.
- **Operated witness service.** `dent8 witness` is a runnable signed-tree-head primitive;
  the remaining product work is running it on separate infrastructure, publishing heads,
  monitoring rollback/rewrite alarms, and rotating keys.
- **Production ergonomics and heavy-concurrency polish.** The Postgres adapter serializes
  appends and the CLI retries id collisions, but DB-assigned ids remain the end-state for
  heavy write fan-out.
- **Richer protocol/product surfaces.** The v0 MCP server is useful today; official `rmcp`,
  richer transports, `resources/subscribe`, prompts, HTTP, SDKs, and a debugger UI are later.
- **Remaining formal/eval work.** `proptest` suites, golden replay fixtures, scenario-family
  fixtures, and the adversarial corpus are built. `cargo-fuzz` and the Stateright-style
  append/projection model remain open.

Operational persistence is no longer the gap — it is **built and runnable on two backends**
(Postgres and embedded SQLite, behind the `AsyncEventStore` boundary). The remaining gap is
*productization*: cryptographic caller identity (authn) and an *operated* witness service.

## Core Fold Work — Done For MVP

These are pure-`dent8-core` changes that make the integrity thesis true in the fold
itself, independent of storage. They are cheap and they are what makes dent8 more
than event-sourcing-with-nicer-words. They are also the prerequisite for *every*
defensible novelty direction ([research/novelty.md](research/novelty.md)): the
verified non-resurrection theorem proves a property of authority arbitration,
policy-counterfactual replay varies it, and earned entrenchment feeds it. The MVP
mechanisms are built; the remaining bullets here are refinements, not blockers.

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
  (including self-supersession). `dent8 verify` surfaces lineage issues and retraction
  taint; a richer debugger/explain tree remains future product work.
  Contradiction-edge integrity is deliberately out of scope (a contradictor may live
  in another entity).

## Canonical Serialization And Hash Chain — Done

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

**Remaining.** No MVP blocker remains here. `ClaimValue::Json` canonicalization — ADR 0004
item 6 — is **done** via the `CanonicalJson` newtype. A real JCS implementation remains
deferred until there is a concrete cross-language interoperability requirement.

## Postgres Store Adapter — Done

**Why.** This is where dent8 becomes a store of record rather than an in-memory/file-backed
developer loop.

**Invariant.** `projection == fold(events)` and append-atomicity.

**Status.** Built and DB-verified. `PostgresEventStore` uses `sqlx`, transactional append,
transaction-scoped advisory-lock serialization for the global chain, shared
`arbitrate_events`, JSONB event storage, and materialized projection/edge tables. The
adapter populates and verifies `event_hash` / `previous_event_hash`; DB-generated
event timestamps were removed so appender-supplied timestamps remain authoritative.
`DATABASE_URL`-gated tests pass against live `postgres:16`, including projection/edge
materialization and a live CLI-over-Postgres path.

**Also done.** The sync-vs-async decision is resolved as two traits: sync `EventStore` for
the file/in-memory path and feature-gated `AsyncEventStore` for async backends. Embedded
SQLite is implemented as the second async backend (`--features sqlite`, `sqlite://`), proving
Postgres is an adapter, not the architecture.

**Remaining.** DB-assigned ids for heavy fan-out, richer per-column event tables /
`uses_as_evidence` edges, operational tuning, and authn are future product work.

## Replay / Explain CLI — Done

**Why.** `dent8 replay`/`dent8 explain` are the demoable surface of the integrity thesis.
**Both are built** (real commands, not stubs), alongside `verify` / `conflicts` / `derive` /
`eval` and the full write lifecycle.

**Invariant.** Deterministic replay and auditability.

**Status.** Built as subject-first commands:
`dent8 replay <subject> <predicate>` and `dent8 explain <subject> <predicate>`. They run
over the file dev store and async backends, use the same trusted reload/integrity gates as
the write path, show provenance/authority/freshness/lifecycle information, and share the
same operation code as MCP. `verify` checks chain integrity, lineage issues, and retraction
taint. The CLI parser is now `clap`, with generated shell completions and a global
`--color auto|always|never` presentation flag.

**Remaining.** `replay_runs` persistence, `--as-of` / `--valid-at`, `valid_to` intervals,
and a richer lineage/debugger view are future work.

**Crates.** `clap`, `clap_complete`, `serde_json`.

## Evals Harness — Mostly Built

**Why.** Integrity claims are only credible if measured.

**Status.** Mostly built. The `dent8-evals` adversarial corpus exists, and `proptest` suites
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
`UPDATE_GOLDEN=1`). The **file-based scenario-family corpus** under
[`evals/`](../evals/README.md) is seeded too:
[`evals_corpus.rs`](../crates/dent8-store/tests/evals_corpus.rs) freezes whole-stream firewall
outcomes (admitted vs rejected writes, per-claim end-state, read-time freshness, retraction
taint) for `beginner_to_senior`, `ttl_expiry`, `summary_drift`, `consistency_required`, and
`low_authority_injection`. Robustness tests cover adversarial deserialization and
panic-freedom over malformed but parseable event streams. Remaining: `cargo-fuzz` over the
deserialize→apply→canonicalize path and a Stateright-style append/projection model.

**Invariant.** All stated invariants, mechanized — see the property list in
[formal-verification.md](formal-verification.md) §(a).

**Concretely.** `evals/fixtures` and `evals/replay` are seeded with the families from
[evals.md](evals.md) — the supersession scenario ("beginner-in-January → senior-in-November"),
the `consistency_required` LFI family, the `summary_drift` retraction taint, `ttl_expiry`, and
`low_authority_injection` — each a frozen firewall outcome. The independent-reference-model
stateful fold harness is built in `proptest_fold.rs`; still open are `cargo-fuzz` targets over
the deserialize→apply→canonicalize path and a model of append/projection atomicity. Optionally
escalate terminal-immutability and fold-determinism to Kani/bolero (documented as **bounded**,
not universal).

**Crates.** `proptest` is in use. Future hardening should add `cargo-fuzz` +
`libfuzzer-sys`; optionally use `bolero`/Kani and a Stateright-style model for
append/projection atomicity.

## MCP Adapter — V0 Built

**Why late.** Pure orchestration over the store — it adds no integrity guarantee, so it
shipped after replay/explain proved the loop. A **v0 is built**: `dent8 mcp serve` runs a
synchronous, newline-delimited JSON-RPC 2.0 server over stdio (no async runtime, no new
heavy deps), handling `initialize` / `tools/list` / `tools/call` for the full belief
surface (`assert` / `supersede` / `retract` / `contradict` / `reinforce` / `expire` /
`derive` / `explain` / `replay`), read/audit tools (`list_facts` / `verify` / `conflicts`),
plus `resources/list` / `resources/read` (each fact stream as a `dent8://` resource),
server instructions for MCP-aware agents, and JSON-RPC batch requests. The tools dispatch to
the shared `op_*` firewall path, so the same
arbitration applies over MCP as on the CLI (a low-authority write is refused, surfaced as a
tool error).

**Role.** *Enforce* the firewall at write time: it already rejects missing-provenance /
sub-floor / non-unique writes (T1) via `op_*`, across the full belief surface
(`assert`/`supersede`/`retract`/`contradict`/`reinforce`/`expire`/`derive`/`explain`/`replay`),
read/audit tools (`list_facts`/`verify`/`conflicts`), plus `resources/list` /
`resources/read`, server instructions, and JSON-RPC batch requests. The freshness filter on reads (T4) is applied
— `explain` headline-flags a stale fact and the receipt carries `fresh` + `expires_at`.
Still to add: the official `rmcp` SDK / richer transports.
See [interfaces.md](interfaces.md).

**Crate.** v0 is hand-rolled on `serde_json` (zero new deps); the official Rust MCP SDK
(`rmcp`) is the upgrade path if richer protocol features (resources, sampling, batch) are
needed.

## Dependency summary

```
DONE: core arbitration + freshness + policy replay
DONE: serde canonical form + hash chain
DONE: Postgres adapter + AsyncEventStore boundary + SQLite proof backend
DONE: replay/explain CLI + full lifecycle + clap/completions/colors
DONE: v0 MCP stdio JSON-RPC surface
ONGOING: evals/formal hardening, mainly fuzzing + append/projection model checking
```

The dependency chain that originally blocked the MVP is now complete. The next dependency
chain is product hardening: signed caller identity -> operated witness -> richer transports /
debugger surfaces -> SDKs and production deployment packaging.

## Later

Postgres multi-tenant partitioning ·
ATMS-style assumption-environment replay for the debugger ·
[valid-time intervals (`valid_to`)](decisions/0005-belief-base-revision-semantics.md) ·
predicate-level volatility policy · HTTP API · **client SDKs** (`pip install dent8` /
`npm i dent8` with first-class in-process framework adapters — LangChain, LlamaIndex, Vercel AI
SDK; MCP is the integration path *today*, see [examples/langchain](../examples/langchain/)) ·
adapters for existing memory providers · an external witness (published signed tree head) for
non-repudiation.
