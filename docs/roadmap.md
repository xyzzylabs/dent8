# Roadmap

The target user is a coding agent or long-running developer assistant that must
remember project facts without silently retaining stale or contradicted context.
The failure modes dent8 attacks: **stale project facts, hidden contradiction,
poisoned summaries, and unexplained context retrieval.**

This roadmap is dependency-ordered: each item unlocks the next, and each is
annotated with the integrity invariant it makes real. It supersedes the older
MVP checklist.

The wedge is **multiple coding agents (and a human) sharing one verified fact base about
one repository** ([project-brief.md](project-brief.md) §MVP User).

## Shipped: the v0.4–v0.6 near-term list

All five items of the previous near-term list landed by v0.6.1:

1. **Capture+inject loop** ✅ — `dent8 context` / `dent8 capture` with read-audit events on
   every retrieval surface, including MCP `resources/read`. *(Invariant: unexplained context
   retrieval becomes explainable.)*
2. **Default authority profile** ✅ — human > CI > agent via `dent8 authority defaults`;
   grant issuer/scope enforced at the write boundary (no self-escalation). *(Invariant:
   authority is typed and policy-visible.)*
3. **On-ramp** ✅ — value-first README/Getting Started; init → assert → explain timed under
   the 2-minute budget by [`examples/on-ramp/demo.sh`](../examples/on-ramp/demo.sh).
4. **External evaluation** ✅ — the 47-case literature-adapted corpus with an honest
   block/detect/out-of-model tally, plus the modeled Mem0/Zep integrity-axis comparison in
   `dent8 eval`. *(Invariant: the result generalizes beyond self-authored fixtures.)*
5. **Python/TS reachability** ✅ — thin SDKs over the CLI's JSON machine contract on PyPI and
   npm ([`sdks/`](../sdks/)), tested against the real binary in CI, released tokenless via
   Trusted Publishing. Bonus beyond the list: **`dent8 whatif`** surfaced policy-counterfactual
   replay (novelty rank 2), and the docs now live at
   [xyzzylabs.github.io/dent8](https://xyzzylabs.github.io/dent8/).

## Near-term focus (post-v0.6)

Priority order. The first item gates the rest — the frozen directions below unfreeze on
evidence of users, not on more features.

1. **Launch and the feedback loop.** Announce (the release is announceable: 2-minute on-ramp,
   honest evals, three registries, docs site), then treat the first weeks of issues and
   questions as the roadmap's primary input. *(No invariant — an unused firewall protects
   nothing.)*
2. **Legitimate-traffic evaluation.** Replay real captured agent sessions through the firewall
   and measure the false-positive rate — the complement of the adversarial corpus. Blocked
   only on trace data, which dogfooding and early users produce. *(Invariant: the firewall
   does not tax legitimate revision.)*
3. **Concurrency load testing and tuning.** ✅ Both backends: `scripts/load-test.sh` (N
   parallel writers; a distinct-fact throughput phase plus a deliberate same-fact
   supersession herd) found and fixed three real defects — BUSY-at-connect classified
   fatal, stale-snapshot commits reported terminal instead of retried, and optimistic-retry
   livelock under sustained contention, fixed with a cross-process write lease per backend
   (SQLite sidecar `BEGIN IMMEDIATE`; Postgres session advisory lock — see
   [storage.md](storage.md)). *(Invariant held on both: every write eventually admitted,
   exactly one believed value, `verify` green.)*
4. **MCP `resources/subscribe`.** ✅ Both transports: subscribe to a
   `dent8://{kind}/{key}/{predicate}` stream and receive `notifications/resources/updated`
   when it changes — immediately for writes through the same connection, within a poll tick
   for writes from any other process sharing the store. The daemon pushes per connection and
   `dent8 mcp proxy` pumps frames bidirectionally, so daemon clients get pushes too.
   *(Invariant held: an agent's injected context cannot silently go stale between reads.)*
5. **Identity productization.** OS keychain / secret-store-backed source keys instead of
   `0600` files, and a team key-distribution story. *(Invariant: stealing a source identity
   requires more than a same-user file read — the threat model's top residual.)*

Explicitly **frozen until the wedge has users**: operated-witness hosting, the desktop
debugger/control plane (its runway is built — the `snapshot` aggregate, the TS SDK, and
`whatif` are exactly its data layer), and any training-substrate direction.

## Where the code actually is

See **[STATUS.md](STATUS.md)** for the authoritative tier list. In summary, the MVP loop
now runs end to end through the CLI and MCP surfaces:

- **The firewall is enforced at the write boundary** (`EventStore::append` via
  `arbitrate`): authority-weighted supersession, the LFI canonical hard-alarm, and
  subject-aware anti-laundering — runnable via the lifecycle CLI commands, `dent8 eval`,
  `examples/firewall/demo.sh`, and `dent8 mcp serve`.
- serde + `canonical_bytes` + `event_hash`/`hash_chain` are wired into append and
  verification; the Postgres adapter stores and re-verifies the global chain.
- The **coding-agent predicate registry** drives the firewall: per-predicate
  authority floor, default TTL, and uniqueness.
- The full lifecycle is runnable and persistent:
  `assert`/`supersede`/`retract`/`contradict`/`reinforce`/`expire`/`derive`/`explain`/
  `replay`/`facts list`/`snapshot`/`verify`/`conflicts`/`eval`/`export`, plus MCP tools for the
  same belief surface.
- Persistence runs over the local file dev store by default, or over the transactional
  async backends selected by `DENT8_STORE_URL`: embedded SQLite (stock build) and Postgres
  (`--features postgres`).

What remains to make it a hardened multi-user product:

- **Signed identity operations.** The stock CLI now includes the authn primitive:
  `dent8 init --identity` / `dent8 init --agent <profile>` create issuer-signed grants binding
  source ids to source public keys, and every configured write checks source-key possession at
  the CLI/MCP boundary. Product hardening remains: key distribution, hardware or
  secret-store-backed keys, and team policy workflows. Signed key rotation/revocation and
  issuer-signed, hash-chained grant-log history
  ([ADR 0014](decisions/0014-grant-history-and-revocation.md)) are now shipped
  (`dent8 identity rotate-source` / `revoke` / `backfill-grant-log`).
- **Operated witness service.** `dent8 witness` is a runnable signed-tree-head primitive;
  role doctor checks validate writer/signer separation, `publish` idempotently appends heads to
  an external JSONL sequence, and `verify-published` verifies externally saved heads so local
  witness-log rollback cannot erase retained evidence. The deployment is **packaged** in
  [`examples/witness-operated/`](../examples/witness-operated/) (Docker Compose signer /
  publisher / monitor split over a shared Postgres store, built from the repo `Dockerfile`,
  plus hardened systemd units) with key-rotation and publication-channel guidance; what
  remains is *hosting* it — a managed signer/publication service instead of your own second
  host.
- **Production ergonomics and heavy-concurrency polish.** The async adapters reserve
  `event:{n}` id ranges from the database before signing (unique, not gap-free) and serialize
  appends, with an in-transaction final projection check for touched unique predicates;
  remaining work is operational load testing and tuning.
- **Richer protocol/product surfaces.** The v0 MCP server is useful today, and the thin
  Python/TS SDKs shipped ([`sdks/`](../sdks/)); official `rmcp`, richer transports,
  `resources/subscribe`, prompts, HTTP, and a TypeScript/Tauri desktop debugger/control
  plane are later ([ADR 0020](decisions/0020-desktop-debugger-control-plane.md)).
- **Remaining formal/eval work.** `proptest` suites, golden replay fixtures, scenario-family
  fixtures, the adversarial corpus, and **`cargo-fuzz` targets** (the
  deserialize→fold→canonicalize path and `CanonicalJson` idempotency, in [`fuzz/`](../fuzz/),
  with a bounded 60s-per-target CI smoke) are built. The Stateright-style append/projection
  model remains open.

Operational persistence is no longer the gap — it is **built and runnable on two backends**
(Postgres and embedded SQLite, behind the `AsyncEventStore` boundary). The remaining gap is
*productization*: operating signed source identity well and running an *operated* witness
service.

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
- **[DONE] Earned entrenchment v0 (novelty rank 3).** `FactState` tracks
  authority-weighted `corroborating_sources` (`corroboration_at_or_above`, Sybil-
  resistant); `SubjectProjection::unearned_supersessions` audits each supersession
  against the replacing fact's *actual* authority and **earned entrenchment**, flagging
  `AuthorityDowngrade` and `WeakerEntrenchment`. The "survived-challenge" half is
  **built too** ([ADR 0015](decisions/0015-survived-challenge-recording.md)): a rejected
  challenge is recorded on the incumbent's stream as `fact.challenge_rejected` (with the
  challenger's provenance and effective authority; Sybil-resistant
  `survived_challenges_at_or_above`), and both the always-on unearned-supersession audit and
  the opt-in earned-supersession gate (`DENT8_ENTRENCHMENT_GATE=1`) now weigh *earned
  entrenchment* — authority-weighted corroboration **plus** survived challenges
  ([ADR 0017](decisions/0017-survived-challenges-in-arbitration.md); the rejection reason is
  `WeakerEntrenchment`, the old `WeakerCorroboration` still deserializes).
  *([research/novelty.md](research/novelty.md) rank 3.)*
- **[DONE] LFI "gentle-explosion" tier.** `apply_event`'s `Contradicted` arm returns
  `CanonicalContradiction` for a contradiction against an `AuthorityLevel::Canonical`
  fact; ordinary contradictions still localize to `Contested`. Future: uniqueness-
  constrained predicates (no such flag in the model yet).
  *([belief-revision.md](belief-revision.md) §Adopt-3.)*
- **[DONE] Read-time freshness evaluator + read surface.** `FactState::is_fresh_at(now)`
  bounds the full validity window `[valid_from, expires_at)` — TTL and the asserted
  `valid_to`/`valid_from` (ADR 0016) — kept separate from the lifecycle, and `explain` (CLI +
  the MCP `explain` tool + `resources/read`) now **applies** it: a still-`Active` fact past
  its TTL or `valid_to` is headline-flagged `[stale — no longer valid]`, one whose
  `valid_from` is still in the future `[not yet valid]`, and the receipt carries `fresh` +
  `not_yet_valid` + the `valid_from`/`expires_at` window.
  *(Invariant T4 in [threat-model.md](threat-model.md); remaining residuals tracked there.)*
- **[DONE] Policy-counterfactual replay (novelty rank 2).** `EpistemicPolicy`
  (distrusted sources, authority floor, confidence floor) + `replay_fact_with_policy`
  + `diff_states` re-fold the same log under different trust assumptions, with zero
  model calls. *([research/novelty.md](research/novelty.md) rank 2.)*
- **[DONE] Cross-stream lineage check.** `replay_entity` folds all of an subject's
  fact streams into an `SubjectProjection`; `lineage_issues()` flags dangling
  supersession, supersession-by-an-invalidated-fact, and supersession cycles
  (including self-supersession). `dent8 verify` surfaces lineage issues and retraction
  taint; a richer debugger/explain tree remains future product work.
  Contradiction-edge integrity is deliberately out of scope (a contradictor may live
  in another subject).

## Canonical Serialization And Hash Chain — Done

**Status.** Built and tested in [`dent8-core/src/hash.rs`](../crates/dent8-core/src/hash.rs):
serde derives on the `FactEvent` graph; `canonical_bytes` (sorted-key `serde_json`
form — **not** JCS); `event_hash`/`hash_chain` (SHA-256, injective length-framed leaf,
`0x00` RFC 6962 domain separation); `CANON_VERSION` as the schema version. Tests cover
key-order independence, round-trip stability, injective genesis/`previous`, and
tamper-cascade. The migration's DB-generated `recorded_at`/edge `created_at` are
dropped. See [storage.md](storage.md) §Canonicalization and
[ADR 0004](decisions/0004-canonicalization-and-hash-chain.md).

**Crates.** `serde`, `serde_json`, `sha2`, `hex` (no `serde_jcs` — JCS interop is not
needed yet).

**Remaining.** No MVP blocker remains here. `FactValue::Json` canonicalization — ADR 0004
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
SQLite is implemented as the stock local async backend (`sqlite://`), proving Postgres is an
adapter, not the architecture.

**Remaining.** Richer per-column event tables /
`uses_as_evidence` edges, operational tuning, and identity operations (key distribution /
external signers) are future product work. (Source-key rotation (`dent8 identity
rotate-source`), revocation (`dent8 identity revoke`), and append-only grant-log history —
[ADR 0014](decisions/0014-grant-history-and-revocation.md) — are built.)

## Replay / Explain CLI — Done

**Why.** `dent8 replay`/`dent8 explain` are the demoable surface of the integrity thesis.
**Both are built** (real commands, not stubs), alongside `facts list` / `verify` /
`conflicts` / `derive` / `eval` and the full write lifecycle.

**Invariant.** Deterministic replay and auditability.

**Status.** Built as subject-first commands:
`dent8 replay <subject> <predicate>` and `dent8 explain <subject> <predicate>`. They run
over the file dev store and async backends, use the same trusted reload/integrity gates as
the write path, show provenance/authority/freshness/lifecycle information, and share the
same operation code as MCP. `verify` checks chain integrity, lineage issues, and retraction
taint. The CLI parser is now `clap`, with generated shell completions and a global
`--color auto|always|never` presentation flag. The write commands, `explain`, `replay`,
`facts list`, `verify`, `conflicts`, `eval`, `init`, `agent add`, `authority`,
`identity <subcommand>`, `doctor`, `completions`, `export`, `schema postgres`, and `mcp install`
support `--output json` for scripts/agents; other commands fail closed when
JSON is requested until their structured contract is designed.

**Remaining.** `replay_runs` persistence and a richer lineage/debugger view are future
work. (`valid_to` intervals and `--as-of` / `--valid-at` time-travel reads are built —
[ADR 0016](decisions/0016-valid-time-and-time-travel-reads.md); the `hook` exit-code
contract and the `witness` JSON surface — including NDJSON streaming from `serve` — are
documented and pinned by tests; MCP is JSON-RPC by construction.)

**Crates.** `clap`, `clap_complete`, `serde_json`.

## Evals Harness — Mostly Built

**Why.** Integrity facts are only credible if measured.

**Status.** Mostly built. The `dent8-evals` adversarial corpus exists, and `proptest` suites
cover invariants (a): [`proptest_invariants.rs`](../crates/dent8-core/tests/proptest_invariants.rs)
(canonicalization/hash/anchor — idempotency + reload-stability over arbitrary JSON, serde
round-trips, tamper localization, anchor accept/reject) and
[`proptest_fold.rs`](../crates/dent8-core/tests/proptest_fold.rs) (the stateful `apply_event`
fold vs an independent reference model: accept/reject + reason + lifecycle, terminal
absorption, value immutability, replay determinism, fact isolation). **Golden replay
fixtures** are built too: [`golden_replay.rs`](../crates/dent8-core/tests/golden_replay.rs)
freezes named event streams ([`tests/golden/replay/`](../crates/dent8-core/tests/golden/replay))
as canonical `.events.jsonl` + an `.expected.json` (chain head + replayed-state summary), so
an encoding/hash/fold change is caught as a snapshot mismatch (regenerate with
`UPDATE_GOLDEN=1`). The **file-based scenario-family corpus** under
[`evals/`](../evals/README.md) is seeded too:
[`evals_corpus.rs`](../crates/dent8-store/tests/evals_corpus.rs) freezes whole-stream firewall
outcomes (admitted vs rejected writes, per-fact end-state, read-time freshness, retraction
taint) for `beginner_to_senior`, `ttl_expiry`, `summary_drift`, `consistency_required`, and
`low_authority_injection`. Robustness tests cover adversarial deserialization and
panic-freedom over malformed but parseable event streams. **`cargo-fuzz` is built**: libFuzzer
targets over the deserialize→fold→canonicalize path (reload stability, hash determinism,
attestation-message independence, fold totality) and `CanonicalJson` idempotency live in
[`fuzz/`](../fuzz/), seeded from the golden fixtures, with a bounded CI smoke (60s/target).
Remaining: a Stateright-style append/projection model.

**Invariant.** All stated invariants, mechanized — see the property list in
[formal-verification.md](formal-verification.md) §(a).

**Concretely.** `evals/fixtures` and `evals/replay` are seeded with the families from
[evals.md](evals.md) — the supersession scenario ("beginner-in-January → senior-in-November"),
the `consistency_required` LFI family, the `summary_drift` retraction taint, `ttl_expiry`, and
`low_authority_injection` — each a frozen firewall outcome. The independent-reference-model
stateful fold harness is built in `proptest_fold.rs`; `cargo-fuzz` targets over the
deserialize→apply→canonicalize path are built (see above); still open is a model of
append/projection atomicity. Optionally
escalate terminal-immutability and fold-determinism to Kani/bolero (documented as **bounded**,
not universal).

**Crates.** `proptest` and `cargo-fuzz` + `libfuzzer-sys` are in use; optionally use
`bolero`/Kani and a Stateright-style model for append/projection atomicity.

## MCP Adapter — V0 Built

**Why late.** Pure orchestration over the store — it adds no integrity guarantee, so it
shipped after replay/explain proved the loop. A **v0 is built**: `dent8 mcp serve` runs a
synchronous, newline-delimited JSON-RPC 2.0 server over stdio (no async runtime, no new
heavy deps), handling `initialize` / `tools/list` / `tools/call` for the full belief
surface (`assert` / `supersede` / `retract` / `contradict` / `reinforce` / `expire` /
`derive` / `explain` / `replay`), read/audit tools (`runtime_status` / `snapshot` /
`list_facts` / `verify` / `conflicts` / `native_scan` / `native_reconcile`),
plus `resources/list` / `resources/read` (each fact stream as a `dent8://` resource),
server instructions for MCP-aware agents, and JSON-RPC batch requests. The tools dispatch to
the shared `op_*` firewall path, so the same
arbitration applies over MCP as on the CLI (a low-authority write is refused, surfaced as a
tool error).

**Role.** *Enforce* the firewall at write time: it already rejects missing-provenance /
sub-floor / non-unique writes (T1) via `op_*`, across the full belief surface
(`assert`/`supersede`/`retract`/`contradict`/`reinforce`/`expire`/`derive`/`explain`/`replay`),
read/audit tools (`runtime_status`/`snapshot`/`list_facts`/`verify`/`conflicts`/`native_scan`/
`native_reconcile`),
plus `resources/list` / `resources/read`, server instructions, and JSON-RPC batch requests.
The freshness filter on reads (T4) is applied — `explain` headline-flags a stale fact and
the receipt carries `fresh` + `expires_at`.
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
DONE: signed source identity primitive + secure init path
ONGOING: evals/formal hardening, mainly fuzzing + append/projection model checking
```

The dependency chain that originally blocked the MVP is now complete, and the SDK link has
shipped. The next dependency chain is product hardening: identity operations -> operated
witness -> stable daemon/API contracts (started with `snapshot`) -> desktop
debugger/control plane and production deployment packaging.

## Later

Postgres multi-tenant partitioning ·
ATMS-style assumption-environment replay for the debugger (the core shipped as
`dent8 whatif`; the interactive debugger view remains) ·
predicate-level volatility policy · HTTP API · **first-class in-process framework adapters**
(LangChain, LlamaIndex, Vercel AI SDK) layered on the shipped `pip install dent8` /
`npm i dent8` SDKs; MCP is the integration path *today*, see
[examples/langchain](../examples/langchain/) and
[examples/vercel-ai-sdk](../examples/vercel-ai-sdk/) ·
a TypeScript/Tauri desktop debugger/control plane for agents, receipts, native-memory audits,
witness status, and replay timelines ·
adapters for existing memory providers · a managed/hosted witness service (publication
channel, monitoring, key-rotation automation) for non-repudiation — the
published-signed-tree-head primitive itself (`witness publish` / `verify-published`, plus
the grant-log `--grants` lane) already ships.
