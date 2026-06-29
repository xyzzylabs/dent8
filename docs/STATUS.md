# dent8 Implementation Status

**Single source of truth for what is built.** If any other doc's "what works" claim
contradicts this file, this file wins. Three tiers, because the distinction that
matters most is *"a tested function exists"* vs *"a user can run it"*:

- **Runnable** — a user can invoke it (a CLI command, a server).
- **Library** — implemented and tested in a crate, but exposed through *no* runnable
  surface (no persistence, no CLI, no MCP). It is correct code that nothing calls.
- **Design-only** — specified in docs, not implemented.

## Runnable today (the entire user-facing surface)

- **`dent8 demo`** — runs the firewall + replay/explain loop end to end against the
  in-memory backend, **driven by the coding-agent predicate registry**: a high-authority
  `repo.database` fact is asserted; a low-authority source is **rejected by the
  predicate's authority floor**; a competing assertion is **rejected by uniqueness**; a
  `branch.status` fact goes stale on its **registered default TTL**; and `explain` returns
  an integrity receipt (value, lifecycle, authority, freshness, evidence, supersession,
  contradiction, replay position, `event_hash`, chain-verified).
- **`dent8 assert <kind> <key> <predicate> <value> <authority> <source>`** — asserts a
  fact through the firewall + registry, **persisted to a JSON-lines event log** and
  composing across separate invocations. A below-floor or non-unique write is rejected and
  **never reaches the log**.
- **`dent8 supersede <kind> <key> <predicate> <new-value> <authority> <source>`** — revises
  the believed fact via the sanctioned supersession path: it asserts a replacement and
  marks **every** believed incumbent superseded by it, persisted as one write. The base
  firewall's **anti-laundering rejects a revision that cannot out-rank each incumbent**;
  the end state is unique because all incumbents become terminal. Reload re-validates
  integrity: a torn write or external edit that leaves two fresh believed claims **or** a
  broken supersession lineage (dangling/cyclic) is rejected, not silently masked.
- **`dent8 retract <kind> <key> <predicate> <authority> <source>`** — terminally removes
  every believed claim for the subject+predicate. Unlike a contradiction (dissent), it is
  **authority-gated** ([ADR 0008](decisions/0008-retraction-authority.md)): a retraction
  that under-ranks its incumbent is rejected, so a low-authority actor cannot delete a
  trusted fact.
- **`dent8 contradict <kind> <key> <predicate> <opposing-value> <authority> <source>`** —
  flags a conflict: asserts an opposing claim and moves the incumbent to `Contested`,
  keeping **both** (paraconsistency, [ADR 0009](decisions/0009-uniqueness-and-contestation.md)).
  This is **dissent** — *not* authority-gated, so a low-authority source can flag a wrong
  fact without overriding it; the exception is a `Canonical` incumbent, which hard-alarms.
- **`dent8 reinforce <kind> <key> <predicate> <authority> <source>`** — corroborates the
  believed fact: records an additional source/authority backing the same value, raising
  **earned entrenchment** without restating the value (no value-mismatch).
- **`dent8 expire <kind> <key> <predicate> <authority> <source>`** — moves the believed
  fact(s) to the terminal `Expired` lifecycle (a lifecycle-natural close, e.g. policy
  retention — *not* an authority-gated removal like `retract`).
- **`dent8 derive <kind> <key> <predicate> <value> <authority> <source> <from-kind> <from-key>
  <from-predicate>`** — asserts a fact **derived from** another (named by subject, resolved to
  its believed claim id), recording a `DerivedFrom` dependency edge (ADR 0010). If the source
  is later retracted/expired, `verify` flags this derivative as **tainted** — the
  "poison does not survive in derivatives" differentiator, demonstrated by the
  `poisoned_source_retraction` eval.
- **`dent8 explain <kind> <key> <predicate>`** — replays the persisted log and prints the
  believed (or, if removed, the terminal) fact's integrity receipt. **Freshness-aware (T4):**
  a still-`Active` fact past its TTL is headline-flagged `[stale — TTL elapsed]`, and the
  receipt carries `fresh` + the `expires_at` instant. Composes with
  `assert`/`supersede`/`retract` across processes (and the same receipt backs the MCP
  `explain` tool and `resources/read`).
- **`dent8 replay <kind> <key> <predicate>`** — prints the full ordered event history
  (every assertion, supersession, retraction, contradiction, with authority + source) and
  the current state — *why* the fact is what it is.
- **`dent8 verify`** — on-demand integrity check. On **Postgres** it re-verifies the *stored*
  global hash chain (a mutated row → `INTEGRITY FAILURE`; CI-exercised); on the file dev store
  it checks *structural* integrity (uniqueness + lineage + canonicalization) and says plainly
  that content-edit tamper-detection there is `dent8 witness verify`'s job. On **both** it also
  reports **retraction taint** — a still-believed claim deriving from a retracted/expired source
  (`TAINTED: X derives from Y`).
- **`dent8 eval`** — runs the adversarial corpus and prints the firewall-vs-recency-baseline
  contrast (5/5 attacks blocked by the firewall, 5/5 compromising a recency-only baseline) —
  the self-demonstrating "why dent8" benchmark.
- **`dent8 conflicts`** — lists every contested fact (in dispute) across all entities, showing
  **both** rival claims (value + authority + lifecycle).
- **`dent8 mcp serve`** — a stdio JSON-RPC 2.0 **MCP server** exposing the **full belief
  surface** as tools to agent clients — `assert` / `supersede` / `retract` / `contradict` /
  `reinforce` / `expire` / `derive` / `explain` / `replay` (`initialize` / `tools/list` /
  `tools/call`).
  Every tool dispatches
  to the *same* `op_*` firewall path as the CLI, so a low-authority, laundered, or
  non-unique write is refused over MCP exactly as on the CLI (surfaced as a tool error,
  not a protocol error, so the agent sees the reason). It also serves **`resources/list` /
  `resources/read`** — each fact stream is a readable resource at
  `dent8://{kind}/{key}/{predicate}` (read returns the integrity receipt) — and accepts
  **JSON-RPC 2.0 batches** (an array of requests → an array of responses, notifications
  omitted; an empty batch is `-32600`).
- **`dent8 authority list | add <source> <max> [issuer] [scope] | remove <source>`** — the
  **authority layer (authz)**, enforced at the CLI/MCP `op_*` write layer (before the
  firewall). A source→authority *ceiling* registry: every write checks the caller-supplied
  `authority` against its `source`'s registered ceiling and **rejects** (does not silently
  cap) a write above it — so a low-trust source cannot mint `canonical`, and the rejection
  names the source, ceiling, and request for debuggability. **Opt-in**: enforcement activates
  once a registry exists (`DENT8_AUTHORITY`, default `./dent8-authority.json`); without one the
  CLI is permissive (dev mode). With one it is **deny-by-default** — an unlisted source's
  ceiling is `Unknown`, below the lowest requestable level (`Low`), so it is blocked from
  writing until granted. The registry is **host-local config**, independent of the event
  backend (a Postgres deployment still reads `DENT8_AUTHORITY` from the local filesystem; sync
  it per instance). Caveats: a grant's `issuer`/`scope` are **recorded but not enforced** in
  v0 (scope does not restrict predicates); the ceiling is an `op_*`-layer check, so a process
  calling the Postgres adapter *directly* (bypassing the CLI/MCP) is outside this trust
  boundary; and cryptographic verification of *which source is calling* (signed tokens) is
  deferred — the ceiling caps *what a source may claim*, not *who it is*.
- **`dent8 witness keygen | sign | verify | head | serve`** — the **witness** (behind
  `--features witness`), built on the Ed25519 signed tree head. `keygen` writes a keypair
  (private key `0600`, with the warning to keep it off the log-writer's machine); `sign` emits
  a signed tree head over the current log and appends it to a witness log
  (`DENT8_WITNESS_LOG`); `verify` re-checks every witnessed head against the current log's
  matching **prefix** and that the counts never decrease — catching a history **rewrite**
  (a re-hashed-forward edit an internal `verify_chain` cannot, threat-model T6) as `TAMPER`
  and a truncation/reorder as `ROLLBACK`. **`serve [interval] [max-heads]`** is the **cadence
  signer** — it signs the head whenever the log grows, the loop a separate operator runs; and
  **`head`** prints the latest signed head as JSON to **publish**. What is *built* is the
  mechanism (cadence signing + publishable heads); what remains *operational* is running it on
  a host separate from the writer, with key rotation and external head publication/monitoring.
- `dent8 schema postgres` — prints the Postgres schema.
- `dent8 --version`, `dent8 --help`.

`assert`/`explain` persist across invocations via a **local file-backed log**
(`DENT8_LOG`, default `./dent8-log.jsonl`), rehydrated through the store's trusted-reload
path. This is a **dev store, not the operational backend**: it is single-writer (no
concurrency control — two processes appending at once can interleave), non-transactional,
and single-user. A long-lived `dent8 mcp serve` sharing one `DENT8_LOG` with ad-hoc CLI
runs makes that race more reachable; corruption is *detected* on the next load
(`validate_unique_log` rejects a duplicated belief, a duplicate `event_id` wedges the
reload), not silently believed — but the operational store with atomic append + isolation
is **Postgres (M2b)**. The file backend exists so the firewall loop is usable and to prove
a *second* `EventStore` backend behind the same contract (de-risking M2b).

`explain` exits 0 whenever a claim exists (believed *or* terminal — a retracted/superseded
fact still has an auditable receipt) and exits 1 only when no claim exists for the
subject+predicate.

## Library — implemented and tested, not exposed

**`dent8-core`:**
- `ClaimEvent` model, lifecycle state machine, terminal immutability, replay fold.
- Authority-weighted supersession **and retraction** arbitration (`InsufficientAuthority`,
  [ADR 0008](decisions/0008-retraction-authority.md)) + canonical contradiction hard-alarm
  (`CanonicalContradiction`); exhaustive 5×5-lattice non-resurrection tests (one per
  supersession/retraction) + `#[cfg(kani)]` harnesses (run manually via `cargo kani`; a green
  CI job is a tracked follow-up — Kani's pinned nightly does not yet build this edition-2024
  workspace).
- Read-time freshness evaluator (`ClaimState::is_expired_at`).
- Earned-entrenchment: authority-weighted `corroboration_at_or_above`.
- Canonicalization + hash chain (`canonical_bytes`, `event_hash`, `hash_chain`):
  serde, SHA-256, injective length-framed leaf, `0x00` domain separation. **Not JCS**
  (sorted-key `serde_json` form — see [storage.md](storage.md)). The "logically-equal →
  identical bytes" invariant holds for **all** fields including embedded JSON:
  `ClaimValue::Json` is the `CanonicalJson` newtype, canonical by construction and
  re-canonicalized on deserialize (ADR 0004 item 6, resolved).
- **External anchor** (`anchor_head` / `verify_anchor` / `ChainAnchor`): an HMAC-SHA256
  commitment to `(count, head)` under a witness key (zero new deps), giving
  tamper-*resistance* on top of the chain's tamper-*evidence* — it catches a
  re-hashed-forward rewrite that `verify_chain` cannot (threat-model T6).
- **Asymmetric anchor** (`sign_head` / `verify_signed_head` / `SignedTreeHead`, behind the
  `signed-anchor` feature): an **Ed25519-signed tree head** over the same domain-separated
  `(count, head)` message. Unlike the symmetric HMAC, the verifier needs only the **public**
  key, so a published head is **publicly verifiable** — the witness keeps the private key.
  Feature-gated so the default build and the CLI keep the HMAC anchor with no signature
  stack. Tested: public verification, tamper detection, and wrong-key rejection.
- **Property-based test suites** (`proptest`): universally-quantified complements to the
  example tests and Kani proofs.
  [`tests/proptest_invariants.rs`](../crates/dent8-core/tests/proptest_invariants.rs) —
  canonicalization is **idempotent + reload-stable for arbitrary JSON** (the property the
  float bug violated; the suite reproduces it when `float_roundtrip` is removed),
  `canonical_bytes`/`event_hash` round-trip through serde, the hash chain **localizes tamper**
  (a changed event flips its hash and every later one, never an earlier one), and the anchor
  accepts its own log while rejecting any change.
  [`tests/proptest_fold.rs`](../crates/dent8-core/tests/proptest_fold.rs) — the **stateful
  fold harness**: a random coherent event stream folded through `apply_event` is checked
  step-by-step against an **independent reference model** (accept/reject, reject *reason*,
  resulting lifecycle), plus **terminal absorption / non-resurrection**, value immutability,
  `updated_at` tracking, replay determinism, and claim isolation. The cross-check is verified
  to catch a deliberately wrong model gate.
  [`tests/proptest_robustness.rs`](../crates/dent8-core/tests/proptest_robustness.rs) — the
  **robustness** complement: the untrusted-input pipeline (parse → `event_hash`/`hash_chain` →
  `canonical_bytes` → `apply_event`) never **panics** on adversarial input, including values
  that bypass the constructors' validation via derived `Deserialize` (out-of-range
  `Confidence`, extreme timestamps, `u64::MAX` TTL, empty/oversized ids, deep JSON); a panic
  on hand-edited-log / MCP / JSONB input would be a DoS, not a wrong answer. The store
  firewall has the matching guard ([`dent8-store/tests/robustness.rs`](../crates/dent8-store/tests/robustness.rs)):
  `replay_entity` absorbs self-referential / cyclic / dangling supersessions and extreme
  freshness/TTL math without crashing.
- **Golden replay fixtures** ([`tests/golden_replay.rs`](../crates/dent8-core/tests/golden_replay.rs),
  fixtures in [`tests/golden/replay/`](../crates/dent8-core/tests/golden/replay)): named
  event streams frozen on disk as canonical `.events.jsonl` (the `DENT8_LOG` format) +
  `.expected.json` (chain head + replayed-state summary). The test replays the **on-disk**
  events and asserts the current code reproduces them, locking the event encoding, the hash
  chain, and the fold against silent drift (regenerate with `UPDATE_GOLDEN=1`).

**`dent8-store`:**
- `replay_claim` / `replay_claim_with_policy` + `diff_states` (policy-counterfactual replay).
- `replay_entity` / `EntityProjection` (`lineage_issues`, `unearned_supersessions`).
- **The firewall** is `EventStore::append` itself (via `arbitrate`): every write is
  arbitrated and there is **no un-arbitrated write path**. It rejects a low-stated-authority
  supersession *and* a laundered one (over-stated event authority backed by a low-authority
  claim). Reachable via `dent8 demo`.
- `InMemoryEventStore` (test/demo + file-backed CLI backend, not operational) +
  `IntegrityReceipt` / `explain` / `explain_subject` + global-chain `verify_chain`
  (internally consistent) + `anchor` / `verify_against_anchor` (external tamper-resistance).
- `InMemoryEventStore::from_trusted_events` — the trusted-reload path (rehydrate an
  already-admitted log without re-arbitration), recomputing the global chain. Used by the
  file-backed CLI; the documented counterpart to the single arbitrated `append` path.
- **`PredicateRegistry`** (coding-agent fact policies): per-predicate authority floor,
  default TTL, and uniqueness, enforced via `enforce_policy` / `apply_policy_defaults`.
  Ships `repo.database`, `repo.test_command`, `dependency.version`, `branch.status`,
  `user.preference`.
- `EventStore` trait — implemented in-memory; the Postgres adapter is written but not yet
  DB-verified (below).
- `arbitrate_events` — the **pure, I/O-free firewall decision** over loaded event streams,
  shared by the in-memory backend and the Postgres adapter so they cannot diverge.

**`dent8-store-postgres` (`--features adapter`):**
- **`PostgresEventStore`** (v0 async sqlx adapter) — `connect`/`migrate`/`append`/
  `load_claim_events`/`scan_events`/`verify_chain` over the `dent8_event_log` table
  (migration 002). Transactional append serialized by an advisory lock for the global
  chain; the firewall reuses `arbitrate_events`; the canonical event is stored as JSONB.
- **Materialized projection + edge graph** (migration 003): each accepted append also folds
  the post-append `ClaimState` (via the shared `apply_event`) into `dent8_claim_projection`
  and records the claim→claim relationship into `dent8_claim_edge`, in the same transaction.
  `materialized_projection` reads the believed state without re-folding; `edges_from` reads
  the supersession/contradiction/reinforcement graph; `verify_projection` re-folds and
  asserts `projection == fold(log)`. Derived caches, not a second source of truth.
- **Status: verified against a live Postgres (`postgres:16`).** The `DATABASE_URL`-gated
  integration tests pass — the firewall over Postgres (incl. laundered-supersession
  rejection) **and** the projection/edge materialization + `projection == fold(log)` + the
  scalar columns matching the fold — via
  `DATABASE_URL=… cargo test -p dent8-store-postgres --features adapter` (the tests share one
  database but self-serialize and retry the initial connection, so no flags are needed).
  `sqlx` is feature-gated so the default build and the CLI stay free of it. The live run
  surfaced and fixed real bugs: `migrate()` now serializes concurrent schema creation under
  an advisory lock (`CREATE TABLE IF NOT EXISTS` is not race-safe on the `pg_class`/`pg_type`
  catalog), and `connect()` bounds its acquire timeout so an unreachable DB fails fast.

**`dent8-evals`:**
- Adversarial corpus: MINJA injection, authority laundering, canonical contradiction, Sybil
  corroboration, and **poisoned-source retraction** run against the **real firewall** vs a
  **recency-only baseline**. `dent8 eval` (or `cargo test -p dent8-evals`) asserts the firewall
  blocks all five while the baseline is compromised by all five (plus a positive control
  admitting legitimate revision). See [evals.md](evals.md).

## Design-only — not implemented

- **Postgres adapter — verified, and the CLI/MCP run on it (M2b done).** The v0
  `PostgresEventStore` + its materialization (migration 003) are **DB-verified** (the gated
  integration tests pass against a live `postgres:16`, via [`compose.yml`](../compose.yml) or
  the CI `postgres` job), **and the runnable surface uses it**: with `DENT8_DATABASE_URL` set
  and a `--features postgres` build, `dent8` and `mcp serve` read/write Postgres, with each
  multi-event operation (supersede/retract/contradict) committed as one transaction
  (`append_many`). Both the *adapter* **and the CLI-over-Postgres path** are **CI-verified**
  against live Postgres (the gated `postgres` job runs the adapter tests *and* a live
  `assert → supersede → explain → verify` end-to-end). The stock binary keeps the file dev
  store (sqlx is opt-in).
  What remains *design-only*: **cryptographic caller identity**
  (the source→authority ceiling is built — see `dent8 authority` above — but *which* source
  is calling is still asserted, not proven by a signed token), the richer per-column event
  table + `uses_as_evidence` edges (migration 001), and operational tuning.
- **Persistent CLI/MCP — built, file *or* Postgres.** The full surface — `assert` /
  `supersede` / `retract` / `contradict` / `reinforce` / `expire` / `derive` / `explain` /
  `replay` / `verify` / `conflicts` / `eval` — across invocations is **Runnable** (above) over
  the file dev store, and over **Postgres** with `DENT8_DATABASE_URL` + a `--features postgres`
  build (selected in `load_store`/`append_events`; multi-event ops use the transactional
  `append_many`, and the Postgres load re-runs the same `validate_unique_log` integrity gate
  as the file path) — **CI-verified** end-to-end against live Postgres (the `postgres` job runs
  a live `assert → supersede → explain → verify`). **Concurrency:**
  the *adapter*
  is **tested** multi-writer-safe — a DB-gated test fires 12 genuinely concurrent appends and
  asserts they serialize (via a transaction-scoped advisory lock) into one gap-free,
  duplicate-free global chain that verifies, with every projection still `== fold(log)`. The
  CLI mints `event:{n}` ids from a snapshot count, so two CLI *processes* racing one DB can pick
  the same id — caught as a duplicate-id conflict and **auto-retried with exponential backoff +
  per-process jitter** (`with_write_retry`, decorrelated so the herd does not phase-lock),
  which re-snapshots and re-mints a non-colliding id. **Integrity is unconditional** — every
  committed log is a contiguous, corruption-free chain, and a writer that exhausts the retry
  budget gets a clean rejection, never a partial or corrupt write. **Convergence is
  best-effort**: the retry lets ordinary concurrent writers through, but under heavy write
  fan-out a writer can still be cleanly rejected (retry the command), and **DB-assigned ids
  remain the end-state** that removes the contention entirely. Authz (source→authority ceilings)
  is built (`dent8 authority`, above)
  and the witness *primitive* is runnable (`dent8 witness`, above); the remaining product gap
  is cryptographic caller identity and the *operated* witness service.
- The official `rmcp` SDK / richer transports — the v0 server (full belief surface as
  tools, `resources/list`/`resources/read`, and JSON-RPC batches, above) is a hand-rolled
  stdio JSON-RPC loop; `resources/subscribe` and prompts are not implemented.
- **A published anchor cadence / *operated* witness service.** Both anchor primitives —
  symmetric (`anchor_head`) and asymmetric (`sign_head`, the publicly-verifiable signed tree
  head) — are built and tested (Library, above), and the signed-tree-head primitive is now
  runnable end-to-end as **`dent8 witness keygen | sign | verify`** (Runnable, above), which
  emits heads and detects rewrite/rollback. What is still design-only is the *operated* piece:
  a witness running on **separate infrastructure** that signs on a cadence and **publishes**
  the head (so the key is provably off the writer), plus key rotation.

## How to keep this honest

The README "what works" list must map 1:1 to the **Runnable** section above. Do not
describe Library-tier mechanisms as things dent8 "does" for a user — they are things
the code can compute, with no user-facing surface. Update this file in the same change
that moves an item between tiers.
