# Storage and the Event Log

The durable design in dent8 is not "Postgres" — it is the **append-only event log
with a derived projection, an edge graph, and a tamper-evident hash chain**. That
design is expressed against the `EventStore` trait in
[`crates/dent8-store/src/lib.rs`](../crates/dent8-store/src/lib.rs); Postgres is the
*first adapter* that realizes it, not the architecture itself. This document
describes the backend-agnostic design first, then the Postgres adapter as a
subordinate section. The *decision* to start with Postgres (and not SQLite) lives in
[ADR 0001](decisions/0001-postgres-first.md); the canonicalization/hash-chain
decision in [ADR 0004](decisions/0004-canonicalization-and-hash-chain.md).

## The storage boundary

`EventStore` is the seam every backend implements:

- `append(event) -> AppendReceipt` — validate the transition against current state,
  then atomically persist the immutable event, update its projection, and write
  graph edges. Returns the assigned `global_sequence` and the computed `event_hash`.
- `load_claim_events(claim_id)` — ordered events for one claim stream.
- `scan_events(filter)` — ordered events by claim / subject+predicate / sequence.

`replay_claim(events)` (a pure free function, not a backend method) folds an ordered
slice into `Option<ClaimState>` via `apply_event`. Any backend that returns events
in `global_sequence` order gets identical replay — which is the whole point: the
backend stores bytes; the *meaning* lives in `dent8-core`.

> Design obligation (now resolved): the `EventStore` trait is synchronous (`&mut self`),
> but a Postgres/sqlx adapter is async. The v0 adapter exposes **concrete inherent
> `async fn`s** rather than implementing a trait, and shares the firewall via the pure
> `arbitrate_events` (so sync and async backends cannot diverge); a unifying
> `AsyncEventStore` trait is deferred until a second async backend needs it. See the
> Postgres-adapter section below.

## What the log must guarantee

These are backend-independent invariants (mechanized per
[formal-verification.md](formal-verification.md)):

- **Append-atomicity** — an event and its projection/edge updates commit or fail
  together; an event must never be partially visible.
- **`projection == fold(events)`** — the materialized projection equals the
  deterministic fold of the ordered log. A backend that cannot reproduce this is
  broken.
- **Order stability** — replay folds strictly by `global_sequence`.
- **Tamper-evidence** — each event links to the previous via a hash chain verified
  on replay.
- **Uniqueness** — `event_id` and `event_hash` are unique; a duplicate is the
  natural idempotency/tamper signal (`StoreError::Conflict`).

## Tables / record shape

The log decomposes into four record kinds (named generically; the Postgres DDL
below is one realization):

- **`claim_events`** — the immutable event log (the source of truth).
- **`claim_projections`** — current lifecycle projection (a cache derivable from the
  log).
- **`claim_edges`** — the contradiction / supersession / reinforcement / evidence
  graph (`reinforces` · `contradicts` · `supersedes` · `uses_as_evidence`).
- **`replay_runs`** — replay and invariant-check reports (record a signed tree head
  — root/last hash + event count — so two runs are externally comparable).

## Canonicalization and the hash chain

Tamper-evidence is only as strong as **deterministic bytes**. The chain columns
(`previous_event_hash`/`event_hash`) exist in schema 001; canonicalization and hashing
are **implemented in [`dent8-core/src/hash.rs`](../crates/dent8-core/src/hash.rs)** and
tested. See [ADR 0004](decisions/0004-canonicalization-and-hash-chain.md). What is done:

1. `serde::{Serialize, Deserialize}` are derived on `ClaimEvent` and sub-types.
2. `canonical_bytes` produces a **sorted-key canonical form via `serde_json`** (route
   through a `BTreeMap`-backed `Value`, emit compact). This is **not RFC 8785 (JCS)**:
   keys sort by UTF-8 byte order (JCS uses UTF-16 code units) and number/escape rules
   differ. The two coincide *only* because every object key is an ASCII field/variant
   name and every number is an integer (`Confidence` is `u16`, `TimestampMillis` is
   `i64`). **Invariant:** no field may introduce a non-ASCII or dynamic object key
   without bumping `CANON_VERSION`. (Switching to real JCS via a `serde_jcs` crate is
   only warranted if cross-implementation interop is needed — it is not yet, so the
   dependency is deliberately avoided.)
3. **`ClaimValue::Json` is canonical by construction (ADR 0004 item 6, resolved).** The
   variant holds `CanonicalJson`, a newtype built only via `ClaimValue::json` /
   `CanonicalJson::new`, which parse and re-emit sorted-key + compact (rejecting invalid
   JSON) and re-canonicalize on deserialize. Two semantically-equal JSON blobs differing
   only in key order/whitespace therefore hash identically — the bytes invariant now holds
   for embedded JSON too.
4. `canonical_bytes` is computed in Rust **from the typed struct, never from the DB's
   `JSONB`** (Postgres does not preserve JSON key order).
5. `provenance.recorded_at` is **appender-supplied**, folded into the hashed payload —
   the SQL `DEFAULT now()` has been **dropped** from the migration (likewise the edge
   `created_at`); `dent8_replay_runs.started_at` remains DB-generated because it is
   operational run metadata, not replayable event data.
6. `event_hash` / `hash_chain` use SHA-256 with an **injective, length-framed leaf
   encoding**: `SHA-256(0x00 || CANON_VERSION || len(canonical) || canonical || tag ||
   prev_digest)`, RFC 6962-style `0x00` leaf prefix (`0x01` reserved for a future
   Merkle layer). Length-framing + a genesis tag mean no two distinct
   `(canonical, previous)` pairs share a hash input; a malformed `previous` is rejected.
7. **`schema_version` is realized as the out-of-band `CANON_VERSION` constant** mixed
   into every leaf hash, not a per-event field (ADR 0004 item 7). Bumping it on any
   encoding change keeps hashes from different versions from colliding.

Crates: `serde` + `serde_derive`, `serde_json`, `sha2` (RustCrypto), `hex`.

**External anchor (tamper-resistance).** The chain alone is tamper-*evident* but not
tamper-*resistant*: a writer with full store access can rewrite an event and re-hash the
log forward into a self-consistent chain that `verify_chain` accepts. `dent8_core::anchor`
closes this — `anchor_head` issues an HMAC-SHA256 commitment to `(event_count, head)`
under a **witness key held off the writer's machine**, and `verify_anchor` rejects any log
whose head no longer matches (the writer cannot forge the MAC). The symmetric anchor needs
the verifier to hold the secret; the **asymmetric** upgrade (`sign_head`/`verify_signed_head`,
behind the `signed-anchor` feature) signs the same message with **Ed25519**, so a published
head is verifiable by **anyone with the public key** while the witness keeps the private key
(RFC 6962-style signed tree head). Both are built and tested; what remains is the
*operational* witness that signs and publishes the head on a cadence.

Remaining: wire `hash_chain` into the (still-unbuilt) Postgres append path to populate
the `event_hash`/`previous_event_hash` columns and reverify on replay.

## Postgres adapter (the first realization)

Postgres is the MVP operational store because the log needs append-only ordering,
uniqueness constraints, transactional projection updates, and future multi-user
operation — and Postgres transactions bundle append + projection + edges into one
atomic, durable, isolation-respecting unit ([PostgreSQL transactions](https://www.postgresql.org/docs/current/tutorial-transactions.html)).
The schema is [migrations/postgres/001_initial.sql](../migrations/postgres/001_initial.sql),
exposed in-crate as `INITIAL_SCHEMA_SQL`.

**Chain semantics (the `EventStore` contract).** The hash chain is **global**: each
`event_hash` links to the previous event across the *whole* log (by `global_sequence`),
not to the previous event of the same claim. This matches the in-memory backend
(`InMemoryEventStore`) and the eventual RFC 6962-style signed-tree-head ambition — there
is one tamper-evident head for the entire log. The cost is that **appends must be
serialized** (each depends on the global head). A faithful Postgres backend therefore
reads the previous hash by `MAX(global_sequence)` over *all* rows and serializes the
append (a single-writer path or an advisory lock), not a per-`claim_id` `FOR UPDATE`,
which would not order global appends. *(This is a one-way door; revisit only if write
throughput — not the v0 concern for an integrity store — forces a per-claim chain plus a
separate Merkle layer over claim heads.)*

**Append transaction shape** (one `BEGIN/COMMIT`, serialized):

1. **firewall** (`dent8_store::arbitrate`): load the claim's events, `replay_claim`,
   `apply_event` to gate the transition, and — for a supersession — resolve the
   *replacing claim's actual authority* and reject an over-stated (laundered) one;
2. take the global append lock and read the previous `event_hash`
   (`MAX(global_sequence)`);
3. compute the `event_hash` (`dent8_core::event_hash`, chained to that previous);
4. insert into `dent8_claim_events`;
5. upsert `dent8_claim_projections`;
6. insert `dent8_claim_edges`;
7. commit. If any step fails, nothing is visible. The firewall (step 1) must run *inside*
   the same serialized transaction so the arbitrated state cannot change before the append.

**JSONB usage.** `jsonb` is used for fields whose internal schema evolves quickly
(`authority`, `ttl`, `provenance`, `evidence`, `links`, `payload`). B-tree indexes
serve ordered lookups; GIN indexes (`provenance`, `payload`) serve inspection.
JSONB is for *query/inspection*, never the canonicalization source (see above).

**Client choice.** Default to `sqlx` (async, compile-time-checked queries via the
`query!` macro when `DATABASE_URL` or committed `.sqlx` metadata is available). Open
question: whether compile-time DB checking is too heavy for early contributors — if
so, start with dynamic queries and move hot paths to checked queries once migrations
settle.

**v0 adapter (DB-verified).** `dent8_store_postgres::PostgresEventStore`
(behind the `adapter` feature) is the first realization: an async `sqlx` adapter using
**dynamic** queries (so it compiles without a database) over a focused append-only
`dent8_event_log` table (migration 002) that stores the **canonical event as JSONB** plus
the scalar columns needed to index and arbitrate. It implements the append-transaction
shape above — advisory-lock-serialized, firewall-in-transaction via the *shared*
`arbitrate_events`, global-chain hash — and now also **materializes the derived caches in
the same transaction** (migration 003): it folds the post-append `ClaimState` via the shared
`apply_event` and upserts it into `dent8_claim_projection` (so `materialized_projection`
reads the believed state without re-folding), and records the claim→claim relationship into
`dent8_claim_edge` (supersedes / contradicts / reinforces). These are derived caches, not a
second source of truth: `verify_projection` re-folds the log and asserts `projection ==
fold(log)`. (Timestamps in migration 003 are `BIGINT` Unix milliseconds matching
`TimestampMillis`, and the exact folded state is kept as `state_json` for lossless reads;
the per-column event table and `uses_as_evidence` edges of migration 001 remain a later
target.) The `DATABASE_URL`-gated integration tests **pass against a live `postgres:16`**
(`DATABASE_URL=… cargo test -p dent8-store-postgres --features adapter`). The tests share one
database and `TRUNCATE` it per test, but are invocation-robust: they **self-serialize** (a
process-static async mutex, so no `--test-threads=1`) and **retry the initial connection**
(so a DB still booting — `docker compose up -d` without `--wait` — is tolerated). The live
run surfaced two real bugs now fixed: `migrate()` serializes concurrent schema creation under
an advisory lock (`CREATE TABLE IF NOT EXISTS` is not race-safe on the `pg_class`/`pg_type`
catalog), and `connect()` bounds its acquire timeout so an unreachable DB fails in seconds.
The async boundary is concrete inherent `async fn`s; a shared `AsyncEventStore` trait is
deferred (YAGNI) — this resolves the "async trait vs separate trait" obligation flagged above.

**Schema reference.** The authoritative table/column listing is the migration SQL
itself; an operator-facing schema reference should be *generated from* the migration,
not hand-maintained here.

### Running the adapter against Postgres

dent8 needs a *stock* Postgres — **no extensions** (no pgvector, no graph engine); the
adapter's `migrate()` creates its tables itself (the event log + the projection/edge caches,
migrations 002–003). Anything ≥ Postgres 10 works (the floor for `GENERATED ALWAYS AS
IDENTITY`); `postgres:16` is the pinned default. The integration tests are **gated on
`DATABASE_URL`** — they skip when it is unset and `TRUNCATE` disposable tables when it is set
— so the same `cargo test` is a no-op locally and a real run wherever a database is provided.

A throwaway local database via Docker ([`compose.yml`](../compose.yml)):

```sh
docker compose up -d
DATABASE_URL=postgres://postgres:dent8@localhost:5432/dent8 \
  cargo test -p dent8-store-postgres --features adapter
docker compose down
```

CI runs the same test against a Postgres service container
([`.github/workflows/ci.yml`](../.github/workflows/ci.yml), the `postgres` job); the
`check` job keeps the workspace `fmt`/`clippy`/`test`-clean (and compile-checks the
feature-gated adapter). The application never assumes a database exists — it is env-gated
and self-migrating; Docker/CI merely *provide* one identically for dev and CI.

## Analytical lane (later, not a runtime store)

DuckDB and Parquet are **not** runtime write stores. Later flow: export event-log
slices and projections to Parquet; query with DuckDB for replay analysis, forensics,
benchmark aggregation, and debugger views; keep Postgres as the write path and
operational projection store.

- [DuckDB Parquet support](https://duckdb.org/docs/stable/data/parquet/overview)
- [Apache Parquet documentation](https://parquet.apache.org/docs/)
