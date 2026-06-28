# dent8

**A memory firewall for coding agents** — it prevents low-authority or stale project
facts from silently overriding trusted state, and can replay exactly *why* an agent
believed something.

![dent8 demo: a trusted fact is asserted, a low-authority override is rejected by the firewall, and explain replays the auditable receipt.](demo.gif)

See it run: **`cargo run -p dent8-cli -- demo`** — a high-authority fact is asserted, a
low-authority source is rejected when it tries to override it, and an integrity receipt
explains the result with a verified hash chain.

The core primitive is a claim event, not a generic memory item: every accepted write
preserves provenance, evidence, authority, freshness, contradiction state, supersession
lineage, and replayability. (Origin: *dentate gyrus*, the hippocampal structure
associated with pattern separation.)

## Status

This is an early open-source project. **[docs/STATUS.md](docs/STATUS.md) is the single
source of truth for what is built.** In short:

- **Runnable today:** `dent8 demo` (the firewall + replay/explain loop, registry-driven);
  the full **`assert` / `supersede` / `retract` / `contradict` / `explain` / `replay`** lifecycle through
  the firewall, persisted to a local file-backed log and **composing across separate
  invocations**; and `dent8 schema postgres`. The file log is a **dev store** (single-writer,
  non-transactional) — the *operational* backend is Postgres (M2b). `dent8 mcp serve` exposes
  the full belief surface to agents over MCP (stdio JSON-RPC), through the same firewall.
- **Implemented as a tested library:** the `ClaimEvent` model and replay fold; the
  unbypassable write-path firewall (`EventStore::append`) with authority-weighted
  arbitration + retraction, an anti-laundering challenger check, and the
  canonical-contradiction hard-alarm; the coding-agent predicate registry; the integrity
  receipt; a freshness evaluator; policy-counterfactual and entity-level replay with
  lineage and earned-entrenchment audits; and serde canonicalization + a SHA-256 hash chain.
- **Validated by an adversarial corpus** (`cargo test -p dent8-evals`): MINJA injection,
  authority laundering, canonical contradiction, and Sybil corroboration all **fail against
  the firewall (0/4)** while **compromising a recency-only baseline (4/4)** — see
  [docs/evals.md](docs/evals.md).
- **DB-verified (M2b):** the v0 Postgres adapter (`PostgresEventStore`, behind
  `--features adapter`) — transactional append, firewall via the shared `arbitrate_events`,
  JSONB event log, **plus a materialized projection + edge graph** (migration 003) folded in
  the same transaction with a `projection == fold(log)` check. The `DATABASE_URL`-gated
  integration tests pass against a live `postgres:16`.
- **Runnable (v0):** an MCP server (`dent8 mcp serve`) exposing the full belief surface
  (`assert`/`supersede`/`retract`/`contradict`/`explain`/`replay`) as tools, plus
  `resources/list`/`resources/read` and JSON-RPC batches, over stdio JSON-RPC, through the
  shared firewall path.
- **Design-only:** the official MCP `rmcp` SDK / richer transports (the v0 server already
  does tools, resources, and JSON-RPC batches) and the per-column Postgres event table +
  `uses_as_evidence` edges (the projection + relationship graph are built, above).

The remaining gap is **operational persistence wiring**: the firewall loop runs, the
predicate registry (M3) governs it, a local file-backed log already persists
`assert`/`explain` across invocations, and the transactional Postgres backend (M2b) is
**DB-verified** — but the runnable CLI/MCP surface still uses the file dev store, so making
it a real multi-user product means wiring those commands onto `PostgresEventStore`. The
[Roadmap](docs/roadmap.md) front-loads exactly that.

## Initial Shape

This repository starts Postgres-first. Postgres is the operational source of truth for append-only claim events, projections, audit queries, and future multi-user use. DuckDB and Parquet remain a later analytical lane for replay, forensic inspection, benchmark analysis, and debugger workflows.

Workspace crates:

- `dent8-core`: typed domain model, claim-event state machine, invariants.
- `dent8-store`: storage and replay traits shared by backends.
- `dent8-store-postgres`: Postgres schema and migration boundary.
- `dent8-cli`: operator and developer CLI surface.

Commands (see [docs/STATUS.md](docs/STATUS.md) for what runs today):

- `dent8 demo`: run the firewall + registry + replay/explain loop end to end (in-memory).
- `dent8 assert <kind> <key> <predicate> <value> <authority> <source>`: assert a fact
  through the firewall, persisted to a file-backed log (`DENT8_LOG`).
- `dent8 supersede <kind> <key> <predicate> <new-value> <authority> <source>`: revise the
  believed fact — rejected unless the revision can out-rank the incumbent.
- `dent8 retract <kind> <key> <predicate> <authority> <source>`: remove the believed fact —
  also rejected unless it can out-rank the incumbent.
- `dent8 contradict <kind> <key> <predicate> <opposing-value> <authority> <source>`: flag a
  conflict (dissent) — contest the fact and keep both, even from low authority.
- `dent8 explain <kind> <key> <predicate>`: print the believed (or terminal) fact's receipt.
- `dent8 replay <kind> <key> <predicate>`: replay the full event history — *why* the fact
  is what it is.
- `dent8 schema postgres`: print the initial Postgres schema.
- `dent8 mcp serve`: expose the full belief surface (tools + resources + JSON-RPC batches)
  to agents over MCP (stdio JSON-RPC).

## Project Docs

**Status**

- [Implementation Status](docs/STATUS.md) — single source of truth for what is built

**Design**

- [Project Brief](docs/project-brief.md)
- [Architecture](docs/architecture.md)
- [Domain Model](docs/domain-model.md)
- [Belief Revision](docs/belief-revision.md) — dent8's formal identity (the lead lens)
- [Storage & the Event Log](docs/storage.md)
- [Interfaces](docs/interfaces.md)
- [Naming](docs/naming.md)

**Correctness & security**

- [Formal Verification](docs/formal-verification.md)
- [Evaluation Strategy](docs/evals.md)
- [Threat Model](docs/threat-model.md)

**Planning & research**

- [Roadmap](docs/roadmap.md)
- [Related Work](docs/related-work.md)
- [Research Dossier](docs/research/dossier.md)
- [Open Research Directions](docs/research/novelty.md)
- [Training Substrate](docs/research/training-substrate.md)
- [Paper Outline](docs/paper/outline.md) · [Preprint Draft](docs/paper/preprint.md)
- [Decision Records](docs/decisions)

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -q -p dent8-cli -- demo

# The Postgres adapter (M2b, DB-verified) is feature-gated; its integration tests are gated
# on DATABASE_URL (they skip without one). Throwaway DB via Docker:
docker compose up -d
DATABASE_URL=postgres://postgres:dent8@localhost:5432/dent8 \
  cargo test -p dent8-store-postgres --features adapter
docker compose down
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the workspace
fmt/clippy/test gate and the adapter against a Postgres service container.

## Status

dent8 is **pre-1.0 (v0.x)** and experimental — the API, the on-disk event encoding, and the
storage schema may change between minor versions. [`docs/STATUS.md`](docs/STATUS.md) is the
single source of truth for what is runnable vs. library-only vs. design-only, and
[`docs/threat-model.md`](docs/threat-model.md) states precisely what the firewall does and
does not defend against. Security reports: see [`SECURITY.md`](SECURITY.md).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed
as above, without any additional terms or conditions.
