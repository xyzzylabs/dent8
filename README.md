# dent8

**A memory firewall for coding agents** — it prevents low-authority or stale project
facts from silently overriding trusted state, and can replay exactly *why* an agent
believed something.

![dent8 demo: a trusted fact is asserted, a low-authority override is rejected by the firewall, and explain replays the auditable receipt.](demo.gif)

See it run: **`cargo run -p dent8-cli -- demo`** — a high-authority fact is asserted, a
low-authority source is rejected when it tries to override it, and an integrity receipt
explains the result with a verified hash chain.

## Why a firewall? (the one-command proof)

Run **`dent8 eval`** — dent8's adversarial corpus pits each attack against the real firewall
*and* a recency-only baseline (newest-write-wins, the resolution Zep/Graphiti use):

| attack | family | firewall | recency-only baseline |
|---|---|---|---|
| `minja_low_authority_injection` | T1 memory injection | blocked ✓ | **compromised** |
| `authority_laundering` | T1 memory injection | blocked ✓ | **compromised** |
| `canonical_contradiction` | T5 canonical contradiction | blocked ✓ | **compromised** |
| `sybil_corroboration` | earned entrenchment | blocked ✓ | **compromised** |
| `poisoned_source_retraction` | T2 retraction cascade | blocked ✓ | **compromised** |

The firewall blocks **5/5** attacks a recency-only memory falls to — including
`poisoned_source_retraction`: retract a poisoned source and dent8 flags every fact *derived*
from it (`dent8 derive` records the edge, `dent8 verify` surfaces the taint), the
dependency-cascade integrity recency-only memory structurally cannot express.

## Install

```sh
# From source (Rust 1.95+):
cargo install --git https://github.com/xyzzylabs/dent8 dent8-cli   # installs the `dent8` binary
# …or run from a clone without installing:
cargo run -p dent8-cli -- demo
```

The stock `dent8` binary uses a local file log and needs no services. Opt-in builds add the
operational **Postgres** backend (`--features postgres`, selected by a `postgres://`
`DENT8_STORE_URL`) and the Ed25519 **witness** (`--features witness`).

## Quickstart

```sh
dent8 eval                                                 # why: 5/5 attacks blocked vs a recency baseline
dent8 assert repo myproj database postgres high owner      # assert a trusted fact
dent8 supersede repo myproj database mysql low web-scrape  # a low-authority override → REJECTED by the firewall
dent8 explain repo myproj database                         # still "postgres", with an integrity receipt
dent8 derive repo myproj deploy_target pg high agent repo myproj database  # derive a fact from it
dent8 retract repo myproj database high owner              # retract the source…
dent8 verify                                               # …and verify flags the now-tainted derivative
```

Facts persist to `./dent8-log.jsonl` by default (override with `DENT8_LOG`). `dent8 --help`
lists the full surface (`assert`/`supersede`/`retract`/`contradict`/`reinforce`/`expire`/
`derive`/`explain`/`replay`/`verify`/`conflicts`/`eval`/`export`/`authority`/`witness`/`mcp serve`).

The core primitive is a claim event, not a generic memory item: every accepted write
preserves provenance, evidence, authority, freshness, contradiction state, supersession
lineage, and replayability. (Origin: *dentate gyrus*, the hippocampal structure
associated with pattern separation.)

## Status

This is an early open-source project. **[docs/STATUS.md](docs/STATUS.md) is the single
source of truth for what is built.** In short:

- **Runnable today:** `dent8 demo` (the firewall + replay/explain loop, registry-driven); the
  full lifecycle through the firewall — **`assert` / `supersede` / `retract` / `contradict` /
  `reinforce` / `expire` / `derive` / `explain` / `replay`** — plus the operator surfaces
  **`verify`** (integrity + retraction-taint check), **`conflicts`**, **`eval`** (the
  self-demonstrating benchmark), and **`export`** (the whole log to Parquet for offline DuckDB
  forensics/audit, behind `--features export` — see [examples/duckdb/](examples/duckdb/)),
  `dent8 authority` / `dent8 witness` (the latter behind
  `--features witness`), and `dent8 schema postgres`. State persists to a local file log and
  **composes across separate invocations**; the file log is a **dev store** (single-writer,
  non-transactional) — the *operational* backend is Postgres (M2b). `dent8 mcp serve` exposes
  the full belief surface plus read/audit tools to agents over MCP (stdio JSON-RPC), through
  the same firewall — see [examples/mcp/](examples/mcp/), [examples/codex/](examples/codex/),
  [examples/claude-code/](examples/claude-code/), [examples/cursor/](examples/cursor/),
  [examples/grok-build/](examples/grok-build/), and [examples/hecate/](examples/hecate/) for
  agent-client wiring.
- **Implemented as a tested library:** the `ClaimEvent` model and replay fold; the
  unbypassable write-path firewall (`EventStore::append`) with authority-weighted
  arbitration + retraction, an anti-laundering challenger check, and the
  canonical-contradiction hard-alarm; the coding-agent predicate registry; the integrity
  receipt; a freshness evaluator; policy-counterfactual and entity-level replay with
  lineage and earned-entrenchment audits; and serde canonicalization + a SHA-256 hash chain.
- **Validated by an adversarial corpus** (`dent8 eval`, or `cargo test -p dent8-evals`): MINJA
  injection, authority laundering, canonical contradiction, Sybil corroboration, and
  **poisoned-source retraction** all **fail against the firewall (0/5)** while **compromising a
  recency-only baseline (5/5)** — see [docs/evals.md](docs/evals.md).
- **DB-verified (M2b):** the v0 Postgres adapter (`PostgresEventStore`, behind
  `--features adapter`) — transactional append, firewall via the shared `arbitrate_events`,
  JSONB event log, **plus a materialized projection + edge graph** (migration 003) folded in
  the same transaction with a `projection == fold(log)` check. The `DATABASE_URL`-gated
  integration tests pass against a live `postgres:16`.
- **Runnable (v0):** an MCP server (`dent8 mcp serve`) exposing read/audit tools
  (`list_facts`/`verify`/`conflicts`) and the full belief surface
  (`assert`/`supersede`/`retract`/`contradict`/`reinforce`/`expire`/`derive`/`explain`/`replay`)
  as tools, plus `resources/list`/`resources/read` and JSON-RPC batches, over stdio JSON-RPC,
  through the shared firewall path.
- **Design-only:** the official MCP `rmcp` SDK / richer transports (the v0 server already does
  the nine tools above, resources, and JSON-RPC batches) and a richer per-column Postgres
  event table (a possible later design; the JSONB log, projection, and edge graph are built, above;
  evidence-dependency edges ship as `EvidenceKind::DerivedFrom` + retraction taint, ADR 0010).

The runnable surface persists either way: a local file dev log by default, or — with
`DENT8_STORE_URL` set and a `--features postgres` build — the **DB-verified transactional
Postgres backend** (each multi-event operation committed as one transaction). An opt-in
**authority ceiling** (`dent8 authority`) caps what each source may assert, rejecting a
write above its registered ceiling. The witness is runnable as a *primitive* — **`dent8
witness`** (`--features witness`) emits Ed25519 signed tree heads and detects a history
rewrite or rollback that an internal chain re-verify cannot. The remaining gap to a hardened
multi-user product is **cryptographic caller identity** (signed grants — *which* source is
calling is still asserted) and an **operated witness service** that signs on a cadence from
separate infrastructure. The [Roadmap](docs/roadmap.md) and
[docs/STATUS.md](docs/STATUS.md) track exactly that.

## Initial Shape

This repository starts Postgres-first. Postgres is the operational source of truth for append-only claim events, projections, audit queries, and future multi-user use. DuckDB and Parquet are an **export-only** analytical lane — built as `dent8 export` (Parquet, queried directly by DuckDB) for replay, forensic inspection, and benchmark analysis, never a runtime write store.

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
- `dent8 expire <kind> <key> <predicate> <authority> <source>`: terminally close the
  believed fact for policy retention — authority-gated like retraction; TTL staleness is
  read-time and non-mutating.
- `dent8 explain <kind> <key> <predicate>`: print the believed (or terminal) fact's receipt.
- `dent8 replay <kind> <key> <predicate>`: replay the full event history — *why* the fact
  is what it is.
- `dent8 export [out.parquet]`: export the whole log to Parquet for offline DuckDB
  forensics/audit (needs `--features export`; see [examples/duckdb/](examples/duckdb/)).
- `dent8 schema postgres`: print the initial Postgres schema.
- `dent8 mcp serve`: expose read/audit tools, the full belief surface, resources, and
  JSON-RPC batches to agents over MCP (stdio JSON-RPC).

## Project Docs

**Status**

- [Implementation Status](docs/STATUS.md) — single source of truth for what is built
- [Configuration](docs/configuration.md) — env vars + Cargo features in one place
- [Changelog](CHANGELOG.md)

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
