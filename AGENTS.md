# AGENTS.md

## Project Intent

dent8 is a memory integrity platform for agentic systems. Treat it as infrastructure for correctness, provenance, replay, and explainability, not as a generic memory provider.

## Architecture Rules

- The core primitive is `ClaimEvent`.
- Materialized memory is a projection of the event log.
- Prefer explicit state machines, typed transitions, and invariant checks.
- Postgres (first) and embedded SQLite (second) are *adapters* of the storage boundary, not the architecture — keep durable storage design backend-agnostic against the `EventStore` / `AsyncEventStore` traits.
- DuckDB and Parquet are an **export-only** analytical lane (built: `dent8 export` → Parquet, behind `--features export`), not runtime write stores.
- dent8's formal identity is a **belief base** with paraconsistent contradiction tolerance and authority-as-entrenchment (`docs/belief-revision.md`). Do not claim AGM compliance; do not enforce global consistency; do not satisfy Recovery.
- Be honest about the gap between *implemented in the library*, *runnable by a user*, and *production-ready*. Authority arbitration, freshness, and the hash chain are **enforced at the write boundary** (`EventStore::append` via `arbitrate` — there is no un-arbitrated write path); the CLI/MCP run that firewall end-to-end over a **file-backed dev store**; the **Postgres adapter is DB-verified** (transactional append + materialized projection/edges); and an **embedded SQLite adapter** is the runnable + tested second backend. The CLI/MCP run on the file dev store **or** any async backend selected by `DENT8_STORE_URL` (a `--features postgres` or `--features sqlite` build, each multi-event operation committed transactionally via the shared `AsyncEventStore`). The remaining gap is *productization*, not enforcement: **authz is built** (a source→authority *ceiling*, `dent8 authority`, that rejects an over-ceiling write at the write boundary), **authn is built as a feature-gated primitive** (`dent8 identity`, issuer-signed grants + per-write source-key possession checks at the CLI/MCP boundary), and the witness is a runnable *primitive* (`dent8 witness`), but key distribution/rotation, stronger secret storage, and an operated witness service are still product work. Check [docs/STATUS.md](docs/STATUS.md) (the single source of truth) before describing anything as "working" or "production," and keep it accurate when you move an item between tiers.
- Keep changes small, but preserve the shape needed for replay, audit, and debugger workflows.

## Key docs

- `docs/belief-revision.md` — formal identity (lead lens).
- `docs/storage.md` — event-log design + Postgres adapter + canonicalization.
- `docs/formal-verification.md` + `docs/evals.md` — how invariants are checked.
- `docs/threat-model.md` — the firewall's adversary model.
- `docs/roadmap.md` — dependency-ordered plan; `docs/decisions/` — ADRs.

## Dogfood

- This repo may have ignored local dogfood state in `.dent8/` and `.codex/config.toml`.
  Do not commit those files.
- When dogfood state is present, consult dent8 for durable project facts before relying on
  remembered setup or preferences. Prefer MCP tools (`list_facts`, `explain`, `verify`) when
  available; otherwise use the local CLI after loading `.dent8/env` and `.dent8/identity.env`.
- The local Codex MCP config should point at `.dent8/bin/dent8`, an ignored wrapper that runs
  a SQLite + witness-enabled build from `.dent8/target-sqlite`. This avoids normal
  `target/debug` rebuilds replacing the MCP binary with one that lacks SQLite or witness
  support.
- The local dogfood store may be witness-backed with `.dent8/witness.jsonl` and
  `.dent8/witness.key.pub`. The private `.dent8/witness.key` stays out of `.dent8/env` and
  should only be passed explicitly when signing a head.
- To validate the local Codex dogfood path, build the isolated SQLite+witness target and run:

```sh
CARGO_TARGET_DIR=.dent8/target-sqlite cargo build -p dent8-cli --features sqlite,witness
.dent8/bin/dent8 doctor --agent codex --dir .dent8 --write-check
DENT8_WITNESS_KEY=.dent8/witness.key .dent8/bin/dent8 witness sign
.dent8/bin/dent8 doctor --agent codex --dir .dent8
```

- Durable project facts should be asserted or superseded through dent8, not silently copied
  into provider-native memory/rules files.

## Commands

Run before handing off Rust changes:

```sh
cargo fmt --all --check
cargo test --workspace
```

Useful smoke command:

```sh
cargo run -q -p dent8-cli -- schema postgres
```

## Documentation

When changing architecture or domain semantics, update the relevant docs under `docs/` and add a decision record under `docs/decisions/` if the choice affects long-term project shape.
