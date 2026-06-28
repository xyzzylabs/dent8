# AGENTS.md

## Project Intent

dent8 is a memory integrity platform for agentic systems. Treat it as infrastructure for correctness, provenance, replay, and explainability, not as a generic memory provider.

## Architecture Rules

- The core primitive is `ClaimEvent`.
- Materialized memory is a projection of the event log.
- Prefer explicit state machines, typed transitions, and invariant checks.
- Postgres is the *first adapter* of the storage boundary, not the architecture — keep durable storage design backend-agnostic against the `EventStore` trait.
- DuckDB and Parquet are later analytical/export lanes, not runtime write stores.
- dent8's formal identity is a **belief base** with paraconsistent contradiction tolerance and authority-as-entrenchment (`docs/belief-revision.md`). Do not claim AGM compliance; do not enforce global consistency; do not satisfy Recovery.
- Be honest about the gap between *implemented in the library*, *runnable by a user*, and *production-ready*. Authority arbitration, freshness, and the hash chain are **enforced at the write boundary** (`EventStore::append` via `arbitrate` — there is no un-arbitrated write path); the CLI/MCP run that firewall end-to-end over a **file-backed dev store**; and the **Postgres adapter is DB-verified** (transactional append + materialized projection/edges). The remaining gap is *productization*, not enforcement: the runnable CLI/MCP still use the file store (not Postgres), authority is client-supplied (no authn/authz mapping credentials to authority), and the witness/anchor is a primitive, not a hosted service. Check [docs/STATUS.md](docs/STATUS.md) (the single source of truth) before describing anything as "working" or "production," and keep it accurate when you move an item between tiers.
- Keep changes small, but preserve the shape needed for replay, audit, and debugger workflows.

## Key docs

- `docs/belief-revision.md` — formal identity (lead lens).
- `docs/storage.md` — event-log design + Postgres adapter + canonicalization.
- `docs/formal-verification.md` + `docs/evals.md` — how invariants are checked.
- `docs/threat-model.md` — the firewall's adversary model.
- `docs/roadmap.md` — dependency-ordered plan; `docs/decisions/` — ADRs.

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

