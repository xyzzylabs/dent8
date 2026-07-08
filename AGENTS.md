# AGENTS.md

## Project Intent

dent8 is a memory integrity platform for agentic systems. Treat it as infrastructure for correctness, provenance, replay, and explainability, not as a generic memory provider.

## Fact base (authoritative)

This repo dogfoods dent8: the shared, verified facts about it (MSRV, CI gates, commit
conventions, the authority profile, eval tallies, roadmap) live in the dent8 store, not in a
hand-edited rules file. **The dent8 fact base is authoritative** — when it and prose
disagree, correct it through the firewall rather than editing around it.

- Rebuild the local store: `scripts/dogfood-seed.sh` (reads `scripts/dogfood-facts.jsonl`).
- Read the believed facts: `dent8 context` (markdown) or `dent8 context -o json`.
- Add or correct a fact: append a proposal to `.dent8/proposals.jsonl`; the `SessionEnd`
  hook flushes it via `dent8 capture … --consume --keep-failed`. Human corrections enter as
  `source:human` at High; agent inferences enter as `source:agent` at Low.
- Hooks are wired in `.claude/settings.json` (`SessionStart` → `dent8 context`,
  `SessionEnd` → `dent8 capture`).

See [docs/dogfooding-notes.md](docs/dogfooding-notes.md) for the setup walkthrough and known rough edges.

## Architecture Rules

- The core primitive is `FactEvent`.
- Materialized memory is a projection of the event log.
- Prefer explicit state machines, typed transitions, and invariant checks.
- Postgres (first) and embedded SQLite (second) are *adapters* of the storage boundary, not the architecture — keep durable storage design backend-agnostic against the `EventStore` / `AsyncEventStore` traits.
- DuckDB and Parquet are an **export-only** analytical lane (built: `dent8 export` → Parquet, behind `--features export`), not runtime write stores.
- dent8's formal identity is a **belief base** with paraconsistent contradiction tolerance and authority-as-entrenchment (`docs/belief-revision.md`). Do not fact AGM compliance; do not enforce global consistency; do not satisfy Recovery.
- Be honest about the gap between *implemented in the library*, *runnable by a user*, and *production-ready*. Authority arbitration, freshness, and the hash chain are **enforced at the write boundary** (`EventStore::append` via `arbitrate` — there is no un-arbitrated write path); the CLI/MCP run that firewall end-to-end over a **file-backed dev store**; the **Postgres adapter is DB-verified** (transactional append + materialized projection/edges); and an **embedded SQLite adapter** is the default local async backend. The CLI/MCP run on the file dev store **or** any async backend selected by `DENT8_STORE_URL` (SQLite in stock builds; Postgres with `--features postgres`; each multi-event operation committed transactionally via the shared `AsyncEventStore`). The remaining gap is *productization*, not enforcement: **authz is built** (a source→authority *ceiling*, `dent8 authority`, that rejects an over-ceiling write at the write boundary), **authn is built into the stock CLI** (`dent8 identity`, issuer-signed grants + per-write source-key possession checks at the CLI/MCP boundary), and the witness is a runnable *primitive* (`dent8 witness`), but key distribution/rotation, stronger secret storage, and an operated witness service are still product work. Check [docs/STATUS.md](docs/STATUS.md) (the single source of truth) before describing anything as "working" or "production," and keep it accurate when you move an item between tiers.
- Keep changes small, but preserve the shape needed for replay, audit, and debugger workflows.

## Key docs

- `docs/belief-revision.md` — formal identity (lead lens).
- `docs/storage.md` — event-log design + Postgres adapter + canonicalization.
- `docs/formal-verification.md` + `docs/evals.md` — how invariants are checked.
- `docs/threat-model.md` — the firewall's adversary model.
- `docs/roadmap.md` — dependency-ordered plan; `docs/decisions/` — ADRs.

## Dogfood

- This repo may have ignored local dogfood state in `.dent8/`, `.codex/config.toml`, and
  `.cursor/mcp.json`. Do not commit those files.
- When dogfood state is present, consult dent8 for durable project facts before relying on
  remembered setup or preferences. Prefer MCP tools (`list_facts`, `explain`, `verify`) when
  available; otherwise use the local CLI after loading `.dent8/env` and the agent-specific
  identity env (for example `.dent8/identity-codex.env` or `.dent8/identity-cursor.env`).
- The local Codex MCP config should point at `.dent8/bin/dent8`, an ignored wrapper that runs
  a SQLite-capable stock build from `.dent8/target-sqlite`. Claude Code uses `.mcp.json`;
  Cursor uses `.cursor/mcp.json`. This avoids Cargo startup on every MCP launch and keeps the
  dogfood binary isolated from normal `target/debug` rebuilds.
- The local dogfood store may be witness-backed with `.dent8/witness.jsonl` and
  `.dent8/witness.key.pub`. The private `.dent8/witness.key` stays out of `.dent8/env` and
  should only be passed explicitly when signing a head.
- To validate the local dogfood path, build the isolated SQLite-capable target and run:

```sh
CARGO_TARGET_DIR=.dent8/target-sqlite cargo build -p dent8 --features sqlite
.dent8/bin/dent8 doctor --agent codex --dir .dent8 --write-check
.dent8/bin/dent8 doctor --agent claude-code --dir .dent8 --write-check
.dent8/bin/dent8 doctor --agent cursor --dir .dent8 --write-check
set -a; . .dent8/env; set +a
export DENT8_WITNESS_GRANTS_LOG=.dent8/witness-grants.jsonl
DENT8_WITNESS_KEY=.dent8/witness.key .dent8/bin/dent8 witness sign
.dent8/bin/dent8 doctor --agent codex --dir .dent8
```

- Durable project facts should be asserted or superseded through dent8, not silently copied
  into provider-native memory/rules files.
- See `docs/dogfood.md` for the repeatable maintainer workflow and
  `examples/dogfood/demo.sh` for the local acceptance check.

## Commands

Run before handing off Rust changes:

```sh
cargo fmt --all --check
cargo test --workspace
```

Useful smoke command:

```sh
cargo run -q -p dent8 -- schema postgres
```

## Documentation

When changing architecture or domain semantics, update the relevant docs under `docs/` and add a decision record under `docs/decisions/` if the choice affects long-term project shape.
