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
- Heads-up: once `dent8` is built and on `PATH`, the `PreToolUse` guard hard-blocks direct edits to native-memory files (`AGENTS.md`, `CLAUDE.md`, `.cursor/rules/*`). Set `DENT8_ALLOW_NATIVE_MEMORY_WRITE=1` for an intentional edit, or route the change through the fact base.

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

<!-- BEGIN dent8 managed block (generated by `dent8 export`; edits inside are overwritten) -->
<!-- dent8 export: 15 believed fact(s); do not edit inside this block — run `dent8 export --target <file>` to refresh -->

### eval:corpus

- `dent8://eval/corpus/core.tally` = "47 adversarial cases / 10 attack classes: 16 blocked by arbitration, 4 detect-only, 27 out-of-model (by design). Frozen: per_class_block_rates_match_the_frozen_honest_tally"  <!-- dent8 receipt fact=fact:eval:corpus:core.tally:10 event_hash=d9ea9b55ec1d… authority=high source=source:human -->
- `dent8://eval/corpus/hook.tally` = "content-check lane: 16 arbitration + 9 hook = 25 blocked, 9 detect-only, 13 admitted unflagged. Frozen: per_class_rates_with_the_demo_scanner_match_the_frozen_honest_tally"  <!-- dent8 receipt fact=fact:eval:corpus:hook.tally:11 event_hash=8d7e93b42cec… authority=high source=source:human -->

### hook:content-check

- `dent8://hook/content-check/contract` = "protocol dent8.content-check/1: DENT8_CONTENT_CHECK spawns a scanner; stdin=JSON payload, stdout=JSON verdict {allow|reject|taint}; exit 0 for any verdict (non-zero = scanner failed), fail-closed by default; runs in the op_* write layer after authority, before arbitration/persist"  <!-- dent8 receipt fact=fact:hook:content-check:contract:12 event_hash=43fe0acc72c6… authority=high source=source:human -->

### policy:authority

- `dent8://policy/authority/default.profile` = "human > CI > agent: source:human max=high, source:ci max=medium, source:agent max=low; seeded by `dent8 authority defaults`; deny-by-default for unlisted sources"  <!-- dent8 receipt fact=fact:policy:authority:default.profile:9 event_hash=c6df02d9eeb7… authority=high source=source:human -->

### repo:dent8

- `dent8://repo/dent8/cli.binary` = "CLI binary is `dent8` (crates/dent8-cli); tagline: a memory firewall for coding agents"  <!-- dent8 receipt fact=fact:repo:dent8:cli.binary:0 event_hash=21b0f5ccd220… authority=high source=source:human -->
- `dent8://repo/dent8/commit.attribution` = "no Co-Authored-By trailers and no AI attribution in commits or PRs"  <!-- dent8 receipt fact=fact:repo:dent8:commit.attribution:7 event_hash=ee0a1b54ca0f… authority=high source=source:human -->
- `dent8://repo/dent8/commit.author` = "single maintainer (chicoxyzzy / Sergey Rubanov) <chi187@gmail.com>"  <!-- dent8 receipt fact=fact:repo:dent8:commit.author:5 event_hash=db7ccdab185b… authority=high source=source:human -->
- `dent8://repo/dent8/commit.style` = "Conventional Commits: feat/fix/docs/test/ci, optional scope, trailing (#PR)"  <!-- dent8 receipt fact=fact:repo:dent8:commit.style:6 event_hash=a260da189709… authority=high source=source:human -->
- `dent8://repo/dent8/gate.clippy` = "cargo clippy --workspace --all-targets -- -D warnings (warnings are errors)"  <!-- dent8 receipt fact=fact:repo:dent8:gate.clippy:4 event_hash=9e79cbc2a7fb… authority=high source=source:human -->
- `dent8://repo/dent8/gate.fmt` = "cargo fmt --all -- --check"  <!-- dent8 receipt fact=fact:repo:dent8:gate.fmt:3 event_hash=f3c5a0436afb… authority=high source=source:human -->
- `dent8://repo/dent8/gate.test` = "cargo test --workspace (CI job: fmt + clippy + test in .github/workflows/ci.yml)"  <!-- dent8 receipt fact=fact:repo:dent8:gate.test:2 event_hash=493f35683f18… authority=high source=source:human -->
- `dent8://repo/dent8/msrv` = "Rust 1.94 — Cargo.toml [workspace.package] rust-version = \"1.94\"; edition 2024; no rust-toolchain.toml (CI builds on stable)"  <!-- dent8 receipt fact=fact:repo:dent8:msrv:1 event_hash=ff0aec510384… authority=high source=source:human -->
- `dent8://repo/dent8/store.default` = "default store is a file dev log at .dent8/memory.jsonl; the .dent8/ store is gitignored (machine-local) — rebuild with scripts/dogfood-seed.sh"  <!-- dent8 receipt fact=fact:repo:dent8:store.default:8 event_hash=70a14c5100b0… authority=high source=source:human -->

### roadmap:dent8

- `dent8://roadmap/dent8/frozen` = "frozen until the wedge has users: operated-witness hosting, the desktop debugger/control plane, and any training-substrate direction"  <!-- dent8 receipt fact=fact:roadmap:dent8:frozen:14 event_hash=82edc2c6ce50… authority=high source=source:human -->
- `dent8://roadmap/dent8/v0.4.focus` = "v0.4 wedge: multiple coding agents and a human sharing one verified fact base per repo. Priorities: (1) capture+inject loop, (2) default authority profile, (3) on-ramp <2min to first fact, (4) external eval (MINJA/mem0/Zep), (5) Python/TS reachability"  <!-- dent8 receipt fact=fact:roadmap:dent8:v0.4.focus:13 event_hash=385938dfc4b3… authority=high source=source:human -->

<!-- END dent8 managed block -->
