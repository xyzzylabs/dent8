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

The stock `dent8` binary uses a local file log, needs no services, and includes signed source
identity. Opt-in builds add the operational **Postgres** backend (`--features postgres`,
selected by a `postgres://` `DENT8_STORE_URL`) and the Ed25519 **witness**
(`--features witness`).

## Quickstart

```sh
dent8 init                                                 # create .dent8/env + authority registry
set -a; . .dent8/env; set +a
dent8 doctor --write-check                                # verify setup + prove the firewall path
dent8 eval                                                 # why: 5/5 attacks blocked vs a recency baseline
dent8 assert person:alice favorite_drink tea --authority high --source user:alice
dent8 supersede person:alice favorite_drink coffee --authority low --source note:old  # REJECTED
dent8 explain person:alice favorite_drink                  # still "tea", with an integrity receipt
dent8 derive person:alice shopping_item tea --from person:alice favorite_drink --authority medium --source assistant
dent8 retract person:alice favorite_drink --authority high --source user:alice
dent8 verify                                               # flags the now-tainted derivative
dent8 completions zsh                                      # generate shell completions
```

For a protected agent setup, let `init` create the authority registry and signed source
identity bundle together:

```sh
dent8 init --agent codex --install-mcp    # source:codex + signed identity + Codex config
dent8 doctor --agent codex --write-check  # installed MCP smoke + MCP firewall write-check
```

Use `dent8 mcp install --agent <profile>` to patch/show an existing agent MCP config later
(`--dry-run` renders without writing; `--check` exits non-zero if the config would change).
If doctor reports a stale generated identity bundle or MCP env, `dent8 doctor --agent
<profile> --repair` repairs the generated env and refreshes the installed MCP config before
rerunning the normal checks.
Source `.dent8/env` + `.dent8/identity.env` when you want to run CLI commands from the same
shell. Use `dent8 init --identity --source <source>` for a custom source id. Agent shortcuts are
available for `codex`, `claude-code`, `cursor`, `grok-build`, `gemini`, `cascade`, and
`hecate`. The installer writes `command = "dent8"` by default, so Codex, Claude Code, Cursor,
Gemini, Grok Build, Cascade, and Hecate can all use one globally installed binary; pass
`--mcp-command` / `--command` if the binary lives elsewhere; `doctor --agent` reads the installed
config back, smokes that exact command/args/cwd/env, and can run the write-check through that
installed MCP server. Stdio MCP clients normally launch their own
dent8 subprocess, but those processes can share the same operational belief base by using the
same `DENT8_STORE_URL` (Postgres is the production-shaped multi-agent store) while keeping
distinct per-agent grants/keys for provenance. A single long-lived local/remote MCP daemon over
HTTP is future transport work, not part of v0. `dent8 identity status` checks a local
identity bundle; `dent8 identity repair-env` repairs legacy generated identity env /
active-grants files from the current signed grant without rotating keys; and
`dent8 identity rotate-source` replaces the active source key/grant while keeping the stable
`.dent8/identity.env` paths that MCP configs use. Rotation updates `.dent8/active-grants.json`,
so the old grant/key pair is rejected even if someone manually points env vars at backed-up
grant material. `identity bootstrap` remains available for custom layouts and keeps the issuer
key outside `.dent8` by default (`$XDG_CONFIG_HOME/dent8/issuer.key` or
`$HOME/.config/dent8/issuer.key`; override with `--issuer-key`). The project bundle contains
only the trust registry, active-grant registry, per-source key, grant, and env snippet an agent
needs. The default issuer key is shared across projects for the same
OS user; use a project-specific `--issuer-key` when you want grant-signing isolation between
projects.

Facts persist to `./dent8-log.jsonl` by default (override with `DENT8_LOG`). `dent8 --help`
lists the full surface (`assert`/`supersede`/`retract`/`contradict`/`reinforce`/`expire`/
`derive`/`explain`/`replay`/`verify`/`conflicts`/`eval`/`export`/`authority`/`hook`/`witness`/
`init`/`doctor`/`completions`/`mcp serve`/`mcp install`). Use the global `--color auto|always|never` flag to control
colored help, errors, and verdict words in human-facing output.

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
  `dent8 init` / `dent8 doctor`, `dent8 authority`, `dent8 identity`, `dent8 witness`
  (behind `--features witness`), and
  `dent8 schema postgres`. State persists to a local file log and
  **composes across separate invocations**; the file log is a **dev store** (single-writer,
  non-transactional) — the *operational* backends are **Postgres** (server) and **embedded
  SQLite**, selected by `DENT8_STORE_URL`. `dent8 mcp serve` exposes
  the full belief surface plus read/audit tools to agents over MCP (stdio JSON-RPC), through
  the same firewall — see [examples/mcp/](examples/mcp/), [examples/codex/](examples/codex/),
  [examples/claude-code/](examples/claude-code/), [examples/gemini/](examples/gemini/),
  [examples/cascade/](examples/cascade/), [examples/cursor/](examples/cursor/),
  [examples/grok-build/](examples/grok-build/), [examples/hecate/](examples/hecate/), and
  [examples/vercel-ai-sdk/](examples/vercel-ai-sdk/) for agent-client wiring. Optional native
  memory/rules hook guards use the built-in
  `dent8 hook native-memory-guard`; provider profiles live in
  [examples/agent-hooks/](examples/agent-hooks/).
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
- **DB-verified:** the v0 Postgres adapter (`PostgresEventStore`, behind the store crate's
  `adapter` feature; CLI users enable it with `--features postgres`) — transactional append,
  firewall via the shared `arbitrate_events`,
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
write above its registered ceiling. Signed source identity — **`dent8 identity`**
— included in the default CLI build — binds a source id to a source public key via an
issuer-signed grant and verifies source-key possession on every CLI/MCP write when a trust
root is configured.
The witness is runnable as a *primitive* — **`dent8 witness`** (`--features witness`) emits
Ed25519 signed tree heads and detects a history rewrite or rollback that an internal chain
re-verify cannot. `dent8 init --witness` configures verifier-side paths and `dent8 doctor`
reports signed-head coverage; `dent8 witness doctor <writer|signer|both>` checks the
operator split so writer/agent/MCP processes do not inherit the private witness key; and
`dent8 witness publish <heads.jsonl>` / `verify-published <heads.jsonl>` append and check
externally saved heads so a local witness-log rollback cannot erase retained evidence. The
remaining gap to a hardened multi-user product is operating those controls well: key
distribution/rotation, stronger secret storage, managed head publication, and an **operated
witness service** that signs on a cadence from separate infrastructure. See
[docs/witness.md](docs/witness.md), the runnable [witness example](examples/witness/), the
[Roadmap](docs/roadmap.md), and [docs/STATUS.md](docs/STATUS.md).

## Initial Shape

The durable design is a backend-agnostic append-only event log (the `EventStore` / `AsyncEventStore` traits), not a database choice. Postgres was the first operational adapter — the source of truth for append-only claim events, projections, audit queries, and multi-user use — and an **embedded SQLite** backend is the second; both are selected by `DENT8_STORE_URL` and share the same firewall and hash chain. DuckDB and Parquet are an **export-only** analytical lane — built as `dent8 export` (Parquet, queried directly by DuckDB) for replay, forensic inspection, and benchmark analysis, never a runtime write store.

Workspace crates:

- `dent8-core`: typed domain model, claim-event state machine, invariants.
- `dent8-store`: storage and replay traits (`EventStore` + async `AsyncEventStore`) shared by backends.
- `dent8-store-postgres`: Postgres adapter, schema, and migration boundary.
- `dent8-store-sqlite`: embedded SQLite adapter (the second `AsyncEventStore` backend).
- `dent8-cli`: operator and developer CLI surface.
- `dent8-evals`: adversarial corpus behind the self-demonstrating `dent8 eval`.
- `dent8-export`: Parquet export for offline DuckDB analysis (opt-in, `--features export`).

Commands (see [docs/STATUS.md](docs/STATUS.md) for what runs today):

- `dent8 demo`: run the firewall + registry + replay/explain loop end to end (in-memory).
- `dent8 init`: create a local `.dent8/` setup: env file, authority registry, and selected
  file/SQLite/Postgres store profile; optional `--witness` adds verifier-side signed-head
  paths without exposing the witness signing key to the writer env.
- `dent8 doctor [--agent <profile>] [--repair] [--write-check]`: inspect binary, store, authority,
  witness coverage when configured, verify, MCP availability; with `--agent`, validate the
  generated bundle/config and smoke `mcp serve` with `initialize` + `tools/list`;
  with `--repair`, refresh stale generated identity env and installed MCP config;
  with `--write-check`, run the Alice trusted-fact / low-authority-rejection flow (through
  the installed MCP server for agent profiles).
- `dent8 identity bootstrap/status/repair-env/rotate-source`: create, inspect, repair generated
  env files for, and rotate a local signed source identity bundle (operator issuer key outside
  the bundle, source key, trust registry, active-grant registry, grant, and `.dent8/identity.env`).
- `dent8 assert <subject> <predicate> <value> --authority <level> --source <source>`: assert a fact
  through the firewall, persisted to a file-backed log (`DENT8_LOG`).
- `dent8 supersede <subject> <predicate> <new-value> --authority <level> --source <source>`: revise the
  believed fact — rejected unless the revision can out-rank the incumbent.
- `dent8 retract <subject> <predicate> --authority <level> --source <source>`: remove the believed fact —
  also rejected unless it can out-rank the incumbent.
- `dent8 contradict <subject> <predicate> <opposing-value> --authority <level> --source <source>`: flag a
  conflict (dissent) — contest the fact and keep both, even from low authority.
- `dent8 derive <subject> <predicate> <value> --from <source-subject> <source-predicate>
  --authority <level> --source <source>`: assert a fact derived from another fact, recording
  the dependency edge that `verify` can later audit.
- `dent8 reinforce <subject> <predicate> --authority <level> --source <source>`: corroborate
  the believed fact without restating its value.
- `dent8 expire <subject> <predicate> --authority <level> --source <source>`: terminally close the
  believed fact for policy retention — authority-gated like retraction; TTL staleness is
  read-time and non-mutating.
- `dent8 explain <subject> <predicate>`: print the believed (or terminal) fact's receipt.
- `dent8 replay <subject> <predicate>`: replay the full event history — *why* the fact
  is what it is.
- `dent8 export [out.parquet]`: export the whole log to Parquet for offline DuckDB
  forensics/audit (needs `--features export`; see [examples/duckdb/](examples/duckdb/)).
- `dent8 completions <bash|elvish|fish|powershell|zsh>`: print a shell completion script.
- `dent8 hook native-memory-guard`: provider hook helper for session verification and
  native memory/rules write guards.
- `dent8 schema postgres`: print the initial Postgres schema.
- `dent8 mcp serve`: expose read/audit tools, the full belief surface, resources, and
  JSON-RPC batches to agents over MCP (stdio JSON-RPC), with `structuredContent` fields
  for accepted/rejected/contested decisions, accepted event hashes, and integrity receipts.
- `dent8 mcp install --agent <profile> [--dry-run|--check] [--command dent8]`: patch the
  selected agent's MCP config with dent8, write it atomically, and print the resulting file.

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

# The DB-verified Postgres adapter is feature-gated; its integration tests are gated
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
