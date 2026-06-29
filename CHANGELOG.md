# Changelog

All notable changes to dent8 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches a tagged release.

dent8 is pre-1.0: the event format, hash-chain encoding, and APIs may change. See
[docs/STATUS.md](docs/STATUS.md) for what is built versus designed.

## [Unreleased]

The runnable surface and library as they stand on `main` (no tagged release yet).

### Added

- **Firewall + lifecycle**, enforced at the write boundary (`EventStore::append`):
  authority-weighted supersession/retraction **and explicit-expiration** arbitration
  (expiration is authority-gated like retraction — [ADR 0011](docs/decisions/0011-authority-gated-expiration.md);
  TTL staleness stays a separate read-time predicate), an anti-laundering challenger
  check, the canonical-contradiction hard-alarm, and per-predicate policy (the coding-agent
  registry). Runnable as `assert` / `supersede` / `retract` / `contradict` / `reinforce` /
  `expire` / `explain` / `replay`.
- **Persistence on either backend**: a local file dev store (default) or the **DB-verified
  transactional Postgres backend** (`--features postgres`, `DENT8_DATABASE_URL`), with each
  multi-event operation committed atomically and concurrent CLI writers auto-retried.
- **Authority layer** (`dent8 authority`): an opt-in source→authority *ceiling* that rejects
  an over-ceiling write before the firewall (deny-by-default once a registry exists). Set
  `DENT8_REQUIRE_AUTHORITY=1` to **fail closed** — a missing registry is an error, not
  permissive dev mode (the `authority` edit commands stay exempt so the registry can be
  bootstrapped).
- **Witness** (`dent8 witness`, `--features witness`): Ed25519 signed tree heads with
  `keygen` / `sign` / `verify` / `head` / `serve` (cadence signer) to detect a history
  rewrite or rollback.
- **Evidence-dependency edges + retraction taint** (ADR 0010): `dent8 derive` records a
  claim→claim derivation; `dent8 verify` flags a believed claim deriving from a
  retracted/expired source ("poison does not survive in derivatives").
- **Operator surfaces**: `dent8 verify` (integrity check — real stored-chain re-verification
  on Postgres), `dent8 conflicts` (contested facts), and `dent8 eval` (the self-demonstrating
  adversarial benchmark: firewall vs a recency-only baseline).
- **MCP server** (`dent8 mcp serve`): the full belief surface as stdio JSON-RPC tools +
  readable resources, through the same firewall ([examples/mcp/](examples/mcp/)). Adds
  **read/audit tools** (`list_facts`, `verify`, `conflicts`) and **server `instructions`** in
  the `initialize` response that tell MCP-aware agents to inspect dent8 before relying on
  durable facts and to treat rejected writes as safety signals.
- **Client integration examples**: ready-to-adapt MCP setup for Claude Code, Codex, Cursor,
  Grok Build, and Hecate ([examples/](examples/)) — each with a distinct source id and
  `DENT8_REQUIRE_AUTHORITY`, validated by an integration test (`agent_integrations.rs`).
- **Analytical/export lane** (`dent8 export`, `--features export`): writes the whole log —
  file *or* Postgres — to flattened columnar Parquet (one row per event, with the `DerivedFrom`
  dependency edges materialized), queried directly by DuckDB for forensics/audit/replay
  ([examples/duckdb/](examples/duckdb/)). Read-only export; the log stays the source of truth.
- **Verification**: hash chain + symmetric/asymmetric anchors, exhaustive authority-lattice
  tests, property-based + robustness proptests, golden replay fixtures, `#[cfg(kani)]` proof
  harnesses (run manually), and the adversarial corpus.
