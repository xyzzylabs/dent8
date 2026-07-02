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
- **Persistence on a pluggable backend**: a local file dev store (default), or a transactional
  async backend selected by `DENT8_STORE_URL` — the **DB-verified Postgres backend**
  (`--features postgres`) or the **embedded SQLite backend** (`--features sqlite`) — each
  committing multi-event operations atomically with concurrent CLI writers auto-retried.
- **Authority layer** (`dent8 authority`): an opt-in source→authority *ceiling* that rejects
  an over-ceiling write before the firewall (deny-by-default once a registry exists). Set
  `DENT8_REQUIRE_AUTHORITY=1` to **fail closed** — a missing registry is an error, not
  permissive dev mode (the `authority` edit commands stay exempt so the registry can be
  bootstrapped).
- **Signed source identity** (`dent8 init --identity`, `dent8 init --agent <profile>`,
  `dent8 identity`): included in the default CLI build. `init --identity` creates or reuses an
  operator issuer key outside the project bundle, then creates a local source key, trust
  registry, grant, and `.dent8/identity.env`; `init --agent` selects a known agent source id
  (`codex`, `claude-code`, `cursor`, `grok-build`, `gemini`, `cascade`, `hecate`) and implies
  identity. `dent8 identity status` checks bundle/trust/active-grant/grant/key/expiry health;
  `dent8 identity repair-env` repairs legacy generated `.dent8/identity.env` /
  `.dent8/active-grants.json` files from the current signed grant without rotating keys; and
  `dent8 identity rotate-source` replaces the active source key and grant at stable paths,
  updates `.dent8/active-grants.json` so old grant+key pairs are rejected, and removes the old
  private source-key backup after a successful rotation. The lower-level commands still expose
  Ed25519 issuer/source key generation, trusted-issuer registry management, signed source
  grants, grant verification, and write-boundary source-key possession checks for CLI/MCP
  writes. Identity fails closed when
  configured in a `--no-default-features` build, when identity material points at a missing
  trust registry, when the grant source/key/scope does not match the write, or when the write
  exceeds the grant's authority ceiling ([ADR 0012](docs/decisions/0012-signed-source-identity.md)).
- **Witness** (`dent8 witness`, `--features witness`): Ed25519 signed tree heads with
  `keygen` / `sign` / `verify` / `verify-published` / `head` / `publish` / `serve` (cadence
  signer) to detect a history rewrite or event-log rollback against locally witnessed or
  externally published heads; externally retained heads keep that evidence available even if
  the local witness log is rolled back. `publish` appends the latest head idempotently and
  refuses to publish behind an existing external sequence. `doctor <writer|signer|both>` role
  checks help operated setups verify that writer/agent/MCP envs have only verifier material
  while the signer holds the private key. `examples/witness/demo.sh` runs the writer/signer/
  monitor split end to end and proves an externally published head rejects event-log rollback.
- **Evidence-dependency edges + retraction taint** (ADR 0010): `dent8 derive` records a
  claim→claim derivation; `dent8 verify` flags a believed claim deriving from a
  retracted/expired source ("poison does not survive in derivatives").
- **Operator surfaces**: `dent8 verify` (integrity check — real stored-chain re-verification
  on Postgres), `dent8 facts list` (known fact streams, with diagnostic streams hidden by
  default), `dent8 conflicts` (contested facts), and `dent8 eval` (the self-demonstrating
  adversarial benchmark: firewall vs a recency-only baseline).
- **Adoption and CLI ergonomics**: `dent8 init` creates a project-local env file, authority
  registry, selected store profile, and optionally the signed identity bundle; `dent8 doctor
  [--write-check]` diagnoses the binary, store, authority, signed identity when configured,
  MCP availability, verification, and an optional trusted write path. `dent8 init --agent
  <profile> --install-mcp` and `dent8 mcp install --agent <profile>` patch/show known agent
  MCP configs from the generated `.dent8` env files, preserving unrelated config; dry-run/check
  modes make setup scripts reviewable and idempotent. `dent8 doctor --agent <profile>` validates
  the generated bundle/config and smokes the installed MCP command/args/cwd/env with
  `initialize` + `tools/list`, with a bounded timeout; with `--repair`, it repairs stale
  generated identity env and refreshes the installed MCP config before checking it; with
  `--write-check`, it runs the acceptance probe through that installed MCP server using
  internal diagnostic fact streams that normal fact/resource browsing hides by default. `dent8 agent
  add --agent <profile>` adds a second agent to an existing shared SQLite/Postgres-backed bundle
  by creating/reusing its signed identity, authority ceiling, and MCP config while refusing
  file-dev bundles. `--mcp-local-bin` / `mcp install --local-bin` writes and verifies a
  repo-local `.dent8/bin/dent8` wrapper around a prebuilt `.dent8/target-sqlite/debug/dent8`,
  avoiding Cargo during MCP startup while letting doctor warn about stale local binaries. The CLI now
  uses `clap` with named write arguments, targeted usage errors, global
  `--color auto|always|never`, machine-readable `--output json` for `explain`, `replay`,
  `facts list`, `verify`, `conflicts`, `eval`, and `doctor`, `--version`, and
  `dent8 completions <bash|elvish|fish|powershell|zsh>`.
- **MCP server** (`dent8 mcp serve`): the full belief surface as stdio JSON-RPC tools +
  readable resources, through the same firewall ([examples/mcp/](examples/mcp/)). Adds
  **read/audit tools** (`list_facts`, `verify`, `conflicts`) and **server `instructions`** in
  the `initialize` response that tell MCP-aware agents to inspect dent8 before relying on
  durable facts and to treat rejected writes as safety signals. Tool definitions advertise
  `outputSchema`, and tool calls return both human-readable `content` and stable
  `structuredContent` receipts/rejection fields so agents do not have to parse prose.
- **Client integration examples**: ready-to-adapt MCP setup for Claude Code, Codex, Cursor,
  Gemini CLI, Devin/Cascade, Grok Build, Hecate, LangChain, and the Vercel AI SDK
  ([examples/](examples/)) — each with a distinct source id where applicable and
  `DENT8_REQUIRE_AUTHORITY`, validated by integration/example tests. Optional hook guard
  examples and the built-in `dent8 hook native-memory-guard` help prevent provider-native
  memory/rules files from bypassing dent8.
- **Analytical/export lane** (`dent8 export`, `--features export`): writes the whole log —
  file *or* Postgres — to flattened columnar Parquet (one row per event, with stable scalar
  columns, a `value_kind` discriminator, `DerivedFrom` dependency edges as a list column, and
  the full event retained as JSON), queried directly by DuckDB for forensics/audit/replay
  ([examples/duckdb/](examples/duckdb/)). Read-only export; the log stays the source of truth.
- **Verification**: hash chain + symmetric/asymmetric anchors, exhaustive authority-lattice
  tests, property-based + robustness proptests, golden replay fixtures, `#[cfg(kani)]` proof
  harnesses (run manually), structured MCP schema tests, CI coverage for Postgres/SQLite and
  feature combinations, and the adversarial corpus.

### Fixed

- `dent8 doctor --agent` and MCP smoke/write checks now scrub `DENT8_ACTIVE_GRANTS` from the
  parent environment before applying the generated agent bundle, preventing stale active-grant
  registries from leaking into subprocess diagnostics.
