# Changelog

All notable changes to dent8 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

dent8 is pre-1.0: the event format, hash-chain encoding, and APIs may change between
minor versions. See [docs/STATUS.md](docs/STATUS.md) for what is built versus designed.

## [Unreleased]

### Added
- **Local Unix-socket MCP daemon with per-connection identity**
  ([ADR 0018](docs/decisions/0018-local-daemon-and-per-connection-identity.md)): `dent8 mcp
  serve --daemon [--socket <path>]` serves the same JSON-RPC belief surface over a per-user
  Unix-domain socket (default `$XDG_RUNTIME_DIR/dent8/dent8.sock`, `0700` dir + `0600` socket;
  a `$TMPDIR` fallback where `$XDG_RUNTIME_DIR` is unset, e.g. macOS), so many agents share one
  belief base over one transport instead of one server per agent. Each connection dispatches
  through the **exact same firewall path** as stdio and is refused unless the peer runs as the
  same OS user. A connection **proves its source identity** before it may write: `dent8/hello`
  presents the grant; the daemon verifies it and issues a single-use, 30-second,
  connection-scoped nonce; `dent8/prove` returns an Ed25519 signature over a domain-separated
  `dent8.session-challenge.v1` challenge binding the nonce + source + grant. Only then are the
  connection's writes accepted — and they are **attested server-side as that source** (ADR 0013
  unchanged), so a daemon-written event re-verifies offline exactly like a CLI write; a
  connection that has not proven identity is read-only and a stray write fails closed rather than
  borrowing the daemon's own identity. Zero new dependencies (reuses the tokio bridge that SQLite
  already pulls in). Internally, identity threads through the write path as a `WriteIdentity` seam
  (byte-identical for the CLI/stdio path). Setting **`DENT8_DAEMON_SOCKET`** makes the CLI's own
  writes route through a running daemon at that socket — the CLI does the handshake with its
  `DENT8_GRANT`/`DENT8_IDENTITY_KEY` and the daemon attests the write — so several agents (and the
  CLI) dogfood one shared belief base on a box. Reads stay local; output is identical to a local
  write. `dent8 doctor` reports the daemon's reachability + handshake when `DENT8_DAEMON_SOCKET`
  is set, and [examples/daemon/](examples/daemon/) is a runnable walkthrough.
- **Freshness on the list surfaces** (threat-model T4): `dent8 facts list`, the MCP
  `list_facts` tool, and `resources/list` now flag each fact stream's freshness
  (`fresh`/`stale`/`not_yet_valid`/`no_longer_believed`) from a single store load — a stale
  fact is visible in the summary without reading each one. Text gains a `[stale]`-style
  marker; JSON/structured output and the `list_facts` schema gain a `freshness` field; the
  resource name/description carry it. Closes the last T4 read-surface residual.
- **`derive` valid-time interval** (ADR 0016): `dent8 derive` and the MCP `derive` tool take
  optional `--valid-from`/`--valid-to`, stamping the derived assertion — completing the
  valid-time write surface (assert/supersede/contradict/derive all carry it).
- **Unearned-supersession advisories in `verify`**
  ([ADR 0017](docs/decisions/0017-survived-challenges-in-arbitration.md)): `dent8 verify`
  now surfaces `EntityProjection::unearned_supersessions` (previously computed but wired into
  nothing) as **advisories** — a supersession admitted by the base firewall whose replacement
  did not out-entrench the incumbent. Advisory, not a failure (enable
  `DENT8_ENTRENCHMENT_GATE` to reject at write time); `verify` stays `OK`, and `--output
  json` gains an `advisories` array.
- **MCP validity + time-travel arguments** (ADR 0016): the `assert`/`supersede`/`contradict`
  MCP tools take optional `valid_from`/`valid_to`, and `explain`/`replay` take optional
  `as_of`/`valid_at` — the same valid-time interval and time-travel reads the CLI has, now
  through the tool surface (schemas advertise them; a non-integer value is a tool error).
- **Not-yet-valid `valid_from`** (ADR 0016): read-time freshness now bounds the full window
  `[valid_from, expires_at)`. A fact whose `valid_from` is in the future reads **not yet
  valid** (`fresh=false`, `not_yet_valid=true`, headline `[not yet valid]`) rather than fresh;
  the receipt gains `not_yet_valid` + `valid_from`, and an elapsed `valid_to`/TTL now reads
  `[stale — no longer valid]` (accurate — no longer the misleading "TTL elapsed").

- **Survived challenges feed arbitration**
  ([ADR 0017](docs/decisions/0017-survived-challenges-in-arbitration.md)): the opt-in
  earned-supersession gate (`DENT8_ENTRENCHMENT_GATE=1`) and the entity-level
  unearned-supersession audit now weigh **earned entrenchment** = authority-weighted
  corroboration + survived challenges (both Sybil-resistant). A fact that survived an
  equal-authority challenge (ADR 0015) resists the next fresh equal-authority replacement —
  protection derived from challenge-survival. No `CANON_VERSION` bump (the new
  `ChallengeRejection::WeakerEntrenchment` reason is additive; the old `WeakerCorroboration`
  still deserializes). `dent8-store` renames the computed audit finding
  `UnearnedSupersession::WeakerCorroboration` → `WeakerEntrenchment` (a non-serialized API
  type).

## [0.2.0] - 2026-07-03

### Added

- **Grant history + revocation** ([ADR 0014](docs/decisions/0014-grant-history-and-revocation.md)):
  an append-only, issuer-signed, hash-chained grant log in the identity bundle
  (`grant-log.jsonl`, `DENT8_GRANT_LOG`). Grant lifecycle commands (`init --identity`,
  `bootstrap`, `rotate-source`, `agent add`) record `issued`/`revoked` history (a rotation
  lands revoked+issued as one write); the new `dent8 identity revoke` ends trust in a source
  **without** a replacement (the missing compromise response — the write path then fails
  closed for that source), and `dent8 identity backfill-grant-log` seeds records for grants
  that predate the log (explicitly stamped *now*, never backdated). `dent8 verify` now
  resolves each attested event's **entitlement at write time** — entitled / unentitled
  (an integrity failure) / unknown (no history, reported honestly) — so rotation no longer
  destroys the evidence needed to audit old writes. `identity status`/`doctor` gain a
  grant-log consistency line. The **witness now covers the grant log** too: `sign`
  appends a signed grant-log head and `serve` signs one whenever the grant log's
  `(count, head)` changes (into `DENT8_WITNESS_GRANTS_LOG`), and `witness verify` detects a
  truncated revocation as ROLLBACK — closing the ADR's named residual. The low-level
  `grant-issue` appends to the history only when `DENT8_GRANT_LOG` is configured and prints
  an explicit note otherwise.
- **Published grant-log heads**: `witness publish`/`verify-published` take
  `--grants <published-grants.jsonl>` to retain signed grant-log heads outside the writer's
  control, with the event lane's exact semantics (idempotent republish, ROLLBACK/CONFLICT on
  a regressed or mismatched external sequence) — a writer who scrubs a revocation *and*
  deletes the local grants-witness file is still caught by the published copy. `publish`
  without `--grants` says so when a grants-witness log exists instead of silently
  half-covering; JSON output gains a `grants` object on both commands.

- **`witness serve` NDJSON**: the cadence signer now supports `--output json`, streaming one
  compact JSON line per event — signed heads on stdout (`event: "head_signed"`, `lane:
  "events" | "grants"`), lifecycle on stderr (`started` / `warning` / `error` / `stopped`) —
  so the operated signer's logs are machine-parseable. `witness sign --output json` gains a
  structured `grant_log_head` field. Exit codes unchanged.
- **Hook contract**: the `dent8 hook native-memory-guard` exit-code contract is now written
  down (examples/agent-hooks/README.md) and pinned by tests — mode x condition -> exit code,
  the stdout-always-empty invariant (providers interpret hook stdout), the bypass flag, and
  the audit/session verify paths.

- **Survived-challenge recording + earned-supersession gate**
  ([ADR 0015](docs/decisions/0015-survived-challenge-recording.md)): a challenge the
  firewall rejects on strength (insufficient/laundered authority, the canonical
  hard-alarm) is now recorded on the incumbent's stream as a `claim.challenge_rejected`
  event — with the *challenger's* provenance and effective authority, so under signed
  identity the attack attempt carries the attacker's own attestation. `ClaimState` gains
  Sybil-resistant `survived_challenges` (the "attacked and stood" half of earned
  entrenchment); `explain`/MCP receipts report the count; `replay` shows each survival.
  Recording is on by default (`DENT8_RECORD_CHALLENGES=0` opts out). The
  `WeakerCorroboration` audit is now enforceable at write time via the opt-in
  earned-supersession gate (`DENT8_ENTRENCHMENT_GATE=1`). Logs containing the new event
  kind need this version to read; existing events, hashes, and golden fixtures are
  unchanged (no canon bump).

- **Valid-time intervals + time-travel reads**
  ([ADR 0016](docs/decisions/0016-valid-time-and-time-travel-reads.md)): `assert` /
  `supersede` / `contradict` take `--valid-from` / `--valid-to` (unix millis) — a fact can
  assert *when it stops holding*, and reads treat an elapsed `valid_to` exactly like an
  elapsed TTL (`expires_at` is the earliest bound; an inverted interval is rejected).
  `explain` / `replay` take `--as-of` (fold only events recorded at or before an instant —
  the store as it stood then) and `--valid-at` (judge freshness at an instant instead of
  now); they compose into "what did we believe, and was it fresh, last Tuesday". `valid_to`
  is an optional field under the ADR 0013 rule — existing events, hashes, and golden
  fixtures unchanged.

## [0.1.0] - 2026-07-03

The first release: the complete v0 surface as developed on `main`.

### Added

- **Firewall + lifecycle**, enforced at the write boundary (`EventStore::append`):
  authority-weighted supersession/retraction **and explicit-expiration** arbitration
  (expiration is authority-gated like retraction — [ADR 0011](docs/decisions/0011-authority-gated-expiration.md);
  TTL staleness stays a separate read-time predicate), an anti-laundering challenger
  check, the canonical-contradiction hard-alarm, and per-predicate policy (the coding-agent
  registry). Runnable as `assert` / `supersede` / `retract` / `contradict` / `reinforce` /
  `expire` / `explain` / `replay`.
- **Persistence on a pluggable backend**: a local file dev store (default), or a transactional
  async backend selected by `DENT8_STORE_URL` — the **embedded SQLite backend** (included in
  the stock build) or the **DB-verified Postgres backend** (`--features postgres`) — each
  committing multi-event operations atomically with concurrent CLI writers auto-retried.
- **Authority layer** (`dent8 authority`): an opt-in source→authority *ceiling* that rejects
  an over-ceiling write before the firewall (deny-by-default once a registry exists). Set
  `DENT8_REQUIRE_AUTHORITY=1` to **fail closed** — a missing registry is an error, not
  permissive dev mode (the `authority` edit commands stay exempt so the registry can be
  bootstrapped).
- **Signed source identity** (`dent8 init --identity`, `dent8 init --agent <profile>`,
  `dent8 identity`): included in the default CLI build. `init --identity` creates or reuses an
  operator issuer key outside the project bundle, then creates a local source key, trust
  registry, grant, and `.dent8/identity-<source>.env`; `init --agent` selects a known agent source id
  (`codex`, `claude-code`, `cursor`, `grok-build`, `gemini`, `cascade`, `hecate`) and implies
  identity. `dent8 identity status` checks bundle/trust/active-grant/grant/key/expiry health;
  `dent8 identity repair-env` repairs generated `.dent8/identity-<source>.env` /
  `.dent8/active-grants.json` files from the current signed grant without rotating keys; and
  `dent8 identity rotate-source` replaces the active source key and grant at stable paths,
  updates `.dent8/active-grants.json` so old grant+key pairs are rejected, and removes the old
  private source-key backup after a successful rotation. The lower-level commands still expose
  Ed25519 issuer/source key generation, trusted-issuer registry management, signed source
  grants, grant verification, and write-boundary source-key possession checks for CLI/MCP
  writes. Every accepted write now carries a persisted **signed write attestation**
  (`provenance.attestation`, [ADR 0013](docs/decisions/0013-signed-write-attestation.md)):
  an Ed25519 signature by the source key over the event content, re-verified by
  `dent8 verify` — on the file dev store this detects a content edit to an attested event,
  which previously required a witness. Identity fails closed when
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
  while the signer holds the private key. The operated split is **packaged**:
  [`examples/witness-operated/`](examples/witness-operated/) runs signer / publisher /
  monitor as separate Docker Compose services over a shared Postgres store (built from the
  repo [`Dockerfile`](Dockerfile), CI-built and smoked), with hardened systemd units for
  bare-metal hosts; the monitor alerts by exiting non-zero on a `tamper`/`rollback` verdict.
  Finite witness subcommands support `--output json`
  for CI/monitors, with `doctor` grouped into stable `ok` / `warn` / `fail` sections.
  `examples/witness/demo.sh` runs the writer/signer/monitor split end to end and proves an
  externally published head rejects event-log rollback.
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
  avoiding Cargo during MCP startup while letting doctor warn about stale local binaries.
  Optional doctor probes that are not requested are reported as `SKIP`, not `WARN`, and
  `doctor --output json` includes stable `ok` / `warn` / `fail` / `skip` sections. Finite
  witness subcommands now emit structured JSON for monitors and CI. The CLI now
  uses `clap` with named write arguments, targeted usage errors, global
  `--color auto|always|never`, machine-readable `--output json` for write commands,
  `explain`, `replay`, `facts list`, `verify`, `conflicts`, `eval`, `init`, `authority`,
  `agent add`, all `identity` subcommands, `doctor`, `completions`, `export`, `witness`,
  `schema postgres`, and `mcp install`, `--version`, and
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
  harnesses (run manually), structured MCP schema tests, libFuzzer targets over the
  deserialize→fold→canonicalize path and `CanonicalJson` idempotency (`fuzz/`, with a bounded
  CI smoke), a committed SQLite concurrent-writers regression test, CI coverage for
  Postgres/SQLite and feature combinations, and the adversarial corpus.
- **Format stability**: security artifacts — signed grants, the trust / active-grant /
  authority registries, and witness signed tree heads — **reject unknown fields**
  (`deny_unknown_fields`), so an unknown key in a security file fails loudly as corrupt
  rather than being silently ignored (unsigned noise at best, tampering at worst). The event
  model deliberately stays lenient under the
  [ADR 0013](docs/decisions/0013-signed-write-attestation.md) optional-field rule (a later
  `valid_to`-style field is a free, hash-stable addition), and event ids stay opaque validated
  strings (a future DB-assigned id scheme needs no format change) — so the event format is
  frozen for the first release.

