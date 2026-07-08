# Changelog

All notable changes to dent8 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

dent8 is pre-1.0: the event format, hash-chain encoding, and APIs may change between
minor versions. See [docs/STATUS.md](docs/STATUS.md) for what is built versus designed.

## [Unreleased]

### Added
- Added `dent8 snapshot` and the MCP `snapshot` read/audit tool: one stable
  debugger/control-plane payload combining runtime status, fact streams, integrity verify,
  conflicts, and summary counts, with `--include-diagnostics` parity with `facts list`.
- Added a local dogfood workflow (`docs/dogfood.md` and `examples/dogfood/demo.sh`) that
  validates this repo's real `.dent8` setup: durable facts, signed identity, low-authority
  rejection, witness coverage, and installed-agent doctor checks.
- `dent8 doctor --agent` now prints the live MCP server version and binary path after
  `runtime_status` succeeds, and warns when that server version differs from the doctor
  binary so stale globally installed or repo-local MCP commands are visible without digging
  into JSON.
- Added `examples/witness-operated/demo.sh`, a live Docker Compose E2E that starts the
  signer/publisher/monitor split, publishes a signed head for one Postgres-backed write, then
  deletes `dent8_event_log` and confirms the monitor exits on a rollback alarm.
- Added a manual `workflow_dispatch` CI job for the live operated-witness rollback demo, so
  maintainers can regression-test the full Compose signer/publisher/monitor split on demand.

### Changed
- Refreshed the README firewall GIF/tape: the walkthrough now starts with a clearer headline,
  supports opt-in reader pauses via `DENT8_DEMO_PAUSE`, and keeps the final witness caveat on
  its own readable line.
- Updated the Docker CI actions to their Node 24 releases (`docker/setup-buildx-action@v4`
  and `docker/build-push-action@v7`) to remove the GitHub Actions Node 20 deprecation
  annotation.

### Security
- Hardened the operated-witness compose recipe: the private witness signing key now lives on a
  signer-only volume, while the publisher mounts only the witness logs and public key
  read-only before writing to the external published-heads volume.

## [0.3.2] - 2026-07-06

### Added
- Added daemon-proxy install modes for known agent configs: `dent8 mcp install --use-daemon`
  / `--daemon-socket PATH`, plus `dent8 init --mcp-use-daemon` /
  `--mcp-daemon-socket PATH` and matching `dent8 agent add` flags. These write `dent8 mcp
  proxy` argv into the MCP config so stdio-only clients can use a running local daemon.
- `dent8 doctor --agent` now recognizes installed `dent8 mcp proxy` configs, preflights the
  target daemon socket with the config's own signed identity env, reports an explicit daemon
  start hint when the socket is unreachable, and skips the MCP write-check when smoke already
  failed.
- Added `dent8 daemon status [--socket PATH]` and `dent8 daemon serve [--socket PATH]` as the
  human-facing local daemon surface. `daemon status` probes the socket with read-only
  `runtime_status`, then verifies write authentication when `DENT8_GRANT` and
  `DENT8_IDENTITY_KEY` are set.

### Fixed
- Hardened async-backend CLI/MCP writes under concurrent processes: SQLite and Postgres now
  reserve event-id ranges at the backend boundary before signing, so competing writers do not
  mint the same `event:{n}` from stale snapshots. Regression coverage now includes concurrent
  CLI writer tests for embedded SQLite and live Postgres.

## [0.3.1] - 2026-07-06

### Added
- Added `dent8 doctor --all-agents`, which checks every installed known agent profile in a
  `.dent8` bundle, skips profiles without a source-bound install, aggregates failures, and emits
  per-agent reports under `agents[]` in `--output json`.
- `dent8 doctor --agent --output json` now includes a structured `mcp_runtime` object with
  the MCP smoke status, human message, and the live `runtime_status` payload when the server
  answered, so agents and CI can detect stale store/source wiring without parsing prose.
- `dent8 doctor --agent` now calls the MCP `runtime_status` tool during its smoke check and
  fails when the installed server starts against a different store or source than the agent
  bundle declares.
- Added a read-only MCP `runtime_status` tool that reports the live server binary, cwd,
  selected store URL/path, event count, authority registry, signed identity, and witness
  configuration before an agent trusts project memory.
- Added a v0.3 upgrade note covering the format-v2 break, re-ingestion path, and
  MCP/JSON automation changes.
- Hardened the operated witness recipe so its packaged publisher/monitor retain and verify
  grant-log heads with `--grants` when signed identity is in use.
- Added a local daemon example README and clarified that daemon writes are authenticated by
  `dent8/hello`/`dent8/prove` while each daemon process remains single-source.
- Added `dent8 native scan --agent <profile>` as a read-only audit of provider-native
  memory/rules files, with size/hash/mtime, receipt-marker detection, and guard posture.
- Added `dent8 native reconcile --agent <profile>` to verify `dent8://<kind>/<key>/<predicate>`
  references in native files against the current dent8 receipt, flagging stale, contested,
  missing, no-longer-believed, or malformed references.
- Exposed the native audits to agents over MCP as read-only `native_scan` and
  `native_reconcile` tools with advertised output schemas and the same receipt-reconciliation
  path as the CLI.
- Accepted the future desktop direction in ADR 0020: a TypeScript/Tauri debugger/control
  plane over the existing CLI/MCP/daemon integrity boundary, not a separate memory provider or
  write path.

## [0.3.0] - 2026-07-06

### Changed (breaking)
- **`fact` vocabulary + event format v2.** The central concept is now **fact** everywhere — the
  library types (`ClaimEvent` → `FactEvent`, `ClaimState` → `FactState`, `ClaimValue` →
  `FactValue`, `ClaimId` → `FactId`, `ClaimEventId` → `FactEventId`, `ClaimEventKind` →
  `FactEventKind`, `ClaimLifecycle` → `FactLifecycle`; and separately `EntityRef` → `Subject`),
  the methods (`load_claim_events` → `load_fact_events`, `replay_claim` → `replay_fact`,
  `believed_claim_ids` → `believed_fact_ids`), and the **on-disk event format**: the field
  `claim_id` → `fact_id`, fact ids are `fact:…` (was `claim:…`), and `authority` is lowercase
  (`"high"`, not `"High"`) so it round-trips with the `--authority high` you type. `CANON_VERSION`
  is bumped to **2**; every event's hash therefore changes, so a v1 log **does not verify against
  this build** and must be re-ingested from source (there is no in-place migration). This
  withdraws the pre-1.0 format-stability promise for this one break; from v2 onward the intent is
  additive-only again.
- **CLI belief-surface `status` now mirrors MCP.** The `--output json` `status` field on the CLI
  reports the same value the MCP tool does for the same operation: a write reports `accepted`
  (`contradict` reports `contested`) instead of the old generic `ok`; `verify` reports
  `integrity_issues` (not `failed`) when the hash chain is broken; and `explain` reports
  `contested` for a disputed fact. The `accepted` boolean on write output is unchanged. A
  consumer that keyed on the CLI's old `status: "ok"` for a successful write must read `accepted`
  / `contested` (or the `accepted` boolean) instead.
- **MCP tools take one `subject` string, and `derive` takes `basis`.** The MCP write/read tools
  now take a single `subject` argument as `"kind:key"` (e.g. `repo:myproj`) instead of separate
  `subject_kind` + `subject_key`, mirroring the CLI's `person:alice` grammar exactly. `derive`'s
  source fact is now `basis` (`"kind:key"`) + `basis_predicate` instead of
  `from_kind`/`from_key`/`from_predicate`, and the **CLI `derive --from` flag is renamed
  `--basis`**. Tool result shapes are unchanged (`subject` stays a `{kind, key}` object on output).
  An MCP client or script must send `subject`/`basis` string arguments; a CLI `derive` invocation
  must use `--basis`.
- **`--output json` errors now print to stdout, not stderr.** Every command's `--output json`
  result — success and error alike — goes to **stdout** as one object (the nonzero exit code still
  signals failure), so a machine consumer reads a single stream instead of merging stdout and
  stderr. Previously most commands wrote error JSON to stderr while `verify` alone used stdout. A
  consumer that read error JSON from stderr must read stdout. The `--output json` allow-list is
  also gone: every command is machine-readable except `mcp serve` (the JSON-RPC server itself) and
  `hook` (a git-hook filter), which still exit 2 with a short note; a newly added command is
  JSON-capable by default.

### Added
- **`doctor --agent` reports native-memory bypass posture.** For checked hook profiles (Codex,
  Claude Code, Gemini, Cascade), doctor now inspects the expected hook config and reports OK only
  when `dent8 hook native-memory-guard` is present in enforced write-guard mode. Missing/advisory
  hooks are WARNs; Cursor, Grok Build, and Hecate report WARN/unknown because their hook surfaces
  are host-specific.
- **Signed identity defaults for CLI/MCP writes.** When `DENT8_GRANT` is configured, CLI and
  stdio MCP write commands can omit `--source` and/or `--authority`: dent8 defaults them from the
  active grant's source and maximum authority, then runs the same authority-ceiling, grant, and
  source-key possession checks before appending anything. Authenticated daemon connections use the
  same defaults from their proven connection identity. Explicit fields still work and still have to
  satisfy the signed identity policy.
- **`schema_version` on every machine payload.** Each `--output json` object and every MCP
  `structuredContent` now carries a top-level `schema_version` (currently `1`) from one shared
  constant, so a consumer can branch when the (still pre-1.0) output shape changes. The MCP tools'
  advertised `outputSchema` requires it on both result arms.
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
  now surfaces `SubjectProjection::unearned_supersessions` (previously computed but wired into
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
  earned-supersession gate (`DENT8_ENTRENCHMENT_GATE=1`) and the subject-level
  unearned-supersession audit now weigh **earned entrenchment** = authority-weighted
  corroboration + survived challenges (both Sybil-resistant). A fact that survived an
  equal-authority challenge (ADR 0015) resists the next fresh equal-authority replacement —
  protection derived from challenge-survival. No `CANON_VERSION` bump (the new
  `ChallengeRejection::WeakerEntrenchment` reason is additive; the old `WeakerCorroboration`
  still deserializes). `dent8-store` renames the computed audit finding
  `UnearnedSupersession::WeakerCorroboration` → `WeakerEntrenchment` (a non-serialized API
  type).

### Documentation
- **Clarified bypass resistance.** The README, threat model, and agent-adapter guide now
  distinguish dent8's enforced write boundary from system-level sandboxing: dent8 prevents
  silent corruption on CLI/MCP/daemon/`EventStore::append` paths, while same-user direct writes
  to provider-native memory or raw storage require hook guards, least-privilege store access,
  verification, and witness publication.

### Changed
- **`identity` and `witness` are no longer Cargo features — they are always compiled.** Signed
  source identity is core to the threat model and `witness` reuses the same Ed25519 crypto, so
  gating them bought ~0 on a default build (identity was already in `default`) while costing 90+
  `#[cfg(feature = …)]` sites and the fail-closed stub paths. Removing the features deletes all of
  that, adds ~0.3 MiB to the stock binary (identity was already included; witness is the delta),
  and makes the identity/witness tests run in the *default* `cargo test`. **Breaking for build
  invocations:** `--features identity` / `--features witness` no longer exist (they error), and a
  `--no-default-features` build now still includes identity + witness (it only drops the
  SQLite/async backend down to the file store). Backends stay opt-in: `postgres` (+3.7 MiB) and
  `export` (+5.3 MiB) carry real weight, so they remain features.
- **`witness` is now real clap subcommands.** `dent8 witness <keygen|sign|verify|verify-published|
  head|publish|serve|doctor>` are parsed like every other command instead of a hand-rolled
  catch-all, so `witness` gets real `--help`, `--output json` works in any position (including
  after the subcommand, via global-flag propagation), and unknown subcommands get clap's own
  diagnostics. The grammar is unchanged (`--grants`, `doctor <writer|signer|both>` with the
  `verifier`/`local` aliases, `serve [interval] [max-heads]`), so existing invocations keep
  working.

### Fixed
- **`conflicts --output json` reported `status: "ok"` while listing live disputes.** A non-empty
  result now reports `status: "contested"` (an empty one still reports `ok`), so a machine
  consumer's `status` check and the `count`/`conflicts` array agree. The MCP `conflicts` tool was
  already correct; this aligns the CLI with it. The CLI and MCP belief surfaces now draw every
  `status` string from one shared `Status` enum, so the two cannot drift on the spelling a
  consumer branches on.

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
  hard-alarm) is now recorded on the incumbent's stream as a `fact.challenge_rejected`
  event — with the *challenger's* provenance and effective authority, so under signed
  identity the attack attempt carries the attacker's own attestation. `FactState` gains
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
- **Witness** (`dent8 witness`): Ed25519 signed tree heads with
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
  fact→fact derivation; `dent8 verify` flags a believed fact deriving from a
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
