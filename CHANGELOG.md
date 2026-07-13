# Changelog

All notable changes to dent8 are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

dent8 is pre-1.0: the event format, hash-chain encoding, and APIs may change between
minor versions. See [docs/STATUS.md](docs/STATUS.md) for what is built versus designed.

## [Unreleased]

### Added
- **First-class TypeScript tools for the Vercel AI SDK and LangChain.js** (`dent8/ai`,
  `dent8/langchain`; roadmap: framework adapters). The `npm i dent8` package now exports
  native tool objects built on the SDK — `dent8Tools({ source, authority })` returns
  `dent8_record_fact` / `dent8_revise_fact` / `dent8_dispute_fact` / `dent8_explain_fact` /
  `dent8_list_facts` / `dent8_verify` as Vercel AI SDK tools (keyed by name) or LangChain.js
  `StructuredTool`s — no MCP subprocess to keep in sync. As with the Python toolkit, the tools
  expose *what* to record (subject, predicate, value); **source and authority are deployment
  configuration, not LLM arguments**, so an agent wired at `authority: "low"` cannot escalate
  its own authority, and a refused write comes back as a tool result it reads and adapts to.
  `ai` / `@langchain/core` are optional peer dependencies (the SDK core stays
  zero-dependency); a framework-agnostic `dent8/tools` (`dent8ToolSpecs`) covers any other
  framework. Tested against the real binary + both frameworks in CI.
- **First-class LangChain tools** (`dent8.langchain`, `pip install "dent8[langchain]"`;
  roadmap: framework adapters). Native LangChain `StructuredTool`s over the belief surface,
  built on the `dent8` SDK — no MCP subprocess, typed args: `dent8_tools(source=…,
  authority=…)` returns `dent8_record_fact` / `dent8_revise_fact` / `dent8_dispute_fact` /
  `dent8_explain_fact` / `dent8_list_facts` / `dent8_verify`. The tools expose *what* to
  record (subject, predicate, value); **source and authority are deployment configuration,
  not LLM arguments**, so an agent wired at `authority="low"` cannot escalate its own
  authority — dent8's thesis at the tool boundary. A refused write comes back as a tool
  result the agent reads and adapts to, not an exception. The SDK core stays
  zero-dependency (the extra is opt-in); tested against the real binary + `langchain-core`
  in CI.
- **HTTP API — MCP-over-HTTP** ([ADR 0019](docs/decisions/0019-http-api-mcp-over-http.md)):
  `dent8 mcp serve --http --port 3369` serves the full MCP JSON-RPC belief surface over HTTP —
  a third transport (after stdio and the Unix-socket daemon) over the **same** `dispatch`
  firewall path, so it cannot drift from the CLI/MCP contract and there is no new write path.
  `POST /` (or `/mcp`) a JSON-RPC message or batch and get the result (`204` for a lone
  notification); the whole surface — `assert`…`derive`, `explain`, `replay`, `list_facts`,
  `conflicts`, `snapshot`, `whatif`, `verify`, `native_*` — is reachable as `tools/call`
  carrying the same `status` / error `code` / `structuredContent`. `curl`-able. Loopback-only
  with an anti-DNS-rebinding `Host` check and a **bearer token** on every non-health request
  (`DENT8_HTTP_TOKEN`, else generated per run and printed on start — it substitutes for the
  daemon's `SO_PEERCRED` guard, which TCP can't do); `GET /healthz` is open. Writes are
  attested with the server's own identity, like stdio serve. Remote multi-tenant identity
  (each client proving its own source key) is a documented deferred follow-up.
- **Predicate volatility now bounds claimable freshness** (roadmap: predicate-level
  volatility policy). The registry's `Volatility` classification was advisory metadata that
  did nothing; it is now functional. A `Volatile` predicate (e.g. `branch.status`,
  `dependency.version`) caps a caller-supplied finite TTL at **7 days**
  (`VOLATILE_RETENTION_CEILING_MS`) — a working belief that changes often cannot be claimed
  *fresh* for months — while a `Stable` predicate keeps the registry-wide 90-day ceiling.
  Precedence: an explicit per-predicate `max_ttl` override wins, then volatility, then the
  global ceiling; the TTL is **rejected, not clamped** (`dent8 assert dependency:serde
  version 1.0 --ttl 30d` → `TtlCeilingExceeded`, ceiling 7 days). Default TTLs and
  `Ttl::Never` are unaffected, so no existing fact's expiry changes.
- **Legitimate-traffic corpus + false-positive rate in `dent8 eval`** (roadmap: legitimate-
  traffic evaluation): the complement of the adversarial corpus. A designed set of benign
  revision sequences (maturing understanding, authority-upgrade correction, corroboration,
  legitimate retraction, disagreement-kept-as-data, serial revisions) runs through the real
  firewall; `dent8 eval` reports how many intended writes it wrongly rejects — currently **0
  false positives across 22 benign writes (7 scenarios)** — with a per-scenario table, in
  both text and `--output json` (`legitimate_traffic`), and gates the exit code on it (any
  false positive is a regression). Frozen as a test. These are designed scenarios; replaying
  real captured agent sessions through the same metric is the post-launch follow-up, blocked
  only on trace data.

## [0.7.2] - 2026-07-12

### Added
- **`dent8 ui` — a local, human-first memory dashboard** (the first deliverable of
  [ADR 0020](docs/decisions/0020-desktop-debugger-control-plane.md), unfrozen): one command
  opens a dashboard in your browser, served straight from the stock binary, designed
  around the belief base rather than the plumbing. Four views:
  - **Memory** (the landing): a headline verdict (*everything verified* / *N contested* /
    *N stale* / *integrity failed*), stat tiles, and the believed facts as cards — the
    value shown large, a freshness color-bar down the side, authority + freshness badges,
    contested facts showing both rival values inline. Click any card for a slide-in drawer
    with the full integrity receipt (authority, hash, chain, corroboration, survived
    challenges, validity window) and the complete replay timeline.
  - **Activity**: every event across the log, newest first (rejected supersessions appear
    as the `fact.challenge_rejected` events recorded on their incumbents).
  - **What-if**: re-fold the log under a different trust policy and see now-vs-under-policy
    with per-fact diffs — deterministic, no model calls.
  - **Health**: a status-page rollup — a healthy/attention banner, integrity/witness/doctor
    status cards, and collapsible detail (doctor checks, witness coverage + TAMPER/ROLLBACK,
    native scan/reconcile per agent profile, and the raw runtime env under *system details*).

  Plus a light/dark toggle, deep-linkable tabs (`#health` etc.), and a click-to-pause live
  poll. Read-only **by construction** — every endpoint is a GET over the same `op_*`/snapshot
  code the CLI and MCP use, so no separate write path exists (the ADR's hard constraint);
  the transport is a minimal hand-rolled HTTP responder over tokio (zero new dependencies)
  that binds 127.0.0.1 only, refuses non-localhost `Host` headers (DNS-rebinding), and
  answers GET only. Fact values are HTML-escaped everywhere — agent-supplied text can never
  execute in the operator's browser. Default port 3368 ("dent" on a phone keypad);
  `--port`/`--no-open` to adjust. The Tauri desktop shell remains the later packaging step
  and will wrap this same surface.

## [0.7.1] - 2026-07-12

### Added
- **Linux and Windows backends for keychain-backed identity keys** — `keychain:<account>`
  now works on all three platforms, same contract as the macOS backend shipped in 0.7.0
  (keygen refuses to overwrite an existing item; the public key derives from the private
  item):
  - **Linux**: through `secret-tool` (libsecret) against any Secret Service implementation
    — GNOME Keyring, KWallet 5.97+ — with the secret passed over stdin, never argv. Needs
    `secret-tool` on `PATH` (`libsecret-tools` on Debian/Ubuntu) and a running, unlocked
    Secret Service; missing pieces produce pointed errors.
  - **Windows**: through the Credential Manager. Windows is the one platform with no
    preinstalled CLI able to read a secret back, so this backend uses the `keyring` crate
    (windows-native only, a Windows-only dependency — macOS/Linux stay subprocess-based and
    dependency-free). A `windows-keychain` CI job lints the CLI for the platform and runs a
    real Credential Manager round trip.
- **[Team identity playbook](docs/team-identity.md)** (roadmap: the key-distribution story):
  what to commit (trust registry, signed grants, active-grant index, grant log — all public
  by construction) versus what never leaves a machine (private keys, ideally
  keychain-backed); onboarding a remote teammate with only their public key traveling;
  rotation, revocation-as-a-PR, CI-bot keys, and clone-side verification. Every command in
  it is exercised against the real binary.

### Fixed
- **`identity repair-env` now works for keys that are not bundle files**: after
  `grant-issue` for a remote teammate (their key never left their machine) or for a
  keychain-backed key, repair-env restores the missing active-grant registry entry from the
  signed grant and honestly skips the env rewrite (it used to hard-fail trying to stat the
  absent key file, leaving no way to register the grant).

## [0.7.0] - 2026-07-11

### Added
- **OS-keychain-backed identity keys** (roadmap: identity productization; macOS in this
  release): `keychain:<account>` is accepted wherever a signing-key path is —
  `DENT8_IDENTITY_KEY`, keygen `--out`, `grant-issue --issuer-key` / `--public-key`,
  `trust-add` — naming a generic-password item under keychain service `dent8` instead of a
  `0600` file. `identity agent-keygen --out keychain:<account>` generates straight into the
  keychain (no file ever exists, the public key is printed and derivable from the private
  item, and an existing item is refused, same as files). This narrows the threat model's
  top residual: the key is encrypted at rest, locks with the session, and never lands in a
  dotfile a backup or homedir sync would sweep. The secret passes to `/usr/bin/security`
  over stdin, never argv. Windows Credential Manager / Linux secret-service are the
  documented follow-up, with a clear error meanwhile.
- **MCP `resources/subscribe`** (roadmap: fact-change push): subscribe to a
  `dent8://{kind}/{key}/{predicate}` fact stream and the server pushes
  `notifications/resources/updated` when it gains events — immediately after a write
  through the same connection, and within a ~2s poll tick for writes from **any other
  process sharing the store** (another agent, the CLI, a daemon peer), so long-running
  agents stop re-polling `explain`. Subscribing to a not-yet-asserted stream is allowed and
  notifies on its first write. Works on both transports: the stdio server (notifier thread;
  responses and pushes interleave under one stdout lock) and the local daemon (per-connection
  notifier + single writer task). `dent8 mcp proxy` now pumps frames **bidirectionally**
  (previously strict request/response), so daemon clients receive pushes through it too.
  `initialize` advertises `resources.subscribe: true` only where a notifier is actually
  wired.
- **`dent8 whatif` — policy-counterfactual replay** (the rank-2 novelty direction in
  [research/novelty.md](docs/research/novelty.md), now surfaced): re-fold the same immutable log
  under a swapped epistemic trust policy — `--distrust <source>` (repeatable),
  `--authority-floor <level>`, `--confidence-floor <millis>` — and see what *would* be believed,
  with a per-fact structural diff (appeared / disappeared / lifecycle / value / supersession /
  evidence changes) against the real fold. Read-only, deterministic, zero model invocations;
  freshness is deliberately not a policy knob. Also an MCP tool (`whatif`, same arguments,
  available to read-only daemon connections), with the diff mirrored in `structuredContent` and
  an advertised `outputSchema`. At least one policy knob is required — the identity policy is
  the plain fold (`explain`).
- **`scripts/load-test.sh` — the concurrency harness** (roadmap: load testing and tuning):
  N parallel writers against one shared store, two phases — distinct facts (throughput +
  event-id uniqueness) and a deliberate same-fact supersession herd (every write eventually
  admitted, exactly one believed value, `verify` green over the full log). Defaults to a
  temporary SQLite store; point `DENT8_STORE_URL` at a throwaway Postgres (with `PSQL`
  overridable for dockerized databases) to run the Postgres leg. The harness found every
  concurrency fix below.
- **Cross-process write lease for `sqlite://` and `postgres://` stores**
  (`SqliteEventStore::acquire_write_lease`, `PostgresEventStore::acquire_write_lease`):
  each write attempt now holds a backend lease across the whole decide+commit cycle — a
  `BEGIN IMMEDIATE` on a `<db>-lease` sidecar database for SQLite, a session advisory lock
  on a dedicated connection for Postgres. Optimistic retry alone is safe but **livelocks**
  under sustained same-fact contention — the decide step re-reads a growing log, so a slow
  writer's snapshot is perpetually stale by commit time; the lease turns the herd into a
  fair queue. A crashed holder releases automatically (SQLite file locks and Postgres
  sessions die with the process), waits are bounded, and a timeout is a retryable conflict
  (SQLSTATE `55P03` on Postgres). Before: 16 writers × 50 contended supersessions exhausted
  the retry budget; after: all 800 admitted on both backends, none exhausted. The SQLite
  sidecar holds no data and may be deleted when no writer is running; in-memory stores skip
  the lease (single-process by construction). See the new write-concurrency section in
  [docs/storage.md](docs/storage.md).

### Fixed
- **`SQLITE_BUSY` at connect/migrate is a retryable conflict now**: concurrent
  first-connects race the schema DDL for the write lock; that BUSY was classified
  `Unavailable` (fatal) and crashed parallel writers on a fresh store. `connect_backend`
  also flattened errors to text, destroying the retryable class — it now returns the typed
  `StoreError`, and the write path routes `Conflict` into the retry loop.
- **A stale-snapshot commit is retried, not reported as terminal**: when a concurrent
  writer lands between an op's decide snapshot and its durable append, the backend's
  re-arbitration correctly rejects the commit (e.g. `cannot mutate terminal fact state
  Superseded`) — but that rejection surfaced as a non-retryable failure and crashed the
  writer. It is now classified as a write conflict: the op re-decides from a fresh snapshot
  and the write lands, or is *genuinely* rejected against current state.
- **Write-conflict retry widened**: 32 attempts (was 16), exponential backoff capped at
  256 ms (was 128 ms), still decorrelated per-process jitter.

## [0.6.1] - 2026-07-11

### Added
- **TypeScript SDK** ([`sdks/typescript`](sdks/typescript/), npm name `dent8`): the mirror of
  the Python SDK — zero runtime dependencies, every call shells out to the binary with
  `--output json`, errors throw `Dent8Rejected` / `Dent8Invalid` carrying the stable `status` +
  `code`. Same 1:1 belief surface (`assertFact`, `supersede`, …, `derive({ basis })`, `verify`
  returning findings as a result), same inherited store discovery / daemon routing / grant
  defaults / human time grammar. Tested with `node:test` against the real binary in CI
  (`node-sdk` job).
- **Tokenless SDK releases via Trusted Publishing:** `release.yml` gains `pypi` and `npm` jobs
  that publish the SDKs on every version tag using per-run OIDC identity — no standing
  credentials anywhere. Each registry side needs its one-time trusted-publisher entry (repo
  `xyzzylabs/dent8`, workflow `release.yml`, environments `pypi` / `npm`).
- **Python SDK** ([`sdks/python`](sdks/python/), PyPI name `dent8`): a deliberately thin,
  zero-dependency wrapper over the CLI's JSON machine contract — every call shells out with
  `--output json`, returns the payload as a `dict`, and raises `Dent8Rejected` / `Dent8Invalid`
  carrying the stable `status` + `code` (`insufficient-authority`, `below-authority-floor`, …)
  so callers branch on codes, never prose. The belief surface maps 1:1 (`assert_fact`,
  `supersede`, `contradict`, `retract`, `reinforce`, `expire`, `derive(basis=…)`, `explain`,
  `replay`, `facts`, `verify`, `conflicts`); store discovery, daemon routing, grant defaults,
  and the human time grammar are inherited from the CLI. Tested against the real binary in CI
  (`python-sdk` job). Roadmap item 5, Python half; the TS SDK remains.

## [0.6.0] - 2026-07-11

### BREAKING
- **The `dent8` package name now means the library; the CLI package is `dent8-cli`.** `cargo add
  dent8` gets the new **facade crate** (`crates/dent8`): curated re-exports of the event model +
  firewall + stores (`dent8::FactEvent`, `dent8::InMemoryEventStore`, `dent8::arbitrate`, …), a
  `prelude`, and a typed `FactBuilder` (`FactBuilder::assert("repo:myproj", "database",
  "postgres").authority(High).source("user:alice")…build()?`) that owns the construction
  boilerplate while the firewall still arbitrates every append. The CLI/MCP package renames to
  `dent8-cli` — the **installed binary is still `dent8`**, and nothing about the command surface
  changes. **Migration:** `cargo install dent8` → `cargo install dent8-cli` (older published
  `dent8` versions remain installable); in-repo `cargo <cmd> -p dent8` now targets the library —
  use `-p dent8-cli` for the CLI.

### Added
- **Human timestamps on every temporal flag.** `--valid-from`/`--valid-to`, `--as-of`/
  `--valid-at`, and the identity expirations now accept `now`, a ±duration offset from now
  (`-7d`, `+12h` — the `--ttl` units), RFC 3339 with an offset (`2026-07-11T12:00:00Z`), and
  bare UTC dates/datetimes (`2026-12-31`, `2026-12-31T12:00`), while raw unix milliseconds keep
  working (and remain the MCP tools' form). Bare forms are **UTC**, not local time, so the same
  command names the same instant on every machine. The identity expiration flags are renamed
  `--expires-at` / `--identity-expires-at` (`--expires-at-ms` / `--identity-expires-at-ms`
  remain as aliases). Parsing uses `jiff` (std-only, no tzdb).
- **Machine-readable error `code` on every error payload.** Each `--output json` error object
  and every MCP tool error's `structuredContent` now carries a stable kebab-case `code` naming
  the *cause* beside the existing `status`: firewall refusals classify from the typed error
  (`insufficient-authority`, `canonical-contradiction`, `terminal-fact`, `laundered-authority`,
  `unbacked-supersession`, `below-authority-floor`, `uniqueness-violation`,
  `ttl-ceiling-exceeded`, `weaker-entrenchment`), the write-boundary gates name themselves
  (`authority-ceiling`, `scope-violation`, `identity-rejected`, `unauthenticated-write`,
  `content-rejected`), and commit/IO paths report `write-conflict` / `commit-failed` /
  `store-unavailable` / `corrupt-event` / `replay-failed`, with generic fallbacks (`rejected`,
  `invalid-argument`, `operation-failed`, `unknown-tool`) when no finer cause is known — so an
  agent branches on the token instead of parsing prose. The MCP `outputSchema` advertises the
  closed code enum and requires the field; a daemon-routed CLI write lifts the code out of the
  daemon's reply, so it reports the same `code` a local write would.
- **MCP `resources/read` auto-records `fact.retrieved`** (purpose `mcp:resources/read`) on
  every successful read from a write-capable connection, closing the MCP half of the
  read-audit loop. Identity resolves like unattributed capture (active grant when present,
  else `source:agent` at `low`). Opt out with `DENT8_MCP_RECORD_RETRIEVAL=0`; unauthenticated
  daemon connections still return the receipt but skip the audit write. Failures to record
  surface as a protocol error so a write-capable read is never silently un-audited.
- **On-ramp acceptance script** [`examples/on-ramp/demo.sh`](examples/on-ramp/demo.sh): times
  `init` → first `assert` → `explain` in a throwaway git repo and fails if wall time exceeds
  120s (v0.4 under-2min-to-first-fact budget).
- **External integrity comparison** (`dent8_evals::comparison`, printed by `dent8 eval`): the
  demonstrative attack axes plus legitimate supersession judged against **modeled** Mem0
  mutate-in-place and Zep/Graphiti recency semantics (not live peer APIs). Frozen tally:
  dent8 holds 6/6; peers fall on all 5 attack axes; all three admit legitimate revision.
  Docs: [evals.md](docs/evals.md) §Integrity-axis comparison.

### Changed
- **`dent8 eval`** also prints the Mem0/Zep integrity comparison and includes a `comparison`
  object in `--output json`; exit is non-zero if either the demonstrative corpus or the
  comparison frozen tally regresses.
- **Value-first on-ramp:** README and [Getting Started](docs/getting-started.md) lead with a
  first-fact path under 2 minutes once `dent8` is on `PATH`; `dent8 init` Next steps now show
  `assert` + `explain` before `doctor --write-check`.
- **Docs agree multi-agent dogfood MCP is project-scoped** (Codex/Claude/Cursor/Grok/Gemini/
  Cascade): install into repo-local agent config, not user-global paths, so a shared
  `.dent8` store does not attach in other workspaces.
- **`doctor --agent` validates Cursor and Grok Build native-memory hooks** at project
  `.cursor/hooks.json` and `.grok/hooks/dent8.json` (same enforce markers as Codex/Claude).
  Samples: `examples/agent-hooks/cursor/hooks.sample.json`,
  `examples/agent-hooks/grok-build/hooks.sample.json`.
- **Explicit `DENT8_LOG` is not overridden by a discovered `.dent8/env` `DENT8_STORE_URL`**
  (hooks/tests that set only `DENT8_LOG` verify that file log, not dogfood SQLite).

## [0.5.0] - 2026-07-09

### BREAKING
- **Store resolution now discovers `.dent8/` within the enclosing git repository.** When
  `DENT8_LOG` / `DENT8_AUTHORITY` / `DENT8_STORE_URL` are unset, the CLI locates the project
  store by scanning from the current directory up to and including the **enclosing repo root**
  (the nearest ancestor holding a `.git` entry, bounded by `$HOME`/the filesystem root) and uses
  the log, `authority.json`, and **backend URL inside it**, instead of silently creating a
  parallel `./dent8-log.jsonl` in the cwd. Discovery is confined to that repo: a `.dent8/` in an
  unrelated ancestor (e.g. `/tmp/.dent8` for a process merely running under `/tmp`) is **no
  longer adopted** as an attacker-controlled store path and authority registry. When the cwd is
  not inside a git repo, only `./.dent8/` in the cwd itself is considered — discovery does not
  walk upward. A command run from a sub-directory of an initialized project still reads and writes
  that project's store even when `.dent8/env` was never sourced. Explicit env overrides still win
  (backward compatible, and the escape hatch for a store outside any repo), `.dent8/env` is parsed
  as safe `KEY=value` (not shell-sourced), and a fresh directory with no store discovered still
  falls back to the legacy cwd default so `dent8 init` keeps working. **Migration:** a stray
  `./dent8-log.jsonl` a previous run created in a sub-directory is no longer read — point
  `DENT8_LOG` at it, or re-capture its facts into the discovered store; a `.dent8/` outside your
  repo that an earlier unbounded walk reached is no longer discovered — set the matching
  `DENT8_*` var to reach it.
- **A discovered `DENT8_STORE_URL` (DB backend) is now honored, not just `DENT8_LOG`.** When
  `DENT8_STORE_URL` is unset in the process environment, the CLI reads it from the discovered
  `.dent8/env` and selects that async backend (SQLite/Postgres) for reads and writes. Previously
  discovery only read `DENT8_LOG`, so an unsourced run against a repo with a DB backend forked a
  **new parallel `memory.jsonl`** inside `.dent8/` and diverged from the real store; that footgun
  is fixed. **Migration:** if an unsourced run previously wrote to a stray `.dent8/memory.jsonl`
  in a DB-backed project, re-capture those facts into the backend (or keep sourcing `.dent8/env`).
- **The authority registry is unified to one location per store.** `dent8 authority add` /
  `defaults` / `list` / `remove` now resolve to the discovered `.dent8/authority.json` (the same
  file `dent8 init` seeds) when `DENT8_AUTHORITY` is unset, rather than a separate
  `./dent8-authority.json`. **Migration:** a `./dent8-authority.json` created by an unsourced-env
  `authority` command is no longer read — its grants must be re-added (or `DENT8_AUTHORITY` set to
  its path). Because discovery now finds the registry a sub-directory command previously missed,
  the registry's deny-by-default enforcement applies in more situations than before.
- **Unregistered predicates are now subject to the TTL retention ceiling.** `enforce_policy`
  previously skipped every check for a predicate not in the registry, so an assertion with an
  arbitrarily far-future *finite* TTL on an unknown predicate bypassed the ceiling. Unregistered
  predicates now fall back to the registry-wide global ceiling (registered predicates are
  unchanged; `Ttl::Never` remains out of scope). An over-ceiling finite TTL on any predicate is
  now rejected on `assert`/`derive`.

### Added
- Added a **`--ttl <DURATION>` flag** to `assert`, `supersede`, `contradict`, and `derive`, and a
  matching **`ttl` field to capture proposals**. The duration accepts `ms`/`s`/`m`/`h`/`d`
  suffixes (e.g. `90d`, `12h`). The caller-supplied finite TTL flows through the write boundary and
  is bounded by the retention ceiling, so a `--ttl` beyond the ceiling is rejected with the
  existing `TtlCeilingExceeded` error. Omitting it leaves the predicate default (or non-expiring).
  This is the first shipped write surface that accepts a caller TTL; the MCP write tools do not yet
  expose one.
- Added **native memory import/export** so agents can round-trip through a `CLAUDE.md` / `AGENTS.md`
  file without hand-editing the store ([native-memory.md](docs/native-memory.md)). Both are **stock
  commands** — they ship in every build (work under `--no-default-features`) and are not tied to the
  Parquet `export` feature.
  - `dent8 export --target <FILE>` renders the currently-believed facts into a receipt-bearing,
    sentinel-delimited **managed block** that is spliced idempotently into the target memory file:
    it preserves the surrounding human-authored text, refreshes byte-identically on re-export, and
    **rejects malformed or stray sentinels before writing** rather than corrupting the file. Each
    fact is emitted as a bullet carrying a `dent8://kind/key/predicate` receipt marker plus the
    event hash, authority, and source, between the `BEGIN`/`END` sentinels.
  - `dent8 import <FILE>` parses durable facts back out of a memory file and routes **each one
    through the full write firewall** (authority → content-check → policy → arbitrate → append) with
    no bypass. It recovers facts three ways — managed-block lines, inline `dent8://…= value`
    markers, and fenced ` ```dent8 ` JSON proposals — supports `--dry-run` to preview without
    writing, and accepts `--authority` / `--source` proposal metadata (still subject to the
    authority ceiling).

### Changed
- `dent8 init` now **seeds the default authority profile** (`source:human`/High,
  `source:ci`/Medium, `source:agent`/Low) into the store's `authority.json`, merge-only, in
  addition to the init source grant — so a fresh store carries the profile without a follow-up
  `dent8 authority defaults`. Running `authority defaults` afterwards stays idempotent (merge-only,
  never downgrades an existing grant).

### Fixed
- `dent8 export --target` locates the managed block with a Markdown-fence-aware sentinel scan, so
  `BEGIN`/`END` markers inside a fenced example (e.g. in the docs) are ignored instead of mistaken
  for the live block; the emitted block now matches the target file's dominant line ending (a CRLF
  file stays CRLF, no mixed endings); and it refuses to append into an unclosed code fence rather
  than corrupting the file.

### Documentation
- Added a **Getting Started guide** ([getting-started.md](docs/getting-started.md)): a zero-to-shared
  fact base walkthrough with commands run against a real binary and trimmed-but-verbatim output.
- Added a **native-memory reference** ([native-memory.md](docs/native-memory.md)) documenting the
  `dent8 export --target` / `dent8 import` memory-file round trip, the managed-block/sentinel format,
  and how imported facts are firewalled through the write path.

## [0.4.0] - 2026-07-08

### Added
- Added a pluggable **content-check hook at the write boundary**
  ([content-check.md](docs/content-check.md)): `DENT8_CONTENT_CHECK` names an external scanner
  run once per candidate fact (fact JSON on stdin, an `allow`/`reject`/`taint` verdict on
  stdout) after the authority gate and before arbitration, attestation, and persistence — so it
  covers **every** write entry point (CLI, `capture`, MCP, daemon) and cannot be bypassed on the
  write path. `reject` refuses the write; `taint` admits-but-flags (surfaced by `dent8 verify`
  as `CONTENT-FLAGGED`). A scanner failure is **fail-closed** by default (opt-in fail-open still
  flags the unscanned admit). dent8 ships no classifier of its own — the hook makes an external
  one un-bypassable on the write path — with a demonstrative reference scanner included.
- Added a **TTL retention ceiling** to the predicate registry: an assertion with a bounded
  (finite) TTL past the effective ceiling — a per-predicate override, else a 90-day global
  default — is **rejected** (`StoreError::TtlCeilingExceeded`), not clamped. `Ttl::Never` is
  out of scope, and the ceiling applies to registered predicates and library callers.
- Added an externally-grounded **47-case adversarial eval corpus** (`dent8-evals::adversarial`)
  across 10 attack classes, with patterns adapted from named public prompt-injection /
  memory-poisoning corpora. Verdicts are computed from attacker-goal predicates over projected
  belief state (never hardcoded) and reported **honestly**: **16/47 blocked** by arbitration,
  **4/47 detect-only** (flagged, not removed), **27/47 out-of-model** (owned by a downstream
  layer) — while a recency-only baseline is compromised by **46/47**. A separate lane re-runs the
  corpus with the content-check hook + demo scanner attached (**25/47 blocked, 9 detect-only,
  13 admitted unflagged**). Per-class tallies are frozen as regression guards; the shipped
  `dent8 eval` demo is unchanged (still 5/5). See [docs/evals.md](docs/evals.md).
- Added `dent8 context --record-retrieval [--purpose TEXT]`: every fact the context pack
  emits now gains a `fact.retrieved` audit event on its stream — the read half of the
  read-audit loop. Recorded before the pack is emitted, all-or-nothing, as the active
  signed grant's source (else the agent tier) through the normal write boundary;
  `--output json` reports `recorded_retrievals`.
- Added the `used_in_decision` capture proposal op: `{"op": "used_in_decision",
  "subject": ..., "predicate": ..., "decision": ...}` records a `fact.used_in_decision`
  audit event on the believed fact(s), so an agent can report which facts informed a
  decision through the proposals queue it already writes. Audit events never change
  lifecycle, value, or authority, and are not authority-gated in the fold (the
  write-boundary gate still applies).
- Added `dent8 capture --keep-failed` (with `--consume`): rejected and malformed proposal
  lines are written back to the queue file instead of truncated away, so a failed proposal
  survives for inspection/retry rather than only in hook logs. `--output json` reports
  `kept_failed`.
- Added `dent8 context`: emit the currently-believed facts as an agent context pack —
  markdown ready for CLAUDE.md/AGENTS.md-style inclusion or `SessionStart`-hook injection,
  or `--output json`. Belief-state aware: terminal facts never appear, stale/not-yet-valid
  facts are omitted by default (or annotated with `--include-stale`), contested facts are
  flagged inline, and every fact carries authority, asserting source, and its `dent8://`
  receipt reference.
- Added `dent8 capture [FILE] [--consume]`: batch structured fact proposals (JSON lines
  from stdin or a file) through the same `op_*` firewall path as the interactive writes,
  with per-line authority/source resolution falling back to the agent tier
  (`source:agent` at `low`). Built for session-end hooks: every line is attempted and
  reported, a firewall rejection exits `1` as a visible safety signal, and `--consume`
  truncates the queue file so the next hook firing does not replay it.
- Added `dent8 authority defaults`: seed the source→authority registry with the
  out-of-the-box trust profile for a shared repository — `source:human` → `high`,
  `source:ci` → `medium`, `source:agent` → `low` (human > CI > agent) — merge-only, so an
  operator's existing grants are never downgraded.
- Documented the capture/inject loop and its Claude Code hook wiring in
  `docs/context-capture.md`, and extended
  `examples/agent-hooks/claude-code/settings.sample.json` with the `SessionStart` context
  injection and `SessionEnd` proposals flush.
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
- Dogfooded dent8 as this repo's own shared fact base: `scripts/dogfood-seed.sh` and
  `scripts/dogfood-facts.jsonl` rebuild the (gitignored) `.dent8/` store from 15
  human-authored facts at `source:human`/**High** — MSRV, the CI gates, commit conventions,
  the authority profile, eval tallies, and roadmap — and `.claude/settings.json` wires a
  `SessionStart` → `dent8 context` inject and a `SessionEnd` → `dent8 capture` flush so
  agents share one verified, provenance-stamped fact base instead of a hand-maintained
  rules file that drifts. The hooks are a silent no-op when the binary is absent, and
  `.gitignore` un-ignores the shared settings file.

### Changed
- Refreshed the README firewall GIF/tape: the walkthrough now starts with a clearer headline,
  supports opt-in reader pauses via `DENT8_DEMO_PAUSE`, and keeps the final witness caveat on
  its own readable line.
- Updated the Docker CI actions to their Node 24 releases (`docker/setup-buildx-action@v4`
  and `docker/build-push-action@v7`) to remove the GitHub Actions Node 20 deprecation
  annotation.

### Documentation
- Reconciled the preprint and outline with the eval corpus: the five hand-authored scenarios are
  scoped as illustrative and the 47-case corpus is presented as the substantive result (16
  blocked / 4 detect-only / 27 out-of-model, 46/47 compromising a recency-only baseline), with
  named provenance, the per-class blocked table, and Limitations bullets on the
  content-inspection boundary and the blocked-means-displacement-prevented semantics.
- Aligned the docs with the code and sharpened the multi-agent shared-fact-base wedge:
  `formal-verification.md` describes the Kani harnesses as written but not yet in CI, the crate
  count is corrected to seven, the Postgres adapter is noted as implemented and CI-tested, the
  fuzz targets are split into implemented vs planned, and the project brief/roadmap are sharpened
  around the shared-fact-base wedge.
- Added a README **flagship example** built from this repo's own `dent8 context` pack, and
  fixed the "Try it" walkthrough so it runs verbatim on a fresh store: the generated env is
  exported inside `set -a`, and `--identity` is dropped so the low-authority supersede is
  rejected for **arbitration** (Low can't override High) rather than a source/grant mismatch.
  `AGENTS.md` points agents at the fact base as authoritative, and
  [docs/dogfooding-notes.md](docs/dogfooding-notes.md) adds a candid usability report with a
  prioritized fix list.

### Fixed
- Hardened the `dent8 doctor --write-check` probe: it now retracts its own `ok` fact after the
  checks complete (no believed residue across runs), asserts at the source's **own granted
  authority ceiling** instead of a hardcoded `high` (the reject sub-check supersedes one level
  below, and is skipped/noted at the minimum level), and hides its diagnostic streams by exact
  path-segment match so a real predicate like `dent8.write_checkout` stays visible.
- `dent8 doctor --write-check` no longer fails for a healthy **subject-scoped** source: the
  write probe is scope-aware and targets the scoped subject under a per-run
  `dent8.write_check.<run-id>` predicate instead of an out-of-scope `diagnostic:` subject —
  a legitimately-authorized write through the unchanged write gate, never an out-of-scope
  one. Scoped probe streams are hidden from fact browsing like the `diagnostic:` ones, and
  an unauthorized source still fails the check.
- `dent8 authority add` now refuses a grant that would complete an issuer cycle regardless
  of insertion order (`add a <max> b` then `add b <max> a` is refused like the reverse
  order); previously one insertion order slipped past the add-time check and was only
  caught later by the write gate.

### Security
- `dent8 authority remove` no longer silently loosens delegates: removing a grant that
  other grants chain their authority through is refused (the deleted issuer would become an
  unregistered name — an operator-level root — so revoking an issuer would have *widened*
  what its delegates may write). `--force` cascades the revocation down the delegation
  chain, so orphaned delegates authorize nothing (deny-by-default) until an operator
  re-parents them with `dent8 authority add`.
- The authority registry now **enforces** a grant's `issuer` and `scope` (previously
  recorded but not enforced): a write about a subject outside the grant's scope (`"*"` or
  an exact `<kind>:<key>`; a malformed scope covers nothing) is rejected, and a grant
  issued by another registered source is capped by that issuer's own grant — ceiling and
  scope, transitively — so an issuer cannot delegate authority it does not hold (no
  self-escalation). Self-issued grants and issuer cycles authorize nothing (fail closed);
  an issuer that is not a registered source remains an operator-level root recorded for
  audit. `dent8 authority add` refuses self-escalating grants up front, and the write gate
  re-checks the chain on every write so a hand-edited registry cannot smuggle an
  escalation past it. Add-time refusal of self-escalating and issuer-cycle-completing grants is
  now **order-independent** — neither insertion order of a two-grant cycle slips past the
  add-time check (previously one order was only caught later by the write gate).
- A pluggable **content-check hook** now sits on the write boundary (see Added):
  `DENT8_CONTENT_CHECK` runs an external scanner over every candidate fact across all write
  entry points and can `reject` a write or `taint` it (admit-but-flag, surfaced by `dent8
  verify` as `CONTENT-FLAGGED`) **by content** — after the authority gate, before persistence.
  A scanner failure is fail-closed by default. dent8 ships no classifier of its own: the hook is
  the un-bypassable seam an external scanner attaches to, so content-inspection quality is the
  operator's scanner, not a dent8 claim.
- The **TTL retention gap is narrowed, not closed**: the new retention ceiling (see Added)
  rejects a finite-TTL assertion that exceeds the effective (per-predicate, else 90-day)
  ceiling, but it only bounds *bounded* TTLs on **registered predicates and library callers** —
  `Ttl::Never` and unregistered predicates stay out of scope. Far-future-but-finite retention on
  covered predicates is capped; the broader staleness-versus-retention exposure remains a
  read-time concern rather than a fully closed write-time guarantee.
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
