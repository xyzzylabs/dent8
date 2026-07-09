# Configuration reference

dent8 is configured by **environment variables** (for paths and the backend) and **Cargo
features** (for opt-in backends/capabilities). This is the single source of truth for both;
the stock binary needs no services (it uses a local file log by default) and includes signed
source identity, witness commands, and the embedded SQLite backend for local multi-agent use.

For a project-local setup, run `dent8 init`, then load the generated env file:

```sh
dent8 init
set -a
. .dent8/env
set +a
dent8 doctor --write-check
```

`dent8 init --store sqlite` writes a `sqlite://…` `DENT8_STORE_URL` profile (supported by the
stock build). `dent8 init --store postgres --store-url postgres://…` writes a Postgres profile
(requires a `--features postgres` build).
`dent8 init --witness` adds witness verification paths to `.dent8/env`; it does **not** put a
witness signing key in the writer environment.

For the secure agent path, use `dent8 init --identity --source <source>` or an agent shortcut:

```sh
dent8 init --agent codex --install-mcp
dent8 doctor --agent codex --write-check
```

## Environment variables

| Variable | Used by | Default | Purpose |
|---|---|---|---|
| `DENT8_LOG` | CLI / MCP (file backend) | discovered `.dent8/` (in-repo), else `./dent8-log.jsonl` | Path to the JSON-lines dev-store log. When unset, the CLI resolves the project store by [repo-confined discovery](#store-and-registry-discovery) and uses the log inside it — a discovered `.dent8/env` `DENT8_LOG` if set, else the store's `memory.jsonl` — so a sub-directory command hits the project store instead of a parallel cwd log. With no store discovered it falls back to `./dent8-log.jsonl`. |
| `DENT8_STORE_URL` | CLI / MCP (an async backend feature) | discovered `.dent8/env` value, else *(file backend)* | A backend store URL, dispatched by **scheme** to the matching async backend (`sqlite://…` is included in the stock build; `postgres://…` needs `--features postgres`). When unset in the process environment, a `DENT8_STORE_URL` recorded in the discovered `.dent8/env` is honored, so an unsourced run in a repo with a DB backend uses that backend instead of forking a parallel file log. When set (here or discovered), reads/writes go to that operational store instead of the file log. Set without a matching backend feature → a clear build-hint error. |
| `DENT8_AUTHORITY` | `dent8 init`, `dent8 authority` + every write | discovered `.dent8/authority.json` (in-repo), else `./dent8-authority.json` | Path to the source→authority **ceiling** registry. When unset, it resolves against the discovered `.dent8/` store — a discovered `.dent8/env` `DENT8_AUTHORITY` if set, else the store's `authority.json` (the same file `dent8 init` seeds) — so `init` and the `authority` subcommands share one registry per store. Enforcement is **opt-in**: it activates only once this file exists (created by `dent8 init` or `dent8 authority add`); then it is deny-by-default. |
| `DENT8_REQUIRE_AUTHORITY` | every write | *(unset / false)* | Fail-closed deployment guard. When true (`1`, `true`, `yes`, or `on`), a missing authority registry is an error instead of permissive dev mode. |
| `DENT8_TRUST` | signed identity | `./dent8-trust.json` | Path to trusted issuer public keys. If this file exists, signed source identity is active for every write. |
| `DENT8_ACTIVE_GRANTS` | signed identity | sibling `active-grants.json` next to `DENT8_TRUST`, when present | Path to the active source-grant registry. Bootstrap writes `.dent8/active-grants.json`; writes presenting an older grant for the same source are rejected once this registry exists. |
| `DENT8_GRANT_LOG` | signed identity + `verify` | sibling `grant-log.jsonl` next to `DENT8_TRUST`, when present | Append-only, issuer-signed grant **history** (ADR 0014). Lifecycle commands append `issued`/`revoked` records; `verify` uses it to decide each attested event's *entitlement at write time*. `dent8 identity revoke` ends trust without a replacement; `dent8 identity backfill-grant-log` seeds records for pre-history grants. |
| `DENT8_REQUIRE_IDENTITY` | every write | *(unset / false)* | Fail-closed identity guard. When true, a missing trust registry, grant, or source key rejects writes. |
| `DENT8_RECORD_CHALLENGES` | rejected writes | *(unset = on)* | Survived-challenge recording (ADR 0015). When the firewall rejects a challenge on strength, the incumbent's stream records a `fact.challenge_rejected` event with the challenger's provenance and effective authority. Set `0`/`false` to opt out; a malformed value keeps recording. |
| `DENT8_MCP_RECORD_RETRIEVAL` | MCP `resources/read` | *(unset = on)* | Auto-record a `fact.retrieved` audit event (purpose `mcp:resources/read`) on every successful resource read from a write-capable connection. Set `0`/`false`/`no`/`off` to opt out; a malformed value keeps recording. Unauthenticated daemon connections never write the audit (read-only). |
| `DENT8_ENTRENCHMENT_GATE` | `supersede` | *(unset / off)* | Opt-in earned-supersession gate: an equal-authority replacement may not displace an incumbent with strictly stronger authority-weighted **earned entrenchment** — corroboration plus survived challenges (ADR 0015 + [ADR 0017](decisions/0017-survived-challenges-in-arbitration.md)). A malformed value fails toward enforcement. |
| `DENT8_CONTENT_CHECK` | every value-carrying write | *(unset → pass-through)* | The pluggable **content-check hook** ([content-check.md](content-check.md)): a scanner command (whitespace-split program + args) run per candidate fact — the fact as JSON on stdin, an `allow` / `reject` / `taint` verdict on stdout — after the authority gate and before arbitration/attestation/persistence, on **every** write entry point (CLI, `dent8 capture`, MCP, daemon). `taint` admits but marks the event (a `content-check:` evidence flag, surfaced by `verify`). dent8 ships no classifier: wire LLM Guard, Rebuff, a Lakera/Azure Prompt Shields bridge, etc. |
| `DENT8_CONTENT_CHECK_TIMEOUT_MS` | the content-check hook | `5000` | Per-fact scanner budget; a scanner still running past it is killed and counts as a scanner failure. |
| `DENT8_CONTENT_CHECK_FAIL_OPEN` | the content-check hook | *(unset / false → **fail-closed**)* | Scanner-failure policy. Default fail-closed: a configured scanner going dark must not silently readmit unchecked content. When true, a failed scan admits the write but still flags it (visible in `verify`). |
| `DENT8_GRANT` | every write | *(unset)* | Signed source grant JSON binding the configured source id to a source public key and maximum authority. CLI and stdio MCP writes use this grant to default missing `--source` and `--authority` before the normal authority/identity checks run; daemon writes default from the authenticated connection identity. |
| `DENT8_IDENTITY_KEY` | every write | *(unset)* | Source private signing key. On Unix, dent8 requires owner-only permissions (`0600`). |
| `DENT8_DAEMON_SOCKET` | CLI writes / `dent8 daemon status` / `dent8 mcp proxy` (Unix, a storage-backend build) | *(unset → write locally / default daemon path)* | CLI **writes** (`assert`/`supersede`/`retract`/`contradict`/`reinforce`/`expire`/`derive`) route through a running local daemon ([`dent8 daemon serve`](decisions/0018-local-daemon-and-per-connection-identity.md)) at this socket path instead of writing the local store: the CLI completes the session-challenge handshake with `DENT8_GRANT`/`DENT8_IDENTITY_KEY` and the daemon attests the write. Reads stay local. `dent8 daemon status` and `dent8 mcp proxy` also use this socket when `--socket` is omitted. |
| `DENT8_ISSUER_KEY` | `dent8 init --identity` / `dent8 identity bootstrap` | `$XDG_CONFIG_HOME/dent8/issuer.key` or `$HOME/.config/dent8/issuer.key` | Optional operator issuer signing-key path for bootstrap. This key should stay outside the project/agent workspace. |
| `DENT8_MCP_SMOKE_TIMEOUT_MS` | `dent8 doctor --agent` | `10000` | Maximum time to wait for the installed MCP server smoke check before killing it and reporting a timeout. |
| `DENT8_WITNESS_KEY` | `dent8 witness` | `./dent8-witness.key` | Path to the Ed25519 **signing** key (hex, `0600`). `<path>.pub` holds the public key. |
| `DENT8_WITNESS_PUBKEY` | `dent8 witness verify` | `<DENT8_WITNESS_KEY>.pub` | Override the public key used for verification (e.g. when verifying a published head without the signing key). |
| `DENT8_WITNESS_LOG` | `dent8 witness sign` / `verify` / `serve` | `./dent8-witness.jsonl` | Path to the appended log of signed tree heads. |
| `DENT8_WITNESS_GRANTS_LOG` | `dent8 witness` (grant-log lane) | `./dent8-witness-grants.jsonl` | Appended log of witness-signed **grant-log** heads (ADR 0014 follow-up): `sign`/`serve` cover the grant log when one is discoverable, and `witness verify` detects grant-history truncation (a hidden revocation) as ROLLBACK. |
| `DATABASE_URL` | the adapter's integration tests only | *(unset → tests skip)* | A throwaway `postgres://…` for `cargo test -p dent8-store-postgres --features adapter`. **Not** read by the CLI/MCP — that is `DENT8_STORE_URL`. |

The optional hook helper `dent8 hook native-memory-guard` has its own variables:
`DENT8_HOOK_MODE`, `DENT8_HOOK_ENFORCE`, and `DENT8_ALLOW_NATIVE_MEMORY_WRITE`.

The bundled [`compose.yml`](../compose.yml) brings up a throwaway `postgres:16`; the matching
URL is in [`.env.example`](../.env.example) (`postgres://postgres:dent8@localhost:5432/dent8`).

## Store and registry discovery

When `DENT8_LOG`, `DENT8_STORE_URL`, and `DENT8_AUTHORITY` are unset in the process environment,
the CLI locates the project's `.dent8/` store and reads those values from its `.dent8/env`.
Discovery is **confined to the enclosing git repository** — the shared fact base for the agents
working on one repo — so a `.dent8/` planted in an unrelated ancestor cannot be silently adopted
as an attacker-controlled store path and authority registry:

- **Enclosing repo root** — the nearest ancestor of the current directory that contains a `.git`
  entry (file or directory), searched upward but **stopping at (and never above) `$HOME` and the
  filesystem root**.
- **In-repo discovery** — inside that repo, scan from the current directory up to and *including*
  the repo root; the first `.dent8/` found wins. A command run from any sub-directory of an
  initialized project therefore resolves the project store, not a parallel one in the cwd.
- **No repo → cwd only** — when the current directory is not inside a git repo (no `.git` within
  bounds), only `./.dent8/` in the current directory itself is considered; discovery does **not**
  walk upward. (So `/tmp/.dent8` is never adopted for a process merely running under `/tmp`.)
- **Explicit env vars always win** — a `DENT8_LOG` / `DENT8_STORE_URL` / `DENT8_AUTHORITY` set in
  the process environment bypasses discovery entirely, keeping a store *outside* any repo
  reachable via those variables (the escape hatch).
- **Safe parsing** — the discovered `.dent8/env` is parsed as safe `KEY=value` assignments
  (single-quote-unquoted), **not** shell-sourced, so a discovered store only supplies
  configuration values and can never execute code. Sourcing `.dent8/env` yourself (`set -a; .
  .dent8/env; set +a`) still works and exports the same values.

Per resolved key: **effective = process-environment value, else the discovered `.dent8/env`
value, else the default.**

## Cargo features (on the `dent8` package)

| Feature | Adds | Default? |
|---|---|---|
| *(default)* | the full firewall + lifecycle over the **file dev store**, embedded SQLite, plus `facts list`, `eval`, `verify`, `conflicts`, `authority`, signed identity, witness, MCP, and the local daemon | yes |
| `postgres` | the operational **transactional Postgres backend** (sqlx + a tokio bridge), selected by a `postgres://` `DENT8_STORE_URL` | no |
| `sqlite` | the embedded **SQLite backend** (sqlx + bundled libsqlite3, no server), selected by a `sqlite://` `DENT8_STORE_URL` | yes |
| `export` | the `dent8 export` analytical lane — the log to **Parquet** for offline DuckDB analysis (pulls the arrow/parquet stack) | no |

```sh
cargo build -p dent8                                    # stock: file store + SQLite + signed identity + witness
cargo build -p dent8 --no-default-features              # minimal: file store only (no async backend)
cargo build -p dent8 --features postgres                # + Postgres backend
cargo build -p dent8 --features sqlite                  # explicit SQLite (already default)
cargo build -p dent8 --features export                  # + Parquet export for DuckDB
cargo build -p dent8 --features postgres,sqlite,export  # all backends + export
```

Postgres and export stay off by default so the stock binary stays free of the Postgres and
Arrow/Parquet stacks. SQLite is default because it is the no-server shared backend for local
multi-agent dogfooding, and witness is always on because it reuses the signed-identity crypto
already required by the threat model. The authority registry, identity
trust/grants/keys, and witness keys are **host-local config**, independent of the event backend
— a Postgres deployment still reads these from the local filesystem, so provision them per
instance. Set `DENT8_REQUIRE_AUTHORITY=1` and `DENT8_REQUIRE_IDENTITY=1` for deployments that
must fail closed if registry or identity material was not provisioned.

## Signed source identity flow

Signed identity proves source-key possession at the CLI/MCP boundary. It is not a login
server: the operator holds an issuer key and issues grants to agent/source keys. Every
accepted write also persists a **signed write attestation** in `provenance.attestation`
(ADR 0013) — an Ed25519 signature by the source key over the event content — which
`dent8 verify` re-checks offline, so attribution outlives the write.

```sh
dent8 init --agent codex --install-mcp
dent8 doctor --agent codex --write-check
```

`dent8 init --identity` and `dent8 init --agent <profile>` create or reuse an operator issuer
key outside the project bundle, then write the normal env plus `.dent8/trust.json`, a
per-source key under `.dent8/identities/`, a grant under `.dent8/grants/`, and
`.dent8/identity-<source>.env` (for example `.dent8/identity-codex.env`). Agent profiles are
`codex`, `claude-code`, `cursor`, `grok-build`, `gemini`, `cascade`, and `hecate`. Add
`--install-mcp` to patch the selected agent's MCP config and print the resulting file; run
`dent8 mcp install --agent <profile>` later to regenerate it from the existing `.dent8` bundle.
The installer supports `--dry-run` to render without writing and `--check` to fail CI or setup
scripts when the file is stale. `--mcp-command` on `init` and `--command` on `mcp install`
override the command written into the config, for example `/usr/local/bin/dent8` when dent8 is
installed globally but not on the agent host's `PATH`. If you use a bundle directory not named
`.dent8`, pass `--mcp-config` / `--config` because dent8 cannot infer the project-local MCP
config path safely. `dent8 doctor --agent <profile>` reads the installed MCP config back, so
custom commands do not need to be repeated for the normal post-install check. The
repo-local alternative is `--mcp-local-bin` on `init` / `agent add`, or `--local-bin` on
`mcp install`. Build the target first:

```sh
CARGO_TARGET_DIR=.dent8/target-sqlite cargo build -p dent8 --features sqlite
dent8 mcp install --agent codex --local-bin
dent8 doctor --agent codex --mcp-local-bin
```

This writes `.dent8/bin/dent8`, a tiny wrapper that execs
`.dent8/target-sqlite/debug/dent8`; it avoids Cargo locks/rebuilds during MCP startup while
letting doctor verify the wrapper, configured store support, witness support when configured,
and stale prebuilt binaries.
To make a stdio-only MCP client use an already running local daemon, add
`--mcp-use-daemon` on `init` / `agent add`, or `--use-daemon` on `mcp install`; this writes
`dent8 mcp proxy`. Use `--mcp-daemon-socket PATH` / `--daemon-socket PATH` to pin a
non-default daemon socket in the installed config. The daemon is single-source in v0, so use
separate stdio server subprocesses against the same backend, or separate daemon instances,
when per-agent provenance matters.
`dent8 identity status` command checks the bundle, active-grant registry, grant, source key,
issuer key when supplied, and expiry.
`dent8 identity repair-env --dir .dent8 --source <source>` rewrites generated
`.dent8/identity-<source>.env` from the current signed grant and restores a missing active-grant
entry without rotating keys; it refuses to overwrite a different active grant. Use it when a
generated env/active-grant registry is stale or doctor reports a repair hint.
`dent8 identity rotate-source` generates a replacement source key, issues a replacement grant,
updates `.dent8/active-grants.json`, rewrites `.dent8/identity-<source>.env` at the same stable
path, rejects the previous grant at the write boundary, and removes the previous private
source-key backup after a successful rotation. It
keeps non-secret audit backups such as the old grant/env/public key. `dent8 identity bootstrap`
remains available for custom layouts. It creates or reuses an
operator issuer key outside the project bundle
(`--issuer-key`, `DENT8_ISSUER_KEY`, `$XDG_CONFIG_HOME/dent8/issuer.key`, or
`$HOME/.config/dent8/issuer.key`). Bootstrap refuses to write the issuer key inside the bundle
and refuses to overwrite existing project identity material. The manual subcommands
(`issuer-keygen`, `agent-keygen`, `trust-add`, `grant-issue`, `grant-verify`) remain available
when you need custom paths, expiration, or exact subject scopes.

By default, the issuer key is shared across all projects bootstrapped by the same OS user. That
is convenient for a single operator: one owner/admin key can issue grants for many project
bundles, while the key itself stays out of agent-readable workspaces. The tradeoff is blast
radius: compromising that one issuer key lets an attacker mint grants for any project that
trusts it. For project-level isolation, pass a project-specific issuer key outside the project
workspace:

```sh
dent8 identity bootstrap \
  --source source:codex \
  --issuer-key "$HOME/.config/dent8/projects/my-project/issuer.key"
```

Each agent should have a distinct source key and grant. Multiple agents can use the same
globally installed `dent8` binary, and their stdio server subprocesses can share the same
belief base by pointing at the same `DENT8_STORE_URL` and authority/trust registries. A shared
stdio MCP process can only prove the single identity whose private key it holds. The local
Unix-socket daemon adds a per-connection session challenge and supports authenticated writes,
but still requires each connection to prove the same source key the daemon process holds; run
separate daemon instances if you need distinct local source identities over sockets. Future
remote HTTP transport needs per-request source authentication without service-held source
keys. See
[ADR 0012](decisions/0012-signed-source-identity.md) and
[ADR 0018](decisions/0018-local-daemon-and-per-connection-identity.md) for the security model
and limits.

For that shared-backend setup, `dent8 agent add` is the normal follow-up to the first
`init`. It refuses file-dev bundles, then adds/repairs the selected profile's authority
grant, source key/grant/env, and MCP config:

```sh
dent8 init --agent codex --store sqlite --install-mcp
dent8 agent add --agent cursor
dent8 agent add --agent claude-code
```

Use `dent8 doctor --agent <profile> --write-check` as the post-install green light. It reads
the generated bundle directly, parses the selected agent's installed MCP config, smokes that
exact command/args/cwd/env, and runs the trusted-fact / low-authority-rejection probe through
that installed MCP server with the agent source id. If doctor reports a stale generated
identity env or installed MCP env, `dent8 doctor --agent <profile> --repair --write-check`
repairs the generated env from the current signed grant, refreshes the selected MCP config,
and then reruns those checks.

For a shared local setup, use `dent8 doctor --all-agents --write-check` to check every installed
known profile in the bundle. Profiles without a source-bound identity env or default project-local
MCP config are reported as `SKIP`; any installed profile that fails its normal agent doctor fails
the aggregate command. Hecate task configs are custom paths, so check them with
`dent8 doctor --agent hecate --mcp-config PATH`.

`doctor --agent` also reports native-memory bypass posture. For Codex, Claude Code, Gemini,
Cascade, Cursor, and Grok Build it inspects the expected **project** hook config and reports
OK only when it finds `dent8 hook native-memory-guard` in enforced write-guard mode
(`DENT8_HOOK_ENFORCE=1`):

| Agent | Hook config path |
|---|---|
| Codex | `.codex/hooks.json` |
| Claude Code | `.claude/settings.json` |
| Gemini | `.gemini/settings.json` |
| Cascade | `.windsurf/hooks.json` |
| Cursor | `.cursor/hooks.json` |
| Grok Build | `.grok/hooks/dent8.json` |

A missing hook is a WARN, not a failure: MCP remains the dent8 integrity boundary, but native
memory/rules files are not guarded against direct writes. Hecate is reported as WARN/unknown
because policy is distributed to supervised child agents rather than one Hecate-local file;
validate those from [`examples/agent-hooks/`](../examples/agent-hooks/). `doctor --agent` also
runs the read-only `dent8 native scan --agent <profile>` audit and reports how many native
memory/rules files are visible and how many carry dent8 receipt markers. Run
`dent8 native reconcile --agent <profile>` when native files contain explicit
`dent8://<kind>/<key>/<predicate>` receipt references and you want to fail on stale,
contested, missing, no-longer-believed, or malformed references.

## Witness flow

`dent8 init --witness` writes verification config into `.dent8/env`:

```sh
dent8 init --witness
set -a
. .dent8/env
set +a
```

The default paths are `.dent8/witness.jsonl` for signed heads and
`.dent8/witness.key.pub` for the public verifying key. The signing key is intentionally not
written into `.dent8/env`. For local development, generate and use it explicitly:

```sh
DENT8_WITNESS_KEY=.dent8/witness.key dent8 witness keygen
export DENT8_WITNESS_GRANTS_LOG=.dent8/witness-grants.jsonl
DENT8_WITNESS_KEY=.dent8/witness.key dent8 witness sign
dent8 doctor
dent8 witness verify
```

For production-shaped use, run `dent8 witness serve` with `DENT8_WITNESS_KEY` on a separate
host/process and share only `DENT8_WITNESS_LOG` plus `DENT8_WITNESS_PUBKEY` with the writer.
`dent8 doctor` reports signed-head coverage and fails on tamper/rollback. See
[witness.md](witness.md) for the runbook and residual risks.

See [STATUS.md](STATUS.md) for what each surface does, and [storage.md](storage.md) for the
backend design.
