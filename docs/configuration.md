# Configuration reference

dent8 is configured by **environment variables** (for paths and the backend) and **Cargo
features** (for opt-in backends/capabilities). This is the single source of truth for both;
the stock binary needs no services (it uses a local file log) and includes signed source
identity.

For a project-local setup, run `dent8 init`, then load the generated env file:

```sh
dent8 init
set -a
. .dent8/env
set +a
dent8 doctor --write-check
```

`dent8 init --store sqlite` writes a `sqlite://…` `DENT8_STORE_URL` profile (requires a
`--features sqlite` build). `dent8 init --store postgres --store-url postgres://…` writes a
Postgres profile (requires a `--features postgres` build).

For the secure agent path, use `dent8 init --identity --source <source>` or an agent shortcut:

```sh
dent8 init --agent codex
set -a
. .dent8/env
. .dent8/identity.env
set +a
dent8 doctor --source source:codex --write-check
```

## Environment variables

| Variable | Used by | Default | Purpose |
|---|---|---|---|
| `DENT8_LOG` | CLI / MCP (file backend) | `./dent8-log.jsonl` | Path to the JSON-lines dev-store log. |
| `DENT8_STORE_URL` | CLI / MCP (an async backend feature) | *(unset → file backend)* | A backend store URL, dispatched by **scheme** to the matching async backend (`postgres://…` needs `--features postgres`; `sqlite://…` needs `--features sqlite`). When set, reads/writes go to that operational store instead of the file log. Set without a matching backend feature → a clear build-hint error. |
| `DENT8_AUTHORITY` | `dent8 init`, `dent8 authority` + every write | `./dent8-authority.json` | Path to the source→authority **ceiling** registry. Enforcement is **opt-in**: it activates only once this file exists (created by `dent8 init` or `dent8 authority add`); then it is deny-by-default. |
| `DENT8_REQUIRE_AUTHORITY` | every write | *(unset / false)* | Fail-closed deployment guard. When true (`1`, `true`, `yes`, or `on`), a missing authority registry is an error instead of permissive dev mode. |
| `DENT8_TRUST` | signed identity | `./dent8-trust.json` | Path to trusted issuer public keys. If this file exists, signed source identity is active for every write. |
| `DENT8_REQUIRE_IDENTITY` | every write | *(unset / false)* | Fail-closed identity guard. When true, a missing trust registry, grant, or source key rejects writes. In a `--no-default-features` build, setting this or configuring identity produces a build-hint error. |
| `DENT8_GRANT` | every write | *(unset)* | Signed source grant JSON binding the configured source id to a source public key and maximum authority. |
| `DENT8_IDENTITY_KEY` | every write | *(unset)* | Source private signing key. On Unix, dent8 requires owner-only permissions (`0600`). |
| `DENT8_ISSUER_KEY` | `dent8 init --identity` / `dent8 identity bootstrap` | `$XDG_CONFIG_HOME/dent8/issuer.key` or `$HOME/.config/dent8/issuer.key` | Optional operator issuer signing-key path for bootstrap. This key should stay outside the project/agent workspace. |
| `DENT8_WITNESS_KEY` | `dent8 witness` (`--features witness`) | `./dent8-witness.key` | Path to the Ed25519 **signing** key (hex, `0600`). `<path>.pub` holds the public key. |
| `DENT8_WITNESS_PUBKEY` | `dent8 witness verify` | `<DENT8_WITNESS_KEY>.pub` | Override the public key used for verification (e.g. when verifying a published head without the signing key). |
| `DENT8_WITNESS_LOG` | `dent8 witness sign` / `verify` / `serve` | `./dent8-witness.jsonl` | Path to the appended log of signed tree heads. |
| `DATABASE_URL` | the adapter's integration tests only | *(unset → tests skip)* | A throwaway `postgres://…` for `cargo test -p dent8-store-postgres --features adapter`. **Not** read by the CLI/MCP — that is `DENT8_STORE_URL`. |

The optional hook helper `dent8 hook native-memory-guard` has its own variables:
`DENT8_HOOK_MODE`, `DENT8_HOOK_ENFORCE`, and `DENT8_ALLOW_NATIVE_MEMORY_WRITE`.

The bundled [`compose.yml`](../compose.yml) brings up a throwaway `postgres:16`; the matching
URL is in [`.env.example`](../.env.example) (`postgres://postgres:dent8@localhost:5432/dent8`).

## Cargo features (on `dent8-cli`)

| Feature | Adds | Default? |
|---|---|---|
| *(default)* | the full firewall + lifecycle over the **file dev store**, plus `eval`, `verify`, `conflicts`, `authority`, signed identity, MCP | yes |
| `postgres` | the operational **transactional Postgres backend** (sqlx + a tokio bridge), selected by a `postgres://` `DENT8_STORE_URL` | no |
| `sqlite` | the embedded **SQLite backend** (sqlx + bundled libsqlite3, no server), selected by a `sqlite://` `DENT8_STORE_URL` | no |
| `identity` | Ed25519 signed source identity commands and write-boundary grant verification | yes |
| `witness` | the `dent8 witness` Ed25519 signed-tree-head commands | no |
| `export` | the `dent8 export` analytical lane — the log to **Parquet** for offline DuckDB analysis (pulls the arrow/parquet stack) | no |

```sh
cargo build -p dent8-cli                                    # stock: file store + signed identity
cargo build -p dent8-cli --no-default-features              # minimal: file store only
cargo build -p dent8-cli --features postgres                # + Postgres backend
cargo build -p dent8-cli --features sqlite                  # + embedded SQLite backend
cargo build -p dent8-cli --features witness                 # + witness
cargo build -p dent8-cli --features export                  # + Parquet export for DuckDB
cargo build -p dent8-cli --features postgres,sqlite,identity,witness,export # all
```

Postgres, SQLite, export, and witness stay off by default so the stock binary stays free of
the async sqlx, Arrow/Parquet, and witness stacks. The authority registry, identity
trust/grants/keys, and witness keys are **host-local config**, independent of the event backend
— a Postgres deployment still reads these from the local filesystem, so provision them per
instance. Set `DENT8_REQUIRE_AUTHORITY=1` and `DENT8_REQUIRE_IDENTITY=1` for deployments that
must fail closed if registry or identity material was not provisioned.

## Signed source identity flow

Signed identity proves source-key possession at the CLI/MCP boundary. It is not a login
server: the operator holds an issuer key and issues grants to agent/source keys.

```sh
dent8 init --agent codex
set -a
. .dent8/env
. .dent8/identity.env
set +a
dent8 doctor --source source:codex --write-check
```

`dent8 init --identity` and `dent8 init --agent <profile>` create or reuse an operator issuer
key outside the project bundle, then write the normal env plus `.dent8/trust.json`, a
per-source key under `.dent8/identities/`, a grant under `.dent8/grants/`, and
`.dent8/identity.env`. Agent profiles are `codex`, `claude-code`, `cursor`, `grok-build`,
`gemini`, `cascade`, and `hecate`. `dent8 identity bootstrap` remains available for manual
rotation/custom layouts. It creates or reuses an operator issuer key outside the project bundle
(`--issuer-key`, `DENT8_ISSUER_KEY`, `$XDG_CONFIG_HOME/dent8/issuer.key`, or
`$HOME/.config/dent8/issuer.key`). Bootstrap refuses to write the issuer key inside the bundle
and refuses to overwrite existing project identity material. The manual subcommands
(`issuer-keygen`, `agent-keygen`, `trust-add`, `grant-issue`, `grant-verify`) remain available
when you need custom paths, rotation, expiration, or exact subject scopes.

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

Each agent should have a distinct source key and grant. A shared MCP process can only prove
the single identity whose private key it holds. See
[ADR 0012](decisions/0012-signed-source-identity.md) for the security model and limits.

See [STATUS.md](STATUS.md) for what each surface does, and [storage.md](storage.md) for the
backend design.
