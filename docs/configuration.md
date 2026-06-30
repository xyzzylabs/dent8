# Configuration reference

dent8 is configured by **environment variables** (for paths and the backend) and **Cargo
features** (for opt-in capabilities). This is the single source of truth for both; the stock
binary needs none of them (it uses a local file log).

## Environment variables

| Variable | Used by | Default | Purpose |
|---|---|---|---|
| `DENT8_LOG` | CLI / MCP (file backend) | `./dent8-log.jsonl` | Path to the JSON-lines dev-store log. |
| `DENT8_STORE_URL` | CLI / MCP (an async backend feature) | *(unset → file backend)* | A backend store URL, dispatched by **scheme** to the matching async backend (`postgres://…` needs `--features postgres`). When set, reads/writes go to that operational store instead of the file log. Set without a matching backend feature → a clear build-hint error. |
| `DENT8_DATABASE_URL` | CLI / MCP | *(unset)* | Back-compat **alias** for `DENT8_STORE_URL` (used when the latter is unset). |
| `DENT8_AUTHORITY` | `dent8 authority` + every write | `./dent8-authority.json` | Path to the source→authority **ceiling** registry. Enforcement is **opt-in**: it activates only once this file exists (created by `dent8 authority add`); then it is deny-by-default. |
| `DENT8_REQUIRE_AUTHORITY` | every write | *(unset / false)* | Fail-closed deployment guard. When true (`1`, `true`, `yes`, or `on`), a missing authority registry is an error instead of permissive dev mode. |
| `DENT8_WITNESS_KEY` | `dent8 witness` (`--features witness`) | `./dent8-witness.key` | Path to the Ed25519 **signing** key (hex, `0600`). `<path>.pub` holds the public key. |
| `DENT8_WITNESS_PUBKEY` | `dent8 witness verify` | `<DENT8_WITNESS_KEY>.pub` | Override the public key used for verification (e.g. when verifying a published head without the signing key). |
| `DENT8_WITNESS_LOG` | `dent8 witness sign` / `verify` / `serve` | `./dent8-witness.jsonl` | Path to the appended log of signed tree heads. |
| `DATABASE_URL` | the adapter's integration tests only | *(unset → tests skip)* | A throwaway `postgres://…` for `cargo test -p dent8-store-postgres --features adapter`. **Not** read by the CLI/MCP — that is `DENT8_DATABASE_URL`. |

The bundled [`compose.yml`](../compose.yml) brings up a throwaway `postgres:16`; the matching
URL is in [`.env.example`](../.env.example) (`postgres://postgres:dent8@localhost:5432/dent8`).

## Cargo features (on `dent8-cli`)

| Feature | Adds | Default? |
|---|---|---|
| *(none)* | the full firewall + lifecycle over the **file dev store**, plus `eval`, `verify`, `conflicts`, `authority`, MCP | yes |
| `postgres` | the operational **transactional Postgres backend** (sqlx + a tokio bridge), selected by `DENT8_DATABASE_URL` | no |
| `witness` | the `dent8 witness` Ed25519 signed-tree-head commands | no |
| `export` | the `dent8 export` analytical lane — the log to **Parquet** for offline DuckDB analysis (pulls the arrow/parquet stack) | no |

```sh
cargo build -p dent8-cli                                    # stock: file store only
cargo build -p dent8-cli --features postgres                # + Postgres backend
cargo build -p dent8-cli --features witness                 # + witness
cargo build -p dent8-cli --features export                  # + Parquet export for DuckDB
cargo build -p dent8-cli --features postgres,witness,export # all
```

Off by default so the stock binary stays free of the async sqlx and signature stacks. The
authority registry and witness keys are **host-local config**, independent of the event
backend — a Postgres deployment still reads `DENT8_AUTHORITY` / the witness key from the local
filesystem, so provision them per instance. Set `DENT8_REQUIRE_AUTHORITY=1` for deployments
that must fail closed if the registry was not provisioned.

See [STATUS.md](STATUS.md) for what each surface does, and [storage.md](storage.md) for the
backend design.
