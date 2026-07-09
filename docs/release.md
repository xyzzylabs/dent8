# Release checklist

This is the release gate. Keep it small and mechanical: the goal is to ship a
correct, installable memory-integrity tool, not to add new mechanisms during release prep.

## Package shape

- Published CLI package: `dent8`; installed binary: `dent8`.
- Source path for the CLI package stays `crates/dent8-cli`.
- Default features: signed source identity + embedded SQLite. The stock install is enough for
  local file-backed use and no-server multi-agent dogfooding via `sqlite://`.
- Opt-in features: `postgres`, `export`.

Install commands:

```sh
cargo install dent8 --locked
cargo install dent8 --features postgres --locked
cargo install dent8 --features export --locked
```

To test unreleased `main` ahead of a release, use the Git source:

```sh
cargo install --git https://github.com/xyzzylabs/dent8 dent8 --locked
```

## Preflight

Run the normal correctness gate:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run the feature-shape gates that CI keeps honest:

```sh
cargo clippy -p dent8 --no-default-features --all-targets -- -D warnings
cargo test -p dent8 --no-default-features
cargo clippy -p dent8 --features postgres --all-targets -- -D warnings
cargo clippy -p dent8 --features export --all-targets -- -D warnings
cargo test -p dent8-export
```

Run the release acceptance path:

```sh
scripts/release-acceptance.sh
```

To include the witness smoke (the witness is in the stock binary):

```sh
cargo build -p dent8
DENT8_BIN=target/debug/dent8 DENT8_EXPECT_WITNESS=1 scripts/release-acceptance.sh
```

The script initializes a throwaway project with the Codex profile, signed identity, a stock
SQLite backend, and the default project-local Codex MCP config; then it runs
`doctor --agent --write-check`, `doctor --all-agents --write-check`, `assert`, `facts list`,
`explain`, and `verify`. It also exercises the witness smoke
(`keygen -> sign -> verify -> publish -> verify-published`), since the witness is a stock
command.

Run the live Postgres gate when preparing a release locally:

```sh
docker compose up -d --wait
DATABASE_URL=postgres://postgres:dent8@localhost:5432/dent8 \
  cargo test -p dent8 --features postgres --test cli_usage \
    concurrent_cli_asserts_on_shared_postgres_store_get_unique_event_ids
DATABASE_URL=postgres://postgres:dent8@localhost:5432/dent8 \
  cargo test -p dent8-store-postgres --features adapter
docker compose down
```

## Packaging

All workspace crates that depend on another dent8 crate must specify both `path` and a
`version` matching the current workspace version (currently `0.5.0`) so crates.io packaging
can replace local paths with published versions.

Fast manifest/package check:

```sh
cargo package --workspace --no-verify
```

Publish/dry-run in dependency order, because downstream crates cannot verify against crates.io
until their internal dependencies are already published:

```sh
cargo publish -p dent8-core --dry-run
cargo publish -p dent8-core

cargo publish -p dent8-store --dry-run
cargo publish -p dent8-store

cargo publish -p dent8-evals --dry-run
cargo publish -p dent8-evals
cargo publish -p dent8-export --dry-run
cargo publish -p dent8-export
cargo publish -p dent8-store-postgres --dry-run
cargo publish -p dent8-store-postgres
cargo publish -p dent8-store-sqlite --dry-run
cargo publish -p dent8-store-sqlite

cargo publish -p dent8 --dry-run
cargo publish -p dent8
```

After publishing, verify the install path in a clean temp directory:

```sh
cargo install dent8 --version 0.5.0 --locked
dent8 --version
```

## Operated witness boundary

Do not block a release on a hosted witness service. The release includes the operated recipe:

- [`docs/witness.md`](witness.md) explains writer/signer/monitor roles and JSON monitor output.
- [`examples/witness-operated/`](../examples/witness-operated/) packages the split with Docker
  Compose and systemd examples.

The fact is: dent8 ships the witness primitive (covering both the event log and, as of
v0.2.0, the grant log), retains event- and grant-log heads off-host via
`witness publish`/`verify-published` (`--grants` for the grant lane), and an operated
deployment recipe. The remaining product work is managed infrastructure, monitoring, and
key-rotation automation.
