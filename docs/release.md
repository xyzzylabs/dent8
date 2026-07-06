# Release checklist

This is the release gate. Keep it small and mechanical: the goal is to ship a
correct, installable memory-integrity tool, not to add new mechanisms during release prep.

## Package shape

- Published CLI package: `dent8`; installed binary: `dent8`.
- Source path for the CLI package stays `crates/dent8-cli`.
- Default features: signed source identity + embedded SQLite. The stock install is enough for
  local file-backed use and no-server multi-agent dogfooding via `sqlite://`.
- Opt-in features: `postgres`, `witness`, `export`.

Install commands:

```sh
cargo install dent8
cargo install dent8 --features witness
cargo install dent8 --features postgres
```

To test unreleased `main` ahead of a release, use the Git source:

```sh
cargo install --git https://github.com/xyzzylabs/dent8 dent8
```

## Preflight

Run the normal correctness gate:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Run the release acceptance path:

```sh
scripts/release-acceptance.sh
```

To include the witness smoke:

```sh
cargo build -p dent8 --features witness
DENT8_BIN=target/debug/dent8 DENT8_EXPECT_WITNESS=1 scripts/release-acceptance.sh
```

The script initializes a throwaway project with the Codex profile, signed identity, a stock
SQLite backend, and an MCP config; then it runs `doctor --agent --write-check`,
`assert`, `facts list`, `explain`, and `verify`. With `DENT8_EXPECT_WITNESS=1`, it also
requires the witness feature and checks `keygen -> sign -> verify -> publish ->
verify-published`.

## Packaging

All workspace crates that depend on another dent8 crate must specify both `path` and a
`version` matching the current workspace version (currently `0.2.0`) so crates.io packaging
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
cargo install dent8
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
