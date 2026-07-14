# Release checklist

This is the release gate. Keep it small and mechanical: the goal is to ship a
correct, installable memory-integrity tool, not to add new mechanisms during release prep.

## Package shape

- Published **library** package: `dent8` (`crates/dent8`) — the facade crate (`cargo add dent8`).
- Published **CLI** package: `dent8-cli` (`crates/dent8-cli`); the installed binary is still `dent8`.
- Default features: signed source identity + embedded SQLite. The stock install is enough for
  local file-backed use and no-server multi-agent dogfooding via `sqlite://`.
- Opt-in features: `postgres`, `export`.

Install commands:

```sh
cargo install dent8-cli --locked
cargo install dent8-cli --features postgres --locked
cargo install dent8-cli --features export --locked
```

To test unreleased `main` ahead of a release, use the Git source:

```sh
cargo install --git https://github.com/xyzzylabs/dent8 dent8-cli --locked
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
cargo clippy -p dent8-cli --no-default-features --all-targets -- -D warnings
cargo test -p dent8-cli --no-default-features
cargo clippy -p dent8-cli --features postgres --all-targets -- -D warnings
cargo clippy -p dent8-cli --features export --all-targets -- -D warnings
cargo test -p dent8-export
```

Check packaging before a tag. This is also in CI now, so path/version metadata and
publishable file lists cannot drift unnoticed:

```sh
cargo package --workspace --no-verify --locked
```

Run the release acceptance path:

```sh
scripts/release-acceptance.sh
```

To include the witness smoke (the witness is in the stock binary):

```sh
cargo build -p dent8-cli
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
  cargo test -p dent8-cli --features postgres --test cli_usage \
    concurrent_cli_asserts_on_shared_postgres_store_get_unique_event_ids
DATABASE_URL=postgres://postgres:dent8@localhost:5432/dent8 \
  cargo test -p dent8-store-postgres --features adapter
docker compose down
```

## Packaging

All workspace crates that depend on another dent8 crate must specify both `path` and a
`version` matching the current workspace version (currently `0.8.0`) so crates.io packaging
can replace local paths with published versions.

Fast manifest/package check:

```sh
cargo package --workspace --no-verify
```

### crates.io publishes automatically on tag (Trusted Publishing)

Pushing a `vX.Y.Z` tag runs the `crates` job in
[`.github/workflows/release.yml`](../.github/workflows/release.yml) — the same tokenless model
PyPI and npm already use. `rust-lang/crates-io-auth-action` exchanges the run's OIDC identity
for a short-lived crates.io token (no `CARGO_REGISTRY_TOKEN` in GitHub secrets), then
`cargo publish --workspace` uploads all eight crates in dependency order, waiting for each to
index before its dependents.

The binary release job also emits GitHub artifact attestations for every archive via
`actions/attest@v4` (SLSA build provenance, signed through Sigstore/GitHub OIDC) before it uploads
the `.tar.gz` / `.zip` and `.sha256` files. Consumers can verify the archive's provenance with
`gh attestation verify <archive> --repo xyzzylabs/dent8`; the checksum still catches accidental
download corruption, while the attestation answers "was this archive built by the release
workflow for this repo/tag?"

**One-time setup — required per crate before this works.** Enable Trusted Publishing on
crates.io for **each** of `dent8`, `dent8-cli`, `dent8-core`, `dent8-evals`, `dent8-export`,
`dent8-store`, `dent8-store-postgres`, `dent8-store-sqlite` (the crate must already exist —
all eight do). For each: crates.io → the crate → **Settings → Trusted Publishing → Add**,
GitHub, with

- Repository owner and name: `xyzzylabs/dent8`
- Workflow filename: `release.yml`
- Environment: `crates-io`

One OIDC exchange then authorizes the whole workspace. Until every crate is configured, the
`crates` job fails on the crate that isn't (the PyPI/npm jobs are independent and still
publish); finish the setup, then re-run the failed job.

### Manual publish (fallback)

To publish by hand — before Trusted Publishing is set up, or to recover a partial run — the
same `cargo publish --workspace` works locally with a `cargo login` token. Or one crate at a
time in dependency order, because a downstream crate cannot verify against crates.io until its
internal dependencies are already published:

```sh
cargo publish -p dent8-core --dry-run
cargo publish -p dent8-core

cargo publish -p dent8-store --dry-run
cargo publish -p dent8-store

cargo publish -p dent8 --dry-run
cargo publish -p dent8

cargo publish -p dent8-evals --dry-run
cargo publish -p dent8-evals
cargo publish -p dent8-export --dry-run
cargo publish -p dent8-export
cargo publish -p dent8-store-postgres --dry-run
cargo publish -p dent8-store-postgres
cargo publish -p dent8-store-sqlite --dry-run
cargo publish -p dent8-store-sqlite

cargo publish -p dent8-cli --dry-run
cargo publish -p dent8-cli
```

After publishing (either path), verify the install in a clean temp directory. Use the rustup
proxy so cargo and rustc are paired — a bare toolchain cargo can desync rustc and false-fail
with `Unrecognized option: 'check-cfg'`:

```sh
rustup run stable cargo install dent8-cli --version 0.8.0 --locked --root "$(mktemp -d)"
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
