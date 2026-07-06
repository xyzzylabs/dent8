# Installation

The published CLI package is `dent8` and the installed binary is `dent8`. The current
release is `0.3.2`.

## crates.io

Install the stock binary from crates.io:

```sh
cargo install dent8 --locked
dent8 --version
```

For a reproducible install pinned to this release:

```sh
cargo install dent8 --version 0.3.2 --locked
```

The stock binary includes the file dev store, embedded SQLite, signed identity, witness
commands, MCP, the local Unix-socket daemon, and the normal CLI surfaces. Optional feature
builds are available when you need heavier integrations:

```sh
cargo install dent8 --features postgres --locked
cargo install dent8 --features export --locked
cargo install dent8 --features postgres,export --locked
```

`postgres` adds the transactional Postgres backend selected by `DENT8_STORE_URL=postgres://...`.
`export` adds the Parquet export lane for DuckDB analysis.

## GitHub Release Binaries

Each tagged release publishes prebuilt archives for:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`

The archives are built with `postgres,sqlite`; Parquet export remains a cargo feature build
because the Arrow/Parquet stack is large and less common.

Example for macOS/Linux:

```sh
version=v0.3.2
target=aarch64-apple-darwin
base="https://github.com/xyzzylabs/dent8/releases/download/$version"

curl -LO "$base/dent8-$version-$target.tar.gz"
curl -LO "$base/dent8-$version-$target.tar.gz.sha256"
shasum -a 256 -c "dent8-$version-$target.tar.gz.sha256"
tar -xzf "dent8-$version-$target.tar.gz"
mkdir -p "$HOME/.local/bin"
install -m 0755 "dent8-$version-$target/dent8" "$HOME/.local/bin/dent8"
dent8 --version
```

For Windows, download `dent8-v0.3.2-x86_64-pc-windows-msvc.zip` and its `.sha256`, verify
the checksum, then put `dent8.exe` on `PATH`.

## First Project

For one local project, initialize a signed SQLite-backed setup:

```sh
dent8 init --store sqlite --identity --source source:owner
set -a
. .dent8/env
. .dent8/identity-owner.env
set +a
dent8 doctor --write-check
```

For an agent profile, let dent8 create the signed identity and patch the MCP config:

```sh
dent8 init --agent codex --store sqlite --install-mcp
dent8 doctor --agent codex --write-check
```

Known profiles are `codex`, `claude-code`, `cursor`, `gemini`, `grok-build`, `cascade`, and
`hecate`.

## One Belief Base, Many Agents

The recommended v0 multi-agent setup is one globally installed `dent8` binary and one shared
backend, with one stdio MCP server subprocess per agent identity:

```sh
dent8 init --agent codex --store sqlite --install-mcp
dent8 agent add --agent claude-code
dent8 agent add --agent cursor
dent8 doctor --all-agents --write-check
```

Each agent gets its own source key/grant and MCP config, but all profiles point at the same
`DENT8_STORE_URL`, authority registry, trust registry, active-grant registry, and grant log.
Use SQLite for local no-server dogfooding; use Postgres for heavier concurrency or team
deployments.

The local daemon is a second v0 shape for many local processes that share one source identity:

```sh
set -a
. .dent8/env
. .dent8/identity-codex.env
set +a
dent8 daemon serve
```

In another shell:

```sh
set -a
. .dent8/env
. .dent8/identity-codex.env
set +a
export DENT8_DAEMON_SOCKET="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/dent8/dent8.sock"
dent8 daemon status
dent8 assert person:alice favorite_drink tea
```

For a stdio-only MCP client that should use the running daemon instead of launching its own
store-backed server, use the bridge command:

```sh
dent8 mcp proxy
```

Known agent configs can be patched to use that bridge:

```sh
dent8 mcp install --agent codex --use-daemon
# or pin a non-default daemon socket:
dent8 mcp install --agent codex --daemon-socket /path/to/dent8.sock
```

`mcp proxy` reads/writes normal stdio MCP on one side, authenticates to the daemon using the
current `DENT8_GRANT` / `DENT8_IDENTITY_KEY`, and forwards frames over the daemon socket.
After installing a proxy config, `dent8 doctor --agent <profile> --write-check` probes that
daemon socket with the generated agent identity and prints the exact
`dent8 daemon serve --socket ...` command to run if the daemon is not reachable.

Authenticated daemon connections can write through the same firewall and receive
offline-verifiable write attestations. The daemon is still per-user and single-source in v0:
use separate stdio MCP subprocesses, or separate daemon instances, when distinct agent
provenance matters. Remote HTTP/streamable MCP is future work, not part of the `0.3.2`
release.
