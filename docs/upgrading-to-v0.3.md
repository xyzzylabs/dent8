# Upgrading to dent8 v0.3

dent8 v0.3.0 is a breaking pre-1.0 release. It introduces the `fact` vocabulary
and canonical event format v2:

- Rust and JSON names move from claim to fact (`claim_id` -> `fact_id`,
  `ClaimEvent` -> `FactEvent`, and related type/API names).
- Stored fact ids use `fact:...` instead of `claim:...`.
- `authority` serializes as lowercase (`"high"`, `"canonical"`) to match CLI input.
- `CANON_VERSION` is now `2`, so each event's hash input changes.

There is no in-place v1 -> v2 event-log migration. Treat v0.2 logs as archived
evidence, then start a fresh v0.3 log and re-ingest facts from their original
sources.

## Who Can Upgrade Directly

- A new or empty dent8 setup can install v0.3 and run `dent8 init` normally.
- A setup where dent8 facts are reproducible from source-of-truth files, issue
  trackers, configs, or operator notes can start a new v0.3 log and re-assert
  those facts.
- Automation that only shells out to human text output may need no code change, but
  should still validate `dent8 doctor` and `dent8 verify`.

Do not point v0.3 at a production v0.2 file, SQLite database, or Postgres event log
and expect the old log to verify. The format change is intentionally hash-breaking.

## Before Upgrading

Back up the old store and config:

```sh
cp -a .dent8 .dent8.v0.2.backup
```

For Postgres-backed deployments, take a database backup too:

```sh
pg_dump "$DATABASE_URL" > dent8-v0.2.sql
```

If you need an inventory of the old facts, run the old binary before replacing it:

```sh
dent8 facts list --include-diagnostics
dent8 explain repo:my-project repo.database
dent8 replay repo:my-project repo.database
```

If the local binary has already been replaced, install the older CLI into a
temporary root and run it against the backed-up env/store:

```sh
cargo install dent8 --version 0.2.0 --root /tmp/dent8-0.2
/tmp/dent8-0.2/bin/dent8 facts list --include-diagnostics
```

## Upgrade a Local Agent Setup

Start a fresh v0.3 bundle for the agent and backend you want to use:

```sh
dent8 init --agent codex --store sqlite --identity --install-mcp
dent8 doctor --agent codex --write-check
```

For a repo-local no-Cargo-startup MCP binary, rebuild the isolated target and refresh
the installed MCP config:

```sh
CARGO_TARGET_DIR=.dent8/target-sqlite cargo build -p dent8-cli --features sqlite
dent8 mcp install --agent codex --local-bin
dent8 doctor --agent codex --mcp-local-bin --write-check
```

Then re-assert only facts you can justify from source. Prefer carrying provenance in
the source/authority/identity fields instead of copying stale summaries wholesale.

## Automation Changes

Machine consumers should check these v0.3 changes:

- CLI `--output json` emits success and error objects on stdout. Use the process exit
  code plus the object's `status`.
- Successful write status is `accepted` (`contradict` is `contested`), not the old
  generic `ok`.
- `verify` reports `integrity_issues` for a broken chain.
- Every JSON payload includes `schema_version`.
- MCP write/read tools take `subject: "kind:key"` instead of separate
  `subject_kind` / `subject_key`.
- MCP `derive` takes `basis: "kind:key"` and `basis_predicate`; the CLI flag is
  `derive --basis`, not `--from`.

## After Upgrading

Run the integrity and setup checks:

```sh
dent8 verify
dent8 doctor --agent codex --write-check
```

For multi-agent local setups, repeat doctor for each configured agent:

```sh
dent8 doctor --agent cursor --write-check
dent8 doctor --agent claude-code --write-check
```

If `doctor` reports an old MCP command or stale local binary, run the suggested
`dent8 mcp install ...` repair command, then re-run doctor.
