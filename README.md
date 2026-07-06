# dent8

**A memory firewall for coding agents.** dent8 sits between your agent and its long-term
memory and refuses the writes that quietly corrupt it — a low-authority source overwriting a
trusted fact, a stale value resurrecting itself, a poisoned source tainting everything
derived from it. Every fact it keeps carries where it came from, and you can replay exactly
*why* the agent believes it.

![dent8 firewall walkthrough: a trusted fact is asserted, a low-authority override is rejected by the firewall, and explain replays the auditable receipt over a verified hash chain.](https://raw.githubusercontent.com/xyzzylabs/dent8/main/demo.gif)

Most agent memory is *newest-write-wins*: the last thing written becomes the truth. That's
how a scraped web page silently overwrites a decision your team made, and how a retracted
source leaves its conclusions behind. dent8 treats memory as an **append-only log of fact
events** — each carrying provenance, authority, and evidence — and **arbitrates every write**
against what is already believed.

## The 30-second proof

```sh
cargo install dent8
dent8 eval
```

`dent8 eval` runs an adversarial corpus against the real firewall **and** a recency-only
baseline (newest-write-wins — the resolution Zep/Graphiti use):

| attack | firewall | recency-only baseline |
|---|---|---|
| low-authority memory injection (MINJA) | blocked ✓ | **compromised** |
| authority laundering | blocked ✓ | **compromised** |
| canonical contradiction | blocked ✓ | **compromised** |
| Sybil corroboration | blocked ✓ | **compromised** |
| poisoned-source retraction | blocked ✓ | **compromised** |

Five for five. The last one is the tell: retract a poisoned source and dent8 flags every fact
*derived* from it — a dependency cascade a recency-only store structurally cannot express.

## Try it

```sh
dent8 init --identity --source source:alice # local setup: env + authority + signed identity
set -a; . .dent8/env; set +a
. .dent8/identity-alice.env
dent8 authority add web:scrape low       # let this source write at Low, so the next rejection
                                         # is about arbitration, not a missing grant

# A trusted fact goes in.
dent8 assert repo:myproj deploy_target production

# A low-authority source tries to overwrite it — the firewall rejects it: Low can't override High.
dent8 supersede repo:myproj deploy_target staging --authority low --source web:scrape

# It is still production, and here is the receipt that proves why.
dent8 explain repo:myproj deploy_target

# Derive a fact from it, then retract the source — the derivative is flagged tainted.
dent8 derive service:api target production --basis repo:myproj deploy_target
dent8 retract repo:myproj deploy_target
dent8 verify
```

No services required — dent8 uses a local file log by default. From a clone, watch the whole
firewall path run through the real CLI:
**`DENT8="cargo run -q -p dent8 --" ./examples/firewall/demo.sh`**.

## How it works

The primitive is a **fact event**, not a generic memory item. Every write is arbitrated at
one unbypassable boundary (`EventStore::append`) before it is persisted:

- **Authority-weighted arbitration** — a write cannot override a fact of higher authority, and
  dent8 checks the *actual* authority behind a revision, not just what the event facts (so
  laundering a weak fact through a high-authority-looking event is caught).
- **Paraconsistent contradiction** — disagreement is *kept* as a contested pair rather than
  silently resolved; but contradicting a `canonical` fact is a hard alarm, not a soft contest.
- **Earned entrenchment** — a fact backed by more independent sources, or one that has
  *survived challenges* (rejected attacks are recorded on the fact itself), becomes harder to
  displace.
- **Freshness & valid-time** — facts carry TTLs and asserted validity windows; reads flag
  stale and not-yet-valid facts, and can **time-travel** ("what did we believe last Tuesday,
  and was it fresh then?").
- **Tamper-evidence** — a SHA-256 hash chain over the log, plus an optional off-host
  **witness** (Ed25519 signed tree heads) that catches a history rewrite an internal re-check
  cannot.
- **Signed identity** — optional issuer-signed grants bind a source to a key; every accepted
  write carries a signature `verify` re-checks offline, backed by a hash-chained grant history
  with first-class **revocation**.

Nothing is a black box: `dent8 replay` shows the full event history behind any fact, and
`dent8 verify` re-checks integrity, supersession lineage, and retraction taint.

## Use it with your agent

dent8 speaks MCP, so agents read and write memory *through the firewall*:

```sh
dent8 init --agent codex --install-mcp     # signed identity + MCP config for Codex
dent8 doctor --agent codex --write-check   # smoke the installed server + prove the firewall path
```

Shortcuts exist for `codex`, `claude-code`, `cursor`, `gemini`, `grok-build`, `cascade`, and
`hecate`, and several agents can share one belief base over a common backend. See
[examples/mcp/](examples/mcp/) and the per-agent example directories, or wire dent8 in over
MCP from [LangChain](examples/langchain/) / the [Vercel AI SDK](examples/vercel-ai-sdk/).

### Share one belief base over a daemon

Instead of one dent8 process per agent, run a **per-user daemon** and point writes at it:

```sh
dent8 mcp serve --daemon                 # Unix socket at $XDG_RUNTIME_DIR/dent8/dent8.sock
export DENT8_DAEMON_SOCKET="$XDG_RUNTIME_DIR/dent8/dent8.sock"
dent8 doctor                             # check the daemon is reachable and you authenticate
dent8 assert repo:app deploy_target production
```

Every connection proves its identity with a signed session challenge, and the daemon arbitrates
and **attests each write as that source** — so a daemon-written fact re-verifies offline exactly
like a local one, and many processes build one firewalled belief base over one transport. Reads
stay local. Run the whole path with
**`DENT8="cargo run -q -p dent8 --" ./examples/daemon/demo.sh`** (see
[examples/daemon/](examples/daemon/)). Today the daemon is single-source (it attests with its own
key), so this shares *one* identity across processes; distinct per-agent identities over one
daemon are future work.

## Status

dent8 is **pre-1.0 and experimental** — the CLI, the library API, the on-disk event format, and
the Postgres storage schema may all still change between minor versions. The event format is
**versioned** by `CANON_VERSION`, mixed into every hash so encodings can never collide. v0.3
introduces **format v2** (the `fact` vocabulary — `claim_id` → `fact_id`, lowercase `authority`);
this is a deliberate one-time pre-1.0 break, so a v1 log does not carry forward and must be
re-ingested from source. From v2 onward the intent is again additive-only (new fields stay
optional and out of the hash), but that stability is not guaranteed until 1.0.
[docs/STATUS.md](docs/STATUS.md) is the single source of truth for what is runnable vs.
library-only vs. design-only. In brief, runnable today:

- The full belief lifecycle — `assert` / `supersede` / `retract` / `contradict` / `reinforce`
  / `expire` / `derive` / `explain` / `replay` — plus the operator surfaces `facts list`,
  `verify`, `conflicts`, `eval`, and `export`.
- Three backends behind one contract: a local **file** dev log (default), embedded **SQLite**,
  and a DB-verified transactional **Postgres** adapter (`--features postgres`) — selected by
  `DENT8_STORE_URL`.
- **Signed identity** with grant history + revocation, the **witness** transparency log, and an
  MCP server (`dent8 mcp serve`) — all in the stock binary.
- Machine-readable `--output json` across the read/write/audit surface, shell completions, and
  Parquet **export** for offline DuckDB analysis (`--features export`).

Run `dent8 --help` for the full command surface. The stock binary needs no services; opt-in
builds add a Postgres backend (`--features postgres`) and Parquet export (`--features export`).

*(Origin: the* dentate gyrus*, the hippocampal structure associated with pattern separation —
keeping similar memories distinct.)*

## Documentation

**Start here**
- [Implementation Status](docs/STATUS.md) — single source of truth for what is built
- [Configuration](docs/configuration.md) — every env var and Cargo feature
- [Changelog](CHANGELOG.md)

**Design**
- [Project Brief](docs/project-brief.md) · [Architecture](docs/architecture.md) ·
  [Domain Model](docs/domain-model.md)
- [Belief Revision](docs/belief-revision.md) — dent8's formal identity (the lead lens)
- [Storage & the Event Log](docs/storage.md) · [Interfaces](docs/interfaces.md) ·
  [Naming](docs/naming.md)
- [Decision Records](docs/decisions/)

**Correctness & security**
- [Threat Model](docs/threat-model.md) — exactly what the firewall does and does not defend
- [Formal Verification](docs/formal-verification.md) · [Evaluation Strategy](docs/evals.md)

**Planning & research**
- [Roadmap](docs/roadmap.md) · [Release Checklist](docs/release.md) ·
  [Related Work](docs/related-work.md)
- [Research Dossier](docs/research/dossier.md) ·
  [Open Directions](docs/research/novelty.md) ·
  [Paper Outline](docs/paper/outline.md)

## Development

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
DENT8="cargo run -q -p dent8 --" ./examples/firewall/demo.sh

# The Postgres adapter's integration tests are gated on DATABASE_URL (they skip without one):
docker compose up -d
DATABASE_URL=postgres://postgres:dent8@localhost:5432/dent8 \
  cargo test -p dent8-store-postgres --features adapter
docker compose down
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the fmt/clippy/test gate
across feature combinations and the adapter against a live Postgres service. Security reports:
see [SECURITY.md](SECURITY.md).

## License

Licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
Unless you state otherwise, any contribution you intentionally submit for inclusion in the
work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms.
