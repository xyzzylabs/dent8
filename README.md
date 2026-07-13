<p align="center">
  <img src="https://raw.githubusercontent.com/xyzzylabs/dent8/main/assets/logo.svg" width="88" alt="dent8 — a crenellated octagon holding one fact">
</p>

# dent8

**A memory firewall for coding agents.** dent8 sits between your agent and its long-term
memory and refuses the writes that quietly corrupt it — a low-authority source overwriting a
trusted fact, a stale value resurrecting itself, a poisoned source tainting everything
derived from it. Every fact it keeps carries where it came from, and you can replay exactly
*why* the agent believes it.

**New here?** First fact in **under 2 minutes** once `dent8` is installed — see the
**[documentation site](https://xyzzylabs.github.io/dent8/)** or
[Getting Started](docs/getting-started.md), or take the path below. Timed acceptance:
`./examples/on-ramp/demo.sh`.

![dent8 firewall walkthrough: a trusted fact is asserted, a low-authority override is rejected by the firewall, and explain replays the auditable receipt over a verified hash chain.](https://raw.githubusercontent.com/xyzzylabs/dent8/main/demo.gif)

Most agent memory is *newest-write-wins*: the last thing written becomes the truth. That's
how a scraped web page silently overwrites a decision your team made, and how a retracted
source leaves its conclusions behind. dent8 treats memory as an **append-only log of fact
events** — each carrying provenance, authority, and evidence — and **arbitrates every write**
against what is already believed.

## First fact (under 2 minutes)

Install once (release binary is fastest; `cargo install dent8-cli --locked` also works), then in
any git repo:

```sh
dent8 init --source source:owner
set -a; . .dent8/env; set +a
dent8 assert repo:myproj deploy_target production --authority high --source source:owner
dent8 explain repo:myproj deploy_target
```

No services. With a binary already on `PATH`, wall time is typically **under a second**; the
2-minute budget is for install + reading the receipt. Full walkthrough and agent wiring:
[Getting Started](docs/getting-started.md).

## The 30-second proof

```sh
dent8 eval
```

`dent8 eval` runs an adversarial corpus against the real firewall **and** a recency-only
baseline (newest-write-wins — the resolution Zep/Graphiti use), then the same axes against a
Mem0-style mutate-in-place model:

| attack | firewall | recency-only (Zep) | mutate-in-place (Mem0) |
|---|---|---|---|
| low-authority memory injection (MINJA) | blocked ✓ | **compromised** | **compromised** |
| authority laundering | blocked ✓ | **compromised** | **compromised** |
| canonical contradiction | blocked ✓ | **compromised** | **compromised** |
| Sybil corroboration | blocked ✓ | **compromised** | **compromised** |
| poisoned-source retraction | blocked ✓ | **compromised** | **compromised** |

Five for five against both peer models. The last one is the tell: retract a poisoned source
and dent8 flags every fact *derived* from it — a dependency cascade neither recency-only nor
mutate-in-place memory structurally expresses. Details: [evals.md](docs/evals.md).

## See the firewall reject a write

```sh
# A low-authority source tries to overwrite the fact — rejected: Low can't override High.
dent8 supersede repo:myproj deploy_target staging --authority low --source source:owner

# Still production, with a receipt (survived: 1 challenge).
dent8 explain repo:myproj deploy_target

# Derive from it, retract the basis — verify flags the derivative tainted.
dent8 derive service:api target production --basis repo:myproj deploy_target --authority high --source source:owner
dent8 retract repo:myproj deploy_target --authority high --source source:owner
dent8 verify
```

For binaries, pinned installs, and feature builds, see [Installation](docs/installation.md).
From a clone: **`DENT8="cargo run -q -p dent8-cli --" ./examples/firewall/demo.sh`**.

## See your memory

```sh
dent8 ui        # opens a local, read-only dashboard in your browser
```

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/ui-memory.png">
  <source media="(prefers-color-scheme: light)" srcset="docs/assets/ui-memory-light.png">
  <img alt="The dent8 ui Memory view — believed facts shown as cards; the contested cache fact shows both rival values inline." src="docs/assets/ui-memory.png">
</picture>

The stock binary serves its own control plane — no install, no services, bound to
`127.0.0.1`. **Memory** shows the believed facts as cards (the value large, a freshness
bar down the side, contested facts showing both rival values inline); click one for the
full integrity receipt and replay timeline. **What-if** re-folds the log under a different
trust policy and shows now-vs-under-policy. **Health** rolls up integrity, witness
coverage, doctor, and native-memory audit behind one banner. Light/dark, deep-linkable
tabs. It is read-only *by construction* — every value comes through the same firewall path
as the CLI, so the dashboard can never become a write bypass.

## The fact base, on this repo

dent8 dogfoods itself. The facts every agent (and human) working on dent8 should share —
MSRV, the CI gates, commit conventions, the authority profile, the eval tallies, the
roadmap — live in the firewall, not in a hand-maintained `CLAUDE.md` that silently drifts.
Rebuild the store from the committed seed, then ask for the context pack:

```sh
scripts/dogfood-seed.sh    # rebuilds .dent8/ from scripts/dogfood-facts.jsonl (15 facts, source:human @ High)
dent8 context              # the believed facts, with authority and provenance
```

`dent8 context` emits a markdown pack ready to inject at session start. Below is the pack from this repo's own store, curated for the README — 6 of the 15 facts, reordered by relevance, with the trailing `ref:` provenance field trimmed for width. Run `dent8 context` for the verbatim pack (all 15 facts, each with its `ref:`).

````markdown
## Project facts (dent8)

Currently-believed facts from the dent8 memory firewall. Each carries its authority and
source; verify one with `dent8 explain <subject> <predicate>`.

### repo:dent8

- `gate.test` = "cargo test --workspace (CI job: fmt + clippy + test in .github/workflows/ci.yml)"  (authority: high, source: source:human)
- `gate.fmt` = "cargo fmt --all -- --check"  (authority: high, source: source:human)
- `gate.clippy` = "cargo clippy --workspace --all-targets -- -D warnings (warnings are errors)"  (authority: high, source: source:human)
- `commit.attribution` = "no Co-Authored-By trailers and no AI attribution in commits or PRs"  (authority: high, source: source:human)

### policy:authority

- `default.profile` = "human > CI > agent: source:human max=high, source:ci max=medium, source:agent max=low; …"  (authority: high, source: source:human)

### eval:corpus

- `core.tally` = "47 adversarial cases / 10 attack classes: 16 blocked by arbitration, 4 detect-only, 27 out-of-model …"  (authority: high, source: source:human)
````

Every line is provenance-stamped and replayable — `dent8 explain repo:dent8 gate.clippy`
shows who asserted the lint gate and exactly why it is believed. When a fact changes, an
agent queues a proposal to `.dent8/proposals.jsonl` and a `SessionEnd`-style hook flushes it
through the firewall, so the shared fact base updates without anyone hand-editing a rules
file. **Four agents develop dent8 against this one store, each with its own signed source
identity:** Claude Code and Grok Build run the full hook loop (`SessionStart` →
`dent8 context`, `SessionEnd` → `dent8 capture`; Claude's wiring is tracked in
[`.claude/settings.json`](.claude/settings.json)), and Codex and Cursor read it through the
tracked [`AGENTS.md`](AGENTS.md) contract — all four via `dent8 mcp serve` with per-agent
grants (`dent8 agent add`). The setup story and its rough edges are in
[docs/dogfooding-notes.md](docs/dogfooding-notes.md).

## How it works

The primitive is a **fact event**, not a generic memory item. Every write that enters dent8 is
arbitrated at the append boundary (`EventStore::append`) before it is persisted:

- **Authority-weighted arbitration** — a write cannot override a fact of higher authority, and
  dent8 checks the *actual* authority behind a revision, not just the authority claimed by the
  event, so laundering a weak fact through a high-authority-looking event is caught.
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
dent8 doctor --all-agents --write-check    # check every installed agent profile in this bundle
```

Shortcuts exist for `codex`, `claude-code`, `cursor`, `gemini`, `grok-build`, `cascade`, and
`hecate`. Several agents can share one belief base by using one globally installed `dent8`
binary and one shared `DENT8_STORE_URL`, while each profile keeps its own signed source
identity:

```sh
dent8 init --agent codex --store sqlite --install-mcp
dent8 agent add --agent claude-code
dent8 agent add --agent cursor
dent8 doctor --all-agents --write-check
```

Because it speaks MCP, **any MCP-capable client** works — the shortcuts above, Claude
Desktop, or your own. For code-first agent frameworks there are two paths:

- **First-class tools** — native tool objects built directly on the SDK: no MCP subprocess to
  keep in sync, the agent writes at a configured authority it *can't* escalate (source and
  authority are deployment config, not tool arguments), and refused writes come back as
  results it reads and adapts to.
  - **Python** — LangChain (`pip install "dent8[langchain]"`, `from dent8.langchain import
    dent8_tools`) and LlamaIndex (`pip install "dent8[llamaindex]"`, `from dent8.llamaindex
    import dent8_tools`). See [examples/langchain/](examples/langchain/) and
    [examples/llamaindex/](examples/llamaindex/).
  - **TypeScript** — the Vercel AI SDK (`import { dent8Tools } from "dent8/ai"`) and
    LangChain.js (`from "dent8/langchain"`), out of the `npm i dent8` package. See
    [examples/vercel-ai-sdk/](examples/vercel-ai-sdk/) and
    [examples/langchain-js/](examples/langchain-js/).
- **Over MCP or the SDKs** — any other framework (Mastra, …) connects to `dent8 mcp serve` or
  drives the thin `pip install dent8` / `npm i dent8` SDKs directly — see
  [examples/mcp/](examples/mcp/).

To close the loop without MCP, wire the session bookends into provider hooks: a
`SessionStart` hook injects `dent8 context` (the believed facts, with authority and
provenance) and a `SessionEnd` hook flushes agent-queued proposals with
`dent8 capture .dent8/proposals.jsonl --consume` — see
[docs/context-capture.md](docs/context-capture.md) and
[examples/agent-hooks/claude-code/](examples/agent-hooks/claude-code/).

### Share one belief base over a daemon

Instead of one dent8 process per agent, run a **per-user daemon** and point writes at it:

```sh
set -a
. .dent8/env
. .dent8/identity-codex.env
set +a
dent8 daemon serve                       # foreground; default per-user Unix socket
```

In another shell with the same env loaded:

```sh
export DENT8_DAEMON_SOCKET="${XDG_RUNTIME_DIR:-${TMPDIR:-/tmp}}/dent8/dent8.sock"
dent8 daemon status                      # check reachability and write authentication
dent8 assert repo:app deploy_target production
```

For a stdio-only MCP client that should use the same daemon, configure it to run:

```sh
dent8 mcp proxy
```

The installer can write that proxy command into known agent configs:

```sh
dent8 mcp install --agent codex --use-daemon
# or pin a non-default socket:
dent8 mcp install --agent codex --daemon-socket /path/to/dent8.sock
```

The proxy authenticates to the daemon once, then forwards the client's MCP frames over that
connection.

Every connection proves the daemon-configured source identity with a signed session challenge,
and the daemon arbitrates and **attests each write as that source** — so a daemon-written fact
re-verifies offline exactly like a local one, and many processes build one firewalled belief
base over one transport. Reads stay local. Run the whole path with
**`DENT8="cargo run -q -p dent8-cli --" ./examples/daemon/demo.sh`** (see
[examples/daemon/](examples/daemon/)). Today each daemon process is single-source: every
client connection must prove the same source key the daemon holds, so this shares *one*
identity across processes. Separate agent identities should use separate MCP subprocesses
against the same backend, or separate daemon instances.

## Status

dent8 is **pre-1.0 and experimental** — the CLI, the library API, the on-disk event format, and
the Postgres storage schema may all still change between minor versions. The event format is
**versioned** by `CANON_VERSION`, mixed into every hash so encodings can never collide. v0.3
introduces **format v2** (the `fact` vocabulary — `claim_id` → `fact_id`, lowercase `authority`);
this is a deliberate one-time pre-1.0 break, so a v1 log does not carry forward and must be
re-ingested from source. See [the v0.3 upgrade note](docs/upgrading-to-v0.3.md). From v2 onward
the intent is again additive-only (new fields stay optional and out of the hash), but that
stability is not guaranteed until 1.0.
[docs/STATUS.md](docs/STATUS.md) is the single source of truth for what is runnable vs.
library-only vs. design-only. In brief, runnable today:

- The full belief lifecycle — `assert` / `supersede` / `retract` / `contradict` / `reinforce`
  / `expire` / `derive` / `explain` / `replay` — plus the operator surfaces `facts list`,
  `snapshot`, `verify`, `conflicts`, `eval`, and `export`, and **`whatif`**
  policy-counterfactual replay (re-fold the same log under a different trust policy and diff
  what would be believed — deterministic, zero model calls).
- The session capture/inject loop: `dent8 context` emits the currently-believed facts as a
  markdown (or JSON) context pack for session-start injection, `dent8 capture` flushes
  structured fact proposals from a session back through the firewall, and
  `dent8 authority defaults` seeds the out-of-the-box **human > CI > agent** trust profile
  ([docs/context-capture.md](docs/context-capture.md)).
- Three backends behind one contract: a local **file** dev log (default), embedded **SQLite**,
  and a DB-verified transactional **Postgres** adapter (`--features postgres`) — selected by
  `DENT8_STORE_URL`, and **load-tested under contention** (cross-process write leases keep
  parallel writers fair; `scripts/load-test.sh` reproduces it on either backend).
- **Signed identity** with grant history + revocation — source keys live in a `0600` file or
  the **OS keychain** (`keychain:<account>` on macOS/Linux/Windows) — the **witness**
  transparency log, and an MCP server (`dent8 mcp serve`) — all in the stock binary.
- MCP **`resources/subscribe`**: agents get `notifications/resources/updated` pushed when a
  fact stream they depend on changes (from any process sharing the store), instead of
  re-polling `explain`.
- **`dent8 ui`** — a local, read-only debugger/control plane in your browser, served by the
  stock binary: live fact table with freshness badges, per-fact integrity receipts and
  replay timelines, contested facts, and an interactive what-if panel. Read-only by
  construction (every payload comes from the same firewall path as the CLI), bound to
  127.0.0.1.
- MCP `runtime_status` diagnostics and one-shot `snapshot` output so agents can see the live
  binary, store, identity, authority, witness configuration, facts, verify status, and
  conflicts before trusting a long-running server.
- Machine-readable `--output json` across the read/write/audit surface, shell completions, and
  Parquet **export** for offline DuckDB analysis (`--features export`).
- Native memory/rules interop: audit with `dent8 native scan --agent <profile>` and receipt
  verification with `dent8 native reconcile --agent <profile>` (MCP exposes the same audits as
  `native_scan` / `native_reconcile`), plus `dent8 import <FILE>` to pull durable facts from a
  native memory/rules file *through the firewall* and `dent8 export --target` to project
  believed facts back into one.

Run `dent8 --help` for the full command surface. The stock binary needs no services; opt-in
builds add a Postgres backend (`--features postgres`) and Parquet export (`--features export`).
The future desktop app is scoped as a debugger/control plane over these same surfaces, not a
separate memory provider ([ADR 0020](docs/decisions/0020-desktop-debugger-control-plane.md)).

*(Origin: the* dentate gyrus*, the hippocampal structure associated with pattern separation —
keeping similar memories distinct.)*

## Documentation

**Start here**
- [Installation](docs/installation.md) — cargo, release binaries, and first setup
- [Implementation Status](docs/STATUS.md) — single source of truth for what is built
- [Configuration](docs/configuration.md) — every env var and Cargo feature
- [Dogfood Workflow](docs/dogfood.md) — how this repo uses dent8 as its own project memory
- [Context & Capture](docs/context-capture.md) — the session inject/capture loop and the
  default authority profile
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
DENT8="cargo run -q -p dent8-cli --" ./examples/firewall/demo.sh

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
