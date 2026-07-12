# Getting Started

dent8 is a **repo-confined, versioned, authority-ranked shared fact base** that your agents
read from and write to instead of hand-editing `CLAUDE.md` / `AGENTS.md`. Every fact carries
where it came from and how much authority it has, so a low-authority write can't silently
overwrite a trusted decision, and nothing goes stale without you seeing it. If your repo has
several agents in flight — Claude Code sessions, CI bots, a teammate's assistant — this is the
one non-stale source of truth they all share.

**Target:** first fact in **under 2 minutes** after `dent8` is on `PATH` (typically under a
second of wall time for `init` → `assert` → `explain`). Timed check:
`./examples/on-ramp/demo.sh`. The sections below expand install, multi-agent wiring, and hooks.

Every command below was run against the real `dent8` v0.7.0 binary; the output blocks are
trimmed but verbatim.

## 0. Sixty-second path (binary already installed)

In a git repository:

```sh
dent8 init --source source:owner
set -a; . .dent8/env; set +a
dent8 assert repo:myproj deploy_target production --authority high --source source:owner
dent8 explain repo:myproj deploy_target
dent8 context
```

`init` creates `.dent8/` (file log + authority registry with human > CI > agent defaults plus
your `source:owner` grant). You do **not** need Postgres, identity, or MCP for the first fact.
Optional smoke: `dent8 doctor --source source:owner --write-check`.

## 1. Install

The stock binary needs no services — it uses a local file log by default. MSRV is Rust
**1.94**.

**Release binaries (recommended, v0.7.0+).** The [releases page][releases] ships prebuilt
archives for five targets, each with a `.sha256` sidecar (built with `postgres,sqlite`):

- `dent8-v0.7.0-aarch64-apple-darwin.tar.gz`
- `dent8-v0.7.0-x86_64-apple-darwin.tar.gz`
- `dent8-v0.7.0-aarch64-unknown-linux-gnu.tar.gz`
- `dent8-v0.7.0-x86_64-unknown-linux-gnu.tar.gz`
- `dent8-v0.7.0-x86_64-pc-windows-msvc.zip`

Download, verify, and install one target (Linux x86_64 shown):

```sh
BASE=https://github.com/xyzzylabs/dent8/releases/download/v0.7.0
curl -LO "$BASE/dent8-v0.7.0-x86_64-unknown-linux-gnu.tar.gz"
curl -LO "$BASE/dent8-v0.7.0-x86_64-unknown-linux-gnu.tar.gz.sha256"
sha256sum -c dent8-v0.7.0-x86_64-unknown-linux-gnu.tar.gz.sha256
tar xzf dent8-v0.7.0-x86_64-unknown-linux-gnu.tar.gz
chmod +x dent8 && sudo mv dent8 /usr/local/bin/
```

**crates.io.** The published crate is `dent8`:

```sh
cargo install dent8-cli --locked
dent8 --version
```

> The `cargo install dent8-cli --version 0.7.0 --locked` path was verified in a clean install
> root as part of cutting v0.7.0 (the built binary reports `dent8 0.7.0`); a from-source build
> takes about **3 minutes**. Only the **Parquet** analytical export
> (`dent8 export <file>.parquet`, for DuckDB) is feature-gated — it is not in the release
> archives and stays a `cargo install dent8-cli --features export --locked` build.
> Native-memory export (`dent8 export --target CLAUDE.md`) and `dent8 import` are stock: they
> ship in every build, including the release binaries, with no extra feature.

Full details, pinned/feature installs, and platform caveats: [Installation](installation.md).

## 2. `dent8 init`

Run `init` at your repo root (it wants an enclosing git repo):

```
$ dent8 init
initialized dent8 in .../.dent8
  authority: .../.dent8/authority.json (granted source:local max=high)
  store: file dev log at .../.dent8/memory.jsonl
  env: .../.dent8/env

Next (first fact in under a minute once `dent8` is on PATH):
  set -a
  . '.../.dent8/env'
  set +a
  dent8 assert repo:myproj deploy_target production --authority high --source source:local
  dent8 explain repo:myproj deploy_target
  dent8 doctor --source source:local --write-check
```

It creates a single `.dent8/` directory with three files:

```
$ ls .dent8
authority.json  env  memory.jsonl
```

`.dent8/env` holds the pointers the CLI reads (`DENT8_AUTHORITY`, `DENT8_LOG`,
`DENT8_REQUIRE_AUTHORITY=1`). Load it once per shell:

```sh
set -a; . .dent8/env; set +a
```

Since PR #12, repo-confined discovery resolves the store and authority registry without
sourcing anything (running any command from inside the repo finds `.dent8/`). Sourcing still
matters for the **enforcement** switch: `DENT8_REQUIRE_AUTHORITY=1` lives in `.dent8/env`, so
load it when you want deny-by-default authority in the current shell.

**`init` auto-seeds the authority profile.** As of PR #12 you no longer run a follow-up
command — `init` writes the **human > CI > agent** ranking (plus the `source:local` init
source at high) straight into `authority.json`:

```
$ dent8 authority list
source:agent  max=low
source:ci  max=medium
source:human  max=high
source:local  max=high
```

**Store discovery is repo-confined.** dent8 finds the nearest ancestor holding a `.git`, then
scans from your cwd up to the repo root for the first `.dent8/` — never above the repo root,
and never above `$HOME`. If you're not inside a git repo, only `./.dent8/` in the cwd is
considered. So `dent8 context` run from a subdirectory resolves the project store instead of
minting a parallel one, and a `.dent8/` planted in an unrelated ancestor (e.g. `/tmp`) is
never silently adopted. Explicit `DENT8_LOG` / `DENT8_STORE_URL` / `DENT8_AUTHORITY` env
overrides bypass discovery entirely.

## 3. Seed real facts

There are three ways to get facts into the base.

**(a) By hand, with `assert`.** Give each fact a subject (`<kind>:<key>`), a predicate, a
value, and an authority + source. `--ttl` accepts human durations (`90d`, `12h`, `30m`):

```
$ dent8 assert repo:dent8 msrv "1.94" --authority high --source source:human --ttl 90d
ACCEPTED  repo:dent8 msrv = "1.94"  (authority=high)
  seq=3  hash=3b2b5821c426…

$ dent8 assert repo:dent8 build_command "cargo build --release" --authority high --source source:human
ACCEPTED  repo:dent8 build_command = "cargo build --release"  (authority=high)
  seq=4  hash=6ddf4ad8324b…
```

The firewall in action — a low-authority agent cannot overwrite the human's MSRV fact (this
exits `1`):

```
$ dent8 supersede repo:dent8 msrv "1.90" --authority low --source source:agent
REJECTED: firewall rejected the write: insufficient authority: low may not override or remove an incumbent of high
  the incumbent recorded the survived challenge (fact.challenge_rejected)
```

**(b) In bulk, from a proposals file, with `capture`.** Write one JSON proposal per line
(`authority` / `source` are optional — an unattributed line lands at `source:agent` @ `low`):

```jsonl
{"subject": "repo:dent8", "predicate": "commit.attribution", "value": "no Co-Authored-By trailers and no AI attribution", "authority": "high", "source": "source:human"}
{"subject": "repo:dent8", "predicate": "lint_gate", "value": "cargo clippy --workspace --all-targets -- -D warnings"}
```

```
$ dent8 capture .dent8/proposals.jsonl --consume --keep-failed
line 1: ACCEPTED  repo:dent8 commit.attribution = "no Co-Authored-By trailers and no AI attribution"  (authority=high)
line 2: ACCEPTED  repo:dent8 lint_gate = "cargo clippy --workspace --all-targets -- -D warnings"  (authority=low)
captured 2 proposal(s): 2 accepted, 0 contested, 0 rejected, 0 invalid
consumed .dent8/proposals.jsonl
```

`--consume` truncates the queue after processing; `--keep-failed` (requires `--consume`)
writes rejected or malformed lines back for retry. This is exactly the shape of the
`SessionEnd` hook (§5).

**(c) From an existing `CLAUDE.md`, with `import`.** `dent8 import <file>` ingests durable
facts from a `CLAUDE.md` / `AGENTS.md` / markdown file **through the firewall** — every
recovered fact runs the same authority / policy / content-check path as `assert` and
`capture`, so nothing is smuggled in. It reads three deterministic shapes and **skips
everything else** (free prose is never turned into a fact): a dent8 managed block (what
`export --target` writes), inline `dent8://<kind>/<key>/<predicate> = <value>` receipt markers
in prose, and fenced ` ```dent8 ` blocks of JSON `capture` proposals. Use `--dry-run` to see
what it would propose without writing:

```
$ dent8 import CLAUDE.md --dry-run
line 5 [inline-marker]: would assert repo:dent8 build_tool = "cargo"
dry run over CLAUDE.md: 1 proposal(s) would be imported, 0 malformed, 5 line(s) skipped (nothing written)
```

To preview which native memory files are present first — a read-only inventory, not an ingest
— use the audit; `import` is what actually pulls the facts in:

```
$ dent8 native scan --agent claude-code
dent8 native scan
  agent: claude-code
  root: .../demo
  guard: missing (no native-memory guard found at .../.claude/settings.json)
  files: 1 native memory/rules file(s), 0 with dent8 receipt markers
  - CLAUDE.md (claude_memory, 26 bytes, sha256=2b65fa708f01, receipt=no)
```

The reverse direction — writing the believed facts back into a `CLAUDE.md` / `AGENTS.md`
managed block with `dent8 export --target` — is covered in
[native-memory.md](native-memory.md). Plain markdown bullets that carry no receipt marker are
still skipped by `import`; translate those into an `assert` or a `capture` proposal as in (a)
and (b).

## 4. Wire your agents

Every adapter reduces to two moves — **context in** (inject the believed facts before the model
runs) and **capture out** (flush proposed facts through the firewall after) — plus, where the
tool speaks it, the **MCP** server for live tool-mediated access. The matrix below maps common
tools to their adapter. The **dent8 side of every bundled profile is verified in this repo**:
the sample MCP configs (Claude Code, Cursor, grok-build, Gemini, Cascade, hecate) are validated
against the real server contract in tests, and the release-acceptance script initializes the
Codex profile and runs `doctor --all-agents --write-check` — a real signed write through every
bundled profile's generated config. On top of that, dent8's own development **dogfoods several
rows at once**: Claude Code and Grok Build run the full hook loop (`SessionStart` →
`dent8 context`, `SessionEnd` → `dent8 capture` — Claude's wiring is tracked in
[`.claude/settings.json`](../.claude/settings.json); Grok's uses the same Claude-compatible
events from its machine-local `.grok/`), and Codex and Cursor work through the tracked
[`AGENTS.md`](../AGENTS.md) contract (the fact base is authoritative for every agent) — all
four via machine-local MCP configs with per-agent signed identities, generated by
`dent8 agent add` and gitignored by design since they name identity paths. What is *not*
exercised here is each **vendor's** half — whether their hook/rules engine fires as their docs
describe — so treat that side as documented per vendor.

| Agent / framework | Context in | Capture out | MCP | Adapter |
| --- | --- | --- | --- | --- |
| Claude Code *(dogfooded)* | `SessionStart` → `dent8 context` | `SessionEnd` → `dent8 capture` | yes | [`.claude/settings.json`](../.claude/settings.json), [`examples/agent-hooks/claude-code/`](../examples/agent-hooks/claude-code/) |
| Cursor *(dogfooded)* | `.cursor/rules/*.mdc` block (or AGENTS.md) | `stop` hook → `dent8 capture` | yes | [`examples/agent-hooks/cursor/`](../examples/agent-hooks/cursor/) |
| Codex CLI *(dogfooded)* | `AGENTS.md` block | `notify` wrapper (coarse) | `mcp_servers` TOML | [`examples/codex/`](../examples/codex/), [mcp-clients](mcp-clients.md) |
| Grok Build *(dogfooded)* | `SessionStart` hook → `dent8 context` | `SessionEnd` hook → `dent8 capture` | `.grok/config.toml` | [`examples/grok-build/`](../examples/grok-build/), [agent-adapters](agent-adapters.md) |
| Windsurf / Cline / Zed | `AGENTS.md` or native rules block | manual / wrapper | yes | [`examples/agent-hooks/generic/`](../examples/agent-hooks/generic/), [mcp-clients](mcp-clients.md) |
| aider | `AGENTS.md` / `--read` file | wrapper → `dent8 capture` | no | [`examples/agent-hooks/generic/`](../examples/agent-hooks/generic/) |
| Any MCP client | (via MCP tools) | (via MCP tools) | yes | [`docs/mcp-clients.md`](mcp-clients.md) |
| Any shell framework | `pre-session.sh` (`dent8 context`) | `post-session.sh` (`dent8 capture`) | — | [`examples/agent-hooks/generic/`](../examples/agent-hooks/generic/) |

The sub-sections below detail the load-bearing patterns — Claude Code hooks (a), the
universal `dent8 context` pipe (b), CI capture (c), and the MCP server (d).

**(a) Claude Code hooks.** This repo ships its own wiring in
[`.claude/settings.json`](../.claude/settings.json). The two load-bearing hooks are
`SessionStart` (inject the believed facts via `dent8 context`) and `SessionEnd` (flush
agent-queued proposals via `dent8 capture`). The full, hardened block — it guards on
`command -v dent8` and sources `.dent8/env` before every call — is:

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "startup|resume",
        "hooks": [
          { "type": "command", "command": "command -v dent8 >/dev/null 2>&1 || exit 0; if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi; DENT8_HOOK_MODE=session-start dent8 hook native-memory-guard", "timeout": 30 },
          { "type": "command", "command": "command -v dent8 >/dev/null 2>&1 || exit 0; if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi; dent8 context", "timeout": 30 }
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          { "type": "command", "command": "command -v dent8 >/dev/null 2>&1 || exit 0; if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi; DENT8_HOOK_MODE=guard-native-memory-write DENT8_HOOK_ENFORCE=1 dent8 hook native-memory-guard", "timeout": 30 }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          { "type": "command", "command": "command -v dent8 >/dev/null 2>&1 || exit 0; if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi; DENT8_HOOK_MODE=post-write-audit dent8 hook native-memory-guard", "timeout": 30 }
        ]
      }
    ],
    "Stop": [
      {
        "hooks": [
          { "type": "command", "command": "command -v dent8 >/dev/null 2>&1 || exit 0; if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi; DENT8_HOOK_MODE=session-start dent8 hook native-memory-guard", "timeout": 30 }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          { "type": "command", "command": "command -v dent8 >/dev/null 2>&1 || exit 0; if [ -f .dent8/env ]; then set -a; . .dent8/env; set +a; fi; dent8 capture .dent8/proposals.jsonl --consume --keep-failed", "timeout": 60 }
        ]
      }
    ]
  }
}
```

A teaching-clean minimal version (same hook events, no defensive guards) lives at
[`examples/agent-hooks/claude-code/settings.sample.json`](../examples/agent-hooks/claude-code/settings.sample.json);
see [Context & Capture](context-capture.md) for the details.

**(b) Any other framework — pipe `dent8 context`.** `dent8 context` emits a markdown pack
(each line stamped with authority, source, and a `dent8://` receipt) that you inject into any
agent's system context:

```
$ dent8 context
## Project facts (dent8)

<!-- generated by `dent8 context` at 1783560209036; regenerate instead of hand-editing -->

Currently-believed facts from the dent8 memory firewall. Each carries its authority and source; verify one with `dent8 explain <subject> <predicate>`.

### repo:dent8

- `build_command` = "cargo build --release"  (authority: high, source: source:human, ref: dent8://repo/dent8/build_command)
- `commit.attribution` = "no Co-Authored-By trailers and no AI attribution"  (authority: high, source: source:human, ref: dent8://repo/dent8/commit.attribution)
- `lint_gate` = "cargo clippy --workspace --all-targets -- -D warnings"  (authority: low, source: source:agent, ref: dent8://repo/dent8/lint_gate)
- `msrv` = "1.94"  (authority: high, source: source:human, ref: dent8://repo/dent8/msrv)
- `test_command` = "cargo test --workspace"  (authority: medium, source: source:ci, ref: dent8://repo/dent8/test_command)
```

Use `--output json` for machine consumption.

**(c) Capture facts from CI.** Let CI assert facts at its own (capped) `medium` authority —
`source:ci` cannot mint `high`, so it can never overwrite a human decision:

```yaml
# .github/workflows/dent8-facts.yml
name: publish facts
on: { push: { branches: [main] } }
jobs:
  facts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo install dent8-cli --locked
      - name: record test command as a CI-sourced fact
        run: |
          set -a; . .dent8/env; set +a
          dent8 assert repo:dent8 test_command "cargo test --workspace" \
            --authority medium --source source:ci
```

**(d) MCP — live tool-mediated access.** For any MCP-capable client, `dent8 mcp serve` exposes
the belief surface over JSON-RPC 2.0 stdio (16 tools; the 7 write tools go through the same
firewall as the CLI). Reading a fact via `resources/read` also records a `fact.retrieved`
audit event by default (opt out with `DENT8_MCP_RECORD_RETRIEVAL=0`) — so MCP retrieval is
replayable like `dent8 context --record-retrieval`. The canonical `mcpServers` block:

```json
{
  "mcpServers": {
    "dent8": { "command": "dent8", "args": ["mcp", "serve"], "env": {} }
  }
}
```

Zed uses `context_servers` instead of `mcpServers`, and Codex uses an `mcp_servers` TOML table —
see [Connect any MCP client](mcp-clients.md) for the verified stdio handshake and per-client
configs, and [`examples/mcp/`](../examples/mcp/) for the belief model and env-var reference. For
a framework with **no** MCP client and **no** native hooks, the provider-neutral scripts in
[`examples/agent-hooks/generic/`](../examples/agent-hooks/generic/) provide the same context-in
/ capture-out loop plus an idempotent `AGENTS.md` writer.

## 5. Day-2 operations

**`verify`** re-checks integrity, supersession lineage, and retraction taint (exit 0 when
healthy):

```
$ dent8 verify
OK: 9 event(s) across 6 subject(s) — STRUCTURAL integrity holds (uniqueness + lineage intact, no retraction taint or content-check flags, all events canonicalize). This does NOT detect a content edit to *unattested* events: the file dev store keeps no stored hash to compare against — use `dent8 witness verify` (or the Postgres backend) for tamper-detection.
```

**`explain <subject> <predicate>`** gives the full receipt — note `survived : 1 challenge(s)`
from the rejected supersede above, and `expires_at` from the 90d TTL:

```
$ dent8 explain repo:dent8 msrv
explain repo:dent8 msrv
    value         : "1.94"
    lifecycle     : Active
    authority     : High
    fresh         : true
    expires_at    : 1791336199745
    evidence      : 1
    corroboration : 1
    survived      : 1 challenge(s)
    chain verified: true
```

**`doctor --write-check`** smoke-tests the whole setup end-to-end (exit 0; the two WARN lines
are expected on a no-identity/no-witness file store):

```
$ dent8 doctor --source source:local --write-check
dent8 doctor
  OK  binary: .../dent8
  OK  file dev store: .../.dent8/memory.jsonl (0 event(s))
  OK  authority: .../.dent8/authority.json (4 source(s); source:local max=high)
  WARN  identity: not configured (optional; run `dent8 identity bootstrap` to create a signed source grant)
  WARN  witness: not configured (optional; set DENT8_WITNESS_LOG + DENT8_WITNESS_PUBKEY for signed tree heads)
  OK  verify: OK: 0 event(s) ... STRUCTURAL integrity holds ...
  OK  mcp: `dent8 mcp serve` is available over stdio
  SKIP  daemon: DENT8_DAEMON_SOCKET not set (CLI writes go to the local store)
  OK  write-check: accepted trusted diagnostic:doctor-… dent8.write_check=ok at high, rejected below-ceiling tampered value, verify OK, probe retracted
```

**Taint.** Derive a fact from another, then retract the basis — `verify` flags the derivative
and exits `1`:

```
$ dent8 retract repo:dent8 msrv --authority high --source source:human
ACCEPTED  retracted 1 believed fact of repo:dent8 msrv  (authority=high)

$ dent8 verify
INTEGRITY ISSUES (1 found):
  TAINTED: fact:service:api:min_toolchain:9 derives from fact:repo:dent8:msrv:3 (now Retracted)
```

**Contested.** `contradict` keeps *both* values as a live dispute (dent8 never silently picks
a winner); `context` flags it inline:

```
$ dent8 contradict repo:dent8 test_command "cargo nextest run" --authority medium --source source:ci
CONTESTED  repo:dent8 test_command: "cargo test --workspace" (incumbent) vs "cargo nextest run"  (authority=medium)
  both are now believed; resolve with `supersede` (install a winner) or `retract`.

$ dent8 context --kind repo
- `test_command` = "cargo test --workspace"  **[contested — 1 rival value(s); check `dent8 conflicts` before relying on this]**  (authority: medium, source: source:ci, ref: dent8://repo/dent8/test_command)
```

**Stale.** `context` omits stale facts and counts them in a trailer; `--include-stale`
annotates them; `explain` shows `fresh : false`:

```
$ dent8 context --kind repo --key dent8
... (fresh facts) ...
_1 believed fact(s) omitted (1 stale, 0 not yet valid) — pass `--include-stale` to show them._

$ dent8 context --kind repo --key dent8 --include-stale
- `nightly_snapshot` = "2026-01-01"  **[stale — past its validity window]**  (authority: medium, source: source:ci, ref: dent8://repo/dent8/nightly_snapshot)
```

**Content-check hook.** dent8's arbitration governs authority, provenance, and lifecycle — it
**never reads a fact's value text**. To screen *content* (injected imperatives, exfil
strings), set `DENT8_CONTENT_CHECK` to an external scanner command; dent8 runs it on every
value-carrying write, fail-closed by default, before the write is arbitrated. dent8 ships no
classifier — the hook is the seam where you wire LLM Guard / Rebuff / Lakera. A demo scanner
(illustrative only, not a defense) lives at
[`examples/scanners/demo-content-check.sh`](../examples/scanners/demo-content-check.sh); full
docs in [content-check.md](content-check.md).

## What dent8 does *not* do

> - **It doesn't inspect fact *content*.** Arbitration is about authority and provenance, not
>   the meaning of the value. Screening injected/obfuscated payloads requires a real scanner
>   behind the content-check hook — dent8 provides the seam, not the classifier
>   ([content-check.md](content-check.md), [threat-model.md](threat-model.md)).
> - **`Ttl::Never` is uncapped.** A fact asserted with no TTL (on a predicate with no default)
>   never expires. Use non-expiring facts sparingly and prefer an explicit `--ttl`.
> - **`dent8 eval` is a 5-scenario demo, not the eval tally.** The CLI's `dent8 eval` runs a
>   5-scenario firewall-vs-recency-only demonstration and prints "5/5 scenarios." The headline
>   **16 blocked / 4 detect-only / 27 out-of-model** figure is a *different* artifact — the
>   frozen **47-case** adversarial corpus documented in [evals.md](evals.md), which lives in
>   the test suite, not the CLI. Don't conflate the two.

[releases]: https://github.com/xyzzylabs/dent8/releases
