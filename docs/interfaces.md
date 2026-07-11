# Interfaces

dent8 should expose multiple interfaces over the same core model. Interfaces must not invent separate memory semantics.

## CLI

The CLI is the first operator and developer surface.

Initial command groups:

- `dent8 schema postgres`
- `dent8 assert <subject> <predicate> <value> [--authority <level>] [--source <source>] [--valid-from <ms>] [--valid-to <ms>] [--ttl <duration>]`
- `dent8 reinforce <subject> <predicate> [--authority <level>] [--source <source>]`
- `dent8 contradict <subject> <predicate> <opposing-value> [--authority <level>] [--source <source>] [--valid-from <ms>] [--valid-to <ms>] [--ttl <duration>]`
- `dent8 supersede <subject> <predicate> <new-value> [--authority <level>] [--source <source>] [--valid-from <ms>] [--valid-to <ms>] [--ttl <duration>]`
- `dent8 expire <subject> <predicate> [--authority <level>] [--source <source>]`
- `dent8 retract <subject> <predicate> [--authority <level>] [--source <source>]`
- `dent8 derive <subject> <predicate> <value> --basis <subject> <predicate> [--authority <level>] [--source <source>] [--valid-from <ms>] [--valid-to <ms>] [--ttl <duration>]`
- `dent8 replay <subject> <predicate> [--as-of <ms>] [--valid-at <ms>]`
- `dent8 explain <subject> <predicate> [--as-of <ms>] [--valid-at <ms>]`
- `dent8 snapshot [--include-diagnostics]`
- `dent8 conflicts`
- `dent8 completions <bash|elvish|fish|powershell|zsh>`
- `dent8 mcp serve`

`<subject>` is written as `<kind>:<key>`, for example `person:alice` or `repo:dent8`.
Authority and source are provenance metadata, not part of the fact's
subject/predicate/value. They can be passed explicitly or defaulted from the active signed
source grant.

`--ttl` takes a human duration (`ms`/`s`/`m`/`h`/`d` suffixes, e.g. `90d`, `12h`) and sets the
fact's retention freshness. It is bounded by the predicate's retention ceiling — a `--ttl`
beyond the effective ceiling (a per-predicate override, else the 90-day global default) is
**rejected, not clamped**. Omitting it leaves the predicate's default TTL (or non-expiring).

The CLI should show integrity metadata by default: lifecycle, freshness (TTL *and* asserted
`valid_to`), authority, evidence count, contradiction count, survived-challenge count,
supersession lineage, and replay position. Reads accept `--as-of` (fold the log as of a
transaction-time instant) and `--valid-at` (evaluate freshness/validity at a valid-time
instant) — [ADR 0016](decisions/0016-valid-time-and-time-travel-reads.md).
Human-facing output supports `--color auto|always|never`; structured adapter surfaces
should keep using plain data fields rather than ANSI formatting.

Several of these are already backed by library functions in `dent8-store` and need
only a CLI/store wiring: subject-level replay
(`replay_entity` → `SubjectProjection` with `lineage_issues`), `conflicts`
(`SubjectProjection::contested`), and freshness (`FactState::is_expired_at`).
Counterfactual replay (`replay_fact_with_policy` / `replay_entity_with_policy` +
`diff_states`) is available for a future `explain --distrust`-style surface.

## MCP

MCP is an adapter, not the product boundary.

The Model Context Protocol lets servers expose tools that language models can call. Tool definitions include names, descriptions, input schemas, optional output schemas, and structured or unstructured results. The spec also calls out human-in-the-loop and security expectations for tool invocation.

Source: [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)

Current v0 MCP tools:

- `runtime_status`
- `snapshot`
- `list_facts`
- `verify`
- `conflicts`
- `native_scan`
- `native_reconcile`
- `assert`
- `supersede`
- `retract`
- `contradict`
- `reinforce`
- `expire`
- `derive`
- `explain`
- `replay`

`runtime_status` is read-only and reports the live server binary, cwd, selected store
URL/path, event count, authority registry, signed identity, and witness configuration.
It exists so agents can detect stale MCP subprocesses or wrong stores before relying on
project memory.

`snapshot` is the stable read/audit aggregate for debugger and control-plane clients. It
combines `runtime_status`, fact-stream browsing, `verify`, and `conflicts` into one
structured payload with summary counts. Use it for polling or status panes; use the
individual tools when a client needs a narrower result or lower-cost refresh.

Tool definitions advertise `outputSchema` for every `structuredContent` shape. Tool results
keep human-readable `content`, and also return MCP 2025-11-25 `structuredContent` for
agents. `initialize` prefers `2025-11-25` and also accepts `2025-06-18` clients because
dent8's v0 tool result shape is valid on both revisions. The structured payloads carry a
stable `status` (`accepted`, `rejected`, `contested`, `ok`, `invalid`, `failed`, or
`integrity_issues`; runtime/snapshot probes may also report `degraded`). Writes include an
`accepted_events` array with every committed event's id/kind/hash, plus a current-state
receipt (`receipt_kind: "current_state"`) when the subject still resolves to an explainable
fact. Refused firewall writes carry
`rejection_reason`; malformed calls carry `error_reason` with `status: "invalid"`. For
older clients that ignore `structuredContent`, dent8 also includes a serialized JSON mirror
as a second text content block.

Every error payload — MCP tool errors and the CLI's `--output json` alike — also carries a
stable kebab-case **`code`** naming the *cause*, classified from the typed firewall error
at the point the message is written, so an agent branches on the token instead of parsing
prose. Where `status` says what happened (`rejected`), `code` says why:
`insufficient-authority`, `canonical-contradiction`, `terminal-fact`,
`laundered-authority`, `unbacked-supersession`, `below-authority-floor`,
`uniqueness-violation`, `ttl-ceiling-exceeded`, `authority-ceiling`, `scope-violation`,
`identity-rejected`, `unauthenticated-write`, `weaker-entrenchment`, `content-rejected`,
`write-conflict`, `commit-failed`, and integrity/IO causes (`corrupt-event`,
`replay-failed`, `canonicalization-failed`, `store-unavailable`), with generic fallbacks
(`rejected`, `invalid-argument`, `operation-failed`, `unknown-tool`) when no finer cause is
known. The MCP `outputSchema` advertises the closed enum of codes this build can emit.

Recommended behavior:

- Treat writes as candidate events through the firewall.
- Call `snapshot` first for a complete read/audit view, or `runtime_status` when debugging
  just the live server/store wiring before trusting a long-running MCP server.
- Carry evidence/provenance fields for assertions; signed identity may provide source and
  authority defaults, but explicit fields must still satisfy the same grant/ceiling checks.
- Make stale, contested, expired, or superseded facts visible to clients.
- Put the core usage workflow in MCP server instructions so Codex, Claude Code, Gemini CLI,
  Devin/Cascade, Cursor, Grok Build, Hecate, and other MCP-aware agent hosts know to inspect
  dent8 before relying on durable project facts.
- Keep tool output schemas synchronized with `structuredContent`.

Client setup examples live under [`examples/mcp/`](../examples/mcp/):
[`Codex`](../examples/codex/), [`Claude Code`](../examples/claude-code/),
[`Gemini CLI`](../examples/gemini/), [`Devin/Cascade`](../examples/cascade/),
[`Cursor`](../examples/cursor/), [`Grok Build`](../examples/grok-build/), and
[`Hecate`](../examples/hecate/). Framework examples live under
[`examples/langchain/`](../examples/langchain/) and
[`examples/vercel-ai-sdk/`](../examples/vercel-ai-sdk/). These are integration profiles, not
separate memory semantics; every write still enters through the shared firewall path.

Transport status: v0 supports stdio plus a local Unix-socket daemon. `dent8 mcp install`
writes configs that launch the globally installed `dent8` binary (`command = "dent8"` by
default, overrideable with `--command`) and, by default, pass `["mcp", "serve"]`. Several
agents can share one belief base either by pointing separate stdio server subprocesses at the
same backend and registries, while keeping distinct grant/key env values for provenance, or by
connecting to one local daemon that requires the session-challenge handshake before writes.
`dent8 mcp proxy` is the stdio bridge for clients that cannot speak Unix sockets directly: it
authenticates to the daemon once, then forwards MCP frames over that connection. The installer
can write proxy mode with `--use-daemon`, or `--daemon-socket PATH` for
`["mcp", "proxy", "--socket", PATH]`. The daemon supports authenticated writes, but each daemon
process is still single-source: use separate stdio subprocesses or separate daemon instances
when per-agent provenance matters. A remote HTTP/streamable transport remains design-only
today.

Optional native-memory guard profiles live under
[`examples/agent-hooks/`](../examples/agent-hooks/) and call `dent8 hook native-memory-guard`.
These hooks are not an alternate write path; they run `dent8 verify` and block direct edits
to provider-native memory/rules files that would bypass the fact-event firewall.
`dent8 native scan --agent <profile>` is the read-only audit counterpart: it inventories
known native files/rules, hashes them, flags dent8 receipt markers, and reports guard posture.
`dent8 native reconcile --agent <profile>` goes one step deeper for explicit
`dent8://<kind>/<key>/<predicate>` references: it resolves each through the same receipt
path as `explain` and fails on stale, contested, no-longer-believed, missing, or malformed
references. It still does not import prose or write native files.
The MCP server exposes the same read-only audits as `native_scan` and `native_reconcile`
with the same agent profiles and optional `dir` / `root` / time-travel arguments, so an
agent can inspect bypass-prone native memory before trusting it.
The adapter design is tracked in
[`agent-adapters.md`](agent-adapters.md).

## MCP Resources

MCP resources provide context such as files, database schemas, or application-specific information identified by URI. For dent8, resources are a good fit for read-only explain and replay artifacts.

Source: [MCP resources specification](https://modelcontextprotocol.io/specification/2025-11-25/server/resources)

Possible resources:

- `dent8://facts/{fact_id}`
- `dent8://subjects/{subject_type}/{subject_key}`
- `dent8://replays/{replay_id}`
- `dent8://conflicts`
- `dent8://schema/postgres`

## HTTP API

The HTTP API should come after the CLI and Postgres adapter have proven the core semantics.
It is the natural home for a shared local daemon or remote dent8 service used by many agents;
it must preserve the same firewall path, identity checks, and replay receipts as CLI/MCP,
instead of becoming a generic memory provider. The local Unix-socket daemon already covers
the single-user, single-source-key version of this with a session challenge; the HTTP API is
the future remote/multi-tenant shape and cannot rely on service-held user source keys.

Likely routes:

- `POST /facts/assert`
- `POST /facts/{fact_id}/reinforce`
- `POST /facts/{fact_id}/contradict`
- `POST /facts/{fact_id}/supersede`
- `GET /facts/{fact_id}`
- `GET /facts/{fact_id}/explain`
- `GET /snapshot`
- `GET /subjects/{subject_type}/{subject_key}/context`
- `POST /replay`
- `GET /conflicts`

## Desktop Debugger

The desktop app is accepted as a future product surface, but only as a debugger/control plane
over the existing integrity boundary ([ADR 0020](decisions/0020-desktop-debugger-control-plane.md)).
It should make the CLI/MCP/daemon state visible: connected agents, authority ceilings, grants,
recent accepted/rejected writes, conflicts, stale facts, `snapshot` health, `explain`/`replay`
timelines, native scan/reconcile findings, witness coverage, and doctor health.

The desktop app must not become a separate memory provider or private write path. Read/audit
views should come first. Any future write action must call the same signed, authority-checked
daemon/HTTP path used by other clients. A TypeScript web debugger should come before a native
shell; Tauri is the preferred wrapper when a desktop package is justified.

## SDK

SDKs should be thin wrappers over the HTTP API and shared JSON schemas.

Do not let SDK convenience helpers hide freshness, conflict, or authority metadata.
