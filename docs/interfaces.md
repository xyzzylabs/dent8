# Interfaces

dent8 should expose multiple interfaces over the same core model. Interfaces must not invent separate memory semantics.

## CLI

The CLI is the first operator and developer surface.

Initial command groups:

- `dent8 schema postgres`
- `dent8 assert <subject> <predicate> <value> [--authority <level>] [--source <source>] [--valid-from <time>] [--valid-to <time>] [--ttl <duration>]`
- `dent8 reinforce <subject> <predicate> [--authority <level>] [--source <source>]`
- `dent8 contradict <subject> <predicate> <opposing-value> [--authority <level>] [--source <source>] [--valid-from <time>] [--valid-to <time>] [--ttl <duration>]`
- `dent8 supersede <subject> <predicate> <new-value> [--authority <level>] [--source <source>] [--valid-from <time>] [--valid-to <time>] [--ttl <duration>]`
- `dent8 expire <subject> <predicate> [--authority <level>] [--source <source>]`
- `dent8 retract <subject> <predicate> [--authority <level>] [--source <source>]`
- `dent8 derive <subject> <predicate> <value> --basis <subject> <predicate> [--authority <level>] [--source <source>] [--valid-from <time>] [--valid-to <time>] [--ttl <duration>]`
- `dent8 replay <subject> <predicate> [--as-of <time>] [--valid-at <time>]`
- `dent8 whatif <subject> <predicate> [--distrust <source>]... [--authority-floor <level>] [--confidence-floor <millis>]`
- `dent8 explain <subject> <predicate> [--as-of <time>] [--valid-at <time>]`
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

Every `<time>` flag (`--valid-from`/`--valid-to`, `--as-of`/`--valid-at`, `--expires-at`)
accepts raw unix milliseconds (the machine form — what the MCP tools take), `now`, a
±duration offset from now (`-7d`, `+12h`), RFC 3339 with an offset
(`2026-07-11T12:00:00Z`), or a bare UTC date/datetime (`2026-07-11`, `2026-07-11T12:00`).
Bare forms are **UTC**, not local time, so the same command names the same instant on every
machine.

The CLI should show integrity metadata by default: lifecycle, freshness (TTL *and* asserted
`valid_to`), authority, evidence count, contradiction count, survived-challenge count,
supersession lineage, and replay position. Reads accept `--as-of` (fold the log as of a
transaction-time instant) and `--valid-at` (evaluate freshness/validity at a valid-time
instant) — [ADR 0016](decisions/0016-valid-time-and-time-travel-reads.md).
Human-facing output supports `--color auto|always|never`; structured adapter surfaces
should keep using plain data fields rather than ANSI formatting.

`dent8 whatif` is **policy-counterfactual replay**: it re-folds the same immutable log under
a swapped epistemic trust policy (`--distrust <source>`, `--authority-floor`,
`--confidence-floor` — at least one required) and reports the believed set under the real
fold vs the counterfactual, plus a per-fact structural diff. Read-only and deterministic
(`replay_subject_with_policy` + `diff_states` in `dent8-store`); freshness is deliberately
not a policy knob.

## MCP

MCP is an adapter, not the product boundary.

The Model Context Protocol lets servers expose tools that language models can call. Tool definitions include names, descriptions, input schemas, optional output schemas, and structured or unstructured results. The spec also calls out human-in-the-loop and security expectations for tool invocation.

Source: [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)

Current v0 MCP tools:

- `runtime_status`
- `snapshot`
- `context`
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
- `whatif`

`runtime_status` is read-only and reports the live server binary, cwd, selected store
URL/path, event count, authority registry, signed identity, and witness configuration.
It exists so agents can detect stale MCP subprocesses or wrong stores before relying on
project memory.

`context` is the agent inject pack (same shape as CLI `dent8 context -o json`): currently
believed facts with **value, authority, source, and freshness**. Prefer it when grounding on
project memory. Weight High human/CI facts above Low agent facts. `detail=summary` shortens
the text half; optional filters mirror the CLI (`kind` / `key` / `predicate` /
`include_stale` / `include_diagnostics` / `record_retrieval`).

`list_facts` remains a lightweight stream **index** (uri + freshness only — no values or
authority). Use it for discovery/polling, not for ranking belief.

`snapshot` is the stable read/audit aggregate for debugger and control-plane clients. It
combines `runtime_status`, fact-stream browsing, `verify`, and `conflicts` into one
structured payload with summary counts, including **`witness_status`**,
**`witness_unwitnessed_events`**, and **`attention`** so agents cannot miss witness lag or
integrity noise behind a nested `ok`. Optional `include_context` nests a full belief pack.
Witness `warn`/`failed` degrades the snapshot status. Use it for health polling or status
panes; use `context` for multi-fact grounding and `explain` (single or `queries[]` batch,
optional `detail=summary`) for receipts.

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
- Call `context` first when relying on believed project facts; call `snapshot` for health
  (verify + conflicts + witness attention), or `runtime_status` when debugging just the live
  server/store wiring before trusting a long-running MCP server.
- Weight High human/CI facts above Low agent facts when ranking what to trust.
- Use `native_reconcile` when provider-native rules or an export block may disagree with the
  live store (export markers are not a second belief base).
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

MCP resources provide context identified by URI. dent8 exposes **one resource per fact
stream** at `dent8://{kind}/{key}/{predicate}` (segments percent-encoded):

- `resources/list` enumerates every stream in the log, with its freshness marked;
- `resources/read` returns the stream's integrity receipt (and, for a write-capable
  connection, records a `fact.retrieved` audit event by default — the same read-audit loop
  as `dent8 context --record-retrieval`);
- `resources/subscribe` / `resources/unsubscribe` register for
  **`notifications/resources/updated`** pushes when a subscribed stream gains events. A
  write through the same connection notifies immediately; a write from any other process
  sharing the store is picked up within a short poll tick — so a long-running agent stops
  re-polling `explain` and reacts when a fact it depends on is superseded, contested, or
  retracted. Subscribing to a not-yet-asserted stream is allowed and notifies on its first
  write. Both the stdio server and the local daemon (through `dent8 mcp proxy`, which pumps
  frames bidirectionally) deliver notifications.

Source: [MCP resources specification](https://modelcontextprotocol.io/specification/2025-11-25/server/resources)

## HTTP API — MCP-over-HTTP (built)

The HTTP API is the **MCP JSON-RPC surface carried over HTTP** — the third transport of
`dent8 mcp serve`, after stdio and the local Unix-socket daemon, over the *same*
`dispatch` firewall path ([ADR 0019](decisions/0019-http-api-mcp-over-http.md)). Rather than a
bespoke REST surface that would re-map every operation and re-derive every receipt (a second
copy of the machine contract, free to drift), the belief surface *is* the MCP method set, and
HTTP just carries it. The "routes" are MCP methods.

```sh
dent8 mcp serve --http --port 3369     # loopback + bearer token; writes with this identity
curl -s http://127.0.0.1:3369/ -H 'authorization: bearer <token>' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"assert","arguments":{"subject":"repo:x","predicate":"database",
       "value":"postgres","authority":"high","source":"source:owner"}}}'
```

- **Endpoint.** `POST /` (and `/mcp`) with a JSON-RPC message or batch; the response is the
  JSON-RPC result (`204 No Content` for a lone notification). `GET /healthz` is an
  unauthenticated liveness probe. The full belief surface — `assert` / `supersede` /
  `retract` / `contradict` / `reinforce` / `expire` / `derive` / `explain` / `replay` /
  `list_facts` / `conflicts` / `snapshot` / `whatif` / `verify` / `native_*` — is reachable
  as MCP `tools/call`, carrying the same `status` / error `code` / `structuredContent` as
  stdio and the CLI's `--output json`.
- **Trust boundary (local-first).** Binds loopback only, validates the `Host` header against
  localhost forms (anti-DNS-rebinding), and requires a **bearer token** on every non-health
  request (`DENT8_HTTP_TOKEN`, else generated per run and printed on start — the token
  substitutes for the daemon's `SO_PEERCRED` check, which TCP cannot do). Writes are attested
  with the **server's own identity** (`DENT8_GRANT` / `DENT8_IDENTITY_KEY`), exactly like
  `dent8 mcp serve` over stdio.
- **Deferred:** a remote, multi-user service where each client proves *its own* source key
  (the daemon's session challenge ported to HTTP, or client-signed write attestations) is a
  distinct decision, blocked until such a deployment exists. Until then the HTTP transport is
  loopback/trusted-network; front it with a reverse proxy (TLS) for anything else.

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
