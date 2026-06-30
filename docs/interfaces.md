# Interfaces

dent8 should expose multiple interfaces over the same core model. Interfaces must not invent separate memory semantics.

## CLI

The CLI is the first operator and developer surface.

Initial command groups:

- `dent8 schema postgres`
- `dent8 assert <subject> <predicate> <value> --authority <level> --source <source>`
- `dent8 reinforce <subject> <predicate> --authority <level> --source <source>`
- `dent8 contradict <subject> <predicate> <opposing-value> --authority <level> --source <source>`
- `dent8 supersede <subject> <predicate> <new-value> --authority <level> --source <source>`
- `dent8 expire <subject> <predicate> --authority <level> --source <source>`
- `dent8 retract <subject> <predicate> --authority <level> --source <source>`
- `dent8 derive <subject> <predicate> <value> --from <subject> <predicate> --authority <level> --source <source>`
- `dent8 replay <subject> <predicate>`
- `dent8 explain <subject> <predicate>`
- `dent8 conflicts`
- `dent8 completions <bash|elvish|fish|powershell|zsh>`
- `dent8 mcp serve`

`<subject>` is written as `<kind>:<key>`, for example `person:alice` or `repo:dent8`.
Authority and source are explicit flags so provenance metadata is not confused with the
fact's subject/predicate/value.

The CLI should show integrity metadata by default: lifecycle, freshness, authority, evidence count, contradiction count, supersession lineage, and replay position.
Human-facing output supports `--color auto|always|never`; structured adapter surfaces
should keep using plain data fields rather than ANSI formatting.

Several of these are already backed by library functions in `dent8-store` and need
only a CLI/store wiring: entity-level replay
(`replay_entity` → `EntityProjection` with `lineage_issues`), `conflicts`
(`EntityProjection::contested`), and freshness (`ClaimState::is_expired_at`).
Counterfactual replay (`replay_claim_with_policy` / `replay_entity_with_policy` +
`diff_states`) is available for a future `explain --distrust`-style surface.

## MCP

MCP is an adapter, not the product boundary.

The Model Context Protocol lets servers expose tools that language models can call. Tool definitions include names, descriptions, input schemas, optional output schemas, and structured or unstructured results. The spec also calls out human-in-the-loop and security expectations for tool invocation.

Source: [MCP tools specification](https://modelcontextprotocol.io/specification/2025-06-18/server/tools)

Current v0 MCP tools:

- `list_facts`
- `verify`
- `conflicts`
- `assert`
- `supersede`
- `retract`
- `contradict`
- `reinforce`
- `expire`
- `derive`
- `explain`
- `replay`

Recommended behavior:

- Return structured content with explicit integrity fields.
- Treat writes as candidate events through the firewall.
- Require evidence/provenance fields for assertions.
- Make stale, contested, expired, or superseded claims visible to clients.
- Put the core usage workflow in MCP server instructions so Codex, Claude Code, Gemini CLI,
  Devin/Cascade, Cursor, Grok Build, Hecate, and other MCP-aware agent hosts know to inspect
  dent8 before relying on durable project facts.
- Use tool output schemas once the Rust types settle.

Client setup examples live under [`examples/mcp/`](../examples/mcp/):
[`Codex`](../examples/codex/), [`Claude Code`](../examples/claude-code/),
[`Gemini CLI`](../examples/gemini/), [`Devin/Cascade`](../examples/cascade/),
[`Cursor`](../examples/cursor/), [`Grok Build`](../examples/grok-build/), and
[`Hecate`](../examples/hecate/). These are integration profiles, not separate memory
semantics; every write still enters through the shared firewall path.

Optional native-memory guard profiles live under
[`examples/agent-hooks/`](../examples/agent-hooks/) and call `dent8 hook native-memory-guard`.
These hooks are not an alternate write path; they run `dent8 verify` and block direct edits
to provider-native memory/rules files that would bypass the claim-event firewall. The
adapter design is tracked in
[`agent-adapters.md`](agent-adapters.md).

## MCP Resources

MCP resources provide context such as files, database schemas, or application-specific information identified by URI. For dent8, resources are a good fit for read-only explain and replay artifacts.

Source: [MCP resources specification](https://modelcontextprotocol.io/specification/2025-06-18/server/resources)

Possible resources:

- `dent8://claims/{claim_id}`
- `dent8://entities/{subject_type}/{subject_key}`
- `dent8://replays/{replay_id}`
- `dent8://conflicts`
- `dent8://schema/postgres`

## HTTP API

The HTTP API should come after the CLI and Postgres adapter have proven the core semantics.

Likely routes:

- `POST /claims/assert`
- `POST /claims/{claim_id}/reinforce`
- `POST /claims/{claim_id}/contradict`
- `POST /claims/{claim_id}/supersede`
- `GET /claims/{claim_id}`
- `GET /claims/{claim_id}/explain`
- `GET /entities/{subject_type}/{subject_key}/context`
- `POST /replay`
- `GET /conflicts`

## SDK

SDKs should be thin wrappers over the HTTP API and shared JSON schemas.

Do not let SDK convenience helpers hide freshness, conflict, or authority metadata.
