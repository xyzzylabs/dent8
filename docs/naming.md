# Naming

## Crates

Public package names use hyphens:

- `dent8-core`
- `dent8-store`
- `dent8-store-postgres`
- `dent8-cli`
- `dent8-policy`
- `dent8-mcp`
- `dent8-debugger`
- `dent8-export`

Rust crate names use underscores:

- `dent8_core`
- `dent8_store`
- `dent8_store_postgres`

## Commands

The binary is `dent8`.

Command groups:

- `dent8 schema postgres`
- `dent8 assert <subject> <predicate> <value> --authority <level> --source <source>`
- `dent8 reinforce <subject> <predicate> --authority <level> --source <source>`
- `dent8 contradict <subject> <predicate> <opposing-value> --authority <level> --source <source>`
- `dent8 supersede <subject> <predicate> <new-value> --authority <level> --source <source>`
- `dent8 expire <subject> <predicate> --authority <level> --source <source>`
- `dent8 retract <subject> <predicate> --authority <level> --source <source>`
- `dent8 replay <subject> <predicate>`
- `dent8 explain <subject> <predicate>`
- `dent8 conflicts`
- `dent8 completions <bash|elvish|fish|powershell|zsh>`
- `dent8 mcp serve`

Subjects use `<kind>:<key>` (`person:alice`, `repo:dent8`) so the fact reads left-to-right:
subject, predicate, value. Authority and source are flags because they are provenance metadata.
Global CLI flags, such as `--color auto|always|never`, should control presentation only and
must not change firewall semantics.

Prefer verbs that name integrity actions rather than generic memory actions. For example, use
`supersede`, not `memory update`.

## Event Types

Event type strings use dotted names:

- `claim.asserted`
- `claim.reinforced`
- `claim.contradicted`
- `claim.superseded`
- `claim.expired`
- `claim.retracted`
- `claim.retrieved`
- `claim.used_in_decision`

Use past-tense event names because events are immutable facts. Commands can be imperative; events should describe what happened.

## Tables

Postgres tables use the `dent8_` prefix:

- `dent8_claim_events`
- `dent8_claim_projections`
- `dent8_claim_edges`
- `dent8_replay_runs`

## IDs

Use explicit prefixes in text IDs during early development:

- `claim_...`
- `event_...`
- `evidence_...`
- `source_...`
- `actor_...`
- `replay_...`

The exact ID generator can change later. The important invariant is that IDs remain stable in the event log.
