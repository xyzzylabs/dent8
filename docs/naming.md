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
- `dent8 claim assert`
- `dent8 claim reinforce`
- `dent8 claim contradict`
- `dent8 claim supersede`
- `dent8 claim expire`
- `dent8 claim retract`
- `dent8 replay claim`
- `dent8 replay entity`
- `dent8 explain claim`
- `dent8 conflicts list`
- `dent8 mcp serve`

Prefer verbs that name integrity actions rather than generic memory actions. For example, use `claim supersede`, not `memory update`.

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

