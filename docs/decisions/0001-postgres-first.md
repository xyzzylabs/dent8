# 0001: Postgres From Start

Date: 2026-06-26

## Status

Accepted. **Updated 2026-06-30:** the Postgres-first decision held — Postgres was the first
adapter. An embedded **SQLite** backend was *later* added as a second adapter behind the
`AsyncEventStore` boundary (see [storage.md](../storage.md)); this ADR records the original
first-backend choice, not a standing exclusion of SQLite. "SQLite is not part of the **initial**
runtime plan" below should be read in that historical context.

## Context

dent8 needs an append-only event log, projection updates, contradiction checks, supersession lineage, replay, and auditability. The original note considered SQLite for a local-first MVP and Postgres later.

## Decision

Use Postgres as the operational source of truth from the start.

SQLite is not part of the initial runtime plan.

## Consequences

Positive:

- Runtime semantics match the intended production architecture earlier.
- Append and projection updates can be transactional from the first adapter.
- Multi-user and audit-heavy workflows do not require a later storage rethink.
- Postgres constraints can enforce important invariants near the data.

Negative:

- Local setup is slightly heavier.
- Integration tests need a disposable Postgres instance.
- SQLx compile-time checking may require `.sqlx` metadata or a build-time database.

## Follow-Up

- Implement `dent8-store-postgres`.
- Decide whether to use SQLx checked queries immediately or begin with dynamic queries.
- Add Postgres integration tests for constraints and concurrent writes.

