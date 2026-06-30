# Project Brief

## Name

`dent8`

Origin: dentate gyrus, the hippocampal structure associated with pattern separation in human memory.

Tagline: Pattern separation for agent memory.

## Thesis

Long-running agents need memory integrity, not just memory persistence. A stored memory is useful only if an agent can tell where it came from, whether it is fresh, what evidence supports it, whether stronger evidence replaced it, and whether it conflicts with other claims.

dent8 exists to make those integrity properties explicit and replayable.

## Product Category

Memory integrity platform for agentic systems.

It combines three surfaces over one event model:

- Memory firewall: validates writes and read eligibility.
- Versioned memory store: records append-only claim events and projections.
- Memory debugger: explains provenance, replay, drift, contradictions, and supersession.

## Differentiator

dent8 should not become "another memory provider." The differentiator is that memory is governed by an event-sourced claim model with provenance, authority, freshness, contradiction handling, supersession, replay, and auditability built in from the first release.

Stated precisely (and honestly): no single one of those primitives is novel — Zep/Graphiti, PROV, SQL:2011, and transparency logs cover most of them ([related-work.md](related-work.md)). The defensible wedge is the *combination as substrate* plus **typed authority-weighted supersession** as a poisoning mitigation. Formally, dent8 is a **belief base** with paraconsistent contradiction tolerance ([belief-revision.md](belief-revision.md)). The headline arbitration is **enforced at the write boundary** (`EventStore::append`) and runnable end-to-end — the CLI/MCP run on either a file dev store or, with `DENT8_STORE_URL`, a transactional async backend (DB-verified Postgres, `--features postgres`, or embedded SQLite, `--features sqlite`). The remaining gap is *productization* — operating signed source identity well (key distribution/rotation and stronger secret storage; the default CLI includes `dent8 init --identity`, `dent8 init --agent <profile>`, and `dent8 identity`) and an operated witness service (the signed-tree-head witness *primitive* is built — `dent8 witness`) — see [STATUS.md](STATUS.md).

## MVP User

The first user is a coding agent or long-running developer assistant that needs to remember project facts without silently retaining stale or contradicted context.

Example facts:

- "This repo uses Postgres as the operational source of truth."
- "The CLI binary is named `dent8`."
- "A user correction superseded an earlier project assumption."
- "This branch has a failing test that should not be treated as resolved."

## Non-Goals

- Generic vector memory as the primary product.
- Chat history summarization as the primary abstraction.
- Notebook-first evals.
- SQLite prototype semantics that later need a different correctness model.
- MCP-only architecture.

## First Principles

- Claims are event streams.
- State is replayed, not trusted blindly.
- Reads must expose integrity metadata.
- Provenance and evidence are mandatory for accepted assertions.
- Authority is typed and policy-visible.
- TTL and freshness are first-class.
- Contradiction is not failure; hidden contradiction is failure.
- Supersession must preserve lineage.
