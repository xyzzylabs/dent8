# 0002: Claim Events, Not Memory Items

Date: 2026-06-26

## Status

Accepted.

## Context

Agent memory systems often expose stored memories as mutable items, summaries, embeddings, or chat-history fragments. dent8 is intended to differentiate on memory integrity: provenance, TTL, contradiction handling, supersession, replay, auditability, freshness, authority, and explainability.

## Decision

The core primitive is `ClaimEvent`.

"Memory" is an agent-facing projection over claim events, not the internal unit of truth.

## Consequences

Positive:

- Replay is a first-class operation.
- Debugger views can explain how state emerged.
- Contradictions and supersessions are preserved instead of overwritten.
- Audit events like retrieval and decision use can be represented in the same history.

Negative:

- The model is more explicit than a simple key-value or vector memory store.
- The first write path must handle event validation and state transitions.
- Query surfaces need to present integrity metadata without overwhelming users.

## Follow-Up

- Extend property tests around claim streams.
- Define stable JSON serialization for events.
- Implement event hashing and replay verification.

