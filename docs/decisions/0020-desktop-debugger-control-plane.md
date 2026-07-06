# ADR 0020 - Desktop app as debugger/control plane

Date: 2026-07-06

## Status

**Accepted.** dent8 should eventually have a desktop app, but only as a debugger/control
plane over the existing integrity boundary. ADR 0019 is intentionally left for the future
networked MCP-over-HTTP decision referenced by ADR 0018.

## Context

dent8 is strongest when every write flows through the same firewall path:

```text
CLI / MCP / daemon / future HTTP -> op_* -> authority + identity checks -> EventStore::append
```

A desktop UI could make dent8 much easier to understand and adopt: users need to see which
agents are connected, what each source may write, why a fact was accepted or rejected, where
native memory files diverge from receipts, and whether witness coverage is current.

But a desktop app is also risky if it becomes its own memory provider or private write path.
That would create a polished bypass of the same firewall dent8 exists to enforce.

## Decision

Build a future desktop app as **dent8 Desktop: a local memory debugger and control plane**.

It is not the foundation of the product. The foundation remains:

- the fact-event log and projections;
- the write-path firewall;
- signed source identity and authority ceilings;
- the MCP/CLI/daemon surfaces;
- SQLite/Postgres adapters;
- witness publication and verification.

The desktop app must sit on top of those surfaces. It may read state, visualize receipts, run
audits, and initiate writes only by calling the same signed, authority-checked API used by
CLI/MCP/daemon clients. It must not write event rows, native memory files, or provider rules
directly.

## Shape

The first useful version should be **read/audit-first**:

- connected agent profiles and their source ids;
- authority ceilings, grants, trust roots, and identity health;
- recent accepted/rejected writes;
- conflicts and contested facts;
- stale, not-yet-valid, expired, superseded, or retracted facts;
- `explain` / `replay` timelines for one fact;
- `native scan` and `native reconcile` results;
- witness status, unwitnessed tail, published heads, and rollback/tamper findings;
- doctor status grouped as OK/WARN/FAIL/SKIP.

The implementation order should be:

1. keep hardening CLI/MCP/daemon and their structured JSON contracts;
2. expose a stable local daemon/API for read/audit/status operations;
3. build a TypeScript web debugger against that API;
4. wrap it with Tauri when a native desktop shell is justified;
5. add write actions only when they reuse the same signed identity and authority path.

## Consequences

- The desktop app is a product/adoption accelerator, not a substitute for core correctness.
- UI work should not fork the domain model; it consumes receipts and status objects emitted by
  the existing surfaces.
- Tauri is the preferred desktop shell because dent8 is Rust-first and should avoid a larger
  Electron runtime unless there is a specific reason.
- A hosted web UI can later reuse the same debugger model, but remote multi-user auth belongs
  to the future networked API decision, not this ADR.

## Non-goals

- No direct DB writes.
- No native memory import/export loop hidden behind UI buttons.
- No provider-specific memory semantics.
- No desktop-only fact format or receipt format.
