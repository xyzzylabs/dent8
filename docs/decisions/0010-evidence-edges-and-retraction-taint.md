# ADR 0010 — Evidence-dependency edges and retraction taint

Status: accepted

## Context

dent8's headline integrity promise is that **poison does not survive in its
derivatives**: if a source claim is retracted (because it was poisoned, or its
source was invalidated), the claims that were *derived from* it should not silently
remain believed as if nothing happened. Recency-only memory systems (Zep/Graphiti,
Mem0) have **no dependency graph at all**, so they cannot express this; it is the
threat model's T2/T8 tier and a core differentiator
([related-work.md](../related-work.md), [threat-model.md](../threat-model.md)).

Until now dent8 had no way to record that claim *C* was derived using claims
*A*, *B* as evidence. `Evidence` modelled only *descriptive* provenance (a locator,
a digest, a summary); migration 001 sketched a `uses_as_evidence` edge table that was
never wired. Two questions had to be decided: **how to represent the edge**, and
**what happens to a derivative when its evidence is retracted**.

## Decided

1. **The edge is `EvidenceKind::DerivedFrom`, with the evidence item's `locator`
   holding the source claim id.** A claim's dependency edges are exactly its
   `Evidence` items whose `kind` is `DerivedFrom`; each such item's `locator` is the
   `claim:…` id it was derived from. This adds **one enum variant** and **no struct
   field** — so it does not churn the (many) `ClaimEvent`/`Evidence` construction
   sites, and it is byte-compatible with existing hashes (existing events use no
   `DerivedFrom` evidence, so their canonical bytes are unchanged). It reuses the
   `Evidence` vector that already travels with every event and is already hashed, so
   the edge is tamper-evident for free.

2. **Retraction is a *taint flag*, computed on replay — not an auto-cascade
   delete (v0).** A believed claim is **tainted** when it transitively `DerivedFrom`
   a claim that is now in a terminal *invalidated* lifecycle — `Retracted` or
   `Expired`. Taint is a **read-side derived property** (like `lineage_issues`),
   computed over the folded claim states across entities; it is **surfaced**, not
   acted upon. This matches dent8's paraconsistent stance — *make the problem
   visible, do not silently destroy* — and avoids a legitimate, non-poisoning
   retraction nuking unrelated derivatives. The event log stays the single source of
   truth; taint is recomputed, never written.

3. **Auto-cascade-retract is a documented future option, gated on intent.** When a
   source is retracted with `RetractionReason::PoisoningDetected` or
   `SourceInvalidated`, an operator may *choose* to retract the tainted derivatives
   (a deliberate, authority-gated action), but dent8 does not do it implicitly. The
   edge model already supports it; only the policy is deferred.

## Why not the alternatives

- **A typed `derived_from: Vec<ClaimId>` field on `ClaimEvent`/`Evidence`** — cleaner
  to read, but adds a required field to a struct with 60+ construction sites and
  changes the canonical bytes of every event with evidence. The `EvidenceKind`
  variant gets the same expressiveness with neither cost. (A typed field is a fine
  future refactor once it earns the churn.)
- **Auto-cascade-retract in the fold** — the fold (`apply_event`) is per-claim-stream;
  a cascade is a cross-claim graph operation that does not belong there, and silent
  deletion contradicts the firewall's "surface, don't blow up" design.

## Consequences

- A claim records its derivation provenance in the same hashed `Evidence` vector;
  the dependency graph is reconstructable from the log alone (deterministic replay).
- "Retract the poison → its derivatives are flagged" becomes a real, tested property
  (the `poisoned_source_retraction` eval), versus recency-only baselines that cannot
  represent it.
- Taint is transitive and cross-entity, so it is computed by a store-level analysis
  over all claim states, surfaced via the CLI/MCP (e.g. `explain`/`verify`), not by
  the per-stream fold.

## Follow-Up

- Add `EvidenceKind::DerivedFrom` + a `dependency_edges(event)` helper (dent8-core).
- A store-level `tainted_claims` analysis (transitive `DerivedFrom` → invalidated
  source) (dent8-store).
- A CLI/MCP surface that records a derivation and flags tainted derivatives, and the
  `poisoned_source_retraction` eval fixture.
- Optionally materialize `uses_as_evidence` edges in the Postgres edge graph
  (migration), and the operator-initiated cascade-retract on `PoisoningDetected`.
