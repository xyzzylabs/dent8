# 0005: Belief-Base Revision Semantics

Date: 2026-06-26

## Status

Accepted.

## Context

dent8's contradiction/supersession/retraction/expiry semantics independently
reinvent ideas from the formal belief-revision literature. Naming the right theory
gives dent8 a defensible vocabulary and pre-empts the obvious reviewer objection
("this isn't real AGM"). Classical AGM operates on logically-closed belief *sets*
and demands global consistency — neither of which dent8 wants.

## Decision

Adopt **belief-base revision** (Hansson), not classical AGM, as dent8's formal
identity:

- dent8's "memory" is a fold/projection over an immutable `ClaimEvent` base, not a
  deductively-closed set. The base, and its history, are authoritative.
- **dent8 deliberately does not satisfy the Recovery postulate.** Retract-then-
  reassert must not resurrect dependents; the re-assertion carries fresh provenance
  and evidence.
- The `contested` lifecycle plus preserved `contradicted_by` edges is a
  **paraconsistent** design (inconsistency ≠ triviality): localize a contradiction,
  keep the store non-trivial, surface it — never silently merge `A` and `¬A`.
- `Authority` is an **epistemic-entrenchment** ordering, kept strictly separate from
  `Confidence` (evidential strength). Entrenchment decides what is surrendered first.
- dent8 makes **no claim of logical closure or an entailment engine**; it implements
  the *operational spirit* of revision operators over opaque triples.

## Consequences

Positive:

- A precise, citable formal grounding ([belief-revision.md](../belief-revision.md)).
- Justifies keeping `AuthorityLevel` and `Confidence` as separate fields.
- The Recovery non-postulate is the correct, defensible answer to "not real AGM."

Negative:

- The mapping of asserted/superseded/retracted onto expansion/revision/contraction is
  *inspirational*, not rigorous — must be stated as such to avoid overclaiming.
- "Belief-base framing" is principled grounding, **not** a novel mechanism (bitemporal
  DBs already provide "history matters"); it must not be sold as a contribution.

## Follow-Up

- Implement authority-as-entrenchment arbitration ([ADR 0007](0007-authority-as-entrenchment.md)).
- Decide JTMS vs ATMS for the debugger's assumption-environment replay (future ADR).
- Add `valid_to` (closed valid-time intervals) — currently only open `valid_from`
  exists, which is weaker than a full bitemporal interval.
