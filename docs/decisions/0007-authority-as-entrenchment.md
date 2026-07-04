# 0007: Authority-as-Entrenchment Arbitration

Date: 2026-06-26

## Status

Accepted; **implemented in `dent8-core`** (supersession arbitration + canonical
hard-alarm + non-resurrection proof), **earned entrenchment v0** (authority-weighted
corroboration + the `unearned_supersessions` entity-level audit), and **survived-challenge
recording** ([ADR 0015](0015-survived-challenge-recording.md): `ChallengeRejected` events +
Sybil-resistant `ClaimState.survived_challenges`, plus the opt-in earned-supersession gate).
Remaining future: uniqueness-constrained predicates and transactional store-layer
enforcement.

## Context

Authority-weighted supersession is dent8's headline differentiator versus Graphiti's
recency-only contradiction resolution ("consistently prioritizes new information"),
and the cleanest mitigation for MINJA-style memory poisoning (a privilege-less user
must not override a high-authority fact). Originally `apply_event` applied every
`Superseded`/`Contradicted` event identically and ignored `Authority` entirely — the
differentiator was a design claim with no code. This ADR's decision is now built.

## Decision

Make `Authority` an **epistemic-entrenchment ordering that arbitrates conflict
resolution in the core fold**, separate from `Confidence`:

- A `claim.superseded` whose replacing claim does **not** strictly out-rank the
  superseded active claim is rejected (or down-ranked), not silently applied. This
  operationalizes the invariant "higher-authority supersession requires an explicit
  basis."
- A `claim.contradicted` against an `AuthorityLevel::Canonical` (or uniqueness-
  constrained predicate) claim is a **hard alarm** (a new `TransitionError`), not a
  soft transition to `Contested` — the LFI "gentle-explosion" tier.
- `Confidence` never substitutes for `Authority` in arbitration; a high-confidence
  low-authority claim cannot override a low-confidence high-authority one.

## Consequences

Positive:

- Turns the headline differentiator into enforced behavior testable against
  MINJA/PoisonedRAG fixtures.
- Gives the eval suite a `consistency_required` fixture family.

Negative:

- Arbitration in the core changes `apply_event`'s contract; needs new
  `TransitionError` variants and careful property tests so legitimate supersession
  still works.
- Authority is *asserted*, not *proven* — this defends against low-privilege
  injection, not a compromised high-authority actor (see [threat-model.md](../threat-model.md)).

## Follow-Up

- [DONE] Implemented in `dent8-core` `apply_event` (`InsufficientAuthority`,
  `CanonicalContradiction`), with unit tests + an exhaustive 5×5-lattice
  non-resurrection test and a `#[cfg(kani)]` harness.
- [DONE] Earned entrenchment v0: authority-weighted `corroborating_sources` /
  `corroboration_at_or_above` on `ClaimState`, and `EntityProjection::unearned_supersessions`
  (`AuthorityDowngrade`, `WeakerEntrenchment` — now weighing earned entrenchment =
  corroboration + survived challenges, ADR 0017; Sybil-resistant), tested.
- Enforce the arbitration *transactionally* in the store layer once the Postgres
  adapter exists (load incumbent, lock, arbitrate, append atomically).
- [DONE] Record *rejected* supersession attempts — the "survived-challenge" half of
  earned entrenchment ([research/novelty.md](../research/novelty.md) rank 3) is built as
  [ADR 0015](0015-survived-challenge-recording.md). Still open here:
  uniqueness-constrained-predicate flags for the LFI tier.
- Grounded in [belief-revision.md](../belief-revision.md) and
  [ADR 0005](0005-belief-base-revision-semantics.md).
