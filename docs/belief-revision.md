# Belief Revision: dent8's Formal Identity

dent8 was designed bottom-up from an engineering intuition — keep an append-only
log of claims, fold it into a current view, and never silently destroy history.
That intuition independently re-derives several results from a decades-deep formal
literature on how rational agents change their minds. Naming that literature is
not decoration: it gives dent8 a vocabulary, a set of theorems, and — crucially —
a set of *postulates dent8 deliberately violates*, which is exactly the precision
a memory-integrity product needs to defend its claims.

This document is the conceptual backbone for [domain-model.md](domain-model.md).
It states which mappings are rigorous and which are inspirational, and turns the
rigorous ones into concrete code obligations.

## The formal toolkit

**AGM belief revision.** The Alchourrón–Gärdenfors–Makinson framework (1985) is the
canonical theory of rational belief change [1]. It defines three operations over a
belief set `K` (a logically *closed* set of sentences): *expansion* `K+p`,
*contraction* `K−p` (give up `p` without adding anything), and *revision* `K*p`
(add `p` while restoring consistency). Revision derives from contraction by the
**Levi identity** `K*p = (K−¬p)+p`. Contraction is pinned down by six postulates —
Closure, Success, Inclusion, Vacuity, Extensionality, and the famously disputed
**Recovery** (`K ⊆ (K−p)+p`).

**Belief base vs belief set.** Classical AGM operates on logically closed sets and
demands global consistency. Hansson's **belief-base** revision instead operates on
a finite, *syntactic, non-closed* set of explicitly held sentences; derived beliefs
are recomputed, not stored, and **Recovery fails** for bases [2]. Hansson's
**kernel contraction** is the base-level contraction operator. This is the theory
that actually matches dent8.

**Epistemic entrenchment.** When two beliefs conflict, which survives? AGM answers
with an *entrenchment ordering* — a preference relation (Transitivity, Dominance,
Conjunctiveness, Minimality, Maximality) that is a structure *separate from* the
content or probability of the beliefs [1].

**Truth Maintenance Systems.** Doyle's JTMS (1979) and de Kleer's ATMS (1986) are
the operational analog: nodes carry *justifications*, are labelled IN/OUT, and
contradictions are resolved over *nogoods* via dependency-directed backtracking. A
JTMS maintains one consistent context; an ATMS labels each fact with the minimal
assumption-sets (*environments*) under which it holds, maintaining many contexts at
once [3].

**Paraconsistent and non-monotonic logic.** Paraconsistent logic rejects
*ex contradictione quodlibet* — the principle of explosion by which a single
contradiction makes a classical theory *trivial* (everything derivable). The
load-bearing distinction is **inconsistency vs triviality**: a knowledge base can
contain a contradiction without becoming trivial, and the Stanford account
explicitly motivates this for databases that "frequently contain
contradictions...because of multiple sourcing" [4]. Non-monotonic logic (Reiter's
Default Logic) formalizes defeasible inference; Gärdenfors and Makinson proved
belief revision and non-monotonic reasoning inter-translatable [5].

## Mapping dent8 onto the formalisms

The lifecycle state machine lives in [`crates/dent8-core/src/state.rs`](../crates/dent8-core/src/state.rs);
the data model in [`crates/dent8-core/src/model.rs`](../crates/dent8-core/src/model.rs).

| dent8 construct | Formal operation | Rigor |
|---|---|---|
| `claim.asserted` into a fresh stream | **Expansion** of a base | Inspirational |
| `claim.superseded` (`Superseded { by, reason }`) | **Revision** (replace value, keep consistency) | Inspirational |
| `claim.retracted` (`Retracted { reason }`) | **Contraction** / kernel contraction | Inspirational |
| `contested` on `claim.contradicted` | **Paraconsistent toleration** of inconsistency | Rigorous (architectural) |
| `Authority` vs `Confidence` | **Entrenchment** vs probability/evidential strength | Rigorous (architectural) |
| `claim.expired` / TTL | **Defeasible/temporal defeat** | Inspirational — TTL read surface built; explicit expiration authority-gated |
| `dent8_claim_edges` | **TMS justifications** | Rigorous (data-structure level) |
| `replay_claim` fold → projection | TMS **labelling pass** / non-monotonic consequence | Rigorous as motivation |

**Why the operator mappings are "inspirational," not rigorous.** AGM and even
Hansson reason over *logical formulas* with entailment. dent8 stores opaque
`subject + predicate + value` triples (`EntityRef`, `Predicate`, `ClaimValue`) with
**no deductive closure and no entailment engine**. dent8 must not claim "AGM
compliance." It can honestly claim it implements the *operational spirit* of
belief-base revision — and "base" is the load-bearing word.

**Why belief-base, not belief-set, is the right anchor.** dent8's "memory" is a
fold/projection over the immutable `ClaimEvent` log (`apply_event`); it stores
asserted claims, not their closure. The *same projection can arise from different
event histories, and the history matters*. dent8 **deliberately does not satisfy
Recovery**: retracting a claim and later re-asserting it must *not* silently
resurrect everything that depended on the original, because the new assertion
carries different `Provenance` and `Evidence`. This is the answer to the inevitable
"this isn't real AGM" objection: correct — it is belief-base revision, and Recovery
is the wrong axiom for an auditable store. See
[ADR 0005](decisions/0005-belief-base-revision-semantics.md).

**The contested state is the rigorous core.** In `state.rs`, a `Contradicted`
event sets `lifecycle = Contested` and *appends* to `contradicted_by` rather than
discarding either side. Silently merging `A` and `¬A` would *trivialize* the store.
The contested-with-preserved-edges design is exactly the paraconsistent move:
localize the contradiction, keep the store non-trivial, surface it. This converts
the project slogan into a citable principle (inconsistency ≠ triviality) [4].

**Authority vs confidence is entrenchment vs probability.** `model.rs` already
derives `Ord` on `AuthorityLevel` (`Unknown < Low < Medium < High < Canonical`) and
on `Confidence` (0..=1000 integer millis). Entrenchment theory validates keeping
these as *two distinct fields*: entrenchment (which belief to surrender first) is
formally separate from evidential strength [1].

## What dent8 should adopt — and the code obligations

> Honesty note: items 2 and 3 are **now implemented** in the `dent8-core` fold —
> `apply_event` arbitrates supersession by authority and hard-alarms canonical
> contradictions, with a runnable exhaustive non-resurrection test and a `#[cfg(kani)]`
> harness. A v0 of **earned entrenchment** (item 2's refinement) is also built —
> authority-weighted corroboration on `ClaimState` plus an entity-level
> unearned-supersession audit. Still *design intent*: item 4 (JTMS-vs-ATMS), the
> freshness *read surface* (item 5's evaluator exists), the "survived-challenge" half
> of earned entrenchment (needs recorded refusals), and transactional enforcement at
> the store layer. See [roadmap.md](roadmap.md), [threat-model.md](threat-model.md),
> and [research/novelty.md](research/novelty.md).

1. **Name belief-base revision (Hansson) and paraconsistency/LFI as the backbone**
   in the domain model, and explicitly disclaim Recovery and AGM-set compliance.
   Cite kernel contraction for retraction semantics [2][4].
2. **Authority as an entrenchment ordering that drives supersession resolution.**
   *Implemented:* `apply_event`'s `Superseded` arm rejects a challenger whose authority
   is strictly below the incumbent's (`InsufficientAuthority`), with confidence kept
   separate. Tested directly (`lower_authority_supersession_is_rejected`,
   `equal_authority_supersession_succeeds`) and exhaustively over the 5×5 authority
   lattice. *Earned entrenchment v0 built:* `ClaimState` tracks authority-weighted
   corroboration (`corroboration_at_or_above`), and `EntityProjection::unearned_supersessions`
   audits supersessions against the replacing claim's real authority/corroboration
   (`AuthorityDowngrade`, `WeakerCorroboration`; Sybil-resistant). *Still future:* the
   challenge-survival half (needs recorded refusals) and a write-time gate
   ([research/novelty.md](research/novelty.md) rank 3).
3. **The LFI "gentle explosion" tier.** *Implemented:* `apply_event`'s `Contradicted`
   arm returns `TransitionError::CanonicalContradiction` for a contradiction against
   an `AuthorityLevel::Canonical` claim, while ordinary contradictions still localize
   to `contested` (tested: `contradicting_a_canonical_claim_hard_alarms`,
   `contradicting_a_non_canonical_claim_still_contests`). *Still future:* extending the
   hard-alarm to predicates flagged *uniqueness-constrained* (no such flag exists in
   the model yet).
4. **Treat `dent8_claim_edges` as TMS justifications; decide JTMS vs ATMS.** dent8
   today is JTMS-like (one projection, one labelling). The "memory debugger"
   differentiator is the ATMS capability — replay claims under an assumption
   *environment* ("trust only `High`+ authority sources") to answer "what does
   memory look like if I distrust source Z." This shapes the replay API and
   deserves its own decision record [3].
5. **Frame TTL/expiry as principled non-monotonic defeat.** The read-time freshness
   evaluator and CLI/MCP receipt surface are built; explicit `claim.expired` is a
   separate authority-gated terminal close (ADR 0011). Remaining work is a richer
   `valid_to` interval and freshness on every summary surface [5].

**Deliberately do NOT:**

1. **Do not build an entailment engine or claim AGM compliance.** Opaque triples by
   design; logical closure is out of scope.
2. **Do not enforce global consistency.** AGM's Consistency postulate is the
   *opposite* of the contested state. Local, auditable inconsistency is a feature.
3. **Do not implement Recovery.** Re-assertion must not resurrect dependents.
4. **Do not collapse authority and confidence into one score.**

In short: dent8 is a **belief base with paraconsistent contradiction-tolerance, an
authority-as-entrenchment ordering, and TMS-style justification edges over a
replayable log** — a precise, defensible formal identity the codebase is already
shaped toward, but has not yet implemented at the arbitration layer.

## References

- [1] [Logic of Belief Revision — Stanford Encyclopedia of Philosophy](https://plato.stanford.edu/entries/logic-belief-revision/)
- [2] [Hansson, *Revision of Belief Sets and Belief Bases* (Springer)](https://link.springer.com/content/pdf/10.1007/978-94-011-5054-5_2.pdf)
- [3] [Problem Solving and Truth Maintenance Systems (Temple CIS)](https://cis.temple.edu/~ingargio/cis587/readings/tms.html)
- [4] [Paraconsistent Logic — Stanford Encyclopedia of Philosophy](https://plato.stanford.edu/entries/logic-paraconsistent/)
- [5] [Non-Monotonic Logic — Stanford Encyclopedia of Philosophy](https://plato.stanford.edu/entries/logic-nonmonotonic/)
