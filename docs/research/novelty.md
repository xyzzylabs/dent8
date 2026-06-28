# Open / Candidate Research Directions (Exploratory)

> **Status: exploratory.** This document is a *vetted idea backlog*, not decided
> architecture. Each direction was generated from a research lens, then adversarially
> checked against prior art (refute-default) — most candidates were killed. Nothing
> here is a commitment; treat it as "where defensible novelty could live," and read it
> after [related-work.md](../related-work.md) and the
> [dossier](dossier.md). Prior-art citations were **partially verified** (see
> §Verification status) — verify the rest before any paper citation.

## The honest thesis

dent8 has **no defensible novelty in any single primitive.** Event sourcing,
hash-chain tamper-evidence, bitemporal memory, contradiction-tolerant belief bases,
audit-logging of rejections, and verifiable decision receipts are all occupied by
2026 prior art (TOKI, MemLineage, Adaptive Memory Admission Control, the
agent-governance receipt drafts, blockchain full-node validation, Hansson screened
revision). The vetting killed 6 of 12 candidate ideas outright — including the one
that looked strongest on paper (non-prioritized revision with recorded refusal).

What the prior art does **not** collectively provide is a single artifact in which
**typed authority-weighted supersession is the contradiction-resolution gate, and
that gate is a deterministic, replayable, hash-pinnable fold over one append-only
log.** dent8's defensible novelty is therefore necessarily *compositional and
substrate-derived*, and it all routes through **authority arbitration in
`apply_event`** — which, as of roadmap §0, **is now implemented** (the prerequisite
has landed; it is no longer vapor). Each surviving direction is *medium* novelty —
pitch them as "first to unify / transplant," never "first to invent."

## The pivot: one change unlocks all three top directions (now landed)

All three top-ranked directions depend on the same prerequisite — the roadmap §0
[authority-as-entrenchment](../decisions/0007-authority-as-entrenchment.md) change,
which is **now implemented and tested** in `crates/dent8-core/src/state.rs`:
`apply_event`'s `Superseded` arm rejects a challenger whose authority is strictly
below the incumbent's, and the `Contradicted` arm hard-alarms against a canonical
claim.

The rank-1 theorem *proves a property of it* (and now has a runnable exhaustive proof
+ a `#[cfg(kani)]` harness — see rank 1 below); rank-2 *varies it*; rank-3 *feeds it*.
With the prerequisite built, all three are now buildable rather than blocked.

## Defensible directions (survivors)

### 1. Verified non-resurrection — *machine-checked anti-poisoning invariant* (rank 1)

**Idea.** Discharge **one** integrity theorem: *once a claim is superseded by an event
of authority A, no sequence of events all below A can ever return it to the believed/
`Active` set in any reachable projection.* This converts a MINJA/PoisonedRAG-class
attack from an empirical attack-success-rate into a **refuted reachability claim.**

**Status: partially built.** The authority gate is implemented; the invariant is
*proven now* over the full 5×5 `AuthorityLevel` lattice by the runnable exhaustive
test `authority_monotone_supersession_and_non_resurrection`, and a `#[cfg(kani)]`
harness (`supersession_is_authority_monotone_and_non_resurrecting`) ships ready for
`cargo kani`. Remaining for the *paper* claim: actually run Kani (not installed here)
and/or a Creusot/Verus unbounded proof of the fold, and extend from the single-stream
fold to the cross-stream projection (resurrection-via-new-`claim_id`).

**Why defensible (medium).** The closest occupied cells are disjoint along orthogonal
axes: the Isabelle/AFP AGM mechanization has machine-checked proofs but no authority
lattice and no executable fold; LBAC/CHERI have verified lattice-monotonicity but in
access control, not belief-set membership; verified CRDT convergence has monotone
folds but no authority gate; the 2025–2026 agent-memory-security literature names
authority-scoped write-gating as an *open problem* and only ever ships empirical ASR.
The proof technique is textbook (monotonicity of a fold over a join-semilattice); the
contribution is the **domain transplant + a shipped, scoped artifact.** Scope strictly
to "first machine-checked authority-non-resurrection invariant for agent memory as a
poisoning-integrity theorem" — *not* "first verified belief revision."

**Build:** the gate + exhaustive proof are done; the remaining Kani/Creusot run and
cross-stream extension are medium. **Paper:** the cheapest credible novelty flag (a
proof, not an ASR number) — and the closest to claimable today.

### 2. Policy-counterfactual replay — *re-fold under a swapped epistemic policy* (rank 2)

**Idea.** Make the fold parametric in an explicit `EpistemicPolicy`; default policy ==
identity (a strict superset of current behavior). A what-if query swaps one knob —
*"distrust `source:web-scrape`"*, *"raise the authority floor to High"* — and re-folds
the **same** log, returning the alternate belief set plus a structural diff (which
claims flip `Active`↔`Contested`↔`Superseded`, which contradiction edges and evidence
appear/disappear), with **zero model invocations.** This is the ATMS
assumption-environment idea, made concrete and deterministic.

**Status: prototyped and tested.** Implemented in `crates/dent8-core/src/policy.rs`
(`EpistemicPolicy` with three trust knobs — `distrusted_sources`, `authority_floor`,
`confidence_floor`) and `crates/dent8-store/src/lib.rs` (`replay_claim_with_policy`,
`StateDiff`, `diff_states`). The headline counterfactual is tested: distrusting a
superseding source keeps the claim `Active`, and the diff reports the flip.
Design refinements vs the original sketch: (1) the *as-of freshness clock* is **not** a
policy knob — freshness is a separate read-time predicate (`ClaimState::is_expired_at`)
so valid-time staleness is never conflated with the event-driven lifecycle; (2) the
*contradiction-resolution rule* is not yet swappable (hard-coded in `apply_event`) — a
documented future knob.

**Why defensible (medium).** The 2026 namesakes MemAudit and CCT define
"counterfactual" as *remove-entry + re-run-the-LLM* (stochastic, majority-vote);
neither swaps an epistemic trust/authority policy nor sits on a deterministic
event-sourced fold. Glavic reenactment is deterministic but the knob is a relational
data edit, not a trust policy. Semiring provenance does deterministic recompute under
swapped weights — so the recompute mechanism isn't new — but no surfaced system
combines (a) epistemic-policy as the knob, (b) a contradiction/supersession lifecycle
as the evaluator, (c) poisoning as the target, with (d) exact no-LLM-rerun
reproducibility. That intersection is empty.

**Build:** core mechanism done; remaining for a paper claim is a swappable
contradiction-resolution rule and an over-an-entity (multi-claim) replay surface.
**Paper:** a memory debugger no agent-memory system offers.

### 3. Earned entrenchment — *protection derived from challenge-survival* (rank 3)

**Idea.** Derive a claim's revision-resistance threshold from the event history rather
than declaring it: a non-prioritized operator whose credibility bar for revising claim
C is a pure, replayable **fold** over the log — the count of authority-weighted
supersession attempts C survived from sources ≥ its own authority, plus the number of
distinct independent authorities that re-asserted it. A claim that withstood
high-authority challenges accrues entrenchment and forces incoming claims to clear a
higher bar; the decision is explainable ("protected because it survived these 4
challenges") and deterministically replayable because entrenchment is a *fold*, not
stored state.

**Status: v0 built and tested.** `ClaimState` tracks `corroborating_sources`
(distinct backers → highest authority each backed at) with `corroboration()` and the
Sybil-resistant `corroboration_at_or_above(level)`; `EntityProjection::unearned_supersessions`
audits each supersession against the replacing claim's *actual* state, flagging
`AuthorityDowngrade` (replacement is really lower-authority than its stated event) and
`WeakerCorroboration` (less authority-weighted backing at equal authority). The Sybil
flood is defeated in code (qualified count, not raw) and tested. **Not built:** the
"survived supersession attempts" half — rejected attempts are not in the accept-only
log, so it needs the firewall to *record refusals* at write time (a write-path
feature). And this is an **audit that detects** unearned supersessions, not a write
gate that *prevents* them (the challenger lives in another stream; prevention belongs
in the future entity-aware firewall).

**Why defensible (medium).** Truth-discovery (TruthFinder, Knowledge Vault) turns
corroboration into a probability of truth, never a *raised revision threshold*.
Dynamic-scope / credibility-limited revision explicitly leaves the scope-update rule
open; deriving it from challenge-survival fills that open slot and answers SSGM's
named-but-unsolved drift-vs-legitimate-update problem. Capped at medium because
"survived more challenges → harder to revise" restates belief perseverance; novelty is
the composition. The Sybil/corroboration-farming failure mode is handled by
authority-weighting (not raw count), and stated honestly.

**Build:** medium (read-side projection feeding the rank-1 gate; no schema change).

### Also surviving (lower priority)

- **Source-distrust blame assignment** — minimal trust-revocation that un-poisons the
  belief set (the inverse search of policy-counterfactual replay; related to MemAudit's
  blame attribution but deterministic and policy-valued).
- **Replay-certified cascade recovery** — retract a poisoned source, cascade-retract
  dependents via evidence edges, and *replay to certify* the belief set is restored
  (MemLineage states "prevention is not recovery" and does no cascade — this is the
  recovery half).
- **Adversarial false-merge as an authority-gated, preserved `Contested` event** — an
  identity-channel-separation invariant defending against ShadowMerge-style merge
  attacks (the rigorous, testable form of the "pattern separation" origin story).

## Killed — do not claim these as novel

| Killed candidate | Prior art that kills it |
|---|---|
| Non-prioritized revision w/ recorded refusal | Adaptive Memory Admission Control (credibility-vs-incumbent admission) + Memory Poisoning Attack & Defense (logs reject decisions); reduces to screened revision (Fermé–Hansson) over an event log |
| Revision / arbitration receipts | Crowded 2026 field: microsoft/agent-governance-toolkit (Ed25519+JCS), IETF receipt drafts, MeshQu Decision Receipts |
| Differential replay as a poisoning oracle | This *is* blockchain full-node validation (re-execute log, recompute state root, halt on mismatch); some with Coq/Isabelle proofs (Velisarios, Canton) |
| Authority-lattice metamorphic conformance suite | TOKI (arXiv 2606.06240) — typed bitemporal contradiction-resolution algebra with soundness theorems + multi-system audit |
| "Belief base" / paraconsistent `contested` as novelty | Vocabulary (Hansson, 40+ yrs); Zep already does contradiction-via-edge-invalidation |

## Verification status of prior art

Spot-checked and **confirmed real** (titles verified against arXiv):

- TOKI — *A Bitemporal Operator Algebra for Contradiction Resolution in LLM-Agent Persistent Memory* ([arXiv:2606.06240](https://arxiv.org/abs/2606.06240))
- *Adaptive Memory Admission Control for LLM Agents* ([arXiv:2603.04549](https://arxiv.org/abs/2603.04549))
- *Memory Poisoning Attack and Defense on Memory Based LLM-Agents* ([arXiv:2601.05504](https://arxiv.org/abs/2601.05504)) — note: its specific "logs every rejection to a durable audit log" claim is **not** confirmed from the abstract; the candidate it killed had a second, solid ground.
- MemLineage — *Lineage-Guided Enforcement for LLM Agent Memory* ([arXiv:2605.14421](https://arxiv.org/abs/2605.14421))

**Not yet verified** (surfaced by the vetting agents; verify before citing in the
paper): SSGM (2603.11768), MemAudit (2605.23723), CCT (2605.22842), ShadowMerge
(2605.09033), the agent-governance-toolkit / IETF receipt drafts, MeshQu Decision
Receipts.

## Recommended next

**[DONE] Authority arbitration in `apply_event`** (rank-1 prerequisite) — implemented
and tested, with the exhaustive non-resurrection proof and a `#[cfg(kani)]` harness.

**[DONE] Rank 2, policy-counterfactual replay** — `EpistemicPolicy` +
`replay_claim_with_policy` + `diff_states`, prototyped and tested (see rank 2 above).

**Now:** (1) run the Kani harness in CI (`cargo kani`) and/or add a Creusot/Verus
unbounded fold proof to upgrade rank 1 from "exhaustive over the lattice" to
"machine-checked"; (2) extend rank 2 with a swappable contradiction-resolution rule
and an entity-level (multi-claim) counterfactual surface; (3) carry the arbitration
into the transactional write path once the Postgres adapter (roadmap §2) exists.
