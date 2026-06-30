# Research Dossier

This dossier is the synthesized output of a multi-source, fact-checked research pass
on dent8's design space (agent-memory integrity, belief revision, formal
verification, provenance/tamper-evidence, and academic positioning). It is the
*entry point*; the depth lives in the topical docs it links. Claims here were
produced by parallel web-search agents, then adversarially fact-checked (16
load-bearing claims: 14 supported, 1 refuted, 1 qualified). Corrections from that
pass are folded into the topical docs and noted below.

## Executive summary

1. **dent8 is principled, not novel-per-primitive.** Every individual mechanism —
   bitemporal validity, supersession-not-deletion, contradiction edges, provenance,
   deterministic replay, hash-chained logs — is prior art (Zep/Graphiti, PROV,
   SQL:2011, event sourcing, Certificate Transparency). These foundations predate and
   are independent of Zep; the overlap with Zep is convergent evolution on shared
   sources, not derivation. The defensible contribution is the *combination as
   substrate* plus **typed authority-weighted supersession**.
   → [related-work.md](../related-work.md)

2. **Belief revision is the right formal identity, and it's a clean fit.** dent8 is a
   **belief base** (Hansson), not an AGM belief set; it should *deliberately violate
   Recovery*; its `contested` state is genuine **paraconsistency** (inconsistency ≠
   triviality); authority-vs-confidence is **entrenchment vs probability**; edges are
   **TMS justifications**. This is the "fresh and inspiring" lens and dent8's
   strongest defensible framing. → [belief-revision.md](../belief-revision.md)

3. **A layered formal-verification stack is achievable today.** proptest/bolero →
   Kani (bounded) → Stateright (concurrency) → optional Creusot/Verus (the fold).
   Frame honestly as "property-tested + bounded-model-checked + concurrency-model-
   checked," never blanket "formally verified."
   → [formal-verification.md](../formal-verification.md)

4. **The honest gap is narrowing.** **Authority arbitration is now implemented** in
   the core fold (the headline differentiator vs Graphiti's recency-only resolution),
   with an exhaustive non-resurrection proof. The freshness evaluator and serde +
   canonicalization + hash chain are also built and tested in the library. The
   write-path firewall (enforced at `EventStore::append`), the **DB-verified** Postgres
   adapter, the CLI/MCP runtime, and the **evidence-edge retraction taint** (ADR 0010,
   `dent8 derive`/`verify` + the `poisoned_source_retraction` eval) are **built** — the
   differentiator is now a running, demonstrated system (see [STATUS.md](../STATUS.md)). The
   analytical/export lane is also built (`dent8 export` → Parquet for DuckDB), and the
   file-based scenario-family golden corpus is seeded ([`evals/`](../../evals/README.md)); what
   remains on the eval side is `cargo-fuzz`.
   → [roadmap.md](../roadmap.md), [threat-model.md](../threat-model.md)

5. **Publish in two stages.** A model + belief-revision-semantics workshop paper is
   claimable now from `dent8-core`; the systems/security paper must wait for the
   runtime and a populated `evals/`. → [paper/outline.md](../paper/outline.md)

6. **Defensible novelty is compositional, and an adversarial pass killed every
   single-primitive claim.** The surviving directions route through authority
   arbitration — **implemented**. All three top directions now have a built+tested v0:
   rank 1 (verified non-resurrection, exhaustive + Kani harness), rank 2
   (policy-counterfactual replay: `EpistemicPolicy` + `replay_*_with_policy` +
   `diff_states`), and rank 3 (earned entrenchment: authority-weighted corroboration +
   `unearned_supersessions` audit). Remaining for rank 3: the challenge-survival half
   (recorded refusals) and a write-time gate. → [novelty.md](novelty.md)

## What's useful for the project (concrete adoptions)

| Adoption | Source/standard | Where |
|---|---|---|
| Belief-base + Recovery-non-postulate framing | Hansson; AGM | [ADR 0005](../decisions/0005-belief-base-revision-semantics.md) |
| Paraconsistent contradiction tolerance ("contested") | LFI / paraconsistency | [belief-revision.md](../belief-revision.md) |
| Authority-as-entrenchment arbitration | AGM entrenchment | [roadmap.md](../roadmap.md) / [ADR 0007](../decisions/0007-authority-as-entrenchment.md) |
| LFI hard-alarm tier on canonical claims | Logics of Formal Inconsistency | [belief-revision.md](../belief-revision.md) §Adopt-3 |
| RFC 8785 (JCS) canonicalization | IETF (Informational) | [ADR 0004](../decisions/0004-canonicalization-and-hash-chain.md) |
| RFC 6962 domain-separated leaf/node hashing | Certificate Transparency | [storage.md](../storage.md) |
| W3C PROV-DM export mapping | W3C Recommendation | [related-work.md](../related-work.md) |
| Layered verification (proptest/Kani/Stateright) | AWS systems-correctness | [ADR 0006](../decisions/0006-formal-verification-stack.md) |
| MINJA/PoisonedRAG poisoning fixtures | attack literature | [threat-model.md](../threat-model.md) |

## Fact-check ledger (corrections applied)

- **Refuted:** "Prusti (uniquely) verifies unsafe code." → Deductive verifiers
  (Creusot/Verus/Prusti/Aeneas) target *safe* Rust with unbounded functional
  correctness at high spec cost; the unsafe-coverage framing was wrong. Fixed in
  [formal-verification.md](../formal-verification.md).
- **Qualified:** RFC 8785 is an *Informational* RFC (Independent Submission), not
  Standards Track; property names sort by UTF-16 code units. Noted in
  [storage.md](../storage.md) / [ADR 0004](../decisions/0004-canonicalization-and-hash-chain.md).
- **Critic corrections folded in:** confidence float hazard was overstated
  (`Confidence` is `u16`; only `ClaimValue::Json` was at risk, now canonicalized via the
  `CanonicalJson` newtype); the temporal-validity
  matrix cell downgraded ✓→◐ (no `valid_to`; freshness evaluator has since been built); TTL/authority
  arbitration flagged as design-only everywhere they are claimed; "AWS originated the
  P language" reworded (P: Microsoft/UC Berkeley); LOC corrected to ~470 non-test.

## Novelty risks (kept deliberately visible)

These are the reviewer objections the project must pre-empt, not hide:

1. **Authority-weighted supersession is THE differentiator vs Graphiti's recency-only
   arbitration — now implemented in the core fold** (no longer "zero code"). The
   remaining honesty caveat is narrower: it is enforced in `apply_event` but not yet
   *transactionally* at a store layer (no Postgres adapter), and the *earned*-
   entrenchment refinement is still future.
2. **Three of four "combination" ingredients are individually prior art** (replay =
   event sourcing; hash-chain = transparency logs; bitemporal/provenance = SQL:2011/
   PROV). Only *typed authority-as-entrenchment arbitration* is uncommon in this
   space.
3. **Belief-base framing is vocabulary, not a novel mechanism** — bitemporal DBs
   already give "history matters, retract doesn't resurrect." Claim it as principled
   grounding, not as a contribution.
4. **On the temporal axis dent8 is currently *behind* Zep** (no `valid_to` interval;
   TTL freshness runs on reads but full bitemporal validity does not). The matrix must
   not overclaim parity.
5. **Deterministic replay alone is not unique** — Zep/Graphiti reconstruct from
   episodes too. The precise differentiator is the *typed, hash-verified,
   single-source-of-truth* log.
6. **Hash-chain tamper-evidence is table-stakes**, not a contribution (RFC 6962,
   blockchains). It is built (canonicalization + SHA-256 chain, DB-verified); the
   *resistance* upgrade (an operated external witness) is the part still maturing.

## Method note

Research harness: scope → 6 parallel search angles → URL-grounded fetch → 3-vote-style
adversarial verification (refute-default) → parallel section synthesis → completeness/
novelty critic. ~28 agents, ~1.3M tokens. The verbatim section drafts, verdicts, and
critic output are preserved outside the repo; this dossier and the topical docs are
the curated, corrected result.
