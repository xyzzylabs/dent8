# dent8 as a Model-Training Substrate (Exploratory)

> **Status: exploratory.** This document maps how dent8 *could* feed model
> fine-tuning (SFT, RL/RLVR, DPO, and related). It is a positioning/feasibility note,
> **not a committed feature** and **not usable today as a training pipeline**:
> dent8 has serialized events and a Parquet event-log export, but no dataset schema,
> label materializer, split/version manifest, or trainer integration yet (see
> §"The missing plumbing"). Read it after [related-work.md](../related-work.md) and
> [novelty.md](novelty.md).

## Thesis

dent8 is **not a trainer** — it has no model, gradients, or optimization loop, and it
never will. What it is, is a **data / reward / preference substrate**: an append-only,
provenanced, replayable log of belief operations, plus audits over that log. That makes
it a clean *producer* of the labeled signals that external training stacks (TRL,
Axolotl, OpenRLHF, verifiers, etc.) consume.

Two honest boundaries frame everything below:

1. **It aligns memory/belief behavior, not general capability.** dent8's signals are
   about *what to believe, when to revise, and how to attribute* — not prose quality or
   broad instruction-following. The natural target is a *memory-managing* agent (or the
   memory-relevant behavior of a general agent), not a base model's style.
2. **It is enabled-by-architecture, not built as a dataset product.** Every mapping
   below is supported by dent8's design and the implemented `dent8-core`/`dent8-store`
   layer, and the raw event-log export exists, but the materializer that turns those
   logs and audits into training-ready examples does not.

## Cleanest-fit ranking

| Rank | Technique | Why it fits | dent8 features it uses |
|---|---|---|---|
| 1 | **DPO / preference** | Supersession/contradiction graph *is* preference data; dent8 uniquely lets you *filter* to legitimate preferences | supersession lineage, `SupersessionReason`, `unearned_supersessions`, authority-weighted corroboration |
| 2 | **RLVR (verifiable rewards)** | dent8 is a deterministic, checkable verifier — the invariants are the reward | replay, invariants, `lineage_issues`, `unearned_supersessions`, TTL/freshness, audit events |
| 3 | **Data curation** (pre-train/SFT filter) | Provenance-aware quality layer; lowest barrier (no RL loop) | provenance, contradiction/retraction, freshness, pattern-separation/dedup |
| 4 | **SFT** | Clean *(context → correct memory op)* labels | the firewall decision + replay invariants as ground truth |
| 5 | **Constitutional AI / RLAIF** | dent8's policy is a "memory constitution"; accept/reject = AI feedback | `EpistemicPolicy`, firewall accept/reject, authority/provenance rules |

## 1. DPO / preference optimization — cleanest structural fit

**What dent8 produces.** A preference triple is *(context, chosen, rejected)*. dent8's
supersession graph yields these directly: for a subject+predicate, the **superseded
claim is `rejected`** and the **superseding claim is `chosen`**, with
`SupersessionReason` as the labeled basis — and `UserCorrection` supersessions are
gold-standard *human* preferences. Contradiction edges (with authority/freshness basis)
give preferences over conflicting claims; [counterfactual replay](novelty.md)
(`replay_*_with_policy` + `diff_states`) can synthesize additional contrastive pairs
under different trust policies.

**Why dent8 beats a plain preference set.** Preference-data *quality* is the known
weakness of DPO-style methods. dent8 addresses it head-on:

- **Poisoning filter.** `EntityProjection::unearned_supersessions` flags
  `AuthorityDowngrade` and `WeakerCorroboration` supersessions — so you can **drop the
  pairs where the "preferred" claim was an attacker's injection**, instead of training
  on them. No plain preference corpus can do this.
- **Confidence weighting.** Authority-weighted corroboration
  (`corroboration_at_or_above`) and the `confidence` field rank how trustworthy each
  preference is.
- **Provenance.** Every pair traces to its source/evidence, so a dataset can be audited
  and bad sources purged retroactively.

**Caveat.** These are preferences over *beliefs* (which claim about a subject+predicate
to hold), not over arbitrary generations. They train factual/memory revision behavior,
not response aesthetics.

## 2. RLVR — best mechanism fit

**What dent8 produces.** RL with verifiable rewards needs a deterministic, automatable
verifier and no human labeler. dent8 *is* that verifier: the integrity invariants are a
reward function. A candidate memory action gets:

- **+** if it survives replay, carries provenance + ≥1 evidence, respects authority
  arbitration, and is fresh;
- **−** if it introduces a hidden contradiction, uses a TTL-stale claim in a decision
  (observable via `claim.used_in_decision` on an expired claim), triggers an
  `unearned_supersession`, or leaves a `lineage_issue` (dangling/cyclic supersession).

Because replay is deterministic and the audits are pure functions, the reward is
exactly reproducible — the RLVR ideal.

**Caveat.** This shapes the agent's *memory-write/read policy*, not its general
reasoning. It is closest to "reward model = the integrity layer."

## 3. Training-data curation — most immediately practical

Not a fine-tuning technique, but the **lowest-barrier, highest-near-term-value** use:
dent8 as a provenance-aware quality layer *in front of* any SFT/pretraining pipeline.

- **Provenance** → weight/trace sources; drop data from sources later retracted.
- **Contradiction detection** → flag conflicting labels for the same subject+predicate.
- **Retraction cascade** → purge poisoned data and everything derived from it.
- **Freshness (TTL)** → drop stale facts before they teach an outdated world.
- **Pattern separation** (the dentate-gyrus origin, made rigorous) → dedup
  near-duplicate examples and avoid false merges of distinct facts.

This needs only the audit functions plus an export — no model, no RL loop.

## 4. SFT — moderate fit

dent8 yields clean *(context, correct memory operation)* labels: given existing claims
and a new fact, the ground-truth transition (assert / reinforce / contradict /
supersede / retract) is fixed by the firewall + replay invariants. Good for training a
memory agent's **write decisions** or for teaching a model to **attach proper
provenance/evidence/authority/TTL** (dent8's required-field schema is the target
format). It is not a generation corpus, so applicability is narrower than (1)–(2).

## 5. Constitutional AI / RLAIF — conceptual fit

dent8's policy (authority + provenance + freshness + contradiction rules, expressible
as an `EpistemicPolicy`) is a literal **constitution for memory**, and the firewall's
accept/reject/quarantine decisions are ready-made AI-feedback labels. Process-reward
modeling is also natural: the replay trace is a step-by-step process to label. Most
aspirational of the set.

## The missing plumbing (what to build to make this real)

None of the above is usable until dent8 can *export* its log and audits as datasets.
The first plank is **built**: `dent8 export` ([storage.md](../storage.md#analytical-lane-export-only-not-a-runtime-store))
emits the event log as flattened Parquet, with the `DerivedFrom` dependency edges
materialized. The remaining planks below build on that substrate:

1. **The event log + projections** (JSONL/Parquet) — the raw substrate. *(Built for the event
   log via `dent8 export`; projection export is still to come.)*
2. **Preference pairs** — derived from supersession/contradiction edges, *pre-filtered*
   by `unearned_supersessions`, with `SupersessionReason` and corroboration as metadata.
3. **Reward traces** — per memory action, the invariant verdicts (replay-survived,
   provenance-complete, lineage-clean, fresh, earned) as a reward vector.
4. **Curation manifests** — source trust, contradiction clusters, retraction cascades,
   freshness flags, dedup groups.

These reuse functions that already exist (`replay_entity`, `lineage_issues`,
`unearned_supersessions`, `diff_states`, `is_expired_at`); serialization is no longer the
blocker, so the remaining work is choosing the dataset schema and deciding which exported
traces are product-critical rather than merely interesting.

## Honest caveats

- **Behavior, not capability.** Repeated for emphasis: this trains memory/belief
  management, not general intelligence.
- **The dataset product is not built.** The event-log export exists, but there is no
  preference/reward dataset schema, materializer, split/version manifest, or trainer
  integration. Pitching dent8 as a "fine-tuning tool" would be exactly the overclaim the
  rest of the docs avoid — it is a *substrate provider* feeding an external trainer.
- **Belief preferences ≠ response preferences.** The DPO mapping produces preferences
  over claims, which is a narrower (and arguably cleaner) signal than typical RLHF
  response-preference data.
- **Garbage-in caveats carry over.** Authority is asserted not proven, corroboration is
  Sybil-resistant only when authority-weighted (see [threat-model.md](../threat-model.md)),
  and a poisoned-but-well-formed claim can still be learned. The *filtering* dent8 adds
  reduces, not eliminates, bad training signal.

## Why this is a real positioning angle

It widens dent8's story from "inference-time agent memory" to **"the provenance and
integrity layer for verifiable rewards and preference data."** The features already
built map onto it one-to-one: supersession lineage → preference pairs;
`unearned_supersessions` → preference *filtering*; the invariants → verifiable rewards;
counterfactual replay → contrastive data. It is worth a paragraph in the
[paper outline](../paper/outline.md)'s future-work now that raw export exists — but
only as future work until a dataset materializer exists.

## Further reading (verify IDs before formal citation)

- DPO — Rafailov et al., *Direct Preference Optimization* (arXiv 2305.18290).
- Constitutional AI / RLAIF — Bai et al. (arXiv 2212.08073).
- RLVR / verifiable rewards — associated with the Tülu 3 line and broader
  verifiable-reward RL work; confirm the specific reference before citing.
