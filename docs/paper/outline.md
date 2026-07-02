# Academic Preprint Plan

> A working **draft** built from this plan lives in [preprint.md](preprint.md); this file
> remains the planning skeleton (titles, venues, novelty positioning, evaluation plan).

A publication-oriented skeleton, written against dent8's *current* state. Built and
tested: `dent8-core` (model, lifecycle state machine, typed IDs, **authority arbitration
+ retraction**, the **freshness evaluator**, **policy-counterfactual replay**), serde +
event hashing, the **unbypassable write-path firewall** with anti-laundering, the
**coding-agent predicate registry**, a **persistent file-backed CLI**
(`assert`/`supersede`/`retract`/`contradict`/`reinforce`/`expire`/`derive`/`explain`/`replay`,
plus `facts list`/`verify`/`conflicts`/`eval`), the **`dent8-evals`
adversarial corpus** (firewall vs recency-only baseline), an **external HMAC anchor** for
tamper-resistance, and an **asymmetric (publicly-verifiable) signed-tree-head anchor**
(Ed25519, feature-gated). The CLI/MCP run on the **operational Postgres adapter** (the
adapter — incl. the materialized projection/edge graph — is DB-verified against `postgres:16`,
and with `DENT8_STORE_URL` the runnable surface uses it, each multi-event operation
committed transactionally; the stock binary keeps the file dev store). Still gated on
implementation: **identity operations** (the signed identity primitive and secure init path are
built as `dent8 init --identity`, `dent8 init --agent <profile>`, and `dent8 identity`;
remaining work is key distribution/rotation and external signers), the
official **`rmcp` SDK** (the v0 stdio server already does tools, resources, and JSON-RPC
batches, and reads apply freshness), and a **published anchor cadence** (a witness that
signs/publishes the head on its own infra).
The plan separates what is *claimable now* from what is *gated on
implementation*, and is explicit about the weakest novelty claims. Prior art and the
fact-checked basis are in [related-work.md](../related-work.md) and
[research/dossier.md](../research/dossier.md).

## Title options

1. *dent8: Memory Integrity for LLM Agents via an Event-Sourced Claim Model with
   Replayable Belief Revision*
2. *Claims, Not Memories: An Append-Only, Bitemporal Belief Base for Auditable Agent
   Memory*
3. *Integrity as Substrate: Provenance, Contradiction, and Supersession as
   First-Class Primitives for Agent Memory*

Option 1 is the safest banner. Option 2 leads with the belief-base framing (the most
defensible theoretical hook). Option 3 overclaims "substrate" relative to a
pre-runtime codebase — avoid for an academic venue.

## Abstract / thesis (one paragraph)

Long-running LLM agents accumulate memory that is silently mutated, deleted, or
overwritten, making it impossible to know a fact's provenance, freshness, or whether
stronger evidence has replaced it — and recent work shows persistent agent memory is
a durable attack surface, with query-only injection achieving >95% success and
persisting across sessions [3]. We argue *memory integrity*, not memory persistence,
is the missing primitive, and that it should be the substrate rather than a feature
bolted onto a vector or graph store. dent8 models every belief as a stream of
immutable `ClaimEvent`s (subject+predicate+value with confidence, authority, TTL,
provenance, evidence, and bitemporal validity); materialized memory is a
deterministic fold over the ordered log, so retraction and supersession leave an
auditable trace instead of destroying history. We formalize the lifecycle as a state
machine whose transitions instantiate the operational spirit of *belief-base*
revision (Hansson) rather than logically-closed AGM revision [1][2], justify
contradiction-tolerance via the inconsistency-vs-triviality distinction from
paraconsistent logic [4], and give a layered correctness argument — exhaustive
property tests and bounded model checking for core invariants, plus a hash-chained
append-only log for tamper-evidence [5][6]. We evaluate on golden replay fixtures and
adversarial memory-poisoning scenarios drawn from the attack literature [3]. We are
explicit that several integrity primitives are not unique — Zep/Graphiti already
ships bitemporal validity, contradiction-driven edge invalidation, and provenance
[7] — and locate dent8's contribution in the *combination*: an event-sourced source
of truth with deterministic replay, typed authority-vs-confidence arbitration, and
verifiable invariants.

## Contributions

- **An event-sourced claim model** in which provenance, evidence, authority,
  freshness/TTL, contradiction, and supersession are first-class typed fields on an
  immutable `ClaimEvent`, and materialized memory is `fold(events)` — so "delete" is
  a recorded `retracted`/`superseded` event, not data loss.
- **A belief-revision semantics for the lifecycle state machine**, mapped explicitly
  onto *belief-base* (non-closed) revision and kernel contraction rather than
  classical AGM, with a stated, deliberate failure of the Recovery postulate, and
  authority modeled as epistemic entrenchment kept separate from confidence [1][2].
- **A formally-checked invariant set**: projection == fold(events); single-`asserted`
  prefix; `reinforced` never changes value; terminal immutability; fresh reads
  exclude expired; contradiction/supersession leave auditable edges — as property
  tests + bounded model checking, with a layered-portfolio justification [5][8].
- **A tamper-evidence design** using a frozen, versioned canonical encoding (dent8's
  sorted-key compact `serde_json` form, explicitly **not** RFC 8785/JCS) and
  RFC 6962-style domain separation [6][9].
- **An integrity/poisoning-robustness evaluation** turning the threat literature into
  a reproducible benchmark: authority-weighted supersession resists query-only
  injection, and every poisoned write remains traceable and replayable [3].

> Scope honestly (see Threats to validity): **authority arbitration is implemented**
> in the core fold (with exhaustive non-resurrection tests + Kani harnesses for both
> supersession and retraction), the **tamper-evidence hash chain + external anchor are
> built** — serde canonicalization + SHA-256 + injective leaf + a witness-keyed
> `(count, head)` commitment, with both a **symmetric (HMAC)** and an **asymmetric
> (Ed25519 signed tree head)** variant — and the **integrity evaluation is built** (the
> `dent8-evals` corpus, bullet 5). Still plans: TTL-expiry evaluation, a published anchor
> cadence (operational witness), and the transactional Postgres store-layer enforcement.

### Novelty positioning (read [research/novelty.md](../research/novelty.md))

An adversarial novelty pass killed every *single-primitive* claim against 2026 prior
art (TOKI [19]-class typed contradiction algebras, MemLineage Merkle provenance,
confidence-gated admission). dent8's defensible novelty is **compositional and
substrate-derived**, and it routes through authority arbitration in `apply_event` —
**now implemented**, so the directions below are buildable rather than blocked. The
two strongest, defensible contributions to lead with (both *medium* novelty, pitched
as "first to unify/transplant," never "first to invent"):

1. **Verified non-resurrection** — a machine-checked invariant that, once a claim is
   superseded by authority *A*, no sequence of sub-*A* events can return it to the
   believed set. Turns a MINJA/PoisonedRAG-class attack from an empirical ASR into a
   *refuted reachability claim* — the cheapest credible novelty flag.
2. **Policy-counterfactual replay** — re-folding the same hash-chained log under a
   swapped `EpistemicPolicy` (distrust a source, raise the authority floor), with zero
   LLM calls — distinct from the stochastic remove-and-rerun "counterfactual" of 2026
   namesakes (MemAudit, CCT).

## Section outline

1. **Introduction** — persistence-vs-integrity gap; the poisoning threat [3]; the
   external-store thesis (parametric model editing is belief revision with shaky
   foundations [10]); contributions.
2. **Background & related work** — Mem0 mutate-in-place [11]; Zep/Graphiti bitemporal
   graph [7]; Letta/MemGPT; MCP memory server; AGM & belief bases [1][2];
   paraconsistency/LFI [4]; bitemporal DBs and SQL:2011 [12]; event sourcing & schema
   evolution [13]; tamper-evident logs [9].
3. **Model & semantics** — `ClaimEvent` and typed IDs; the lifecycle state machine;
   fold/projection; the bitemporal axes (`observed_at`/`valid_from` vs `recorded_at`
   [12]); belief-base mapping and the Recovery non-postulate [2].
4. **Invariants & formal verification** — the invariant list (grounded in
   [evals.md](../evals.md)); the layered method (property/stateful tests; Kani
   bounded model checking; optional Creusot/Verus on the fold; Stateright for
   serializability) [5][8], with explicit bounded-vs-universal caveats.
5. **System & implementation** — the Rust workspace (edition 2024, `unsafe`
   forbidden, clippy pedantic); `dent8-core`; Postgres schema 001; honest status of
   unbuilt components.
6. **Evaluation** — the built `dent8-evals` adversarial corpus (MINJA, laundering,
   canonical contradiction, Sybil, poisoned-source retraction) showing **0/5 attack success
   against the firewall vs 5/5 against a recency-only baseline** [3], plus the exhaustive
   authority-lattice test
   and Kani proofs; comparison axes. Still to add: golden replay fixtures, `proptest`
   property results, TTL-expiry evaluation.
7. **Threats to validity** — model-vs-implementation gap; bounded proofs;
   canonicalization-not-yet-frozen; the file backend is a single-writer dev store (no
   transactional/concurrent evaluation yet); **TTL-expiry and Postgres-layer evaluation
   pending**; overlap with Zep [7].
8. **Limitations & future work** — ATMS-style assumption-environment replay; valid-
   time intervals (`valid_to`); predicate-level volatility policy; the sqlx adapter
   and log-conformance checking.

## Evaluation plan

- **Golden replay fixtures.** Populate `evals/fixtures` and `evals/replay` with the
  families in [evals.md](../evals.md). Each asserts: fresh read returns only the
  current value; the prior value is excluded but preserved; a supersession/
  contradiction edge exists and is explainable. The executable form of
  `projection == fold(events)` and "fresh reads exclude expired."
- **Property tests.** `proptest`/stateful with an independent reference model:
  determinism, no-transition-after-terminal, reinforced-value-stability, single-
  `asserted`-prefix, claim isolation. Escalate the most critical to Kani for bounded
  coverage [5].
- **Adversarial poisoning.** Replay PoisonedRAG/MINJA-style injection sequences [3]
  and assert that low-authority writes do not auto-supersede high-authority active
  claims (vs Graphiti's recency-only arbitration [7]), that poisoned writes are quarantined or out-ranked, and
  that the audit log + hash-chain trace every poisoned write to its provenance.
  *(Note: this depends on authority arbitration — cite the MemConflict-style scenario
  with its not-yet-peer-reviewed caveat.)*
- **Comparison axes (integrity, not retrieval).** Provenance-on-write, deterministic
  replay, supersession-preserves-history, contradiction-is-auditable, authority-
  weighted arbitration, tamper-evidence. Benchmark against Mem0 [11], Zep [7], Letta,
  MCP memory on *these* axes — **not** retrieval F1/LOCOMO, where dent8 does not
  compete.

## Weakest novelty claims & how to strengthen

- **"Bitemporal + supersession + provenance are our differentiators."** Weakest
  claim: Zep ships all three [7]. *Strengthen* by reframing as the *combination* and
  making **authority-weighted supersession** the headline (Graphiti arbitrates
  contradictions by recency only — "consistently prioritizes new information" [7]) —
  after implementing it.
- **"Belief-revision semantics."** Weak if stated as AGM compliance. *Strengthen* by
  claiming the *operational spirit of belief-base revision* and disclaiming closure +
  Recovery [1][2].
- **"Formally verified."** Overclaims. *Strengthen* to "property-tested + bounded-
  model-checked, fold optionally deductively verified, concurrency model-checked" —
  and ship the proofs [5][8].
- **"Tamper-evident hash-chain + external anchor."** Built+tested in `dent8-core`
  (versioned canonical encoding, `0x00` domain separation [9], injective leaf, round-trip
  + tamper-cascade tests), **populated** by the in-memory/file store, and extended with an
  external anchor that catches a re-hashed-forward rewrite (witness-keyed `(count, head)`),
  in both a symmetric (HMAC) and an asymmetric (Ed25519 signed tree head) variant. Caveats:
  **not** RFC 8785/JCS; the anchor *primitives* are built (the Postgres append path is
  DB-verified) but the operational witness that signs/publishes the head on a cadence is
  unbuilt. *Claim tamper-resistance only with the off-writer witness-key assumption.*
- **"Pattern separation" framing.** A loose neuroscience analogy; CA3 pattern
  *completion* does not map at all. *Strengthen* by defining pattern separation as a
  testable invariant (distinct subject+predicate streams never merge; near-duplicate
  assertions never fork) — otherwise confine it to the origin story, out of the
  academic framing.

## Venues & sequencing

- **arXiv primary:** `cs.AI` (agent memory / belief revision), cross-listed `cs.DB`
  (event sourcing, bitemporal) and `cs.CR` (poisoning, tamper-evidence); `cs.LO` only
  if the belief-revision/paraconsistency formalization is developed substantively.
- **Workshops (best near-term fit, given a pre-runtime artifact):** agent-memory /
  long-context / continual-learning workshops at NeurIPS/ICLR/ACL; LLM-security
  venues for the poisoning evaluation; a systems/DB venue once the adapter and
  replay runtime exist.
- **Sequencing:** publish a short workshop/preprint on the *model and belief-revision
  semantics* now (claimable from `dent8-core` alone); gate the systems/security paper
  on the replay runtime, the hash-chain, authority arbitration, and a populated
  `evals/`. Conflating the two before the runtime exists is the single biggest
  credibility risk.

## References

- [1] [Logic of Belief Revision — SEP](https://plato.stanford.edu/entries/logic-belief-revision/)
- [2] [Hansson, *Revision of Belief Sets and Belief Bases*](https://link.springer.com/content/pdf/10.1007/978-94-011-5054-5_2.pdf)
- [3] [MINJA: A Practical Memory Injection Attack against LLM Agents (arXiv 2503.03704)](https://arxiv.org/html/2503.03704v2)
- [4] [Paraconsistent Logic — SEP](https://plato.stanford.edu/entries/logic-paraconsistent/)
- [5] [Kani Rust Verifier — limitations](https://model-checking.github.io/kani/rust-feature-support.html)
- [6] [RFC 8785: JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- [7] [Zep: A Temporal Knowledge Graph Architecture for Agent Memory (arXiv 2501.13956)](https://arxiv.org/html/2501.13956v1)
- [8] [Lessons Learned Verifying the Rust Standard Library (arXiv 2510.01072)](https://arxiv.org/html/2510.01072v1)
- [9] [RFC 6962: Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962.html)
- [10] [Fundamental Problems With Model Editing (arXiv 2406.19354)](https://arxiv.org/html/2406.19354v1)
- [11] [Mem0 (arXiv 2504.19413)](https://arxiv.org/html/2504.19413v1)
- [12] [SQL:2011 temporal](https://en.wikipedia.org/wiki/SQL:2011)
- [13] [Event Sourced Systems and Their Schema Evolution (arXiv 2104.01146)](https://arxiv.org/abs/2104.01146)
