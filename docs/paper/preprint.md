# dent8: Memory Integrity for LLM Agents via an Event-Sourced Claim Model with Replayable Belief Revision

**Draft preprint.** This is a working draft generated against the current implementation;
every "built" claim below maps to code and tests in the dent8 repository
([STATUS.md](../STATUS.md) is the authoritative built-vs-planned ledger). Section
numbering follows [outline.md](outline.md). Author/affiliation blocks are placeholders.

---

## Abstract

Long-running LLM agents accumulate memory that is silently mutated, deleted, or
overwritten, so it becomes impossible to know a fact's provenance, its freshness, or
whether stronger evidence has replaced it. Recent work shows this persistent memory is a
durable attack surface: a privilege-less user can poison an agent's long-term memory
through query-only interaction with >95% success, persisting across sessions and users
[3]. We argue the missing primitive is *memory integrity*, not memory persistence, and
that integrity should be the **source of truth** rather than a feature bolted onto a vector
or graph store. dent8 models every belief as a stream of immutable `ClaimEvent`s — a
subject–predicate–value triple carrying confidence, authority, a time-to-live, provenance,
evidence, and bitemporal validity — and materializes memory as a deterministic fold over
the ordered log, so retraction and supersession leave an auditable trace instead of
destroying history. We formalize the belief lifecycle as a state machine whose transitions
instantiate the operational spirit of **belief-base** revision (Hansson) rather than
logically-closed AGM revision [1][2], and justify contradiction-tolerance through the
inconsistency-vs-triviality distinction of paraconsistent logic [4]. The integrity layer
is a **write-path firewall**: it rejects a lower-authority claim that attempts to override
a higher-authority one (and the *laundered* variant of that attack), hard-alarms a
contradiction against a canonical fact, admits low-authority *dissent* without letting it
override, and authority-gates *removal*. We give a layered correctness argument —
exhaustive bounded (lattice-enumerated) tests plus Kani model checking for the core
arbitration invariants — and a tamper-evident hash chain extended with an external HMAC anchor that
detects a history rewrite an internal re-verification cannot. We evaluate with a
reproducible adversarial corpus: across MINJA-style injection, authority laundering,
canonical contradiction, and Sybil corroboration, **0/4 attacks succeed against the
firewall while 4/4 compromise a recency-only baseline**. We are explicit that several
integrity primitives are not individually novel — Zep/Graphiti already ships bitemporal
validity, contradiction-driven edge invalidation, and provenance [7] — and locate dent8's
contribution in the *combination*: an event-sourced source of truth with deterministic
replay, typed authority-versus-confidence arbitration, machine-checked non-resurrection,
and policy-counterfactual replay.

## 1. Introduction

Agent frameworks increasingly treat "memory" as a persistence problem: store the agent's
observations in a vector index or knowledge graph and retrieve them later. Persistence is
necessary but not sufficient. Once memory survives across sessions it becomes a *durable
attack surface* and an *audit liability*: an operator cannot tell why the agent believes
something, whether that belief is current, who asserted it, or whether it quietly replaced
a better-sourced fact. The security framing is now concrete — MINJA demonstrates that a
privilege-less user, interacting only through ordinary queries, can implant persistent
false memories in an LLM agent with high success and cross-session/cross-user persistence
[3], and PoisonedRAG shows a handful of injected texts can dominate retrieval [14].

The usual responses edit memory *in place* (overwrite the old value [11]) or arbitrate
conflicts by *recency* (newest write wins [7]). Both discard exactly the information an
auditor or a defense needs: the prior value, its provenance, and the basis on which it was
replaced. We take the opposite stance. **Memory integrity is the source of truth.** Every belief
is an append-only stream of immutable claim events; the believed state is a pure function
of that log; and every state change — assertion, reinforcement, supersession, retraction,
contradiction — is itself a recorded, replayable event. "Delete" becomes a `retracted`
event, not data loss; "update" becomes a `superseded` event that preserves the lineage.

This reframing lets us treat conflict resolution as **belief revision** with an explicit
epistemic ordering (authority), rather than an implicit recency heuristic, and lets us
*verify* properties of that revision. Our contributions:

1. **An event-sourced claim model** (§4) where provenance, evidence, authority,
   freshness, contradiction, and supersession are first-class typed fields, and
   materialized memory is `fold(events)`.
2. **A belief-revision semantics** (§5) for the lifecycle, mapped onto *belief-base*
   (non-closed) revision with a deliberate failure of the Recovery postulate, and
   authority modeled as epistemic entrenchment kept separate from confidence.
3. **A write-path integrity firewall** (§6) — authority-weighted supersession and
   retraction, anti-laundering, a paraconsistent contested state, a canonical-claim
   hard-alarm, and read-time freshness.
4. **A layered correctness argument** (§7): exhaustive bounded authority-lattice tests and
   Kani model checking of *non-resurrection*, plus a tamper-evident hash chain and an
   external anchor for tamper-resistance.
5. **A reproducible poisoning-robustness evaluation** (§9): the firewall blocks four
   attack families that compromise a recency-only baseline.

## 2. Threat model

The adversary of record is a **malicious end-user** with query-only access who can cause
the agent to write attacker-chosen claims (the MINJA case [3]); a **compromised source**
that feeds false tool output or documents; and a **low-authority agent** attempting to
override higher-authority facts. An **operator with database access** is partially in
scope — we make tampering *evident* and, under an external-witness assumption,
*resistant* — and a network/transport attacker is out of scope (delegated to TLS). dent8
does not prevent an agent from *acting* on bad context; it makes the badness **visible and
attributable** so that policy and an audit replay can catch it. Authority is *asserted*,
not *proven*: dent8 defends against low-privilege injection, not a compromised
high-authority principal (the binding of authority to an authenticated source is a
deployment responsibility).

## 3. Background and related work

**Agent-memory systems.** Mem0 mutates memory in place [11]; Zep/Graphiti maintains a
bitemporal knowledge graph with contradiction-driven edge invalidation but arbitrates
conflicts by recency ("consistently prioritizes new information") [7]; Letta/MemGPT and
the MCP memory server expose memory as a tool surface. dent8 differs by making the
*event log* the source of truth and arbitration *authority-weighted* rather than
recency-only.

**Belief revision.** AGM revision operates on logically-closed belief *sets* and demands
postulates (notably Recovery) that are awkward for an engineering store [1]. Hansson's
*belief-base* revision operates on a finite, non-closed base and is the better fit; we
adopt its operational spirit and deliberately *reject* Recovery (§5) [2].

**Paraconsistency.** Classical logic trivializes under contradiction (ex falso quodlibet).
Paraconsistent logic separates inconsistency from triviality [4]; dent8's `contested`
lifecycle localizes a contradiction and preserves both claims rather than dropping one or
exploding.

**Temporal data and event sourcing.** Bitemporality (transaction time vs valid time,
SQL:2011 [12]) motivates dent8's split between `recorded_at` and `observed_at`/`valid_from`.
Event-sourcing practice [13] informs the append-only-log-plus-projection design and the
versioned canonical encoding.

**Tamper-evident logs.** Certificate Transparency's Merkle log and signed tree heads [9]
and JSON canonicalization [6] inform the hash chain and the anchor — including the
asymmetric (Ed25519 signed-tree-head) variant, whose published head is verifiable with the
public key alone.

## 4. The claim-event model

A `ClaimEvent` is the sole primitive. It carries a typed subject (`EntityRef`, a
kind+key), a predicate, an optional value, a `Confidence` (probabilistic, `u16`
milliprobability), an `Authority` (an ordered epistemic level `Unknown < Low < Medium <
High < Canonical`, with optional issuer/scope), a `Ttl`, mandatory provenance (source,
actor, tool, run, input digest, `recorded_at`), evidence references, and the bitemporal
`observed_at`/`valid_from` axes. Its `kind` is one of `Asserted`, `Reinforced`,
`Superseded{by, reason}`, `Contradicted{by, basis}`, `Retracted{reason}`, `Expired`,
`Retrieved`, or `UsedInDecision`.

The believed state of a claim is `fold(apply_event, events)` over its ordered stream.
`apply_event` is a total function from `(Option<ClaimState>, &ClaimEvent)` to
`Result<ClaimState, TransitionError>`. Materialization is therefore deterministic and
replayable: the same ordered log always yields the same projection, and any divergence
between a stored projection and `fold(log)` is a defect by definition. A second projection,
`replay_entity`, folds *all* claim streams for one subject independently and enables
cross-stream checks (supersession-lineage integrity, earned entrenchment).

## 5. Belief-revision semantics

The lifecycle state machine instantiates *belief-base* revision rather than AGM. Three
design commitments follow. First, the base is the (non-closed) set of believed claims; we
do not compute logical closure. Second, **Recovery is deliberately not satisfied**:
re-asserting a previously retracted claim does not restore its old dependents or edges; the
re-assertion is a fresh claim with fresh provenance. This blocks a "claim-laundering" path
(retract, then re-assert to silently resurrect a dependency graph). Third, **authority is
epistemic entrenchment** and is kept categorically separate from confidence: a
high-confidence low-authority claim cannot override a low-confidence high-authority one.
Contradiction is handled paraconsistently — a `Contradicted` event moves the incumbent to
`Contested` and *appends* to its `contradicted_by` edge set, localizing the inconsistency
and keeping the store non-trivial.

## 6. The integrity firewall

The write path is a firewall with **two tiers**. The **base firewall** — `arbitrate`, run
*inside* `EventStore::append` with no un-arbitrated write path — enforces the
security-critical invariants. A thin **application-level predicate registry** adds
per-predicate *policy* (an authority *floor* and *uniqueness*) that a caller applies
*before* `append`; it is configuration on top of the base firewall, not part of it, and a
caller that skips it loses only those per-predicate checks, never the base invariants.
Together they realize a deliberate **asymmetry** between creating, overriding, removing,
and dissenting.

Base firewall (unbypassable, inside `append`):

- **Authority-weighted supersession.** A `Superseded` event whose replacing claim does not
  out-rank (or tie) the incumbent is rejected (`InsufficientAuthority`). This is the direct
  mitigation for low-privilege memory injection.
- **Anti-laundering.** Because a supersession names a *replacing claim*, an attacker could
  over-state the supersession event's authority while backing it with a weak claim. The
  firewall resolves the replacing claim's *actual* authority and rejects the laundered case
  (`LaunderedAuthority`).
- **Authority-gated retraction.** Removal is terminal, so a `Retracted` event is gated
  exactly like supersession: a lower-authority actor cannot delete a higher-authority fact.
- **Dissent is free.** A `Contradicted` event is *not* authority-gated — any source may
  flag a fact as contested — with one exception: a contradiction against a `Canonical`
  claim is a **hard alarm** (`CanonicalContradiction`, the paraconsistent "gentle
  explosion" tier), not a soft contest.

Application-level registry (per-predicate policy, applied before `append`):

- **Authority floor + uniqueness with contestation.** A predicate can require a minimum
  authority to assert and be marked *unique* (at most one **fresh** believed claim).
  Uniqueness is over *mutually-consistent* believed claims; an explicitly contested set (a
  `Contested` claim plus the contradictors it names) is a surfaced conflict, not a
  violation.
- **Freshness.** A read-time predicate excludes TTL-expired claims from "fresh" reads
  without deleting them; freshness is a separate axis from the event-driven lifecycle.

The net guarantee of the base firewall, stated operationally: *a low-privilege source can
flag a wrong fact, but cannot override, delete, or fabricate one.*

**Tamper-evidence.** Each event is hashed with an injective, length-framed, domain-
separated leaf encoding — `SHA-256(0x00 ‖ version ‖ len(canonical) ‖ canonical ‖ tag ‖
prev)` — over a deterministic sorted-key serialization (a `serde_json` canonical form;
**not** RFC 8785/JCS, a stated limitation §10). Altering any event changes its hash and
every subsequent one, so a stored chain is reverifiable on replay.

**Tamper-resistance (external anchor).** The chain alone is tamper-*evident* but not
tamper-*resistant*: an operator with store access can edit an event *and* re-hash the whole
log forward, producing a self-consistent chain that internal re-verification accepts. dent8
closes this with an **external anchor** — an HMAC-SHA256 commitment to `(event_count,
head)` under a witness key held off the writer's machine. A rewrite changes the head, so
the witness commitment no longer verifies and cannot be forged. The construction adds **no
new dependency** (HMAC over the existing SHA-256, validated against an RFC 4231 test vector,
case 1).
We are explicit (§10) that resistance holds only under a witness deployment: the anchor
must be issued by the witness at write time, the key kept off the writer, and a monotonic
anchor sequence published so a never-issued or rolled-back anchor is itself detectable. The
anchor comes in two variants — symmetric (HMAC) and an asymmetric, publicly-verifiable
Ed25519 signed tree head [9] whose published head is checkable with the public key alone;
both are built and tested. What remains future work is the *operational* witness that signs
and publishes the head on a cadence.

## 7. Formal verification

We make a layered, deliberately-bounded correctness argument rather than an unqualified
"formally verified" claim. The security-critical invariant is **non-resurrection**: once a
claim is superseded (or retracted) by authority *A*, no later event of authority below *A*
returns it to the believed set. We establish it two ways over the finite five-level
authority lattice:

- **Exhaustive bounded tests.** For all 25 (incumbent, challenger) pairs, a supersession is
  accepted iff the challenger does not under-rank the incumbent, and a terminal claim
  cannot be resurrected by any later event — including a canonical one. A parallel test
  covers retraction.
- **Bounded model checking (Kani).** The same property is checked symbolically over all
  five authority levels (a symbolic `u8` constrained to the lattice and mapped to a level)
  for both supersession and retraction [5].

Additional invariants are unit/lattice-tested in the core fold: a stream must begin with
`Asserted`; `Reinforced` cannot change a value; terminal states reject mutation; canonical
contradiction hard-alarms; and the hash leaf is injective (a malformed predecessor is
rejected, not silently treated as genesis). We are explicit that Kani results are *bounded*
and that full property-based testing (`proptest`) and deductive proof of the fold are
future work [8].

## 8. Implementation

dent8 is a Rust workspace (edition 2024, `rustc` 1.95, `unsafe_code = "forbid"`, clippy
pedantic) of five crates: `dent8-core` (model, fold, hashing, anchor), `dent8-store`
(the `EventStore` trait, the firewall `arbitrate`, an in-memory backend, the coding-agent
registry, policy-counterfactual and entity replay), `dent8-evals` (the adversarial
corpus), `dent8-cli` (the runnable surface), and `dent8-store-postgres` (the operational
schema, adapter pending). The base firewall *is* `EventStore::append`: every write passes
base arbitration (override-gate, anti-laundering, canonical hard-alarm), with no
un-arbitrated write path *for those invariants*; the per-predicate authority floor and
uniqueness are an application policy the CLI applies before `append` (§6). A documented
trusted-reload path (`from_trusted_events`) is the only way to rehydrate an
already-admitted log without re-arbitration. A persistent, file-backed CLI exposes the
full lifecycle — `assert`, `supersede`, `retract`, `contradict`, `explain`, `replay` —
composing across process invocations and re-validating log integrity on load. We are
explicit (§10) that the stock binary uses a single-writer **dev** store; the operational,
transactional Postgres backend (`PostgresEventStore`) is built, **DB-verified**, and **driven
by the CLI/MCP** when `DENT8_DATABASE_URL` is set (a `--features postgres` build), each
multi-event operation committed transactionally. The remaining productization step is an
authn/authz layer (authority is client-supplied) and an operational witness service.

## 9. Evaluation

We evaluate *integrity*, not retrieval quality, with a reproducible adversarial corpus
(`dent8-evals`). Each scenario is a concrete attack — a sequence of claim events a
poisoning adversary might submit — run two ways: through the **real firewall**
(`EventStore::append`) and through a **recency-only baseline** that resolves conflicts by
"newest write wins" with no authority arbitration (the strategy dent8 argues against). An
attack *demonstrates* a defense only if the firewall blocks it *and* the baseline is
compromised.

| Attack family | Firewall | Recency-only baseline |
|---|---|---|
| MINJA low-authority injection | blocked | **compromised** |
| Authority laundering | blocked | **compromised** |
| Canonical contradiction | blocked | **compromised** |
| Sybil corroboration | blocked | **compromised** |

**Attack-success rate: 0/4 against the firewall, 4/4 against the baseline.** Two
safeguards keep this honest. A *positive control* asserts that a legitimate
equal-or-higher-authority supersession **is** admitted — the firewall is not a blanket
"reject all change" gate. A *mechanism* test asserts the first three families are rejected by their *intended*
typed control (`InsufficientAuthority`, `LaunderedAuthority`, `CanonicalContradiction`)
rather than incidental validation; the Sybil family is not an error-code case — it is
checked separately, by the divergence between a naïve corroboration *count* (fooled by
volume) and authority-weighted corroboration (unmoved by ten low-authority sources). The external anchor is evaluated by
the rewrite test in §6: on a re-hashed-forward edit, internal `verify_chain` returns true
while `verify_against_anchor` returns false. Planned additions: golden replay fixtures, a
`proptest` property suite, and a TTL-expiry (T4) family.

## 10. Limitations and threats to validity

- **Model-vs-implementation gap and bounded proofs.** Verification covers the core fold
  over the finite authority lattice; it is not a whole-system proof, and Kani results are
  bounded [5].
- **Canonicalization is not frozen to JCS.** The canonical form is a sorted-key
  `serde_json` encoding that coincides with RFC 8785 only because all keys are ASCII and
  all numbers are integers. Embedded `ClaimValue::Json` is itself canonicalized (a
  `CanonicalJson` newtype, sorted-key + compact, re-applied on deserialize), so the bytes
  invariant holds for it too; freezing the *outer* encoding to JCS for cross-implementation
  interop is the remaining canonicalization item [6].
- **The anchor is symmetric and assumes a witness deployment.** Resistance requires the
  witness to issue the anchor at write time with an off-writer key and publish a monotonic
  sequence; the primitive alone does not provide it, and a writer who holds the key, never
  anchors, or replays a stale anchor gets no resistance.
- **No operational persistence yet.** The file backend is single-writer and
  non-transactional; concurrency/serializability are unevaluated until the Postgres adapter
  exists.
- **Overlap with prior art.** Bitemporality, contradiction-driven invalidation, and
  provenance individually overlap with Zep [7]; the contribution is the combination (§11).

## 11. Novelty positioning

An adversarial novelty pass refuted every *single-primitive* claim against 2026 prior art.
dent8's defensible novelty is **compositional**, led by two medium-novelty claims pitched
as "first to unify/transplant," never "first to invent":

1. **Verified non-resurrection** — a machine-checked invariant that, once a claim is
   superseded/retracted by authority *A*, no sub-*A* sequence returns it to the believed
   set. This turns a MINJA/PoisonedRAG-class attack from an empirical success rate into a
   *refuted reachability claim*.
2. **Policy-counterfactual replay** — re-folding the same hash-chained log under a swapped
   `EpistemicPolicy` (distrust a source, raise the authority floor) with zero LLM calls,
   distinct from stochastic remove-and-rerun "counterfactuals."

We benchmark against Mem0 [11], Zep [7], Letta, and the MCP memory server on *integrity*
axes — provenance-on-write, deterministic replay, supersession-preserves-history,
contradiction-is-auditable, authority-weighted arbitration, tamper-evidence — and
explicitly **not** on retrieval F1/LOCOMO, where dent8 does not compete.

## 12. Conclusion and future work

dent8 reframes agent memory as an integrity problem and shows that an event-sourced claim
model with authority-weighted belief revision can make poisoning *visible, attributable,
and — for the headline non-resurrection property — refutable by construction*, with a
reproducible adversarial evaluation and a tamper-evident log made tamper-resistant under an
external-witness deployment (§6, §10). The honest frontier is the operational layer: an
authn/authz layer that maps a verified caller to its allowed authority (the CLI/MCP already
run on the DB-verified transactional Postgres backend via `DENT8_DATABASE_URL`, but authority
is client-supplied), a published anchor cadence (the asymmetric signed-tree-head
primitive is built; the signing/publishing witness is not), a `valid_to` validity interval
(reads already apply TTL freshness — `explain` flags stale facts), the official `rmcp` SDK
(the v0 server already does tools, resources, and batches), and a broader
property/fixture suite.
A short workshop paper on the model and belief-revision semantics is claimable now; the
full systems/security paper should follow the operational backend.

## References

- [1] *Logic of Belief Revision* — Stanford Encyclopedia of Philosophy. https://plato.stanford.edu/entries/logic-belief-revision/
- [2] S. O. Hansson, *Revision of Belief Sets and Belief Bases*. https://link.springer.com/content/pdf/10.1007/978-94-011-5054-5_2.pdf
- [3] *MINJA: A Practical Memory Injection Attack against LLM Agents*, arXiv:2503.03704. https://arxiv.org/html/2503.03704v2
- [4] *Paraconsistent Logic* — Stanford Encyclopedia of Philosophy. https://plato.stanford.edu/entries/logic-paraconsistent/
- [5] *Kani Rust Verifier — feature support / limitations*. https://model-checking.github.io/kani/rust-feature-support.html
- [6] *RFC 8785: JSON Canonicalization Scheme (JCS)*. https://datatracker.ietf.org/doc/html/rfc8785
- [7] *Zep: A Temporal Knowledge Graph Architecture for Agent Memory*, arXiv:2501.13956. https://arxiv.org/html/2501.13956v1
- [8] *Lessons Learned Verifying the Rust Standard Library*, arXiv:2510.01072. https://arxiv.org/html/2510.01072v1
- [9] *RFC 6962: Certificate Transparency*. https://www.rfc-editor.org/rfc/rfc6962.html
- [10] *Fundamental Problems With Model Editing*, arXiv:2406.19354. https://arxiv.org/html/2406.19354v1
- [11] *Mem0: Building Production-Ready AI Agents with Scalable Long-Term Memory*, arXiv:2504.19413. https://arxiv.org/html/2504.19413v1
- [12] *SQL:2011 temporal features*. https://en.wikipedia.org/wiki/SQL:2011
- [13] *Event Sourced Systems and Their Schema Evolution*, arXiv:2104.01146. https://arxiv.org/abs/2104.01146
- [14] *PoisonedRAG: Knowledge Corruption Attacks to RAG*, USENIX Security 2025, arXiv:2402.07867. https://arxiv.org/abs/2402.07867
