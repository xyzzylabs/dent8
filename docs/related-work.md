# Related Work and Competitive Landscape

dent8 occupies the intersection of two literatures: a crowded, fast-moving market of
LLM-agent memory systems, and a set of mature data-infrastructure and
formal-reasoning traditions that the agent-memory market has largely failed to
absorb. This document maps both, then states plainly where dent8 is differentiated
and where it is not. It is the prior-art basis for the
[paper outline](paper/outline.md) and should be read alongside
[belief-revision.md](belief-revision.md) and [threat-model.md](threat-model.md).

**Lineage (so the overlap below is not misread).** dent8's primitives descend from
mature, public traditions that *predate and are independent of* any current
agent-memory product: event sourcing / CQRS, bitemporal databases (SQL:2011), belief
revision (AGM / Hansson), the W3C PROV provenance model, and tamper-evident
transparency logs (RFC 6962). Where dent8 overlaps a contemporary system such as
Zep/Graphiti, that is **convergent evolution on shared foundations, not derivation** —
both draw on the same decades-old sources. We cite Zep as prior art precisely because
honest attribution is the point; the overlap is acknowledged, not borrowed, and no
Zep-specific mechanism is presented here as dent8's own.

## Agent-memory systems and products

Contemporary agent-memory systems split into *mutate-in-place* stores and
*temporal/graph* stores. The integrity properties dent8 treats as first-class —
provenance, contradiction handling, temporal validity, supersession, auditability,
deterministic replay — are unevenly supported, and in most systems absent.

**Mem0** is the clearest contrast to dent8's event-sourced stance. Its base
(non-graph) store is mutate-in-place: an LLM tool-call selects
`ADD`/`UPDATE`/`DELETE`/`NOOP` over semantically similar memories, with no
append-only log, no provenance, no confidence, no TTL, and no supersession history;
a `DELETE` destroys the original record [1]. The graph variant `Mem0g` softens this
by marking obsolete relationships *invalid* rather than physically deleting them [1]
— a partial supersession analog, but an attribute flip on a node, not a typed,
replayable event.

**Zep / Graphiti** is dent8's strongest overlap and the most important honesty
check. Zep is "a memory layer service powered by Graphiti, a dynamic,
temporally-aware knowledge graph engine" [2]; the engine-level behaviors below are
Graphiti's. It already ships much of dent8's headline list: per-edge valid-time
(`t_valid`/`t_invalid`) vs system/transaction-time (`t′created`/`t′expired`),
contradiction handling via **edge invalidation** (not deletion — the older edge's
`t_invalid` is set to the invalidating edge's `t_valid`), supersession in place of
deletion, and a **non-lossy** episode store providing provenance from extracted facts
back to source messages [2]. **dent8 cannot claim provenance, temporal validity,
supersession, or contradiction edges as unique.** What Graphiti does *not* do: it
resolves contradictions purely by **recency** — it "consistently prioritizes new
information when determining edge invalidation" [2], arbitrated by neither source
authority nor confidence (a last-write-wins semantics, in our terms); it has no
explicit confidence/authority weighting, no event-sourced log as the source of
truth, no deterministic replay, and no cryptographic hash-chain. The stores are also
architecturally different: Graphiti is graph-database-native (Neo4j, FalkorDB, or
Amazon Neptune) with a hybrid semantic+keyword+graph retrieval layer, optimized for
*retrieval quality* [2a]; dent8 is relational and event-sourced (Postgres), optimized
for transactional append+projection atomicity, append-only auditability, and
deterministic replay. The two solve different jobs — dent8 does not compete on
retrieval and can sit beneath or beside a graph store.

**Letta / MemGPT** is an OS-style tiered-context manager (core/archival/recall
memory edited by the agent itself) — orchestration of the context window, not
auditable claim integrity; no provenance, contradiction edges, supersession history,
or replay as first-class features [3]. It is complementary: dent8 could sit beneath
it as the audited store of record. **A-MEM** models memory as an evolving
Zettelkasten note graph whose "memory evolution" retroactively rewrites the
attributes of historical notes when new memories arrive [4] — closer to Mem0's
mutate model than to an append-only log. **Cognee** adds a typed knowledge graph
with optional temporal extraction [5], richer structure than vector stores but
oriented to modeling event sequence in *content*, not integrity-as-substrate. The
official **MCP "memory" server** is a minimal entity/relation/observation knowledge
graph with no integrity semantics whatsoever [6]; dent8 could ship an MCP server
whose differentiator is exactly these guarantees. **CoALA** is a conceptual taxonomy
(working/episodic/semantic/procedural memory), useful vocabulary for positioning,
not prior art that implements integrity [7].

### Feature matrix (✓ first-class · ◐ partial/heuristic · ✗ absent)

| System | Provenance | Contradiction edges | Temporal validity | Supersession | Audit log | Det. replay | Authority/confidence |
|---|---|---|---|---|---|---|---|
| Mem0 (base) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| Mem0g (graph) | ✗ | ◐ | ◐ | ◐ (mark-invalid) | ✗ | ✗ | ✗ |
| Zep / Graphiti | ✓ (episodic) | ✓ | ✓ (bi-temporal, runs) | ✓ | ◐ | ✗ | ✗ (recency-only) |
| Letta / MemGPT | ✗ | ✗ | ✗ | ✗ | ◐ (DB state) | ✗ | ✗ |
| A-MEM | ✗ | ✗ | ✗ | ✗ (rewrites) | ✗ | ✗ | ✗ |
| Cognee | ◐ | ◐ | ◐ | ✗ | ✗ | ✗ | ✗ |
| MCP memory | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| **dent8** | ✓ (mandatory) | ✓ (typed event) | ◐ (open `valid_from` + TTL; freshness applied on reads — `explain` flags stale, receipt carries `fresh`/`expires_at`; **no `valid_to`**) | ✓ (lineage-preserving) | ✓ (append-only) | ✓ (fold) | ✓ (authority-weighted, core fold) |

Two cells deserve blunt honesty:

- **Temporal validity.** dent8 has `observed_at` + `valid_from` but **no `valid_to`
  interval**, and `apply_event` never evaluates `Ttl` — `Ttl::is_expired_at` is dead
  code. On the temporal axis dent8 is currently *behind* Zep (which has both
  `t_valid` and `t_invalid` plus an edge-invalidation mechanism that actually runs),
  not at parity. Marked ◐, not ✓.
- **Authority/confidence.** The typed fields exist (`AuthorityLevel`, `Confidence`),
  and arbitration is **implemented in the `dent8-core` fold**: `apply_event` rejects a
  strictly-lower-authority supersession and hard-alarms a canonical contradiction —
  the mechanism that distinguishes dent8 from Graphiti's recency-only resolution.
  Marked ✓ for the core fold; transactional enforcement at the store layer is **built and
  DB-verified** (the Postgres adapter — advisory-lock-serialized append + materialization).

Of dent8's differentiating mechanisms, serde serialization, event hashing and the
hash-chain, the real Postgres adapter, the replay/explain runtime, and authority
arbitration are **not yet implemented**, and `evals/` is empty. The guarantees are
credible only once those land — see [roadmap.md](roadmap.md).

## Academic and infrastructure prior art

dent8's primitives are not invented; they recombine four mature traditions — a
strength (the design is principled) that also bounds its novelty.

**Event sourcing / CQRS and bitemporal data.** Treating stored events as an
immutable append-only contract — never mutated in place, evolved only by adding
versions and *upcasting* old events on read — is standard event-sourcing practice.
An empirical study of 19 industrial event-sourced systems found schema evolution to
be the dominant pain point (≈15/19 struggled) with no tooling consensus [8]. This
warns dent8 to commit to a `schema_version` field and upcasting hook *before* any
events are stored, since `projection == fold(events)` is fragile under schema drift,
and since the hash-chain must decide whether `schema_version` is inside or outside
the hashed canonical bytes (see [ADR 0004](decisions/0004-canonicalization-and-hash-chain.md)).
dent8's three time fields are an instance of bitemporal modeling (valid vs
transaction time, standardized in SQL:2011), but PostgreSQL does not implement
SQL:2011 temporal tables natively, so freshness and "replay as-of T" must be
enforced in the `replay_claim` fold, not delegated to the database [9].

**Provenance.** W3C PROV-DM provides a standard vocabulary (Entity/Activity/Agent
plus `wasGeneratedBy`/`wasAttributedTo`/`wasDerivedFrom`/`wasInvalidatedBy`) onto
which dent8's provenance, authority, evidence, and edge model map cleanly, enabling
an interoperable analytical export [10]. Honest caveat: PROV models trust only
structurally and has no confidence metric, so dent8's `confidence` is an extension,
not standard PROV [10].

**Tamper-evident logs.** dent8 has `previous_event_hash`/`event_hash` columns and now a
built+tested canonicalization + SHA-256 hash chain in `dent8-core` (sorted-key
`serde_json` form — **not** RFC 8785/JCS; injective length-framed leaf; `0x00` domain
separation), though the columns are not yet populated by any append path. RFC 8785
(JSON Canonicalization Scheme) was the original plan but is **not** what shipped (see
[ADR 0004](decisions/0004-canonicalization-and-hash-chain.md)); note it is an
*Informational* RFC (Independent Submission stream), it sorts property
names by UTF-16 code units, and it constrains numbers to IEEE-754 doubles and errors
on NaN/Infinity — once a hazard for arbitrary numeric content inside `ClaimValue::Json`,
now mitigated since `CanonicalJson` parses with `serde_json` (which itself rejects
NaN/Infinity); it never affected `confidence`/timestamps (already integers) [11]. Beyond a
linear chain, RFC 6962 (Certificate Transparency) shows how domain-separated
leaf/node hashing (`0x00`/`0x01` prefixes) enables O(log n) inclusion/consistency
proofs — but the prefix rule must be fixed from day one [12].

**Belief revision and knowledge editing.** dent8's contradiction/supersession/
retraction semantics independently reinvent decades-old ideas. The better-matched
theory is not classical AGM (logically-closed *sets*) but Hansson's belief-*base*
revision over non-closed syntactic sets, where Recovery fails — exactly correct for
dent8 [13]. Paraconsistent logic supplies the rigorous justification for "hidden
contradiction is failure, but a visible contradiction must not blow up the store":
the inconsistency-vs-triviality distinction [14]. See
[belief-revision.md](belief-revision.md). Separately, 2024 work argues LLM model
editing *is* belief revision with "shaky" foundations and poor cross-belief
consistency [15] — the academic case that beliefs belong in an external, auditable,
revisable store rather than baked into weights, which is dent8's core bet.

**Memory/RAG poisoning.** The threat literature validates dent8's premise.
PoisonedRAG corrupts retrieval with ~5 injected texts (~90%+ attack success) [16],
and MINJA shows a privilege-less regular user can poison an agent's long-term memory
via query-only interaction (>95% injection success), persisting across sessions [17]
— the most direct analog to dent8's append-time controls. See
[threat-model.md](threat-model.md).

**The 2026 agent-memory-integrity wave.** The design space is not just contested by
Zep — a cluster of 2026 work targets exactly dent8's concerns and further bounds its
novelty: **TOKI** types contradiction-resolution as a bitemporal operator algebra with
soundness theorems and audits Mem0/Zep/Letta/Graphiti against it [19]; **MemLineage**
adds cryptographic provenance + derivation-lineage over an RFC 6962 Merkle log,
explicitly noting "prevention is not recovery" [20]; **Adaptive Memory Admission
Control** gates writes by factual confidence and four other factors [21]; and
poisoning attack/defense work formalizes trust-scored moderation and sanitization
[22]. The implication for dent8 is sharpening, not discouraging: single primitives
(typed contradiction operators, Merkle provenance, confidence-gated admission) are now
*individually* published, so dent8's only defensible territory is the **specific
composition** — typed authority-weighted supersession as the gate, *and* that gate as
a deterministic, replayable, hash-pinnable fold over one append-only log. See
[research/novelty.md](research/novelty.md) for the vetted (and largely killed)
candidate directions.

## Where dent8 is — and is not — differentiated

Honestly stated: dent8 is **not** differentiated on any individual primitive.
Bi-temporal validity, supersession-not-deletion, contradiction edges, and episodic
provenance are all shipped by Zep/Graphiti today [2]; mark-invalid supersession
appears even in Mem0g [1]; provenance and bitemporality are textbook PROV and
SQL:2011 [9][10]; deterministic replay is standard event sourcing [8]; hash-chained
tamper-evidence is textbook transparency-log machinery [12]. Belief-base framing is
good *vocabulary*, not a novel *mechanism* — bitemporal DBs (XTDB/Datomic) already
provide "history matters, retract doesn't resurrect" without naming Hansson.

dent8's defensible wedge is narrower and should be stated precisely: **the
combination treated as substrate rather than feature** — an append-only `ClaimEvent`
log as the single typed, hash-verified source of truth, deterministic replay
(`projection == fold(events)`), and, above all, **typed authority-weighted
supersession** (a regular-user write must not override a high-authority claim — a
direct mitigation for MINJA-style poisoning that Graphiti's recency-only arbitration
cannot offer). The honest caveat: *the headline differentiator is now real in the core
fold but not yet end-to-end* — `apply_event` enforces authority arbitration and the
canonical hard-alarm (with an exhaustive non-resurrection test), but serde, hashing,
the Postgres adapter, replay, and the eval corpus do not yet exist, so the
differentiator is not yet a running system. The closest contemporary system (Zep) —
itself convergent on the same shared foundations — still occupies most of the
conceptual ground. The correct positioning is "the governed, replayable store of record
*beneath* Mem0/Letta/MCP," benchmarked on replay determinism, poisoning resistance,
and auditability — **not** on retrieval F1, where dent8 does not compete.

## References

- [1] [Mem0: Building Production-Ready AI Agents with Scalable Long-Term Memory (arXiv 2504.19413)](https://arxiv.org/html/2504.19413v1)
- [2] [Zep: A Temporal Knowledge Graph Architecture for Agent Memory (arXiv 2501.13956)](https://arxiv.org/html/2501.13956v1)
- [2a] Graphiti backends — [getzep/graphiti](https://github.com/getzep/graphiti) · [Zep Neo4j configuration](https://help.getzep.com/graphiti/configuration/neo-4-j-configuration) (Neo4j 5.26+/FalkorDB/Neptune; Community Edition deprecated 2025-04)
- [3] [Agent Memory — Letta](https://www.letta.com/blog/agent-memory/)
- [4] [A-MEM: Agentic Memory for LLM Agents (arXiv 2502.12110)](https://arxiv.org/abs/2502.12110)
- [5] [Cognee — Temporal Cognification](https://www.cognee.ai/blog/cognee-news/unlock-your-llm-s-time-awareness-introducing-temporal-cognification)
- [6] [Memory MCP Server (modelcontextprotocol/memory)](https://mcpservers.org/servers/modelcontextprotocol/memory)
- [7] [Cognitive Architectures for Language Agents (arXiv 2309.02427)](https://arxiv.org/abs/2309.02427)
- [8] [An Empirical Characterization of Event Sourced Systems and Their Schema Evolution (arXiv 2104.01146)](https://arxiv.org/abs/2104.01146)
- [9] [SQL2011Temporal — PostgreSQL wiki](https://wiki.postgresql.org/wiki/SQL2011Temporal)
- [10] [PROV-DM: The PROV Data Model (W3C Recommendation)](https://www.w3.org/TR/prov-dm/)
- [11] [RFC 8785: JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- [12] [RFC 6962: Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962.html)
- [13] [Hansson, *Revision of Belief Sets and Belief Bases*](https://link.springer.com/content/pdf/10.1007/978-94-011-5054-5_2.pdf)
- [14] [Paraconsistent Logic — Stanford Encyclopedia of Philosophy](https://plato.stanford.edu/entries/logic-paraconsistent/)
- [15] [Fundamental Problems With Model Editing: How Should Rational Belief Revision Work in LLMs? (arXiv 2406.19354)](https://arxiv.org/html/2406.19354v1)
- [16] [PoisonedRAG: Knowledge Corruption Attacks to RAG (USENIX Security 2025, arXiv 2402.07867)](https://arxiv.org/abs/2402.07867)
- [17] [A Practical Memory Injection Attack against LLM Agents (MINJA, arXiv 2503.03704)](https://arxiv.org/html/2503.03704v2)
- [18] [Governed Shared Memory for Multi-Agent LLM Systems (arXiv 2606.24535)](https://arxiv.org/html/2606.24535)
- [19] [TOKI: A Bitemporal Operator Algebra for Contradiction Resolution in LLM-Agent Persistent Memory (arXiv 2606.06240)](https://arxiv.org/abs/2606.06240)
- [20] [MemLineage: Lineage-Guided Enforcement for LLM Agent Memory (arXiv 2605.14421)](https://arxiv.org/abs/2605.14421)
- [21] [Adaptive Memory Admission Control for LLM Agents (arXiv 2603.04549)](https://arxiv.org/abs/2603.04549)
- [22] [Memory Poisoning Attack and Defense on Memory Based LLM-Agents (arXiv 2601.05504)](https://arxiv.org/abs/2601.05504)
