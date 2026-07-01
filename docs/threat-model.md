# Threat Model

dent8's first surface is a **memory firewall**. A firewall is only meaningful
against a stated adversary. This document defines what dent8 defends against, maps
each threat to the control that mitigates it, and is honest about which controls
exist in code today versus which are design intent. It complements
[architecture.md](architecture.md) (write/read paths) and
[related-work.md](related-work.md) (the attack literature).

## Why memory is an attack surface

Long-running agents persist memory across sessions, and that persistence is a
durable attack surface, not just a convenience:

- **PoisonedRAG** corrupts a retrieval corpus with as few as ~5 injected texts and
  achieves ~90%+ attack success [1]. The lesson for dent8: retrieved context is
  attacker-influenceable, so reads must carry integrity metadata, not bare strings.
- **MINJA** is the more direct analog. A *privilege-less regular user* poisons an
  agent's long-term memory through **query-only interaction** — no backend access —
  with >95% injection success that **persists across sessions and across users** [2].
  This is precisely the write-time threat a memory firewall must govern.
- 2026 governance work and OWASP's agentic-security guidance converge on dent8's own
  prescription — provenance on every write, append-only audit logging, explicit
  supersession, freshness decay, and trust/authority-aware retrieval — while noting
  that no major 2026 framework actually governs memory with lineage, freshness, and
  supersession *together* [3].

## Adversary model

| Actor | Capability | In scope? |
|---|---|---|
| Malicious end-user | Query-only interaction; can cause the agent to write attacker-chosen claims (MINJA-style) | **Yes — primary** |
| Compromised/poisoned source | Feeds false tool output or documents that become evidence | **Yes** |
| Compromised low-authority agent | Writes claims attempting to override higher-authority facts | **Yes** |
| Operator with DB access | Can edit Postgres rows directly | Partial — hash-chain makes tampering *evident*, not *impossible* |
| Network/transport attacker | MITM on MCP/HTTP | Out of scope (delegated to TLS/transport) |

Non-goals: dent8 does not prevent an agent from *acting* on bad context; it makes
the badness **visible and attributable** so policy and the debugger can catch it.

## Threats → controls

| # | Threat | dent8 control | Status |
|---|---|---|---|
| T1 | Memory injection by a regular user (MINJA) silently becomes "fact" | **Authority-weighted supersession** (base firewall) + **per-predicate authority floor & uniqueness** (registry) | **Enforced.** The unbypassable base firewall (`EventStore::append` via `arbitrate`) rejects a low-stated-authority supersession *and* a laundered one (over-stated event authority backed by a low-authority claim). The coding-agent registry adds, per predicate, a minimum authority to *assert* (e.g. `repo.database` needs High) and uniqueness — but never gates *dissent* (a low-authority contradiction is always admitted, preserving the canonical hard-alarm). The sanctioned revision path is **Runnable** as `dent8 supersede`: it mints a fresh-id replacement that must out-rank *every* believed incumbent, so a low-authority revision is rejected, not just demoed. The same firewall is **verified over a transactional Postgres backend** — the `DATABASE_URL`-gated adapter tests (incl. laundered-supersession rejection) pass against a live `postgres:16`. |
| T2 | Poisoned source's claims trusted indefinitely | **`claim.retracted` (SourceInvalidated/PoisoningDetected)** + the evidence-edge cascade to dependent claims | **Both Runnable.** Retraction is `dent8 retract` (authority-gated per [ADR 0008](decisions/0008-retraction-authority.md)). The **evidence-edge cascade** ships as **retraction taint** ([ADR 0010](decisions/0010-evidence-edges-and-retraction-taint.md)): `EvidenceKind::DerivedFrom` records a claim→claim derivation (`dent8 derive`), and `dent8 verify` **flags** every still-believed claim that transitively derives from a retracted/expired source (`tainted_claims`, cross-entity + cycle-safe) — *surfaced*, not auto-retracted (paraconsistent "make it visible"). Demonstrated by the `poisoned_source_retraction` eval; auto-cascade-retract on `PoisoningDetected` is the deferred next step |
| T3 | Contradictory claims silently merged or one silently dropped | **`contested` lifecycle + preserved `contradicted_by` edges** (paraconsistency: localize, don't trivialize) | **Runnable** via `dent8 contradict`: dissent (not authority-gated) flags the incumbent `Contested` and keeps both claims; a contested set is exempt from uniqueness ([ADR 0009](decisions/0009-uniqueness-and-contestation.md)). Edge *symmetry* still unbuilt |
| T4 | Stale fact returned as if current | **TTL/freshness**: reads prefer unexpired claims and flag a returned stale one | **Applied on reads.** `explain_subject` deprioritizes expired claims (prefers a fresh believed one, **falling back to a stale one it then flags** — the fact is returned, not hidden), and `explain` (CLI + the MCP `explain` tool + `resources/read`) headline-flags a still-`Active` fact past its TTL as `[stale — TTL elapsed]`; the receipt carries `fresh` + the `expires_at` instant (evaluator `ClaimState::is_expired_at`, a read-time predicate, tested). On the **write** path the registry uniqueness check (`enforce_policy`) excludes expired claims, so a stale fact does not block a fresh re-assertion — whereas `believed_claim_ids` deliberately does *not* filter, so `supersede`/`retract`/`expire` revise every non-terminal incumbent, stale or fresh. Freshness (TTL) is a read-time axis distinct from the lifecycle: a stale-but-`Active` claim is still revisable, while `dent8 expire` is a *separate*, explicit terminal close (`claim.expired`) authority-gated by [ADR 0011](decisions/0011-authority-gated-expiration.md). Remaining: a `valid_to` validity interval and a not-yet-valid `valid_from` lower bound (point-in-TTL upper bound only — a future `valid_from` reads as fresh), and freshness on the `resources/list` summary (only `resources/read`/`explain` flag stale) |
| T5 | Contradiction against a canonical fact treated as ordinary disagreement | **LFI "gentle-explosion" tier**: hard-alarm on contradiction targeting `AuthorityLevel::Canonical` (uniqueness-constrained predicates pending) | **Implemented** in the core fold (`apply_event` → `CanonicalContradiction`) |
| T5b| Poisoned write hidden by lossy summarization | **Evidence never erases source spans** — derived summaries are claims-with-evidence, not privileged replacements (`EvidenceKind::DerivedSummary`) | Type exists; firewall enforcement unbuilt |
| T6 | Operator edits a stored event after the fact | **Hash-chain** (tamper-evidence) **+ external-anchor primitive** (tamper-resistance) | **Primitive built; full resistance needs a witness deployment.** The chain (SHA-256, injective length-framed leaf, `0x00` domain separation) is tamper-evident; `verify_chain` catches an event mutated *without* rehashing. The remaining gap — a writer who re-hashes the whole log forward (internally self-consistent) — is closed by the **anchor** (`dent8_core::anchor`): an HMAC-SHA256 commitment to `(count, head)`. A rewrite changes the head, so the commitment no longer verifies and cannot be forged (tested incl. the re-hashed-forward case). **Resistance holds only when an external witness issues the anchor at write time with a key held off the writer's machine** — these functions are that primitive, *not* a hosted witness service. The asymmetric (Ed25519 signed-tree-head) form is now runnable end-to-end as **`dent8 witness keygen \| sign \| verify \| verify-published`**, which emits heads, re-checks each against the current log's prefix to flag a rewrite (`TAMPER`) or truncation/reorder (`ROLLBACK`), and verifies externally retained heads without trusting the local witness log; the remaining operated pieces are separate infrastructure, a managed publication channel, monitoring, and key rotation. Residuals (symmetric-only, never-anchor, rollback) are enumerated below. The Postgres adapter populates the chain columns and the materialized projection/edges and re-verifies the chain (DB-verified). |
| T7 | Unprovenanced assertion accepted | **Mandatory provenance + ≥1 evidence on `claim.asserted`** | **Implemented** — `ClaimEvent::validate` + schema `CHECK`s |
| T8 | Claim laundering: re-assert a retracted claim to resurrect its dependents | **Recovery deliberately not satisfied** — re-assertion carries fresh provenance, does not restore old edges | Semantics decided ([ADR 0005](decisions/0005-belief-base-revision-semantics.md)). The *fresh-provenance* half is **Runnable**: `dent8 supersede`'s replacement is a brand-new claim id that does not inherit the incumbent's edges. **`dent8 retract` and explicit `dent8 expire` are authority-gated** ([ADR 0008](decisions/0008-retraction-authority.md), [ADR 0011](decisions/0011-authority-gated-expiration.md)) — a low-authority actor cannot terminally remove or close a high-authority fact. The *dependent-resurrection* cascade is the remaining half |

## The firewall write path (target)

The firewall is the enforcement point for T1, T5, T5b, and T7. Per
[architecture.md](architecture.md), a candidate `claim.asserted`/`superseded`/
`contradicted` event must, in one transaction:

1. validate schema, provenance, evidence, authority, TTL (`ClaimEvent::validate` — exists);
2. load relevant active/contested projections for the same subject+predicate;
3. **arbitrate by authority-as-entrenchment** — reject a write that attempts to
   supersede a strictly higher-authority active claim (T1 — *implemented in the core
   fold*; the firewall must call it within the transaction);
4. **apply the LFI tier** — hard-fail a contradiction against a canonical claim
   (T5 — *implemented in the core fold*);
5. append the immutable event and update projections + edges atomically;
6. emit integrity metadata for the read path and debugger.

Steps 3 and 4 — the security-relevant arbitration — are **enforced at the write boundary**
(`EventStore::append` via `arbitrate`), not merely computed in the fold: there is no
un-arbitrated write path. The in-memory backend runs steps 1–6 end-to-end (it is what
`dent8 assert`/`supersede`/… and the demo exercise), and the **Postgres adapter runs them
transactionally** — advisory-lock-serialized, in-transaction projection load + arbitration,
atomic append, and materialized projection/edges (steps 1, 2, 5, 6) — and is **DB-verified**.
So end-to-end firewall behavior *is* runnable — and the CLI/MCP run on `PostgresEventStore`
when `DENT8_STORE_URL` is set (a `--features postgres` build), with each multi-event
operation committed in one transaction. The remaining gap is *productization*, not
enforcement: an opt-in **authority ceiling** caps what each source may assert (`dent8
authority`), and the stock CLI's **signed source identity** layer (`dent8 init --identity`,
`dent8 init --agent <profile>`, or `dent8 identity`) proves source-key possession at the
CLI/MCP boundary when a trust root is configured. The witness is a runnable *primitive*
(`dent8 witness`) but not yet an *operated* service on separate infrastructure.
See [STATUS.md](STATUS.md).

## Residual risks & honest limits

- **Tamper-evidence + external anchor — and its assumptions.** The hash-chain detects
  after-the-fact edits on replay; a DB-admin who rewrites an event *and* re-hashes the
  chain forward produces a self-consistent log that the internal `verify_chain` accepts.
  The **external anchor** (`dent8_core::anchor`) closes this *only under a witness
  deployment* with these assumptions, none of which the primitive alone provides:
  - **Issued by the witness, at write time, off the writer's machine.** A writer who holds
    the key (or computes the anchor itself) can tamper and simply re-anchor — that confers
    no resistance.
  - **Never-anchor.** A writer who never requests an anchor leaves nothing to check; the
    witness must anchor proactively, not on the writer's request.
  - **Rollback / stale anchor.** `verify_anchor` checks *one supplied* anchor with no
    "latest committed" notion, so a writer can present an old anchor for a pre-tamper
    state. Mitigation: a **monotonic, append-only, published anchor sequence**
    (non-decreasing `event_count`) on a cadence, so a missing or rewound anchor is itself
    detectable. `dent8 witness verify-published <heads.jsonl>` verifies such an externally
    retained JSONL sequence; the remaining product work is operating the publication channel
    and monitor outside the writer's control.
  - The symmetric HMAC anchor needs the verifier to hold the witness key; the
    **asymmetric** anchor (`sign_head`/`verify_signed_head`, `signed-anchor` feature) signs
    the same head with Ed25519, so a published head is **publicly verifiable** (RFC 6962-style
    signed tree head). Both are built, and the asymmetric form is runnable as `dent8 witness`
    (which checks each head against the current log prefix and that counts never decrease — the
    monotonic, append-only check above). The remaining piece is *operating* the witness on
    separate infrastructure with managed publication/monitoring and key rotation.
- **Source identity is proven only at the dent8 boundary.** The opt-in **authority registry**
  (`dent8 authority`) caps a stated `Authority` at the source's registered ceiling and
  *rejects* an over-ceiling write — so a low-trust source cannot mint `canonical` even by
  passing it. The stock CLI's **signed source identity** layer (`dent8 init --identity`,
  `dent8 init --agent <profile>`, or `dent8 identity`) adds authn: a trusted issuer signs a
  grant binding source id -> source public key + authority ceiling + optional subject
  scope/expiration, and each write proves possession of the source private key before the
  candidate event reaches the firewall. This closes the "copy a grant but not the key" and
  "claim to be `source:owner`" gap for CLI/MCP writes.
  Residuals: a compromised source private key or same-OS-user process that can read the key
  can still impersonate the source; a compromised issuer can issue bad grants; direct DB
  writes or direct adapter calls bypass this boundary; and a shared MCP server can only prove
  the single identity whose key it holds. Stronger deployments need separate OS users,
  hardware/secret-store-backed keys, external signers, and key rotation. Authority arbitration
  plus the ceiling/identity chiefly defends against *low*-privilege injection (the MINJA
  case); a compromised high-authority actor remains out of scope.
- **The firewall cannot judge truth.** It governs provenance, freshness, authority,
  and contradiction *visibility* — not whether a well-formed, well-sourced claim is
  factually correct. That is the correct scope for an integrity layer.
- **Deserialization trusts field-level validity (but is panic-safe).** `Deserialize` is
  derived for the scalar newtypes, so loading an event does *not* re-run the constructors'
  validation — a hand-edited log line, JSONB row, or MCP argument can carry an out-of-range
  `Confidence`, an empty predicate, or an extreme timestamp/TTL. This is **non-crashing**: the
  parse → hash → fold → canonicalize pipeline is property-tested to never panic on adversarial
  input, and numeric edges fail open (`checked_add` TTL, comparison-only confidence), so a
  corrupt field is a denial-of-*service* non-issue. The most safety-critical value, the JSON
  claim value, *does* validate on load (`CanonicalJson` re-canonicalizes). Such an edit is a
  *tamper* of the log, caught by the hash chain / witness, not by field validation.

## References

- [1] [PoisonedRAG: Knowledge Corruption Attacks to RAG (USENIX Security 2025, arXiv 2402.07867)](https://arxiv.org/abs/2402.07867)
- [2] [A Practical Memory Injection Attack against LLM Agents (MINJA, arXiv 2503.03704)](https://arxiv.org/html/2503.03704v2)
- [3] [Governed Shared Memory for Multi-Agent LLM Systems (arXiv 2606.24535)](https://arxiv.org/html/2606.24535)
