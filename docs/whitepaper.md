# dent8: A Memory Firewall for Coding Agents

## Abstract

Long-running LLM agents accumulate durable memory across sessions, and that memory is almost universally governed by *newest-write-wins* semantics: the most recent write to a key, edge, or record becomes the believed value. This makes agent memory a persistent, low-friction attack surface. A privilege-less user, a poisoned document, or a compromised low-authority tool can silently overwrite a trusted decision, and the corruption persists across sessions and users. dent8 is an open-source memory integrity firewall, written in Rust, that interposes on every durable write. It models memory not as mutable items but as an append-only log of typed *fact-events*, and arbitrates each candidate write against the current belief state by **authority-weighted supersession**: a write cannot displace a strictly higher-authority incumbent, and the *actual* backing authority of a revision is checked rather than the label it claims. Contradiction is retained as data rather than silently resolved; entrenchment is earned through corroboration and survived challenges; freshness and valid-time are first-class; provenance is mandatory; and the log is tamper-evident via a SHA-256 hash chain with an optional off-host Ed25519 signed-tree-head witness. As of v0.8.0, writes above the agent tier require a valid signed source identity by default, closing an unauthenticated-label bypass.

We are explicit about scope. dent8 is an authority and provenance layer, not a content scanner and not a truth oracle. Against an externally-grounded adversarial corpus of 47 cases across 10 attack classes — adapted from AgentDojo, InjecAgent, MINJA, AgentPoison, PoisonedRAG, and related public work — arbitration blocks 16 by preventing belief displacement, flags 4 as detect-only, and admits 27 as out-of-model (owned by named downstream layers), while a recency-only baseline is compromised by 46 of 47. On a complementary legitimate-traffic corpus the firewall produces 0 false positives across 22 benign writes in 7 scenarios. We distinguish throughout what is proven and tested from what is designed.

## 1. Introduction

Agent frameworks increasingly persist memory so that an agent can recall prior decisions, learned facts, and user preferences across sessions. The dominant storage models fall into two families, and both resolve conflicting writes in ways that offer no structural defense against corruption.

*Mutate-in-place stores* (Mem0's base path is the clearest example) let an LLM tool-call select `ADD`/`UPDATE`/`DELETE`/`NOOP` over semantically similar memories. There is no append-only log, no provenance, no confidence, no TTL, and no supersession history; the last `UPDATE` wins and a `DELETE` destroys the original record. The graph variant softens deletion into a mark-invalid attribute flip, but this is a flag on a node, not a typed, replayable event.

*Temporal/graph stores* (Zep, powered by the Graphiti engine) are considerably more sophisticated: they ship per-edge valid-time versus transaction-time, contradiction handling via edge invalidation rather than deletion, supersession in place of deletion, and a non-lossy episodic provenance trail from extracted facts back to source messages. This is genuinely close to dent8's headline list, and dent8 does not claim any of these primitives as unique. But Graphiti resolves contradictions purely by **recency** — it "consistently prioritizes new information when determining edge invalidation" — with no arbitration by source authority or confidence, no event-sourced log as the source of truth, no deterministic replay, and no cryptographic hash chain.

Recency arbitration is precisely the property an attacker exploits. Consider the failure modes documented in the recent literature:

- **Memory injection (MINJA).** A privilege-less regular user, through query-only interaction and with no backend access, poisons an agent's long-term memory with reported injection success above 95%, and the injection persists across sessions and across users. Under newest-write-wins, the attacker's write is the newest write, so it becomes the belief.
- **Authority laundering.** An attacker asserts a weak fact but stamps the *revision event* with a high authority label, or routes a low-authority value through a high-authority-looking supersession. If the store trusts the label on the event rather than the real backing, the weak fact is laundered into a trusted one.
- **Source poisoning and derivation cascades.** A retrieved corpus is corrupted (PoisonedRAG reports ~90%+ attack success from as few as ~5 injected texts). Even if the poisoned source is later retracted, any facts *derived* from it silently remain believed — because a recency store has no dependency graph to express "this conclusion rested on that source."
- **Cross-session persistence.** Because the corruption lives in durable memory, it survives the session in which it was injected and is re-served as trusted context indefinitely.

None of these are prevented *structurally* by mutate-in-place or recency semantics. They can only be patched heuristically — a content classifier, a similarity threshold, a hand-tuned prompt — none of which changes the resolution rule that let the bad write win in the first place. dent8's thesis is that the resolution rule itself is the control point: memory writes should pass through a firewall that arbitrates by *authority as entrenchment* over an append-only, replayable, tamper-evident log.

## 2. Design

### 2.1 Memory as an append-only log of fact-events

The core primitive is a `FactEvent`, not a mutable memory item (ADR 0002). A fact stream is identified by a `fact_id` and begins with a `fact.asserted` event; subsequent events reinforce, contradict, supersede, expire, retract, retrieve, record a decision-use, or record a rejected challenge. Each event carries a `subject` (a `kind:key` pair, e.g. `repo:myproj`), a `predicate`, a `fact_value`, a `confidence`, an `authority`, a `ttl`, a `valid_from`/`valid_to` window, mandatory `provenance`, at least one `evidence` reference, timestamps, and a chained `event_hash`.

"Memory" is a *projection* over this log — a deterministic fold, `replay_fact`, that applies each event via the pure function `apply_event` to produce an `Option<FactState>`. The lifecycle state machine is intentionally small: `active` can transition to `contested`, `superseded`, `expired`, or `retracted`; `contested` can further transition to the terminal states. Retrieval and decision-use are audit events that never change lifecycle. The invariant that makes this trustworthy is `projection == fold(events)`: the materialized state any backend serves must equal the fold of the ordered log, and a backend that cannot reproduce it is defined as broken.

This is belief-*base* revision in the sense of Hansson, not classical AGM (ADR 0005, belief-revision.md). dent8 stores opaque `subject + predicate + value` triples with no deductive closure and no entailment engine, so it implements the *operational spirit* of revision operators, which the design documents label "inspirational," not a formal AGM claim. One postulate is deliberately violated: **Recovery**. Retracting a fact and later re-asserting it must not resurrect the facts that depended on the original, because the new assertion carries different provenance and evidence. For an auditable store, non-recovery is the correct choice, not a defect.

### 2.2 The arbitration function at the write boundary

Every write that enters dent8 passes through `EventStore::append`, and `append` itself calls the firewall — there is no un-arbitrated write path. The security decision is factored into a single pure, I/O-free function, `arbitrate_events`, shared by the in-memory, file, SQLite, and Postgres backends so they cannot diverge. It enforces two layers.

**Layer 1 — per-fact arbitration** (`apply_event`) gates on the candidate event's own stated authority and the incumbent's folded state. The authority lattice is a total order, `Unknown < Low < Medium < High < Canonical`, kept strictly separate from `Confidence` (an integer in 0..=1000 millis). The relevant rules:

- A `fact.superseded` whose event authority is strictly below the incumbent's is rejected with `InsufficientAuthority`. Confidence is deliberately never consulted here — a high-confidence low-authority fact cannot out-rank a low-confidence high-authority one.
- `fact.expired` and `fact.retracted` are terminal closes and are gated identically: a strictly lower-authority actor cannot make a trusted fact disappear by calling it stale or retracting it.
- A `fact.contradicted` against a `Canonical` fact is a hard alarm (`CanonicalContradiction`), not a soft transition to `contested`.
- A re-assertion of a live fact id is a `DuplicateAssertion`; any lifecycle event against a terminal fact is a `TerminalStateMutation`.

**Layer 2 — subject-aware anti-laundering** closes a hole the per-fact gate cannot see. A supersession event *names* a replacing fact. Layer 1 can only check the authority the event asserts; a laundering attacker asserts `high` on the event while the fact behind it is `low`. So `arbitrate_events` loads the replacing fact's own stream, folds it to resolve its **actual** authority, and rejects the write with `LaunderedAuthority` if that real authority is below the incumbent's (or `UnbackedSupersession` if the named fact does not exist). This is the mechanism that distinguishes dent8 from a recency store on the laundering axis, and it is enforced identically in the transactional Postgres path, inside the same serialized append transaction so the arbitrated state cannot change before the write lands.

### 2.3 Contradiction as data

Silently merging `A` and `¬A` would trivialize the store. Instead, a `fact.contradicted` event (which, unlike supersession, is *not* authority-gated — dissent is always admissible) flips the incumbent to `Contested` and appends to its `contradicted_by` edge set, keeping both rival values. This is the paraconsistent move: localize the contradiction, keep the store non-trivial, surface it (belief-revision.md, citing the inconsistency-vs-triviality distinction). A contested set is exempt from uniqueness so both beliefs coexist. The one exception is the canonical hard-alarm above — a fact declared `Canonical` that genuinely changed must be superseded by an equal-authority fact, never merely contradicted.

### 2.4 Earned entrenchment

Authority is the primary entrenchment ordering, but dent8 also lets a fact *earn* additional entrenchment (ADR 0007, ADR 0015, ADR 0017). Two signals accumulate on `FactState`:

- **Corroboration.** Distinct reinforcing sources are recorded with the highest authority each has backed the value at (`corroborating_sources`), read Sybil-resistantly via `corroboration_at_or_above` — a volume of low-authority sources earns no high-trust standing.
- **Survived challenges.** When a supersession is rejected, the firewall records a `fact.challenge_rejected` event on the *incumbent's* stream carrying the challenger's provenance and effective authority. These accumulate into `survived_challenges`, again read Sybil-resistantly.

A subject-level audit, `unearned_supersessions`, flags supersessions where the replacing fact is actually weaker than the incumbent's earned entrenchment (`AuthorityDowngrade`, `WeakerEntrenchment`). Challenge recording is on by default; feeding earned entrenchment into write-time arbitration is an opt-in gate (`DENT8_ENTRENCHMENT_GATE`). This keeps the aggressive form opt-in while the audit and recording ship by default.

### 2.5 Freshness and valid-time

Facts carry TTLs and asserted validity windows (ADR 0016). Freshness is a *read-time predicate*, `is_fresh_at`, distinct from the lifecycle: a stale-but-`Active` fact is still revisable. `expires_at()` is the earliest of the TTL bound and the asserted `valid_to`, so an elapsed `valid_to` reads stale exactly like an elapsed TTL, and a future `valid_from` reads not-yet-valid. Reads prefer a fresh believed fact but fall back to a stale one they then flag (`[stale — no longer valid]` / `[not yet valid]`) rather than hiding it. Enumeration surfaces (`facts list`, MCP `list_facts`, `resources/list`) mark each stream's freshness from a single load, and `--as-of`/`--valid-at` provide deterministic time-travel reads ("what did we believe last Tuesday, and was it fresh then?"). A predicate registry adds a retention ceiling: a finite TTL past the effective ceiling (a per-predicate override, else a 90-day global default, with a 7-day ceiling for predicates classed `Volatile`) is *rejected, not clamped* — silently rewriting an asserted freshness window would falsify the audit record.

### 2.6 Provenance and derivation edges

Every `fact.asserted` requires provenance and at least one evidence reference, enforced by `FactEvent::validate` and, on Postgres, by schema `CHECK` constraints. Derivation is modeled as an evidence edge: `EvidenceKind::DerivedFrom` records a fact→fact dependency, with the source fact id in the evidence locator (ADR 0010). Because it reuses the already-hashed evidence vector, the dependency graph is tamper-evident and reconstructable from the log alone. When a source fact enters a terminal invalidated state (retracted or expired), a store-level analysis, `tainted_facts`, flags every still-believed fact that transitively derives from it — cross-subject and cycle-safe. Taint is *surfaced, not auto-removed*: this is the paraconsistent "make it visible, do not silently destroy" stance, and it avoids a legitimate retraction nuking unrelated derivatives. Operator-initiated cascade-retract on `PoisoningDetected` is a documented, deferred option.

### 2.7 Signed source identity, with anti-laundering

Authority arbitration defends against low-privilege injection, but on its own it trusts the authority *label* on an event. Two layers bind labels to real principals.

The opt-in **authority registry** caps a source's stated authority at its registered ceiling and enforces the grant's issuer and scope, with deny-by-default and no self-escalation. Above it sits **signed source identity** (ADR 0012): an issuer key signs a grant binding a source id to a source public key, a maximum authority, an optional subject scope, and an optional expiration; each write proves possession of the source private key before the candidate event reaches the firewall.

As of **v0.8.0 this is enforced by default above the agent tier** (BREAKING). A write whose effective authority is strictly greater than `low` — i.e. `medium`, `high`, or `canonical` — is rejected unless backed by a valid signed identity: a grant chaining to a trusted issuer, matching the claimed source/authority/scope, with proven key possession. Previously, when signed identity was unconfigured, such a write was trusted on the strength of the label alone, so `dent8 assert --authority high --source source:human` was an unauthenticated label any shell-capable agent could claim for free. That bypass is now closed at the shared write boundary — CLI, capture/import, MCP, and daemon all funnel through the same `require_signed_above_agent` gate. Writes at or below the agent tier stay permissive and need no signing, so ordinary local and agent use is unchanged, and `dent8 init` provisions a default signing identity so the honest path keeps working. Signed keys may live in a `0600` file or the OS keychain (`keychain:<account>` on macOS, Linux via the Secret Service, and Windows Credential Manager), narrowing but not eliminating the key-at-rest residual.

Each accepted write is durably attested (ADR 0013): `provenance.attestation` carries an Ed25519 `WriteAttestation` over a domain-separated message — the tag `dent8.event-attestation.v1\0` followed by the length-framed canonical bytes of the event with the attestation field stripped, so a signature cannot cover itself. Any later verifier recomputes the message from the stored event alone, so an attested event is offline-re-verifiable long after the write and without dent8's trust files. On the file dev store, which keeps no per-event hash column, the attestation is the one available content-tamper check.

### 2.8 Tamper-evidence: hash chain and off-host witness

Tamper-evidence is only as strong as deterministic bytes (ADR 0004). dent8 canonicalizes each event to a sorted-key `serde_json` form — explicitly **not** RFC 8785/JCS; the two coincide only because every object key is an ASCII field name and every number is an integer, an invariant guarded by a canonicalization-version constant. The chain uses SHA-256 over an injective, length-framed leaf: `SHA-256(0x00 || CANON_VERSION || len(canonical) || canonical || tag || prev_digest)`, with an RFC 6962-style `0x00` leaf prefix (`0x01` reserved for a future Merkle layer). Length-framing plus a genesis tag guarantee that no two distinct `(canonical, previous)` pairs share a hash input. The chain is **global** — one tamper-evident head for the whole log — which is why appends are serialized. `verify_chain` recomputes the chain to catch any event mutated without rehashing.

The chain is tamper-*evident*, not tamper-*resistant*: a writer with full store access can rewrite an event and re-hash the log forward into a self-consistent chain. Closing that requires an **external witness** (`dent8_core::anchor`, `dent8 witness`). The witness commits to `(event_count, head)`: symmetrically via HMAC-SHA256, or — the runnable end-to-end form — asymmetrically via an Ed25519 **signed tree head**, so a published head is publicly verifiable by anyone with the witness public key (the RFC 6962 construction). `dent8 witness` checks each head against the current log prefix, flags `TAMPER` (rewrite) or `ROLLBACK` (truncation/reorder), and appends heads to a monotonic, append-only published sequence (`event_count` non-decreasing) so a retained later head still catches a rewound local state. The honest caveat: **resistance holds only when the witness issues heads at write time with a key held off the writer's machine.** These functions are that primitive; an operated witness service on separate infrastructure, with a managed publication channel, monitoring, and key rotation, is future product work.

### 2.9 Deterministic counterfactuals: `dent8 whatif`

Because belief state is a deterministic fold, dent8 can answer counterfactuals without any model invocation. `dent8 whatif` re-folds the *same immutable log* under a swapped epistemic trust policy — `--distrust <source>`, `--authority-floor <level>`, `--confidence-floor <millis>` — and emits a per-fact structural diff (appeared / disappeared / lifecycle / value / supersession / evidence changes) against the real fold. It is read-only, deterministic, and makes zero LLM calls; it is also an MCP tool available to read-only connections. This is a first, JTMS-style cut at the ATMS capability the design documents flag as future work: labeling facts under an assumption environment ("what would memory look like if I distrust source Z"). Freshness is deliberately not a policy knob.

## 3. Threat model and guarantees

dent8 is a firewall, and a firewall is only meaningful against a stated adversary (threat-model.md). The primary adversary is a **malicious end-user** who, through query-only interaction, can cause the agent to write attacker-chosen facts (the MINJA case). Also in scope: a **compromised or poisoned source** feeding false tool output or documents that become evidence, and a **compromised low-authority agent** attempting to override higher-authority facts. Partially in scope: a **same-user process bypassing dent8** by writing provider-native files or raw store rows (guard/detect/harden, not absolute prevention), and an **operator with direct DB access** (the hash chain makes tampering evident, not impossible). Out of scope: a network/transport attacker (delegated to TLS).

**The trust boundary is the append path.** Any write that enters through the CLI, MCP server, daemon, or an adapter calling `EventStore::append` is validated, authority-checked, arbitrated, hashed, attested, and made replayable, and a low-authority or stale write cannot silently override trusted state on that path. dent8 is explicitly **not a sandbox for a same-user process**. A shell-capable agent that edits provider-native memory files, rewrites a file-backed log directly, or connects with raw database write privileges routes around the firewall. Against that, dent8 shifts from prevention to detection and containment: a `PreToolUse` native-memory guard (installed and enforced by default as of v0.8.0, blocking raw edits to `CLAUDE.md`, `AGENTS.md`, `MEMORY.md`, `GEMINI.md`, `.cursor/rules`, and similar), `verify` catching broken chains and unentitled attestations, and witness-published heads exposing rewrites, rollback, and truncation. The recommended hardening is to make the dent8 service the only writer, deny agents raw table access, and keep native-memory files read-only or hook-guarded.

Several things are **out of scope by design**, and stating them precisely is part of the design:

- **Content truth.** Arbitration governs provenance, freshness, authority, and contradiction *visibility* — not whether a well-formed, well-sourced fact is factually correct. A confidently-false-but-authoritative statement is admitted.
- **A legitimately high-authority source asserting a falsehood.** Authority is asserted and (above the agent tier) authenticated, but authenticity is not correctness. dent8 defends against low-privilege injection and label forgery, not a genuinely trusted principal that is wrong or compromised.
- **The local-daemon trust boundary is the OS user.** The Unix-socket daemon refuses any peer not running as the same OS user (`SO_PEERCRED`), and a same-OS-user process that can read a private key can impersonate its source. OS-user separation, hardware-backed keys, or external signers are the stronger boundary.
- **Real tamper-resistance requires the witness on a second host.** On a single machine the writer can re-anchor after tampering; only an off-host witness with a proactively-issued, monotonic, published head sequence provides resistance rather than evidence.
- **Content scanning is delegated.** dent8 ships no classifier. A pluggable write-boundary hook (`DENT8_CONTENT_CHECK`) runs an external scanner per candidate fact, after the authority gate and before persistence, on every write entry point; it can `reject` or `taint` (admit-but-flag), is fail-closed by default, and is un-bypassable on the write path — but detection quality is the attached scanner's, not dent8's.

## 4. Evaluation

dent8's evaluation is designed to test invariants and to report adversarial results *honestly*, including the attacks arbitration does not block. All numbers below are produced by `crates/dent8-evals`, frozen as regression tests, and reproducible via `dent8 eval` and `cargo test -p dent8-evals`.

### 4.1 The five demonstrated attack axes

A demonstrative corpus runs five concrete attacks two ways — through the real firewall (`InMemoryEventStore::append`) and through a recency-only baseline (newest-write-wins, the resolution Zep/Graphiti use). Each case computes its verdict from an attacker-goal predicate over the projected belief state; nothing is hardcoded.

| axis | family | firewall | recency-only baseline |
|---|---|---|---|
| `minja_low_authority_injection` | T1 memory injection | blocked | compromised |
| `authority_laundering` | T1 memory injection | blocked | compromised |
| `canonical_contradiction` | T5 canonical contradiction | blocked | compromised |
| `sybil_corroboration` | earned entrenchment | blocked | compromised |
| `poisoned_source_retraction` | T2 retraction / evidence taint | blocked | compromised |

Attack-success rate is **0/5 against the firewall, 5/5 against the baseline**. A positive control (`legitimate_supersession_is_accepted`) confirms the firewall is not a blanket reject gate: an equal-authority supersession is admitted. The fifth axis is the differentiator neither peer model can structurally express — retract a poisoned source and dent8 flags every fact derived from it.

### 4.2 Comparison against modeled Mem0 and Zep semantics

The same sequences are judged against **modeled** peer resolution policies rather than live API clients (network, accounts, and version drift would make the suite non-hermetic; the integrity claim is about what each policy *admits*, which the papers document): `zep_recency` (newest-write-wins edge invalidation, no authority weight) and `mem0_mutate` (mutate-in-place by key, last `UPDATE` wins, no lineage or taint graph).

| axis | dent8 | zep/graphiti (recency) | mem0 (mutate-in-place) |
|---|---|---|---|
| low-authority write cannot displace trusted belief | holds | compromised | compromised |
| over-stated supersession cannot launder a low backing fact | holds | compromised | compromised |
| canonical fact not softened by low-authority contradiction | holds | compromised | compromised |
| volume of low-authority sources earns no entrenchment | holds | compromised | compromised |
| derivative of a retracted source is flagged, not silent | holds | compromised | compromised |
| equal-authority revision is admitted (positive control) | holds | holds | holds |

dent8 holds **6/6**; both peers fail all 5 attack axes and admit the positive control. This is an *integrity* comparison, not a retrieval-quality bake-off — Mem0 and Zep optimize for a different job (retrieval F1), which dent8 does not compete on.

### 4.3 Externally-grounded adversarial corpus (47 cases / 10 classes)

To move beyond self-authored demonstrations, a larger corpus adapts attack *patterns* from the public prompt-injection and memory-poisoning literature — AgentDojo (ETH Zürich / Invariant Labs), InjecAgent (UIUC), BIPIA (Microsoft), MINJA (Penn State), AgentPoison, PoisonedRAG, HackAPrompt, garak (NVIDIA), Lakera Gandalf, and the OWASP LLM / Agentic Top 10 taxonomy. Patterns are adapted into dent8's fact-proposal format (original phrasings, so no ShareAlike text enters the corpus), and every case is tagged with the public work it adapts. Verdicts are computed, not hardcoded: `firewall_blocked = !attacker_goal(firewall_state)`. Each non-block is classified as **detect-only** (admitted but flagged by read-time freshness or retraction taint) or **out-of-model** (admitted by arbitration by design; a named downstream layer owns it).

| class | OWASP | cases | blocked | detect-only | out-of-model |
|---|---|---|---|---|---|
| injection-in-content | LLM01 / ASI06 | 5 | 0 | 0 | 5 |
| authority/identity spoofing | ASI03 / ASI09 | 5 | 2 | 0 | 3 |
| supersede/override abuse | ASI06 | 6 | 5 | 0 | 1 |
| staleness/temporal exploitation | ASI06 | 5 | 2 | 2 | 1 |
| cross-agent contamination | ASI07 | 5 | 2 | 1 | 2 |
| data-exfiltration trigger | LLM01 (exfil) | 4 | 0 | 0 | 4 |
| conditional/delayed time-bomb | ASI06 / ASI02 | 4 | 0 | 1 | 3 |
| obfuscated/evasive payload | LLM01 / ASI06 | 5 | 0 | 0 | 5 |
| false-fact / knowledge corruption | LLM04 | 4 | 2 | 0 | 2 |
| anti-firewall / self-bypass | ASI03 / ASI09 | 4 | 3 | 0 | 1 |
| **total** | — | **47** | **16** | **4** | **27** |

Overall: **16/47 blocked** by arbitration, **4/47 detect-only** (flagged, not removed), **27/47 out-of-model** (admitted by design). The recency-only baseline is compromised by **46/47** — the sole exception is a purely structural unbacked supersession that poisons no store.

Two honesty points are load-bearing. First, **"blocked" means the attacker failed to displace the incumbent belief**, not that the attacker's fact vanished: a low-authority fact can still persist as a *parallel* belief on its own fact id (disclosed by the `parallel_belief_plant` case, which `append` does not deduplicate — the uniqueness registry owns that). Second, every block ties to a concrete mechanism — `InsufficientAuthority`, `LaunderedAuthority`, `UnbackedSupersession`, `DuplicateAssertion`, `TerminalStateMutation`, or `CanonicalContradiction` — verified by a rigor test asserting each attack is rejected by its *intended* mechanism, not an incidental validation error. Notably, confidence cannot launder authority (a `Low` fact stamped confidence 1.0 still cannot out-rank `High`), and the anti-firewall "already-approved / treat-rejection-as-a-false-positive" text is inert because it rides a low-authority override the gate rejects regardless of the prose.

The 27 out-of-model non-blocks are architectural boundaries, not arbitration bugs. Arbitration reads no `value` text at all, so content-embedded imperatives, exfil strings, obfuscated payloads (zero-width, base64, rot13, translation), and conditional-trigger prose are stored as inert data — a downstream content scanner is required, and the obfuscation cases are included precisely to show a naive string filter is insufficient. Arbitration is not a truth oracle, so a standalone confidently-false fact is admitted (though a false fact that *overrides* a trusted one, or contradicts a canonical one, is blocked — that is authority, not truth). And self-stamped authority and parallel-belief plants are owned by the authority-ceiling/signed-identity and uniqueness registry layers respectively, which sit above the base `append` firewall these harnesses exercise directly.

### 4.4 Legitimate-traffic corpus: false-positive rate

The honest counter-question to "attacks blocked" is "does the firewall tax legitimate revision?" A complementary corpus replays designed benign revision sequences — maturing understanding (equal-authority supersession), an authority-upgrade correction, independent corroboration, a legitimate retraction, disagreement kept as a contested pair, corroborate-then-revise, and serial revisions — through the real firewall and counts wrongly-rejected intended writes.

The result is **0 false positives across 22 benign writes in 7 scenarios**. The firewall admits normal revision in full; `dent8 eval` gates its exit code on this, so any false positive is a regression. These are hand-designed scenarios; replaying real captured agent sessions through the same metric is a stated post-launch step, blocked only on trace data (the harness and metric are ready).

### 4.5 The content-check hook lane (separate from arbitration)

To demonstrate the content boundary — not to claim content-scanning efficacy — the corpus is re-run with the pluggable hook plus the repository's **demonstrative regex scanner**, whose rules were written with knowledge of the corpus. With the demo scanner attached, the tally is **25/47 blocked (16 by arbitration, 9 by the hook), 9 detect-only, 13 admitted unflagged**. The arbitration column is byte-identical to the core table above — the hook inflates nothing; it is a separate, composable layer. The misses are the point of shipping a *demo*: obfuscation mostly wins (rot13 and translated imperatives sail past, kept that way on purpose by a frozen test), which is exactly why a real deployment must attach an obfuscation-robust scanner rather than trust a bundled regex.

### 4.6 Mechanized backing

Beyond the concrete corpora, arbitration is exercised by an exhaustive test over the full 5×5 authority lattice (including non-resurrection after retraction), property tests over event-stream invariants, a golden-fixture replay corpus that freezes whole-stream firewall outcomes (including writes expected to be *rejected*), and two `cargo-fuzz` targets run in CI (JSON event ingestion/replay and canonicalization idempotency) whose oracle is that malformed input may be rejected but must never panic or corrupt projection state. Model-checking harnesses (`#[cfg(kani)]`) are written for the arbitration invariants but, per the project's own documentation, are not yet wired into CI.

## 5. Related work

dent8 sits at the intersection of a fast-moving agent-memory market and several mature formal and infrastructural traditions, and it does not claim novelty on any individual primitive.

**Truth-maintenance systems.** Doyle's JTMS (1979) and de Kleer's ATMS (1986) are the operational ancestors: nodes carry justifications, are labeled IN/OUT, and contradictions are handled over nogoods. dent8's `DerivedFrom` edges are TMS justifications over a replayable log; its single-projection fold is JTMS-like, and `dent8 whatif` is a first step toward the ATMS capability of labeling facts under an assumption environment.

**Belief revision.** The AGM framework (Alchourrón, Gärdenfors, Makinson, 1985) is the canonical theory of rational belief change over logically-closed sets. dent8 is better matched by Hansson's belief-*base* revision over finite, non-closed syntactic sets, where the Recovery postulate fails — which is exactly dent8's deliberate non-recovery on retract-then-reassert. Authority-versus-confidence maps to the entrenchment-versus-probability distinction; the contested state is grounded in paraconsistent logic's inconsistency-versus-triviality separation. dent8 makes no claim of logical closure or AGM compliance, and the design documents are careful to label the operator mappings inspirational rather than rigorous.

**Data provenance and bitemporality.** The provenance, authority, evidence, and edge model maps onto W3C PROV-DM (`wasDerivedFrom`, `wasInvalidatedBy`, and related), with confidence as a non-standard extension. The transaction-time/valid-time split is textbook bitemporal modeling (SQL:2011), enforced in the `replay_fact` fold rather than delegated to the database.

**Transparency logs.** The hash chain is standard tamper-evident-log machinery. RFC 6962 (Certificate Transparency), building on Merkle hash trees, supplies the domain-separated leaf/node hashing (`0x00`/`0x01` prefixes) and the signed-tree-head construction dent8's witness adopts; RFC 8785 (JCS) was the original canonicalization plan but is deliberately not what shipped.

**Prompt-injection and memory-poisoning literature.** PoisonedRAG (USENIX Security 2025) and MINJA together establish the premise: retrieval corpora and long-term agent memory are attacker-influenceable, cheaply and persistently. dent8's adversarial corpus draws its attack patterns from these plus AgentDojo, InjecAgent, AgentPoison, BIPIA, garak, HackAPrompt, and Lakera Gandalf, aligned to the OWASP LLM and Agentic Top 10 taxonomies. Contemporary agent-memory systems — Mem0 (mutate-in-place, with a mark-invalid graph variant) and Zep/Graphiti (bitemporal, recency-arbitrated) — are the closest peers; a 2026 wave of work on typed contradiction operators, Merkle-backed memory provenance, and confidence-gated admission control individually publishes several of dent8's primitives, which sharpens rather than refutes its position.

dent8's defensible wedge is therefore not any single primitive but their **composition treated as substrate**: an append-only, typed, hash-verified `FactEvent` log as the single source of truth; deterministic replay (`projection == fold(events)`); and, above all, authority-weighted supersession *as the write-boundary gate* — a direct mitigation for MINJA-style poisoning that recency-only arbitration cannot offer. The correct positioning is "the governed, replayable store of record *beneath* a retrieval-optimized memory system," benchmarked on poisoning resistance, replay determinism, and auditability, not on retrieval F1.

## 6. Limitations and future work

We state the limitations plainly, several of which follow directly from Section 3.

- **Authority is authenticated, not correct.** Above the agent tier, dent8 now proves a source holds its signing key, but it cannot tell whether a genuinely trusted principal is wrong or compromised. Content correctness is delegated to an external scanner via the write-boundary hook; dent8 ships no classifier, and unconfigured deployments admit content-embedded payloads as inert data.
- **Key-at-rest is the standing residual.** A compromised source private key, or a same-OS-user process that can read it, can make trusted above-agent writes. Keychain-backed keys narrow but do not close this; OS-user separation, hardware-backed keys, and external signers are the stronger boundary and remain future work.
- **Tamper-resistance requires an operated off-host witness.** The signed-tree-head primitive is runnable end to end, but resistance (as opposed to evidence) holds only when a witness on a second host issues monotonic heads at write time. The operated service — publication channel, monitoring, key rotation — is not yet productized.
- **Retraction taint is detect-only.** Derivatives of a retracted source are flagged, not auto-removed; operator-initiated cascade-retract on `PoisoningDetected` is designed but deferred. The canonical hard-alarm currently covers only `Canonical`-authority facts, not a general uniqueness-constrained-predicate flag; contradiction-edge symmetry at query time is designed but not fully built.
- **Assumption-environment replay is a first cut.** `dent8 whatif` provides deterministic policy counterfactuals but not the full ATMS multi-environment labeling the design documents envision.
- **Pre-1.0 and experimental.** The CLI, library API, on-disk event format, and Postgres schema may change between minor versions. The format is versioned by the canonicalization constant; v0.3 introduced a one-time format-v2 break, after which the intent is additive-only, but that stability is not guaranteed until 1.0.
- **Evals are hand-designed.** Both the adversarial patterns (adapted, not replayed from live attacks) and the legitimate-traffic scenarios are authored; replaying real captured agent sessions through the same measurement is the next evaluation step, and Kani model-checking is written but not yet in CI.

## 7. Conclusion

Agent long-term memory is a durable, cross-session attack surface, and its dominant resolution rule — newest-write-wins, whether by key mutation or recency-based edge invalidation — is precisely what lets a low-authority write, a laundered label, or a poisoned source win. dent8 relocates the control point to the resolution rule itself: an arbitration function at the write boundary over an append-only log of typed fact-events, ordering conflicts by authority-as-entrenchment, checking the *real* backing authority rather than the claimed label, retaining contradiction as data, and making the whole history replayable, freshness-aware, provenance-stamped, and tamper-evident. The measured results are specific and bounded: 0/5 on the demonstrative axes and 6/6 against modeled Mem0 and Zep semantics; 16 blocked, 4 detect-only, and 27 out-of-model of 47 externally-grounded cases against a baseline compromised by 46/47; and 0 false positives across 22 benign writes. dent8 is an authority and provenance firewall, not a content scanner and not a truth oracle — and its honesty about that boundary, backed by frozen tests that encode the known gaps rather than a "blocks everything" fiction, is the point. The governed, replayable store of record belongs beneath a retrieval system, not in place of one.

## References

1. Alchourrón, C. E., Gärdenfors, P., and Makinson, D. (1985). On the Logic of Theory Change: Partial Meet Contraction and Revision Functions. *Journal of Symbolic Logic* 50(2). (AGM belief revision.)
2. Hansson, S. O. *Revision of Belief Sets and Belief Bases.* In *Belief Dynamics* (Springer). (Belief-base revision; Recovery fails for bases; kernel contraction.)
3. Doyle, J. (1979). A Truth Maintenance System. *Artificial Intelligence* 12(3). (JTMS.)
4. de Kleer, J. (1986). An Assumption-Based TMS. *Artificial Intelligence* 28(2). (ATMS; assumption environments.)
5. Reiter, R. (1980). A Logic for Default Reasoning. *Artificial Intelligence* 13. (Non-monotonic / default reasoning.)
6. Priest, G., et al. Paraconsistent Logic. *Stanford Encyclopedia of Philosophy.* (Inconsistency vs. triviality.)
7. Merkle, R. C. (1987). A Digital Signature Based on a Conventional Encryption Function. *CRYPTO '87.* (Merkle hash trees.)
8. Laurie, B., Langley, A., and Kasper, E. (2013). RFC 6962: Certificate Transparency. IETF. (Signed tree heads; domain-separated leaf/node hashing; inclusion/consistency proofs.)
9. Rundgren, A., Jordan, B., and Erdtman, S. (2020). RFC 8785: JSON Canonicalization Scheme (JCS). IETF. (The scheme dent8 deliberately does *not* implement; cited for contrast.)
10. W3C. PROV-DM: The PROV Data Model. W3C Recommendation. (Provenance vocabulary.)
11. Zou, W., Geng, R., Wang, B., and Jia, J. (2025). PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models. *USENIX Security 2025* (arXiv:2402.07867).
12. MINJA: A Practical Memory Injection Attack against LLM Agents (arXiv:2503.03704). (Query-only long-term-memory poisoning; cross-session/cross-user persistence.)
13. AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents. ETH Zürich / Invariant Labs (MIT-licensed).
14. InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents. UIUC (MIT-licensed).
15. AgentPoison: Red-teaming LLM Agents via Poisoning Memory or Knowledge Bases (MIT-licensed).
16. BIPIA: Benchmarking Indirect Prompt Injection Attacks. Microsoft (MIT-licensed, code).
17. garak: LLM vulnerability scanner. NVIDIA (Apache-2.0).
18. HackAPrompt. Learn Prompting (MIT / CC-BY-4.0).
19. Lakera Gandalf. Lakera (MIT).
20. OWASP Top 10 for LLM Applications and OWASP Agentic Security Initiative (Top 10). (CC-BY-SA; taxonomy alignment only.)
21. Mem0: Building Production-Ready AI Agents with Scalable Long-Term Memory (arXiv:2504.19413). (Mutate-in-place; graph variant mark-invalid.)
22. Zep: A Temporal Knowledge Graph Architecture for Agent Memory (arXiv:2501.13956). (Graphiti engine; bitemporal, recency-arbitrated edge invalidation.)
