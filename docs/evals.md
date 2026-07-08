# Evaluation Strategy

dent8 evals should be formal enough to test invariants, not ad hoc notebooks. The
*tooling* choices behind these layers — which property tester, model checker, and
deductive verifier, and how invariants map to each — are in
[formal-verification.md](formal-verification.md) and
[ADR 0006](decisions/0006-formal-verification-stack.md).

## Adversarial corpus (built)

`crates/dent8-evals` runs concrete attack scenarios two ways — through the **real
firewall** (`InMemoryEventStore::append` = `arbitrate` + the core fold) and through a
**recency-only baseline** ("newest write wins", no authority arbitration — the strategy
dent8 argues against). Each scenario asserts the firewall *blocks* the attack while the
baseline is *compromised*; `cargo test -p dent8-evals` is the empirical complement to the
`#[cfg(kani)]` proofs and the exhaustive authority-lattice tests in `dent8-core`. Current
result (`dent8_evals::summary_table()`):

| attack | family | firewall | recency-only baseline |
|---|---|---|---|
| `minja_low_authority_injection` | T1 memory injection | blocked ✓ | **compromised** |
| `authority_laundering` | T1 memory injection | blocked ✓ | **compromised** |
| `canonical_contradiction` | T5 canonical contradiction | blocked ✓ | **compromised** |
| `sybil_corroboration` | earned entrenchment | blocked ✓ | **compromised** |
| `poisoned_source_retraction` | T2 retraction cascade / evidence taint | blocked ✓ | **compromised** |

Attack-success-rate: **0/5 against the firewall, 5/5 against the baseline.** A positive
control (`legitimate_supersession_is_accepted`) confirms the firewall is not a blanket
"reject all change" gate — an equal-authority supersession is admitted. Run it as
`dent8 eval`.

## Externally-grounded adversarial corpus (built)

The five cases above are self-authored and hand-picked to *demonstrate* the firewall. To
establish credibility we added a larger, provenance-tagged corpus
(`crates/dent8-evals/src/adversarial.rs`, `run_adversarial_corpus()`) whose attack
**patterns are adapted from the public prompt-injection / memory-poisoning literature** —
and we report the results **honestly**, including the attacks dent8's arbitration does not
block.

**47 cases across 10 attack classes.** For each case the attacker's goal is an explicit
predicate over the firewall-projected belief state; the verdict is *computed* —
`firewall_blocked = !attacker_goal(firewall_state)` — never hardcoded. A non-block is
reported truthfully and classified: **detect-only** (admitted but flagged by read-time
freshness or retraction taint) or **out-of-model** (admitted by `append`-arbitration by
design — dent8 is an authority firewall, not a content scanner — so a named downstream
layer must own it).

### Provenance & licensing

Patterns are **adapted into dent8's fact-proposal format, not copied** (so attribution
suffices and no ShareAlike obligation attaches). Every case carries a `source` string
naming the public work it adapts:

| Source | License | Used for classes |
|---|---|---|
| AgentDojo (ETH Zurich / Invariant Labs) | MIT | A (authority-frame injection) |
| InjecAgent (UIUC) | MIT | A, F (data-stealing/exfil) |
| BIPIA (Microsoft, code) | MIT | A, H (context/instruction confusion) |
| MINJA (Penn State, paper) | paper — adapt idea | C, D, E (memory injection, plant) |
| AgentPoison | MIT | D, G (backdoor/trigger records) |
| PoisonedRAG | MIT | C, I (knowledge corruption/override) |
| HackAPrompt (Learn Prompting) | MIT / CC-BY-4.0 | A, B, H (override/obfuscation) |
| garak (NVIDIA) | Apache-2.0 | F, H (markdown-image exfil, encoding) |
| Lakera Gandalf | MIT | J (guard-bypass framing) |
| OWASP LLM / Agentic Top 10 | CC-BY-SA (taxonomy only) | B, C, D, E, J (class labels) |
| Rehberger SpAIware / Gemini PoCs | blog — cite only | F, G (persistent exfil, delayed trigger) |

CC-BY-SA sources (OWASP text, some BIPIA sub-datasets) are used only for **taxonomy
alignment and technique inspiration**; our payloads are original phrasings, so no verbatim
ShareAlike text enters the corpus. Rehberger blog prose has no reuse grant — cited as
provenance only.

### Attack-class taxonomy (aligned to OWASP)

- **A — injection-in-content** (LLM01 / ASI06): an imperative embedded in a fact's `value`.
- **B — authority/identity spoofing** (ASI03 / ASI09): a fact claiming elevated origin.
- **C — supersede/override abuse** (ASI06): a false fact engineered to displace a trusted one.
- **D — staleness/temporal exploitation** (ASI06): TTL / valid-time / backdating metadata.
- **E — cross-agent contamination** (ASI07): one source's fact steering another principal.
- **F — data-exfiltration trigger** (LLM01 exfil): a standing instruction to leak.
- **G — conditional/delayed time-bomb** (ASI06 / ASI02): inert until a future trigger/state.
- **H — obfuscated/evasive payload** (LLM01 / ASI06): any class encoded to dodge string matching.
- **I — false-fact / knowledge corruption** (LLM04): confidently-worded falsehood, no imperative.
- **J — anti-firewall / self-bypass** (ASI03 / ASI09): facts that try to talk past the vetting layer.

### Honest per-class results

Generated by `dent8_evals::adversarial_summary_table()` and frozen as a regression guard
in the module's tests (`per_class_block_rates_match_the_frozen_honest_tally`):

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

Overall: **16/47 blocked** by arbitration, **4/47 detect-only** (flagged, not removed),
**27/47 out-of-model** (admitted by design; a downstream layer owns them). The recency-only
baseline is compromised by **46/47** (the exception is a purely structural unbacked
supersession that poisons *no* store).

### What arbitration blocks (16/47)

Every block is a real `append` rejection tied to a mechanism: under-ranked
supersession/retraction/expiration (`InsufficientAuthority`), over-stated backing
(`LaunderedAuthority`), a supersession naming a nonexistent fact (`UnbackedSupersession`),
in-place overwrite (`DuplicateAssertion`), re-asserting a terminal fact
(`TerminalStateMutation`), and contradicting a canonical fact (`CanonicalContradiction`).
Notably, **confidence cannot launder authority** (a Low fact stamped confidence 1.0 still
cannot out-rank High), and the anti-firewall "already-approved / treat-rejection-as-false-
positive" bypass text is **inert** — it rides a low-authority override that the authority
gate rejects regardless of the text.

### Known gaps / out-of-scope (the honest non-blocks)

None of the 31 non-blocks are arbitration *bugs*; each is an explicit architectural
boundary. dent8's `append` firewall arbitrates **authority, provenance, and lifecycle** —
it deliberately does not:

1. **Read `value` text** (classes A, F, H, most of G, and the content variants of E/J —
   ~20 cases). Content-embedded imperatives, exfil strings, obfuscated payloads, and
   conditional-trigger prose are stored as inert data. **A downstream content scanner is
   required**; obfuscation (zero-width, base64, rot13, translation, instruction-as-data) is
   included precisely to show a naive string filter is insufficient — but arbitration reads
   *no* text at all, so all are admitted.
2. **Judge ground truth** (class I standalone false facts). Arbitration is not a truth
   oracle; a confidently-false-but-authoritative statement is admitted. External validation
   owns this. (A false fact that tries to *override* a trusted one, or contradict a
   canonical one, **is** blocked — that is authority, not truth.)
3. **Independently verify a claimed authority level** at `append` (classes B/C/E "self-
   stamped High/Canonical" — 5 cases). `append` trusts the stated `authority.level`; the
   **authority-ceiling registry + signed identity** layer (the `op_*` CLI/MCP path, above
   `append`, and *not* exercised by these harnesses) is the intended control that binds a
   source to a maximum authority. This is a documented layer split, not a firewall hole.
4. **Enforce predicate uniqueness** at `append` (class E parallel-belief plant). A competing
   fact on the same subject/predicate coexists as a distinct fact id; the `PredicateRegistry`
   uniqueness layer (also not run by `append`) owns this.
5. **Cap TTL reach** (class D far-future TTL). Arbitration does not police a "reasonable"
   TTL; a retention-policy layer would.

**Detect-only (4/47):** retraction taint (a derivative of a retracted source stays believed
but is flagged tainted — ADR 0010) and read-time freshness (an elapsed `valid_to` reads
stale; a future `valid_from` reads not-yet-valid — ADR 0016). These are **surfaced, not
auto-removed**: `explain`/`context`/`verify` flag them, and `context` omits stale facts by
default, but the belief itself lingers in the log. We count them as detect-only, **not** as
blocks.

Run the honest report with
`cargo test -p dent8-evals --lib adversarial -- --nocapture` (prints the table).

## Scenario-family golden corpus (built)

The file-based fixture corpus this strategy calls for lives under
[`evals/`](../evals/README.md), generated and verified by
[`crates/dent8-store/tests/evals_corpus.rs`](../crates/dent8-store/tests/evals_corpus.rs). Each
scenario freezes a whole stream's **firewall outcome** — admitted vs rejected writes, the
per-fact end-state, read-time freshness, and retraction taint — to
`evals/fixtures/<name>.events.jsonl` + `evals/replay/<name>.expected.json`, so a regression in
arbitration, the canonical hard-alarm, freshness, or the evidence-edge taint is caught as a
snapshot mismatch (regenerate with `UPDATE_GOLDEN=1`). It covers `beginner_to_senior`
(`project_fact_correction`), **`ttl_expiry`** (read-time staleness), **`summary_drift`**
(retraction taint, [ADR 0010](decisions/0010-evidence-edges-and-retraction-taint.md)),
`consistency_required` (the canonical hard-alarm), and `low_authority_injection` (MINJA).
Unlike the single-fact encoding goldens in
[`golden_replay.rs`](../crates/dent8-core/tests/golden_replay.rs), these are multi-fact and
include writes the firewall is **expected to reject**.

## Layers

1. Unit tests for state transitions.
2. Property tests for event stream invariants.
3. Fuzzing for malformed events and adversarial sequences.
4. Golden fixtures for replay scenarios.
5. Postgres migration and projection tests.
6. End-to-end CLI and MCP adapter scenarios.

## Invariants

Initial invariants:

- A fact stream must start with `fact.asserted`.
- `fact.asserted` must include a value and at least one evidence reference.
- `fact.reinforced` cannot change the fact value.
- Terminal states cannot be mutated by lifecycle events.
- Contradicted facts become `contested` unless already terminal.
- Superseded facts must point at the replacing fact.
- Expired facts must not be returned as fresh context — the freshness evaluator `FactState::is_expired_at` is built and tested **and applied on reads**: `explain` headline-flags a stale fact and the receipt carries `fresh`/`expires_at`; closed `valid_to` validity intervals are applied on reads too — an elapsed asserted `valid_to` reads stale exactly like an elapsed TTL, since `FactState::expires_at()` is the earliest of the TTL bound and `valid_to` ([ADR 0016](decisions/0016-valid-time-and-time-travel-reads.md); see [threat-model.md](threat-model.md) T4).
- Retrieval events must not alter fact lifecycle.
- Replaying the same ordered event stream must produce the same projection.
- Projection rows must be derivable from the event log.
- Event hashes must form a tamper-evident chain once hashing lands.
- Fact isolation: events on one `fact_id` never perturb another fact's projection.
- Higher-authority supersession requires an explicit basis (replacing fact out-ranks) — enforced in `apply_event` (`InsufficientAuthority`); exercised by the exhaustive lattice test.
- Cross-stream lineage: a `superseded_by` target exists, is not itself invalidated, and forms no cycle — checked by `SubjectProjection::lineage_issues` (`replay_entity`), tested.
- Canonicalization stability: `canonicalize(deserialize(canonicalize(e))) == canonicalize(e)`.
- Re-assertion after retraction does not restore prior dependents (Recovery not satisfied).

## Fixture Families

Fixtures live under `evals/fixtures` (authored streams) and `evals/replay` (frozen outcomes),
generated and verified by the corpus harness above. Families marked *(frozen)* are pinned as
golden fixtures there; the rest are designed and exercised by the adversarial corpus
and/or the unit/property tests but not yet frozen as file fixtures.

- `basic_assertion`: one fact becomes active.
- `reinforcement_same_value`: evidence increases without changing value.
- `reinforcement_value_mismatch`: replay rejects mutation disguised as reinforcement.
- `same_predicate_conflict`: two facts conflict on the same subject/predicate.
- `authority_supersession`: higher-authority fact replaces weaker fact.
- `ttl_expiry`: fresh fact becomes read-time stale at a later clock. *(frozen.)*
- `poisoned_source_retraction`: source invalidation **flags** (taints) the facts derived from
  it via `DerivedFrom` evidence edges — surfaced, not auto-retracted (ADR 0010). *(Built — the
  adversarial corpus; the frozen file form is `summary_drift`.)*
- `stale_context_use`: retrieved event records use of stale memory.
- `summary_drift`: a derived summary outlives the retraction of its source and is flagged tainted. *(frozen.)*
- `project_fact_correction`: a project fact is corrected via supersession and replayed (`beginner_to_senior`). *(frozen.)*
- `consistency_required`: a contradiction against a `canonical`/uniqueness-constrained fact hard-alarms instead of softly contesting (the LFI tier; see [belief-revision.md](belief-revision.md)). *(frozen.)*
- `low_authority_injection`: a low-authority write must not auto-supersede a high-authority active fact (MINJA-style poisoning; see [threat-model.md](threat-model.md)). *(frozen.)*
- `content_injection_admitted`: a fact whose value embeds an imperative is admitted and believed — arbitration does not scan value text (an honest out-of-model non-block; a downstream content scanner owns it). *(frozen.)*
- `parallel_belief_plant`: a competing fact on the same subject/predicate coexists as a distinct fact id — `append` does not enforce uniqueness (the `PredicateRegistry` layer does). *(frozen.)*
- `unbacked_supersession`: a supersession naming a nonexistent backing fact is rejected (`UnbackedSupersession`); the trusted incumbent stands. *(frozen.)*
- `duplicate_overwrite`: a second assertion of the same fact id with a new value is rejected (`DuplicateAssertion`); the original value stands. *(frozen.)*

## Property Tests

Use `proptest` once dependencies are introduced.

Generators should produce:

- Valid fact streams.
- Invalid fact streams.
- Interleaved streams for the same subject.
- Authority gradients.
- TTL boundary cases.
- Contradiction and supersession graphs.

Properties should assert:

- Deterministic replay.
- No lifecycle event after terminal state is accepted.
- Facts never become active again without a new fact id.
- Projection equals fold(event log).
- Contradiction edges are symmetric at query time even if stored directionally.
- Higher-authority supersession requires an explicit basis — enforced in `apply_event`; see the exhaustive lattice + non-resurrection test in `dent8-core`.

## Fuzzing

Use `cargo-fuzz`. Two targets are implemented in `fuzz/fuzz_targets/` and run in CI:

- JSON event ingestion and replay of arbitrary event sequences
  (`deserialize_apply_canonicalize`: deserialize → apply → canonicalize).
- Canonicalization idempotency (`canonical_json`).

Planned, not yet implemented:

- MCP write payload ingestion.
- Postgres row decoding.
- Explain-query graph traversal.

The fuzz oracle should be invariant preservation: malformed input may be rejected, but it must not panic, corrupt projection state, or produce impossible lifecycle transitions.

## Postgres Tests

Use disposable Postgres in CI rather than SQLite compatibility tests.

Minimum database checks:

- Migrations apply from empty database.
- `event_id` and `event_hash` uniqueness hold.
- `fact.asserted` cannot omit value or evidence.
- Projection update and event append are atomic.
- Concurrent contradiction writes serialize into deterministic outcomes.

