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

## Scenario-family golden corpus (built)

The file-based fixture corpus this strategy calls for lives under
[`evals/`](../evals/README.md), generated and verified by
[`crates/dent8-store/tests/evals_corpus.rs`](../crates/dent8-store/tests/evals_corpus.rs). Each
scenario freezes a whole stream's **firewall outcome** — admitted vs rejected writes, the
per-claim end-state, read-time freshness, and retraction taint — to
`evals/fixtures/<name>.events.jsonl` + `evals/replay/<name>.expected.json`, so a regression in
arbitration, the canonical hard-alarm, freshness, or the evidence-edge taint is caught as a
snapshot mismatch (regenerate with `UPDATE_GOLDEN=1`). It covers `beginner_to_senior`
(`project_fact_correction`), **`ttl_expiry`** (read-time staleness), **`summary_drift`**
(retraction taint, [ADR 0010](decisions/0010-evidence-edges-and-retraction-taint.md)),
`consistency_required` (the canonical hard-alarm), and `low_authority_injection` (MINJA).
Unlike the single-claim encoding goldens in
[`golden_replay.rs`](../crates/dent8-core/tests/golden_replay.rs), these are multi-claim and
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

- A claim stream must start with `claim.asserted`.
- `claim.asserted` must include a value and at least one evidence reference.
- `claim.reinforced` cannot change the claim value.
- Terminal states cannot be mutated by lifecycle events.
- Contradicted claims become `contested` unless already terminal.
- Superseded claims must point at the replacing claim.
- Expired claims must not be returned as fresh context — the freshness evaluator `ClaimState::is_expired_at` is built and tested **and applied on reads**: `explain` headline-flags a stale fact and the receipt carries `fresh`/`expires_at`; the remaining target is a `valid_to` interval (see [threat-model.md](threat-model.md) T4).
- Retrieval events must not alter claim lifecycle.
- Replaying the same ordered event stream must produce the same projection.
- Projection rows must be derivable from the event log.
- Event hashes must form a tamper-evident chain once hashing lands.
- Claim isolation: events on one `claim_id` never perturb another claim's projection.
- Higher-authority supersession requires an explicit basis (replacing claim out-ranks) — enforced in `apply_event` (`InsufficientAuthority`); exercised by the exhaustive lattice test.
- Cross-stream lineage: a `superseded_by` target exists, is not itself invalidated, and forms no cycle — checked by `EntityProjection::lineage_issues` (`replay_entity`), tested.
- Canonicalization stability: `canonicalize(deserialize(canonicalize(e))) == canonicalize(e)`.
- Re-assertion after retraction does not restore prior dependents (Recovery not satisfied).

## Fixture Families

Fixtures live under `evals/fixtures` (authored streams) and `evals/replay` (frozen outcomes),
generated and verified by the corpus harness above. Families marked *(frozen)* are pinned as
golden fixtures there; the rest are designed and exercised by the adversarial corpus
and/or the unit/property tests but not yet frozen as file fixtures.

- `basic_assertion`: one claim becomes active.
- `reinforcement_same_value`: evidence increases without changing value.
- `reinforcement_value_mismatch`: replay rejects mutation disguised as reinforcement.
- `same_predicate_conflict`: two claims conflict on the same subject/predicate.
- `authority_supersession`: higher-authority claim replaces weaker claim.
- `ttl_expiry`: fresh claim becomes read-time stale at a later clock. *(frozen.)*
- `poisoned_source_retraction`: source invalidation **flags** (taints) the claims derived from
  it via `DerivedFrom` evidence edges — surfaced, not auto-retracted (ADR 0010). *(Built — the
  adversarial corpus; the frozen file form is `summary_drift`.)*
- `stale_context_use`: retrieved event records use of stale memory.
- `summary_drift`: a derived summary outlives the retraction of its source and is flagged tainted. *(frozen.)*
- `project_fact_correction`: a project fact is corrected via supersession and replayed (`beginner_to_senior`). *(frozen.)*
- `consistency_required`: a contradiction against a `canonical`/uniqueness-constrained claim hard-alarms instead of softly contesting (the LFI tier; see [belief-revision.md](belief-revision.md)). *(frozen.)*
- `low_authority_injection`: a low-authority write must not auto-supersede a high-authority active claim (MINJA-style poisoning; see [threat-model.md](threat-model.md)). *(frozen.)*

## Property Tests

Use `proptest` once dependencies are introduced.

Generators should produce:

- Valid claim streams.
- Invalid claim streams.
- Interleaved streams for the same entity.
- Authority gradients.
- TTL boundary cases.
- Contradiction and supersession graphs.

Properties should assert:

- Deterministic replay.
- No lifecycle event after terminal state is accepted.
- Claims never become active again without a new claim id.
- Projection equals fold(event log).
- Contradiction edges are symmetric at query time even if stored directionally.
- Higher-authority supersession requires an explicit basis — enforced in `apply_event`; see the exhaustive lattice + non-resurrection test in `dent8-core`.

## Fuzzing

Use `cargo-fuzz` after the parser/adapter layer exists.

Fuzz targets:

- JSON event ingestion.
- MCP write payload ingestion.
- Postgres row decoding.
- Replay of arbitrary event sequences.
- Explain-query graph traversal.

The fuzz oracle should be invariant preservation: malformed input may be rejected, but it must not panic, corrupt projection state, or produce impossible lifecycle transitions.

## Postgres Tests

Use disposable Postgres in CI rather than SQLite compatibility tests.

Minimum database checks:

- Migrations apply from empty database.
- `event_id` and `event_hash` uniqueness hold.
- `claim.asserted` cannot omit value or evidence.
- Projection update and event append are atomic.
- Concurrent contradiction writes serialize into deterministic outcomes.

