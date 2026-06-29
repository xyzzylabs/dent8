# dent8 scenario-family golden corpus

A file-based, language-agnostic corpus of named belief-event streams and their **frozen
firewall outcomes**. Each scenario is a small story an adversary or a normal workflow might
produce; the corpus freezes exactly how dent8's write-boundary firewall resolves it.

```
evals/
  fixtures/<name>.events.jsonl   # the authored event stream (DENT8_LOG format, one event/line),
                                 #   INCLUDING any write the firewall is expected to reject
  replay/<name>.expected.json    # the frozen outcome: chain head, per-claim end-state,
                                 #   rejected writes (with a stable category), retraction taint
```

The Rust harness that generates and verifies it is
[`crates/dent8-store/tests/evals_corpus.rs`](../crates/dent8-store/tests/evals_corpus.rs): it
replays each on-disk stream through the real store firewall
(`InMemoryEventStore::append` = `arbitrate` + the core fold), recomputes the outcome, and
asserts it matches the frozen `.expected.json` **and** that the authored events re-serialize to
the exact on-disk bytes. A regression in authority arbitration, the canonical hard-alarm,
read-time freshness, or the evidence-edge taint surfaces as a snapshot mismatch.

```sh
cargo test -p dent8-store --test evals_corpus                 # verify against the frozen corpus
UPDATE_GOLDEN=1 cargo test -p dent8-store --test evals_corpus  # regenerate after an intended change
```

## Scenarios

| scenario | family | what it freezes |
| --- | --- | --- |
| `beginner_to_senior` | `project_fact_correction` | an authority-sufficient supersession installs the new value; the old claim goes `Superseded` |
| `ttl_expiry` | `ttl_expiry` | a finite-TTL fact with no `Expired` event is still `Active` but **`fresh=false`** at a later clock (the T4 stale-read axis) |
| `summary_drift` | `summary_drift` / retraction taint ([ADR 0010](../docs/decisions/0010-evidence-edges-and-retraction-taint.md)) | a derived summary outlives the retraction of its source and is flagged **tainted** — poison does not silently survive in derivatives |
| `consistency_required` | `T5_canonical_contradiction` | a contradiction of a `Canonical` fact is **rejected** (`CanonicalContradiction`), not softened to `Contested` |
| `low_authority_injection` | `T1_memory_injection` (MINJA) | a low-authority supersession of a high-authority fact is **rejected** (`InsufficientAuthority`); the trusted fact stands |

## Relationship to the other eval surfaces

- **`crates/dent8-core/tests/golden_replay.rs`** freezes the *single-claim* encoding + `apply_event`
  fold (every event must apply). This corpus runs the *store-level firewall* over whole,
  often multi-claim streams that intentionally include **rejected** writes.
- **`crates/dent8-evals`** (run as `dent8 eval`) is the firewall-vs-recency *benchmark* —
  booleans proving the firewall blocks attacks a recency-only baseline falls to. This corpus is
  the frozen *fixture* form of the same kinds of scenarios, byte-for-byte regression-guarded.

See [docs/evals.md](../docs/evals.md) for the full evaluation strategy and fixture-family list.
