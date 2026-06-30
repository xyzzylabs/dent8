# 0006: Formal Verification Stack

Date: 2026-06-26

## Status

Accepted.

## Context

dent8 makes strong correctness claims (deterministic replay, `projection ==
fold(events)`, terminal immutability, tamper-evidence, serializable concurrent
writes) but has only example-based unit tests. No single Rust verification tool
covers all of these: bounded model checkers cannot do unbounded proofs or
concurrency; deductive verifiers are high-cost and mostly prove safety; protocol
checkers prove a model, not the code.

## Decision

Adopt a **layered portfolio**, mapping invariants to the right tool and the maturity of
the codebase:

1. **proptest / bolero** (now, against the pure core) — fold determinism,
   `projection == fold`, reinforced-value-stability, terminal immutability,
   single-assertion prefix, claim isolation, contradiction-edge symmetry,
   higher-authority basis, cross-stream lineage, canonicalization stability.
2. **Kani** (after hashing exists) — bounded panic-/overflow-freedom of `apply_event`
   over all event kinds; fold-determinism and terminal-immutability up to length *N*;
   hash-chain link verification. Documented as **bounded, not universal**.
3. **Stateright** (after the sqlx adapter is designed) — append+projection atomicity
   and concurrent-contradiction serializability/linearizability, sharing Rust types
   with the adapter; add PObserve-style trace conformance when the real adapter lands.
4. **Optional Creusot/Verus** — one scoped, unbounded `projection == fold` proof of
   the pure fold (~470 non-test LOC).

## Consequences

Positive:

- Each claim is checked by a tool that can actually check it.
- Honest public framing: "property-tested + bounded-model-checked + concurrency-
  model-checked," never blanket "formally verified."

Negative:

- Kani is bounded and concurrency-blind; deductive tools are spec-heavy and (Verus)
  suffer SMT instability at scale; model checks prove the model, not the Postgres code
  unless code is shared or trace conformance is added.

## Follow-Up

- Seed `evals/` with the proptest stateful harness (tracked in the roadmap's evals
  hardening section).
- Resolve canonicalization first ([ADR 0004](0004-canonicalization-and-hash-chain.md))
  so hash-link proofs have deterministic bytes.
- See [formal-verification.md](../formal-verification.md).
