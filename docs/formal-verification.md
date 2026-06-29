# Formal Verification Stack

dent8 makes strong correctness claims — deterministic replay, `projection ==
fold(events)`, terminal-state immutability, tamper-evident hash chains,
serializable concurrent contradiction writes — but today has only example-based
unit tests in `dent8-core` and no implementation behind `dent8-store`'s
`replay_claim`/`EventStore` ([`crates/dent8-store/src/lib.rs`](../crates/dent8-store/src/lib.rs)).
This document surveys the 2025–2026 Rust verification ecosystem with honest scope,
then recommends a concrete *layered* stack, mapping specific dent8 invariants to
specific tools in a phased order tied to the current code.

The guiding principle: there is no one-size-fits-all tool. Serious correctness work
combines design-level model checking with implementation-level property and
simulation testing [1][2]. The honest end-state positioning is *"integrity
invariants are property-tested and bounded-model-checked, the core fold is
deductively verified, and the concurrency protocol is model-checked for
linearizability"* — **not** a blanket "formally verified memory integrity," which
would overclaim what any single tool provides.

## The landscape, with accurate scope

**Property-based / stateful testing (proptest, bolero, proptest-stateful).** The
lowest-effort, highest-immediate-ROI layer. `proptest-stateful` generates an
operation sequence, runs each operation against the real system, and checks it
against an independent *reference model* plus pre/postconditions [3] — exactly the
shape of `projection == fold(events)`. It exercises real code but gives only
probabilistic coverage, not a proof. `bolero` unifies PBT and bounded model
checking behind one harness, so a critical invariant can be escalated to Kani
without rewriting it [4].

**Kani (CBMC bounded model checker).** Kani translates Rust MIR to a CBMC
goto-program and exhaustively checks *all* inputs and paths up to an unwinding
bound, automatically proving panic-freedom, arithmetic-overflow absence, and user
assertions [5]. Two hard limits matter. First, it is *bounded*: unbounded loops and
data structures (arbitrarily long event streams) are explored only to finite length
and need manual loop invariants or unwind caps [6]. Second, **concurrency is out of
scope** — Kani compiles concurrent code as sequential and warns [5]. So Kani fits
the pure, single-threaded `apply_event` and per-event hash computation, but cannot
touch the append+projection transaction or contradiction-write serialization.

**Deductive verifiers (Creusot, Verus, Prusti, Aeneas).** These are deductive
verifiers that can prove *unbounded* functional correctness of safe Rust (via
loop/inductive invariants, unlike bounded model checkers) — a genuine "for all
streams of any length, `projection == fold`" theorem — but at high specification
cost [7][8]. Encodings differ: Creusot translates to Coma/Why3 and discharges SMT
obligations with a prophecy encoding of mutable borrows; Verus uses Z3 with linear
ghost types; Prusti encodes into Viper separation logic; Aeneas does a functional
translation to a pure calculus. The realistic-expectations caveat is strong: a 2025
std-library effort reports most challenges were satisfied only at the *safety* level
(no panic/UB); functional-correctness verification remains low-coverage and
effort-heavy [6]. Verus is the most active SMT tool but young (<500 verified files
on GitHub as of 2025) and suffers **SMT query instability** at scale — large
projects generate unstable queries that flip pass/fail and become flaky CI
dependencies [9]. Lesson: reserve deductive proof for the smallest, most critical
core, never the whole workspace.

**Protocol-level checkers (TLA+/Apalache, Stateright, P).** Serializability,
append+projection atomicity, and event-log linearizability live at a layer Kani and
the deductive tools cannot reach. TLC enumerates states; Apalache encodes bounded
symbolic runs as SMT and supports inductive invariants [10]. **Stateright** is
uniquely valuable for dent8 because the model is written in Rust, ships a built-in
linearizability tester, and "can also be run on a real network without being
reimplemented in a different language" [11][12] — shrinking the model-to-code gap
that TLA+/P leave open. (Kani originated at AWS; the P language originated at
Microsoft Research / UC Berkeley and is also used at AWS — both inform the
"portfolio, not silver bullet" stance [1][2].) The critical caveat: checking a
*model* proves things about the model, not the not-yet-built
`dent8-store-postgres` adapter. Closing that gap requires either Stateright's shared
Rust code or trace/log conformance checking (P's PObserve-style approach, an active
2025–2026 research area) [2].

## Recommended layered stack, invariants mapped to tools

**(a) proptest / bolero — the fold and state-machine algebra.** A `proptest-stateful`
harness whose model re-implements the lifecycle independently and whose operations
are random `ClaimEvent` streams. After each event assert:

- **replay determinism** — same events, same order → same `ClaimState`;
- **`projection == fold(events)`** against the reference model;
- **reinforced never mutates value** — the `ReinforcementValueMismatch` guard (`state.rs:97`);
- **terminal immutability** — no lifecycle event accepted in `Superseded`/`Expired`/`Retracted`
  (`state.rs`), with authority-monotone terminal transitions for supersession, explicit
  expiration, and retraction;
- **single-assertion prefix** — exactly one `claim.asserted` starts a stream;
- **claim isolation** — events on one `claim_id` never perturb another's projection;
- **contradiction-edge symmetry** — `contradicted_by` is one-sided in `state.rs`, but [evals.md](evals.md) requires edges be symmetric at query time; test that the reverse edge is materialized or that `explain` queries both directions;
- **higher-authority basis** — `SupersessionReason::HigherAuthority` must require the replacing claim to actually out-rank the superseded one (the resolution rule from [belief-revision.md](belief-revision.md), once implemented);
- **cross-stream lineage** — if `A.superseded_by = B`, then `B` exists and is not itself retracted/expired in a way that orphans `A`'s lineage;
- **canonicalization stability** — `canonicalize(deserialize(canonicalize(e))) == canonicalize(e)`.

This directly populates the empty `evals/` with proptest's shrunk regression corpus.

**(b) Kani — `apply_event` reachability/panic-freedom and hash-chain links.**
Escalate the most critical invariants via bolero to bounded-exhaustive Kani proofs:
panic-/overflow-freedom of `apply_event` over all event kinds; terminal-immutability
and fold-determinism for streams up to length *N*; and, once hashing exists, that
the chain link verifies (`event_hash` recomputes from canonical bytes;
`previous_event_hash` matches the prior leaf). Keep *N* small and explicit, and
document that this is **bounded, not universal** — do not advertise Kani-verified
"deterministic replay over arbitrarily long streams" [5][6]. If a true unbounded
fold theorem is wanted, scope a single Creusot/Verus proof to just the pure
`dent8-core` fold (~470 non-test LOC across `model.rs`/`state.rs`/`ids.rs`),
accepting the annotation cost and Verus's SMT-instability risk [6][9].

**(c) Stateright (or TLA+) — the Postgres append+projection transaction and
concurrent contradiction serializability.** Model `EventStore::append` + projection
+ contradiction-edge protocol and run Stateright's linearizability tester. Prefer
Stateright over a standalone TLA+/Apalache spec because its Rust model can share
types/logic with the eventual sqlx adapter [11][12]. When the real adapter lands,
do not assume the result transfers automatically: add a PObserve-style trace
conformance check emitting the ordered event-application trace from `dent8-store`
and validating it against the model's allowed behaviors [2].

## Phased adoption tied to current code

1. **Now (pure `dent8-core`, no store impl):** add `proptest` + a stateful harness
   for invariants (a). Highest leverage; needs no new subsystems and seeds `evals/`.
   **Built.** Two property suites cover (a):
   [`tests/proptest_invariants.rs`](../crates/dent8-core/tests/proptest_invariants.rs) — the
   canonicalization/hash/anchor properties (canonicalization idempotency + reload-stability
   over arbitrary JSON, the regression that motivated the suite: it reproduces the float bug
   when `float_roundtrip` is removed; `canonical_bytes`/`event_hash` serde round-trips;
   hash-chain tamper localization; anchor accept/reject); and
   [`tests/proptest_fold.rs`](../crates/dent8-core/tests/proptest_fold.rs) — the **stateful
   fold harness**, folding a random coherent event stream through `apply_event` and checking
   every step against an **independent reference model** (accept/reject, the reject *reason*,
   and the resulting lifecycle), plus terminal absorption / non-resurrection, value
   immutability, `updated_at` tracking, replay determinism, and claim isolation. The model
   cross-check is verified to have teeth (a deliberately wrong gate is caught and shrunk).
   **Golden replay fixtures** are also built —
   [`tests/golden_replay.rs`](../crates/dent8-core/tests/golden_replay.rs) freezes named
   event streams (`.events.jsonl`) and their replayed outcome (`.expected.json`: chain head +
   state summary), locking the on-disk encoding, the hash chain, and the fold against drift.
   Remaining for (a): `proptest-stateful`/`bolero` escalation and `cargo-fuzz`.
2. **After event serialization + hashing exist:** keep the frozen canonical form explicit
   (dent8 currently uses sorted-key compact `serde_json`, **not** RFC 8785/JCS — see
   [storage.md](storage.md) and
   [ADR 0004](decisions/0004-canonicalization-and-hash-chain.md)), since tamper-evidence
   is only as strong as deterministic bytes; then add `bolero`/Kani proofs (b) for
   panic-freedom and hash-link checks [13].
3. **After the sqlx adapter is designed:** introduce the Stateright model (c) for
   append+projection atomicity and contradiction serializability, sharing Rust types
   with the adapter.
4. **Optional, scoped:** one Creusot/Verus proof of the fold for an unbounded
   `projection == fold` theorem.

## Honest costs and limits

Kani is bounded and concurrency-blind [5][6]; deductive tools demand heavy specs and
(Verus) suffer SMT timeouts/instability at scale [9]; model checks prove the model,
not the Postgres code, unless Stateright shares code or trace conformance is added
[2]. State this explicitly wherever the project claims verification, so the claim
matches what the portfolio actually delivers.

## References

- [1] [Systems Correctness Practices at AWS (ACM Queue, 2025)](https://queue.acm.org/detail.cfm?id=3712057)
- [2] [The P language — safety/liveness, systematic exploration, PObserve](https://p-org.github.io/P/)
- [3] [proptest-stateful (ReadySet)](https://github.com/readysettech/proptest-stateful)
- [4] [bolero — property testing & fuzzing harness](https://github.com/camshaft/bolero)
- [5] [Kani Rust Verifier — Rust feature support (limitations)](https://model-checking.github.io/kani/rust-feature-support.html)
- [6] [Lessons Learned From a Community Effort to Verify the Rust Standard Library (arXiv 2510.01072)](https://arxiv.org/html/2510.01072v1)
- [7] [Creusot: A Foundry for the Deductive Verification of Rust Programs](https://jhjourdan.mketjh.fr/pdf/denis2022creusot.pdf)
- [8] [A hybrid approach to semi-automated Rust verification (Prusti/Aeneas/Creusot)](https://arxiv.org/html/2403.15122v1)
- [9] [Verus — Verifying Rust Programs using Linear Ghost Types (PACMPL)](https://arxiv.org/pdf/2303.05491)
- [10] [Apalache: symbolic model checker for TLA+](https://apalache-mc.org/)
- [11] [Achieving Linearizability — Building Distributed Systems With Stateright](https://www.stateright.rs/achieving-linearizability.html)
- [12] [Comparison with TLA+ — Stateright](https://www.stateright.rs/comparison-with-tlaplus.html)
- [13] [RFC 8785: JSON Canonicalization Scheme (JCS)](https://datatracker.ietf.org/doc/html/rfc8785)
- [14] [Surveying the Rust Verification Landscape (arXiv 2410.01981)](https://arxiv.org/abs/2410.01981)
