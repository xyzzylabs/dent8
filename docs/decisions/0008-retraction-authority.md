# 0008: Retraction Authority (gate `claim.retracted` before shipping `dent8 retract`)

Date: 2026-06-27

## Status

**Accepted (option 1) — implemented.** The authority gate is built in
`dent8-core::apply_event`'s `Retracted` arm and covered by the exhaustive lattice test
`authority_monotone_retraction_and_non_resurrection` plus a `#[cfg(kani)]` proof; `dent8
retract` exposes it. Options 2 (asserter-identity) and 3 (reason-scoping) remain future
refinements on top of this baseline.

## Context

An adversarial review of the `supersede` verb surfaced a real, code-confirmed asymmetry:
a naively-built `dent8 retract` would let a **low-authority actor terminally retract a
high-authority fact**. Three gates that protect supersession do *not* apply to retraction:

- `apply_event`'s `Retracted` arm (`state.rs`) sets `lifecycle = Retracted` with **no
  authority comparison**, unlike the `Superseded` arm (which rejects
  `event.authority < state.authority` as `InsufficientAuthority`).
- `arbitrate`'s anti-laundering check (`firewall.rs`) fires **only** for
  `Superseded` events; a `Retracted` event is never authority-checked against the
  incumbent.
- The registry's authority floor and uniqueness (`registry.rs`) gate **only**
  `Asserted`. A `Retracted` candidate passes untouched.

`Retracted` is terminal (`ClaimLifecycle::is_terminal`), so a successful low-authority
retraction permanently kills a trusted fact — the same MINJA threat (T1) that authority-
weighted supersession exists to stop. Today this is *latent*: no CLI verb and nothing
outside `#[cfg(test)]` constructs a `Retracted` event, so it is a pre-emptive design gate,
not a live vulnerability.

Retraction is **not** the same as dissent. A low-authority `Contradicted` is deliberately
admitted (it moves a claim to `Contested` and preserves it, and a contradiction against a
`Canonical` claim trips the hard-alarm — see [ADR 0007](0007-authority-as-entrenchment.md)).
Retraction *removes* the belief. So it must **not** inherit the contradiction/dissent
exemption.

## Decision

**Option 1 (symmetric with supersession), chosen.** A `Retracted` event whose authority
strictly under-ranks the incumbent is rejected with the existing
`TransitionError::InsufficientAuthority`, enforced in `apply_event`'s `Retracted` arm —
the same gate the `Superseded` arm applies. Equal-or-higher authority is admitted (a
source can retract its own claim with its own authority).

One correction to the framing above: unlike supersession, retraction carries **no backing
claim**, so there is no laundering indirection (an over-stated *event* authority backed by
a weaker *claim*). The supersession-only `arbitrate` anti-laundering check therefore has no
retraction analogue, and the `apply_event` stated-authority gate is the *complete* check.
Retraction is **not** subjected to the registry's `Asserted`-only floor (the
incumbent-relative gate is stronger), and `from_trusted_events` reload still treats the
log as already-arbitrated (the gate lives at write time, like the others).

Candidates **not** chosen, kept as future refinements:

2. **Asserter-only** — only the source that made a claim (or a strictly higher one) may
   retract it. Needs the retractor's identity checked against the incumbent's provenance,
   not just authority levels.
3. **Reason-scoped** — `RetractionReason::PoisoningDetected` / `SourceInvalidated` could be
   privileged to a high authority regardless of the incumbent (a trust-and-safety action).

## Consequences

Positive:

- Closes the T1 gap for retraction before it can be reached, keeping the firewall's
  "low-privilege cannot destroy a trusted fact" guarantee total across *all* belief-
  removing events, not just supersession.
- Forces the asymmetry to be a conscious choice (dissent is cheap; removal is not).

Negative:

- Adds a `Retracted` branch to `apply_event` plus property tests mirroring the
  supersession ones — retraction is no longer a trivial terminal transition.
- Rule 2/3 require provenance/identity plumbing the current authority-level comparison
  does not need.

Residual risk:

- The gate stops a *low-authority* retraction. It does **not** stop a writer with
  store/log access from **injecting** an equal-or-higher-authority `Retracted` event to
  drop a fact — the same class as the threat model's "authority is asserted, not proven"
  and "operator with DB access" limits. Lineage validation does not flag this (a retracted
  successor is a legitimate `SupersededByInvalidated` history); it is caught only by the
  hash chain plus a future external anchor (a signed/published head), not by replay alone.

## Follow-Up

- [DONE] Authority gate in `apply_event`'s `Retracted` arm
  (`TransitionError::InsufficientAuthority`), the exhaustive lattice test
  `authority_monotone_retraction_and_non_resurrection`, and a `#[cfg(kani)]` proof
  `retraction_is_authority_monotone_and_non_resurrecting`.
- [DONE] `dent8 retract <kind> <key> <predicate> <authority> <source>` removes **every**
  believed claim for the subject+predicate, each authority-gated; a low-authority retract
  of a high fact is rejected.
- Future: option 2 (asserter-identity) / option 3 (reason-scoped trust-and-safety
  retraction) if needed; and the retraction-cascade to dependents (the second half of T8).
- Grounded in [ADR 0007](0007-authority-as-entrenchment.md) (authority-as-entrenchment)
  and [ADR 0005](0005-belief-base-revision-semantics.md) (belief-base revision).
