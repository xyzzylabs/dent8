# 0009: Uniqueness Coexists with Contestation

Date: 2026-06-28

## Status

**Accepted — implemented.** The reload-time uniqueness validator and the `dent8
contradict` verb both treat an explicitly contested set as a single flagged conflict, not
a uniqueness violation.

## Context

The coding-agent predicate registry marks facts like `repo.database` **unique**: at most
one *believed* claim per subject+predicate ([registry](../../crates/dent8-store/src/registry.rs)).
Independently, dent8's belief-revision identity is **paraconsistent**: a `claim.contradicted`
moves the incumbent to `Contested` and *preserves* both the claim and its
`contradicted_by` edge — "localize the contradiction, keep the store non-trivial, surface
it" ([ADR 0005](0005-belief-base-revision-semantics.md), [belief-revision.md](../belief-revision.md)).

These collide. The sanctioned way to *flag* a conflict — `dent8 contradict` — asserts an
opposing claim and contests the incumbent, leaving **two** believed claims (the `Contested`
incumbent and its `Active` contradictor) for one unique subject+predicate. A naïve
uniqueness rule ("at most one believed claim, full stop") would either forbid contradiction
entirely or reject a legitimately-contested log on reload (the same false-positive class as
the [ADR 0008](0008-retraction-authority.md) `SupersededByInvalidated` regression).

## Decision

**Uniqueness is over *mutually-consistent* believed claims, and contestation is the
explicit exception.** Concretely:

- A unique predicate is *violated* only when **more than one fresh believed claim exists
  and none of them is `Contested`** — i.e. a *silent* duplication, the corruption the
  invariant exists to catch.
- When at least one believed claim is `Contested`, the set is a **surfaced conflict**, not
  a violation. The firewall has done its job (the disagreement is visible and auditable);
  resolving it is a separate, deliberate act (`supersede` installs a winner; `retract`
  removes one side).
- Contradiction is **dissent**, so it is *not* authority-gated (a low-authority source may
  contest a high-authority fact), with the one exception that a contradiction against a
  `Canonical` claim is a hard alarm, not a soft contest ([ADR 0007](0007-authority-as-entrenchment.md)).
  This is the deliberate asymmetry: dissent (`contradict`) is cheap; override (`supersede`)
  and removal (`retract`) must out-rank the incumbent.

## Consequences

Positive:

- `dent8 contradict` is runnable without weakening uniqueness: a low-privilege actor can
  **flag** a wrong fact (forcing it `Contested`) but still cannot **override** or **delete**
  it — completing the assert / supersede / retract / contradict surface.
- The reload validator stays sound: silent duplication is still rejected; a flagged
  contestation reloads cleanly.

Negative:

- "At least one `Contested`" is a coarse exemption: it permits a believed set larger than
  two if multiple contradictors pile on. That is acceptable (every member is an audited
  part of the surfaced conflict) but means uniqueness no longer implies "≤2 believed".
- A plain `assert` into a contested predicate is still blocked by registry uniqueness (the
  believed set is non-empty); the user must resolve the contest (`supersede`/`retract`)
  first. This is intended — you do not silently add a third opinion.

## Follow-Up

- [DONE] `dent8 contradict` (asserts the opposing claim + a `Contradicted` event on the
  incumbent, atomically; a `Canonical` incumbent hard-alarms).
- [DONE] `validate_unique_log` exempts a set containing a `Contested` claim.
- Future: a `dent8 resolve` shortcut (supersede that also clears the contest), and surfacing
  the full contradictor list in `explain` rather than just a count.
- Grounded in [ADR 0005](0005-belief-base-revision-semantics.md) (paraconsistent
  contested state) and [ADR 0007](0007-authority-as-entrenchment.md) (dissent is not
  authority-gated; canonical is the exception).
