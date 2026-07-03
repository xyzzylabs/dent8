# ADR 0017 - Survived challenges as entrenchment in the supersession gate

Date: 2026-07-03

## Status

Accepted.

## Context

ADR 0015 built survived-challenge *recording*: a challenge the firewall rejects on strength
is written to the incumbent's stream as a `claim.challenge_rejected` event, accumulating
`ClaimState.survived_challenges` (Sybil-resistant `survived_challenges_at_or_above`). Its
closing note deferred one thing on purpose:

> Survived challenges are **recorded but not yet consulted by arbitration** … Feeding them
> into the supersession gate (a claim that survived N high challenges demands more than
> corroboration parity to displace) is future work, deliberately separate: the recording must
> exist and accumulate honestly before any gate consumes it.

Meanwhile the opt-in earned-supersession gate (ADR 0015, `DENT8_ENTRENCHMENT_GATE=1`) and the
always-on `EntityProjection::unearned_supersessions` audit both weigh **corroboration only**
at equal authority. That is half of "earned entrenchment": a claim is entrenched both by
*independent backing* (corroboration) and by *having been attacked and stood*
(survived challenges). A fact that beat two high-authority takeover attempts is more
entrenched than a never-tested one with the same single backer — but today an equal-authority
fresh challenger displaces both identically.

## Decision

Define **earned entrenchment** at a level as the sum of the two Sybil-resistant halves:

```
earned_entrenchment_at_or_above(L) = corroboration_at_or_above(L) + survived_challenges_at_or_above(L)
```

Both terms count only backers / challengers at authority ≥ `L`, so minting low-authority
sources or challenges cannot inflate it. Add `ClaimState::earned_entrenchment_at_or_above`.

### The gate now weighs both halves

The opt-in `DENT8_ENTRENCHMENT_GATE=1` supersession gate compares **earned entrenchment**
instead of bare corroboration: at equal authority, a supersession is rejected when the
incumbent's earned entrenchment strictly exceeds the challenger's. A `supersede` mints a
*fresh* replacement (corroboration 1 — its asserter — and 0 survived challenges, so earned
entrenchment 1), so the gate condition is exactly "incumbent earned entrenchment > 1". The
consequence is the intended one: **surviving even a single equal-or-higher-authority
challenge raises a claim's entrenchment to 2, so it resists the next fresh equal-authority
replacement** — protection derived from challenge-survival, the novelty-rank-3 property.

A rejection under the gate is itself a survived challenge, recorded like any other. Its
recorded reason is a new `ChallengeRejection::WeakerEntrenchment` (the old
`WeakerCorroboration` reason stays a *deserializable* variant so pre-0.3 challenge-rejected
events still parse — event bytes are never rewritten).

Still opt-in, still off by default. It trades plasticity for entrenchment — a genuinely newer
fact usually arrives from one source with nothing survived, and rejecting it until it earns
standing is a policy choice, not a default. The recording (ADR 0015) stays on by default; only
the *gating* is opt-in, unchanged from ADR 0015.

### The audit agrees with the gate

`EntityProjection::unearned_supersessions` uses the same earned-entrenchment measure, so the
always-on detector and the write-time gate render the same verdict on "unearned." Its
`WeakerCorroboration` finding is renamed `WeakerEntrenchment`
(`incumbent_entrenchment` / `challenger_entrenchment`) — a `dent8-store` API change, not a
format change (the audit is computed, never serialized). `AuthorityDowngrade` is unchanged;
authority downgrades are already rejected at write time by the anti-laundering check.

### Not consulted: the default path

The base firewall (no gate) is unchanged: survived challenges do not gate a write unless the
operator opts in. This keeps the unbypassable security floor exactly as ADR 0007/0015 defined
it and confines the plasticity trade-off to operators who choose it.

## Compatibility

- **No `CANON_VERSION` bump.** No event field changes; the new `WeakerEntrenchment` rejection
  reason is additive and the old one still deserializes. Existing events, hashes, and golden
  fixtures are untouched.
- `dent8-store`'s `UnearnedSupersession::WeakerCorroboration → WeakerEntrenchment` is a
  breaking rename of a computed (non-serialized) API type — a `0.3.0` minor bump, with no
  external consumers today.

## Consequences

- A battle-tested fact becomes progressively harder to displace at equal authority, exactly
  as much as it has been attacked-and-held — closing the loop ADR 0015 opened.
- The gate and the projection audit share one definition of earned entrenchment, so
  `verify`/doctor and the write path cannot disagree about what "unearned" means.
- Feeding survived challenges into arbitration remains **bounded to the opt-in gate**; a
  future step could weight survival differently from corroboration (they are summed 1:1 here)
  or consult it in the default path — deliberately out of scope until the 1:1 sum is shown
  wanting.
