# Domain Model

## Core Primitive

The core primitive is `ClaimEvent`.

A claim event records something that happened to a claim: assertion, reinforcement, contradiction, supersession, expiration, retraction, retrieval, or use in a decision.

The platform may expose "memory" to agents, but internally memory is always a replayed projection over claim events.

## Claim Shape

A claim is shaped as:

```text
subject + predicate + value
```

Examples:

```text
repo:dent8 + uses_database + postgres
repo:dent8 + cli_binary + dent8
user:project_owner + prefers_eval_style + formal fixtures and invariants
```

## Event Types

- `claim.asserted`: creates a new claim stream.
- `claim.reinforced`: adds compatible evidence without changing value.
- `claim.contradicted`: records a conflict from another claim.
- `claim.superseded`: points to a replacing claim.
- `claim.expired`: marks a claim stale by TTL or policy.
- `claim.retracted`: removes trust in a claim because the source, policy, or evidence failed.
- `claim.retrieved`: audits that a claim was returned as context.
- `claim.used_in_decision`: audits that a claim influenced an agent decision.

Use past-tense event names because events are immutable facts.

## Required Assertion Fields

`claim.asserted` requires:

- `event_id`
- `claim_id`
- `subject`
- `predicate`
- `value`
- `confidence`
- `authority`
- `ttl`
- `provenance` (which carries `recorded_at`, the appender-supplied transaction time)
- at least one `evidence` entry

`event_hash` is **derived on append** from the canonical bytes (it lives on
`AppendReceipt` and as a stored column), not a field the appender supplies.
`observed_at` and `valid_from` are optional `ClaimEvent` fields (valid-time anchors).

## Provenance

Provenance should answer:

- Who or what produced this event?
- Which tool, run, or adapter recorded it?
- When was it recorded?
- Which input digest or source reference can reproduce it?

Initial fields:

- `source`
- `actor`
- `tool`
- `run_id`
- `input_digest`
- `recorded_at`

## Evidence

Evidence links claims to observable support.

Initial evidence kinds:

- Direct observation.
- Tool output.
- File span.
- User statement.
- Derived summary.
- External document.

Derived summaries should never erase their source spans. They are claims with evidence, not privileged replacements for evidence.

## Authority

Authority answers how much weight a claim should receive for a specific scope.

Initial authority levels:

- `unknown`
- `low`
- `medium`
- `high`
- `canonical`

Authority is not the same as confidence. A low-authority claim can be high-confidence about what a weak source said; a canonical source can still be superseded if it changes.

Formally, authority is an **epistemic-entrenchment** ordering and confidence is evidential strength — two distinct structures, which is the reason they are separate fields. Authority *arbitrates* conflict (higher entrenchment wins), and this is now enforced in the fold: `apply_event` rejects a supersession whose challenger authority is strictly below the incumbent's, and hard-alarms a contradiction against a `Canonical` claim. Confidence is deliberately not consulted in arbitration. See [belief-revision.md](belief-revision.md) and [ADR 0007](decisions/0007-authority-as-entrenchment.md).

## TTL and Freshness

TTL answers when a claim should stop being returned as fresh context.

Initial TTL forms:

- `never`
- `expires_at`
- `duration`

Expired claims remain in the event log. Expiration changes read eligibility and projection state; it does not delete history.

> Status: the read-time **freshness evaluator is implemented** —
> `ClaimState::is_expired_at(now)` (`state.rs`) evaluates TTL against the claim's
> `freshness_anchor` (`valid_from`, else `observed_at`, else `recorded_at`) and is
> tested. It is deliberately a *read-time predicate*, kept separate from the
> event-driven lifecycle: a claim is not auto-mutated to `Expired` by TTL; `Expired`
> as a lifecycle state still comes only from a `claim.expired` event. Not yet built:
> a read surface (CLI/MCP) that *applies* the predicate to exclude stale claims, and
> a `valid_to` closed valid-time interval (only an open `valid_from` plus TTL today).

## Lifecycle State

The first claim lifecycle is intentionally small:

```text
none -> active
active -> contested
active -> superseded
active -> expired
active -> retracted
contested -> superseded
contested -> expired
contested -> retracted
```

Terminal lifecycle states:

- `superseded`
- `expired`
- `retracted`

Retrieval and decision-use events are audit events. They do not change lifecycle state.

## Contradiction

Contradiction records a relationship between claims. It should preserve both sides and a basis.

Initial contradiction bases:

- Same predicate, different value.
- Mutually exclusive predicate.
- Authority challenge.
- Freshness challenge.

A contradiction does not automatically delete either claim. It makes the conflict visible to read policy, replay, and debugger surfaces.

## Supersession

Supersession records that one claim has been replaced by another.

Initial supersession reasons:

- Newer observation.
- Higher authority.
- User correction.
- Schema migration.

Supersession must be explainable: the old claim should point to the replacing claim, and the replacing claim should preserve evidence for why it is now preferred.

## Formal grounding

dent8 is a **belief base** (Hansson), not a logically-closed AGM belief *set*, and it
**deliberately does not satisfy the Recovery postulate**: retracting a claim and later
re-asserting it must not resurrect everything that depended on the original, because
the new assertion carries different provenance and evidence. The `contested` state is
a **paraconsistent** design — a visible contradiction must not trivialize the store.
See [belief-revision.md](belief-revision.md) and
[ADR 0005](decisions/0005-belief-base-revision-semantics.md).

## Invariants

- A claim stream starts with exactly one `claim.asserted`.
- `claim.asserted` must include value and evidence.
- `claim.reinforced` must not change value.
- Terminal claims cannot be changed by lifecycle events.
- State replay must be deterministic.
- Projection state must be derivable from ordered events.
- Fresh reads must exclude expired claims unless explicitly requested *(evaluator `ClaimState::is_expired_at` built and **applied on reads**: `explain` flags a stale fact and the receipt carries `fresh`/`expires_at`; remaining target is a `valid_to` interval — see [threat-model.md](threat-model.md) T4)*.
- Contradictions and supersessions must leave auditable edges, symmetric at query time.
- Higher-authority supersession requires an explicit basis: the replacing claim must out-rank or tie the incumbent (enforced in `apply_event`).
- Cross-stream lineage holds: if a claim is `superseded_by` another, the replacing claim exists and does not orphan the lineage.
- Re-assertion after retraction does not restore prior dependents (Recovery deliberately not satisfied).

