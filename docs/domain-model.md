# Domain Model

## Core Primitive

The core primitive is `FactEvent`.

A fact event records something that happened to a fact: assertion, reinforcement, contradiction, supersession, expiration, retraction, retrieval, or use in a decision.

The platform may expose "memory" to agents, but internally memory is always a replayed projection over fact events.

## Fact Shape

A fact is shaped as:

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

- `fact.asserted`: creates a new fact stream.
- `fact.reinforced`: adds compatible evidence without changing value.
- `fact.contradicted`: records a conflict from another fact.
- `fact.superseded`: points to a replacing fact.
- `fact.expired`: terminally closes a fact by explicit policy action; TTL staleness is a
  separate read-time predicate and does not mutate lifecycle.
- `fact.retracted`: removes trust in a fact because the source, policy, or evidence failed.
- `fact.retrieved`: audits that a fact was returned as context. Emitted by
  `dent8 context --record-retrieval` for every fact the context pack emits.
- `fact.used_in_decision`: audits that a fact influenced an agent decision. Emitted by a
  `dent8 capture` proposal with `"op": "used_in_decision"` — the channel agents already use
  to report back during a session. Audit events are deliberately **not** authority-gated in
  the fold (like dissent): a low-authority reader may record that it retrieved or used a
  high-authority fact; the write-boundary gate (source ceiling, grant scope, signed
  identity) still applies.
- `fact.challenge_rejected`: records that the firewall rejected a challenge against this
  fact on strength (ADR 0015) — written with the *challenger's* provenance and effective
  authority, so surviving an attack is replayable, attributed entrenchment evidence.

Use past-tense event names because events are immutable facts.

## Required Assertion Fields

`fact.asserted` requires:

- `event_id`
- `fact_id`
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
`observed_at`, `valid_from`, and `valid_to` are optional `FactEvent` fields (the
valid-time anchors and the asserted end of validity — ADR 0016).

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

Evidence links facts to observable support.

Initial evidence kinds:

- Direct observation.
- Tool output.
- File span.
- User statement.
- Derived summary.
- External document.

Derived summaries should never erase their source spans. They are facts with evidence, not privileged replacements for evidence.

## Authority

Authority answers how much weight a fact should receive for a specific scope.

Initial authority levels:

- `unknown`
- `low`
- `medium`
- `high`
- `canonical`

Authority is not the same as confidence. A low-authority fact can be high-confidence about what a weak source said; a canonical source can still be superseded if it changes.

Formally, authority is an **epistemic-entrenchment** ordering and confidence is evidential strength — two distinct structures, which is the reason they are separate fields. Authority *arbitrates* conflict (higher entrenchment wins), and this is now enforced in the fold: `apply_event` rejects a supersession whose challenger authority is strictly below the incumbent's, and hard-alarms a contradiction against a `Canonical` fact. Confidence is deliberately not consulted in arbitration. See [belief-revision.md](belief-revision.md) and [ADR 0007](decisions/0007-authority-as-entrenchment.md).

## TTL and Freshness

TTL answers when a fact should stop being returned as fresh context.

Initial TTL forms:

- `never`
- `expires_at`
- `duration`

Expired facts remain in the event log. Explicit expiration changes read eligibility and
projection state; it does not delete history, and it is authority-gated like retraction.

> Status: the read-time **freshness evaluator is implemented** —
> `FactState::is_expired_at(now)` (`state.rs`) evaluates TTL against the fact's
> `freshness_anchor` (`valid_from`, else `observed_at`, else `recorded_at`) and is
> tested. It is deliberately a *read-time predicate*, kept separate from the
> event-driven lifecycle: a fact is not auto-mutated to `Expired` by TTL; `Expired`
> as a lifecycle state still comes only from an authority-gated `fact.expired` event
> (ADR 0011). The CLI/MCP read surface applies freshness by flagging stale receipts.
> `valid_to` closes the interval (ADR 0016): an asserted end of validity is treated by
> reads exactly like an elapsed TTL (`expires_at` is the earliest of the two bounds), and a
> future `valid_from` reads *not yet valid*. The enumeration surfaces — `facts list`, MCP
> `list_facts`, and `resources/list` — now flag each stream's freshness too, so the read
> surface is complete.

## Lifecycle State

The first fact lifecycle is intentionally small:

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

Contradiction records a relationship between facts. It should preserve both sides and a basis.

Initial contradiction bases:

- Same predicate, different value.
- Mutually exclusive predicate.
- Authority challenge.
- Freshness challenge.

A contradiction does not automatically delete either fact. It makes the conflict visible to read policy, replay, and debugger surfaces.

## Supersession

Supersession records that one fact has been replaced by another.

Initial supersession reasons:

- Newer observation.
- Higher authority.
- User correction.
- Schema migration.

Supersession must be explainable: the old fact should point to the replacing fact, and the replacing fact should preserve evidence for why it is now preferred.

## Formal grounding

dent8 is a **belief base** (Hansson), not a logically-closed AGM belief *set*, and it
**deliberately does not satisfy the Recovery postulate**: retracting a fact and later
re-asserting it must not resurrect everything that depended on the original, because
the new assertion carries different provenance and evidence. The `contested` state is
a **paraconsistent** design — a visible contradiction must not trivialize the store.
See [belief-revision.md](belief-revision.md) and
[ADR 0005](decisions/0005-belief-base-revision-semantics.md).

## Invariants

- A fact stream starts with exactly one `fact.asserted`.
- `fact.asserted` must include value and evidence.
- `fact.reinforced` must not change value.
- Terminal facts cannot be changed by lifecycle events.
- State replay must be deterministic.
- Projection state must be derivable from ordered events.
- Fresh reads must exclude expired facts unless explicitly requested *(evaluator `FactState::is_expired_at` built and **applied on reads**: `explain` flags a stale fact and the receipt carries `fresh`/`expires_at`; `valid_to` intervals are built (ADR 0016) — see [threat-model.md](threat-model.md) T4)*.
- Contradictions and supersessions must leave auditable edges, symmetric at query time.
- Higher-authority supersession requires an explicit basis: the replacing fact must out-rank or tie the incumbent (enforced in `apply_event`).
- Cross-stream lineage holds: if a fact is `superseded_by` another, the replacing fact exists and does not orphan the lineage.
- Re-assertion after retraction does not restore prior dependents (Recovery deliberately not satisfied).
