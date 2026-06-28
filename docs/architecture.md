# Architecture

dent8 is a memory integrity platform, not a memory provider. The platform owns correctness around memory writes and reads: provenance, freshness, contradiction handling, supersession, replay, authority, and explainability.

## Product Boundary

The first product boundary is one runtime with three surfaces:

- Memory firewall: validates claim-event writes before they alter projections.
- Versioned memory store: persists immutable events and materialized current state.
- Memory debugger: replays event streams and explains why state looks the way it does.

These surfaces share one event model. A debugger that cannot replay the same events accepted by the firewall is not trustworthy.

The integrity semantics behind these surfaces have a formal identity — dent8 is a **belief base** with paraconsistent contradiction tolerance and an authority-as-entrenchment ordering. See [belief-revision.md](belief-revision.md). The adversary the firewall defends against is in [threat-model.md](threat-model.md), and how the invariants are checked is in [formal-verification.md](formal-verification.md).

## Storage

The durable storage design is the append-only event log, its projection, the edge graph, and a tamper-evident hash chain — expressed against the `EventStore` trait. **Postgres is the first adapter that realizes it, not the architecture.** The full design (backend-agnostic event log + Postgres adapter + canonicalization) lives in [storage.md](storage.md); the decision to start Postgres-first (and not SQLite) is [ADR 0001](decisions/0001-postgres-first.md). DuckDB and Parquet are a later analytical lane that consumes *exported* event streams, never runtime writes.

## Rust Workspace

```text
dent8/
  crates/
    dent8-core/            # claim-event model, lifecycle state machine, invariants
    dent8-store/           # store traits, replay boundary, invariant result types
    dent8-store-postgres/  # Postgres migrations and adapter implementation
    dent8-cli/             # CLI commands for schema, replay, explain, MCP
  migrations/postgres/     # SQL migrations
  docs/                    # architecture, eval strategy, naming, MVP notes
  evals/
    fixtures/              # canonical event streams
    replay/                # replay scenarios and expected outcomes
```

Later crates should be added only when they own a real boundary:

- `dent8-policy`: write/read policy and approval state machines.
- `dent8-mcp`: MCP transport adapter.
- `dent8-http`: HTTP API.
- `dent8-debugger`: debugger query model before the TypeScript UI exists.
- `dent8-export`: Parquet export and DuckDB analysis helpers.

## Core Model

The primitive is `ClaimEvent`.

Each event belongs to a claim stream identified by `claim_id`. A claim stream starts with `claim.asserted`; later events can reinforce, contradict, supersede, expire, retract, retrieve, or use the claim in a decision.

Core fields:

- `event_id`
- `claim_id`
- `event_type`
- `subject`
- `predicate`
- `claim_value`
- `confidence`
- `authority`
- `ttl`
- `provenance`
- `evidence`
- `observed_at`
- `valid_from`
- `recorded_at`
- `causation_event_id`
- `correlation_id`
- `event_hash`

The first projection state machine is intentionally small:

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

Retrieval and decision-use events are audit events. They do not change lifecycle state but they matter for debugging stale or unsafe context use.

## Write Path

1. Normalize input into a candidate claim event.
2. Validate required provenance, evidence, authority, TTL, and schema shape.
3. Read relevant active/contested projections for the same subject and predicate.
4. Detect duplicate, contradiction, or supersession candidates.
5. Accept, reject, or require explicit policy approval.
6. Append the immutable event in Postgres.
7. Update projections in the same transaction.
8. Emit invariant results for replay and debugger use.

## Read Path

Reads should return claim state plus integrity metadata:

- lifecycle state
- freshness and TTL
- authority level
- supporting evidence
- contradiction count
- supersession chain
- provenance summary
- replay position

The MCP and CLI surfaces should expose this metadata by default. dent8 should make unsafe or stale memory visible, not hide it behind a plain string context blob.

## Implementation status (honest)

The write/read paths above are the *target*. The core fold implements lifecycle
transitions, terminal immutability, contradiction-as-`contested`, and — now —
**authority-weighted arbitration**: a strictly-lower-authority supersession is
rejected and a canonical contradiction hard-alarms
([ADR 0007](decisions/0007-authority-as-entrenchment.md)), with an exhaustive
non-resurrection test. The read-time freshness evaluator (`ClaimState::is_expired_at`),
policy-counterfactual replay (`EpistemicPolicy` + `replay_claim_with_policy` +
`diff_states`), and **entity-level replay** (`replay_entity` + `EntityProjection` with
cross-stream `lineage_issues`) also exist and are tested. Still **not built**: a read
surface that *applies* freshness and exposes these views (CLI/MCP), and the
*transactional firewall* that calls the arbitration within a locked append (it lives in
the not-yet-built store layer). So
"low-authority writes can't override high-authority facts" is enforced in the fold but
not yet end-to-end; "fresh reads exclude expired" remains a claim of intent. See
[roadmap.md](roadmap.md) and [threat-model.md](threat-model.md).

