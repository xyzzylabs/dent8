-- dent8 Postgres schema, migration 003: materialized projection + edge graph.
--
-- These tables are **derived caches** of the event log (migration 002), maintained inside
-- the same append transaction so a reader can fetch the believed state without re-folding
-- the log. The log remains the single source of truth: `projection == fold(log)` is the
-- invariant, checkable with `PostgresEventStore::verify_projection`. They populate the
-- inspection/materialization role migration 001 sketched, but aligned with the actual
-- `dent8_core` types: timestamps are `BIGINT` Unix milliseconds (matching `TimestampMillis`,
-- never DB-generated, so a deterministic replay rebuilds identical rows), and the exact
-- folded state is kept as `state_json` for lossless reconstruction.

-- The current folded `ClaimState` per claim. Upserted on every accepted append.
CREATE TABLE IF NOT EXISTS dent8_claim_projection (
    claim_id TEXT PRIMARY KEY,
    subject_type TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    predicate TEXT NOT NULL,
    lifecycle TEXT NOT NULL CHECK (
        lifecycle IN ('active', 'contested', 'superseded', 'expired', 'retracted')
    ),
    superseded_by TEXT,
    -- Claims that contradict this one (the accumulated `contradicted_by`).
    contradicted_by TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    -- Distinct sources backing the believed value (earned-entrenchment degree). BIGINT so
    -- the count binds losslessly from the Rust `usize`, with no saturation.
    corroboration BIGINT NOT NULL CHECK (corroboration >= 0),
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    last_event_id TEXT NOT NULL,
    -- The exact folded `ClaimState`, for lossless reconstruction without re-folding. The
    -- scalar columns above are derived from it for indexing and must never disagree.
    state_json JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS dent8_claim_projection_subject_idx
    ON dent8_claim_projection (subject_type, subject_key, predicate);

CREATE INDEX IF NOT EXISTS dent8_claim_projection_lifecycle_idx
    ON dent8_claim_projection (lifecycle, updated_at);

-- The claim->claim relationship graph. Each row is recorded from one originating event:
-- the event lives on `from_claim_id` and names `to_claim_id` (its `by`). Direction reads
-- "`from` records a `<edge_type>` link to `to`" — e.g. a `claim.superseded {by: B}` on A
-- yields (from=A, to=B, supersedes). `recorded_at` is the originating event's stamp (never
-- DB-generated), so replay rebuilds identical edges. (`uses_as_evidence` — claim->evidence,
-- a different namespace — is deferred.)
CREATE TABLE IF NOT EXISTS dent8_claim_edge (
    from_claim_id TEXT NOT NULL,
    to_claim_id TEXT NOT NULL,
    edge_type TEXT NOT NULL CHECK (
        edge_type IN ('reinforces', 'contradicts', 'supersedes')
    ),
    event_id TEXT NOT NULL,
    recorded_at BIGINT NOT NULL,
    PRIMARY KEY (from_claim_id, to_claim_id, edge_type, event_id)
);

CREATE INDEX IF NOT EXISTS dent8_claim_edge_to_idx
    ON dent8_claim_edge (to_claim_id, edge_type);
