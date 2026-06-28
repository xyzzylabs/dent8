-- dent8 Postgres schema, migration 001.
--
-- Postgres is the operational source of truth. The schema stores immutable
-- claim events first, then derives current claim state through projections.

CREATE TABLE IF NOT EXISTS dent8_claim_events (
    global_sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL CHECK (
        event_type IN (
            'claim.asserted',
            'claim.reinforced',
            'claim.contradicted',
            'claim.superseded',
            'claim.expired',
            'claim.retracted',
            'claim.retrieved',
            'claim.used_in_decision'
        )
    ),
    claim_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    predicate TEXT NOT NULL,
    claim_value JSONB,
    confidence_millis INTEGER NOT NULL CHECK (
        confidence_millis >= 0 AND confidence_millis <= 1000
    ),
    authority JSONB NOT NULL DEFAULT '{}'::jsonb,
    ttl JSONB NOT NULL DEFAULT '{"kind":"never"}'::jsonb,
    provenance JSONB NOT NULL,
    evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
    links JSONB NOT NULL DEFAULT '{}'::jsonb,
    observed_at TIMESTAMPTZ,
    valid_from TIMESTAMPTZ,
    -- Appender-supplied, never DB-generated: recorded_at is part of the hashed
    -- provenance, so a wall-clock default would make the event hash unreproducible.
    recorded_at TIMESTAMPTZ NOT NULL,
    causation_event_id TEXT,
    correlation_id TEXT,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (event_type <> 'claim.asserted' OR claim_value IS NOT NULL),
    CHECK (event_type <> 'claim.asserted' OR jsonb_array_length(evidence) > 0)
);

CREATE INDEX IF NOT EXISTS dent8_claim_events_claim_seq_idx
    ON dent8_claim_events (claim_id, global_sequence);

CREATE INDEX IF NOT EXISTS dent8_claim_events_subject_predicate_idx
    ON dent8_claim_events (subject_type, subject_key, predicate, global_sequence);

CREATE INDEX IF NOT EXISTS dent8_claim_events_type_recorded_idx
    ON dent8_claim_events (event_type, recorded_at);

CREATE INDEX IF NOT EXISTS dent8_claim_events_correlation_idx
    ON dent8_claim_events (correlation_id)
    WHERE correlation_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS dent8_claim_events_payload_gin_idx
    ON dent8_claim_events USING GIN (payload);

CREATE INDEX IF NOT EXISTS dent8_claim_events_provenance_gin_idx
    ON dent8_claim_events USING GIN (provenance);

CREATE TABLE IF NOT EXISTS dent8_claim_projections (
    claim_id TEXT PRIMARY KEY,
    lifecycle_state TEXT NOT NULL CHECK (
        lifecycle_state IN (
            'active',
            'contested',
            'superseded',
            'expired',
            'retracted'
        )
    ),
    subject_type TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    predicate TEXT NOT NULL,
    claim_value JSONB NOT NULL,
    confidence_millis INTEGER NOT NULL CHECK (
        confidence_millis >= 0 AND confidence_millis <= 1000
    ),
    authority JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ,
    superseded_by_claim_id TEXT,
    contradicted_by_claim_ids TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_event_id TEXT NOT NULL,
    last_event_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (created_event_id) REFERENCES dent8_claim_events(event_id),
    FOREIGN KEY (last_event_id) REFERENCES dent8_claim_events(event_id)
);

CREATE INDEX IF NOT EXISTS dent8_claim_projections_lookup_idx
    ON dent8_claim_projections (subject_type, subject_key, predicate);

CREATE INDEX IF NOT EXISTS dent8_claim_projections_lifecycle_idx
    ON dent8_claim_projections (lifecycle_state, updated_at);

CREATE TABLE IF NOT EXISTS dent8_claim_edges (
    from_claim_id TEXT NOT NULL,
    to_claim_id TEXT NOT NULL,
    edge_type TEXT NOT NULL CHECK (
        edge_type IN (
            'reinforces',
            'contradicts',
            'supersedes',
            'uses_as_evidence'
        )
    ),
    event_id TEXT NOT NULL REFERENCES dent8_claim_events(event_id),
    -- Derived from the originating event (its recorded_at), never DB-generated, so a
    -- deterministic replay rebuilds identical edges. Operational run metadata such as
    -- dent8_replay_runs.started_at may stay DB-generated; this edge data may not.
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (from_claim_id, to_claim_id, edge_type, event_id)
);

CREATE INDEX IF NOT EXISTS dent8_claim_edges_to_claim_idx
    ON dent8_claim_edges (to_claim_id, edge_type);

CREATE TABLE IF NOT EXISTS dent8_replay_runs (
    replay_id TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    event_range_start BIGINT,
    event_range_end BIGINT,
    invariant_status TEXT NOT NULL CHECK (
        invariant_status IN ('running', 'passed', 'failed')
    ),
    failure_count INTEGER NOT NULL DEFAULT 0,
    report JSONB NOT NULL DEFAULT '{}'::jsonb
);

