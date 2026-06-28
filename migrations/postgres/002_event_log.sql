-- dent8 Postgres schema, migration 002: the v0 append-only event log.
--
-- This is the table the v0 `PostgresEventStore` adapter writes and reads. It stores the
-- *canonical event* as a single JSONB document (`event_json`) — the same bytes the hash
-- chain commits to — plus the scalar columns needed to index and arbitrate appends. The
-- believed projection is derived by folding the log on read (the `projection == fold(log)`
-- invariant), exactly as the in-memory backend does; the richer per-column event table and
-- the materialized projection/edge tables in migration 001 are the inspection /
-- materialization target a later adapter version populates, not a separate source of truth.
--
-- Appends are serialized by a transaction-scoped advisory lock so the global hash chain
-- (each event_hash links to the previous event across the whole log, by global_sequence)
-- stays consistent without a per-claim race.

CREATE TABLE IF NOT EXISTS dent8_event_log (
    global_sequence BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    claim_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    predicate TEXT NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    -- The canonical claim event. Source of truth for replay; the scalar columns above are
    -- derived from it for indexing and must never disagree with it.
    event_json JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS dent8_event_log_claim_seq_idx
    ON dent8_event_log (claim_id, global_sequence);

CREATE INDEX IF NOT EXISTS dent8_event_log_subject_idx
    ON dent8_event_log (subject_type, subject_key, predicate, global_sequence);
