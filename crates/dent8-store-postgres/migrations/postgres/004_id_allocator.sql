-- dent8 Postgres schema, migration 004: event-id allocator.
--
-- `global_sequence` remains the durable append order. This allocator only reserves the
-- numeric suffix for user-visible CLI/MCP event identifiers (`event:{n}`) before the CLI
-- signs the final event payload. Reservations are unique, but not gap-free: a later rejected
-- write leaves its reserved suffix unused.

CREATE TABLE IF NOT EXISTS dent8_id_allocator (
    name TEXT PRIMARY KEY,
    next_value BIGINT NOT NULL CHECK (next_value >= 0)
);

INSERT INTO dent8_id_allocator (name, next_value)
VALUES ('event', 0)
ON CONFLICT (name) DO NOTHING;

UPDATE dent8_id_allocator
   SET next_value = GREATEST(
       next_value,
       COALESCE((
           SELECT MAX(substring(event_id FROM 7)::BIGINT) + 1
             FROM dent8_event_log
            WHERE event_id ~ '^event:[0-9]+$'
       ), 0)
   )
 WHERE name = 'event';
