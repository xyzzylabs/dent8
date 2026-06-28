pub const INITIAL_SCHEMA_SQL: &str = include_str!("../../../migrations/postgres/001_initial.sql");

/// The v0 append-only event-log table the [`adapter`] writes/reads (migration 002).
pub const EVENT_LOG_SCHEMA_SQL: &str =
    include_str!("../../../migrations/postgres/002_event_log.sql");

/// The materialized projection + edge-graph tables the [`adapter`] maintains in the append
/// transaction (migration 003). Derived caches of the event log, not a source of truth.
pub const MATERIALIZATION_SCHEMA_SQL: &str =
    include_str!("../../../migrations/postgres/003_materialization.sql");

#[cfg(feature = "adapter")]
mod adapter;
#[cfg(feature = "adapter")]
pub use adapter::PostgresEventStore;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Migration {
    pub version: u32,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "initial_claim_event_log",
        sql: INITIAL_SCHEMA_SQL,
    },
    Migration {
        version: 2,
        name: "event_log",
        sql: EVENT_LOG_SCHEMA_SQL,
    },
    Migration {
        version: 3,
        name: "materialization",
        sql: MATERIALIZATION_SCHEMA_SQL,
    },
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostgresEventStoreConfig {
    pub schema: String,
    pub statement_timeout_ms: u64,
}

impl Default for PostgresEventStoreConfig {
    fn default() -> Self {
        Self {
            schema: "public".to_string(),
            statement_timeout_ms: 5_000,
        }
    }
}

#[must_use]
pub fn validate_identifier(identifier: &str) -> bool {
    let mut chars = identifier.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::{INITIAL_SCHEMA_SQL, validate_identifier};

    #[test]
    fn schema_names_claim_events_table() {
        assert!(INITIAL_SCHEMA_SQL.contains("dent8_claim_events"));
        assert!(INITIAL_SCHEMA_SQL.contains("claim.asserted"));
    }

    #[test]
    fn identifiers_follow_postgres_safe_subset() {
        assert!(validate_identifier("dent8"));
        assert!(validate_identifier("_dent8"));
        assert!(!validate_identifier(""));
        assert!(!validate_identifier("8dent"));
        assert!(!validate_identifier("dent8;drop"));
    }
}
