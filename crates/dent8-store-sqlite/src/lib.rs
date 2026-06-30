//! Embedded `SQLite` adapter for the dent8 event log — the second async backend, and the proof
//! that the storage boundary is backend-agnostic.
//!
//! It implements [`dent8_store::AsyncEventStore`] over a single append-only table, reusing the
//! *same* pure firewall decision as every other backend ([`dent8_store::arbitrate_events`]) and
//! the same canonical [`event_hash`]/[`hash_chain`]. Where it differs from the Postgres adapter
//! is only the **primitives**, exactly as a second backend should:
//! - storage is **embedded** (a file or `:memory:`, no server, bundled libsqlite3);
//! - writers **serialize via `BEGIN IMMEDIATE` + `busy_timeout`** (the write lock is taken up
//!   front, before the chain-head read), with WAL for reader concurrency — so concurrent writers
//!   *wait* rather than fail, and a residual busy past the timeout is surfaced as a retryable
//!   `Conflict` (the analogue of Postgres' advisory lock + optimistic-id retry);
//! - the canonical event is stored as **TEXT** (`event_json`), since `SQLite` has no `JSONB`.
//!
//! v0 is lean: the event log only. The believed projection is folded from the log on read (the
//! `projection == fold(log)` invariant), like the in-memory/file backend — the materialized
//! caches the Postgres adapter keeps (migration 003) are a possible later addition. The
//! per-event append *algorithm* (arbitrate → dedup → chain → insert) is structurally the same
//! as Postgres'; only the SQL dialect is `SQLite`-native (so Postgres assumptions cannot leak).

use std::str::FromStr;

use dent8_core::{ClaimEvent, ClaimEventKind, ClaimId, event_hash, hash_chain};
use dent8_store::{AppendReceipt, AsyncEventStore, EventFilter, StoreError, arbitrate_events};
use sqlx::SqliteConnection;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};

/// The v0 append-only event-log schema. Mirrors the Postgres `dent8_event_log` (migration 002)
/// minus the materialized caches: `event_json` is TEXT (no `JSONB`), `global_sequence` is the
/// `SQLite` rowid.
pub const SCHEMA_SQL: &str = "\
CREATE TABLE IF NOT EXISTS dent8_event_log (
    global_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    claim_id TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    subject_key TEXT NOT NULL,
    predicate TEXT NOT NULL,
    previous_event_hash TEXT,
    event_hash TEXT NOT NULL UNIQUE,
    event_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS dent8_event_log_claim_seq_idx
    ON dent8_event_log (claim_id, global_sequence);
CREATE INDEX IF NOT EXISTS dent8_event_log_subject_idx
    ON dent8_event_log (subject_type, subject_key, predicate, global_sequence);
";

/// A v0 `SQLite`-backed event store. The pool is capped at **one connection**: that serializes
/// writers *within* a process (cross-process serialization is `BEGIN IMMEDIATE` + `busy_timeout`
/// in [`Self::append_many`]), and keeps an in-`:memory:` database alive for the pool's lifetime.
#[derive(Clone, Debug)]
pub struct SqliteEventStore {
    pool: SqlitePool,
}

impl SqliteEventStore {
    /// Connect at `url`, creating the database file if it does not exist. Examples:
    /// `sqlite://dent8.db` (a *file* in the cwd), `sqlite:///abs/path/dent8.db` (an absolute
    /// path), or `sqlite::memory:` (a transient in-memory DB that lives only for this store's
    /// pool — fine for tests, but each CLI invocation opens a fresh pool, so use a file path for
    /// persistence).
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::from_str(url)
            .map_err(|error| StoreError::Unavailable(error.to_string()))?
            .create_if_missing(true)
            // WAL lets readers run concurrently with the single writer; `busy_timeout` makes a
            // contending `BEGIN IMMEDIATE` *wait* for the write lock rather than fail at once.
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(unavailable)?;
        Ok(Self { pool })
    }

    /// Wrap an existing pool. For the in-process write serialization in [`Self::append_many`] to
    /// hold, the pool should be **single-connection** (as [`Self::connect`] configures); the
    /// cross-process serialization (`BEGIN IMMEDIATE` + `busy_timeout`) holds regardless.
    #[must_use]
    pub fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Create the event-log table + indexes if they do not exist (idempotent).
    pub async fn migrate(&self) -> Result<(), StoreError> {
        sqlx::raw_sql(SCHEMA_SQL)
            .execute(&self.pool)
            .await
            .map_err(unavailable)?;
        Ok(())
    }

    /// Append one candidate through the firewall (a one-event [`Self::append_many`]).
    pub async fn append(&self, event: ClaimEvent) -> Result<AppendReceipt, StoreError> {
        let mut receipts = self.append_many(vec![event]).await?;
        Ok(receipts.pop().expect("one event -> one receipt"))
    }

    /// Append a whole operation as **one transaction** — every event arbitrates, chains, and
    /// inserts, or none do. Uses `BEGIN IMMEDIATE` so the write lock is taken **before** the
    /// chain-head read: a concurrent writer then *waits* on `busy_timeout` and serializes (like
    /// the Postgres advisory lock), instead of failing a deferred read→write upgrade with an
    /// immediate `SQLITE_BUSY`. A residual busy (lock held past the timeout) surfaces as a
    /// retryable [`StoreError::Conflict`] so the CLI's write-retry loop re-runs it.
    pub async fn append_many(
        &self,
        events: Vec<ClaimEvent>,
    ) -> Result<Vec<AppendReceipt>, StoreError> {
        let mut conn = self.pool.acquire().await.map_err(map_busy)?;
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *conn)
            .await
            .map_err(map_busy)?;
        let mut receipts = Vec::with_capacity(events.len());
        for event in &events {
            match append_event_in_tx(&mut conn, event).await {
                Ok(receipt) => receipts.push(receipt),
                Err(error) => {
                    // Roll back the partial operation; ignore a rollback error (the connection is
                    // discarded/reset on return to the pool anyway).
                    let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                    return Err(error);
                }
            }
        }
        sqlx::query("COMMIT")
            .execute(&mut *conn)
            .await
            .map_err(map_busy)?;
        Ok(receipts)
    }

    /// Ordered events for one claim stream.
    pub async fn load_claim_events(
        &self,
        claim_id: &ClaimId,
    ) -> Result<Vec<ClaimEvent>, StoreError> {
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT event_json FROM dent8_event_log WHERE claim_id = ?1 ORDER BY global_sequence",
        )
        .bind(claim_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        rows.iter().map(|json| event_from_json(json)).collect()
    }

    /// Events matching a filter, in global order.
    pub async fn scan_events(&self, filter: &EventFilter) -> Result<Vec<ClaimEvent>, StoreError> {
        let claim_id = filter.claim_id.as_ref().map(ClaimId::as_str);
        let subject_type = filter.subject.as_ref().map(dent8_core::EntityRef::kind);
        let subject_key = filter.subject.as_ref().map(dent8_core::EntityRef::key);
        let predicate = filter.predicate.as_ref().map(dent8_core::Predicate::as_str);
        let after = filter
            .after_sequence
            .map(|seq| i64::try_from(seq).unwrap_or(i64::MAX));
        let limit = filter.limit.map_or(i64::MAX, i64::from);

        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT event_json FROM dent8_event_log \
             WHERE (?1 IS NULL OR claim_id = ?1) \
               AND (?2 IS NULL OR subject_type = ?2) \
               AND (?3 IS NULL OR subject_key = ?3) \
               AND (?4 IS NULL OR predicate = ?4) \
               AND (?5 IS NULL OR global_sequence > ?5) \
             ORDER BY global_sequence LIMIT ?6",
        )
        .bind(claim_id)
        .bind(subject_type)
        .bind(subject_key)
        .bind(predicate)
        .bind(after)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        rows.iter().map(|json| event_from_json(json)).collect()
    }

    /// Re-verify the stored global hash chain by re-folding it from `event_json` and comparing
    /// each recomputed `event_hash` to the stored one — `false` if a stored event was altered.
    pub async fn verify_chain(&self) -> Result<bool, StoreError> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT event_json, event_hash FROM dent8_event_log ORDER BY global_sequence",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        let mut events = Vec::with_capacity(rows.len());
        let mut stored = Vec::with_capacity(rows.len());
        for (json, hash) in &rows {
            events.push(event_from_json(json)?);
            stored.push(hash.clone());
        }
        let recomputed =
            hash_chain(&events).map_err(|error| StoreError::Canonicalization(error.to_string()))?;
        Ok(recomputed == stored)
    }
}

/// One event, firewalled + chained + inserted inside the caller's transaction. The same
/// algorithm as the Postgres adapter (arbitrate FIRST so an inadmissible-and-duplicate event
/// fails with the firewall's error, not `Conflict`), with `SQLite`-native primitives.
async fn append_event_in_tx(
    conn: &mut SqliteConnection,
    event: &ClaimEvent,
) -> Result<AppendReceipt, StoreError> {
    let existing = load_claim_in_tx(&mut *conn, event.claim_id.as_str()).await?;
    let replacing = match &event.kind {
        ClaimEventKind::Superseded { by, .. } => {
            Some(load_claim_in_tx(&mut *conn, by.as_str()).await?)
        }
        _ => None,
    };
    arbitrate_events(event, &existing, replacing.as_deref())?;

    let duplicate: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM dent8_event_log WHERE event_id = ?1")
            .bind(event.event_id.as_str())
            .fetch_optional(&mut *conn)
            .await
            .map_err(map_busy)?;
    if duplicate.is_some() {
        return Err(StoreError::Conflict(format!(
            "duplicate event_id {}",
            event.event_id
        )));
    }

    // Chain to the current global head (NULL for the first event, or the previous event of this
    // same transaction, since its INSERT is visible here). The `BEGIN IMMEDIATE` write lock is
    // already held, so no other writer can move the head between this read and the INSERT.
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT event_hash FROM dent8_event_log ORDER BY global_sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(map_busy)?;
    let hash = event_hash(event, previous.as_deref())
        .map_err(|error| StoreError::Canonicalization(error.to_string()))?;
    let event_json = serde_json::to_string(event)
        .map_err(|error| StoreError::Canonicalization(error.to_string()))?;

    let global_sequence: i64 = sqlx::query_scalar(
        "INSERT INTO dent8_event_log \
         (event_id, claim_id, subject_type, subject_key, predicate, previous_event_hash, event_hash, event_json) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING global_sequence",
    )
    .bind(event.event_id.as_str())
    .bind(event.claim_id.as_str())
    .bind(event.subject.kind())
    .bind(event.subject.key())
    .bind(event.predicate.as_str())
    .bind(previous.as_deref())
    .bind(hash.as_str())
    .bind(event_json)
    .fetch_one(&mut *conn)
    .await
    .map_err(map_busy)?;

    let global_sequence = u64::try_from(global_sequence).map_err(|_| {
        StoreError::CorruptEvent(format!("non-positive global_sequence {global_sequence}"))
    })?;
    Ok(AppendReceipt {
        global_sequence,
        event_id: event.event_id.clone(),
        event_hash: hash,
    })
}

async fn load_claim_in_tx(
    conn: &mut SqliteConnection,
    claim_id: &str,
) -> Result<Vec<ClaimEvent>, StoreError> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT event_json FROM dent8_event_log WHERE claim_id = ?1 ORDER BY global_sequence",
    )
    .bind(claim_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(map_busy)?;
    rows.iter().map(|json| event_from_json(json)).collect()
}

fn event_from_json(value: &str) -> Result<ClaimEvent, StoreError> {
    serde_json::from_str(value).map_err(|error| StoreError::CorruptEvent(error.to_string()))
}

// By value so it composes with `.map_err(unavailable)`; only borrowed in the body.
#[allow(clippy::needless_pass_by_value)]
fn unavailable(error: sqlx::Error) -> StoreError {
    StoreError::Unavailable(error.to_string())
}

/// Like [`unavailable`], but classifies `SQLite`'s `SQLITE_BUSY` ("database is locked") as a
/// **retryable** [`StoreError::Conflict`] — so the CLI's `with_write_retry` re-runs a write that
/// lost the write lock past `busy_timeout` (the `SQLite` analogue of the Postgres optimistic-id
/// race), instead of failing it as a terminal `Unavailable`. Used on the write path.
#[allow(clippy::needless_pass_by_value)]
fn map_busy(error: sqlx::Error) -> StoreError {
    if let sqlx::Error::Database(db) = &error {
        let code = db.code();
        // SQLITE_BUSY = 5; SQLITE_BUSY_SNAPSHOT = 517. Fall back to the message for safety.
        if matches!(code.as_deref(), Some("5" | "517"))
            || db.message().contains("database is locked")
        {
            return StoreError::Conflict(format!("sqlite write contention (retryable): {error}"));
        }
    }
    StoreError::Unavailable(error.to_string())
}

#[async_trait::async_trait(?Send)]
impl AsyncEventStore for SqliteEventStore {
    async fn migrate(&self) -> Result<(), StoreError> {
        self.migrate().await
    }

    async fn append(&self, event: ClaimEvent) -> Result<AppendReceipt, StoreError> {
        self.append(event).await
    }

    async fn append_many(&self, events: Vec<ClaimEvent>) -> Result<Vec<AppendReceipt>, StoreError> {
        self.append_many(events).await
    }

    async fn load_claim_events(&self, claim_id: &ClaimId) -> Result<Vec<ClaimEvent>, StoreError> {
        self.load_claim_events(claim_id).await
    }

    async fn scan_events(&self, filter: &EventFilter) -> Result<Vec<ClaimEvent>, StoreError> {
        self.scan_events(filter).await
    }

    async fn verify_chain(&self) -> Result<bool, StoreError> {
        self.verify_chain().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, ClaimEventId, ClaimValue, Confidence, EntityRef,
        Evidence, EvidenceId, EvidenceKind, Predicate, Provenance, SourceId, SupersessionReason,
        TimestampMillis, Ttl,
    };

    fn asserted(event_id: &str, claim: &str, value: &str, authority: AuthorityLevel) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).unwrap(),
            claim_id: ClaimId::new(claim).unwrap(),
            kind: ClaimEventKind::Asserted,
            subject: EntityRef::new("repo", "dent8").unwrap(),
            predicate: Predicate::new("database").unwrap(),
            value: Some(ClaimValue::Text(value.to_string())),
            confidence: Confidence::from_millis(900).unwrap(),
            authority: Authority {
                level: authority,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:owner").unwrap(),
                actor: ActorId::new("actor:test").unwrap(),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(1),
            },
            evidence: vec![Evidence {
                id: EvidenceId::new("evidence:1").unwrap(),
                kind: EvidenceKind::UserStatement,
                locator: "x".to_string(),
                digest: None,
                summary: None,
            }],
            observed_at: None,
            valid_from: None,
        }
    }

    #[tokio::test]
    async fn append_scan_and_chain_round_trip_in_memory() {
        let store = SqliteEventStore::connect("sqlite::memory:").await.unwrap();
        store.migrate().await.unwrap();

        let receipt = store
            .append(asserted(
                "event:0",
                "claim:a",
                "postgres",
                AuthorityLevel::High,
            ))
            .await
            .unwrap();
        assert_eq!(receipt.global_sequence, 1);

        let scanned = store.scan_events(&EventFilter::default()).await.unwrap();
        assert_eq!(scanned.len(), 1);
        assert_eq!(scanned[0].event_id.as_str(), "event:0");

        assert!(store.verify_chain().await.unwrap(), "fresh chain verifies");
    }

    #[tokio::test]
    async fn the_firewall_rejects_a_low_authority_supersession() {
        let store = SqliteEventStore::connect("sqlite::memory:").await.unwrap();
        store.migrate().await.unwrap();
        store
            .append(asserted(
                "event:0",
                "claim:a",
                "postgres",
                AuthorityLevel::High,
            ))
            .await
            .unwrap();
        // A low-authority replacement asserted, then a supersession of the High incumbent by it.
        store
            .append(asserted("event:1", "claim:b", "mysql", AuthorityLevel::Low))
            .await
            .unwrap();
        let supersede = ClaimEvent {
            kind: ClaimEventKind::Superseded {
                by: ClaimId::new("claim:b").unwrap(),
                reason: SupersessionReason::UserCorrection,
            },
            value: None,
            ..asserted("event:2", "claim:a", "ignored", AuthorityLevel::Low)
        };
        let result = store.append(supersede).await;
        assert!(
            matches!(result, Err(StoreError::Rejected(_))),
            "a low-authority supersession of a High fact must be rejected: {result:?}"
        );
    }
}
