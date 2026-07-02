//! v0 async Postgres adapter for the dent8 event log.
//!
//! **Status: verified against a live Postgres (`postgres:16`).** The `DATABASE_URL`-gated
//! tests at the bottom pass — firewall (incl. laundered-supersession rejection) + global
//! chain, the materialized projection/edge graph, and `projection == fold(log)` — run via
//! `DATABASE_URL=… cargo test -p dent8-store-postgres --features adapter` (the tests
//! self-serialize and retry the initial connection, so no special flags are needed). It also
//! reuses the *same* pure firewall decision as the in-memory backend
//! ([`dent8_store::arbitrate_events`], exhaustively tested) and stores the canonical event
//! as one JSONB document. Still v0: a single-table JSONB event log + derived caches, not a
//! per-column materialization (a possible later design).
//!
//! Design choices (see [`storage.md`](../../../docs/storage.md)):
//! - **Async boundary:** the adapter exposes inherent `async fn`s (it cannot implement the
//!   *synchronous* `EventStore` trait) and also implements the shared
//!   [`dent8_store::AsyncEventStore`] trait, so the CLI can hold it as a
//!   `Box<dyn AsyncEventStore>` alongside other async backends.
//! - **Global hash chain:** each `event_hash` links to the previous event across the whole
//!   log; appends are serialized by a transaction-scoped advisory lock so the chain has one
//!   consistent head with no per-claim race.
//! - **Materialized projection + edges:** on every accepted append the folded `ClaimState`
//!   is upserted into `dent8_claim_projection` and the claim->claim relationship into
//!   `dent8_claim_edge`, inside the same transaction (migration 003). These are derived
//!   caches — the log stays the source of truth, and `verify_projection` checks the
//!   `projection == fold(log)` invariant. `load_claim_events`/`scan_events` still fold from
//!   the log; `materialized_projection` reads the cache without re-folding.

use dent8_core::{
    ClaimEvent, ClaimEventKind, ClaimId, ClaimLifecycle, ClaimState, apply_event, event_hash,
    hash_chain,
};
use dent8_store::{AppendReceipt, AsyncEventStore, EventFilter, StoreError, arbitrate_events};
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

/// Transaction-scoped advisory-lock key that serializes appends (so the global chain head
/// is read-modify-written atomically). The value is arbitrary but fixed across writers.
const APPEND_LOCK_KEY: i64 = 0x0064_656e_7438_0001;

/// Transaction-scoped advisory-lock key that serializes schema migrations. `CREATE TABLE IF
/// NOT EXISTS` is not race-safe against concurrent creation (it can still collide on the
/// `pg_class`/`pg_type` catalog), so concurrent `migrate()` calls — e.g. several app
/// instances starting at once — must be serialized.
const MIGRATE_LOCK_KEY: i64 = 0x0064_656e_7438_0002;

/// A v0 Postgres-backed event store over the `dent8_event_log` table (migration 002).
#[derive(Clone, Debug)]
pub struct PostgresEventStore {
    pool: PgPool,
}

impl PostgresEventStore {
    /// Connect to Postgres at `url` (a standard `postgres://…` connection string). Bounds
    /// the acquire timeout so an unreachable database fails in seconds, not the 30s default.
    pub async fn connect(url: &str) -> Result<Self, StoreError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(5))
            .connect(url)
            .await
            .map_err(unavailable)?;
        Ok(Self { pool })
    }

    /// Wrap an existing pool (e.g. one shared with the rest of an application).
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Create the event-log table and the materialized projection/edge tables if they do
    /// not exist (idempotent). Concurrency-safe: the DDL runs in one transaction under an
    /// advisory lock, so simultaneous migrations serialize instead of racing on the catalog.
    pub async fn migrate(&self) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(MIGRATE_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::raw_sql(crate::EVENT_LOG_SCHEMA_SQL)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::raw_sql(crate::MATERIALIZATION_SCHEMA_SQL)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(())
    }

    /// Append a candidate event **through the firewall**, transactionally (a one-event
    /// [`Self::append_many`]). Arbitrates against current state (rejecting an inadmissible or
    /// laundered write), chains the `event_hash` to the global head, and persists — all under
    /// one advisory-lock-serialized transaction so the chain stays consistent and the append
    /// is atomic.
    pub async fn append(&self, event: ClaimEvent) -> Result<AppendReceipt, StoreError> {
        let mut receipts = self.append_many(vec![event]).await?;
        Ok(receipts.pop().expect("one event -> one receipt"))
    }

    /// Append several events as **one transaction** — the durable form of a multi-event
    /// operation (supersede / retract / contradict): the replacement plus its
    /// supersessions/retractions/contradiction commit together or not at all. Each event is
    /// firewalled, chained, and materialized in order under a single advisory-lock-serialized
    /// transaction, and later events see the earlier ones' in-transaction writes (so a
    /// supersession resolves the replacement claim asserted just before it).
    ///
    /// Trust boundary: the base claim-stream firewall (authority arbitration,
    /// anti-laundering, canonical hard alarms, terminal-state rules) runs here. The
    /// source→authority *ceiling* (`dent8 authority`) and predicate registry policy
    /// (authority floors, default TTLs, uniqueness) are enforced one layer up, at the CLI/MCP
    /// `op_*` write path — a process calling this adapter directly is responsible for those
    /// product-policy checks itself.
    pub async fn append_many(
        &self,
        events: Vec<ClaimEvent>,
    ) -> Result<Vec<AppendReceipt>, StoreError> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // One advisory lock for the whole batch: the global chain head is read-modify-written
        // atomically across every event in the operation.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(APPEND_LOCK_KEY)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        let mut receipts = Vec::with_capacity(events.len());
        for event in &events {
            receipts.push(append_event_in_tx(&mut tx, event).await?);
        }
        tx.commit().await.map_err(unavailable)?;
        Ok(receipts)
    }

    /// Ordered events for one claim stream.
    pub async fn load_claim_events(
        &self,
        claim_id: &ClaimId,
    ) -> Result<Vec<ClaimEvent>, StoreError> {
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT event_json FROM dent8_event_log WHERE claim_id = $1 ORDER BY global_sequence",
        )
        .bind(claim_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        rows.into_iter().map(event_from_json).collect()
    }

    /// Ordered events matching a filter (by claim / subject+predicate / sequence).
    pub async fn scan_events(&self, filter: &EventFilter) -> Result<Vec<ClaimEvent>, StoreError> {
        let claim_id = filter.claim_id.as_ref().map(ClaimId::as_str);
        let subject_type = filter.subject.as_ref().map(dent8_core::EntityRef::kind);
        let subject_key = filter.subject.as_ref().map(dent8_core::EntityRef::key);
        let predicate = filter.predicate.as_ref().map(dent8_core::Predicate::as_str);
        let after = filter
            .after_sequence
            .map(|seq| i64::try_from(seq).unwrap_or(i64::MAX));
        let limit = filter.limit.map_or(i64::MAX, i64::from);

        let rows: Vec<serde_json::Value> = sqlx::query_scalar(
            "SELECT event_json FROM dent8_event_log \
             WHERE ($1::text IS NULL OR claim_id = $1) \
               AND ($2::text IS NULL OR subject_type = $2) \
               AND ($3::text IS NULL OR subject_key = $3) \
               AND ($4::text IS NULL OR predicate = $4) \
               AND ($5::bigint IS NULL OR global_sequence > $5) \
             ORDER BY global_sequence LIMIT $6",
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
        rows.into_iter().map(event_from_json).collect()
    }

    #[cfg(test)]
    fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Recompute the global hash chain over the whole log and confirm it matches the stored
    /// hashes (internal consistency, as in the in-memory backend). For tamper-*resistance*
    /// against a re-hashing writer, pair this with an external anchor (`dent8_core::anchor`).
    pub async fn verify_chain(&self) -> Result<bool, StoreError> {
        let rows: Vec<(serde_json::Value, String)> = sqlx::query_as(
            "SELECT event_json, event_hash FROM dent8_event_log ORDER BY global_sequence",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        let mut events = Vec::with_capacity(rows.len());
        let mut stored = Vec::with_capacity(rows.len());
        for (json, hash) in rows {
            events.push(event_from_json(json)?);
            stored.push(hash);
        }
        let recomputed =
            hash_chain(&events).map_err(|error| StoreError::Canonicalization(error.to_string()))?;
        Ok(recomputed == stored)
    }

    /// Read the **materialized** projection for a claim without re-folding the log (`None`
    /// if the claim has no events). The exact `ClaimState` is reconstructed from the cached
    /// `state_json`.
    pub async fn materialized_projection(
        &self,
        claim_id: &ClaimId,
    ) -> Result<Option<ClaimState>, StoreError> {
        let row: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT state_json FROM dent8_claim_projection WHERE claim_id = $1")
                .bind(claim_id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(unavailable)?;
        row.map(|json| {
            serde_json::from_value(json)
                .map_err(|error| StoreError::CorruptEvent(error.to_string()))
        })
        .transpose()
    }

    /// The outgoing relationship edges recorded *from* a claim (its supersession /
    /// contradiction / reinforcement links), ordered by the originating event.
    pub async fn edges_from(&self, claim_id: &ClaimId) -> Result<Vec<ClaimEdge>, StoreError> {
        let rows: Vec<(String, String, String, String, i64)> = sqlx::query_as(
            "SELECT from_claim_id, to_claim_id, edge_type, event_id, recorded_at \
             FROM dent8_claim_edge WHERE from_claim_id = $1 ORDER BY recorded_at, event_id",
        )
        .bind(claim_id.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        Ok(rows
            .into_iter()
            .map(
                |(from_claim_id, to_claim_id, edge_type, event_id, recorded_at)| ClaimEdge {
                    from_claim_id,
                    to_claim_id,
                    edge_type,
                    event_id,
                    recorded_at,
                },
            )
            .collect())
    }

    /// Confirm the materialized projection equals an independent fold of the claim's log —
    /// the `projection == fold(log)` invariant. The materialization is a derived cache, so
    /// this must always hold for an untampered store.
    pub async fn verify_projection(&self, claim_id: &ClaimId) -> Result<bool, StoreError> {
        let folded = fold_state(&self.load_claim_events(claim_id).await?)?;
        let materialized = self.materialized_projection(claim_id).await?;
        Ok(folded == materialized)
    }
}

/// The backend-agnostic [`AsyncEventStore`] view: each method delegates to the inherent one
/// of the same name (inherent methods win method resolution, so this is delegation, not
/// recursion). This is what lets the CLI hold a `Box<dyn AsyncEventStore>` and treat Postgres
/// like any other async backend. `connect`/`from_pool` and the materialization helpers stay
/// inherent — construction and the Postgres-specific projection cache are not part of the
/// portable contract.
#[async_trait::async_trait(?Send)]
impl AsyncEventStore for PostgresEventStore {
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

/// A claim->claim relationship edge (see migration 003 for direction semantics).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimEdge {
    pub from_claim_id: String,
    pub to_claim_id: String,
    pub edge_type: String,
    pub event_id: String,
    pub recorded_at: i64,
}

/// Fold an ordered claim stream into its current state via the shared `apply_event` (the
/// same projection the in-memory backend computes). A persisted log is already admitted, so
/// a fold failure means corruption.
fn fold_state(events: &[ClaimEvent]) -> Result<Option<ClaimState>, StoreError> {
    let mut state: Option<ClaimState> = None;
    for event in events {
        state = Some(
            apply_event(state, event)
                .map_err(|error| StoreError::CorruptEvent(error.to_string()))?,
        );
    }
    Ok(state)
}

/// Lifecycle as the lowercase tag the `dent8_claim_projection.lifecycle` CHECK expects.
fn lifecycle_tag(lifecycle: ClaimLifecycle) -> &'static str {
    match lifecycle {
        ClaimLifecycle::Active => "active",
        ClaimLifecycle::Contested => "contested",
        ClaimLifecycle::Superseded => "superseded",
        ClaimLifecycle::Expired => "expired",
        ClaimLifecycle::Retracted => "retracted",
    }
}

/// Upsert the folded `state` into the materialized projection cache.
async fn upsert_projection(
    tx: &mut Transaction<'_, Postgres>,
    state: &ClaimState,
) -> Result<(), StoreError> {
    let contradicted_by: Vec<String> = state
        .contradicted_by
        .iter()
        .map(|claim| claim.as_str().to_string())
        .collect();
    let state_json = serde_json::to_value(state)
        .map_err(|error| StoreError::Canonicalization(error.to_string()))?;
    let conn: &mut PgConnection = tx;
    sqlx::query(
        "INSERT INTO dent8_claim_projection \
         (claim_id, subject_type, subject_key, predicate, lifecycle, superseded_by, \
          contradicted_by, corroboration, created_at, updated_at, last_event_id, state_json) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
         ON CONFLICT (claim_id) DO UPDATE SET \
           lifecycle = EXCLUDED.lifecycle, \
           superseded_by = EXCLUDED.superseded_by, \
           contradicted_by = EXCLUDED.contradicted_by, \
           corroboration = EXCLUDED.corroboration, \
           updated_at = EXCLUDED.updated_at, \
           last_event_id = EXCLUDED.last_event_id, \
           state_json = EXCLUDED.state_json",
    )
    .bind(state.claim_id.as_str())
    .bind(state.subject.kind())
    .bind(state.subject.key())
    .bind(state.predicate.as_str())
    .bind(lifecycle_tag(state.lifecycle))
    .bind(state.superseded_by.as_ref().map(ClaimId::as_str))
    .bind(&contradicted_by)
    .bind(i64::try_from(state.corroboration()).unwrap_or(i64::MAX))
    .bind(state.created_at.as_unix_millis())
    .bind(state.updated_at.as_unix_millis())
    .bind(state.last_event_id.as_str())
    .bind(&state_json)
    .execute(&mut *conn)
    .await
    .map_err(unavailable)?;
    Ok(())
}

/// Record the claim->claim edge an event implies, if any (idempotent).
async fn insert_edge(
    tx: &mut Transaction<'_, Postgres>,
    event: &ClaimEvent,
) -> Result<(), StoreError> {
    let edge = match &event.kind {
        ClaimEventKind::Reinforced { by } => Some(("reinforces", by.as_str())),
        ClaimEventKind::Contradicted { by, .. } => Some(("contradicts", by.as_str())),
        ClaimEventKind::Superseded { by, .. } => Some(("supersedes", by.as_str())),
        _ => None,
    };
    let Some((edge_type, to_claim)) = edge else {
        return Ok(());
    };
    let conn: &mut PgConnection = tx;
    sqlx::query(
        "INSERT INTO dent8_claim_edge (from_claim_id, to_claim_id, edge_type, event_id, recorded_at) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
    )
    .bind(event.claim_id.as_str())
    .bind(to_claim)
    .bind(edge_type)
    .bind(event.event_id.as_str())
    .bind(event.provenance.recorded_at.as_unix_millis())
    .execute(&mut *conn)
    .await
    .map_err(unavailable)?;
    Ok(())
}

/// Load one claim stream inside an in-flight transaction (for the firewall's read).
/// Firewall + chain + persist + materialize **one** event inside an in-flight transaction
/// (no begin/commit/lock of its own — the caller holds them, so a batch commits atomically).
async fn append_event_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    event: &ClaimEvent,
) -> Result<AppendReceipt, StoreError> {
    // The firewall: the SAME pure decision the in-memory backend uses — run FIRST so a
    // candidate that is both inadmissible and a duplicate fails with the firewall's error
    // (matching the in-memory backend's arbitrate-before-dedup precedence), not Conflict.
    let existing = load_claim_in_tx(&mut *tx, event.claim_id.as_str()).await?;
    let replacing = match &event.kind {
        ClaimEventKind::Superseded { by, .. } => {
            Some(load_claim_in_tx(&mut *tx, by.as_str()).await?)
        }
        _ => None,
    };
    arbitrate_events(event, &existing, replacing.as_deref())?;

    // Idempotency / tamper signal: a duplicate event_id is a conflict (the UNIQUE constraint
    // is the backstop if a race ever slipped past the advisory lock).
    let duplicate = sqlx::query("SELECT 1 FROM dent8_event_log WHERE event_id = $1")
        .bind(event.event_id.as_str())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
    if duplicate.is_some() {
        return Err(StoreError::Conflict(format!(
            "duplicate event_id {}",
            event.event_id
        )));
    }

    // Chain to the current global head (NULL for the first event — or the previous event of
    // this same transaction, since its INSERT is visible here).
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT event_hash FROM dent8_event_log ORDER BY global_sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .flatten();
    let hash = event_hash(event, previous.as_deref())
        .map_err(|error| StoreError::Canonicalization(error.to_string()))?;
    let event_json = serde_json::to_value(event)
        .map_err(|error| StoreError::Canonicalization(error.to_string()))?;

    let global_sequence: i64 = sqlx::query_scalar(
        "INSERT INTO dent8_event_log \
         (event_id, claim_id, subject_type, subject_key, predicate, previous_event_hash, event_hash, event_json) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING global_sequence",
    )
    .bind(event.event_id.as_str())
    .bind(event.claim_id.as_str())
    .bind(event.subject.kind())
    .bind(event.subject.key())
    .bind(event.predicate.as_str())
    .bind(previous.as_deref())
    .bind(hash.as_str())
    .bind(&event_json)
    .fetch_one(&mut **tx)
    .await
    .map_err(unavailable)?;

    // Materialize the derived caches in the same transaction.
    let current = fold_state(&existing)?;
    let state =
        apply_event(current, event).map_err(|error| StoreError::CorruptEvent(error.to_string()))?;
    upsert_projection(&mut *tx, &state).await?;
    insert_edge(&mut *tx, event).await?;

    // `global_sequence` is a positive BIGINT IDENTITY; a non-positive value would be corrupt,
    // so fail loudly rather than emit a phantom seq 0.
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
    tx: &mut Transaction<'_, Postgres>,
    claim_id: &str,
) -> Result<Vec<ClaimEvent>, StoreError> {
    let conn: &mut PgConnection = tx;
    let rows: Vec<serde_json::Value> = sqlx::query_scalar(
        "SELECT event_json FROM dent8_event_log WHERE claim_id = $1 ORDER BY global_sequence",
    )
    .bind(claim_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(unavailable)?;
    rows.into_iter().map(event_from_json).collect()
}

fn event_from_json(value: serde_json::Value) -> Result<ClaimEvent, StoreError> {
    serde_json::from_value(value).map_err(|error| StoreError::CorruptEvent(error.to_string()))
}

// By-value so it can be used directly as `map_err(unavailable)`, which hands over an owned
// `sqlx::Error`.
#[allow(clippy::needless_pass_by_value)]
fn unavailable(error: sqlx::Error) -> StoreError {
    StoreError::Unavailable(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::PostgresEventStore;
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
        ClaimLifecycle, ClaimValue, Confidence, EntityRef, Evidence, EvidenceId, EvidenceKind,
        Predicate, Provenance, SourceId, SupersessionReason, TimestampMillis, Ttl,
    };
    use dent8_store::StoreError;

    // These tests run only when DATABASE_URL is set (a throwaway Postgres). They are the
    // live verification of the adapter; without a database they skip, having still
    // compile-checked the adapter and the test code. They share one database and `TRUNCATE`
    // it per test, but are robust to invocation: `fresh_store` self-serializes (so
    // `--test-threads=1` is unnecessary) and retries the initial connection (so a DB still
    // booting — e.g. `docker compose up -d` without `--wait` — is tolerated).
    fn database_url() -> Option<String> {
        std::env::var("DATABASE_URL").ok()
    }

    /// Serializes all DB-touching tests in this process so they never race on the shared
    /// database, independent of the test harness's thread count. (`tokio::sync::Mutex` does
    /// not poison, so a failing test still releases it for the next.)
    static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Connect, tolerating a just-started Postgres by retrying briefly before giving up.
    async fn connect_with_retry(url: &str) -> PostgresEventStore {
        let mut last = String::new();
        for _ in 0..20 {
            match PostgresEventStore::connect(url).await {
                Ok(store) => return store,
                Err(error) => {
                    last = error.to_string();
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
            }
        }
        panic!("could not connect to Postgres after retries: {last}");
    }

    /// Acquire the serial guard, connect (with retry), migrate, and truncate — returning the
    /// guard so the caller holds the lock for the test's duration.
    async fn fresh_store() -> (tokio::sync::MutexGuard<'static, ()>, PostgresEventStore) {
        let guard = SERIAL.lock().await;
        let store = connect_with_retry(&database_url().unwrap()).await;
        store.migrate().await.expect("migrate");
        // Isolate each run (all three tables: log + the derived caches).
        sqlx::query(
            "TRUNCATE dent8_event_log, dent8_claim_projection, dent8_claim_edge RESTART IDENTITY",
        )
        .execute(store.pool())
        .await
        .expect("truncate");
        (guard, store)
    }

    fn assert_event(
        event_id: &str,
        claim_id: &str,
        value: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        base(
            event_id,
            claim_id,
            ClaimEventKind::Asserted,
            Some(ClaimValue::Text(value.to_string())),
            source,
            authority,
        )
    }

    fn supersede_event(
        event_id: &str,
        claim_id: &str,
        by: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        base(
            event_id,
            claim_id,
            ClaimEventKind::Superseded {
                by: ClaimId::new(by).expect("by"),
                reason: SupersessionReason::NewerObservation,
            },
            None,
            source,
            authority,
        )
    }

    fn reinforce_event(
        event_id: &str,
        claim_id: &str,
        by: &str,
        value: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        base(
            event_id,
            claim_id,
            ClaimEventKind::Reinforced {
                by: ClaimId::new(by).expect("by"),
            },
            Some(ClaimValue::Text(value.to_string())),
            source,
            authority,
        )
    }

    fn base(
        event_id: &str,
        claim_id: &str,
        kind: ClaimEventKind,
        value: Option<ClaimValue>,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).expect("event id"),
            claim_id: ClaimId::new(claim_id).expect("claim id"),
            kind,
            subject: EntityRef::new("repo", "myproj").expect("entity"),
            predicate: Predicate::new("database").expect("predicate"),
            value,
            confidence: Confidence::from_millis(900).expect("confidence"),
            authority: Authority {
                level: authority,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new(source).expect("source"),
                actor: ActorId::new("actor:test").expect("actor"),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(1),
                attestation: None,
            },
            evidence: vec![Evidence {
                id: EvidenceId::new("evidence:1").expect("evidence id"),
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
    async fn firewall_holds_over_postgres() {
        let Some(_) = database_url() else {
            eprintln!("skipping: DATABASE_URL unset");
            return;
        };
        let (_guard, store) = fresh_store().await;

        // A high-authority fact is admitted and chained.
        let receipt = store
            .append(assert_event(
                "e1",
                "claim:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .await
            .expect("admitted");
        assert_eq!(receipt.global_sequence, 1); // identity starts at 1

        // A low-authority backing claim may exist...
        store
            .append(assert_event(
                "e2",
                "claim:B",
                "mysql",
                "source:web-scrape",
                AuthorityLevel::Low,
            ))
            .await
            .expect("low claim may exist");

        // ...but an over-stated (laundered) supersession is rejected by the SAME firewall.
        let laundered = store
            .append(supersede_event(
                "e3",
                "claim:A",
                "claim:B",
                "source:web-scrape",
                AuthorityLevel::High,
            ))
            .await;
        assert!(matches!(
            laundered,
            Err(StoreError::LaunderedAuthority { .. })
        ));

        // The trusted fact stands and the chain verifies.
        let events = store
            .load_claim_events(&ClaimId::new("claim:A").unwrap())
            .await
            .expect("load");
        assert_eq!(events.len(), 1);
        assert!(store.verify_chain().await.expect("verify"));

        // A duplicate event_id is a conflict.
        let dup = store
            .append(assert_event(
                "e1",
                "claim:C",
                "redis",
                "source:owner",
                AuthorityLevel::High,
            ))
            .await;
        assert!(matches!(dup, Err(StoreError::Conflict(_))));
    }

    /// An `Asserted` event on a distinct subject, so N of them are all independently
    /// admissible (no per-predicate uniqueness conflict between them).
    fn assert_on_subject(
        event_id: &str,
        claim_id: &str,
        subject_key: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        let mut event = assert_event(event_id, claim_id, "v", source, authority);
        event.subject = EntityRef::new("repo", subject_key).expect("subject");
        event
    }

    /// Genuinely concurrent appends (each its own transaction on the shared pool) must
    /// serialize into ONE consistent global hash chain: the transaction-scoped advisory lock
    /// makes the chain-head read-modify-write atomic, so the assigned `global_sequence`s are a
    /// gap-free, duplicate-free `1..=N`, the whole chain verifies, and every claim's
    /// projection equals the fold of its log. This is the adapter's multi-writer guarantee
    /// (the CLI's snapshot-minted `event:{n}` ids are a separate, documented single-writer
    /// caveat — here every event id is distinct, the case the adapter must handle cleanly).
    #[tokio::test]
    async fn concurrent_appends_keep_one_consistent_global_chain() {
        const N: usize = 12;
        let Some(_) = database_url() else {
            eprintln!("skipping: DATABASE_URL unset");
            return;
        };
        let (_guard, store) = fresh_store().await;

        let mut handles = Vec::with_capacity(N);
        for i in 0..N {
            let store = store.clone();
            handles.push(tokio::spawn(async move {
                store
                    .append(assert_on_subject(
                        &format!("e{i}"),
                        &format!("claim:{i}"),
                        &format!("proj{i}"),
                        "source:owner",
                        AuthorityLevel::High,
                    ))
                    .await
            }));
        }

        let mut sequences = Vec::with_capacity(N);
        for handle in handles {
            let receipt = handle
                .await
                .expect("task joined")
                .expect("each append admitted");
            sequences.push(receipt.global_sequence);
        }

        // No gaps, no duplicates — the advisory lock serialized the chain head.
        sequences.sort_unstable();
        assert_eq!(sequences, (1..=N as u64).collect::<Vec<_>>());
        // The single global chain verifies end-to-end under the concurrent interleaving.
        assert!(store.verify_chain().await.expect("verify chain"));
        // And every claim's materialized projection still equals the fold of its log.
        for i in 0..N {
            let claim = ClaimId::new(format!("claim:{i}")).unwrap();
            assert!(
                store
                    .verify_projection(&claim)
                    .await
                    .expect("verify projection"),
                "projection != fold for claim:{i}"
            );
        }
    }

    #[tokio::test]
    async fn materialization_tracks_projection_and_edges() {
        let Some(_) = database_url() else {
            eprintln!("skipping: DATABASE_URL unset");
            return;
        };
        let (_guard, store) = fresh_store().await;
        let a = ClaimId::new("claim:A").unwrap();
        let b = ClaimId::new("claim:B").unwrap();

        // Assert A, corroborate it from a second source, assert the replacement B, then
        // supersede A by B at equal authority (admitted, not laundered).
        store
            .append(assert_event(
                "e1",
                "claim:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .await
            .expect("assert A");
        store
            .append(reinforce_event(
                "e2",
                "claim:A",
                "claim:R",
                "postgres",
                "source:scanner",
                AuthorityLevel::Medium,
            ))
            .await
            .expect("reinforce A");
        store
            .append(assert_event(
                "e3",
                "claim:B",
                "mysql",
                "source:owner",
                AuthorityLevel::High,
            ))
            .await
            .expect("assert B");
        store
            .append(supersede_event(
                "e4",
                "claim:A",
                "claim:B",
                "source:owner",
                AuthorityLevel::High,
            ))
            .await
            .expect("supersede A by B");

        // A's materialized projection reflects the fold: Superseded, by B, value preserved,
        // corroboration of 2 (owner + scanner).
        let projection = store
            .materialized_projection(&a)
            .await
            .expect("read")
            .expect("A has a projection");
        assert_eq!(projection.lifecycle, ClaimLifecycle::Superseded);
        assert_eq!(
            projection.superseded_by.as_ref().map(ClaimId::as_str),
            Some("claim:B")
        );
        assert_eq!(projection.value, ClaimValue::Text("postgres".to_string()));
        assert_eq!(projection.corroboration(), 2);

        // The replacement stands on its own.
        let projection_b = store
            .materialized_projection(&b)
            .await
            .expect("read")
            .expect("B has a projection");
        assert_eq!(projection_b.lifecycle, ClaimLifecycle::Active);

        // The materialized cache equals an independent fold of the log.
        assert!(store.verify_projection(&a).await.expect("verify A"));
        assert!(store.verify_projection(&b).await.expect("verify B"));

        // A's outgoing edges: it reinforces R and is superseded toward B.
        let edges = store.edges_from(&a).await.expect("edges");
        assert_eq!(edges.len(), 2);
        assert!(
            edges
                .iter()
                .any(|e| e.edge_type == "supersedes" && e.to_claim_id == "claim:B")
        );
        assert!(
            edges
                .iter()
                .any(|e| e.edge_type == "reinforces" && e.to_claim_id == "claim:R")
        );

        // A claim with no events has no materialized projection.
        assert!(
            store
                .materialized_projection(&ClaimId::new("claim:none").unwrap())
                .await
                .expect("read")
                .is_none()
        );
    }

    #[tokio::test]
    async fn append_many_commits_a_multi_event_operation_atomically() {
        let Some(_) = database_url() else {
            eprintln!("skipping: DATABASE_URL unset");
            return;
        };
        let (_guard, store) = fresh_store().await;
        let a = ClaimId::new("claim:A").unwrap();
        let r = ClaimId::new("claim:R").unwrap();

        store
            .append(assert_event(
                "a1",
                "claim:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .await
            .expect("assert incumbent A");

        // The supersede *operation* as one transaction: assert the replacement R, then mark
        // A superseded by R. Both commit together; the supersession resolves R from the same
        // in-flight transaction.
        let receipts = store
            .append_many(vec![
                assert_event(
                    "r1",
                    "claim:R",
                    "mysql",
                    "source:owner",
                    AuthorityLevel::High,
                ),
                supersede_event(
                    "s1",
                    "claim:A",
                    "claim:R",
                    "source:owner",
                    AuthorityLevel::High,
                ),
            ])
            .await
            .expect("append_many");
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            store
                .materialized_projection(&a)
                .await
                .unwrap()
                .unwrap()
                .lifecycle,
            ClaimLifecycle::Superseded
        );
        assert_eq!(
            store
                .materialized_projection(&r)
                .await
                .unwrap()
                .unwrap()
                .value,
            ClaimValue::Text("mysql".to_string())
        );
        assert!(store.verify_projection(&a).await.unwrap());
        assert!(store.verify_chain().await.unwrap());

        // Atomicity: a batch whose second event is rejected (the supersession targets the
        // now-terminal A) commits NOTHING — the R2 assert rolls back with it.
        let bad = store
            .append_many(vec![
                assert_event(
                    "r2",
                    "claim:R2",
                    "redis",
                    "source:owner",
                    AuthorityLevel::High,
                ),
                supersede_event(
                    "s2",
                    "claim:A",
                    "claim:R2",
                    "source:owner",
                    AuthorityLevel::High,
                ),
            ])
            .await;
        assert!(bad.is_err());
        assert!(
            store
                .materialized_projection(&ClaimId::new("claim:R2").unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }

    /// The indexed scalar columns are derived by separate bind expressions from `state_json`,
    /// so verify them against the (lossless) folded state directly — a bind/mapping bug here
    /// would otherwise pass both `verify_projection` and the read-side assertions above.
    #[tokio::test]
    async fn projection_scalar_columns_match_the_folded_state() {
        let Some(_) = database_url() else {
            eprintln!("skipping: DATABASE_URL unset");
            return;
        };
        let (_guard, store) = fresh_store().await;
        let a = ClaimId::new("claim:A").unwrap();

        store
            .append(assert_event(
                "e1",
                "claim:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .await
            .expect("assert A");
        store
            .append(reinforce_event(
                "e2",
                "claim:A",
                "claim:R",
                "postgres",
                "source:scanner",
                AuthorityLevel::Medium,
            ))
            .await
            .expect("reinforce A");
        store
            .append(assert_event(
                "e3",
                "claim:B",
                "mysql",
                "source:owner",
                AuthorityLevel::High,
            ))
            .await
            .expect("assert B");
        store
            .append(supersede_event(
                "e4",
                "claim:A",
                "claim:B",
                "source:owner",
                AuthorityLevel::High,
            ))
            .await
            .expect("supersede A by B");

        // The lossless state (state_json) is the reference; the raw scalar columns must agree.
        let state = store
            .materialized_projection(&a)
            .await
            .expect("read")
            .expect("A has a projection");

        #[allow(clippy::type_complexity)]
        let (
            lifecycle,
            superseded_by,
            contradicted_by,
            corroboration,
            created_at,
            updated_at,
            last_event_id,
        ): (String, Option<String>, Vec<String>, i64, i64, i64, String) = sqlx::query_as(
            "SELECT lifecycle, superseded_by, contradicted_by, corroboration, created_at, \
             updated_at, last_event_id FROM dent8_claim_projection WHERE claim_id = $1",
        )
        .bind(a.as_str())
        .fetch_one(store.pool())
        .await
        .expect("read scalar columns");

        assert_eq!(lifecycle, "superseded");
        assert_eq!(
            superseded_by.as_deref(),
            state.superseded_by.as_ref().map(ClaimId::as_str)
        );
        let expected_contradicted: Vec<String> = state
            .contradicted_by
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        assert_eq!(contradicted_by, expected_contradicted);
        assert_eq!(corroboration, i64::try_from(state.corroboration()).unwrap());
        assert_eq!(created_at, state.created_at.as_unix_millis());
        assert_eq!(updated_at, state.updated_at.as_unix_millis());
        assert_eq!(last_event_id, state.last_event_id.as_str());
    }
}
