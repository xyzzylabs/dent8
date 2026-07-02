//! The concurrency contract of the `SQLite` backend, as a committed regression test.
//!
//! The adversarial review of this adapter found (and reproduced) a parity gap: with a
//! DEFERRED transaction, concurrent cross-connection writers hit `SQLITE_BUSY` on the
//! read→write upgrade and were *dropped* (13/20 succeeded) where Postgres' advisory lock
//! would have serialized them. The fix — `BEGIN IMMEDIATE` + WAL + `busy_timeout` — was
//! verified manually (20/20) but never committed as a test. This is that test: every writer
//! must **wait and succeed**, and the resulting chain must be gap-free and re-verifiable.
//!
//! Each writer runs on its own OS thread with its own current-thread runtime and its own
//! single-connection pool against one shared database file — the same shape as N concurrent
//! CLI/MCP processes (`AsyncEventStore` is `?Send`, so cross-thread sharing is not possible,
//! which is exactly the production topology).

use std::sync::{Arc, Barrier};

use dent8_core::{
    ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
    ClaimValue, Confidence, EntityRef, Evidence, EvidenceId, EvidenceKind, Predicate, Provenance,
    SourceId, TimestampMillis, Ttl,
};
use dent8_store::EventFilter;
use dent8_store_sqlite::SqliteEventStore;

const WRITERS: usize = 8;
const EVENTS_PER_WRITER: usize = 3;

fn asserted(writer: usize, sequence: usize) -> ClaimEvent {
    ClaimEvent {
        event_id: ClaimEventId::new(format!("event:w{writer}-{sequence}")).unwrap(),
        claim_id: ClaimId::new(format!("claim:w{writer}-{sequence}")).unwrap(),
        kind: ClaimEventKind::Asserted,
        // Distinct subjects per event: the race under test is the *global chain head*, not
        // firewall arbitration between competing claims.
        subject: EntityRef::new("repo", format!("proj-w{writer}-{sequence}")).unwrap(),
        predicate: Predicate::new("database").unwrap(),
        value: Some(ClaimValue::Text("postgres".to_string())),
        confidence: Confidence::from_millis(900).unwrap(),
        authority: Authority {
            level: AuthorityLevel::High,
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
            attestation: None,
        },
        evidence: vec![Evidence {
            id: EvidenceId::new(format!("evidence:w{writer}-{sequence}")).unwrap(),
            kind: EvidenceKind::UserStatement,
            locator: "x".to_string(),
            digest: None,
            summary: None,
        }],
        observed_at: None,
        valid_from: None,
    }
}

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

#[test]
fn concurrent_writers_serialize_instead_of_failing() {
    let dir = std::env::temp_dir().join(format!(
        "dent8-sqlite-concurrency-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let url = format!("sqlite://{}", dir.join("race.db").display());

    // Create the schema once before the writers race.
    current_thread_runtime().block_on(async {
        let store = SqliteEventStore::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
    });

    // All writers block on the barrier, then append through their own connections at once.
    let barrier = Arc::new(Barrier::new(WRITERS));
    let handles: Vec<_> = (0..WRITERS)
        .map(|writer| {
            let url = url.clone();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                current_thread_runtime().block_on(async {
                    let store = SqliteEventStore::connect(&url).await.expect("connect");
                    barrier.wait();
                    for sequence in 0..EVENTS_PER_WRITER {
                        // The contract under test: a contending writer WAITS on the write
                        // lock (`BEGIN IMMEDIATE` + `busy_timeout`) and then succeeds — it
                        // must never be dropped with a busy/conflict error.
                        store
                            .append(asserted(writer, sequence))
                            .await
                            .unwrap_or_else(|error| {
                                panic!("writer {writer} event {sequence} failed: {error}")
                            });
                    }
                });
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("writer thread");
    }

    // Every event landed, the global sequence has no forks, and the stored chain re-verifies.
    current_thread_runtime().block_on(async {
        let store = SqliteEventStore::connect(&url).await.expect("connect");
        let events = store
            .scan_events(&EventFilter::default())
            .await
            .expect("scan");
        assert_eq!(events.len(), WRITERS * EVENTS_PER_WRITER);
        assert!(store.verify_chain().await.expect("verify"), "chain forked");
    });

    let _ = std::fs::remove_dir_all(&dir);
}
