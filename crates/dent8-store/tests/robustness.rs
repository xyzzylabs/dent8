//! Robustness: the store firewall + projection must never *panic* on adversarial event
//! **structure**.
//!
//! `proptest_fold.rs` and `proptest_invariants.rs` already exercise the fold on valid,
//! coherent streams, and `proptest_robustness.rs` (core) proves the scalar pipeline is
//! panic-free. This pins the remaining surface: `replay_entity` folding a *structurally*
//! hostile stream — supersession/contradiction edges that point at the claim itself, form a
//! cycle, or dangle (the successor never exists), plus extreme timestamps driving the
//! freshness/TTL math, and a large evidence vector. The firewall must return a clean
//! projection (with `lineage_issues` flagged) or an error — never crash. A panic here would be
//! a denial-of-service reachable from a hand-edited log or a hostile event source.

use dent8_core::{
    ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
    ClaimValue, Confidence, Evidence, EvidenceId, EvidenceKind, Predicate, Provenance, SourceId,
    SupersessionReason, TimestampMillis, Ttl,
};
use dent8_store::replay_entity;

/// Build an event on the shared `repo:proj database` entity, with a chosen kind, timestamp,
/// TTL, and evidence count — all via the real constructors, so only the *structure* is hostile.
fn event(
    event_id: &str,
    claim_id: &str,
    kind: ClaimEventKind,
    recorded_at_ms: i64,
    ttl: Ttl,
    evidence_count: usize,
) -> ClaimEvent {
    ClaimEvent {
        event_id: ClaimEventId::new(event_id).unwrap(),
        claim_id: ClaimId::new(claim_id).unwrap(),
        kind,
        subject: dent8_core::EntityRef::new("repo", "proj").unwrap(),
        predicate: Predicate::new("database").unwrap(),
        value: Some(ClaimValue::Text("postgres".to_string())),
        confidence: Confidence::from_millis(900).unwrap(),
        authority: Authority {
            level: AuthorityLevel::High,
            issuer: None,
            scope: None,
        },
        ttl,
        provenance: Provenance {
            source: SourceId::new("source:owner").unwrap(),
            actor: ActorId::new("actor:test").unwrap(),
            tool: None,
            run_id: None,
            input_digest: None,
            recorded_at: TimestampMillis::from_unix_millis(recorded_at_ms),
        },
        evidence: (0..evidence_count)
            .map(|i| Evidence {
                id: EvidenceId::new(format!("evidence:{i}")).unwrap(),
                kind: EvidenceKind::UserStatement,
                locator: "x".to_string(),
                digest: None,
                summary: None,
            })
            .collect(),
        observed_at: None,
        valid_from: None,
    }
}

fn superseded_by(by: &str) -> ClaimEventKind {
    ClaimEventKind::Superseded {
        by: ClaimId::new(by).unwrap(),
        reason: SupersessionReason::NewerObservation,
    }
}

/// `replay_entity` (fold + `lineage_issues` + projection) must absorb every hostile shape
/// without panicking — both the whole stream and every prefix of it.
fn assert_replay_never_panics(events: &[ClaimEvent]) {
    for end in 0..=events.len() {
        // The result may be Ok (possibly with lineage issues) or Err — never a panic.
        if let Ok(projection) = replay_entity(&events[..end]) {
            let _ = projection.lineage_issues();
        }
    }
}

#[test]
fn self_referential_supersession_does_not_panic() {
    // claim:a is superseded *by itself*.
    let events = vec![
        event(
            "event:1",
            "claim:a",
            ClaimEventKind::Asserted,
            1,
            Ttl::Never,
            1,
        ),
        event(
            "event:2",
            "claim:a",
            superseded_by("claim:a"),
            2,
            Ttl::Never,
            1,
        ),
    ];
    assert_replay_never_panics(&events);
}

#[test]
fn cyclic_supersession_does_not_panic() {
    // claim:a -> superseded by claim:b, claim:b -> superseded by claim:a (a 2-cycle).
    let events = vec![
        event(
            "event:1",
            "claim:a",
            ClaimEventKind::Asserted,
            1,
            Ttl::Never,
            1,
        ),
        event(
            "event:2",
            "claim:b",
            ClaimEventKind::Asserted,
            2,
            Ttl::Never,
            1,
        ),
        event(
            "event:3",
            "claim:a",
            superseded_by("claim:b"),
            3,
            Ttl::Never,
            1,
        ),
        event(
            "event:4",
            "claim:b",
            superseded_by("claim:a"),
            4,
            Ttl::Never,
            1,
        ),
    ];
    assert_replay_never_panics(&events);
}

#[test]
fn dangling_supersession_does_not_panic() {
    // claim:a is superseded by a claim that never appears in the stream.
    let events = vec![
        event(
            "event:1",
            "claim:a",
            ClaimEventKind::Asserted,
            1,
            Ttl::Never,
            1,
        ),
        event(
            "event:2",
            "claim:a",
            superseded_by("claim:ghost"),
            2,
            Ttl::Never,
            1,
        ),
    ];
    assert_replay_never_panics(&events);
}

#[test]
fn extreme_timestamps_and_ttls_do_not_panic_the_freshness_math() {
    // i64::MIN / i64::MAX anchors combined with a u64::MAX duration TTL: the expiry math must
    // stay fail-open (checked arithmetic), never overflow-panic.
    let events = vec![
        event(
            "event:1",
            "claim:a",
            ClaimEventKind::Asserted,
            i64::MAX,
            Ttl::DurationMillis(u64::MAX),
            1,
        ),
        event(
            "event:2",
            "claim:b",
            ClaimEventKind::Asserted,
            i64::MIN,
            Ttl::ExpiresAt(TimestampMillis::from_unix_millis(i64::MIN)),
            1,
        ),
        event(
            "event:3",
            "claim:b",
            superseded_by("claim:a"),
            i64::MAX,
            Ttl::DurationMillis(u64::MAX),
            1,
        ),
    ];
    assert_replay_never_panics(&events);
}

#[test]
fn a_large_evidence_and_event_stream_does_not_panic() {
    // Many events on one entity, each carrying a sizeable evidence vector — exercises the
    // count/aggregation paths without overflow.
    let mut events = vec![event(
        "event:0",
        "claim:a",
        ClaimEventKind::Asserted,
        0,
        Ttl::Never,
        64,
    )];
    for i in 1..500 {
        events.push(event(
            &format!("event:{i}"),
            "claim:a",
            ClaimEventKind::Reinforced {
                by: ClaimId::new("claim:a").unwrap(),
            },
            i64::from(i),
            Ttl::Never,
            8,
        ));
    }
    // Only the full stream (the per-prefix loop would be O(n^2) for n=500).
    if let Ok(projection) = replay_entity(&events) {
        let _ = projection.lineage_issues();
    }
}
