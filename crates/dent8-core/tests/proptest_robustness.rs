//! Robustness property tests: the **parse → hash → fold → canonicalize** pipeline must never
//! *panic* on adversarial input.
//!
//! The firewall ingests untrusted, possibly hand-edited or hostile data — a file JSONL log,
//! MCP JSON-RPC arguments, Postgres JSONB — and every one of those routes through
//! `serde_json` deserialization into a [`ClaimEvent`], then through `event_hash` /
//! `hash_chain` / `canonical_bytes` / `apply_event`. A panic on any of them is a
//! denial-of-service / availability break, not just a wrong answer. These properties assert
//! *robustness* (clean `Ok`/`Err`, never a crash), complementing `proptest_fold.rs` (which
//! checks *correctness* on valid coherent streams) and `proptest_invariants.rs`.
//!
//! They deliberately exercise values that bypass the constructors' validation, because
//! `Deserialize` is derived for the scalar newtypes and so does *not* re-run `::new` /
//! `from_millis`: an out-of-range [`Confidence`] (`> 1000`), extreme timestamps, a huge TTL
//! duration, empty/oversized ids and predicates, and deeply nested / pathological JSON values
//! can all enter through a crafted log line. The pipeline must absorb them without crashing.

use dent8_core::{
    ActorId, Authority, AuthorityLevel, CanonicalJson, ClaimEvent, ClaimEventId, ClaimEventKind,
    ClaimId, Confidence, EntityRef, Evidence, EvidenceId, EvidenceKind, Predicate, Provenance,
    SourceId, TimestampMillis, Ttl, apply_event, canonical_bytes, event_hash, hash_chain,
};
use proptest::prelude::*;

/// A valid event used only as a *shape-correct skeleton*: the property then overrides
/// individual fields in its JSON form with adversarial values, so the serde representation is
/// always right and only the values under test are hostile.
fn skeleton_event() -> ClaimEvent {
    ClaimEvent {
        event_id: ClaimEventId::new("event:1").unwrap(),
        claim_id: ClaimId::new("claim:1").unwrap(),
        kind: ClaimEventKind::Asserted,
        subject: EntityRef::new("repo", "dent8").unwrap(),
        predicate: Predicate::new("database").unwrap(),
        value: Some(dent8_core::ClaimValue::Text("postgres".to_string())),
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

/// A bounded, recursive JSON strategy: nulls/bools/ints/finite-floats/strings at the leaves,
/// arrays and objects (arbitrary keys) to a small depth. Bounds keep it well under
/// `serde_json`'s parse recursion limit while still nesting.
fn arb_json() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::from),
        any::<i64>().prop_map(serde_json::Value::from),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(serde_json::Value::from),
        ".*".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(6, 64, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8).prop_map(serde_json::Value::Array),
            prop::collection::hash_map(".*", inner, 0..8)
                .prop_map(|map| serde_json::Value::Object(map.into_iter().collect())),
        ]
    })
}

/// Run the whole untrusted-input pipeline on `event`. None of these may panic.
fn exercise_pipeline(event: &ClaimEvent) {
    let _ = event_hash(event, None);
    let _ = event_hash(event, Some("00"));
    let _ = canonical_bytes(event);
    let _ = hash_chain(std::slice::from_ref(event));
    let _ = hash_chain(&[event.clone(), event.clone()]);
    let _ = apply_event(None, event);
}

proptest! {
    /// Arbitrary bytes must never panic the parser, and any event that *does* parse must run
    /// the whole pipeline without panicking. (Most random byte strings fail to parse — that is
    /// fine; the point is no crash on either path.)
    #[test]
    fn arbitrary_bytes_never_panic_the_pipeline(raw in prop::collection::vec(any::<u8>(), 0..1024)) {
        if let Ok(event) = serde_json::from_slice::<ClaimEvent>(&raw) {
            exercise_pipeline(&event);
        }
    }

    /// A shape-correct event whose scalar fields carry adversarial, validation-bypassing values
    /// must (a) parse-or-error without panic, (b) run the whole pipeline without panic if it
    /// parses, (c) hash deterministically, and (d) canonicalize idempotently — the property
    /// that prevents a false tamper alarm on reload.
    #[test]
    fn adversarial_field_values_never_panic_and_canonicalize_idempotently(
        confidence in any::<u16>(),
        recorded_at in any::<i64>(),
        ttl_ms in any::<u64>(),
        event_id in ".*",
        predicate in ".*",
        value_json in arb_json(),
    ) {
        let mut doc = serde_json::to_value(skeleton_event()).expect("serialize skeleton");
        doc["confidence"] = serde_json::json!(confidence);
        doc["provenance"]["recorded_at"] = serde_json::json!(recorded_at);
        doc["ttl"] = serde_json::to_value(Ttl::DurationMillis(ttl_ms)).expect("ttl to value");
        doc["event_id"] = serde_json::json!(event_id);
        doc["predicate"] = serde_json::json!(predicate);
        doc["value"] = serde_json::json!({
            "Json": serde_json::to_string(&value_json).expect("value to string")
        });

        let text = serde_json::to_string(&doc).expect("doc to string");
        if let Ok(event) = serde_json::from_str::<ClaimEvent>(&text) {
            exercise_pipeline(&event);
            // Determinism.
            prop_assert_eq!(event_hash(&event, None).ok(), event_hash(&event, None).ok());
            // Canonical idempotence: re-parsing the canonical bytes and re-canonicalizing is a
            // fixpoint (no drift that would read as tamper).
            if let Ok(bytes) = canonical_bytes(&event) {
                let reparsed: ClaimEvent =
                    serde_json::from_slice(&bytes).expect("canonical bytes re-parse");
                prop_assert_eq!(canonical_bytes(&reparsed).ok(), Some(bytes));
            }
        }
    }

    /// Arbitrary JSON canonicalizes without panicking, and the canonical form is a fixpoint
    /// (canonicalizing it again yields the same bytes).
    #[test]
    fn canonical_json_is_panic_free_and_idempotent(value in arb_json()) {
        let raw = serde_json::to_string(&value).expect("value to string");
        if let Ok(canonical) = CanonicalJson::new(&raw) {
            let again = CanonicalJson::new(canonical.as_str()).expect("canonical re-canonicalizes");
            prop_assert_eq!(canonical.as_str(), again.as_str());
        }
    }
}

/// A concrete, deterministic pin of the same robustness contract: an event whose scalars
/// bypass their constructors' validation via `Deserialize` (out-of-range `Confidence`, empty
/// predicate, whitespace id, `u64::MAX` TTL) still deserializes and runs the whole pipeline
/// without panic — and TTL overflow is fail-*open* (no expiry), not a crash. This also
/// guarantees the proptest above genuinely reaches the parse-and-process path, not just the
/// rejected path.
#[test]
fn an_out_of_range_event_deserializes_and_the_pipeline_absorbs_it() {
    let mut doc = serde_json::to_value(skeleton_event()).expect("serialize skeleton");
    doc["confidence"] = serde_json::json!(u16::MAX); // 65535 — far above Confidence::MAX (1000)
    doc["predicate"] = serde_json::json!(""); // empty — bypasses Predicate::new
    doc["event_id"] = serde_json::json!("   "); // whitespace — bypasses ClaimEventId::new
    doc["ttl"] = serde_json::to_value(Ttl::DurationMillis(u64::MAX)).expect("ttl");
    let text = serde_json::to_string(&doc).expect("doc to string");

    let event: ClaimEvent = serde_json::from_str(&text).expect("adversarial event deserializes");
    assert_eq!(
        event.confidence.as_millis(),
        u16::MAX,
        "Deserialize bypassed the bound"
    );

    // No panic across the pipeline, and the unrepresentable TTL is fail-open (no expiry).
    exercise_pipeline(&event);
    assert!(
        event
            .ttl
            .expires_at(TimestampMillis::from_unix_millis(0))
            .is_none(),
        "an overflowing TTL must fail open, not panic"
    );

    // Canonical idempotence holds even for the out-of-range value (no false tamper on reload).
    let bytes = canonical_bytes(&event).expect("canonicalize");
    let reparsed: ClaimEvent = serde_json::from_slice(&bytes).expect("re-parse canonical");
    assert_eq!(canonical_bytes(&reparsed).expect("re-canonicalize"), bytes);
}
