//! Property-based tests for the integrity-critical invariants of `dent8-core`.
//!
//! These generalize the example-based unit tests into universally-quantified properties —
//! motivated directly by the float-canonicalization bug, which was an *idempotency*
//! violation that example tests missed but a property test catches automatically:
//!
//! - **Canonicalization is idempotent and reload-stable** — for *any* JSON value, so the
//!   re-canonicalizing deserialize never changes a written value (no false hash-chain alarm).
//! - **`canonical_bytes` round-trips through serde** and **`event_hash` is reload-stable** —
//!   for arbitrary events.
//! - **The hash chain localizes tamper** — a single changed event flips its hash and every
//!   later one, never an earlier one.
//! - **The external anchor accepts its own log and rejects any change.**

use dent8_core::{
    ActorId, Authority, AuthorityLevel, CanonicalJson, ClaimEvent, ClaimEventId, ClaimEventKind,
    ClaimId, ClaimValue, Confidence, ContradictionBasis, EntityRef, Evidence, EvidenceId,
    EvidenceKind, ExpirationReason, Predicate, Provenance, RetractionReason, SourceId,
    SupersessionReason, TimestampMillis, Ttl, anchor_head, canonical_bytes, event_hash, hash_chain,
    verify_anchor,
};
use proptest::prelude::*;
use serde_json::Value as JsonValue;

/// An arbitrary JSON value: nulls, bools, integers, finite floats, strings, and nested
/// arrays/objects (with arbitrary, possibly non-ASCII, keys).
fn arb_json() -> impl Strategy<Value = JsonValue> {
    let leaf = prop_oneof![
        Just(JsonValue::Null),
        any::<bool>().prop_map(JsonValue::Bool),
        any::<i64>().prop_map(|n| JsonValue::Number(n.into())),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(
                |f| serde_json::Number::from_f64(f).map_or(JsonValue::Null, JsonValue::Number)
            ),
        any::<String>().prop_map(JsonValue::String),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(JsonValue::Array),
            prop::collection::vec((any::<String>(), inner), 0..6)
                .prop_map(|pairs| JsonValue::Object(pairs.into_iter().collect())),
        ]
    })
}

/// Render an ordered list of (key, value) pairs as a raw JSON object string, preserving
/// the given key order (unlike `serde_json::Map`, which sorts). Keys and values are escaped
/// via `serde_json`, so arbitrary strings are emitted as valid JSON.
fn object_text<'a>(pairs: impl Iterator<Item = &'a (String, JsonValue)>) -> String {
    let body: Vec<String> = pairs
        .map(|(key, value)| {
            format!(
                "{}:{}",
                serde_json::to_string(key).expect("key"),
                serde_json::to_string(value).expect("value"),
            )
        })
        .collect();
    format!("{{{}}}", body.join(","))
}

/// A non-empty identifier string (the only constraint the ID newtypes and `EntityRef`/
/// `Predicate` impose). Mixes a tidy id-shaped form with arbitrary non-blank strings so
/// escape-sensitive bytes (quotes, backslashes, control chars, non-ASCII) also reach the
/// identity fields the hash chain commits to — not just the `Json`/`Text`/`Option` leaves.
fn arb_id() -> impl Strategy<Value = String> {
    prop_oneof![
        proptest::string::string_regex("[a-z0-9][a-z0-9:_-]{0,11}").expect("regex"),
        any::<String>().prop_filter("non-blank", |s| !s.trim().is_empty()),
    ]
}

fn arb_authority() -> impl Strategy<Value = Authority> {
    let level = prop_oneof![
        Just(AuthorityLevel::Unknown),
        Just(AuthorityLevel::Low),
        Just(AuthorityLevel::Medium),
        Just(AuthorityLevel::High),
        Just(AuthorityLevel::Canonical),
    ];
    (
        level,
        proptest::option::of(any::<String>()),
        proptest::option::of(any::<String>()),
    )
        .prop_map(|(level, issuer, scope)| Authority {
            level,
            issuer,
            scope,
        })
}

fn arb_ttl() -> impl Strategy<Value = Ttl> {
    prop_oneof![
        Just(Ttl::Never),
        any::<i64>().prop_map(|m| Ttl::ExpiresAt(TimestampMillis::from_unix_millis(m))),
        any::<u64>().prop_map(Ttl::DurationMillis),
    ]
}

fn arb_value() -> impl Strategy<Value = Option<ClaimValue>> {
    prop_oneof![
        Just(None),
        any::<String>().prop_map(|s| Some(ClaimValue::Text(s))),
        arb_json().prop_map(|v| Some(ClaimValue::json(&v.to_string()).expect("valid json"))),
        Just(Some(ClaimValue::Redacted)),
    ]
}

fn arb_kind() -> impl Strategy<Value = ClaimEventKind> {
    let sup_reason = prop_oneof![
        Just(SupersessionReason::NewerObservation),
        Just(SupersessionReason::HigherAuthority),
        Just(SupersessionReason::UserCorrection),
        Just(SupersessionReason::SchemaMigration),
    ];
    let basis = prop_oneof![
        Just(ContradictionBasis::SamePredicateDifferentValue),
        Just(ContradictionBasis::MutuallyExclusivePredicate),
        Just(ContradictionBasis::AuthorityChallenge),
        Just(ContradictionBasis::FreshnessChallenge),
    ];
    let expiration = prop_oneof![
        Just(ExpirationReason::TtlElapsed),
        Just(ExpirationReason::PolicyRetention),
    ];
    let retraction = prop_oneof![
        Just(RetractionReason::SourceInvalidated),
        Just(RetractionReason::PoisoningDetected),
        Just(RetractionReason::UserDeleted),
        Just(RetractionReason::PolicyViolation),
    ];
    // All eight variants, so every embedded reason/basis enum is round-trip-tested.
    prop_oneof![
        Just(ClaimEventKind::Asserted),
        arb_id().prop_map(|by| ClaimEventKind::Reinforced {
            by: ClaimId::new(by).expect("claim id"),
        }),
        (arb_id(), basis).prop_map(|(by, basis)| ClaimEventKind::Contradicted {
            by: ClaimId::new(by).expect("claim id"),
            basis,
        }),
        (arb_id(), sup_reason).prop_map(|(by, reason)| ClaimEventKind::Superseded {
            by: ClaimId::new(by).expect("claim id"),
            reason,
        }),
        expiration.prop_map(|reason| ClaimEventKind::Expired { reason }),
        retraction.prop_map(|reason| ClaimEventKind::Retracted { reason }),
        any::<String>().prop_map(|purpose| ClaimEventKind::Retrieved { purpose }),
        any::<String>().prop_map(|decision_id| ClaimEventKind::UsedInDecision { decision_id }),
    ]
}

fn arb_evidence() -> impl Strategy<Value = Vec<Evidence>> {
    let kind = prop_oneof![
        Just(EvidenceKind::DirectObservation),
        Just(EvidenceKind::ToolOutput),
        Just(EvidenceKind::FileSpan),
        Just(EvidenceKind::UserStatement),
        Just(EvidenceKind::DerivedSummary),
        Just(EvidenceKind::ExternalDocument),
    ];
    let one = (
        arb_id(),
        kind,
        any::<String>(),
        proptest::option::of(any::<String>()),
        proptest::option::of(any::<String>()),
    )
        .prop_map(|(id, kind, locator, digest, summary)| Evidence {
            id: EvidenceId::new(id).expect("evidence id"),
            kind,
            locator,
            digest,
            summary,
        });
    prop::collection::vec(one, 0..3)
}

fn arb_provenance() -> impl Strategy<Value = Provenance> {
    (
        arb_id(),
        arb_id(),
        proptest::option::of(any::<String>()),
        proptest::option::of(any::<String>()),
        proptest::option::of(any::<String>()),
        any::<i64>(),
    )
        .prop_map(
            |(source, actor, tool, run_id, input_digest, recorded_at)| Provenance {
                source: SourceId::new(source).expect("source"),
                actor: ActorId::new(actor).expect("actor"),
                tool,
                run_id,
                input_digest,
                recorded_at: TimestampMillis::from_unix_millis(recorded_at),
                attestation: None,
            },
        )
}

/// An arbitrary, structurally-valid [`ClaimEvent`]. Semantic validity (a coherent event
/// *sequence*) is irrelevant here — these properties exercise canonicalization, hashing,
/// and anchoring, which operate on individual events as opaque records.
fn arb_event() -> impl Strategy<Value = ClaimEvent> {
    (
        arb_id(),
        arb_id(),
        arb_kind(),
        (arb_id(), arb_id()),
        (
            arb_id(),
            arb_value(),
            proptest::option::of(any::<i64>()),
            proptest::option::of(any::<i64>()),
        ),
        0u16..=1000,
        arb_authority(),
        arb_ttl(),
        arb_provenance(),
        arb_evidence(),
    )
        .prop_map(
            |(
                event_id,
                claim_id,
                kind,
                (subject_kind, subject_key),
                (predicate, value, observed_at, valid_from),
                confidence,
                authority,
                ttl,
                provenance,
                evidence,
            )| ClaimEvent {
                event_id: ClaimEventId::new(event_id).expect("event id"),
                claim_id: ClaimId::new(claim_id).expect("claim id"),
                kind,
                subject: EntityRef::new(subject_kind, subject_key).expect("entity"),
                predicate: Predicate::new(predicate).expect("predicate"),
                value,
                confidence: Confidence::from_millis(confidence).expect("confidence"),
                authority,
                ttl,
                provenance,
                evidence,
                observed_at: observed_at.map(TimestampMillis::from_unix_millis),
                valid_from: valid_from.map(TimestampMillis::from_unix_millis),
            },
        )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// For ANY JSON value: canonicalization is idempotent, and a value survives the actual
    /// serialize -> (re-canonicalizing) deserialize path unchanged. This is the property the
    /// float bug violated — `13e300`-class values drift without `float_roundtrip`.
    #[test]
    fn canonical_json_is_idempotent_and_reload_stable(v in arb_json()) {
        let once = CanonicalJson::new(&v.to_string()).expect("valid json");
        let twice = CanonicalJson::new(once.as_str()).expect("valid json");
        prop_assert_eq!(&once, &twice);

        let value = ClaimValue::Json(once.clone());
        let bytes = serde_json::to_string(&value).expect("serialize");
        let reloaded: ClaimValue = serde_json::from_str(&bytes).expect("deserialize");
        prop_assert_eq!(value, reloaded);
    }

    /// The canonical form is independent of insignificant whitespace.
    #[test]
    fn canonical_json_is_whitespace_invariant(v in arb_json()) {
        let compact = CanonicalJson::new(&serde_json::to_string(&v).expect("compact"))
            .expect("valid json");
        let pretty = CanonicalJson::new(&serde_json::to_string_pretty(&v).expect("pretty"))
            .expect("valid json");
        prop_assert_eq!(compact, pretty);
    }

    /// The canonical form is independent of object key *order*: the same object written
    /// with its keys in two different orders canonicalizes to identical bytes. (The other
    /// properties feed already-sorted `serde_json::Value`s, so this exercises the raw-text
    /// ordering path the hash chain most directly depends on.)
    #[test]
    fn canonical_json_is_key_order_invariant(
        pairs in prop::collection::vec((any::<String>(), arb_json()), 1..6),
    ) {
        // JSON objects have unique keys; keep the first occurrence of each.
        let mut seen = std::collections::HashSet::new();
        let unique: Vec<(String, JsonValue)> =
            pairs.into_iter().filter(|(k, _)| seen.insert(k.clone())).collect();
        let forward = object_text(unique.iter());
        let reversed = object_text(unique.iter().rev());
        prop_assert_eq!(
            CanonicalJson::new(&forward).expect("valid json"),
            CanonicalJson::new(&reversed).expect("valid json"),
        );
    }

    /// `canonical_bytes` is stable across a serde round trip (so replay/reload reproduces
    /// the exact bytes that were hashed).
    #[test]
    fn event_canonical_bytes_round_trips_through_serde(e in arb_event()) {
        let canon = canonical_bytes(&e).expect("canonicalize");
        let reloaded: ClaimEvent = serde_json::from_slice(&canon).expect("deserialize");
        prop_assert_eq!(canonical_bytes(&reloaded).expect("re-canonicalize"), canon);
    }

    /// An event's hash is reproduced exactly after a serde round trip.
    #[test]
    fn event_hash_is_reload_stable(e in arb_event()) {
        let original = event_hash(&e, None).expect("hash");
        let canon = canonical_bytes(&e).expect("canonicalize");
        let reloaded: ClaimEvent = serde_json::from_slice(&canon).expect("deserialize");
        prop_assert_eq!(event_hash(&reloaded, None).expect("hash"), original);
    }

    /// `event_hash` binds the `previous` link: the genesis form and two distinct previous
    /// digests give three pairwise-distinct hashes, and a non-hex `previous` is rejected.
    /// (Direct coverage of the chaining parameter, which the other properties only use as
    /// `None`.)
    #[test]
    fn event_hash_binds_the_previous_link(
        e in arb_event(),
        p1 in "[0-9a-f]{64}",
        p2 in "[0-9a-f]{64}",
    ) {
        prop_assume!(p1 != p2);
        let genesis = event_hash(&e, None).expect("hash");
        let chained1 = event_hash(&e, Some(&p1)).expect("hash");
        let chained2 = event_hash(&e, Some(&p2)).expect("hash");
        prop_assert_ne!(&genesis, &chained1);
        prop_assert_ne!(&genesis, &chained2);
        prop_assert_ne!(&chained1, &chained2);
        // A previous that is not a 64-char hex digest is an error, never a silent hash.
        prop_assert!(event_hash(&e, Some("not-a-digest")).is_err());
    }

    /// Tamper is localized: changing one event flips its hash and every later one, but no
    /// earlier one.
    #[test]
    fn hash_chain_localizes_tamper(
        events in prop::collection::vec(arb_event(), 1..6),
        index in any::<prop::sample::Index>(),
        replacement in arb_event(),
    ) {
        let original = hash_chain(&events).expect("chain");
        let idx = index.index(events.len());
        let mut tampered = events.clone();
        tampered[idx] = replacement;
        // Only meaningful when the replacement actually differs in canonical bytes.
        prop_assume!(
            canonical_bytes(&tampered[idx]).expect("canon")
                != canonical_bytes(&events[idx]).expect("canon")
        );
        let recomputed = hash_chain(&tampered).expect("chain");
        for j in 0..idx {
            prop_assert_eq!(&recomputed[j], &original[j]);
        }
        for j in idx..events.len() {
            prop_assert_ne!(&recomputed[j], &original[j]);
        }
    }

    /// The external anchor verifies the exact log it committed to and rejects any change
    /// (here: appending an event, which changes the count and head).
    #[test]
    fn anchor_accepts_its_log_and_rejects_a_change(
        events in prop::collection::vec(arb_event(), 0..5),
        // Span the HMAC block size (64) so the key-hashing branch is exercised too.
        key in prop::collection::vec(any::<u8>(), 1..100),
        extra in arb_event(),
    ) {
        let anchor = anchor_head(&events, &key).expect("anchor");
        prop_assert!(verify_anchor(&events, &anchor, &key).expect("verify"));

        let mut changed = events.clone();
        changed.push(extra);
        prop_assert!(!verify_anchor(&changed, &anchor, &key).expect("verify"));
    }
}
