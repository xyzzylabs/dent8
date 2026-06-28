//! Canonical serialization and tamper-evident hashing for claim events.
//!
//! [`canonical_bytes`] produces a deterministic byte encoding of a [`ClaimEvent`] by
//! serializing through `serde_json`'s default (`BTreeMap`-backed) `Value`, which emits
//! object keys in sorted order and compact output. This is a sorted-key canonical form
//! produced by `serde_json`, **not RFC 8785 (JCS)**: keys sort by Rust `String` order (UTF-8 byte
//! order, whereas JCS uses UTF-16 code units) and the number/escape rules differ. The
//! two coincide here only because every *dent8* object key is an ASCII field/variant name
//! and every *dent8* number is an integer (`Confidence` is `u16`, `TimestampMillis` is
//! `i64`). No dent8 field may introduce a non-ASCII or dynamic object key without bumping
//! [`CANON_VERSION`] and revisiting this. (Embedded JSON inside `ClaimValue::Json` is
//! exempt: its keys *may* be non-ASCII/dynamic and its numbers `f64` — they are sorted and
//! emitted deterministically and idempotently, enough for the hash chain, but not in JCS
//! order; see [`crate::model::CanonicalJson`].) See
//! `docs/decisions/0004-canonicalization-and-hash-chain.md`.
//!
//! The "logically-equal events produce identical bytes" invariant holds for every field,
//! **including** `ClaimValue::Json`: that variant is [`crate::model::CanonicalJson`], which
//! is canonical by construction (parsed and re-emitted with sorted keys and no whitespace,
//! re-applied on deserialize), so two semantically-equal JSON blobs that differ only in key
//! order or whitespace hash identically (ADR 0004 item 6, resolved).
//!
//! [`event_hash`] chains events with an **injective, length-framed** leaf encoding —
//! `SHA-256(0x00 || version || len(canonical) || canonical || tag || prev_digest)` —
//! with RFC 6962-style domain separation (a `0x00` leaf prefix). Length-prefixing the
//! canonical bytes and tagging the genesis case mean no two distinct `(canonical,
//! previous)` pairs can share a hash input, so the log is tamper-evident: altering any
//! event changes its hash and every later one.

use sha2::{Digest, Sha256};

use crate::model::ClaimEvent;

/// Version of the canonical encoding. Bump on any change to the serialized shape so
/// hashes from different schema versions never collide. Mixed into every leaf hash.
/// (This is dent8's `schema_version`, realized as an out-of-band constant rather than
/// a per-event field — see ADR 0004 item 7.)
pub const CANON_VERSION: u8 = 1;

/// Domain-separation prefix for a leaf (event) hash, RFC 6962 style. Interior/Merkle
/// nodes would use `0x01`, reserved for a future inclusion/consistency-proof layer.
const LEAF_PREFIX: u8 = 0x00;

/// Byte width of a SHA-256 digest.
const DIGEST_LEN: usize = 32;

/// Canonical, deterministic byte encoding of a claim event: two logically-equal events
/// produce identical bytes regardless of struct field order, map ordering, or — for a
/// `ClaimValue::Json` value — the embedded JSON's key order and whitespace.
pub fn canonical_bytes(event: &ClaimEvent) -> Result<Vec<u8>, CanonError> {
    // Route through a Value so object keys are emitted in sorted order (serde_json's
    // default Map is BTreeMap-backed); to_vec is compact (no insignificant whitespace).
    let value = serde_json::to_value(event).map_err(CanonError::Serialize)?;
    serde_json::to_vec(&value).map_err(CanonError::Serialize)
}

/// The tamper-evident hash of an event, chained to `previous` (the prior event's hash
/// as lowercase hex, or `None` for the first event in a stream). Returns lowercase hex
/// of a SHA-256. Errors if `previous` is not a valid 64-char hex digest.
pub fn event_hash(event: &ClaimEvent, previous: Option<&str>) -> Result<String, CanonError> {
    let canonical = canonical_bytes(event)?;
    let previous = previous.map(decode_digest).transpose()?;
    Ok(hash_leaf(&canonical, previous.as_ref()))
}

/// Decode a lowercase-hex SHA-256 digest into its 32 raw bytes, rejecting any string
/// that is not exactly a 64-char hex digest (including the empty string).
fn decode_digest(hex_str: &str) -> Result<[u8; DIGEST_LEN], CanonError> {
    let mut out = [0u8; DIGEST_LEN];
    hex::decode_to_slice(hex_str, &mut out)
        .map_err(|_| CanonError::InvalidPreviousHash(hex_str.to_string()))?;
    Ok(out)
}

/// Injective, length-framed leaf hash over already-canonical bytes. The genesis case
/// (`previous = None`, tag `0x00`) and any chained case (tag `0x01` + 32-byte digest)
/// are unambiguous, and `len(canonical)` removes any `canonical || previous` framing
/// ambiguity.
#[must_use]
fn hash_leaf(canonical: &[u8], previous: Option<&[u8; DIGEST_LEN]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX, CANON_VERSION]);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    match previous {
        None => hasher.update([0u8]),
        Some(previous) => {
            hasher.update([1u8]);
            hasher.update(previous);
        }
    }
    hex::encode(hasher.finalize())
}

/// Compute the hash chain for an ordered event stream: each event's hash links to the
/// previous one. Returns one hash per event, in order. Altering any event changes its
/// hash and every subsequent hash, so a stored chain can be reverified on replay.
pub fn hash_chain(events: &[ClaimEvent]) -> Result<Vec<String>, CanonError> {
    let mut hashes = Vec::with_capacity(events.len());
    let mut previous: Option<String> = None;
    for event in events {
        let hash = event_hash(event, previous.as_deref())?;
        previous = Some(hash.clone());
        hashes.push(hash);
    }
    Ok(hashes)
}

/// Failure to canonicalize or hash an event. Distinct from invalid events, which are
/// rejected earlier by validation.
#[derive(Debug)]
pub enum CanonError {
    /// The event could not be serialized to canonical bytes.
    Serialize(serde_json::Error),
    /// A supplied previous-event hash was not a valid 64-char hex digest.
    InvalidPreviousHash(String),
}

impl std::fmt::Display for CanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialize(error) => write!(f, "canonicalization failed: {error}"),
            Self::InvalidPreviousHash(value) => {
                write!(f, "previous hash is not a 64-char hex digest: {value:?}")
            }
        }
    }
}

impl std::error::Error for CanonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialize(error) => Some(error),
            Self::InvalidPreviousHash(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonError, canonical_bytes, event_hash, hash_chain};
    use crate::ids::{ActorId, ClaimEventId, ClaimId, EvidenceId, SourceId, TimestampMillis};
    use crate::model::{
        Authority, AuthorityLevel, ClaimEvent, ClaimEventKind, ClaimValue, Confidence, EntityRef,
        Evidence, EvidenceKind, Predicate, Provenance, SupersessionReason, Ttl,
    };

    fn event(event_id: &str, kind: ClaimEventKind, value: Option<ClaimValue>) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).expect("event id"),
            claim_id: ClaimId::new("claim:1").expect("claim id"),
            kind,
            subject: EntityRef::new("repo", "dent8").expect("entity"),
            predicate: Predicate::new("uses_database").expect("predicate"),
            value,
            confidence: Confidence::from_millis(900).expect("confidence"),
            authority: Authority {
                level: AuthorityLevel::High,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:test").expect("source"),
                actor: ActorId::new("actor:test").expect("actor"),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(1),
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

    fn asserted(event_id: &str) -> ClaimEvent {
        event(
            event_id,
            ClaimEventKind::Asserted,
            Some(ClaimValue::Text("postgres".to_string())),
        )
    }

    #[test]
    fn canonicalization_is_deterministic() {
        let e = asserted("event:1");
        assert_eq!(canonical_bytes(&e).unwrap(), canonical_bytes(&e).unwrap());
    }

    #[test]
    fn canonicalization_is_key_order_independent() {
        // `to_vec(&event)` serializes struct fields in DECLARATION order (event_id
        // first), which is not alphabetical; `canonical_bytes` sorts keys. The two must
        // therefore differ — and a differently-ordered document must canonicalize to
        // the same bytes. The inequality also fails loudly if serde_json's
        // `preserve_order` feature is ever unified ON, breaking determinism.
        let e = asserted("event:1");
        let declaration_order = serde_json::to_vec(&e).expect("serialize");
        let canonical = canonical_bytes(&e).expect("canonicalize");
        assert_ne!(
            declaration_order, canonical,
            "to_value did not reorder keys"
        );

        let reparsed: ClaimEvent = serde_json::from_slice(&declaration_order).expect("deserialize");
        assert_eq!(
            canonical_bytes(&reparsed).expect("re-canonicalize"),
            canonical
        );
    }

    #[test]
    fn embedded_json_is_canonicalized_so_equal_values_hash_equally() {
        let json_event = |raw: &str| {
            event(
                "event:1",
                ClaimEventKind::Asserted,
                Some(ClaimValue::json(raw).expect("valid json")),
            )
        };
        // Same JSON, different key order *and* whitespace.
        let a = json_event("{ \"b\": 2, \"a\": 1 }");
        let b = json_event("{\"a\":1,\n  \"b\":2}");
        assert_eq!(canonical_bytes(&a).unwrap(), canonical_bytes(&b).unwrap());
        assert_eq!(event_hash(&a, None).unwrap(), event_hash(&b, None).unwrap());

        // A genuinely different value must still hash differently.
        let c = json_event(r#"{"a": 2, "b": 1}"#);
        assert_ne!(event_hash(&a, None).unwrap(), event_hash(&c, None).unwrap());
    }

    #[test]
    fn a_float_json_event_survives_a_serde_round_trip_unchanged() {
        // Regression for the float-idempotency bug: the re-canonicalizing Deserialize must
        // not alter a legitimately-written float value, or replay/reload would false-alarm
        // the hash chain. `13e300` is one of the ~10% of f64 values that drifts without the
        // `float_roundtrip` feature.
        let e = event(
            "event:1",
            ClaimEventKind::Asserted,
            Some(ClaimValue::json(r#"{"ratio": 13e300, "p": 0.1}"#).expect("json")),
        );
        let original = canonical_bytes(&e).expect("canonicalize");
        let reloaded: ClaimEvent = serde_json::from_slice(&original).expect("deserialize");
        assert_eq!(
            canonical_bytes(&reloaded).expect("re-canonicalize"),
            original
        );
        assert_eq!(
            event_hash(&reloaded, None).unwrap(),
            event_hash(&e, None).unwrap()
        );
    }

    #[test]
    fn canonicalization_round_trips_through_serde() {
        // canonicalize(deserialize(canonicalize(e))) == canonicalize(e)
        let e = asserted("event:1");
        let bytes = canonical_bytes(&e).expect("canonicalize");
        let decoded: ClaimEvent = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(decoded, e);
        assert_eq!(canonical_bytes(&decoded).expect("re-canonicalize"), bytes);
    }

    #[test]
    fn distinct_events_hash_differently() {
        let a = event_hash(&asserted("event:1"), None).unwrap();
        let b = event_hash(&asserted("event:2"), None).unwrap();
        assert_ne!(a, b);
        // A SHA-256 hex digest is 64 chars.
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn genesis_is_unambiguous_and_previous_is_validated() {
        let e = asserted("event:1");
        // A genesis hash (no previous) is well-defined and 64 hex chars.
        let genesis = event_hash(&e, None).unwrap();
        assert_eq!(genesis.len(), 64);
        // An empty or malformed previous is rejected, not silently treated as genesis —
        // this is what makes the leaf encoding injective.
        assert!(matches!(
            event_hash(&e, Some("")),
            Err(CanonError::InvalidPreviousHash(_))
        ));
        assert!(matches!(
            event_hash(&e, Some("not-hex")),
            Err(CanonError::InvalidPreviousHash(_))
        ));
        // A valid predecessor links cleanly and changes the hash.
        let chained = event_hash(&e, Some(&genesis)).unwrap();
        assert_ne!(genesis, chained);
    }

    #[test]
    fn the_chain_links_each_event_to_the_previous() {
        let first = asserted("event:1");
        let second = event(
            "event:2",
            ClaimEventKind::Superseded {
                by: ClaimId::new("claim:2").expect("claim id"),
                reason: SupersessionReason::NewerObservation,
            },
            None,
        );

        let unchained = event_hash(&second, None).unwrap();
        let chained = event_hash(&second, Some(&event_hash(&first, None).unwrap())).unwrap();
        assert_ne!(unchained, chained);
    }

    #[test]
    fn tampering_with_an_event_breaks_the_chain_from_that_point() {
        let events = [
            asserted("event:1"),
            asserted("event:2"),
            asserted("event:3"),
        ];
        let original = hash_chain(&events).expect("chain");

        // Tamper with the middle event only.
        let tampered = [
            asserted("event:1"),
            asserted("event:CHANGED"),
            asserted("event:3"),
        ];
        let recomputed = hash_chain(&tampered).expect("chain");

        assert_eq!(recomputed[0], original[0]); // before the tamper: unchanged
        assert_ne!(recomputed[1], original[1]); // the tampered event
        assert_ne!(recomputed[2], original[2]); // and everything after cascades
    }
}
