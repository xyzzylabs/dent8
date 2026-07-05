use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::{ActorId, EvidenceId, FactEventId, FactId, SourceId, TimestampMillis};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct EntityRef {
    kind: String,
    key: String,
}

impl EntityRef {
    pub fn new(kind: impl Into<String>, key: impl Into<String>) -> Result<Self, ValidationError> {
        let kind = kind.into();
        let key = key.into();
        if kind.trim().is_empty() {
            return Err(ValidationError::EmptyField("entity.kind"));
        }
        if key.trim().is_empty() {
            return Err(ValidationError::EmptyField("entity.key"));
        }
        Ok(Self { kind, key })
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Predicate(String);

impl Predicate {
    pub fn new(value: impl Into<String>) -> Result<Self, ValidationError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ValidationError::EmptyField("predicate"));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// JSON held in **canonical form** — parsed and re-emitted with sorted object keys and no
/// insignificant whitespace — so two semantically-equal JSON values share identical bytes
/// and therefore identical hashes ([ADR 0004](../../docs/decisions/0004-canonicalization-and-hash-chain.md)
/// item 6). The inner form is an invariant: there is no way to construct a non-canonical
/// value. Build via [`FactValue::json`] / [`CanonicalJson::new`]; the canonicalization is
/// re-applied on deserialize, so the invariant also holds on the trusted-reload path.
///
/// **Number model.** Numbers follow `serde_json`'s `f64`/`i64`/`u64` model, not JCS:
/// floats are normalized to their shortest round-tripping form (the `float_roundtrip`
/// feature, which keeps canonicalization idempotent), but a JSON integer beyond `u64`
/// range or a high-precision decimal is parsed as `f64` and **loses precision on the first
/// canonicalization** (e.g. `18446744073709551616` → `1.8446744073709552e19`). Pass such
/// values as JSON *strings* if exact preservation matters. This is idempotent after the
/// first pass (so it never trips the hash chain), but it is lossy — consistent with the
/// "not JCS" caveat in [`crate::hash`].
///
/// **Keys.** Object keys are sorted by Rust `String` (UTF-8 byte) order at every depth.
/// Embedded JSON may legitimately contain non-ASCII/dynamic keys; the ordering is
/// deterministic and idempotent (sufficient for dent8's hash chain) but, like the rest of
/// the encoding, is **not** JCS's UTF-16 ordering.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CanonicalJson(String);

impl CanonicalJson {
    /// Parse `raw` and re-emit it in canonical form. Errors if `raw` is not valid JSON.
    ///
    /// Canonicalization routes through `serde_json`'s default (`BTreeMap`-backed) `Value`,
    /// which sorts object keys and drops whitespace — the same canonical form
    /// [`crate::hash::canonical_bytes`] relies on, and idempotent on already-canonical input.
    pub fn new(raw: &str) -> Result<Self, ValidationError> {
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|error| ValidationError::InvalidJson(error.to_string()))?;
        let canonical = serde_json::to_string(&value)
            .map_err(|error| ValidationError::InvalidJson(error.to_string()))?;
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CanonicalJson {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Re-canonicalize on load so a hand-edited or legacy non-canonical value cannot
        // re-enter as canonical; idempotent for a value written through `new`.
        let raw = String::deserialize(deserializer)?;
        Self::new(&raw).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FactValue {
    Text(String),
    Json(CanonicalJson),
    Redacted,
}

impl FactValue {
    /// A canonical JSON fact value (see [`CanonicalJson`]). Errors on invalid JSON.
    pub fn json(raw: &str) -> Result<Self, ValidationError> {
        Ok(Self::Json(CanonicalJson::new(raw)?))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct Confidence(u16);

impl Confidence {
    pub const MAX: u16 = 1_000;

    /// The minimum confidence. Used as the identity confidence floor in
    /// [`crate::policy::EpistemicPolicy`].
    pub const ZERO: Self = Self(0);

    /// The confidence a fresh assertion carries (0.9). High but not certain, leaving headroom for
    /// corroboration. This is the common construction, so it is a named infallible constant
    /// rather than `from_millis(900).unwrap()` repeated at every call site.
    pub const ASSERTED: Self = Self(900);

    pub fn from_millis(value: u16) -> Result<Self, ValidationError> {
        if value > Self::MAX {
            return Err(ValidationError::ConfidenceOutOfRange(value));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn as_millis(self) -> u16 {
        self.0
    }
}

impl Default for Confidence {
    /// A fresh assertion's confidence ([`Confidence::ASSERTED`]).
    fn default() -> Self {
        Self::ASSERTED
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorityLevel {
    Unknown,
    Low,
    Medium,
    High,
    Canonical,
}

impl AuthorityLevel {
    /// The stable lowercase name for the level, matching both its serde representation and the
    /// CLI/MCP input spelling (`--authority high`), so a level round-trips: what you write is what
    /// you read back. Use this — not `format!("{self:?}")` — anywhere the name is persisted or
    /// becomes a query key (e.g. the Parquet export's `authority` column).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Canonical => "canonical",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Authority {
    pub level: AuthorityLevel,
    pub issuer: Option<String>,
    pub scope: Option<String>,
}

impl Authority {
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            level: AuthorityLevel::Unknown,
            issuer: None,
            scope: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Ttl {
    Never,
    ExpiresAt(TimestampMillis),
    DurationMillis(u64),
}

impl Ttl {
    /// The absolute instant at which this TTL elapses, anchored at `anchor`, if ever.
    ///
    /// `Never` has no expiry. A `DurationMillis` whose `anchor + duration` is not
    /// representable in `i64` milliseconds (durations beyond ~292 million years)
    /// returns `None` and is therefore treated as non-expiring — a deliberate,
    /// fail-open choice for an unreachable boundary.
    #[must_use]
    pub fn expires_at(&self, anchor: TimestampMillis) -> Option<TimestampMillis> {
        match self {
            Self::Never => None,
            Self::ExpiresAt(at) => Some(*at),
            Self::DurationMillis(duration) => i64::try_from(*duration)
                .ok()
                .and_then(|duration| anchor.as_unix_millis().checked_add(duration))
                .map(TimestampMillis::from_unix_millis),
        }
    }

    #[must_use]
    pub fn is_expired_at(&self, anchor: TimestampMillis, now: TimestampMillis) -> bool {
        self.expires_at(anchor)
            .is_some_and(|expires_at| expires_at <= now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub source: SourceId,
    pub actor: ActorId,
    pub tool: Option<String>,
    pub run_id: Option<String>,
    pub input_digest: Option<String>,
    pub recorded_at: TimestampMillis,
    /// Optional signed write attestation (ADR 0013): the writer's persisted proof that the
    /// holder of `public_key` signed this event's content. `None` (the pre-attestation
    /// default) is **skipped during serialization**, so events written before this field
    /// existed keep byte-identical canonical form and their stored hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<WriteAttestation>,
}

/// A per-write source signature carried inside [`Provenance`] (ADR 0013). The signed message
/// is [`crate::attestation_message`] — the domain-framed canonical bytes of the event with
/// `attestation` stripped — so any holder of `public_key` can re-verify offline that the
/// event content is exactly what the source key signed. The hash chain covers the attestation
/// bytes themselves, so the attestation is as tamper-evident as the rest of the event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WriteAttestation {
    pub algorithm: AttestationAlgorithm,
    /// The source's Ed25519 verifying key, lowercase hex (32 bytes).
    pub public_key: String,
    /// Signature over [`crate::attestation_message`], lowercase hex (64 bytes).
    pub signature: String,
}

/// The attestation signature scheme. A closed enum (not a free string) so an unknown or
/// misspelled algorithm fails loudly at deserialize time instead of silently "verifying".
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AttestationAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EvidenceKind {
    DirectObservation,
    ToolOutput,
    FileSpan,
    UserStatement,
    DerivedSummary,
    ExternalDocument,
    /// The fact was **derived from another fact**: the [`Evidence::locator`] holds the
    /// source `fact:` id (ADR 0010). These items form the fact->fact dependency graph that
    /// retraction-taint analysis walks (poison must not survive in its derivatives).
    DerivedFrom,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub kind: EvidenceKind,
    pub locator: String,
    pub digest: Option<String>,
    pub summary: Option<String>,
}

impl FactEvent {
    /// The fact ids this event was **derived from** — its [`EvidenceKind::DerivedFrom`]
    /// evidence items, whose `locator` is the source `fact:` id (ADR 0010). A malformed
    /// locator is skipped (it simply contributes no edge), so this never fails.
    #[must_use]
    pub fn dependency_edges(&self) -> Vec<FactId> {
        self.evidence
            .iter()
            .filter(|item| item.kind == EvidenceKind::DerivedFrom)
            .filter_map(|item| FactId::new(item.locator.clone()).ok())
            .collect()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ContradictionBasis {
    SamePredicateDifferentValue,
    MutuallyExclusivePredicate,
    AuthorityChallenge,
    FreshnessChallenge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SupersessionReason {
    NewerObservation,
    HigherAuthority,
    UserCorrection,
    SchemaMigration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ExpirationReason {
    TtlElapsed,
    PolicyRetention,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RetractionReason {
    SourceInvalidated,
    PoisoningDetected,
    UserDeleted,
    PolicyViolation,
}

/// What kind of write the incumbent was challenged by (ADR 0015). Only challenges that
/// were real contests lost on strength are recorded — see [`ChallengeRejection`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChallengeKind {
    Supersession,
    Contradiction,
    Retraction,
    Expiration,
}

/// Why the firewall rejected the challenge (ADR 0015). These are the strength-based
/// rejections; malformed writes, duplicates, and terminal-state mutations are not
/// "survived" challenges and are never recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChallengeRejection {
    /// The challenge's stated authority was below the incumbent's.
    InsufficientAuthority,
    /// The supersession stated enough authority, but its backing fact was actually
    /// weaker (the entity-aware anti-laundering check).
    LaunderedAuthority,
    /// A contradiction against a canonical incumbent (the LFI hard-alarm).
    CanonicalContradiction,
    /// An equal-authority supersession whose backing fact had strictly weaker
    /// authority-weighted corroboration (the earned-supersession gate, opt-in). Superseded
    /// by [`Self::WeakerEntrenchment`] as of ADR 0017; kept so pre-0.3 challenge-rejected
    /// events still deserialize.
    WeakerCorroboration,
    /// An equal-authority supersession whose challenger had strictly weaker **earned
    /// entrenchment** — corroboration plus survived challenges — than the incumbent
    /// (the earned-supersession gate, opt-in; ADR 0017).
    WeakerEntrenchment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FactEventKind {
    Asserted,
    Reinforced {
        by: FactId,
    },
    Contradicted {
        by: FactId,
        basis: ContradictionBasis,
    },
    Superseded {
        by: FactId,
        reason: SupersessionReason,
    },
    Expired {
        reason: ExpirationReason,
    },
    Retracted {
        reason: RetractionReason,
    },
    Retrieved {
        purpose: String,
    },
    UsedInDecision {
        decision_id: String,
    },
    /// A challenge against this fact was rejected by the firewall (ADR 0015). Written to
    /// the **incumbent's** stream with the **challenger's** provenance and *effective*
    /// authority, so surviving it is replayable, attributed entrenchment evidence.
    ChallengeRejected {
        challenge: ChallengeKind,
        /// The challenging fact, when the challenge named one (a supersession's
        /// replacement, a contradiction's contradictor).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        by: Option<FactId>,
        rejection: ChallengeRejection,
    },
}

impl FactEventKind {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Asserted => "fact.asserted",
            Self::Reinforced { .. } => "fact.reinforced",
            Self::Contradicted { .. } => "fact.contradicted",
            Self::Superseded { .. } => "fact.superseded",
            Self::Expired { .. } => "fact.expired",
            Self::Retracted { .. } => "fact.retracted",
            Self::Retrieved { .. } => "fact.retrieved",
            Self::UsedInDecision { .. } => "fact.used_in_decision",
            Self::ChallengeRejected { .. } => "fact.challenge_rejected",
        }
    }

    #[must_use]
    pub const fn is_lifecycle_terminal(&self) -> bool {
        matches!(
            self,
            Self::Superseded { .. } | Self::Expired { .. } | Self::Retracted { .. }
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FactEvent {
    pub event_id: FactEventId,
    pub fact_id: FactId,
    pub kind: FactEventKind,
    pub subject: EntityRef,
    pub predicate: Predicate,
    pub value: Option<FactValue>,
    pub confidence: Confidence,
    pub authority: Authority,
    pub ttl: Ttl,
    pub provenance: Provenance,
    pub evidence: Vec<Evidence>,
    pub observed_at: Option<TimestampMillis>,
    pub valid_from: Option<TimestampMillis>,
    /// Valid-time upper bound (ADR 0016): the instant this fact is asserted to stop
    /// holding. Read-time freshness treats it like an elapsed TTL. `None` (the
    /// pre-interval default) is **skipped during serialization**, so events written
    /// before this field existed keep byte-identical canonical form and their stored
    /// hashes (the ADR 0013 optional-field rule; unlike `observed_at`/`valid_from`,
    /// which predate it and serialize as explicit nulls).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<TimestampMillis>,
}

impl FactEvent {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if let (Some(from), Some(to)) = (self.valid_from, self.valid_to)
            && to <= from
        {
            return Err(ValidationError::InvalidValidityInterval);
        }
        match &self.kind {
            FactEventKind::Asserted if self.value.is_none() => {
                Err(ValidationError::MissingFactValue)
            }
            FactEventKind::Asserted if self.evidence.is_empty() => {
                Err(ValidationError::MissingEvidence)
            }
            FactEventKind::Retrieved { purpose } if purpose.trim().is_empty() => {
                Err(ValidationError::EmptyField("retrieval.purpose"))
            }
            FactEventKind::UsedInDecision { decision_id } if decision_id.trim().is_empty() => {
                Err(ValidationError::EmptyField("decision_id"))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ValidationError {
    EmptyField(&'static str),
    ConfidenceOutOfRange(u16),
    MissingFactValue,
    MissingEvidence,
    InvalidJson(String),
    /// `valid_to` at or before `valid_from` — an empty or inverted validity interval.
    InvalidValidityInterval,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "{field} cannot be empty"),
            Self::ConfidenceOutOfRange(value) => {
                write!(f, "confidence {value} is outside 0..=1000")
            }
            Self::MissingFactValue => f.write_str("asserted facts must include a value"),
            Self::MissingEvidence => f.write_str("asserted facts must include evidence"),
            Self::InvalidJson(error) => write!(f, "invalid JSON fact value: {error}"),
            Self::InvalidValidityInterval => {
                f.write_str("valid_to must be after valid_from (non-empty validity interval)")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

#[cfg(test)]
mod tests {
    use super::{CanonicalJson, FactValue, ValidationError};

    #[test]
    fn canonical_json_sorts_keys_and_strips_whitespace() {
        let c = CanonicalJson::new("{ \"b\": 2, \"a\": 1 }").expect("valid json");
        assert_eq!(c.as_str(), r#"{"a":1,"b":2}"#);
    }

    #[test]
    fn canonical_json_is_idempotent() {
        let once = CanonicalJson::new(r#"{"b":2,"a":1}"#).expect("valid json");
        let twice = CanonicalJson::new(once.as_str()).expect("valid json");
        assert_eq!(once, twice);
    }

    #[test]
    fn float_canonicalization_is_idempotent_through_reload() {
        // `serde_json`'s `float_roundtrip` feature makes f64 parse to its shortest round-trip
        // form, so canonicalization is idempotent for floats. Without it, values like 13e300
        // drift on the second pass and the re-canonicalizing Deserialize would change a
        // legitimately-written value on reload — a false hash-chain tamper alarm.
        for raw in [
            r#"{"x":13e300}"#,
            r#"{"x":17e300}"#,
            r#"{"x":37e-300}"#,
            r#"{"a":0.1,"b":1.0,"c":-0.5,"d":1e10}"#,
        ] {
            let once = CanonicalJson::new(raw).expect("valid json");
            let twice = CanonicalJson::new(once.as_str()).expect("valid json");
            assert_eq!(once, twice, "not idempotent: {raw}");

            // The reload path (custom Deserialize re-canonicalizes) must not change it.
            let value = FactValue::Json(once.clone());
            let bytes = serde_json::to_string(&value).expect("serialize");
            let reloaded: FactValue = serde_json::from_str(&bytes).expect("deserialize");
            assert_eq!(value, reloaded, "reload changed the value: {raw}");
        }
    }

    #[test]
    fn semantically_equal_json_is_equal_regardless_of_form() {
        let a = FactValue::json("{ \"b\": 2, \"a\": 1 }").expect("valid json");
        let b = FactValue::json(r#"{"a":1,"b":2}"#).expect("valid json");
        assert_eq!(a, b);
    }

    #[test]
    fn invalid_json_is_rejected() {
        let error = FactValue::json("{not json").unwrap_err();
        assert!(matches!(error, ValidationError::InvalidJson(_)));
    }

    #[test]
    fn oversized_integers_are_lossy_but_idempotent() {
        // Documented limitation: a JSON integer beyond u64 is parsed as f64 (lossy), so the
        // canonical form differs from the input — but it is stable thereafter, so it never
        // trips the hash chain on reload.
        let raw = r#"{"n":18446744073709551616}"#;
        let once = CanonicalJson::new(raw).expect("valid json");
        assert_ne!(
            once.as_str(),
            raw,
            "an out-of-u64-range integer is reformatted as f64"
        );
        let twice = CanonicalJson::new(once.as_str()).expect("valid json");
        assert_eq!(once, twice, "but canonicalization is idempotent thereafter");
    }

    #[test]
    fn deserialize_recanonicalizes_a_non_canonical_stored_value() {
        // A hand-edited or legacy non-canonical encoding is re-canonicalized on load, so
        // the canonical invariant holds even off the constructor path.
        let loaded: FactValue =
            serde_json::from_str(r#"{"Json":"{ \"b\": 2, \"a\": 1 }"}"#).expect("load");
        assert_eq!(loaded, FactValue::json(r#"{"a":1,"b":2}"#).unwrap());
    }

    #[test]
    fn deserialize_rejects_invalid_embedded_json() {
        let result: Result<FactValue, _> = serde_json::from_str(r#"{"Json":"{not json"}"#);
        assert!(result.is_err());
    }
}
