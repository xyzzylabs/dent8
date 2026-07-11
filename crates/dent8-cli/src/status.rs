//! The machine-readable outcome `status` shared by the CLI's `--output json` and the MCP tool
//! results, so the two surfaces cannot drift on the vocabulary a consumer branches on.
//!
//! One enum, one wire spelling. [`Status::as_str`] is the single source of truth; the
//! [`serde::Serialize`] impl and the `From<Status> for serde_json::Value` conversion both delegate
//! to it, so there is no second place a spelling could disagree.

/// A dent8 operation's outcome, as it appears in the top-level `status` field of every
/// `--output json` object and every MCP `structuredContent`.
///
/// Serializes to a stable lowercase `snake_case` string (e.g. `"integrity_issues"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    /// A read/verify/list/conflicts scan completed cleanly with nothing to flag.
    Ok,
    /// A write was admitted by the firewall.
    Accepted,
    /// A write was refused by the firewall (insufficient authority, contradiction of a
    /// canonical fact, or terminal immutability).
    Rejected,
    /// The request was malformed — bad input or a parse error that never reached the firewall.
    Invalid,
    /// A subject carries an unresolved contradiction: emitted by `conflicts` when disputes exist,
    /// and by a `contradict` write that records dissent.
    Contested,
    /// `verify` found a hash-chain or attestation integrity problem.
    IntegrityIssues,
    /// A read/audit command ran, but some runtime dependency could not be inspected.
    Degraded,
    /// An operational failure (I/O, backend) unrelated to any firewall decision.
    Failed,
}

impl Status {
    /// The stable wire string for this status. The one place the spelling is defined.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Invalid => "invalid",
            Self::Contested => "contested",
            Self::IntegrityIssues => "integrity_issues",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for Status {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl From<Status> for serde_json::Value {
    fn from(status: Status) -> Self {
        serde_json::Value::String(status.as_str().to_string())
    }
}

/// The machine-readable *reason* behind a non-`ok` outcome, as the top-level `code` field on
/// every `--output json` error object and MCP tool error. Where [`Status`] says *what happened*
/// (`rejected`), `ErrorCode` says *why* (`insufficient-authority`), so an agent branches on a
/// stable kebab-case token instead of parsing prose. Classified from the typed firewall errors
/// ([`dent8_store::StoreError`] / [`dent8_core::TransitionError`]) at the point where they are
/// formatted into a message — the prose and the code always describe the same cause.
///
/// The generic fallbacks (`rejected`, `invalid-argument`, `write-conflict`, `operation-failed`)
/// mirror their status: they are what a consumer sees when no finer cause is known, so checking
/// `code` alone is always safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorCode {
    // --- Generic fallbacks (one per error-shaped status) ---
    /// Malformed input or unusable configuration; no finer cause attached.
    InvalidArgument,
    /// Refused, with no finer cause attached.
    Rejected,
    /// A retryable concurrent-writer conflict that exhausted its retries.
    WriteConflict,
    /// An operational failure (I/O, backend) unrelated to any firewall decision.
    OperationFailed,
    /// An MCP `tools/call` named a tool this server does not serve.
    UnknownTool,
    // --- Per-fact firewall (dent8-core `TransitionError`) ---
    /// The event failed schema validation.
    InvalidEvent,
    /// A non-assertion event arrived for a fact with no initial assertion.
    MissingInitialAssertion,
    /// A second initial assertion for an already-asserted fact.
    DuplicateAssertion,
    /// The event's `fact_id` does not match the stream it was applied to.
    FactIdMismatch,
    /// The event's subject/predicate does not match the fact's.
    FactShapeMismatch,
    /// A reinforcement stated a different value than the fact it corroborates.
    ReinforcementValueMismatch,
    /// A write attempted to mutate a terminal (retracted/superseded/expired) fact.
    TerminalFact,
    /// The write's stated authority does not outrank the incumbent.
    InsufficientAuthority,
    /// The write contradicts a canonical fact — the hard alarm.
    CanonicalContradiction,
    // --- Store / subject-aware firewall + predicate policy (dent8-store `StoreError`) ---
    /// The backend is unreachable or refused the connection.
    StoreUnavailable,
    /// A persisted event failed integrity re-validation on load.
    CorruptEvent,
    /// The persisted stream no longer replays cleanly — an internally inconsistent log.
    ReplayFailed,
    /// The event could not be canonicalized for hashing.
    CanonicalizationFailed,
    /// A supersession whose *backing fact's* real authority is below the incumbent's
    /// (anti-laundering).
    LaunderedAuthority,
    /// A supersession naming a replacement fact that does not exist.
    UnbackedSupersession,
    /// The write's stated authority is below the predicate's registered floor.
    BelowAuthorityFloor,
    /// A second believed fact for a unique predicate (must supersede, not assert).
    UniquenessViolation,
    /// The requested TTL exceeds the predicate's retention ceiling.
    TtlCeilingExceeded,
    // --- CLI/MCP write-boundary gates ---
    /// The source asserted above its registered authority ceiling (or is unregistered under
    /// deny-by-default).
    AuthorityCeiling,
    /// The write subject is outside the source's granted scope.
    ScopeViolation,
    /// The signed-identity gate refused the write (bad/expired/revoked grant, key mismatch).
    IdentityRejected,
    /// A write reached the identity seam without a proven connection identity (daemon backstop).
    UnauthenticatedWrite,
    /// ADR 0017 entrenchment gate: the replacement has strictly weaker earned entrenchment
    /// than its incumbent.
    WeakerEntrenchment,
    /// The configured content-check scanner refused the write's value (docs/content-check.md).
    ContentRejected,
    /// The write was admitted but could not be durably committed.
    CommitFailed,
}

impl ErrorCode {
    /// The stable wire token for this code. The one place the spelling is defined.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid-argument",
            Self::Rejected => "rejected",
            Self::WriteConflict => "write-conflict",
            Self::OperationFailed => "operation-failed",
            Self::UnknownTool => "unknown-tool",
            Self::InvalidEvent => "invalid-event",
            Self::MissingInitialAssertion => "missing-initial-assertion",
            Self::DuplicateAssertion => "duplicate-assertion",
            Self::FactIdMismatch => "fact-id-mismatch",
            Self::FactShapeMismatch => "fact-shape-mismatch",
            Self::ReinforcementValueMismatch => "reinforcement-value-mismatch",
            Self::TerminalFact => "terminal-fact",
            Self::InsufficientAuthority => "insufficient-authority",
            Self::CanonicalContradiction => "canonical-contradiction",
            Self::StoreUnavailable => "store-unavailable",
            Self::CorruptEvent => "corrupt-event",
            Self::ReplayFailed => "replay-failed",
            Self::CanonicalizationFailed => "canonicalization-failed",
            Self::LaunderedAuthority => "laundered-authority",
            Self::UnbackedSupersession => "unbacked-supersession",
            Self::BelowAuthorityFloor => "below-authority-floor",
            Self::UniquenessViolation => "uniqueness-violation",
            Self::TtlCeilingExceeded => "ttl-ceiling-exceeded",
            Self::AuthorityCeiling => "authority-ceiling",
            Self::ScopeViolation => "scope-violation",
            Self::IdentityRejected => "identity-rejected",
            Self::UnauthenticatedWrite => "unauthenticated-write",
            Self::WeakerEntrenchment => "weaker-entrenchment",
            Self::ContentRejected => "content-rejected",
            Self::CommitFailed => "commit-failed",
        }
    }

    /// Every code, for the exhaustive wire-spelling test and the advertised MCP enum.
    pub(crate) const ALL: [Self; 30] = [
        Self::InvalidArgument,
        Self::Rejected,
        Self::WriteConflict,
        Self::OperationFailed,
        Self::UnknownTool,
        Self::InvalidEvent,
        Self::MissingInitialAssertion,
        Self::DuplicateAssertion,
        Self::FactIdMismatch,
        Self::FactShapeMismatch,
        Self::ReinforcementValueMismatch,
        Self::TerminalFact,
        Self::InsufficientAuthority,
        Self::CanonicalContradiction,
        Self::StoreUnavailable,
        Self::CorruptEvent,
        Self::ReplayFailed,
        Self::CanonicalizationFailed,
        Self::LaunderedAuthority,
        Self::UnbackedSupersession,
        Self::BelowAuthorityFloor,
        Self::UniquenessViolation,
        Self::TtlCeilingExceeded,
        Self::AuthorityCeiling,
        Self::ScopeViolation,
        Self::IdentityRejected,
        Self::UnauthenticatedWrite,
        Self::WeakerEntrenchment,
        Self::ContentRejected,
        Self::CommitFailed,
    ];

    /// Parse a wire token back into a code (the daemon client lifts codes out of tool replies).
    /// Unknown tokens return `None` so a newer server's code degrades to the caller's generic.
    // Only the Unix-socket daemon client consumes this; a file-only build has no daemon route.
    #[cfg_attr(not(all(unix, feature = "async-store")), allow(dead_code))]
    pub(crate) fn from_wire(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == token)
    }

    /// Classify a store-layer failure, descending into the nested per-fact firewall error.
    pub(crate) fn for_store_error(error: &dent8_store::StoreError) -> Self {
        use dent8_store::StoreError as S;
        match error {
            S::Conflict(_) => Self::WriteConflict,
            S::Unavailable(_) => Self::StoreUnavailable,
            S::CorruptEvent(_) => Self::CorruptEvent,
            S::Replay(_) => Self::ReplayFailed,
            S::Canonicalization(_) => Self::CanonicalizationFailed,
            S::Rejected(transition) => Self::for_transition_error(transition),
            S::LaunderedAuthority { .. } => Self::LaunderedAuthority,
            S::UnbackedSupersession(_) => Self::UnbackedSupersession,
            S::BelowAuthorityFloor { .. } => Self::BelowAuthorityFloor,
            S::UniquenessViolation { .. } => Self::UniquenessViolation,
            S::TtlCeilingExceeded { .. } => Self::TtlCeilingExceeded,
        }
    }

    /// Classify a per-fact firewall rejection.
    pub(crate) fn for_transition_error(error: &dent8_core::TransitionError) -> Self {
        use dent8_core::TransitionError as T;
        match error {
            T::InvalidEvent(_) => Self::InvalidEvent,
            T::MissingInitialAssertion => Self::MissingInitialAssertion,
            T::DuplicateAssertion => Self::DuplicateAssertion,
            T::FactIdMismatch => Self::FactIdMismatch,
            T::FactShapeMismatch => Self::FactShapeMismatch,
            T::ReinforcementValueMismatch => Self::ReinforcementValueMismatch,
            T::TerminalStateMutation(_) => Self::TerminalFact,
            T::InsufficientAuthority { .. } => Self::InsufficientAuthority,
            T::CanonicalContradiction => Self::CanonicalContradiction,
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorCode, Status};

    #[test]
    fn serialize_and_as_str_and_value_agree() {
        // The three representations must never diverge.
        for status in [
            Status::Ok,
            Status::Accepted,
            Status::Rejected,
            Status::Invalid,
            Status::Contested,
            Status::IntegrityIssues,
            Status::Degraded,
            Status::Failed,
        ] {
            let via_str = status.as_str();
            let via_serde = serde_json::to_value(status).expect("serialize");
            let via_into: serde_json::Value = status.into();
            assert_eq!(via_serde, serde_json::Value::String(via_str.to_string()));
            assert_eq!(via_into, via_serde);
            assert_eq!(status.to_string(), via_str);
        }
    }

    #[test]
    fn wire_spellings_are_the_documented_snake_case() {
        assert_eq!(Status::Ok.as_str(), "ok");
        assert_eq!(Status::Accepted.as_str(), "accepted");
        assert_eq!(Status::Rejected.as_str(), "rejected");
        assert_eq!(Status::Invalid.as_str(), "invalid");
        assert_eq!(Status::Contested.as_str(), "contested");
        assert_eq!(Status::IntegrityIssues.as_str(), "integrity_issues");
        assert_eq!(Status::Degraded.as_str(), "degraded");
        assert_eq!(Status::Failed.as_str(), "failed");
    }

    #[test]
    fn error_codes_are_unique_kebab_case_and_round_trip() {
        let mut seen = std::collections::BTreeSet::new();
        for code in ErrorCode::ALL {
            let token = code.as_str();
            assert!(
                token
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '-' || c.is_ascii_digit()),
                "{token} is not kebab-case"
            );
            assert!(seen.insert(token), "duplicate wire token {token}");
            assert_eq!(ErrorCode::from_wire(token), Some(code));
            assert_eq!(code.to_string(), token);
            assert_eq!(
                serde_json::to_value(code).expect("serialize"),
                serde_json::Value::String(token.to_string())
            );
        }
        assert_eq!(seen.len(), ErrorCode::ALL.len());
        assert_eq!(ErrorCode::from_wire("no-such-code"), None);
    }

    #[test]
    fn store_errors_classify_to_their_codes() {
        use dent8_core::TransitionError;
        use dent8_store::StoreError;
        assert_eq!(
            ErrorCode::for_store_error(&StoreError::Rejected(
                TransitionError::CanonicalContradiction
            )),
            ErrorCode::CanonicalContradiction
        );
        assert_eq!(
            ErrorCode::for_store_error(&StoreError::Conflict("race".into())),
            ErrorCode::WriteConflict
        );
        assert_eq!(
            ErrorCode::for_transition_error(&TransitionError::DuplicateAssertion),
            ErrorCode::DuplicateAssertion
        );
    }
}
