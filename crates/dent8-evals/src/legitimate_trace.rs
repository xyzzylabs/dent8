//! Human-reviewed legitimate-traffic traces.
//!
//! A persisted dent8 event log contains only admitted writes, so replaying it and claiming a
//! zero false-positive rate would be circular. This module instead consumes annotated
//! **attempted operation batches**. Every operation is explicitly reviewed as legitimate and
//! expected to be admitted, then replayed atomically through the real store-level firewall.
//! Fact values are never copied into the report.

use std::collections::BTreeSet;
use std::fmt;

use dent8_core::{FactEvent, TransitionError};
use dent8_store::{EventStore, InMemoryEventStore, PredicateRegistry, StoreError, enforce_policy};
use serde::{Deserialize, Serialize};

/// Exact schema identifier for annotated legitimate-traffic traces.
pub const LEGITIMATE_TRACE_SCHEMA: &str = "dent8.legitimate-trace/1";
const RAW_CONTENT_WARNING: &str =
    "trace is marked raw; keep the source file local and do not publish it";

/// Whether the trace came from an observed agent session or is authored test material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceOrigin {
    Captured,
    Synthetic,
}

impl TraceOrigin {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::Synthetic => "synthetic",
        }
    }
}

/// Explicit privacy classification for the event values embedded in a trace.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceContent {
    /// Values and locators were reviewed and redacted or pseudonymized before sharing.
    Redacted,
    /// The trace may contain unredacted session content and should stay local.
    Raw,
}

impl TraceContent {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Redacted => "redacted",
            Self::Raw => "raw",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceProvenance {
    pub origin: TraceOrigin,
    /// Agent or integration that produced the attempted writes (`codex`, `claude-code`, ...).
    pub agent: String,
    /// Optional pseudonymous session identifier. Never required to be globally identifying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TracePrivacy {
    pub content: TraceContent,
    /// Human-readable redaction note. Reports deliberately do not echo it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceReview {
    /// Human or review process that classified every operation in this trace as legitimate.
    pub reviewer: String,
    /// Why these writes are expected legitimate traffic. Reports deliberately do not echo it.
    pub basis: String,
}

/// The only valid expectation in a legitimate-traffic trace. Keeping it explicit on every
/// operation prevents an accidental mixture of attack and benign labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceExpectation {
    Admit,
}

/// Closed operation vocabulary. Replay uses it to select the same predicate-policy seam as the
/// live operation, so a review edit cannot bypass policy by inventing an operation string.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TraceOperationKind {
    Assert,
    Derive,
    Supersede,
    Retract,
    Reinforce,
    Expire,
    Contradict,
    UsedInDecision,
    RecordRetrievals,
    /// Synthetic unit fixtures that intentionally isolate the base store firewall.
    StoreAppend,
}

impl TraceOperationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assert => "assert",
            Self::Derive => "derive",
            Self::Supersede => "supersede",
            Self::Retract => "retract",
            Self::Reinforce => "reinforce",
            Self::Expire => "expire",
            Self::Contradict => "contradict",
            Self::UsedInDecision => "used-in-decision",
            Self::RecordRetrievals => "record-retrievals",
            Self::StoreAppend => "store-append",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegitimateTraceOperation {
    pub operation_id: String,
    /// Stable write operation name (`assert`, `supersede`, ...), used to replay the same
    /// predicate-policy seam as the operational path.
    pub operation: TraceOperationKind,
    pub expected: TraceExpectation,
    /// Already-admitted store state immediately before this operation. The baseline is
    /// trusted setup and is not counted or re-arbitrated by the eval.
    #[serde(default)]
    pub baseline_events: Vec<FactEvent>,
    /// The exact event batch attempted by one logical operation. Multi-event writes are
    /// evaluated atomically: all events land or none do.
    pub events: Vec<FactEvent>,
}

/// A human-reviewed trace of attempted legitimate writes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegitimateTrace {
    pub schema: String,
    pub trace_id: String,
    pub provenance: TraceProvenance,
    pub privacy: TracePrivacy,
    pub review: TraceReview,
    pub operations: Vec<LegitimateTraceOperation>,
}

/// One operation's privacy-safe eval result. Event values, notes, evidence locators, and error
/// strings are intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TraceOperationResult {
    pub operation_id: String,
    pub event_count: usize,
    pub admitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_category: Option<&'static str>,
}

/// Aggregate result for one annotated trace. A false positive is an expected-admit operation
/// whose atomic event batch the firewall rejected.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LegitimateTraceReport {
    pub trace_id: String,
    pub origin: TraceOrigin,
    pub agent: String,
    pub content: TraceContent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privacy_warning: Option<&'static str>,
    pub operation_count: usize,
    pub event_count: usize,
    pub admitted_operations: usize,
    pub admitted_events: usize,
    pub false_positives: usize,
    pub operations: Vec<TraceOperationResult>,
}

impl LegitimateTraceReport {
    #[must_use]
    pub fn clean(&self) -> bool {
        self.false_positives == 0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceError(String);

impl TraceError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TraceError {}

/// Parse and structurally validate a trace. Duplicate operation/event ids are malformed
/// evidence, not false positives, and are rejected before evaluation.
pub fn parse_legitimate_trace(input: &str) -> Result<LegitimateTrace, TraceError> {
    let trace: LegitimateTrace = serde_json::from_str(input)
        .map_err(|error| TraceError::invalid(format!("invalid trace JSON: {error}")))?;
    validate_trace(&trace)?;
    Ok(trace)
}

/// Replay an annotated trace through the same store-level firewall as the built-in corpus.
/// Each operation starts from its independent trusted baseline and evaluates its batch in a
/// disposable store, matching the all-or-nothing semantics of operational multi-event writes.
pub fn evaluate_legitimate_trace(
    trace: &LegitimateTrace,
) -> Result<LegitimateTraceReport, TraceError> {
    validate_trace(trace)?;

    let mut results = Vec::with_capacity(trace.operations.len());
    let mut admitted_operations = 0;
    let mut admitted_events = 0;

    for operation in &trace.operations {
        let mut trial = InMemoryEventStore::from_trusted_events(operation.baseline_events.clone())
            .map_err(|error| {
                TraceError::invalid(format!(
                    "operation {:?} has an invalid trusted baseline: {error}",
                    operation.operation_id
                ))
            })?;
        let mut rejection = None;
        for event in &operation.events {
            if let Err(error) = append_candidate(&mut trial, operation, event) {
                rejection = Some((event.event_id.to_string(), store_error_category(&error)));
                break;
            }
        }

        let admitted = rejection.is_none();
        let (rejected_event_id, rejection_category) = rejection.unzip();
        if admitted {
            admitted_operations += 1;
            admitted_events += operation.events.len();
        }
        results.push(TraceOperationResult {
            operation_id: operation.operation_id.clone(),
            event_count: operation.events.len(),
            admitted,
            rejected_event_id,
            rejection_category,
        });
    }

    let operation_count = trace.operations.len();
    Ok(LegitimateTraceReport {
        trace_id: trace.trace_id.clone(),
        origin: trace.provenance.origin,
        agent: trace.provenance.agent.clone(),
        content: trace.privacy.content,
        privacy_warning: (trace.privacy.content == TraceContent::Raw)
            .then_some(RAW_CONTENT_WARNING),
        operation_count,
        event_count: trace
            .operations
            .iter()
            .map(|operation| operation.events.len())
            .sum(),
        admitted_operations,
        admitted_events,
        false_positives: operation_count.saturating_sub(admitted_operations),
        operations: results,
    })
}

/// Replay the operation-specific policy seam. Plain assertions and derivations use the
/// predicate registry before the base store firewall; sanctioned lifecycle batches enforce
/// their own end-state invariants and therefore append directly, matching the CLI path.
fn append_candidate(
    store: &mut InMemoryEventStore,
    operation: &LegitimateTraceOperation,
    event: &FactEvent,
) -> Result<(), StoreError> {
    if matches!(
        operation.operation,
        TraceOperationKind::Assert | TraceOperationKind::Derive
    ) {
        let registry = PredicateRegistry::coding_agent();
        enforce_policy(&registry, store, event, event.provenance.recorded_at)?;
    }
    store.append(event.clone()).map(|_| ())
}

fn validate_trace(trace: &LegitimateTrace) -> Result<(), TraceError> {
    if trace.schema != LEGITIMATE_TRACE_SCHEMA {
        return Err(TraceError::invalid(format!(
            "unsupported trace schema {:?}; expected {LEGITIMATE_TRACE_SCHEMA}",
            trace.schema
        )));
    }
    require_text("trace_id", &trace.trace_id)?;
    require_text("provenance.agent", &trace.provenance.agent)?;
    require_text("review.reviewer", &trace.review.reviewer)?;
    require_text("review.basis", &trace.review.basis)?;
    if trace.operations.is_empty() {
        return Err(TraceError::invalid(
            "trace must contain at least one reviewed operation",
        ));
    }

    let mut operation_ids = BTreeSet::new();
    for operation in &trace.operations {
        require_text("operation_id", &operation.operation_id)?;
        if trace.provenance.origin == TraceOrigin::Captured
            && operation.operation == TraceOperationKind::StoreAppend
        {
            return Err(TraceError::invalid(format!(
                "operation {:?}: store-append is synthetic-only",
                operation.operation_id
            )));
        }
        if !operation_ids.insert(operation.operation_id.as_str()) {
            return Err(TraceError::invalid(format!(
                "duplicate operation_id {:?}",
                operation.operation_id
            )));
        }
        if operation.events.is_empty() {
            return Err(TraceError::invalid(format!(
                "operation {:?} must contain at least one event",
                operation.operation_id
            )));
        }
        let mut event_ids = BTreeSet::new();
        for event in operation
            .baseline_events
            .iter()
            .chain(operation.events.iter())
        {
            event.validate().map_err(|error| {
                TraceError::invalid(format!(
                    "event {:?} is not a valid FactEvent: {error}",
                    event.event_id.as_str()
                ))
            })?;
            if !event_ids.insert(event.event_id.as_str()) {
                return Err(TraceError::invalid(format!(
                    "duplicate event_id {:?} in operation {:?}",
                    event.event_id.as_str(),
                    operation.operation_id
                )));
            }
        }
    }
    Ok(())
}

fn require_text(field: &str, value: &str) -> Result<(), TraceError> {
    if value.trim().is_empty() {
        Err(TraceError::invalid(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

/// Stable, typed rejection categories. Never parse `Debug` or `Display`, since both may change
/// and may contain user-provided ids.
const fn store_error_category(error: &StoreError) -> &'static str {
    match error {
        StoreError::Conflict(_) => "write-conflict",
        StoreError::Unavailable(_) => "store-unavailable",
        StoreError::CorruptEvent(_) => "corrupt-event",
        StoreError::Canonicalization(_) => "canonicalization-failed",
        StoreError::Replay(_) => "replay-failed",
        StoreError::Rejected(transition) => transition_error_category(transition),
        StoreError::LaunderedAuthority { .. } => "laundered-authority",
        StoreError::UnbackedSupersession(_) => "unbacked-supersession",
        StoreError::BelowAuthorityFloor { .. } => "below-authority-floor",
        StoreError::UniquenessViolation { .. } => "uniqueness-violation",
        StoreError::TtlCeilingExceeded { .. } => "ttl-ceiling-exceeded",
    }
}

const fn transition_error_category(error: &TransitionError) -> &'static str {
    match error {
        TransitionError::InvalidEvent(_) => "invalid-event",
        TransitionError::MissingInitialAssertion => "missing-initial-assertion",
        TransitionError::DuplicateAssertion => "duplicate-assertion",
        TransitionError::FactIdMismatch => "fact-id-mismatch",
        TransitionError::FactShapeMismatch => "fact-shape-mismatch",
        TransitionError::ReinforcementValueMismatch => "reinforcement-value-mismatch",
        TransitionError::TerminalStateMutation(_) => "terminal-fact",
        TransitionError::InsufficientAuthority { .. } => "insufficient-authority",
        TransitionError::CanonicalContradiction => "canonical-contradiction",
    }
}

#[cfg(test)]
mod tests {
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, Confidence, Evidence, EvidenceId, EvidenceKind,
        FactEvent, FactEventId, FactEventKind, FactId, FactValue, Predicate, Provenance, SourceId,
        Subject, SupersessionReason, TimestampMillis, Ttl,
    };

    use super::{
        LEGITIMATE_TRACE_SCHEMA, LegitimateTrace, LegitimateTraceOperation, TraceContent,
        TraceExpectation, TraceOperationKind, TraceOrigin, TracePrivacy, TraceProvenance,
        TraceReview, evaluate_legitimate_trace, parse_legitimate_trace,
    };

    fn event(
        sequence: i64,
        fact_id: &str,
        kind: FactEventKind,
        value: Option<&str>,
        authority: AuthorityLevel,
    ) -> FactEvent {
        FactEvent {
            event_id: FactEventId::new(format!("event:{sequence}")).expect("event id"),
            fact_id: FactId::new(fact_id).expect("fact id"),
            kind,
            subject: Subject::new("repo", "example").expect("subject"),
            predicate: Predicate::new("database").expect("predicate"),
            value: value.map(|value| FactValue::Text(value.to_string())),
            confidence: Confidence::from_millis(900).expect("confidence"),
            authority: Authority {
                level: authority,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:reviewed").expect("source"),
                actor: ActorId::new("actor:agent").expect("actor"),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(sequence),
                attestation: None,
            },
            evidence: vec![Evidence {
                id: EvidenceId::new(format!("evidence:{sequence}")).expect("evidence id"),
                kind: EvidenceKind::UserStatement,
                locator: "redacted".to_string(),
                digest: None,
                summary: None,
            }],
            observed_at: None,
            valid_from: None,
            valid_to: None,
        }
    }

    fn operation(id: &str, events: Vec<FactEvent>) -> LegitimateTraceOperation {
        LegitimateTraceOperation {
            operation_id: id.to_string(),
            operation: TraceOperationKind::StoreAppend,
            expected: TraceExpectation::Admit,
            baseline_events: Vec::new(),
            events,
        }
    }

    fn trace(operations: Vec<LegitimateTraceOperation>) -> LegitimateTrace {
        LegitimateTrace {
            schema: LEGITIMATE_TRACE_SCHEMA.to_string(),
            trace_id: "trace:reviewed-session".to_string(),
            provenance: TraceProvenance {
                origin: TraceOrigin::Synthetic,
                agent: "codex".to_string(),
                session: Some("session:pseudonymous".to_string()),
            },
            privacy: TracePrivacy {
                content: TraceContent::Redacted,
                note: Some("values pseudonymized".to_string()),
            },
            review: TraceReview {
                reviewer: "human:reviewer".to_string(),
                basis: "normal project correction".to_string(),
            },
            operations,
        }
    }

    #[test]
    fn a_reviewed_revision_round_trips_and_is_clean() {
        let original = event(
            0,
            "fact:old",
            FactEventKind::Asserted,
            Some("old"),
            AuthorityLevel::High,
        );
        let replacement = event(
            1,
            "fact:new",
            FactEventKind::Asserted,
            Some("new"),
            AuthorityLevel::High,
        );
        let supersession = event(
            2,
            "fact:old",
            FactEventKind::Superseded {
                by: FactId::new("fact:new").expect("fact id"),
                reason: SupersessionReason::UserCorrection,
            },
            None,
            AuthorityLevel::High,
        );
        let authored = trace(vec![
            operation("op:assert", vec![original]),
            LegitimateTraceOperation {
                operation_id: "op:revise".to_string(),
                operation: TraceOperationKind::Supersede,
                expected: TraceExpectation::Admit,
                baseline_events: vec![event(
                    0,
                    "fact:old",
                    FactEventKind::Asserted,
                    Some("old"),
                    AuthorityLevel::High,
                )],
                events: vec![replacement, supersession],
            },
        ]);
        let json = serde_json::to_string(&authored).expect("serialize trace");
        let parsed = parse_legitimate_trace(&json).expect("parse trace");
        let report = evaluate_legitimate_trace(&parsed).expect("evaluate trace");

        assert!(report.clean());
        assert_eq!(report.operation_count, 2);
        assert_eq!(report.event_count, 3);
        assert_eq!(report.admitted_operations, 2);
        assert_eq!(report.admitted_events, 3);
    }

    #[test]
    fn a_rejected_batch_is_one_false_positive_and_rolls_back_atomically() {
        let incumbent = event(
            0,
            "fact:old",
            FactEventKind::Asserted,
            Some("trusted"),
            AuthorityLevel::High,
        );
        let weak = event(
            1,
            "fact:weak",
            FactEventKind::Asserted,
            Some("candidate"),
            AuthorityLevel::Low,
        );
        let rejected = event(
            2,
            "fact:old",
            FactEventKind::Superseded {
                by: FactId::new("fact:weak").expect("fact id"),
                reason: SupersessionReason::UserCorrection,
            },
            None,
            AuthorityLevel::Low,
        );
        // This assertion succeeds only if the rejected operation's first event was rolled back.
        let retry = event(
            3,
            "fact:weak",
            FactEventKind::Asserted,
            Some("candidate"),
            AuthorityLevel::Low,
        );
        let report = evaluate_legitimate_trace(&trace(vec![
            operation("op:incumbent", vec![incumbent.clone()]),
            LegitimateTraceOperation {
                operation_id: "op:weak-revision".to_string(),
                operation: TraceOperationKind::Supersede,
                expected: TraceExpectation::Admit,
                baseline_events: vec![incumbent],
                events: vec![weak, rejected],
            },
            operation("op:retry-assert", vec![retry]),
        ]))
        .expect("evaluate trace");

        assert_eq!(report.false_positives, 1);
        assert_eq!(report.admitted_operations, 2);
        assert_eq!(report.admitted_events, 2);
        assert_eq!(
            report.operations[1].rejection_category,
            Some("insufficient-authority")
        );
        assert!(report.operations[2].admitted, "failed batch must roll back");
    }

    #[test]
    fn duplicate_ids_are_scoped_to_each_independent_operation() {
        let first = event(
            0,
            "fact:first",
            FactEventKind::Asserted,
            Some("one"),
            AuthorityLevel::Low,
        );
        let duplicate = event(
            0,
            "fact:second",
            FactEventKind::Asserted,
            Some("two"),
            AuthorityLevel::Low,
        );
        let report = evaluate_legitimate_trace(&trace(vec![
            operation("op:first", vec![first]),
            operation("op:second", vec![duplicate]),
        ]))
        .expect("independent operation ids may repeat");

        assert!(report.clean());

        let baseline = event(
            0,
            "fact:first",
            FactEventKind::Asserted,
            Some("one"),
            AuthorityLevel::Low,
        );
        let candidate = event(
            0,
            "fact:second",
            FactEventKind::Asserted,
            Some("two"),
            AuthorityLevel::Low,
        );
        let error = evaluate_legitimate_trace(&trace(vec![LegitimateTraceOperation {
            operation_id: "op:duplicate-within-scenario".to_string(),
            operation: TraceOperationKind::StoreAppend,
            expected: TraceExpectation::Admit,
            baseline_events: vec![baseline],
            events: vec![candidate],
        }]))
        .expect_err("an operation may not reuse a baseline event id");

        assert!(error.to_string().contains("duplicate event_id"));
    }

    #[test]
    fn malformed_events_are_invalid_evidence_not_false_positives() {
        let mut malformed = event(
            0,
            "fact:first",
            FactEventKind::Asserted,
            Some("one"),
            AuthorityLevel::Low,
        );
        malformed.evidence.clear();
        let error =
            evaluate_legitimate_trace(&trace(vec![operation("op:malformed", vec![malformed])]))
                .expect_err("malformed event must fail validation");

        assert!(error.to_string().contains("not a valid FactEvent"));
        assert!(error.to_string().contains("must include evidence"));
    }

    #[test]
    fn raw_content_is_machine_visibly_warned_without_echoing_values() {
        let mut authored = trace(vec![operation(
            "op:assert",
            vec![event(
                0,
                "fact:first",
                FactEventKind::Asserted,
                Some("private-value"),
                AuthorityLevel::Low,
            )],
        )]);
        authored.privacy.content = TraceContent::Raw;
        let report = evaluate_legitimate_trace(&authored).expect("evaluate trace");
        let json = serde_json::to_string(&report).expect("serialize report");

        assert!(report.privacy_warning.is_some());
        assert!(json.contains("keep the source file local"));
        assert!(!json.contains("private-value"));
    }

    #[test]
    fn wrong_schema_and_unknown_fields_are_rejected() {
        let authored = trace(vec![operation(
            "op:assert",
            vec![event(
                0,
                "fact:first",
                FactEventKind::Asserted,
                Some("one"),
                AuthorityLevel::Low,
            )],
        )]);
        let mut value = serde_json::to_value(authored).expect("serialize trace");
        value["schema"] = serde_json::json!("dent8.legitimate-trace/99");
        let error = parse_legitimate_trace(&value.to_string()).expect_err("unknown schema");
        assert!(error.to_string().contains("unsupported trace schema"));

        value["schema"] = serde_json::json!(LEGITIMATE_TRACE_SCHEMA);
        value["surprise"] = serde_json::json!(true);
        let error = parse_legitimate_trace(&value.to_string()).expect_err("unknown field");
        assert!(error.to_string().contains("unknown field"));
    }
}
