//! Opt-in operation capture and explicit review into legitimate-traffic traces.
//!
//! Capture records are raw evidence, not labels. Each attempted operation carries the exact
//! trusted store baseline that preceded it, so attempts can be evaluated independently without
//! assuming that an earlier rejected write changed state. A separate draft schema forces a
//! reviewer to classify every operation before it can become a `dent8.legitimate-trace/1`.

use std::collections::BTreeSet;
use std::fmt;

use dent8_core::FactEvent;
use serde::{Deserialize, Serialize};

use crate::legitimate_trace::{
    LEGITIMATE_TRACE_SCHEMA, LegitimateTrace, LegitimateTraceOperation, TraceExpectation,
    TraceOperationKind, TracePrivacy, TraceProvenance, TraceReview,
};

/// JSONL schema emitted by the opt-in operation recorder.
pub const CAPTURE_JOURNAL_SCHEMA: &str = "dent8.eval-capture/1";
/// JSON schema for a capture that still requires human classification.
pub const TRACE_REVIEW_SCHEMA: &str = "dent8.legitimate-trace-review/1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturedDecision {
    Admitted,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedOutcome {
    pub decision: CapturedDecision,
    /// Stable machine-readable rejection category. Absent for admitted operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record", rename_all = "snake_case", deny_unknown_fields)]
pub enum CaptureJournalRecord {
    Header {
        schema: String,
        capture_id: String,
        provenance: TraceProvenance,
        privacy: TracePrivacy,
    },
    Attempt {
        schema: String,
        operation_id: String,
        operation: TraceOperationKind,
        recorded_at: i64,
        /// Already-admitted state immediately before this operation. It is trusted setup,
        /// never counted as legitimate traffic or re-arbitrated by the eval.
        baseline_events: Vec<FactEvent>,
        /// Exact candidate batch submitted to the store-level firewall.
        events: Vec<FactEvent>,
        observed: CapturedOutcome,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureJournal {
    pub capture_id: String,
    pub provenance: TraceProvenance,
    pub privacy: TracePrivacy,
    pub attempts: Vec<CapturedAttempt>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedAttempt {
    pub operation_id: String,
    pub operation: TraceOperationKind,
    pub recorded_at: i64,
    pub baseline_events: Vec<FactEvent>,
    pub events: Vec<FactEvent>,
    pub observed: CapturedOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewClassification {
    ReviewRequired,
    Legitimate,
    Exclude,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceReviewDraft {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceReviewOperation {
    pub operation_id: String,
    pub operation: TraceOperationKind,
    pub classification: ReviewClassification,
    pub observed: CapturedOutcome,
    pub baseline_events: Vec<FactEvent>,
    pub events: Vec<FactEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegitimateTraceReview {
    pub schema: String,
    pub trace_id: String,
    pub provenance: TraceProvenance,
    pub privacy: TracePrivacy,
    pub review: TraceReviewDraft,
    pub operations: Vec<TraceReviewOperation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureError(String);

impl CaptureError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CaptureError {}

/// Parse a complete JSONL capture. The first record must be exactly one header.
pub fn parse_capture_journal(input: &str) -> Result<CaptureJournal, CaptureError> {
    let mut records = input
        .lines()
        .enumerate()
        .filter_map(|(index, line)| (!line.trim().is_empty()).then_some((index + 1, line)));
    let Some((header_line, header)) = records.next() else {
        return Err(CaptureError::invalid("capture journal is empty"));
    };
    let header = parse_record(header_line, header)?;
    let CaptureJournalRecord::Header {
        schema,
        capture_id,
        provenance,
        privacy,
    } = header
    else {
        return Err(CaptureError::invalid(
            "capture journal must start with a header record",
        ));
    };
    require_schema(&schema, header_line)?;
    require_text("capture_id", &capture_id)?;
    require_text("provenance.agent", &provenance.agent)?;
    if provenance.origin != crate::TraceOrigin::Captured {
        return Err(CaptureError::invalid(
            "capture journal provenance.origin must be captured",
        ));
    }
    if privacy.content != crate::TraceContent::Raw {
        return Err(CaptureError::invalid(
            "capture journal privacy.content must be raw; redaction happens during review",
        ));
    }

    let mut attempts = Vec::new();
    let mut operation_ids = BTreeSet::new();
    for (line_number, line) in records {
        match parse_record(line_number, line)? {
            CaptureJournalRecord::Header { .. } => {
                return Err(CaptureError::invalid(format!(
                    "line {line_number}: duplicate capture header"
                )));
            }
            CaptureJournalRecord::Attempt {
                schema,
                operation_id,
                operation,
                recorded_at,
                baseline_events,
                events,
                observed,
            } => {
                require_schema(&schema, line_number)?;
                require_text("operation_id", &operation_id)?;
                if operation == TraceOperationKind::StoreAppend {
                    return Err(CaptureError::invalid(format!(
                        "line {line_number}: store-append is synthetic-only and cannot appear in a captured journal"
                    )));
                }
                if !operation_ids.insert(operation_id.clone()) {
                    return Err(CaptureError::invalid(format!(
                        "line {line_number}: duplicate operation_id {operation_id:?}"
                    )));
                }
                validate_operation(&operation_id, &baseline_events, &events)?;
                validate_outcome(&operation_id, &observed)?;
                attempts.push(CapturedAttempt {
                    operation_id,
                    operation,
                    recorded_at,
                    baseline_events,
                    events,
                    observed,
                });
            }
        }
    }
    if attempts.is_empty() {
        return Err(CaptureError::invalid(
            "capture journal contains no completed arbitration attempts",
        ));
    }

    Ok(CaptureJournal {
        capture_id,
        provenance,
        privacy,
        attempts,
    })
}

/// Turn raw capture records into an intentionally non-runnable review draft.
#[must_use]
pub fn prepare_trace_review(journal: CaptureJournal) -> LegitimateTraceReview {
    LegitimateTraceReview {
        schema: TRACE_REVIEW_SCHEMA.to_string(),
        trace_id: journal.capture_id.replacen("capture:", "trace:", 1),
        provenance: journal.provenance,
        privacy: journal.privacy,
        review: TraceReviewDraft {
            reviewer: None,
            basis: None,
        },
        operations: journal
            .attempts
            .into_iter()
            .map(|attempt| TraceReviewOperation {
                operation_id: attempt.operation_id,
                operation: attempt.operation,
                classification: ReviewClassification::ReviewRequired,
                observed: attempt.observed,
                baseline_events: attempt.baseline_events,
                events: attempt.events,
            })
            .collect(),
    }
}

pub fn parse_trace_review(input: &str) -> Result<LegitimateTraceReview, CaptureError> {
    let review: LegitimateTraceReview = serde_json::from_str(input)
        .map_err(|error| CaptureError::invalid(format!("invalid review JSON: {error}")))?;
    validate_review(&review, false)?;
    Ok(review)
}

/// Finalize an explicitly classified draft into the only schema accepted by `dent8 eval
/// --trace`. Excluded operations remain absent because each operation carries an independent
/// baseline; removing one cannot change another operation's state.
pub fn finalize_trace_review(
    review: LegitimateTraceReview,
) -> Result<LegitimateTrace, CaptureError> {
    validate_review(&review, true)?;
    let reviewer = review
        .review
        .reviewer
        .expect("validated review must have a reviewer");
    let basis = review
        .review
        .basis
        .expect("validated review must have a basis");
    let operations = review
        .operations
        .into_iter()
        .filter(|operation| operation.classification == ReviewClassification::Legitimate)
        .map(|operation| LegitimateTraceOperation {
            operation_id: operation.operation_id,
            operation: operation.operation,
            expected: TraceExpectation::Admit,
            baseline_events: operation.baseline_events,
            events: operation.events,
        })
        .collect();

    Ok(LegitimateTrace {
        schema: LEGITIMATE_TRACE_SCHEMA.to_string(),
        trace_id: review.trace_id,
        provenance: review.provenance,
        privacy: review.privacy,
        review: TraceReview { reviewer, basis },
        operations,
    })
}

fn parse_record(line_number: usize, line: &str) -> Result<CaptureJournalRecord, CaptureError> {
    serde_json::from_str(line).map_err(|error| {
        CaptureError::invalid(format!(
            "line {line_number}: invalid capture record: {error}"
        ))
    })
}

fn require_schema(schema: &str, line_number: usize) -> Result<(), CaptureError> {
    if schema == CAPTURE_JOURNAL_SCHEMA {
        Ok(())
    } else {
        Err(CaptureError::invalid(format!(
            "line {line_number}: unsupported capture schema {schema:?}; expected {CAPTURE_JOURNAL_SCHEMA}"
        )))
    }
}

fn validate_outcome(operation_id: &str, outcome: &CapturedOutcome) -> Result<(), CaptureError> {
    match (&outcome.decision, outcome.code.as_deref()) {
        (CapturedDecision::Admitted, None) => Ok(()),
        (CapturedDecision::Admitted, Some(_)) => Err(CaptureError::invalid(format!(
            "operation {operation_id:?}: admitted outcome must not carry a rejection code"
        ))),
        (CapturedDecision::Rejected, Some(code)) if !code.trim().is_empty() => Ok(()),
        (CapturedDecision::Rejected, _) => Err(CaptureError::invalid(format!(
            "operation {operation_id:?}: rejected outcome requires a non-empty code"
        ))),
    }
}

fn validate_review(review: &LegitimateTraceReview, finalizing: bool) -> Result<(), CaptureError> {
    if review.schema != TRACE_REVIEW_SCHEMA {
        return Err(CaptureError::invalid(format!(
            "unsupported review schema {:?}; expected {TRACE_REVIEW_SCHEMA}",
            review.schema
        )));
    }
    require_text("trace_id", &review.trace_id)?;
    require_text("provenance.agent", &review.provenance.agent)?;
    if review.provenance.origin != crate::TraceOrigin::Captured {
        return Err(CaptureError::invalid(
            "review provenance.origin must be captured",
        ));
    }
    if review.operations.is_empty() {
        return Err(CaptureError::invalid("review contains no operations"));
    }

    let mut operation_ids = BTreeSet::new();
    let mut legitimate = 0;
    for operation in &review.operations {
        require_text("operation_id", &operation.operation_id)?;
        if !operation_ids.insert(operation.operation_id.as_str()) {
            return Err(CaptureError::invalid(format!(
                "duplicate operation_id {:?}",
                operation.operation_id
            )));
        }
        validate_operation(
            &operation.operation_id,
            &operation.baseline_events,
            &operation.events,
        )?;
        validate_outcome(&operation.operation_id, &operation.observed)?;
        if operation.operation == TraceOperationKind::StoreAppend {
            return Err(CaptureError::invalid(format!(
                "operation {:?}: store-append is synthetic-only and cannot be finalized from captured traffic",
                operation.operation_id
            )));
        }
        match operation.classification {
            ReviewClassification::Legitimate => legitimate += 1,
            ReviewClassification::ReviewRequired if finalizing => {
                return Err(CaptureError::invalid(format!(
                    "operation {:?} still requires review; classify it as legitimate or exclude",
                    operation.operation_id
                )));
            }
            ReviewClassification::ReviewRequired | ReviewClassification::Exclude => {}
        }
    }

    if finalizing {
        let reviewer = review.review.reviewer.as_deref().unwrap_or_default();
        let basis = review.review.basis.as_deref().unwrap_or_default();
        require_text("review.reviewer", reviewer)?;
        require_text("review.basis", basis)?;
        if legitimate == 0 {
            return Err(CaptureError::invalid(
                "review must classify at least one operation as legitimate",
            ));
        }
    }
    Ok(())
}

fn validate_operation(
    operation_id: &str,
    baseline_events: &[FactEvent],
    events: &[FactEvent],
) -> Result<(), CaptureError> {
    if events.is_empty() {
        return Err(CaptureError::invalid(format!(
            "operation {operation_id:?} has an empty candidate batch"
        )));
    }
    let mut ids = BTreeSet::new();
    for (role, event) in baseline_events
        .iter()
        .map(|event| ("baseline", event))
        .chain(events.iter().map(|event| ("candidate", event)))
    {
        event.validate().map_err(|error| {
            CaptureError::invalid(format!(
                "operation {operation_id:?} {role} event {:?} is invalid: {error}",
                event.event_id.as_str()
            ))
        })?;
        if !ids.insert(event.event_id.as_str()) {
            return Err(CaptureError::invalid(format!(
                "operation {operation_id:?} repeats event_id {:?} across its baseline and candidate batch",
                event.event_id.as_str()
            )));
        }
    }
    Ok(())
}

fn require_text(field: &str, value: &str) -> Result<(), CaptureError> {
    if value.trim().is_empty() {
        Err(CaptureError::invalid(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, Confidence, Evidence, EvidenceId, EvidenceKind,
        FactEventId, FactEventKind, FactId, FactValue, Predicate, Provenance, SourceId, Subject,
        TimestampMillis, Ttl,
    };

    use super::*;
    use crate::{TraceContent, TraceOrigin};

    fn event(id: &str, fact: &str) -> FactEvent {
        FactEvent {
            event_id: FactEventId::new(id).expect("event id"),
            fact_id: FactId::new(fact).expect("fact id"),
            kind: FactEventKind::Asserted,
            subject: Subject::new("shopper", "alice").expect("subject"),
            predicate: Predicate::new("shopping_item").expect("predicate"),
            value: Some(FactValue::Text("milk".to_string())),
            confidence: Confidence::from_millis(900).expect("confidence"),
            authority: Authority {
                level: AuthorityLevel::High,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:codex").expect("source"),
                actor: ActorId::new("actor:agent").expect("actor"),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(1),
                attestation: None,
            },
            evidence: vec![Evidence {
                id: EvidenceId::new(format!("evidence:{id}")).expect("evidence"),
                kind: EvidenceKind::UserStatement,
                locator: "raw".to_string(),
                digest: None,
                summary: None,
            }],
            observed_at: None,
            valid_from: None,
            valid_to: None,
        }
    }

    fn journal() -> String {
        let provenance = TraceProvenance {
            origin: TraceOrigin::Captured,
            agent: "codex".to_string(),
            session: Some("session:pseudonymous".to_string()),
        };
        let privacy = TracePrivacy {
            content: TraceContent::Raw,
            note: Some("contains raw values".to_string()),
        };
        let records = [
            CaptureJournalRecord::Header {
                schema: CAPTURE_JOURNAL_SCHEMA.to_string(),
                capture_id: "capture:one".to_string(),
                provenance,
                privacy,
            },
            CaptureJournalRecord::Attempt {
                schema: CAPTURE_JOURNAL_SCHEMA.to_string(),
                operation_id: "attempt:one".to_string(),
                operation: TraceOperationKind::Assert,
                recorded_at: 1,
                baseline_events: vec![],
                events: vec![event("event:1", "fact:one")],
                observed: CapturedOutcome {
                    decision: CapturedDecision::Admitted,
                    code: None,
                },
            },
        ];
        records
            .iter()
            .map(|record| serde_json::to_string(record).expect("serialize"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn capture_requires_explicit_review_before_finalization() {
        let parsed = parse_capture_journal(&journal()).expect("parse journal");
        let mut review = prepare_trace_review(parsed);
        let error = finalize_trace_review(review.clone()).expect_err("review is required");
        assert!(error.to_string().contains("still requires review"));

        review.review.reviewer = Some("human:owner".to_string());
        review.review.basis = Some("normal shopping-list write".to_string());
        review.operations[0].classification = ReviewClassification::Legitimate;
        let trace = finalize_trace_review(review).expect("finalize");
        assert_eq!(trace.schema, LEGITIMATE_TRACE_SCHEMA);
        assert_eq!(trace.operations.len(), 1);
        assert_eq!(trace.operations[0].operation, TraceOperationKind::Assert);
        assert!(trace.operations[0].baseline_events.is_empty());
    }

    #[test]
    fn excluded_operations_do_not_enter_the_trace() {
        let parsed = parse_capture_journal(&journal()).expect("parse journal");
        let mut review = prepare_trace_review(parsed);
        let mut excluded = review.operations[0].clone();
        excluded.operation_id = "attempt:excluded".to_string();
        excluded.classification = ReviewClassification::Exclude;
        review.operations.push(excluded);
        review.review.reviewer = Some("human:owner".to_string());
        review.review.basis = Some("reviewed normal traffic".to_string());
        review.operations[0].classification = ReviewClassification::Legitimate;

        let trace = finalize_trace_review(review).expect("finalize");
        assert_eq!(trace.operations.len(), 1);
        assert_eq!(trace.operations[0].operation_id, "attempt:one");
    }

    #[test]
    fn malformed_outcomes_duplicate_ids_and_synthetic_operations_are_rejected() {
        let invalid = journal().replace(
            r#""decision":"admitted""#,
            r#""decision":"admitted","code":"rejected""#,
        );
        let error = parse_capture_journal(&invalid).expect_err("admitted cannot have code");
        assert!(error.to_string().contains("must not carry"));

        let original = journal();
        let attempt = original.lines().nth(1).expect("attempt record");
        let duplicate = format!("{original}\n{attempt}");
        let error = parse_capture_journal(&duplicate).expect_err("duplicate operation id");
        assert!(error.to_string().contains("duplicate operation_id"));

        let synthetic =
            journal().replace(r#""operation":"assert""#, r#""operation":"store-append""#);
        let error = parse_capture_journal(&synthetic).expect_err("synthetic-only operation");
        assert!(error.to_string().contains("synthetic-only"));
    }
}
