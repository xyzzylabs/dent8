//! `dent8 context`: emit the currently-believed facts as an agent **context pack** — the
//! retrieval half of the capture/inject loop. The default output is markdown ready to place
//! in (or inject alongside) an agent's memory file (`CLAUDE.md`, `AGENTS.md`, a
//! `SessionStart` hook, ...); `--output json` is the machine-readable form. It respects belief state — only
//! non-terminal facts appear, stale/not-yet-valid ones are omitted unless asked for, and a
//! contested fact is flagged, never silently picked — and every fact carries its authority,
//! source, and `dent8://` receipt reference so `dent8 native reconcile` can re-verify the
//! generated block later.

use std::fmt::Write as _;

use dent8_core::{AuthorityLevel, FactEventKind, FactLifecycle, FactValue, TimestampMillis};
use dent8_store::{EventStore, IntegrityReceipt};

use crate::{
    CliOutput, ContextArgs, WriteIdentity, display_value, fact_value_json, load_store, log_path,
    now_millis,
    ops::{
        AuditFactRef, FactFreshness, OpError, is_diagnostic_fact_stream, op_error_exit_code,
        op_error_json, op_record_retrievals,
    },
    print_json_stdout, print_json_stdout_with_code,
    status::Status,
};

/// One believed fact as it appears in the context pack: the current value plus the cheap
/// provenance annotations (authority, asserting source, freshness, contest state, receipt URI).
pub(crate) struct ContextFact {
    /// The believed fact's id — kept so `--record-retrieval` can append the audit event to
    /// exactly the stream this pack emitted, without re-resolving (and racing) the read.
    fact_id: String,
    subject_kind: String,
    subject_key: String,
    predicate: String,
    value: FactValue,
    authority: AuthorityLevel,
    /// The asserting event's provenance source, when the stream still has one.
    source: Option<String>,
    freshness: FactFreshness,
    /// Rival facts contradicting this one (non-empty means the fact is contested).
    contested_by: usize,
    expires_at: Option<TimestampMillis>,
}

impl ContextFact {
    fn uri(&self) -> String {
        crate::mcp::resource_uri(&self.subject_kind, &self.subject_key, &self.predicate)
    }
}

pub(crate) struct ContextOutcome {
    facts: Vec<ContextFact>,
    /// Believed-but-stale facts omitted because `--include-stale` was not passed.
    omitted_stale: usize,
    /// Believed-but-not-yet-valid facts omitted because `--include-stale` was not passed.
    omitted_not_yet_valid: usize,
    generated_at: i64,
    /// `fact.retrieved` audit events recorded because `--record-retrieval` was passed
    /// (`None` when it was not).
    recorded_retrievals: Option<usize>,
}

impl ContextOutcome {
    fn contested(&self) -> bool {
        self.facts.iter().any(|fact| fact.contested_by > 0)
    }

    fn omitted(&self) -> usize {
        self.omitted_stale + self.omitted_not_yet_valid
    }
}

fn matches_filters(args: &ContextArgs, kind: &str, key: &str, predicate: &str) -> bool {
    args.kind.as_deref().is_none_or(|want| kind == want)
        && args.key.as_deref().is_none_or(|want| key == want)
        && args
            .predicate
            .as_deref()
            .is_none_or(|want| predicate == want)
}

/// The asserting event's provenance source for the receipt's fact — the "who said this"
/// annotation. Best-effort: a stream whose assertion cannot be loaded reads as unattributed
/// rather than failing the whole pack.
fn asserting_source(
    store: &dent8_store::InMemoryEventStore,
    receipt: &IntegrityReceipt,
) -> Option<String> {
    store
        .load_fact_events(&receipt.fact_id)
        .ok()?
        .iter()
        .find(|event| matches!(event.kind, FactEventKind::Asserted))
        .map(|event| event.provenance.source.as_str().to_string())
}

/// Resolve the believed facts for the context pack: every non-terminal stream, filtered,
/// with stale/not-yet-valid facts either counted out or annotated in (`--include-stale`).
/// Sorted by subject then predicate so regenerating the pack diffs cleanly.
pub(crate) fn context_outcome(path: &str, args: &ContextArgs) -> Result<ContextOutcome, OpError> {
    let store = load_store(path).map_err(OpError::Invalid)?;
    let now = now_millis();
    let mut facts = Vec::new();
    let mut omitted_stale = 0usize;
    let mut omitted_not_yet_valid = 0usize;
    for (subject, predicate) in store.subjects() {
        let kind = subject.kind();
        let key = subject.key();
        let pred = predicate.as_str();
        if !matches_filters(args, kind, key, pred) {
            continue;
        }
        if !args.include_diagnostics && is_diagnostic_fact_stream(kind, key, pred) {
            continue;
        }
        // The chain-check-free resolver, like `facts list`: a context pack over N streams
        // must not re-hash the whole log N times.
        let Some(receipt) = store
            .latest_freshness(&subject, &predicate, now)
            .map_err(|error| OpError::Rejected(format!("context failed: {error}")))?
        else {
            continue;
        };
        // Only currently-believed facts belong in injected context; a terminal fact is
        // history, not belief.
        if receipt.lifecycle.is_terminal() {
            continue;
        }
        let freshness = if receipt.not_yet_valid {
            FactFreshness::NotYetValid
        } else if receipt.fresh {
            FactFreshness::Fresh
        } else {
            FactFreshness::Stale
        };
        if !args.include_stale {
            match freshness {
                FactFreshness::Stale => {
                    omitted_stale += 1;
                    continue;
                }
                FactFreshness::NotYetValid => {
                    omitted_not_yet_valid += 1;
                    continue;
                }
                _ => {}
            }
        }
        let contested_by = if receipt.lifecycle == FactLifecycle::Contested {
            receipt.contradicted_by.len().max(1)
        } else {
            0
        };
        facts.push(ContextFact {
            fact_id: receipt.fact_id.as_str().to_string(),
            subject_kind: kind.to_string(),
            subject_key: key.to_string(),
            predicate: pred.to_string(),
            value: receipt.value.clone(),
            authority: receipt.authority,
            source: asserting_source(&store, &receipt),
            freshness,
            contested_by,
            expires_at: receipt.expires_at,
        });
    }
    facts.sort_by(|a, b| {
        (&a.subject_kind, &a.subject_key, &a.predicate).cmp(&(
            &b.subject_kind,
            &b.subject_key,
            &b.predicate,
        ))
    });
    Ok(ContextOutcome {
        facts,
        omitted_stale,
        omitted_not_yet_valid,
        generated_at: now.as_unix_millis(),
        recorded_retrievals: None,
    })
}

/// Record one `fact.retrieved` audit event per fact the pack emitted (`--record-retrieval`).
/// Identity resolves like unattributed capture: the active signed grant's source/authority
/// when configured, else the agent tier — a retrieval audit enters at the bottom of the
/// trust ordering instead of minting authority. All-or-nothing: a failure is surfaced (the
/// caller asked for the audit) rather than silently skipped.
fn record_pack_retrievals(
    path: &str,
    outcome: &ContextOutcome,
    purpose: &str,
) -> Result<usize, OpError> {
    let retrieved: Vec<AuditFactRef> = outcome
        .facts
        .iter()
        .map(|fact| AuditFactRef {
            fact_id: fact.fact_id.clone(),
            subject_kind: fact.subject_kind.clone(),
            subject_key: fact.subject_key.clone(),
            predicate: fact.predicate.clone(),
        })
        .collect();
    let defaults = crate::identity::IdentityContext::from_env()
        .map_err(OpError::Invalid)?
        .write_defaults()
        .map_err(OpError::Invalid)?;
    let (authority, source) = defaults.map_or_else(
        || {
            (
                crate::capture::CAPTURE_FALLBACK_AUTHORITY,
                crate::capture::CAPTURE_FALLBACK_SOURCE.to_string(),
            )
        },
        |defaults| (defaults.authority, defaults.source),
    );
    op_record_retrievals(
        path,
        &retrieved,
        purpose,
        authority,
        &source,
        &WriteIdentity::Env,
    )
}

/// The provenance annotation appended to each markdown fact line. Deliberately compact —
/// the pack is written for an agent's context window, not a debugger.
fn markdown_annotation(fact: &ContextFact) -> String {
    let mut parts = vec![format!("authority: {}", fact.authority.name())];
    if let Some(source) = &fact.source {
        parts.push(format!("source: {source}"));
    }
    parts.push(format!("ref: {}", fact.uri()));
    let mut markers = String::new();
    if fact.contested_by > 0 {
        let _ = write!(
            markers,
            "  **[contested — {} rival value(s); check `dent8 conflicts` before relying on \
             this]**",
            fact.contested_by
        );
    }
    match fact.freshness {
        FactFreshness::Stale => markers.push_str("  **[stale — past its validity window]**"),
        FactFreshness::NotYetValid => markers.push_str("  **[not yet valid]**"),
        _ => {}
    }
    format!("{markers}  ({})", parts.join(", "))
}

/// Render the context pack as markdown for CLAUDE.md/AGENTS.md-style inclusion. Facts are
/// grouped by subject; provenance rides inline so the reading agent sees who asserted what
/// at which authority without a second lookup.
pub(crate) fn format_context_markdown(outcome: &ContextOutcome) -> String {
    let mut out = String::from("## Project facts (dent8)\n\n");
    let _ = writeln!(
        out,
        "<!-- generated by `dent8 context` at {}; regenerate instead of hand-editing -->",
        outcome.generated_at
    );
    out.push_str(
        "\nCurrently-believed facts from the dent8 memory firewall. Each carries its \
         authority and source; verify one with `dent8 explain <subject> <predicate>`.\n",
    );
    if outcome.facts.is_empty() {
        out.push_str("\nNo believed facts recorded yet — seed them with `dent8 assert`.\n");
    }
    let mut current_subject = None;
    for fact in &outcome.facts {
        let subject = format!("{}:{}", fact.subject_kind, fact.subject_key);
        if current_subject.as_ref() != Some(&subject) {
            let _ = write!(out, "\n### {subject}\n\n");
            current_subject = Some(subject);
        }
        let _ = writeln!(
            out,
            "- `{}` = {}{}",
            fact.predicate,
            display_value(&fact.value),
            markdown_annotation(fact)
        );
    }
    if outcome.omitted() > 0 {
        let _ = write!(
            out,
            "\n_{} believed fact(s) omitted ({} stale, {} not yet valid) — pass \
             `--include-stale` to show them._\n",
            outcome.omitted(),
            outcome.omitted_stale,
            outcome.omitted_not_yet_valid
        );
    }
    out
}

pub(crate) fn context_json(outcome: &ContextOutcome) -> serde_json::Value {
    // Mirror `conflicts`/`snapshot`: a pack carrying a live dispute reads `contested`, not
    // `ok`, so a machine consumer cannot inject conflicted context without noticing.
    let status = if outcome.contested() {
        Status::Contested
    } else {
        Status::Ok
    };
    serde_json::json!({
        "status": status.as_str(),
        "tool": "context",
        "generated_at": outcome.generated_at,
        "count": outcome.facts.len(),
        "facts": outcome
            .facts
            .iter()
            .map(|fact| {
                serde_json::json!({
                    "uri": fact.uri(),
                    "subject": {
                        "kind": fact.subject_kind,
                        "key": fact.subject_key,
                    },
                    "predicate": fact.predicate,
                    "value": fact_value_json(&fact.value),
                    "authority": fact.authority.name(),
                    "source": fact.source,
                    "freshness": fact.freshness.json_name(),
                    "contested_by": fact.contested_by,
                    "expires_at": fact.expires_at.map(TimestampMillis::as_unix_millis),
                })
            })
            .collect::<Vec<_>>(),
        "omitted": {
            "stale": outcome.omitted_stale,
            "not_yet_valid": outcome.omitted_not_yet_valid,
        },
        "recorded_retrievals": outcome.recorded_retrievals,
    })
}

pub(crate) fn cmd_context(args: &ContextArgs, output: CliOutput) -> i32 {
    let path = log_path();
    let outcome = context_outcome(&path, args).and_then(|mut outcome| {
        // Record the retrieval audit *before* emitting the pack, so an emitted pack is
        // never un-audited; a recording failure fails the command (the caller explicitly
        // asked for the audit) instead of injecting silently-unaudited context.
        if args.record_retrieval {
            outcome.recorded_retrievals =
                Some(record_pack_retrievals(&path, &outcome, &args.purpose)?);
        }
        Ok(outcome)
    });
    match (outcome, output) {
        (Ok(outcome), CliOutput::Text) => {
            print!("{}", format_context_markdown(&outcome));
            0
        }
        // A contested pack is still a successful read (the conflict is *surfaced*, exactly
        // as designed); only a failed load/replay is an error.
        (Ok(outcome), CliOutput::Json) => print_json_stdout(&context_json(&outcome)),
        (Err(error), CliOutput::Text) => crate::ops::present(Err(error)),
        (Err(error), CliOutput::Json) => {
            print_json_stdout_with_code(&op_error_json(&error), op_error_exit_code(&error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(subject_key: &str, predicate: &str, value: &str) -> ContextFact {
        ContextFact {
            fact_id: format!("fact:repo:{subject_key}:{predicate}:0"),
            subject_kind: "repo".to_string(),
            subject_key: subject_key.to_string(),
            predicate: predicate.to_string(),
            value: FactValue::Text(value.to_string()),
            authority: AuthorityLevel::High,
            source: Some("source:human".to_string()),
            freshness: FactFreshness::Fresh,
            contested_by: 0,
            expires_at: None,
        }
    }

    #[test]
    fn markdown_groups_by_subject_and_annotates_provenance() {
        let outcome = ContextOutcome {
            facts: vec![
                fact("dent8", "uses_database", "postgres"),
                fact("dent8", "test_command", "cargo test --workspace"),
                fact("other", "uses_database", "sqlite"),
            ],
            omitted_stale: 0,
            omitted_not_yet_valid: 0,
            generated_at: 1,
            recorded_retrievals: None,
        };
        let markdown = format_context_markdown(&outcome);
        assert!(markdown.contains("## Project facts (dent8)"), "{markdown}");
        assert!(markdown.contains("### repo:dent8"), "{markdown}");
        assert!(markdown.contains("### repo:other"), "{markdown}");
        assert!(
            markdown.contains("- `uses_database` = \"postgres\""),
            "{markdown}"
        );
        assert!(
            markdown.contains("authority: high, source: source:human"),
            "{markdown}"
        );
        assert!(
            markdown.contains("ref: dent8://repo/dent8/uses_database"),
            "{markdown}"
        );
        // One subject header per subject, not per fact.
        assert_eq!(markdown.matches("### repo:dent8").count(), 1);
    }

    #[test]
    fn markdown_flags_contested_and_stale_facts() {
        let mut contested = fact("dent8", "uses_database", "postgres");
        contested.contested_by = 1;
        let mut stale = fact("dent8", "branch_status", "green");
        stale.freshness = FactFreshness::Stale;
        let outcome = ContextOutcome {
            facts: vec![contested, stale],
            omitted_stale: 0,
            omitted_not_yet_valid: 0,
            generated_at: 1,
            recorded_retrievals: None,
        };
        let markdown = format_context_markdown(&outcome);
        assert!(
            markdown.contains("[contested — 1 rival value(s)"),
            "{markdown}"
        );
        assert!(
            markdown.contains("[stale — past its validity window]"),
            "{markdown}"
        );
    }

    #[test]
    fn markdown_reports_empty_store_and_omissions() {
        let empty = ContextOutcome {
            facts: Vec::new(),
            omitted_stale: 2,
            omitted_not_yet_valid: 1,
            generated_at: 1,
            recorded_retrievals: None,
        };
        let markdown = format_context_markdown(&empty);
        assert!(
            markdown.contains("No believed facts recorded yet"),
            "{markdown}"
        );
        assert!(
            markdown.contains("3 believed fact(s) omitted (2 stale, 1 not yet valid)"),
            "{markdown}"
        );
    }

    #[test]
    fn json_status_is_contested_when_any_fact_is_disputed() {
        let mut contested = fact("dent8", "uses_database", "postgres");
        contested.contested_by = 2;
        let outcome = ContextOutcome {
            facts: vec![contested],
            omitted_stale: 0,
            omitted_not_yet_valid: 0,
            generated_at: 7,
            recorded_retrievals: None,
        };
        let json = context_json(&outcome);
        assert_eq!(json["status"], "contested");
        assert_eq!(json["count"], 1);
        assert_eq!(json["facts"][0]["contested_by"], 2);
        assert_eq!(json["facts"][0]["freshness"], "fresh");

        let calm = ContextOutcome {
            facts: vec![fact("dent8", "uses_database", "postgres")],
            omitted_stale: 0,
            omitted_not_yet_valid: 0,
            generated_at: 7,
            recorded_retrievals: None,
        };
        assert_eq!(context_json(&calm)["status"], "ok");
    }
}
