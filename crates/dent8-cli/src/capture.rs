//! `dent8 capture`: batch structured **fact proposals** into the store — the capture half of
//! the capture/inject loop. Proposals arrive as JSON lines on stdin or from a file (so an
//! agent can queue them during a session and a session-end hook can flush them), and every
//! proposal runs through the *same* `op_*` firewall path as the interactive CLI and MCP
//! tools: a below-ceiling, laundered, or non-unique write is rejected here exactly as it
//! would be anywhere else. There is no daemon and no new write path — capture is a reader
//! that feeds the existing one.
//!
//! A proposal line looks like:
//!
//! ```json
//! {"subject": "repo:dent8", "predicate": "uses_database", "value": "postgres"}
//! ```
//!
//! with optional `op` (`assert` — the default — `supersede`, `reinforce`, `contradict`,
//! `retract`, `expire`, `used_in_decision`), `authority`, `source`, `valid_from`, and
//! `valid_to`. A `used_in_decision` proposal takes a `decision` instead of a `value` and
//! records a `fact.used_in_decision` audit event on the believed fact(s) — how an agent
//! reports which facts informed a decision. Authority and
//! source resolve per line: the line's own fields, then the `--authority`/`--source` flags,
//! then the active signed grant (`DENT8_GRANT`), then the **agent tier of the default
//! authority profile** (`source:agent` at `low`) — so unattributed agent capture enters at
//! the bottom of the trust ordering instead of failing or minting authority.

use std::io::Read as _;
use std::str::FromStr;

use dent8_core::AuthorityLevel;

use crate::{
    CaptureArgs, CliAuthority, CliOutput, CliStream, CliSubject, WriteIdentity, first_line,
    log_path,
    ops::{
        OpError, Validity, op_assert, op_contradict, op_expire, op_reinforce, op_retract,
        op_supersede, op_used_in_decision, with_write_retry,
    },
    paint_status, parse_authority, print_json_stdout, print_json_stdout_with_code,
    status::Status,
};

/// The agent tier of the default authority profile (`dent8 authority defaults`): the
/// fallback identity for capture when neither the proposal, the flags, nor a signed grant
/// names one. Lowest requestable authority — captured agent facts start at the bottom of
/// the human > CI > agent ordering.
pub(crate) const CAPTURE_FALLBACK_SOURCE: &str = "source:agent";
pub(crate) const CAPTURE_FALLBACK_AUTHORITY: AuthorityLevel = AuthorityLevel::Low;

/// One structured fact proposal. Strict deserialization (`deny_unknown_fields`): capture
/// feeds the write boundary, and a typo'd field (`authorty`) silently defaulting to the
/// fallback tier would misattribute the write rather than fail loudly.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    /// The belief operation; defaults to `assert`.
    #[serde(default)]
    op: Option<String>,
    /// Fact subject as `<kind>:<key>`.
    subject: String,
    predicate: String,
    /// Required for `assert`/`supersede`/`contradict`; forbidden for the rest.
    #[serde(default)]
    value: Option<String>,
    /// What the fact informed. Required for `used_in_decision`; forbidden for the rest.
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    authority: Option<String>,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    valid_from: Option<i64>,
    #[serde(default)]
    valid_to: Option<i64>,
    /// Retention TTL as a human duration (e.g. `"90d"`, `"12h"`). Parsed like the `--ttl`
    /// flag and bounded by the predicate's retention ceiling. Absent leaves the predicate
    /// default (or non-expiring).
    #[serde(default)]
    ttl: Option<String>,
}

/// The outcome of one proposal line, in input order.
pub(crate) struct CaptureLineResult {
    line: usize,
    status: Status,
    message: String,
}

pub(crate) struct CaptureOutcome {
    results: Vec<CaptureLineResult>,
    accepted: usize,
    contested: usize,
    rejected: usize,
    invalid: usize,
    /// The consumed proposals file, when `--consume` truncated one.
    consumed: Option<String>,
    /// Rejected/malformed lines kept in the consumed file, when `--keep-failed` asked for
    /// them (`None` when it did not).
    kept_failed: Option<usize>,
}

impl CaptureOutcome {
    fn total(&self) -> usize {
        self.results.len()
    }

    /// The whole batch's status and exit code: malformed input dominates (exit 2), then a
    /// firewall rejection (exit 1 — a *safety signal* for hook logs, not a crash), then
    /// success. An empty batch is a clean no-op.
    fn overall(&self) -> (Status, i32) {
        if self.invalid > 0 {
            (Status::Invalid, 2)
        } else if self.rejected > 0 {
            (Status::Rejected, 1)
        } else if self.total() == 0 {
            (Status::Ok, 0)
        } else {
            (Status::Accepted, 0)
        }
    }
}

/// Resolve a proposal's authority + source: line fields > CLI flags > signed-grant defaults >
/// the agent tier of the default profile. Line-level values are validated here so a bad
/// proposal fails alone instead of poisoning the batch.
fn resolve_proposal_meta(
    proposal: &Proposal,
    flag_authority: Option<CliAuthority>,
    flag_source: Option<&str>,
) -> Result<(AuthorityLevel, String), String> {
    let line_authority = proposal
        .authority
        .as_deref()
        .map(|raw| {
            parse_authority(raw)
                .ok_or_else(|| format!("invalid authority {raw:?} (low|medium|high|canonical)"))
        })
        .transpose()?;
    let line_source = proposal
        .source
        .as_deref()
        .map(crate::parse_source)
        .transpose()?;

    let grant_defaults = crate::identity::IdentityContext::from_env()?.write_defaults()?;
    let authority = line_authority
        .or_else(|| flag_authority.map(CliAuthority::level))
        .or_else(|| grant_defaults.as_ref().map(|defaults| defaults.authority))
        .unwrap_or(CAPTURE_FALLBACK_AUTHORITY);
    let source = line_source
        .or_else(|| flag_source.map(ToString::to_string))
        .or_else(|| grant_defaults.map(|defaults| defaults.source))
        .unwrap_or_else(|| CAPTURE_FALLBACK_SOURCE.to_string());
    Ok((authority, source))
}

/// Parse and apply one proposal line through the shared op layer. `Invalid` never reaches
/// the store; `Rejected` is the firewall speaking.
pub(crate) fn apply_proposal(
    path: &str,
    raw: &str,
    flag_authority: Option<CliAuthority>,
    flag_source: Option<&str>,
) -> Result<String, OpError> {
    let proposal: Proposal = serde_json::from_str(raw)
        .map_err(|error| OpError::invalid(format!("malformed proposal: {error}")))?;
    let subject = CliSubject::from_str(&proposal.subject).map_err(OpError::invalid)?;
    let (authority, source) =
        resolve_proposal_meta(&proposal, flag_authority, flag_source).map_err(OpError::invalid)?;
    let ttl = proposal
        .ttl
        .as_deref()
        .map(crate::parse_duration_ms)
        .transpose()
        .map_err(OpError::invalid)?;
    let validity = Validity {
        from: proposal.valid_from,
        to: proposal.valid_to,
        ttl,
    };
    let op = proposal.op.as_deref().unwrap_or("assert");
    let takes_value = match op {
        "assert" | "supersede" | "contradict" => true,
        "reinforce" | "retract" | "expire" | "used_in_decision" => false,
        other => {
            return Err(OpError::invalid(format!(
                "unknown proposal op {other:?} \
                 (assert|supersede|reinforce|contradict|retract|expire|used_in_decision)"
            )));
        }
    };
    let value = match (takes_value, proposal.value.as_deref()) {
        (true, Some(value)) => value,
        (true, None) => {
            return Err(OpError::invalid(format!("{op} proposal requires a value")));
        }
        (false, Some(_)) => {
            return Err(OpError::invalid(format!("{op} proposal takes no value")));
        }
        (false, None) => "",
    };
    let decision = match (op, proposal.decision.as_deref()) {
        ("used_in_decision", Some(decision)) => decision,
        ("used_in_decision", None) => {
            return Err(OpError::invalid(
                "used_in_decision proposal requires a decision".to_string(),
            ));
        }
        (_, Some(_)) => {
            return Err(OpError::invalid(format!("{op} proposal takes no decision")));
        }
        (_, None) => "",
    };
    let identity = WriteIdentity::Env;
    let (kind, key, predicate) = (&subject.kind, &subject.key, proposal.predicate.as_str());
    // One retry wrapper around the dispatch: each attempt re-runs the whole op against a
    // fresh snapshot, exactly like the interactive write commands.
    with_write_retry(|| match op {
        "assert" => op_assert(
            path, kind, key, predicate, value, authority, &source, validity, &identity,
        ),
        "supersede" => op_supersede(
            path, kind, key, predicate, value, authority, &source, validity, &identity,
        ),
        "contradict" => op_contradict(
            path, kind, key, predicate, value, authority, &source, validity, &identity,
        ),
        "reinforce" => op_reinforce(path, kind, key, predicate, authority, &source, &identity),
        "retract" => op_retract(path, kind, key, predicate, authority, &source, &identity),
        "used_in_decision" => op_used_in_decision(
            path, kind, key, predicate, decision, authority, &source, &identity,
        ),
        _ => op_expire(path, kind, key, predicate, authority, &source, &identity),
    })
}

/// Process a whole batch of proposal lines. Every line is attempted — one bad or rejected
/// proposal must not silently drop the rest of a session's capture.
pub(crate) fn capture_outcome(
    path: &str,
    input: &str,
    flag_authority: Option<CliAuthority>,
    flag_source: Option<&str>,
) -> CaptureOutcome {
    let mut outcome = CaptureOutcome {
        results: Vec::new(),
        accepted: 0,
        contested: 0,
        rejected: 0,
        invalid: 0,
        consumed: None,
        kept_failed: None,
    };
    for (index, line) in input.lines().enumerate() {
        let line_no = index + 1;
        let raw = line.trim();
        if raw.is_empty() {
            continue;
        }
        let (status, message) = match apply_proposal(path, raw, flag_authority, flag_source) {
            Ok(message) => {
                if message.starts_with("CONTESTED") {
                    outcome.contested += 1;
                    (Status::Contested, message)
                } else {
                    outcome.accepted += 1;
                    (Status::Accepted, message)
                }
            }
            Err(OpError::Invalid { message, .. }) => {
                outcome.invalid += 1;
                (Status::Invalid, message)
            }
            Err(OpError::Rejected { message, .. } | OpError::Conflict(message)) => {
                outcome.rejected += 1;
                (Status::Rejected, message)
            }
        };
        outcome.results.push(CaptureLineResult {
            line: line_no,
            status,
            message,
        });
    }
    outcome
}

pub(crate) fn format_capture(outcome: &CaptureOutcome) -> String {
    if outcome.total() == 0 {
        return "no proposals to capture".to_string();
    }
    let mut lines = Vec::with_capacity(outcome.total() + 1);
    for result in &outcome.results {
        lines.push(format!(
            "line {}: {}",
            result.line,
            first_line(&result.message)
        ));
    }
    lines.push(format!(
        "captured {} proposal(s): {} accepted, {} contested, {} rejected, {} invalid",
        outcome.total(),
        outcome.accepted,
        outcome.contested,
        outcome.rejected,
        outcome.invalid
    ));
    if let Some(consumed) = &outcome.consumed {
        match outcome.kept_failed {
            Some(kept) if kept > 0 => lines.push(format!(
                "consumed {consumed} (kept {kept} failed proposal line(s) for inspection/retry)"
            )),
            _ => lines.push(format!("consumed {consumed}")),
        }
    }
    lines.join("\n")
}

/// The raw input lines whose proposals failed (rejected by the firewall or malformed) —
/// what `--consume --keep-failed` writes back to the proposals file, in input order, so a
/// failed proposal survives for inspection/retry instead of only in hook logs. Accepted and
/// contested lines are done; blank lines are dropped like the processor dropped them.
pub(crate) fn failed_lines<'a>(input: &'a str, outcome: &CaptureOutcome) -> Vec<&'a str> {
    let failed: std::collections::BTreeSet<usize> = outcome
        .results
        .iter()
        .filter(|result| matches!(result.status, Status::Rejected | Status::Invalid))
        .map(|result| result.line)
        .collect();
    input
        .lines()
        .enumerate()
        .filter(|(index, _)| failed.contains(&(index + 1)))
        .map(|(_, line)| line)
        .collect()
}

pub(crate) fn capture_json(outcome: &CaptureOutcome) -> serde_json::Value {
    let (status, _) = outcome.overall();
    serde_json::json!({
        "status": status.as_str(),
        "tool": "capture",
        "total": outcome.total(),
        "accepted": outcome.accepted,
        "contested": outcome.contested,
        "rejected": outcome.rejected,
        "invalid": outcome.invalid,
        "consumed": outcome.consumed,
        "kept_failed": outcome.kept_failed,
        "results": outcome
            .results
            .iter()
            .map(|result| {
                serde_json::json!({
                    "line": result.line,
                    "status": result.status.as_str(),
                    "message": result.message,
                })
            })
            .collect::<Vec<_>>(),
    })
}

/// Read the proposals: from the file when one is named, otherwise from stdin. The file path
/// exists precisely so a provider hook (whose *own* stdin carries the hook payload) can
/// flush a queue the agent wrote during the session.
fn read_proposals(file: Option<&str>) -> Result<String, String> {
    let Some(path) = file else {
        let mut raw = String::new();
        std::io::stdin()
            .read_to_string(&mut raw)
            .map_err(|error| format!("cannot read proposals from stdin: {error}"))?;
        return Ok(raw);
    };
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        // A missing queue file is an empty session, not an error — hooks fire whether or
        // not the agent proposed anything.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(format!("cannot read {path}: {error}")),
    }
}

pub(crate) fn cmd_capture(args: &CaptureArgs, output: CliOutput) -> i32 {
    let input = match read_proposals(args.file.as_deref()) {
        Ok(input) => input,
        Err(message) => {
            return match output {
                CliOutput::Text => {
                    eprintln!("{message}");
                    2
                }
                CliOutput::Json => print_json_stdout_with_code(
                    &serde_json::json!({
                        "status": Status::Invalid.as_str(),
                        "tool": "capture",
                        "message": message,
                    }),
                    2,
                ),
            };
        }
    };
    let mut outcome = capture_outcome(&log_path(), &input, args.authority, args.source.as_deref());
    // Consume after processing: every line was read and has a reported outcome, so the
    // queue's job is done — leaving it in place would replay the same proposals (and mint
    // duplicate uniqueness conflicts) on the next hook firing. With --keep-failed the
    // rejected/malformed lines are written back instead of truncated away, so a failed
    // proposal survives for inspection/retry rather than only in hook logs.
    if args.consume
        && let Some(path) = args.file.as_deref()
        && std::path::Path::new(path).exists()
    {
        let kept = if args.keep_failed {
            failed_lines(&input, &outcome)
        } else {
            Vec::new()
        };
        let contents = if kept.is_empty() {
            String::new()
        } else {
            let mut contents = kept.join("\n");
            contents.push('\n');
            contents
        };
        match std::fs::write(path, contents) {
            Ok(()) => {
                outcome.consumed = Some(path.to_string());
                outcome.kept_failed = args.keep_failed.then_some(kept.len());
            }
            Err(error) => eprintln!("warning: could not consume {path}: {error}"),
        }
    }
    let (_, code) = outcome.overall();
    match output {
        CliOutput::Text => {
            let text = format_capture(&outcome);
            if code == 0 {
                println!("{}", paint_status(&text, CliStream::Stdout));
            } else {
                eprintln!("{}", paint_status(&text, CliStream::Stderr));
            }
            code
        }
        CliOutput::Json => {
            if code == 0 {
                print_json_stdout(&capture_json(&outcome))
            } else {
                print_json_stdout_with_code(&capture_json(&outcome), code)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_log(name: &str) -> String {
        let dir =
            std::env::temp_dir().join(format!("dent8-capture-unit-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir.join("log.jsonl").to_string_lossy().into_owned()
    }

    #[test]
    fn capture_asserts_and_supersedes_through_the_firewall() {
        let log = temp_log("assert-supersede");
        let input = concat!(
            r#"{"subject": "repo:demo", "predicate": "uses_database", "value": "postgres", "authority": "medium", "source": "source:ci"}"#,
            "\n",
            r#"{"op": "supersede", "subject": "repo:demo", "predicate": "uses_database", "value": "sqlite", "authority": "high", "source": "source:human"}"#,
            "\n",
        );
        let outcome = capture_outcome(&log, input, None, None);
        assert_eq!(outcome.total(), 2);
        assert_eq!(outcome.accepted, 2, "{}", format_capture(&outcome));
        assert_eq!(outcome.overall().1, 0);
    }

    #[test]
    fn a_proposal_with_a_ttl_field_round_trips() {
        let proposal: Proposal = serde_json::from_str(
            r#"{"subject":"repo:demo","predicate":"note","value":"v","ttl":"90d"}"#,
        )
        .expect("a proposal carrying a ttl field must deserialize");
        assert_eq!(proposal.ttl.as_deref(), Some("90d"));
        // deny_unknown_fields is preserved: a typo'd field still fails loudly.
        assert!(
            serde_json::from_str::<Proposal>(
                r#"{"subject":"repo:demo","predicate":"note","value":"v","tt1":"90d"}"#,
            )
            .is_err(),
            "an unknown field must be rejected"
        );
    }

    #[test]
    fn capture_applies_a_proposal_ttl_and_enforces_the_ceiling() {
        let log = temp_log("ttl");
        let input = concat!(
            r#"{"subject": "repo:demo", "predicate": "note", "value": "temp", "authority": "high", "source": "source:human", "ttl": "30d"}"#,
            "\n",
            // Past the 90-day retention ceiling: rejected on write even for an unregistered predicate.
            r#"{"subject": "repo:demo", "predicate": "note", "value": "toolong", "authority": "high", "source": "source:human", "ttl": "120d"}"#,
            "\n",
        );
        let outcome = capture_outcome(&log, input, None, None);
        assert_eq!(outcome.accepted, 1, "{}", format_capture(&outcome));
        assert_eq!(outcome.rejected, 1, "{}", format_capture(&outcome));
        let contents = std::fs::read_to_string(&log).expect("read capture log");
        let thirty_days_ms = (30u64 * 86_400_000).to_string();
        assert!(
            contents.contains("DurationMillis") && contents.contains(&thirty_days_ms),
            "the captured fact must carry the finite {thirty_days_ms}ms TTL: {contents}"
        );
    }

    #[test]
    fn rejected_proposal_is_reported_not_dropped() {
        let log = temp_log("rejected");
        let input = concat!(
            r#"{"subject": "repo:demo", "predicate": "uses_database", "value": "postgres", "authority": "high", "source": "source:human"}"#,
            "\n",
            // A low-authority supersession cannot out-rank the High incumbent.
            r#"{"op": "supersede", "subject": "repo:demo", "predicate": "uses_database", "value": "mysql", "authority": "low", "source": "source:agent"}"#,
            "\n",
        );
        let outcome = capture_outcome(&log, input, None, None);
        assert_eq!(outcome.accepted, 1);
        assert_eq!(outcome.rejected, 1, "{}", format_capture(&outcome));
        let (status, code) = outcome.overall();
        assert_eq!(status, Status::Rejected);
        assert_eq!(code, 1);
    }

    #[test]
    fn malformed_and_unknown_op_lines_are_invalid() {
        let log = temp_log("invalid");
        let input = concat!(
            "not json\n",
            r#"{"subject": "repo:demo", "predicate": "p", "value": "v", "authorty": "high"}"#,
            "\n",
            r#"{"op": "merge", "subject": "repo:demo", "predicate": "p", "value": "v"}"#,
            "\n",
            r#"{"op": "reinforce", "subject": "repo:demo", "predicate": "p", "value": "v"}"#,
            "\n",
        );
        let outcome = capture_outcome(&log, input, None, None);
        assert_eq!(outcome.invalid, 4, "{}", format_capture(&outcome));
        let (status, code) = outcome.overall();
        assert_eq!(status, Status::Invalid);
        assert_eq!(code, 2);
        // Unknown field is called out (deny_unknown_fields).
        assert!(
            outcome.results[1].message.contains("authorty"),
            "{}",
            outcome.results[1].message
        );
    }

    #[test]
    fn unattributed_proposal_falls_back_to_the_agent_tier() {
        let log = temp_log("fallback");
        let input = concat!(
            r#"{"subject": "repo:demo", "predicate": "build_tool", "value": "cargo"}"#,
            "\n"
        );
        let outcome = capture_outcome(&log, input, None, None);
        assert_eq!(outcome.accepted, 1, "{}", format_capture(&outcome));
        assert!(
            outcome.results[0].message.contains("authority=low"),
            "{}",
            outcome.results[0].message
        );
        let persisted = std::fs::read_to_string(&log).expect("read log");
        assert!(persisted.contains(CAPTURE_FALLBACK_SOURCE), "{persisted}");
    }

    #[test]
    fn used_in_decision_proposals_record_the_audit_event() {
        let log = temp_log("used-in-decision");
        let input = concat!(
            r#"{"subject": "repo:demo", "predicate": "uses_database", "value": "postgres", "authority": "high", "source": "source:human"}"#,
            "\n",
            r#"{"op": "used_in_decision", "subject": "repo:demo", "predicate": "uses_database", "decision": "chose the sqlx driver"}"#,
            "\n",
            // A decision on nothing believed is a rejection, not a crash.
            r#"{"op": "used_in_decision", "subject": "repo:demo", "predicate": "missing", "decision": "x"}"#,
            "\n",
            // Malformed shapes fail alone: no decision, a stray decision, a stray value.
            r#"{"op": "used_in_decision", "subject": "repo:demo", "predicate": "uses_database"}"#,
            "\n",
            r#"{"op": "assert", "subject": "repo:demo", "predicate": "p", "value": "v", "decision": "x"}"#,
            "\n",
            r#"{"op": "used_in_decision", "subject": "repo:demo", "predicate": "uses_database", "value": "v", "decision": "x"}"#,
            "\n",
        );
        let outcome = capture_outcome(&log, input, None, None);
        assert_eq!(outcome.accepted, 2, "{}", format_capture(&outcome));
        assert_eq!(outcome.rejected, 1, "{}", format_capture(&outcome));
        assert_eq!(outcome.invalid, 3, "{}", format_capture(&outcome));
        assert!(
            outcome.results[1].message.contains("recorded decision use"),
            "{}",
            outcome.results[1].message
        );
        // The audit event is on the fact's stream: an unattributed reader (agent tier, low)
        // recorded that it used the high-authority fact — audit is not authority-gated.
        let persisted = std::fs::read_to_string(&log).expect("read log");
        assert!(persisted.contains("UsedInDecision"), "{persisted}");
        assert!(persisted.contains("chose the sqlx driver"), "{persisted}");
    }

    #[test]
    fn failed_lines_keep_rejected_and_malformed_proposals_in_input_order() {
        let log = temp_log("failed-lines");
        let input = concat!(
            r#"{"subject": "repo:demo", "predicate": "uses_database", "value": "postgres", "authority": "high", "source": "source:human"}"#,
            "\n",
            "\n", // blank lines are skipped by the processor and never kept
            r#"{"op": "supersede", "subject": "repo:demo", "predicate": "uses_database", "value": "mysql", "authority": "low", "source": "source:agent"}"#,
            "\n",
            "not json\n",
        );
        let outcome = capture_outcome(&log, input, None, None);
        assert_eq!(outcome.accepted, 1);
        assert_eq!(outcome.rejected, 1);
        assert_eq!(outcome.invalid, 1);
        let kept = failed_lines(input, &outcome);
        assert_eq!(kept.len(), 2, "{kept:?}");
        assert!(kept[0].contains("\"op\": \"supersede\""), "{kept:?}");
        assert_eq!(kept[1], "not json");
    }

    #[test]
    fn empty_input_is_a_clean_no_op() {
        let log = temp_log("empty");
        let outcome = capture_outcome(&log, "\n  \n", None, None);
        assert_eq!(outcome.total(), 0);
        let (status, code) = outcome.overall();
        assert_eq!(status, Status::Ok);
        assert_eq!(code, 0);
        assert_eq!(format_capture(&outcome), "no proposals to capture");
    }
}
