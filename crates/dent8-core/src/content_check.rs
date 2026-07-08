//! Pluggable write-time content-check hook.
//!
//! dent8's `append` arbitration governs **authority, provenance, and lifecycle** — it
//! deliberately never reads a fact's `value` text, so content-embedded attacks (injected
//! imperatives, exfil instructions, obfuscated payloads, confident falsehoods) are admitted
//! as inert data by design (see the honest non-blocks in `docs/evals.md`). This module is
//! the seam that lets a deployment compose an **external content scanner** into the write
//! boundary: dent8 ships **no classifier of its own** — the configured command (LLM Guard,
//! Rebuff, a Lakera/Azure Prompt Shields bridge, a bespoke model, …) owns the content
//! judgment, and dent8 owns running it on every candidate fact with no bypass.
//!
//! # Protocol (`dent8.content-check/1`)
//!
//! Per candidate fact (an event that carries a `value`), dent8 runs the configured command,
//! writes one JSON payload ([`candidate_payload`]) to its stdin, and reads one JSON verdict
//! object from its stdout:
//!
//! ```json
//! {"verdict": "allow"}
//! {"verdict": "reject", "reason": "why"}
//! {"verdict": "taint",  "reason": "why"}
//! ```
//!
//! `allow` admits the fact unchanged; `reject` refuses the write (nothing is persisted);
//! `taint` admits the fact **but marks it** — a detect-only flag recorded as an
//! [`Evidence`] item with a [`CONTENT_FLAG_LOCATOR_PREFIX`] locator, mirroring how
//! retraction taint rides `DerivedFrom` evidence (ADR 0010): stored in the event, surfaced
//! by `dent8 verify`, never silently dropped. Anything else — a non-zero exit, a timeout,
//! malformed output — is a **scanner failure**, not a verdict, and is resolved by the
//! configured [`FailurePolicy`].
//!
//! # Failure policy: fail-closed by default
//!
//! The default is [`FailurePolicy::FailClosed`]: a scanner you configured going dark must
//! not silently readmit unchecked content — an attacker who can crash or wedge the scanner
//! would otherwise hold a bypass. [`FailurePolicy::FailOpen`] (availability over scanning)
//! admits the write but still **marks it** with a fail-open content flag, so even the
//! permissive mode never admits unscanned content invisibly.
//!
//! No daemon and no network dependency live here: the hook is one short-lived subprocess
//! per candidate fact, `std::process` only. Unconfigured (`enforce` never called, or called
//! with no config by the CLI layer) is exact pass-through.

use std::fmt;
use std::io::{Read as _, Write as _};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::ids::EvidenceId;
use crate::model::{Evidence, EvidenceKind, FactEvent, FactValue};

/// The stdin payload's protocol marker, so scanners can version-check what they parse.
pub const CONTENT_CHECK_PROTOCOL: &str = "dent8.content-check/1";

/// The `Evidence::locator` prefix that marks a content flag: `content-check:<scanner>`.
/// The scanner's verdict is genuinely tool output, so the flag rides an ordinary
/// [`EvidenceKind::ToolOutput`] item — no new event field, old logs keep byte-identical
/// canonical form, and read surfaces detect the mark by this prefix.
pub const CONTENT_FLAG_LOCATOR_PREFIX: &str = "content-check:";

/// Cap on the scanner-supplied `reason` persisted into a content flag, so a hostile or
/// buggy scanner cannot stuff megabytes into the event log through its verdict.
const MAX_REASON_LEN: usize = 256;

/// How often a still-running scanner is re-polled while waiting for the timeout.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// What to do when the configured scanner itself fails (spawn error, timeout, non-zero
/// exit, malformed verdict). Fail-closed is the default: see the module docs.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FailurePolicy {
    /// Refuse the write. A configured-but-broken scanner blocks, never bypasses.
    #[default]
    FailClosed,
    /// Admit the write, but mark it with a fail-open content flag so the unscanned admit
    /// stays visible (`dent8 verify` surfaces it).
    FailOpen,
}

/// The configured external scanner: a command line (program + args), a per-fact timeout,
/// and the failure policy.
#[derive(Clone, Debug)]
pub struct ContentCheckConfig {
    /// The scanner command: `command[0]` is the program, the rest are its arguments.
    command: Vec<String>,
    /// Per-candidate-fact wall-clock budget; past it the scanner is killed and the run
    /// counts as a scanner failure.
    pub timeout: Duration,
    pub failure_policy: FailurePolicy,
}

impl ContentCheckConfig {
    /// The default per-fact timeout (5 seconds).
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

    /// A config for `command` (program + args) with the default timeout and the default
    /// fail-closed policy. Errors on an empty command.
    pub fn new(command: Vec<String>) -> Result<Self, String> {
        if command
            .first()
            .is_none_or(|program| program.trim().is_empty())
        {
            return Err("content check command cannot be empty".to_string());
        }
        Ok(Self {
            command,
            timeout: Self::DEFAULT_TIMEOUT,
            failure_policy: FailurePolicy::default(),
        })
    }

    /// The scanner's name as recorded in content flags: the configured program.
    #[must_use]
    pub fn scanner_name(&self) -> &str {
        &self.command[0]
    }
}

/// The scanner's judgment on one candidate fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Verdict {
    /// Admit the fact unchanged.
    Allow,
    /// Refuse the write; nothing is persisted.
    Reject { reason: Option<String> },
    /// Admit the fact but mark it (detect-only, like retraction taint).
    Taint { reason: Option<String> },
}

/// A scanner **failure** — not a verdict. Resolved by the configured [`FailurePolicy`].
#[derive(Clone, Debug)]
pub enum ScanError {
    /// The command could not be spawned (missing binary, permissions).
    Spawn(String),
    /// An I/O failure while feeding or reading the scanner.
    Io(String),
    /// The scanner did not answer within the configured timeout and was killed.
    Timeout(Duration),
    /// The scanner exited non-zero.
    NonZeroExit(String),
    /// The scanner's stdout was not a well-formed verdict object.
    MalformedVerdict(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(f, "could not spawn the scanner: {error}"),
            Self::Io(error) => write!(f, "scanner I/O failed: {error}"),
            Self::Timeout(timeout) => write!(
                f,
                "the scanner did not answer within {} ms and was killed",
                timeout.as_millis()
            ),
            Self::NonZeroExit(detail) => write!(f, "the scanner exited non-zero ({detail})"),
            Self::MalformedVerdict(detail) => {
                write!(f, "the scanner returned a malformed verdict: {detail}")
            }
        }
    }
}

impl std::error::Error for ScanError {}

/// Why [`enforce`] refused a batch: a scanner `reject` verdict, or a scanner failure under
/// the fail-closed policy.
#[derive(Clone, Debug)]
pub enum ContentCheckRefusal {
    /// The scanner rejected a candidate fact's content.
    Rejected {
        subject: String,
        predicate: String,
        reason: Option<String>,
    },
    /// The scanner itself failed and the policy is fail-closed: refuse rather than
    /// silently readmit unchecked content.
    ScannerUnavailable(ScanError),
}

impl fmt::Display for ContentCheckRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected {
                subject,
                predicate,
                reason,
            } => {
                write!(f, "content check rejected {subject} {predicate}")?;
                if let Some(reason) = reason {
                    write!(f, ": {reason}")?;
                }
                Ok(())
            }
            Self::ScannerUnavailable(error) => write!(
                f,
                "content check failed closed — {error} (the configured scanner must \
                 answer, or set DENT8_CONTENT_CHECK_FAIL_OPEN=1 to admit-but-flag)"
            ),
        }
    }
}

impl std::error::Error for ContentCheckRefusal {}

/// A persisted content flag read back off an event: the scanner that flagged it and its
/// stated reason.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentFlag {
    pub scanner: String,
    pub reason: String,
}

/// The first content flag on `event`, if any (an [`Evidence`] item whose locator carries
/// [`CONTENT_FLAG_LOCATOR_PREFIX`]).
#[must_use]
pub fn content_flag(event: &FactEvent) -> Option<ContentFlag> {
    event.evidence.iter().find_map(|item| {
        let scanner = item.locator.strip_prefix(CONTENT_FLAG_LOCATOR_PREFIX)?;
        Some(ContentFlag {
            scanner: scanner.to_string(),
            reason: item.summary.clone().unwrap_or_default(),
        })
    })
}

/// The `dent8.content-check/1` stdin payload for one candidate fact: everything a scanner
/// needs to judge the content — the value, the attacker-influenceable evidence strings,
/// and the arbitration-relevant metadata for context.
#[must_use]
pub fn candidate_payload(event: &FactEvent) -> serde_json::Value {
    let value = match &event.value {
        Some(FactValue::Text(text)) => serde_json::json!({ "kind": "text", "text": text }),
        Some(FactValue::Json(json)) => serde_json::json!({ "kind": "json", "json": json.as_str() }),
        Some(FactValue::Redacted) => serde_json::json!({ "kind": "redacted" }),
        None => serde_json::Value::Null,
    };
    let evidence: Vec<serde_json::Value> = event
        .evidence
        .iter()
        .map(|item| {
            serde_json::json!({
                "kind": format!("{:?}", item.kind),
                "locator": item.locator,
                "summary": item.summary,
            })
        })
        .collect();
    serde_json::json!({
        "protocol": CONTENT_CHECK_PROTOCOL,
        "event_id": event.event_id.as_str(),
        "fact_id": event.fact_id.as_str(),
        "event_type": event.kind.name(),
        "subject": { "kind": event.subject.kind(), "key": event.subject.key() },
        "predicate": event.predicate.as_str(),
        "value": value,
        "source": event.provenance.source.as_str(),
        "authority": event.authority.level.name(),
        "evidence": evidence,
    })
}

/// The wire form of a scanner's stdout. Extra fields are tolerated (forward compatibility);
/// an unknown `verdict` string is a malformed verdict, never a silent allow.
#[derive(Deserialize)]
struct WireVerdict {
    verdict: String,
    #[serde(default)]
    reason: Option<String>,
}

/// Run the configured scanner on one candidate fact and parse its verdict.
pub fn scan_event(config: &ContentCheckConfig, event: &FactEvent) -> Result<Verdict, ScanError> {
    let payload = candidate_payload(event).to_string();
    let stdout = run_scanner(config, &payload)?;
    parse_verdict(&stdout)
}

fn parse_verdict(stdout: &str) -> Result<Verdict, ScanError> {
    let trimmed = stdout.trim();
    let wire: WireVerdict = serde_json::from_str(trimmed).map_err(|error| {
        ScanError::MalformedVerdict(format!(
            "{error} (stdout: {})",
            truncate_chars(trimmed, 120)
        ))
    })?;
    let reason = wire
        .reason
        .map(|reason| truncate_chars(&reason, MAX_REASON_LEN));
    match wire.verdict.as_str() {
        "allow" => Ok(Verdict::Allow),
        "reject" => Ok(Verdict::Reject { reason }),
        "taint" => Ok(Verdict::Taint { reason }),
        other => Err(ScanError::MalformedVerdict(format!(
            "unknown verdict {other:?} (allow|reject|taint)"
        ))),
    }
}

/// Truncate on a char boundary so a multi-byte reason cannot panic the slice.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

/// Spawn the scanner, feed it `payload`, and collect stdout — bounded by the configured
/// timeout. Writer/reader run on threads so a scanner that neither reads its stdin nor
/// bounds its stdout cannot deadlock the write path; `try_wait` polling (std has no waiting
/// primitive with a deadline) keeps the whole run inside the budget, and a scanner that
/// overruns it is killed.
fn run_scanner(config: &ContentCheckConfig, payload: &str) -> Result<String, ScanError> {
    let mut child = Command::new(&config.command[0])
        .args(&config.command[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| ScanError::Spawn(format!("{}: {error}", config.command[0])))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ScanError::Io("scanner stdin unavailable".to_string()))?;
    let payload = payload.to_string();
    // Errors writing stdin are ignored deliberately: a scanner may legitimately decide
    // early and close its stdin (EPIPE); its verdict/exit status is what gets judged.
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(payload.as_bytes());
        drop(stdin);
    });
    let mut stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| ScanError::Io("scanner stdout unavailable".to_string()))?;
    let (send_stdout, recv_stdout) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut out = String::new();
        let read = stdout_pipe.read_to_string(&mut out).map(|_| ());
        let _ = send_stdout.send((read, out));
    });

    let status = match wait_with_timeout(&mut child, config.timeout) {
        Ok(status) => status,
        Err(error) => {
            // Detach the pipe threads instead of joining: a killed scanner may leave
            // orphaned grandchildren holding the pipes open (e.g. `sh` killed but a
            // process it spawned still alive), and joining would hand them the write
            // path's time.
            drop(writer);
            drop(reader);
            return Err(error);
        }
    };
    // The scanner exited; drain its stdout, still under a bounded wait — an orphaned
    // grandchild inheriting the pipe must not be able to wedge the write path either.
    // The writer is detached rather than joined for the same reason.
    drop(writer);
    let (read_result, stdout) = recv_stdout
        .recv_timeout(config.timeout)
        .map_err(|_| ScanError::Timeout(config.timeout))?;
    let _ = reader.join();
    read_result.map_err(|error| ScanError::Io(format!("reading scanner stdout: {error}")))?;
    if !status.success() {
        return Err(ScanError::NonZeroExit(format!(
            "{status}; stdout: {}",
            stdout.trim().chars().take(120).collect::<String>()
        )));
    }
    Ok(stdout)
}

/// Poll `try_wait` until exit or deadline; on deadline, kill and reap, and report a
/// timeout.
fn wait_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> Result<std::process::ExitStatus, ScanError> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(ScanError::Timeout(timeout));
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(ScanError::Io(format!("waiting for the scanner: {error}")));
            }
        }
    }
}

/// The content-flag evidence item recorded on a tainted (or fail-open) admit.
fn flag_evidence(event: &FactEvent, scanner: &str, reason: &str) -> Evidence {
    Evidence {
        id: EvidenceId::new(format!(
            "evidence:content-check:{}",
            event.event_id.as_str()
        ))
        .expect("a content-flag evidence id built from a non-empty event id is non-empty"),
        kind: EvidenceKind::ToolOutput,
        locator: format!("{CONTENT_FLAG_LOCATOR_PREFIX}{scanner}"),
        digest: None,
        summary: Some(reason.to_string()),
    }
}

/// Enforce the content check over a batch of candidate events, **before** they are
/// arbitrated, attested, or persisted. Only events that carry a `value` are scanned —
/// value-less lifecycle/audit events (supersession markers, retractions, retrieval
/// records) introduce no new content. A `reject` verdict (or a scanner failure under
/// fail-closed) refuses the whole batch so a multi-event operation stays all-or-nothing;
/// a `taint` verdict marks the event in place ([`content_flag`]).
pub fn enforce(
    config: &ContentCheckConfig,
    events: &mut [FactEvent],
) -> Result<(), ContentCheckRefusal> {
    for event in events.iter_mut() {
        if event.value.is_none() {
            continue;
        }
        match scan_event(config, event) {
            Ok(Verdict::Allow) => {}
            Ok(Verdict::Reject { reason }) => {
                return Err(ContentCheckRefusal::Rejected {
                    subject: format!("{}:{}", event.subject.kind(), event.subject.key()),
                    predicate: event.predicate.as_str().to_string(),
                    reason,
                });
            }
            Ok(Verdict::Taint { reason }) => {
                let reason = reason.unwrap_or_else(|| "flagged by the content check".to_string());
                let flag = flag_evidence(event, config.scanner_name(), &reason);
                event.evidence.push(flag);
            }
            Err(error) => match config.failure_policy {
                FailurePolicy::FailClosed => {
                    return Err(ContentCheckRefusal::ScannerUnavailable(error));
                }
                // Fail-open still marks the admit: unscanned content must stay visible.
                FailurePolicy::FailOpen => {
                    let reason = format!("content check unavailable (fail-open): {error}");
                    let reason = truncate_chars(&reason, MAX_REASON_LEN);
                    let flag = flag_evidence(event, config.scanner_name(), &reason);
                    event.evidence.push(flag);
                }
            },
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CONTENT_FLAG_LOCATOR_PREFIX, ContentCheckConfig, ContentCheckRefusal, FailurePolicy,
        ScanError, Verdict, candidate_payload, content_flag, enforce, parse_verdict,
    };
    use crate::ids::{ActorId, EvidenceId, FactEventId, FactId, SourceId, TimestampMillis};
    use crate::model::{
        Authority, AuthorityLevel, Confidence, Evidence, EvidenceKind, FactEvent, FactEventKind,
        FactValue, Predicate, Provenance, Subject, Ttl,
    };

    fn event(value: Option<&str>) -> FactEvent {
        FactEvent {
            event_id: FactEventId::new("event:1").expect("event id"),
            fact_id: FactId::new("fact:x").expect("fact id"),
            kind: FactEventKind::Asserted,
            subject: Subject::new("repo", "app").expect("subject"),
            predicate: Predicate::new("build_command").expect("predicate"),
            value: value.map(|text| FactValue::Text(text.to_string())),
            confidence: Confidence::ASSERTED,
            authority: Authority {
                level: AuthorityLevel::Low,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:agent").expect("source"),
                actor: ActorId::new("actor:test").expect("actor"),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(1),
                attestation: None,
            },
            evidence: vec![Evidence {
                id: EvidenceId::new("evidence:test").expect("evidence id"),
                kind: EvidenceKind::UserStatement,
                locator: "test".to_string(),
                digest: None,
                summary: None,
            }],
            observed_at: None,
            valid_from: None,
            valid_to: None,
        }
    }

    #[test]
    fn verdict_parsing_accepts_the_three_verdicts_and_rejects_the_rest() {
        assert_eq!(
            parse_verdict(r#"{"verdict":"allow"}"#).unwrap(),
            Verdict::Allow
        );
        assert_eq!(
            parse_verdict(r#"{"verdict":"reject","reason":"why"}"#).unwrap(),
            Verdict::Reject {
                reason: Some("why".to_string())
            }
        );
        assert_eq!(
            parse_verdict("  {\"verdict\":\"taint\"}\n").unwrap(),
            Verdict::Taint { reason: None }
        );
        // Extra fields are tolerated (forward compatibility).
        assert_eq!(
            parse_verdict(r#"{"verdict":"allow","score":0.1}"#).unwrap(),
            Verdict::Allow
        );
        // Unknown verdicts and non-JSON are malformed, never a silent allow.
        assert!(matches!(
            parse_verdict(r#"{"verdict":"maybe"}"#),
            Err(ScanError::MalformedVerdict(_))
        ));
        assert!(matches!(
            parse_verdict("yes"),
            Err(ScanError::MalformedVerdict(_))
        ));
    }

    #[test]
    fn a_multibyte_malformed_verdict_is_reported_without_panicking() {
        // 1 + 3*50 = 151 bytes but only 51 chars: byte 120 falls inside a '€',
        // so a byte slice at 120 would panic before the failure policy applied.
        let garbage = format!("a{}", "€".repeat(50));
        let error = parse_verdict(&garbage).expect_err("non-JSON must be malformed");
        assert!(matches!(error, ScanError::MalformedVerdict(_)));
    }

    #[test]
    fn the_candidate_payload_carries_the_content_and_the_protocol_marker() {
        let payload = candidate_payload(&event(Some("make test")));
        assert_eq!(payload["protocol"], super::CONTENT_CHECK_PROTOCOL);
        assert_eq!(payload["event_type"], "fact.asserted");
        assert_eq!(payload["subject"]["kind"], "repo");
        assert_eq!(payload["predicate"], "build_command");
        assert_eq!(payload["value"]["kind"], "text");
        assert_eq!(payload["value"]["text"], "make test");
        assert_eq!(payload["authority"], "low");
        assert_eq!(payload["evidence"][0]["locator"], "test");
    }

    #[test]
    fn a_scanner_reason_is_bounded_before_it_is_persisted() {
        let long = "x".repeat(10_000);
        let Verdict::Taint {
            reason: Some(reason),
        } = parse_verdict(&format!(r#"{{"verdict":"taint","reason":"{long}"}}"#)).unwrap()
        else {
            panic!("expected a taint verdict with a reason");
        };
        assert!(reason.chars().count() <= super::MAX_REASON_LEN + 1);
    }

    #[test]
    fn content_flags_round_trip_through_the_evidence_marker() {
        let mut flagged = event(Some("suspicious"));
        flagged
            .evidence
            .push(super::flag_evidence(&flagged, "demo.sh", "matched a rule"));
        let flag = content_flag(&flagged).expect("flag present");
        assert_eq!(flag.scanner, "demo.sh");
        assert_eq!(flag.reason, "matched a rule");
        assert!(
            flagged.evidence[1]
                .locator
                .starts_with(CONTENT_FLAG_LOCATOR_PREFIX)
        );
        assert!(content_flag(&event(Some("clean"))).is_none());
    }

    #[test]
    fn an_empty_command_is_refused_at_construction() {
        assert!(ContentCheckConfig::new(vec![]).is_err());
        assert!(ContentCheckConfig::new(vec![String::new()]).is_err());
        assert!(ContentCheckConfig::new(vec!["scanner".to_string()]).is_ok());
    }

    #[test]
    fn a_missing_scanner_fails_closed_by_default_and_flags_on_fail_open() {
        let mut config =
            ContentCheckConfig::new(vec!["/nonexistent/dent8-test-scanner".to_string()])
                .expect("config");
        let mut events = [event(Some("anything"))];
        let refusal = enforce(&config, &mut events).expect_err("fail-closed must refuse");
        assert!(matches!(
            refusal,
            ContentCheckRefusal::ScannerUnavailable(ScanError::Spawn(_))
        ));

        config.failure_policy = FailurePolicy::FailOpen;
        enforce(&config, &mut events).expect("fail-open admits");
        let flag = content_flag(&events[0]).expect("fail-open must mark the admit");
        assert!(flag.reason.contains("fail-open"), "{}", flag.reason);
    }

    #[test]
    fn value_less_events_are_not_scanned() {
        // A config pointing at a nonexistent scanner would fail closed if it ran at all.
        let config = ContentCheckConfig::new(vec!["/nonexistent/dent8-test-scanner".to_string()])
            .expect("config");
        let mut events = [event(None)];
        enforce(&config, &mut events).expect("no value, no scan, no failure");
    }

    // Verdict-driven behaviour through a real subprocess: `/bin/sh` scanners on Unix.
    #[cfg(unix)]
    mod subprocess {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;
        use std::time::Duration;

        use super::super::{
            ContentCheckConfig, ContentCheckRefusal, FailurePolicy, ScanError, Verdict,
            content_flag, enforce, scan_event,
        };
        use super::event;

        /// Serialize the subprocess tests: a concurrently-forked sibling can otherwise
        /// inherit another test's still-open script write fd between fork and exec,
        /// making that exec fail with ETXTBSY ("Text file busy").
        fn serialized() -> std::sync::MutexGuard<'static, ()> {
            static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            LOCK.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        }

        /// Write an executable scanner script into a fresh temp dir and return its path.
        fn scanner_script(body: &str) -> (std::path::PathBuf, tempdir::Guard) {
            let dir = tempdir::create();
            let path = dir.path.join("scanner.sh");
            let mut file = std::fs::File::create(&path).expect("create script");
            writeln!(file, "#!/bin/sh\n{body}").expect("write script");
            drop(file);
            let mut perms = std::fs::metadata(&path).expect("stat").permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).expect("chmod");
            (path, dir)
        }

        /// A minimal self-cleaning temp dir (no external crate; MSRV-safe).
        mod tempdir {
            use std::path::PathBuf;
            use std::sync::atomic::{AtomicU32, Ordering};

            pub struct Guard {
                pub path: PathBuf,
            }

            impl Drop for Guard {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir_all(&self.path);
                }
            }

            pub fn create() -> Guard {
                static COUNTER: AtomicU32 = AtomicU32::new(0);
                let path = std::env::temp_dir().join(format!(
                    "dent8-content-check-{}-{}",
                    std::process::id(),
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                ));
                std::fs::create_dir_all(&path).expect("create temp dir");
                Guard { path }
            }
        }

        fn config_for(path: &std::path::Path) -> ContentCheckConfig {
            ContentCheckConfig::new(vec![path.to_string_lossy().into_owned()]).expect("config")
        }

        #[test]
        fn allow_reject_and_taint_verdicts_drive_enforcement() {
            let _guard = serialized();
            let (path, _dir) = scanner_script(
                r#"input="$(cat)"
case "$input" in
  *poison*) printf '{"verdict":"reject","reason":"matched poison"}\n' ;;
  *odd*)    printf '{"verdict":"taint","reason":"looks odd"}\n' ;;
  *)        printf '{"verdict":"allow"}\n' ;;
esac"#,
            );
            let config = config_for(&path);

            assert_eq!(
                scan_event(&config, &event(Some("a clean fact"))).unwrap(),
                Verdict::Allow
            );

            let mut rejected = [event(Some("this is poison"))];
            let refusal = enforce(&config, &mut rejected).expect_err("reject verdict refuses");
            let ContentCheckRefusal::Rejected {
                subject,
                predicate,
                reason,
            } = refusal
            else {
                panic!("expected a rejection");
            };
            assert_eq!(subject, "repo:app");
            assert_eq!(predicate, "build_command");
            assert_eq!(reason.as_deref(), Some("matched poison"));

            let mut tainted = [event(Some("something odd"))];
            enforce(&config, &mut tainted).expect("taint admits");
            let flag = content_flag(&tainted[0]).expect("taint must mark");
            assert_eq!(flag.reason, "looks odd");

            let mut clean = [event(Some("a clean fact"))];
            enforce(&config, &mut clean).expect("allow admits");
            assert!(content_flag(&clean[0]).is_none(), "allow must not mark");
        }

        #[test]
        fn a_hung_scanner_is_killed_at_the_timeout_and_fails_closed() {
            let _guard = serialized();
            let (path, _dir) = scanner_script("cat > /dev/null\nsleep 60");
            let mut config = config_for(&path);
            config.timeout = Duration::from_millis(200);

            let started = std::time::Instant::now();
            let error = scan_event(&config, &event(Some("anything"))).expect_err("must time out");
            assert!(matches!(error, ScanError::Timeout(_)), "{error}");
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the kill must not wait for the scanner's sleep"
            );

            let mut events = [event(Some("anything"))];
            let refusal = enforce(&config, &mut events).expect_err("fail-closed refuses");
            assert!(matches!(
                refusal,
                ContentCheckRefusal::ScannerUnavailable(ScanError::Timeout(_))
            ));
        }

        #[test]
        fn a_non_zero_exit_and_garbage_stdout_are_scanner_failures() {
            let _guard = serialized();
            let (crash, _dir_a) = scanner_script("cat > /dev/null\nexit 3");
            let error =
                scan_event(&config_for(&crash), &event(Some("x"))).expect_err("non-zero exit");
            assert!(matches!(error, ScanError::NonZeroExit(_)), "{error}");

            let (garbage, _dir_b) = scanner_script("cat > /dev/null\necho not-json");
            let error =
                scan_event(&config_for(&garbage), &event(Some("x"))).expect_err("garbage stdout");
            assert!(matches!(error, ScanError::MalformedVerdict(_)), "{error}");
        }

        #[test]
        fn fail_open_admits_a_broken_scanner_run_but_marks_it() {
            let _guard = serialized();
            let (path, _dir) = scanner_script("cat > /dev/null\nexit 3");
            let mut config = config_for(&path);
            config.failure_policy = FailurePolicy::FailOpen;
            let mut events = [event(Some("anything"))];
            enforce(&config, &mut events).expect("fail-open admits");
            let flag = content_flag(&events[0]).expect("fail-open must mark");
            assert!(flag.reason.contains("fail-open"), "{}", flag.reason);
        }
    }
}
