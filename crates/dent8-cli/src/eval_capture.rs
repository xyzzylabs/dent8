//! Opt-in capture of store-level arbitration attempts for legitimate-traffic evaluation.
//!
//! `DENT8_EVAL_CAPTURE=<path>` enables a raw, append-only JSONL journal. Recording is
//! deliberately fail-open: an eval artifact must never change whether a production write lands.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use dent8_core::FactEvent;
use dent8_evals::{
    CAPTURE_JOURNAL_SCHEMA, CaptureJournalRecord, CapturedDecision, CapturedOutcome, TraceContent,
    TraceOperationKind, TraceOrigin, TracePrivacy, TraceProvenance,
};
use dent8_store::{EventFilter, EventStore, InMemoryEventStore};

use crate::status::ErrorCode;

const CAPTURE_ENV: &str = "DENT8_EVAL_CAPTURE";
const AGENT_ENV: &str = "DENT8_EVAL_AGENT";
const SESSION_ENV: &str = "DENT8_EVAL_SESSION";
const RAW_NOTE: &str =
    "raw FactEvents and baseline state; redact before sharing or marking redacted";
static ATTEMPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A held capture-file lock plus the state immediately before one operation.
pub(crate) struct EvalCapture {
    active: Option<ActiveCapture>,
}

struct ActiveCapture {
    file: File,
    operation: TraceOperationKind,
    operation_id: String,
    recorded_at: i64,
    baseline_events: Vec<FactEvent>,
}

impl EvalCapture {
    /// Begin a capture at the point an event batch is ready to enter store arbitration.
    /// The returned no-op guard is cheap when capture is disabled or unavailable.
    pub(crate) fn begin(
        operation: TraceOperationKind,
        source: &str,
        store: &InMemoryEventStore,
    ) -> Self {
        let Some(path) = capture_path() else {
            return Self { active: None };
        };
        match Self::try_begin(&path, operation, source, store) {
            Ok(capture) => capture,
            Err(error) => {
                eprintln!("warning: dent8 eval capture disabled for this write: {error}");
                Self { active: None }
            }
        }
    }

    fn try_begin(
        path: &Path,
        operation: TraceOperationKind,
        source: &str,
        store: &InMemoryEventStore,
    ) -> Result<Self, String> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                format!(
                    "cannot create capture directory {}: {error}",
                    parent.display()
                )
            })?;
        }

        let mut options = OpenOptions::new();
        options.create(true).read(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = file
                .metadata()
                .map_err(|error| format!("cannot inspect {} permissions: {error}", path.display()))?
                .permissions();
            permissions.set_mode(0o600);
            file.set_permissions(permissions).map_err(|error| {
                format!("cannot restrict {} to mode 0600: {error}", path.display())
            })?;
        }
        file.lock()
            .map_err(|error| format!("cannot lock {}: {error}", path.display()))?;

        let provenance = TraceProvenance {
            origin: TraceOrigin::Captured,
            agent: capture_agent(source),
            session: env_text(SESSION_ENV),
        };
        let privacy = TracePrivacy {
            content: TraceContent::Raw,
            note: Some(RAW_NOTE.to_string()),
        };
        if file
            .metadata()
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?
            .len()
            == 0
        {
            let now = unix_millis();
            let header = CaptureJournalRecord::Header {
                schema: CAPTURE_JOURNAL_SCHEMA.to_string(),
                capture_id: format!("capture:{now}:{}", unique_suffix()),
                provenance,
                privacy,
            };
            append_record(&mut file, &header)?;
        } else {
            validate_existing_header(&file, &provenance)?;
        }

        let baseline_events = store
            .scan_events(&EventFilter::default())
            .map_err(|error| format!("cannot snapshot capture baseline: {error}"))?;
        let recorded_at = unix_millis();
        Ok(Self {
            active: Some(ActiveCapture {
                file,
                operation,
                operation_id: format!("attempt:{recorded_at}:{}", unique_suffix()),
                recorded_at,
                baseline_events,
            }),
        })
    }

    pub(crate) fn admitted(self, events: &[FactEvent]) {
        self.finish(
            events,
            CapturedOutcome {
                decision: CapturedDecision::Admitted,
                code: None,
            },
        );
    }

    pub(crate) fn rejected(self, events: &[FactEvent], code: ErrorCode) {
        self.finish(
            events,
            CapturedOutcome {
                decision: CapturedDecision::Rejected,
                code: Some(code.as_str().to_string()),
            },
        );
    }

    fn finish(self, events: &[FactEvent], observed: CapturedOutcome) {
        let Some(mut active) = self.active else {
            return;
        };
        let record = CaptureJournalRecord::Attempt {
            schema: CAPTURE_JOURNAL_SCHEMA.to_string(),
            operation_id: active.operation_id,
            operation: active.operation,
            recorded_at: active.recorded_at,
            baseline_events: active.baseline_events,
            events: events.to_vec(),
            observed,
        };
        if let Err(error) = append_record(&mut active.file, &record) {
            eprintln!("warning: dent8 eval capture could not record this write: {error}");
        }
    }
}

fn append_record(file: &mut File, record: &CaptureJournalRecord) -> Result<(), String> {
    let mut encoded = serde_json::to_vec(record)
        .map_err(|error| format!("cannot serialize capture record: {error}"))?;
    encoded.push(b'\n');
    file.write_all(&encoded)
        .map_err(|error| format!("cannot append capture record: {error}"))?;
    file.flush()
        .and_then(|()| file.sync_data())
        .map_err(|error| format!("cannot sync capture record: {error}"))
}

fn validate_existing_header(file: &File, provenance: &TraceProvenance) -> Result<(), String> {
    let reader = BufReader::new(
        file.try_clone()
            .map_err(|error| format!("cannot inspect capture header: {error}"))?,
    );
    let line = reader
        .lines()
        .find_map(|line| match line {
            Ok(line) if !line.trim().is_empty() => Some(Ok(line)),
            Ok(_) => None,
            Err(error) => Some(Err(error)),
        })
        .transpose()
        .map_err(|error| format!("cannot read capture header: {error}"))?
        .ok_or_else(|| "capture file has no header".to_string())?;
    let record: CaptureJournalRecord = serde_json::from_str(&line)
        .map_err(|error| format!("existing capture header is invalid: {error}"))?;
    let CaptureJournalRecord::Header {
        schema,
        capture_id,
        provenance: existing,
        privacy,
        ..
    } = record
    else {
        return Err("existing capture does not start with a header record".to_string());
    };
    if schema != CAPTURE_JOURNAL_SCHEMA {
        return Err(format!(
            "existing capture uses schema {schema:?}, expected {CAPTURE_JOURNAL_SCHEMA}"
        ));
    }
    if capture_id.trim().is_empty() {
        return Err("existing capture header has an empty capture_id".to_string());
    }
    if privacy.content != TraceContent::Raw {
        return Err("existing capture header must declare privacy.content=raw".to_string());
    }
    if existing != *provenance {
        return Err(format!(
            "existing capture belongs to agent {:?} session {:?}; use a separate file for agent {:?} session {:?}",
            existing.agent, existing.session, provenance.agent, provenance.session
        ));
    }
    Ok(())
}

fn capture_path() -> Option<std::path::PathBuf> {
    env_text(CAPTURE_ENV).map(Into::into)
}

fn capture_agent(source: &str) -> String {
    env_text(AGENT_ENV)
        .unwrap_or_else(|| source.strip_prefix("source:").unwrap_or(source).to_string())
}

fn env_text(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn unix_millis() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

fn unique_suffix() -> String {
    let mut random = [0u8; 8];
    if getrandom::getrandom(&mut random).is_ok() {
        return hex::encode(random);
    }
    let sequence = ATTEMPT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{}-{sequence}", std::process::id())
}
