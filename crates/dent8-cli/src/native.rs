//! Read-only audit of agent-native memory/rules files. These files are integration surfaces
//! around dent8, not the source of truth; this module inventories them and reuses the same path
//! classifier as the native-memory hook guard.

use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use dent8_core::FactLifecycle;
use sha2::{Digest, Sha256};

use crate::doctor::{self, BypassGuardStatus};
use crate::ops::{self, OpError, ReadClock};
use crate::{
    CliOutput, InitAgent, NativeReconcileArgs, NativeScanArgs, absolute_path, log_path,
    print_json_stdout, receipt_fields_json,
};

#[derive(Debug)]
pub(crate) struct NativeScan {
    pub(crate) agent: InitAgent,
    pub(crate) root: PathBuf,
    pub(crate) dent8_dir: PathBuf,
    pub(crate) guard: NativeGuardSummary,
    pub(crate) files: Vec<NativeFile>,
}

#[derive(Debug)]
pub(crate) struct NativeGuardSummary {
    pub(crate) status: &'static str,
    pub(crate) protected: bool,
    pub(crate) path: Option<PathBuf>,
    pub(crate) message: String,
}

#[derive(Debug)]
pub(crate) struct NativeFile {
    pub(crate) path: PathBuf,
    pub(crate) relative_path: String,
    pub(crate) kind: &'static str,
    pub(crate) size_bytes: u64,
    pub(crate) modified_unix_ms: Option<i64>,
    pub(crate) sha256: Option<String>,
    pub(crate) has_receipt_marker: bool,
    pub(crate) read_error: Option<String>,
}

#[derive(Debug)]
pub(crate) struct NativeReconcile {
    scan: NativeScan,
    references: Vec<NativeReconcileReference>,
}

#[derive(Debug)]
struct NativeReconcileReference {
    file: NativeFileRef,
    reference: NativeReceiptReference,
    status: ReconcileStatus,
    message: String,
    receipt: Option<dent8_store::IntegrityReceipt>,
}

#[derive(Clone, Debug)]
struct NativeFileRef {
    relative_path: String,
    kind: &'static str,
}

#[derive(Clone, Debug)]
struct NativeReceiptReference {
    uri: String,
    line: usize,
    column: usize,
    subject_kind: Option<String>,
    subject_key: Option<String>,
    predicate: Option<String>,
    parse_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconcileStatus {
    Ok,
    Stale,
    NotYetValid,
    Contested,
    NoLongerBelieved,
    Missing,
    Invalid,
}

impl ReconcileStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Stale => "stale",
            Self::NotYetValid => "not_yet_valid",
            Self::Contested => "contested",
            Self::NoLongerBelieved => "no_longer_believed",
            Self::Missing => "missing",
            Self::Invalid => "invalid",
        }
    }

    const fn is_failure(self) -> bool {
        !matches!(self, Self::Ok)
    }
}

pub(crate) fn cmd_native_scan(args: &NativeScanArgs, output: CliOutput) -> i32 {
    match scan_from_args(args) {
        Ok(scan) => match output {
            CliOutput::Text => {
                print!("{}", native_scan_text(&scan));
                0
            }
            CliOutput::Json => print_json_stdout(&native_scan_json(&scan)),
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                2
            }
            CliOutput::Json => crate::print_json_stdout_with_code(
                &serde_json::json!({
                    "status": "invalid",
                    "tool": "native scan",
                    "error": error,
                }),
                2,
            ),
        },
    }
}

pub(crate) fn cmd_native_reconcile(args: &NativeReconcileArgs, output: CliOutput) -> i32 {
    match reconcile_from_args(args) {
        Ok(reconcile) => {
            let code = i32::from(reconcile_has_failures(&reconcile));
            match output {
                CliOutput::Text => {
                    print!("{}", native_reconcile_text(&reconcile));
                    code
                }
                CliOutput::Json => {
                    crate::print_json_stdout_with_code(&native_reconcile_json(&reconcile), code)
                }
            }
        }
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                2
            }
            CliOutput::Json => crate::print_json_stdout_with_code(
                &serde_json::json!({
                    "status": "invalid",
                    "tool": "native reconcile",
                    "error": error,
                }),
                2,
            ),
        },
    }
}

pub(crate) fn scan_from_args(args: &NativeScanArgs) -> Result<NativeScan, String> {
    scan_from_options(args.agent, &args.dir, args.root.as_deref())
}

pub(crate) fn scan_from_options(
    agent: InitAgent,
    dent8_dir: &str,
    root: Option<&str>,
) -> Result<NativeScan, String> {
    let dent8_dir = absolute_path(&PathBuf::from(dent8_dir))?;
    let root = match root {
        Some(root) => absolute_path(&PathBuf::from(root))?,
        None => native_scan_root_for_dir(&dent8_dir)?,
    };
    scan_agent_native_memory(agent, &dent8_dir, &root)
}

fn reconcile_from_args(args: &NativeReconcileArgs) -> Result<NativeReconcile, String> {
    reconcile_from_options(
        args.agent,
        &args.dir,
        args.root.as_deref(),
        ReadClock {
            as_of: args.as_of,
            valid_at: args.valid_at,
        },
        &log_path(),
    )
}

pub(crate) fn reconcile_from_options(
    agent: InitAgent,
    dent8_dir: &str,
    root: Option<&str>,
    clock: ReadClock,
    store_path: &str,
) -> Result<NativeReconcile, String> {
    let scan = scan_from_options(agent, dent8_dir, root)?;
    reconcile_scan(scan, clock, store_path)
}

fn reconcile_scan(
    scan: NativeScan,
    clock: ReadClock,
    store_path: &str,
) -> Result<NativeReconcile, String> {
    let mut references = Vec::new();
    for file in &scan.files {
        let Some(text) = read_native_file_text(&file.path)? else {
            continue;
        };
        let file_ref = NativeFileRef {
            relative_path: file.relative_path.clone(),
            kind: file.kind,
        };
        for reference in extract_receipt_references(&text) {
            references.push(reconcile_reference(
                file_ref.clone(),
                reference,
                clock,
                store_path,
            ));
        }
    }
    Ok(NativeReconcile { scan, references })
}

pub(crate) fn scan_agent_native_memory(
    agent: InitAgent,
    dent8_dir: &Path,
    root: &Path,
) -> Result<NativeScan, String> {
    let root = absolute_path(root)?;
    let dent8_dir = absolute_path(dent8_dir)?;
    let guard = guard_summary(doctor::inspect_agent_bypass_guard(agent, &dent8_dir));
    let mut files = collect_native_files(&root)?;
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    Ok(NativeScan {
        agent,
        root,
        dent8_dir,
        guard,
        files,
    })
}

pub(crate) fn native_scan_root_for_dir(dent8_dir: &Path) -> Result<PathBuf, String> {
    let dir = absolute_path(dent8_dir)?;
    if dir.file_name().is_some_and(|name| name == ".dent8")
        && let Some(parent) = dir.parent()
    {
        return Ok(parent.to_path_buf());
    }
    std::env::current_dir().map_err(|error| format!("current dir: {error}"))
}

fn guard_summary(status: BypassGuardStatus) -> NativeGuardSummary {
    match status {
        BypassGuardStatus::Enforced(path) => NativeGuardSummary {
            status: "enforced",
            protected: true,
            message: format!("native-memory guard is enforced in {}", path.display()),
            path: Some(path),
        },
        BypassGuardStatus::Advisory(path) => NativeGuardSummary {
            status: "advisory",
            protected: false,
            message: format!(
                "native-memory guard exists in {} but is not enforced",
                path.display()
            ),
            path: Some(path),
        },
        BypassGuardStatus::Missing(path) => NativeGuardSummary {
            status: "missing",
            protected: false,
            message: format!("no native-memory guard found at {}", path.display()),
            path: Some(path),
        },
        BypassGuardStatus::Unreadable(path, error) => NativeGuardSummary {
            status: "unreadable",
            protected: false,
            message: format!("could not inspect {}: {error}", path.display()),
            path: Some(path),
        },
        BypassGuardStatus::Unvalidated(reason) => NativeGuardSummary {
            status: "unvalidated",
            protected: false,
            message: reason,
            path: None,
        },
    }
}

fn collect_native_files(root: &Path) -> Result<Vec<NativeFile>, String> {
    let mut files = Vec::new();
    for file in [
        "AGENTS.md",
        "CLAUDE.md",
        "CLAUDE.local.md",
        "GEMINI.md",
        "MEMORY.md",
        ".windsurfrules",
    ] {
        collect_file_if_native(root, &root.join(file), &mut files);
    }
    for dir in [".cursor/rules", ".devin/rules", ".windsurf/rules"] {
        collect_native_dir(root, &root.join(dir), &mut files)?;
    }
    Ok(files)
}

fn collect_native_dir(root: &Path, dir: &Path, files: &mut Vec<NativeFile>) -> Result<(), String> {
    let Ok(metadata) = std::fs::metadata(dir) else {
        return Ok(());
    };
    if !metadata.is_dir() {
        return Ok(());
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|error| format!("cannot read native memory dir {}: {error}", dir.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot read native memory dir entry: {error}"))?;
        let path = entry.path();
        let metadata = entry
            .metadata()
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
        if metadata.is_dir() {
            collect_native_dir(root, &path, files)?;
        } else if metadata.is_file() {
            collect_file_if_native(root, &path, files);
        }
    }
    Ok(())
}

fn collect_file_if_native(root: &Path, path: &Path, files: &mut Vec<NativeFile>) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if !metadata.is_file() {
        return;
    }
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    if !is_native_memory_path(&relative) {
        return;
    }
    let modified_unix_ms = metadata.modified().ok().and_then(system_time_unix_ms);
    let (sha256, has_receipt_marker, read_error) = read_file_audit_fields(path);
    files.push(NativeFile {
        path: path.to_path_buf(),
        relative_path: relative,
        kind: native_memory_kind(path),
        size_bytes: metadata.len(),
        modified_unix_ms,
        sha256,
        has_receipt_marker,
        read_error,
    });
}

fn system_time_unix_ms(time: std::time::SystemTime) -> Option<i64> {
    let millis = time.duration_since(UNIX_EPOCH).ok()?.as_millis();
    i64::try_from(millis).ok()
}

fn read_file_audit_fields(path: &Path) -> (Option<String>, bool, Option<String>) {
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) => return (None, false, Some(error.to_string())),
    };
    let mut bytes = Vec::new();
    if let Err(error) = file.read_to_end(&mut bytes) {
        return (None, false, Some(error.to_string()));
    }
    let sha256 = Some(hex::encode(Sha256::digest(&bytes)));
    let text = String::from_utf8_lossy(&bytes);
    (sha256, has_receipt_marker(&text), None)
}

fn read_native_file_text(path: &Path) -> Result<Option<String>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot read native memory file {}: {error}",
            path.display()
        )),
    }
}

fn has_receipt_marker(text: &str) -> bool {
    text.contains("dent8://")
        || text.contains("DENT8_RECEIPT")
        // A dent8-managed export block is a sanctioned, receipt-bearing surface even when it is
        // empty (no believed facts to embed a `dent8://` ref yet), so recognize its sentinel.
        || text.contains("dent8 managed block")
        || (text.contains("fact_id") && text.contains("event_hash"))
        || (text.contains("fact:") && text.contains("event_hash"))
}

fn extract_receipt_references(text: &str) -> Vec<NativeReceiptReference> {
    let mut references = Vec::new();
    for (line_index, line) in text.lines().enumerate() {
        let mut offset = 0;
        while let Some(relative_start) = line[offset..].find("dent8://") {
            let start = offset + relative_start;
            let tail = &line[start..];
            let end = tail
                .char_indices()
                .find_map(|(idx, ch)| uri_token_terminator(ch).then_some(idx))
                .unwrap_or(tail.len());
            let uri = tail[..end].to_string();
            references.push(parse_receipt_reference(uri, line_index + 1, start + 1));
            offset = start + end.max("dent8://".len());
            if offset >= line.len() {
                break;
            }
        }
    }
    references
}

fn uri_token_terminator(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '"' | '\'' | '`' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
        )
}

fn parse_receipt_reference(uri: String, line: usize, column: usize) -> NativeReceiptReference {
    let Some(rest) = uri.strip_prefix("dent8://") else {
        return invalid_reference(uri, line, column, "missing dent8:// scheme");
    };
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.trim().is_empty()) {
        return invalid_reference(
            uri,
            line,
            column,
            "expected dent8://<kind>/<key>/<predicate>",
        );
    }
    let subject_kind = parts[0].to_string();
    let subject_key = parts[1].to_string();
    let predicate = parts[2].to_string();
    NativeReceiptReference {
        uri,
        line,
        column,
        subject_kind: Some(subject_kind),
        subject_key: Some(subject_key),
        predicate: Some(predicate),
        parse_error: None,
    }
}

fn invalid_reference(
    uri: String,
    line: usize,
    column: usize,
    error: impl Into<String>,
) -> NativeReceiptReference {
    NativeReceiptReference {
        uri,
        line,
        column,
        subject_kind: None,
        subject_key: None,
        predicate: None,
        parse_error: Some(error.into()),
    }
}

fn reconcile_reference(
    file: NativeFileRef,
    reference: NativeReceiptReference,
    clock: ReadClock,
    store_path: &str,
) -> NativeReconcileReference {
    if let Some(error) = reference.parse_error.clone() {
        return NativeReconcileReference {
            file,
            reference,
            status: ReconcileStatus::Invalid,
            message: error,
            receipt: None,
        };
    }
    let subject_kind = reference
        .subject_kind
        .as_deref()
        .expect("validated reference has subject kind");
    let subject_key = reference
        .subject_key
        .as_deref()
        .expect("validated reference has subject key");
    let predicate = reference
        .predicate
        .as_deref()
        .expect("validated reference has predicate");
    match ops::op_explain_receipt(store_path, subject_kind, subject_key, predicate, clock) {
        Ok(receipt) => {
            let status = receipt_status(&receipt);
            let message = match status {
                ReconcileStatus::Ok => format!(
                    "current receipt verified (fact_id={}, hash={})",
                    receipt.fact_id.as_str(),
                    crate::short(&receipt.event_hash)
                ),
                ReconcileStatus::Stale => "receipt resolves, but the fact is stale".to_string(),
                ReconcileStatus::NotYetValid => {
                    "receipt resolves, but the fact is not yet valid".to_string()
                }
                ReconcileStatus::Contested => {
                    "receipt resolves, but the fact is contested".to_string()
                }
                ReconcileStatus::NoLongerBelieved => {
                    "receipt resolves, but the fact is no longer believed".to_string()
                }
                ReconcileStatus::Missing | ReconcileStatus::Invalid => {
                    unreachable!("receipt status is derived from an existing receipt")
                }
            };
            NativeReconcileReference {
                file,
                reference,
                status,
                message,
                receipt: Some(receipt),
            }
        }
        Err(error) => {
            let status = match error {
                OpError::Invalid(_) => ReconcileStatus::Invalid,
                OpError::Rejected(_) | OpError::Conflict(_) => ReconcileStatus::Missing,
            };
            let message = error.message().to_string();
            NativeReconcileReference {
                file,
                reference,
                status,
                message,
                receipt: None,
            }
        }
    }
}

fn receipt_status(receipt: &dent8_store::IntegrityReceipt) -> ReconcileStatus {
    if receipt.lifecycle == FactLifecycle::Contested {
        ReconcileStatus::Contested
    } else if receipt.lifecycle.is_terminal() {
        ReconcileStatus::NoLongerBelieved
    } else if receipt.not_yet_valid {
        ReconcileStatus::NotYetValid
    } else if !receipt.fresh {
        ReconcileStatus::Stale
    } else {
        ReconcileStatus::Ok
    }
}

fn native_memory_kind(path: &Path) -> &'static str {
    let path = path.to_string_lossy().replace('\\', "/");
    if path.ends_with("AGENTS.md") {
        "agent_instructions"
    } else if path.ends_with("CLAUDE.md") || path.ends_with("CLAUDE.local.md") {
        "claude_memory"
    } else if path.ends_with("GEMINI.md") {
        "gemini_memory"
    } else if path.ends_with("MEMORY.md") {
        "memory"
    } else if path.contains("/.cursor/rules/") || path.starts_with(".cursor/rules/") {
        "cursor_rules"
    } else if path.contains("/.devin/rules/") || path.starts_with(".devin/rules/") {
        "devin_rules"
    } else if path.contains("/.windsurf/rules/")
        || path.starts_with(".windsurf/rules/")
        || path.ends_with(".windsurfrules")
    {
        "windsurf_rules"
    } else {
        "native_memory"
    }
}

pub(crate) fn native_scan_text(scan: &NativeScan) -> String {
    let mut out = format!(
        "dent8 native scan\n  agent: {}\n  root: {}\n  guard: {} ({})\n",
        scan.agent.cli_name(),
        scan.root.display(),
        scan.guard.status,
        scan.guard.message,
    );
    if scan.files.is_empty() {
        out.push_str("  files: none\n");
        return out;
    }
    let receipt_count = scan
        .files
        .iter()
        .filter(|file| file.has_receipt_marker)
        .count();
    let _ = writeln!(
        out,
        "  files: {} native memory/rules file(s), {} with dent8 receipt markers",
        scan.files.len(),
        receipt_count,
    );
    for file in &scan.files {
        let receipt = if file.has_receipt_marker {
            "receipt=yes"
        } else {
            "receipt=no"
        };
        let hash = file
            .sha256
            .as_ref()
            .map_or("sha256=<unreadable>".to_string(), |hash| {
                format!("sha256={}", &hash[..12])
            });
        let _ = writeln!(
            out,
            "  - {} ({}, {} bytes, {hash}, {receipt})",
            file.relative_path, file.kind, file.size_bytes,
        );
        if let Some(error) = &file.read_error {
            let _ = writeln!(out, "    read_error: {error}");
        }
    }
    out
}

pub(crate) fn native_scan_json(scan: &NativeScan) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": "native scan",
        "agent": scan.agent.cli_name(),
        "root": scan.root,
        "dent8_dir": scan.dent8_dir,
        "guard": {
            "status": scan.guard.status,
            "protected": scan.guard.protected,
            "path": scan.guard.path,
            "message": scan.guard.message,
        },
        "files": scan.files.iter().map(native_file_json).collect::<Vec<_>>(),
        "summary": {
            "files": scan.files.len(),
            "with_receipt_markers": scan.files.iter().filter(|file| file.has_receipt_marker).count(),
            "without_receipt_markers": scan.files.iter().filter(|file| !file.has_receipt_marker).count(),
            "guard_protected": scan.guard.protected,
        },
    })
}

pub(crate) fn native_reconcile_text(reconcile: &NativeReconcile) -> String {
    let summary = reconcile_summary(reconcile);
    let status = if summary.failures == 0 {
        "ok"
    } else {
        "failed"
    };
    let mut out = format!(
        "dent8 native reconcile\n  status: {status}\n  agent: {}\n  root: {}\n  guard: {} ({})\n  files: {} native memory/rules file(s), {} with dent8 references\n  references: {} checked, {} ok, {} problem(s)\n",
        reconcile.scan.agent.cli_name(),
        reconcile.scan.root.display(),
        reconcile.scan.guard.status,
        reconcile.scan.guard.message,
        summary.files,
        summary.files_with_references,
        summary.references,
        summary.ok,
        summary.failures,
    );
    if !summary.unreferenced_files.is_empty() {
        out.push_str("  unreferenced native files:\n");
        for file in &summary.unreferenced_files {
            let _ = writeln!(out, "  - {file}");
        }
    }
    if reconcile.references.is_empty() {
        out.push_str("  receipt references: none\n");
        return out;
    }
    out.push_str("  receipt references:\n");
    for reference in &reconcile.references {
        let _ = writeln!(
            out,
            "  - {}:{}:{} {} -> {} ({})",
            reference.file.relative_path,
            reference.reference.line,
            reference.reference.column,
            reference.reference.uri,
            reference.status.as_str(),
            reference.message,
        );
    }
    out
}

pub(crate) fn native_reconcile_json(reconcile: &NativeReconcile) -> serde_json::Value {
    let summary = reconcile_summary(reconcile);
    serde_json::json!({
        "status": if summary.failures == 0 { "ok" } else { "failed" },
        "tool": "native reconcile",
        "agent": reconcile.scan.agent.cli_name(),
        "root": reconcile.scan.root,
        "dent8_dir": reconcile.scan.dent8_dir,
        "guard": {
            "status": reconcile.scan.guard.status,
            "protected": reconcile.scan.guard.protected,
            "path": reconcile.scan.guard.path,
            "message": reconcile.scan.guard.message,
        },
        "files": reconcile.scan.files.iter().map(native_file_json).collect::<Vec<_>>(),
        "references": reconcile.references.iter().map(reconcile_reference_json).collect::<Vec<_>>(),
        "summary": {
            "files": summary.files,
            "files_with_references": summary.files_with_references,
            "unreferenced_files": summary.unreferenced_files,
            "references": summary.references,
            "ok": summary.ok,
            "failures": summary.failures,
            "stale": summary.stale,
            "not_yet_valid": summary.not_yet_valid,
            "contested": summary.contested,
            "no_longer_believed": summary.no_longer_believed,
            "missing": summary.missing,
            "invalid": summary.invalid,
            "guard_protected": reconcile.scan.guard.protected,
        },
    })
}

fn reconcile_reference_json(reference: &NativeReconcileReference) -> serde_json::Value {
    serde_json::json!({
        "file": {
            "relative_path": reference.file.relative_path,
            "kind": reference.file.kind,
        },
        "reference": {
            "uri": reference.reference.uri,
            "line": reference.reference.line,
            "column": reference.reference.column,
            "subject": match (&reference.reference.subject_kind, &reference.reference.subject_key) {
                (Some(kind), Some(key)) => serde_json::json!({ "kind": kind, "key": key }),
                _ => serde_json::Value::Null,
            },
            "predicate": reference.reference.predicate,
            "parse_error": reference.reference.parse_error,
        },
        "status": reference.status.as_str(),
        "ok": !reference.status.is_failure(),
        "message": reference.message,
        "receipt": reference.receipt.as_ref().map(receipt_fields_json),
    })
}

struct NativeReconcileSummary {
    files: usize,
    files_with_references: usize,
    unreferenced_files: Vec<String>,
    references: usize,
    ok: usize,
    failures: usize,
    stale: usize,
    not_yet_valid: usize,
    contested: usize,
    no_longer_believed: usize,
    missing: usize,
    invalid: usize,
}

fn reconcile_summary(reconcile: &NativeReconcile) -> NativeReconcileSummary {
    let referenced_files: std::collections::BTreeSet<&str> = reconcile
        .references
        .iter()
        .map(|reference| reference.file.relative_path.as_str())
        .collect();
    let unreferenced_files = reconcile
        .scan
        .files
        .iter()
        .filter(|file| !referenced_files.contains(file.relative_path.as_str()))
        .map(|file| file.relative_path.clone())
        .collect::<Vec<_>>();
    let mut summary = NativeReconcileSummary {
        files: reconcile.scan.files.len(),
        files_with_references: referenced_files.len(),
        unreferenced_files,
        references: reconcile.references.len(),
        ok: 0,
        failures: 0,
        stale: 0,
        not_yet_valid: 0,
        contested: 0,
        no_longer_believed: 0,
        missing: 0,
        invalid: 0,
    };
    for reference in &reconcile.references {
        match reference.status {
            ReconcileStatus::Ok => summary.ok += 1,
            ReconcileStatus::Stale => summary.stale += 1,
            ReconcileStatus::NotYetValid => summary.not_yet_valid += 1,
            ReconcileStatus::Contested => summary.contested += 1,
            ReconcileStatus::NoLongerBelieved => summary.no_longer_believed += 1,
            ReconcileStatus::Missing => summary.missing += 1,
            ReconcileStatus::Invalid => summary.invalid += 1,
        }
    }
    summary.failures = summary.references.saturating_sub(summary.ok);
    summary
}

pub(crate) fn reconcile_has_failures(reconcile: &NativeReconcile) -> bool {
    reconcile
        .references
        .iter()
        .any(|reference| reference.status.is_failure())
}

fn native_file_json(file: &NativeFile) -> serde_json::Value {
    serde_json::json!({
        "path": file.path,
        "relative_path": file.relative_path,
        "kind": file.kind,
        "size_bytes": file.size_bytes,
        "modified_unix_ms": file.modified_unix_ms,
        "sha256": file.sha256,
        "has_receipt_marker": file.has_receipt_marker,
        "read_error": file.read_error,
    })
}

pub(crate) fn native_memory_paths_in_payload(payload: &serde_json::Value) -> Vec<String> {
    let mut paths = std::collections::BTreeSet::new();
    for candidate in hook_candidate_strings(payload) {
        let normalized = candidate.replace('\\', "/");
        if is_native_memory_path(&normalized) {
            paths.insert(normalized);
            continue;
        }
        // The candidate may be a shell command or an `apply_patch` body that *writes* a native
        // memory file with the path embedded (not as the whole string) — e.g. `echo x >> AGENTS.md`
        // or an `*** Update File: AGENTS.md` header. Pull out the write targets and check those.
        for target in embedded_write_targets(&normalized) {
            if is_native_memory_path(&target) {
                paths.insert(target);
            }
        }
    }
    paths.into_iter().collect()
}

/// Best-effort extraction of the file paths a shell command or `apply_patch` body **writes**:
/// `apply_patch` `*** Update/Add/Delete File:` / `*** Move to:` headers, and `>` / `>>` /
/// `tee` redirect targets. Deliberately conservative — it flags *write* targets, not mere
/// mentions (so `cat AGENTS.md` is not flagged), and does not model every shell write mechanism
/// (`sed -i`, `cp`, `mv`, an interpreter writing a file): the MCP/CLI firewall, not this hook,
/// is the integrity boundary. See `examples/agent-hooks/README.md`.
fn embedded_write_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        for prefix in [
            "*** Update File: ",
            "*** Add File: ",
            "*** Delete File: ",
            "*** Move to: ",
        ] {
            if let Some(rest) = line.strip_prefix(prefix) {
                targets.push(unquote(rest.trim()));
            }
        }
    }
    let tokens: Vec<&str> = text.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if *token == ">" || *token == ">>" {
            // Spaced redirection: the next token is the destination file.
            if let Some(next) = tokens.get(idx + 1) {
                targets.push(unquote(next));
            }
        } else if let Some(rest) = token.strip_prefix(">>").or_else(|| token.strip_prefix('>')) {
            // Attached redirection: `>file` / `>>file`.
            if !rest.is_empty() {
                targets.push(unquote(rest));
            }
        } else if *token == "tee" {
            // `tee [-a] FILE`: the first non-flag argument is a write target.
            if let Some(arg) = tokens[idx + 1..].iter().find(|arg| !arg.starts_with('-')) {
                targets.push(unquote(arg));
            }
        }
    }
    targets
}

/// Strip surrounding shell quotes and normalize backslashes for path matching.
fn unquote(token: &str) -> String {
    token.trim_matches(['"', '\'']).replace('\\', "/")
}

fn hook_candidate_strings(value: &serde_json::Value) -> Vec<&str> {
    fn walk<'a>(value: &'a serde_json::Value, out: &mut Vec<&'a str>) {
        const PATH_KEYS: &[&str] = &[
            "absolute_path",
            "file",
            "filePath",
            "file_path",
            "new_path",
            "old_path",
            "path",
            "relative_path",
            "target_file",
        ];
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if PATH_KEYS.contains(&key.as_str())
                        && let Some(path) = child.as_str()
                    {
                        out.push(path);
                    }
                    walk(child, out);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    walk(child, out);
                }
            }
            serde_json::Value::String(text) if hook_string_looks_like_path(text) => {
                out.push(text);
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

fn hook_string_looks_like_path(value: &str) -> bool {
    [
        "/",
        "\\",
        "AGENTS.md",
        "CLAUDE.md",
        "CLAUDE.local.md",
        "GEMINI.md",
        "MEMORY.md",
        ".cursor/rules",
        ".devin/rules",
        ".windsurf/rules",
        ".windsurfrules",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

pub(crate) fn is_native_memory_path(path: &str) -> bool {
    let path = path.trim_start_matches("./");
    let ends_with_named_file = [
        "AGENTS.md",
        "CLAUDE.md",
        "CLAUDE.local.md",
        "GEMINI.md",
        "MEMORY.md",
    ]
    .iter()
    .any(|name| {
        path == *name
            || path
                .strip_suffix(name)
                .is_some_and(|prefix| prefix.ends_with('/'))
    });
    if ends_with_named_file {
        return true;
    }

    if path == ".windsurfrules" || path.ends_with("/.windsurfrules") {
        return true;
    }

    let in_cursor_rules = path.starts_with(".cursor/rules/") || path.contains("/.cursor/rules/");
    let has_rule_ext = Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("mdc"));
    if in_cursor_rules && has_rule_ext {
        return true;
    }

    let in_devin_rules = path.starts_with(".devin/rules/") || path.contains("/.devin/rules/");
    let in_windsurf_rules =
        path.starts_with(".windsurf/rules/") || path.contains("/.windsurf/rules/");
    let has_md_ext = Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
    (in_devin_rules || in_windsurf_rules) && has_md_ext
}

#[cfg(test)]
mod tests {
    use super::has_receipt_marker;

    #[test]
    fn receipt_marker_recognizes_refs_and_managed_block_but_not_arbitrary_prose() {
        // A rendered `dent8://` receipt reference.
        assert!(has_receipt_marker(
            "- `dent8://repo/demo/db` = \"postgres\""
        ));
        // A dent8-managed export block sentinel, even with no believed facts to embed a ref.
        assert!(has_receipt_marker(
            "<!-- BEGIN dent8 managed block (generated by `dent8 export`; edits inside are overwritten) -->\n<!-- END dent8 managed block -->"
        ));
        // Explicit receipt fields.
        assert!(has_receipt_marker("fact_id=fact:x event_hash=abc"));
        // Arbitrary prose is not a receipt-bearing surface.
        assert!(!has_receipt_marker(
            "# CLAUDE.md\n\nJust some hand-written project notes about dent8."
        ));
    }
}
