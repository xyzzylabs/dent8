//! Read-only audit of agent-native memory/rules files. These files are integration surfaces
//! around dent8, not the source of truth; this module inventories them and reuses the same path
//! classifier as the native-memory hook guard.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use sha2::{Digest, Sha256};

use crate::doctor::{self, BypassGuardStatus};
use crate::{CliOutput, InitAgent, NativeScanArgs, absolute_path, print_json_stdout};

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

pub(crate) fn scan_from_args(args: &NativeScanArgs) -> Result<NativeScan, String> {
    let dent8_dir = absolute_path(&PathBuf::from(&args.dir))?;
    let root = match &args.root {
        Some(root) => absolute_path(&PathBuf::from(root))?,
        None => native_scan_root_for_dir(&dent8_dir)?,
    };
    scan_agent_native_memory(args.agent, &dent8_dir, &root)
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
        collect_file_if_native(root, &root.join(file), &mut files)?;
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
            collect_file_if_native(root, &path, files)?;
        }
    }
    Ok(())
}

fn collect_file_if_native(
    root: &Path,
    path: &Path,
    files: &mut Vec<NativeFile>,
) -> Result<(), String> {
    let Ok(metadata) = std::fs::metadata(path) else {
        return Ok(());
    };
    if !metadata.is_file() {
        return Ok(());
    }
    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    if !is_native_memory_path(&relative) {
        return Ok(());
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
    Ok(())
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

fn has_receipt_marker(text: &str) -> bool {
    text.contains("dent8://")
        || text.contains("DENT8_RECEIPT")
        || (text.contains("fact_id") && text.contains("event_hash"))
        || (text.contains("fact:") && text.contains("event_hash"))
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
    } else if path.contains("/.windsurf/rules/") || path.starts_with(".windsurf/rules/") {
        "windsurf_rules"
    } else if path.ends_with(".windsurfrules") {
        "windsurf_rules"
    } else {
        "native_memory"
    }
}

fn native_scan_text(scan: &NativeScan) -> String {
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
    out.push_str(&format!(
        "  files: {} native memory/rules file(s), {} with dent8 receipt markers\n",
        scan.files.len(),
        receipt_count,
    ));
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
        out.push_str(&format!(
            "  - {} ({}, {} bytes, {hash}, {receipt})\n",
            file.relative_path, file.kind, file.size_bytes,
        ));
        if let Some(error) = &file.read_error {
            out.push_str(&format!("    read_error: {error}\n"));
        }
    }
    out
}

fn native_scan_json(scan: &NativeScan) -> serde_json::Value {
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
