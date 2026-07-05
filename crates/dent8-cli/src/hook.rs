//! The `dent8 hook native-memory-guard` helper for provider hook systems: block or audit
//! direct writes to agent-native memory/rules files (`CLAUDE.md`, `AGENTS.md`,
//! `.cursor/rules/*`, …) so durable facts flow through the firewall instead. Best-effort by
//! design — the MCP/CLI write path is the integrity boundary; this is the seatbelt (see
//! `examples/agent-hooks/`).

use crate::{env_flag, log_path, verify_log};

/// Built-in helper for provider hook systems. It intentionally does not write native memory
/// files; it only runs `verify` or blocks writes that would bypass the fact-event firewall.
pub(crate) fn cmd_hook_native_memory_guard() -> i32 {
    let mode = std::env::var("DENT8_HOOK_MODE")
        .unwrap_or_else(|_| "guard-native-memory-write".to_string());

    if mode == "session-start" {
        return hook_verify("session start");
    }

    if mode != "guard-native-memory-write" && mode != "post-write-audit" {
        eprintln!("dent8 hook: unknown DENT8_HOOK_MODE={mode}");
        return 2;
    }

    // The payload could not be read or parsed, so we cannot tell whether a native memory file is
    // being written. The blocking guard fails closed under enforcement; the post-write audit
    // re-verifies the chain rather than assume nothing changed.
    let Some(payload) = read_hook_payload() else {
        return match mode.as_str() {
            "post-write-audit" => hook_verify("unreadable post-write hook payload"),
            _ if hook_enforced() => {
                eprintln!(
                    "dent8 hook: unreadable payload under DENT8_HOOK_ENFORCE — blocking (fail closed)."
                );
                2
            }
            _ => 0,
        };
    };

    let touched = native_memory_paths(&payload);
    if mode == "post-write-audit" {
        if touched.is_empty() {
            return 0;
        }
        return hook_verify(&format!(
            "native memory/rules changed: {}",
            touched.join(", ")
        ));
    }

    // guard-native-memory-write
    if touched.is_empty() {
        return 0;
    }

    eprintln!(
        "dent8 native memory/rules guard: direct writes to {} bypass the fact-event firewall. \
         Use dent8 MCP tools or an explicit reviewed export from dent8. Set \
         DENT8_ALLOW_NATIVE_MEMORY_WRITE=1 to bypass this local guard.",
        touched.join(", ")
    );

    if hook_allow_bypass() {
        return 0;
    }
    if hook_enforced() { 2 } else { 0 }
}

/// `DENT8_HOOK_ENFORCE` turns a guard hit (or an unreadable payload) into a blocking exit 2.
/// Parsed like every dent8 boolean (`1`/`true`/`yes`/`on`); a malformed value **fails closed**
/// (treated as enforcing) so a typo cannot silently disable enforcement.
fn hook_enforced() -> bool {
    match env_flag("DENT8_HOOK_ENFORCE") {
        Ok(value) => value,
        Err(message) => {
            eprintln!("dent8 hook: {message}");
            true
        }
    }
}

/// `DENT8_ALLOW_NATIVE_MEMORY_WRITE` is the explicit local bypass. A malformed value never grants
/// a bypass (treated as unset), so a typo cannot accidentally open the guard.
fn hook_allow_bypass() -> bool {
    match env_flag("DENT8_ALLOW_NATIVE_MEMORY_WRITE") {
        Ok(value) => value,
        Err(message) => {
            eprintln!("dent8 hook: {message}");
            false
        }
    }
}

/// Read the hook JSON from stdin. `Some(Null)` is an empty payload (nothing to guard); `None`
/// means stdin could not be read or did not parse as JSON, so callers can fail closed.
fn read_hook_payload() -> Option<serde_json::Value> {
    let mut raw = String::new();
    let mut stdin = std::io::stdin();
    if let Err(error) = std::io::Read::read_to_string(&mut stdin, &mut raw) {
        eprintln!("dent8 hook: could not read hook JSON: {error}");
        return None;
    }
    if raw.trim().is_empty() {
        return Some(serde_json::Value::Null);
    }
    match serde_json::from_str(&raw) {
        Ok(value) => Some(value),
        Err(error) => {
            eprintln!("dent8 hook: could not parse hook JSON: {error}");
            None
        }
    }
}

fn hook_verify(reason: &str) -> i32 {
    eprintln!("dent8 hook: verify ({reason})");
    match verify_log(&log_path()) {
        Ok(report) => {
            eprintln!("{report}");
            0
        }
        Err(message) => {
            eprintln!("{message}");
            1
        }
    }
}

fn native_memory_paths(payload: &serde_json::Value) -> Vec<String> {
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
/// `apply_patch` `*** Update/Add/Delete File:` / `*** Move to:` headers, and `>` / `>>` / `tee`
/// redirect targets. Deliberately conservative — it flags *write* targets, not mere mentions (so
/// `cat AGENTS.md` is not flagged), and does not model every shell write mechanism (`sed -i`,
/// `cp`, `mv`, an interpreter writing a file): the MCP/CLI firewall, not this hook, is the
/// integrity boundary. See `examples/agent-hooks/README.md`.
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

fn is_native_memory_path(path: &str) -> bool {
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
    let has_rule_ext = std::path::Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("mdc"));
    if in_cursor_rules && has_rule_ext {
        return true;
    }

    let in_devin_rules = path.starts_with(".devin/rules/") || path.contains("/.devin/rules/");
    let in_windsurf_rules =
        path.starts_with(".windsurf/rules/") || path.contains("/.windsurf/rules/");
    let has_md_ext = std::path::Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
    (in_devin_rules || in_windsurf_rules) && has_md_ext
}
