//! Install the enforced `PreToolUse` native-memory guard into an agent's project hook config.
//!
//! `dent8 init` wires this **by default** (opt out with `--no-native-memory-guard`) so a fresh
//! project blocks raw agent writes to `CLAUDE.md`/`AGENTS.md`/`.cursor/rules/*`/… out of the box
//! instead of shipping only a sample the user must copy in. The merge is idempotent: an existing
//! guard entry is replaced in place and unrelated hooks are preserved, so re-running init or
//! layering another agent never clobbers or duplicates hooks.
//!
//! The wired command **degrades gracefully**: it is guarded by `command -v dent8` so a clone
//! that has the hook in its settings but does not have the `dent8` binary on `PATH` allows the
//! write (exit 0) rather than bricking every edit. The guard only blocks once `dent8` is present.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::{InitAgent, write_atomic};

/// The exact shell command wired into an agent's `PreToolUse` guard entry. `command -v dent8`
/// makes it fail **open** (exit 0 = allow) when the binary is missing — a binary-less clone is
/// never bricked — while a present binary runs the enforced guard (`DENT8_HOOK_ENFORCE=1`), which
/// exits 2 on a native-memory write. The substrings here are what `dent8 doctor` matches to report
/// the guard as installed and enforced (see `doctor::inspect_agent_bypass_guard`).
pub(crate) const GUARD_COMMAND: &str = "command -v dent8 >/dev/null 2>&1 || exit 0; \
     DENT8_HOOK_MODE=guard-native-memory-write DENT8_HOOK_ENFORCE=1 dent8 hook native-memory-guard";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum HookAction {
    Created,
    Updated,
    Unchanged,
}

impl HookAction {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Unchanged => "unchanged",
        }
    }
}

pub(crate) struct HookInstallResult {
    pub(crate) path: PathBuf,
    pub(crate) action: HookAction,
}

impl HookInstallResult {
    pub(crate) fn changed(&self) -> bool {
        self.action != HookAction::Unchanged
    }

    pub(crate) fn message(&self) -> String {
        format!(
            "native-memory guard {} (enforced PreToolUse hook): {}",
            self.action.name(),
            self.path.display()
        )
    }
}

/// Merge the enforced native-memory guard into `target` for `agent`, idempotently. `agent` must be
/// a hook-capable profile (not `Hecate`, whose policy lives in a task payload, not a stable file);
/// callers resolve the target path via `doctor::agent_hook_config_path` and skip `Hecate`.
pub(crate) fn install_native_memory_guard(
    agent: InitAgent,
    target: &Path,
) -> Result<HookInstallResult, String> {
    let existing = match std::fs::read_to_string(target) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("cannot read {}: {error}", target.display())),
    };

    let mut root = match existing.as_deref() {
        Some(text) if !text.trim().is_empty() => {
            let value = serde_json::from_str::<Value>(text).map_err(|error| {
                format!("cannot parse hook config {}: {error}", target.display())
            })?;
            if !value.is_object() {
                return Err(format!(
                    "{} hook config root must be a JSON object",
                    target.display()
                ));
            }
            value
        }
        _ => Value::Object(Map::new()),
    };

    let object = root.as_object_mut().expect("hook config root object");
    if agent_needs_version_field(agent) && !object.contains_key("version") {
        object.insert("version".to_string(), json!(1));
    }

    let hooks = object
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| format!("{} hooks must be a JSON object", target.display()))?;

    let event_key = guard_event_key(agent);
    let entries = hooks
        .entry(event_key.to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| {
            format!(
                "{} hooks.{event_key} must be a JSON array",
                target.display()
            )
        })?;

    let entry = guard_entry(agent);
    if let Some(slot) = entries.iter_mut().find(|value| entry_is_dent8_guard(value)) {
        *slot = entry;
    } else {
        entries.push(entry);
    }

    let rendered = serde_json::to_string_pretty(&root)
        .map(ensure_trailing_newline)
        .map_err(|error| format!("cannot serialize hook config: {error}"))?;

    let changed = existing.as_deref() != Some(rendered.as_str());
    let action = match (existing.is_some(), changed) {
        (false, _) => HookAction::Created,
        (true, true) => HookAction::Updated,
        (true, false) => HookAction::Unchanged,
    };

    if changed {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        write_atomic(&target.to_string_lossy(), &rendered)?;
    }

    Ok(HookInstallResult {
        path: target.to_path_buf(),
        action,
    })
}

/// Only Cursor's hook config carries a top-level `{"version": 1}` envelope.
fn agent_needs_version_field(agent: InitAgent) -> bool {
    matches!(agent, InitAgent::Cursor)
}

/// The provider-specific key under `hooks` that fires before a tool runs.
fn guard_event_key(agent: InitAgent) -> &'static str {
    match agent {
        InitAgent::Codex | InitAgent::ClaudeCode | InitAgent::GrokBuild => "PreToolUse",
        InitAgent::Gemini => "BeforeTool",
        InitAgent::Cursor => "preToolUse",
        InitAgent::Cascade => "pre_write_code",
        // Hecate has no stable project hook file; callers skip it before reaching here.
        InitAgent::Hecate => unreachable!("Hecate has no stable project hook file"),
    }
}

/// The guard entry in each provider's expected shape, mirroring `examples/agent-hooks/<agent>/`.
fn guard_entry(agent: InitAgent) -> Value {
    match agent {
        InitAgent::ClaudeCode => nested_entry("Write|Edit|MultiEdit", None, 30),
        InitAgent::Codex => nested_entry("Bash|apply_patch|Edit|Write", None, 30),
        InitAgent::GrokBuild => nested_entry("Write|Edit|MultiEdit|Bash", None, 30),
        InitAgent::Gemini => nested_entry(
            "write_file|replace",
            Some("dent8-native-memory-guard"),
            30_000,
        ),
        InitAgent::Cursor => json!({
            "command": GUARD_COMMAND,
            "matcher": "Write|StrReplace|Edit|Shell|TabWrite|ApplyPatch",
        }),
        InitAgent::Cascade => json!({
            "command": GUARD_COMMAND,
            "show_output": true,
        }),
        InitAgent::Hecate => unreachable!("Hecate has no stable project hook file"),
    }
}

/// The `{matcher, hooks: [{...command...}]}` shape shared by Claude Code, Codex, Grok, and Gemini.
fn nested_entry(matcher: &str, name: Option<&str>, timeout: u64) -> Value {
    let mut inner = Map::new();
    if let Some(name) = name {
        inner.insert("name".to_string(), json!(name));
    }
    inner.insert("type".to_string(), json!("command"));
    inner.insert("command".to_string(), json!(GUARD_COMMAND));
    inner.insert("timeout".to_string(), json!(timeout));
    json!({
        "matcher": matcher,
        "hooks": [Value::Object(inner)],
    })
}

/// A hook entry is the dent8 guard if any string inside it invokes the guard command. Matching by
/// command (not by array position) is what keeps re-runs idempotent and leaves unrelated hooks be.
fn entry_is_dent8_guard(entry: &Value) -> bool {
    let mut strings = Vec::new();
    crate::doctor::collect_json_strings(entry, &mut strings);
    strings
        .iter()
        .any(|text| text.contains("dent8 hook native-memory-guard"))
}

fn ensure_trailing_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_command_degrades_gracefully_when_binary_is_absent() {
        // The wired command must fail OPEN when dent8 is missing: `command -v` short-circuits to
        // `exit 0` so a binary-less clone allows the write instead of bricking every edit.
        assert!(GUARD_COMMAND.starts_with("command -v dent8 >/dev/null 2>&1 || exit 0;"));
        assert!(GUARD_COMMAND.contains("DENT8_HOOK_ENFORCE=1"));
        assert!(GUARD_COMMAND.contains("DENT8_HOOK_MODE=guard-native-memory-write"));
        assert!(GUARD_COMMAND.contains("dent8 hook native-memory-guard"));
    }

    #[test]
    fn install_is_idempotent_and_preserves_unrelated_hooks() {
        let dir = std::env::temp_dir().join(format!("dent8-hookcfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let target = dir.join(".claude/settings.json");
        std::fs::create_dir_all(target.parent().unwrap()).expect("parent");
        // A pre-existing, unrelated PreToolUse hook must survive the merge.
        std::fs::write(
            &target,
            r#"{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":[{"type":"command","command":"echo keep-me"}]}]}}"#,
        )
        .expect("seed");

        let first = install_native_memory_guard(InitAgent::ClaudeCode, &target).expect("install");
        assert_eq!(first.action, HookAction::Updated);
        let written = std::fs::read_to_string(&target).expect("read settings");
        assert!(written.contains("dent8 hook native-memory-guard"));
        assert!(written.contains("echo keep-me"));
        assert!(written.contains("DENT8_HOOK_ENFORCE=1"));

        // Re-running is a no-op (no duplicate guard entry, unchanged file).
        let second = install_native_memory_guard(InitAgent::ClaudeCode, &target).expect("install");
        assert_eq!(second.action, HookAction::Unchanged);
        let rewritten = std::fs::read_to_string(&target).expect("read settings");
        assert_eq!(
            rewritten.matches("dent8 hook native-memory-guard").count(),
            1,
            "guard entry must not be duplicated on re-run"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cursor_install_writes_version_and_flat_entry() {
        let dir = std::env::temp_dir().join(format!("dent8-hookcfg-cursor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        let target = dir.join(".cursor/hooks.json");
        let result = install_native_memory_guard(InitAgent::Cursor, &target).expect("install");
        assert_eq!(result.action, HookAction::Created);
        let written = std::fs::read_to_string(&target).expect("read settings");
        let parsed: Value = serde_json::from_str(&written).expect("valid JSON");
        assert_eq!(parsed.get("version"), Some(&json!(1)));
        assert!(parsed["hooks"]["preToolUse"].is_array());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
