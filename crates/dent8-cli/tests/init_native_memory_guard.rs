//! `dent8 init` wires the enforced `PreToolUse` native-memory guard **by default**, closing the old
//! bypass where the guard shipped only as a sample the user had to copy in. These tests would have
//! failed before this change (init installed no hook) and pin the three guarantees: default-on,
//! opt-out, and graceful degrade on a binary-less clone.

use std::{
    io::Write as _,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use serde_json::Value;

fn dent8_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dent8"))
}

fn unique_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dent8-init-guard-{tag}-{}-{:?}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp project dir");
    dir
}

/// Run `dent8 init` with a scrubbed env inside `project`, using the default file store.
fn run_init(project: &PathBuf, extra: &[&str]) -> Output {
    let mut command = Command::new(dent8_bin());
    command
        .arg("init")
        .args(extra)
        .current_dir(project)
        .env_remove("DENT8_STORE_URL")
        .env_remove("DENT8_LOG")
        .env_remove("DENT8_HOOK_ENFORCE")
        .env_remove("DENT8_ALLOW_NATIVE_MEMORY_WRITE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.output().expect("run dent8 init")
}

/// The exact guard command string the installed hook runs (extracted so tests exercise the real
/// wiring, not a hand-copied approximation).
fn guard_command_from_settings(settings: &Value) -> String {
    let hooks = settings["hooks"]["PreToolUse"]
        .as_array()
        .expect("PreToolUse array");
    for entry in hooks {
        for hook in entry["hooks"].as_array().into_iter().flatten() {
            let command = hook["command"].as_str().unwrap_or_default();
            if command.contains("dent8 hook native-memory-guard") {
                return command.to_string();
            }
        }
    }
    panic!("no native-memory guard command found in PreToolUse hooks");
}

/// Feed `payload` to `dent8 hook native-memory-guard` under the same enforcing env the installed
/// hook sets.
fn run_guard(payload: &str) -> Output {
    let mut command = Command::new(dent8_bin());
    command
        .args(["hook", "native-memory-guard"])
        .env("DENT8_HOOK_MODE", "guard-native-memory-write")
        .env("DENT8_HOOK_ENFORCE", "1")
        .env_remove("DENT8_ALLOW_NATIVE_MEMORY_WRITE")
        .env_remove("DENT8_STORE_URL")
        .env_remove("DENT8_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().expect("spawn guard");
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(payload.as_bytes());
    }
    child.wait_with_output().expect("wait for guard")
}

const CLAUDE_WRITE: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/CLAUDE.md"}}"#;
const AGENTS_EDIT: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Edit","tool_input":{"file_path":"/repo/AGENTS.md"}}"#;
const CODE_WRITE: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/src/lib.rs"}}"#;

#[test]
fn default_init_installs_enforced_guard_and_blocks_native_memory_writes() {
    let project = unique_dir("default");
    let output = run_init(&project, &[]);
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The default agent (claude-code) settings file exists and carries the enforced guard.
    let settings_path = project.join(".claude/settings.json");
    let raw = std::fs::read_to_string(&settings_path)
        .expect("default init must create .claude/settings.json with the guard");
    let settings: Value = serde_json::from_str(&raw).expect("settings parse");
    let command = guard_command_from_settings(&settings);
    assert!(command.contains("DENT8_HOOK_MODE=guard-native-memory-write"));
    assert!(command.contains("DENT8_HOOK_ENFORCE=1"));
    assert!(command.contains("dent8 hook native-memory-guard"));
    // Graceful-degrade clause is present in the wired command.
    assert!(command.starts_with("command -v dent8 >/dev/null 2>&1 || exit 0;"));

    // A raw CLAUDE.md / AGENTS.md write is now blocked out of the box (exit 2)…
    let claude = run_guard(CLAUDE_WRITE);
    assert_eq!(
        claude.status.code(),
        Some(2),
        "CLAUDE.md write must be blocked: {}",
        String::from_utf8_lossy(&claude.stderr)
    );
    let agents = run_guard(AGENTS_EDIT);
    assert_eq!(
        agents.status.code(),
        Some(2),
        "AGENTS.md edit must be blocked"
    );

    // …while an ordinary source write is allowed (exit 0).
    let code = run_guard(CODE_WRITE);
    assert!(code.status.success(), "ordinary write must be allowed");

    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn init_no_native_memory_guard_opts_out() {
    let project = unique_dir("optout");
    let output = run_init(&project, &["--no-native-memory-guard"]);
    assert!(
        output.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let settings_path = project.join(".claude/settings.json");
    assert!(
        !settings_path.exists(),
        "--no-native-memory-guard must not write a hook config"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("native-memory guard: skipped (--no-native-memory-guard)"),
        "opt-out should be reported: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn wired_guard_command_degrades_gracefully_without_the_binary() {
    let project = unique_dir("degrade");
    let output = run_init(&project, &[]);
    assert!(output.status.success());
    let raw = std::fs::read_to_string(project.join(".claude/settings.json")).expect("settings");
    let settings: Value = serde_json::from_str(&raw).expect("parse");
    let command = guard_command_from_settings(&settings);

    // Run the exact wired command through a shell with dent8 NOT resolvable (empty PATH). The
    // `command -v dent8 || exit 0` clause must make it allow the CLAUDE.md write (exit 0) instead
    // of failing closed — a fresh clone without the binary is never bricked.
    let mut absent = Command::new("/bin/sh");
    absent
        .arg("-c")
        .arg(&command)
        .env("PATH", "")
        .env_remove("DENT8_ALLOW_NATIVE_MEMORY_WRITE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = absent.spawn().expect("spawn shell");
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(CLAUDE_WRITE.as_bytes());
    }
    let degraded = child.wait_with_output().expect("wait");
    assert_eq!(
        degraded.status.code(),
        Some(0),
        "missing dent8 binary must allow the write (exit 0), got {:?}: {}",
        degraded.status.code(),
        String::from_utf8_lossy(&degraded.stderr)
    );

    // With the binary present on PATH, the very same wired command blocks the write (exit 2).
    let bin_dir = dent8_bin()
        .parent()
        .expect("binary parent dir")
        .to_path_buf();
    let mut present = Command::new("/bin/sh");
    present
        .arg("-c")
        .arg(&command)
        .env("PATH", &bin_dir)
        .env_remove("DENT8_ALLOW_NATIVE_MEMORY_WRITE")
        .env_remove("DENT8_STORE_URL")
        .env_remove("DENT8_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = present.spawn().expect("spawn shell");
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(CLAUDE_WRITE.as_bytes());
    }
    let enforced = child.wait_with_output().expect("wait");
    assert_eq!(
        enforced.status.code(),
        Some(2),
        "with dent8 on PATH the wired command must block: {}",
        String::from_utf8_lossy(&enforced.stderr)
    );

    let _ = std::fs::remove_dir_all(&project);
}
