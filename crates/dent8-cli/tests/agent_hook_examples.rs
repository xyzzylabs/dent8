use std::{
    path::PathBuf,
    process::{Command, Stdio},
};

use serde_json::Value;

#[test]
fn hook_samples_parse_and_reference_the_shared_guard() {
    let samples = [
        include_str!("../../../examples/agent-hooks/codex/hooks.sample.json"),
        include_str!("../../../examples/agent-hooks/claude-code/settings.sample.json"),
        include_str!("../../../examples/agent-hooks/gemini/settings.sample.json"),
        include_str!("../../../examples/agent-hooks/cascade/hooks.sample.json"),
    ];

    for raw in samples {
        let parsed = serde_json::from_str::<Value>(raw).expect("hook sample parses as JSON");
        let text = parsed.to_string();
        assert!(text.contains("hook native-memory-guard"));
        assert!(text.contains("DENT8_HOOK_MODE"));
        assert!(text.contains("guard-native-memory-write"));
    }
}

#[test]
fn builtin_native_memory_guard_blocks_agent_memory_files_when_enforced() {
    let denied = run_builtin_guard(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/CLAUDE.md"}}"#,
        true,
    );
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("bypass the claim-event firewall"));

    let allowed = run_builtin_guard(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/src/lib.rs"}}"#,
        true,
    );
    assert!(allowed.status.success());
}

fn run_builtin_guard(input: &str, enforce: bool) -> std::process::Output {
    run_builtin_guard_env(input, if enforce { "1" } else { "0" })
}

fn run_builtin_guard_env(input: &str, enforce_value: &str) -> std::process::Output {
    let mut command = Command::new(dent8_bin());
    command
        .args(["hook", "native-memory-guard"])
        .env("DENT8_HOOK_MODE", "guard-native-memory-write")
        .env("DENT8_HOOK_ENFORCE", enforce_value)
        .env_remove("DENT8_ALLOW_NATIVE_MEMORY_WRITE")
        .env_remove("DENT8_STORE_URL")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn built-in native memory guard");
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .expect("guard stdin")
            .write_all(input.as_bytes())
            .expect("write guard input");
    }
    child.wait_with_output().expect("wait for guard")
}

#[test]
fn builtin_guard_accepts_word_form_enforce_flag() {
    // `true` / `on` / `YES` must enforce exactly like `1` — DENT8_HOOK_ENFORCE is parsed like
    // every other dent8 boolean, so a word-form value cannot silently fail to enforce.
    let memory_write = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/CLAUDE.md"}}"#;
    for value in ["true", "on", "YES"] {
        let denied = run_builtin_guard_env(memory_write, value);
        assert_eq!(
            denied.status.code(),
            Some(2),
            "DENT8_HOOK_ENFORCE={value} should block the write"
        );
    }
}

#[test]
fn builtin_guard_fails_closed_on_malformed_payload() {
    // An unparseable hook payload under enforcement blocks: the guard cannot prove the write is
    // safe, so it fails closed rather than waving it through.
    let denied = run_builtin_guard("this is not json", true);
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("fail closed"));

    // Without enforcement it stays advisory (exit 0).
    let allowed = run_builtin_guard("this is not json", false);
    assert!(allowed.status.success());
}

#[test]
fn builtin_guard_fails_closed_on_malformed_enforce_flag() {
    // A typo'd DENT8_HOOK_ENFORCE must not silently disable enforcement — it fails closed.
    let denied = run_builtin_guard_env(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/CLAUDE.md"}}"#,
        "maybe",
    );
    assert_eq!(denied.status.code(), Some(2));
}

fn dent8_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dent8"))
}
