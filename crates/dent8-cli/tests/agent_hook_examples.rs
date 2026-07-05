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
    assert!(String::from_utf8_lossy(&denied.stderr).contains("bypass the fact-event firewall"));

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
    run_hook(
        input,
        &[
            ("DENT8_HOOK_MODE", "guard-native-memory-write"),
            ("DENT8_HOOK_ENFORCE", enforce_value),
        ],
    )
}

/// Run `dent8 hook native-memory-guard` with exactly the given environment (plus a scrubbed
/// baseline), feeding `input` on stdin.
fn run_hook(input: &str, envs: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(dent8_bin());
    command
        .args(["hook", "native-memory-guard"])
        .env_remove("DENT8_HOOK_MODE")
        .env_remove("DENT8_HOOK_ENFORCE")
        .env_remove("DENT8_ALLOW_NATIVE_MEMORY_WRITE")
        .env_remove("DENT8_STORE_URL")
        .env_remove("DENT8_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in envs {
        command.env(name, value);
    }

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

#[test]
fn builtin_guard_blocks_apply_patch_writes_to_native_memory() {
    // apply_patch carries the path in a `*** Update File:` header, not a path field.
    let denied = run_builtin_guard(
        r#"{"tool_name":"apply_patch","tool_input":{"input":"*** Begin Patch\n*** Update File: AGENTS.md\n@@\n+poisoned\n*** End Patch\n"}}"#,
        true,
    );
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("bypass the fact-event firewall"));
}

#[test]
fn builtin_guard_blocks_shell_redirects_to_native_memory() {
    // A shell command that *writes* a native memory file via redirection / tee.
    for command in [
        "echo hi >> AGENTS.md",
        "echo hi > CLAUDE.md",
        "printf x | tee -a AGENTS.md",
    ] {
        let payload = format!(
            r#"{{"tool_name":"Bash","tool_input":{{"command":{}}}}}"#,
            serde_json::to_string(command).expect("encode command"),
        );
        let denied = run_builtin_guard(&payload, true);
        assert_eq!(denied.status.code(), Some(2), "should block: {command}");
    }
}

#[test]
fn builtin_guard_allows_shell_reads_and_unrelated_writes() {
    // Reads and writes to *other* files must not be flagged (no over-blocking).
    for command in [
        "cat AGENTS.md",
        "grep todo AGENTS.md",
        r#"echo "see AGENTS.md" >> notes.txt"#,
    ] {
        let payload = format!(
            r#"{{"tool_name":"Bash","tool_input":{{"command":{}}}}}"#,
            serde_json::to_string(command).expect("encode command"),
        );
        let allowed = run_builtin_guard(&payload, true);
        assert!(allowed.status.success(), "should allow: {command}");
    }
}

// ---- the exit-code contract (documented in examples/agent-hooks/README.md) ---------------

const MEMORY_WRITE: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/CLAUDE.md"}}"#;
const CODE_WRITE: &str = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/src/lib.rs"}}"#;

#[test]
fn hook_never_writes_stdout() {
    // Some providers interpret hook stdout (Claude Code parses it as a decision document);
    // the guard's entire contract is exit code + stderr. Every outcome must keep stdout empty.
    let temp_log =
        std::env::temp_dir().join(format!("dent8-hook-contract-{}.jsonl", std::process::id()));
    let log = temp_log.to_string_lossy().into_owned();
    let scenarios: Vec<std::process::Output> = vec![
        run_builtin_guard(MEMORY_WRITE, true),  // block
        run_builtin_guard(MEMORY_WRITE, false), // advisory warn
        run_builtin_guard(CODE_WRITE, true),    // pass-through
        run_builtin_guard("not json", true),    // fail closed
        run_hook(MEMORY_WRITE, &[("DENT8_HOOK_MODE", "no-such-mode")]), // unknown mode
        run_hook(
            "",
            &[("DENT8_HOOK_MODE", "session-start"), ("DENT8_LOG", &log)],
        ), // verify
    ];
    for output in scenarios {
        assert!(
            output.stdout.is_empty(),
            "hook stdout must stay empty, got: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let _ = std::fs::remove_file(&temp_log);
}

#[test]
fn hook_rejects_unknown_mode() {
    let output = run_hook(MEMORY_WRITE, &[("DENT8_HOOK_MODE", "no-such-mode")]);
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unknown DENT8_HOOK_MODE"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn hook_bypass_flag_opens_the_guard_but_a_typo_does_not() {
    // The explicit bypass wins over enforcement (still warning on stderr)…
    let bypassed = run_hook(
        MEMORY_WRITE,
        &[
            ("DENT8_HOOK_MODE", "guard-native-memory-write"),
            ("DENT8_HOOK_ENFORCE", "1"),
            ("DENT8_ALLOW_NATIVE_MEMORY_WRITE", "1"),
        ],
    );
    assert!(bypassed.status.success());
    assert!(String::from_utf8_lossy(&bypassed.stderr).contains("bypass the fact-event firewall"));
    // …but a malformed bypass value never grants a bypass.
    let denied = run_hook(
        MEMORY_WRITE,
        &[
            ("DENT8_HOOK_MODE", "guard-native-memory-write"),
            ("DENT8_HOOK_ENFORCE", "1"),
            ("DENT8_ALLOW_NATIVE_MEMORY_WRITE", "maybe"),
        ],
    );
    assert_eq!(denied.status.code(), Some(2));
}

#[test]
fn hook_audit_and_session_modes_reverify_the_log() {
    let dir = std::env::temp_dir().join(format!("dent8-hook-verify-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let healthy = dir.join("healthy.jsonl").to_string_lossy().into_owned();
    let corrupt_path = dir.join("corrupt.jsonl");
    std::fs::write(&corrupt_path, "this is not a fact event\n").expect("write corrupt log");
    let corrupt = corrupt_path.to_string_lossy().into_owned();

    // session-start always verifies: a healthy (missing = empty) log passes, a corrupt one
    // exits 1.
    let ok = run_hook(
        "",
        &[
            ("DENT8_HOOK_MODE", "session-start"),
            ("DENT8_LOG", &healthy),
        ],
    );
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    let broken = run_hook(
        "",
        &[
            ("DENT8_HOOK_MODE", "session-start"),
            ("DENT8_LOG", &corrupt),
        ],
    );
    assert_eq!(broken.status.code(), Some(1));

    // post-write-audit verifies only when a native memory/rules file was touched.
    let untouched = run_hook(
        CODE_WRITE,
        &[
            ("DENT8_HOOK_MODE", "post-write-audit"),
            ("DENT8_LOG", &corrupt),
        ],
    );
    assert!(
        untouched.status.success(),
        "an unrelated write must not trigger a verify"
    );
    let touched = run_hook(
        MEMORY_WRITE,
        &[
            ("DENT8_HOOK_MODE", "post-write-audit"),
            ("DENT8_LOG", &corrupt),
        ],
    );
    assert_eq!(touched.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&touched.stderr).contains("verify"),
        "{}",
        String::from_utf8_lossy(&touched.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

fn dent8_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dent8"))
}
