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

#[test]
fn python_native_memory_guard_blocks_agent_memory_files_when_enforced() {
    let denied = run_python_guard(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/CLAUDE.md"}}"#,
        true,
    );
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("bypass the claim-event firewall"));

    let allowed = run_python_guard(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/src/lib.rs"}}"#,
        true,
    );
    assert!(allowed.status.success());
}

#[test]
fn typescript_native_memory_guard_blocks_agent_memory_files_when_enforced() {
    if !node_supports_type_stripping() {
        eprintln!("node with TypeScript type stripping not found; skipping TypeScript hook check");
        return;
    }

    let denied = run_typescript_guard(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/CLAUDE.md"}}"#,
        true,
    );
    assert_eq!(denied.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&denied.stderr).contains("bypass the claim-event firewall"));

    let allowed = run_typescript_guard(
        r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/src/lib.rs"}}"#,
        true,
    );
    assert!(allowed.status.success());
}

fn run_builtin_guard(input: &str, enforce: bool) -> std::process::Output {
    let mut command = Command::new(dent8_bin());
    command
        .args(["hook", "native-memory-guard"])
        .env("DENT8_HOOK_MODE", "guard-native-memory-write")
        .env("DENT8_HOOK_ENFORCE", if enforce { "1" } else { "0" })
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

fn run_python_guard(input: &str, enforce: bool) -> std::process::Output {
    let mut command = Command::new("python3");
    command
        .arg(python_hook_script())
        .env("DENT8_HOOK_MODE", "guard-native-memory-write")
        .env("DENT8_HOOK_ENFORCE", if enforce { "1" } else { "0" })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn native memory guard");
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

fn run_typescript_guard(input: &str, enforce: bool) -> std::process::Output {
    let mut command = Command::new("node");
    command
        .arg(typescript_hook_script())
        .env("DENT8_HOOK_MODE", "guard-native-memory-write")
        .env("DENT8_HOOK_ENFORCE", if enforce { "1" } else { "0" })
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .expect("spawn TypeScript native memory guard");
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

fn python_hook_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("examples/agent-hooks/bin/dent8-native-memory-guard.py")
}

fn typescript_hook_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("examples/agent-hooks/bin/dent8-native-memory-guard.ts")
}

fn node_supports_type_stripping() -> bool {
    let output = match Command::new("node").arg("--version").output() {
        Ok(output) if output.status.success() => output,
        _ => return false,
    };

    let version = String::from_utf8_lossy(&output.stdout);
    let version = version.trim().trim_start_matches('v');
    let mut parts = version.split('.');
    let major = parts.next().and_then(|part| part.parse::<u64>().ok());
    let minor = parts.next().and_then(|part| part.parse::<u64>().ok());

    matches!((major, minor), (Some(major), _) if major >= 23)
        || matches!((major, minor), (Some(22), Some(minor)) if minor >= 18)
}

fn dent8_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dent8"))
}
