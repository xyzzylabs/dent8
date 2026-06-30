use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicU32, Ordering},
};

#[test]
fn alice_fact_round_trips_with_subject_and_metadata_flags() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    let asserted = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_drink",
            "tea",
            "--authority",
            "high",
            "--source",
            "user:alice",
        ],
        &envs,
    );
    assert_success(&asserted, "assert");
    assert!(
        stdout(&asserted).contains("person:alice favorite_drink = \"tea\""),
        "{}",
        stdout(&asserted)
    );

    let explained = run_dent8(&["explain", "person:alice", "favorite_drink"], &envs);
    assert_success(&explained, "explain");
    assert!(stdout(&explained).contains("value         : \"tea\""));

    let replayed = run_dent8(&["replay", "person:alice", "favorite_drink"], &envs);
    assert_success(&replayed, "replay");
    assert!(stdout(&replayed).contains("user:alice"));
}

#[test]
fn low_authority_supersede_is_rejected_and_original_fact_remains() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_drink",
                "tea",
                "--authority=high",
                "--source=user:alice",
            ],
            &envs,
        ),
        "assert",
    );

    let rejected = run_dent8(
        &[
            "supersede",
            "person:alice",
            "favorite_drink",
            "coffee",
            "--authority",
            "low",
            "--source",
            "note:old",
        ],
        &envs,
    );
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        stderr(&rejected).contains("REJECTED"),
        "{}",
        stderr(&rejected)
    );

    let explained = run_dent8(&["explain", "person:alice", "favorite_drink"], &envs);
    assert_success(&explained, "explain");
    assert!(stdout(&explained).contains("value         : \"tea\""));
}

#[test]
fn missing_write_metadata_gets_targeted_usage() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    let output = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_drink",
            "tea",
            "--source",
            "user:alice",
        ],
        &envs,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("required arguments"));
    assert!(stderr(&output).contains("--authority <AUTHORITY>"));
    assert!(stderr(&output).contains("Usage: dent8 assert"));
}

#[test]
fn malformed_subject_is_rejected_before_store_access() {
    let output = run_dent8(&["explain", "alice", "favorite_drink"], &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("invalid subject 'alice'"));
    assert!(stderr(&output).contains("<kind>:<key>"));
}

#[test]
fn legacy_positional_write_form_is_no_longer_accepted() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    let output = run_dent8(
        &[
            "assert",
            "person",
            "alice",
            "favorite_drink",
            "tea",
            "high",
            "user:alice",
        ],
        &envs,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("invalid value 'person' for '<SUBJECT>'"));
    assert!(stderr(&output).contains("person:alice"));
}

#[test]
fn completions_command_emits_shell_script() {
    let output = run_dent8(&["completions", "fish"], &[]);
    assert_success(&output, "completions");
    assert!(stdout(&output).contains("function __fish_dent8_needs_command"));
    assert!(stdout(&output).contains("complete -c dent8"));
    assert!(stdout(&output).contains("assert"));
}

#[test]
fn color_always_paints_status_words_even_when_captured() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    let output = run_dent8(
        &[
            "--color",
            "always",
            "assert",
            "person:alice",
            "favorite_drink",
            "tea",
            "--authority",
            "high",
            "--source",
            "user:alice",
        ],
        &envs,
    );
    assert_success(&output, "assert with forced color");
    assert!(stdout(&output).contains("\x1b[32;1mACCEPTED\x1b[0m"));
}

#[test]
fn init_bootstraps_authority_env_and_doctor_write_check() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();

    let init = run_dent8(&["init", "--dir", &dir], &[]);
    assert_success(&init, "init");
    assert!(stdout(&init).contains("initialized dent8"));
    assert!(stdout(&init).contains("dent8 doctor --write-check"));

    let env_path = temp.file(".dent8/env");
    let authority_path = temp.file(".dent8/authority.json");
    let log_path = temp.file(".dent8/memory.jsonl");
    let env_file = fs::read_to_string(&env_path).expect("env file");
    assert!(env_file.contains("DENT8_REQUIRE_AUTHORITY=1"));
    assert!(env_file.contains("DENT8_LOG="));
    assert!(env_file.contains("DENT8_AUTHORITY="));

    let authority = fs::read_to_string(&authority_path).expect("authority registry");
    assert!(authority.contains("source:local"));
    assert!(authority.contains("High"));
    assert!(log_path.exists(), "init should create the file dev log");

    let log = log_path.to_string_lossy().into_owned();
    let authority = authority_path.to_string_lossy().into_owned();
    let doctor = run_dent8(
        &["doctor", "--write-check"],
        &[
            ("DENT8_LOG", &log),
            ("DENT8_AUTHORITY", &authority),
            ("DENT8_REQUIRE_AUTHORITY", "1"),
        ],
    );
    assert_success(&doctor, "doctor --write-check");
    let stdout = stdout(&doctor);
    assert!(stdout.contains("write-check: accepted trusted person:alice-doctor-"));
    assert!(stdout.contains("rejected low-authority coffee"));
    assert!(stdout.contains("verify OK"));
}

#[test]
fn init_refuses_to_rewrite_env_without_force() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();

    assert_success(&run_dent8(&["init", "--dir", &dir], &[]), "first init");
    let second = run_dent8(&["init", "--dir", &dir], &[]);
    assert_eq!(second.status.code(), Some(1));
    assert!(stderr(&second).contains("--force"), "{}", stderr(&second));

    assert_success(
        &run_dent8(&["init", "--dir", &dir, "--force"], &[]),
        "forced init",
    );
}

#[cfg(not(feature = "identity"))]
#[test]
fn identity_command_explains_feature_gate_without_identity_build() {
    let output = run_dent8(&["identity", "trust-list"], &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--features identity"));
}

#[cfg(feature = "identity")]
#[test]
#[allow(clippy::too_many_lines)]
fn signed_identity_grant_is_required_and_bound_to_the_write() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let trust = temp.file("trust.json").to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    let codex_key = temp.file("codex.key").to_string_lossy().into_owned();
    let cursor_key = temp.file("cursor.key").to_string_lossy().into_owned();
    let grant = temp.file("codex.grant.json").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(&["identity", "issuer-keygen", "--out", &issuer_key], &[]),
        "issuer keygen",
    );
    assert_success(
        &run_dent8(
            &[
                "identity",
                "agent-keygen",
                "source:codex",
                "--out",
                &codex_key,
            ],
            &[],
        ),
        "codex keygen",
    );
    assert_success(
        &run_dent8(
            &[
                "identity",
                "agent-keygen",
                "source:cursor",
                "--out",
                &cursor_key,
            ],
            &[],
        ),
        "cursor keygen",
    );
    assert_success(
        &run_dent8(
            &[
                "identity",
                "trust-add",
                "owner",
                &format!("{issuer_key}.pub"),
            ],
            &[("DENT8_TRUST", &trust)],
        ),
        "trust add",
    );
    assert_success(
        &run_dent8(
            &[
                "identity",
                "grant-issue",
                "source:codex",
                "--public-key",
                &format!("{codex_key}.pub"),
                "--max",
                "high",
                "--issuer",
                "owner",
                "--issuer-key",
                &issuer_key,
                "--scope",
                "person:alice",
                "--out",
                &grant,
            ],
            &[],
        ),
        "grant issue",
    );
    assert_success(
        &run_dent8(
            &["identity", "grant-verify", &grant],
            &[("DENT8_TRUST", &trust)],
        ),
        "grant verify",
    );

    let missing_trust = temp
        .file("missing-trust.json")
        .to_string_lossy()
        .into_owned();
    let missing_trust_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", missing_trust.as_str()),
        ("DENT8_GRANT", grant.as_str()),
        ("DENT8_IDENTITY_KEY", codex_key.as_str()),
    ];
    let missing_registry = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_shape",
            "circle",
            "--authority",
            "high",
            "--source",
            "source:codex",
        ],
        &missing_trust_env,
    );
    assert_eq!(missing_registry.status.code(), Some(2));
    assert!(stderr(&missing_registry).contains("identity trust registry is required"));

    let identity_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", grant.as_str()),
        ("DENT8_IDENTITY_KEY", codex_key.as_str()),
        ("DENT8_REQUIRE_IDENTITY", "1"),
    ];
    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_drink",
                "tea",
                "--authority",
                "high",
                "--source",
                "source:codex",
            ],
            &identity_env,
        ),
        "signed identity write",
    );

    let wrong_source = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_color",
            "green",
            "--authority",
            "high",
            "--source",
            "source:claude",
        ],
        &identity_env,
    );
    assert_eq!(wrong_source.status.code(), Some(2));
    assert!(stderr(&wrong_source).contains("does not match write source"));

    let wrong_key_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", grant.as_str()),
        ("DENT8_IDENTITY_KEY", cursor_key.as_str()),
        ("DENT8_REQUIRE_IDENTITY", "1"),
    ];
    let wrong_key = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_snack",
            "apple",
            "--authority",
            "high",
            "--source",
            "source:codex",
        ],
        &wrong_key_env,
    );
    assert_eq!(wrong_key.status.code(), Some(2));
    assert!(stderr(&wrong_key).contains("identity key does not match"));

    let too_high = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_city",
            "paris",
            "--authority",
            "canonical",
            "--source",
            "source:codex",
        ],
        &identity_env,
    );
    assert_eq!(too_high.status.code(), Some(2));
    assert!(stderr(&too_high).contains("may assert at most High"));

    let out_of_scope = run_dent8(
        &[
            "assert",
            "person:bob",
            "favorite_drink",
            "coffee",
            "--authority",
            "high",
            "--source",
            "source:codex",
        ],
        &identity_env,
    );
    assert_eq!(out_of_scope.status.code(), Some(2));
    assert!(stderr(&out_of_scope).contains("does not cover write subject"));
}

fn run_dent8(args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(dent8_bin());
    command.args(args).env_remove("DENT8_STORE_URL");
    command
        .env_remove("DENT8_TRUST")
        .env_remove("DENT8_GRANT")
        .env_remove("DENT8_IDENTITY_KEY")
        .env_remove("DENT8_REQUIRE_IDENTITY");
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("run dent8")
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed\nstdout:\n{}\nstderr:\n{}",
        stdout(output),
        stderr(output)
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn dent8_bin() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_dent8").map_or_else(
        || {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug/dent8")
                .canonicalize()
                .expect("dent8 binary")
        },
        PathBuf::from,
    )
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("dent8-cli-usage-{}-{n}", std::process::id()));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
