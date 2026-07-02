use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU32, Ordering},
};

use serde_json::Value;

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
fn facts_list_hides_diagnostics_by_default_and_supports_filters() {
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
                "--authority",
                "high",
                "--source",
                "user:alice",
            ],
            &envs,
        ),
        "assert alice fact",
    );
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:dent8",
                "database",
                "sqlite",
                "--authority",
                "high",
                "--source",
                "source:codex",
            ],
            &envs,
        ),
        "assert repo fact",
    );
    assert_success(
        &run_dent8(
            &[
                "assert",
                "diagnostic:doctor-test",
                "dent8.write_check",
                "ok",
                "--authority",
                "high",
                "--source",
                "source:dent8",
            ],
            &envs,
        ),
        "assert diagnostic fact",
    );

    let listed = run_dent8(&["facts", "list"], &envs);
    assert_success(&listed, "facts list");
    let listed_stdout = stdout(&listed);
    assert!(
        listed_stdout.contains("2 dent8 fact stream(s)"),
        "{listed_stdout}"
    );
    assert!(listed_stdout.contains("dent8://person/alice/favorite_drink"));
    assert!(listed_stdout.contains("dent8://repo/dent8/database"));
    assert!(
        listed_stdout.contains("1 diagnostic stream(s) hidden"),
        "{listed_stdout}"
    );
    assert!(!listed_stdout.contains("diagnostic/doctor-test"));

    let filtered = run_dent8(&["facts", "list", "--kind", "repo"], &envs);
    assert_success(&filtered, "facts list --kind repo");
    let filtered_stdout = stdout(&filtered);
    assert!(filtered_stdout.contains("dent8://repo/dent8/database"));
    assert!(!filtered_stdout.contains("dent8://person/alice/favorite_drink"));

    let diagnostics = run_dent8(
        &[
            "facts",
            "list",
            "--kind",
            "diagnostic",
            "--include-diagnostics",
        ],
        &envs,
    );
    assert_success(&diagnostics, "facts list diagnostics");
    let diagnostics_stdout = stdout(&diagnostics);
    assert!(diagnostics_stdout.contains("1 dent8 fact stream(s)"));
    assert!(diagnostics_stdout.contains("dent8://diagnostic/doctor-test/dent8.write_check"));
    assert!(!diagnostics_stdout.contains("hidden"));
}

#[test]
fn read_audit_commands_emit_machine_readable_json() {
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
                "--authority",
                "high",
                "--source",
                "user:alice",
            ],
            &envs,
        ),
        "assert alice fact",
    );

    let facts = run_dent8(&["--output", "json", "facts", "list"], &envs);
    assert_success(&facts, "facts list --output json");
    let facts = stdout_json(&facts);
    assert_eq!(facts["status"], "ok");
    assert_eq!(facts["tool"], "facts list");
    assert_eq!(facts["count"], 1);
    assert_eq!(
        facts["facts"][0]["uri"],
        "dent8://person/alice/favorite_drink"
    );
    assert_eq!(facts["facts"][0]["subject"]["kind"], "person");
    assert_eq!(facts["hidden_diagnostics_count"], 0);

    let explain = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "person:alice",
            "favorite_drink",
        ],
        &envs,
    );
    assert_success(&explain, "explain --output json");
    let explain = stdout_json(&explain);
    assert_eq!(explain["status"], "ok");
    assert_eq!(explain["tool"], "explain");
    assert_eq!(explain["subject"]["key"], "alice");
    assert_eq!(explain["predicate"], "favorite_drink");
    assert_eq!(explain["value"]["kind"], "text");
    assert_eq!(explain["value"]["text"], "tea");
    assert_eq!(explain["authority"], "High");
    assert!(
        explain["event_hash"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );

    let verify = run_dent8(&["--output", "json", "verify"], &envs);
    assert_success(&verify, "verify --output json");
    let verify = stdout_json(&verify);
    assert_eq!(verify["status"], "ok");
    assert_eq!(verify["tool"], "verify");
    assert_eq!(verify["ok"], true);
    assert_eq!(verify["findings"].as_array().expect("findings").len(), 0);

    let doctor = run_dent8(&["--output", "json", "doctor"], &envs);
    assert_success(&doctor, "doctor --output json");
    let doctor = stdout_json(&doctor);
    assert_eq!(doctor["status"], "ok");
    assert_eq!(doctor["tool"], "doctor");
    assert_eq!(doctor["ok"], true);
    assert!(
        doctor["checks"]
            .as_array()
            .expect("checks")
            .iter()
            .any(|check| check["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("verify: OK"))),
        "{doctor}"
    );
}

#[test]
fn replay_and_conflicts_emit_machine_readable_json() {
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
                "--authority",
                "high",
                "--source",
                "user:alice",
            ],
            &envs,
        ),
        "assert alice fact",
    );

    let replay = run_dent8(
        &[
            "--output",
            "json",
            "replay",
            "person:alice",
            "favorite_drink",
        ],
        &envs,
    );
    assert_success(&replay, "replay --output json");
    let replay = stdout_json(&replay);
    assert_eq!(replay["status"], "ok");
    assert_eq!(replay["tool"], "replay");
    assert_eq!(replay["event_count"], 1);
    assert_eq!(replay["events"][0]["kind"], "claim.asserted");
    assert_eq!(replay["events"][0]["source"], "user:alice");
    assert_eq!(replay["events"][0]["value"]["text"], "tea");
    assert_eq!(replay["current"]["value"]["text"], "tea");

    assert_success(
        &run_dent8(
            &[
                "contradict",
                "person:alice",
                "favorite_drink",
                "coffee",
                "--authority",
                "low",
                "--source",
                "note:counter",
            ],
            &envs,
        ),
        "contradict alice fact",
    );
    let conflicts = run_dent8(&["--output", "json", "conflicts"], &envs);
    assert_success(&conflicts, "conflicts --output json");
    let conflicts = stdout_json(&conflicts);
    assert_eq!(conflicts["status"], "ok");
    assert_eq!(conflicts["tool"], "conflicts");
    assert_eq!(conflicts["count"], 1);
    assert_eq!(conflicts["conflicts"][0]["subject"]["key"], "alice");
    assert_eq!(conflicts["conflicts"][0]["predicate"], "favorite_drink");
    let rivals = conflicts["conflicts"][0]["rivals"]
        .as_array()
        .expect("conflict rivals");
    assert_eq!(rivals.len(), 2);
    assert!(
        rivals
            .iter()
            .any(|rival| rival["lifecycle"] == "Contested" && rival["value"]["text"] == "tea"),
        "{conflicts}"
    );
}

#[test]
fn eval_emits_machine_readable_json() {
    let eval = run_dent8(&["--output", "json", "eval"], &[]);
    assert_success(&eval, "eval --output json");
    let eval = stdout_json(&eval);
    assert_eq!(eval["status"], "ok");
    assert_eq!(eval["tool"], "eval");
    assert_eq!(eval["scenario_count"], 5);
    assert_eq!(eval["demonstrated_count"], 5);
    assert!(
        eval["scenarios"]
            .as_array()
            .expect("eval scenarios")
            .iter()
            .all(|scenario| scenario["demonstrates_defense"] == true),
        "{eval}"
    );
}

#[test]
fn firewall_demo_runs_against_test_binary() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/firewall/demo.sh");
    let output = Command::new("bash")
        .arg(script)
        .env("DENT8", dent8_bin())
        .env("DENT8_STORE_URL", "postgres://poisoned-parent-env")
        .env("DENT8_LOG", "/poisoned/parent-memory.jsonl")
        .env("DENT8_AUTHORITY", "/poisoned/authority.json")
        .env("DENT8_REQUIRE_AUTHORITY", "1")
        .env("DENT8_TRUST", "/poisoned/trust.json")
        .env("DENT8_ACTIVE_GRANTS", "/poisoned/active-grants.json")
        .env("DENT8_REQUIRE_IDENTITY", "1")
        .env("DENT8_GRANT", "/poisoned/source.grant.json")
        .env("DENT8_IDENTITY_KEY", "/poisoned/source.key")
        .output()
        .expect("run firewall demo");
    assert_success(&output, "examples/firewall/demo.sh");
    let stdout = stdout(&output);
    let stderr = stderr(&output);
    assert!(
        stdout.contains("# 4. Try a low-authority override; dent8 rejects it")
            && stdout.contains("person:alice favorite_drink")
            && stdout.contains("value         : \"tea\"")
            && stdout.contains("chain verified: true"),
        "{stdout}"
    );
    assert!(stderr.contains("REJECTED"), "{stderr}");
}

#[test]
fn write_commands_emit_machine_readable_json() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    let asserted = run_dent8(
        &[
            "--output",
            "json",
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
    assert_success(&asserted, "assert --output json");
    let asserted = stdout_json(&asserted);
    assert_eq!(asserted["status"], "ok");
    assert_eq!(asserted["tool"], "assert");
    assert_eq!(asserted["accepted"], true);
    assert_eq!(asserted["subject"]["key"], "alice");
    assert_eq!(asserted["predicate"], "favorite_drink");
    assert_eq!(asserted["value"]["text"], "tea");
    assert_eq!(asserted["authority"], "High");
    assert_eq!(asserted["source"], "user:alice");

    let rejected = run_dent8(
        &[
            "--output",
            "json",
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
    assert!(stdout(&rejected).is_empty());
    let rejected = serde_json::from_slice::<Value>(&rejected.stderr).unwrap_or_else(|error| {
        panic!(
            "stderr is not JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            stdout(&rejected),
            stderr(&rejected)
        )
    });
    assert_eq!(rejected["status"], "rejected");
    assert_eq!(rejected["tool"], "supersede");
    assert_eq!(rejected["accepted"], false);
    assert_eq!(rejected["value"]["text"], "coffee");
    assert!(
        rejected["message"]
            .as_str()
            .is_some_and(|message| message.contains("REJECTED")),
        "{rejected}"
    );
}

#[test]
fn derived_write_json_includes_source_fact() {
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
                "--authority",
                "high",
                "--source",
                "user:alice",
            ],
            &envs,
        ),
        "assert source fact",
    );
    let derived = run_dent8(
        &[
            "--output",
            "json",
            "derive",
            "person:alice",
            "shopping_item",
            "tea",
            "--from",
            "person:alice",
            "favorite_drink",
            "--authority",
            "medium",
            "--source",
            "assistant:local",
        ],
        &envs,
    );
    assert_success(&derived, "derive --output json");
    let derived = stdout_json(&derived);
    assert_eq!(derived["status"], "ok");
    assert_eq!(derived["tool"], "derive");
    assert_eq!(derived["derived_from"]["subject"]["kind"], "person");
    assert_eq!(derived["derived_from"]["subject"]["key"], "alice");
    assert_eq!(derived["derived_from"]["predicate"], "favorite_drink");
}

#[test]
fn authority_commands_emit_machine_readable_json() {
    let temp = TempDir::new();
    let authority = temp.file("authority.json").to_string_lossy().into_owned();
    let envs = [
        ("DENT8_AUTHORITY", authority.as_str()),
        ("DENT8_REQUIRE_AUTHORITY", "1"),
    ];

    let before = run_dent8(&["--output", "json", "authority", "list"], &envs);
    assert_success(&before, "authority list --output json before registry");
    let before = stdout_json(&before);
    assert_eq!(before["status"], "ok");
    assert_eq!(before["tool"], "authority list");
    assert_eq!(before["registry_present"], false);
    assert_eq!(before["require_authority"], true);
    assert_eq!(before["enforcement"], "blocked_missing_registry");
    assert_eq!(before["count"], 0);

    let add = run_dent8(
        &[
            "--output",
            "json",
            "authority",
            "add",
            "source:codex",
            "high",
            "owner",
            "project:dent8",
        ],
        &envs,
    );
    assert_success(&add, "authority add --output json");
    let add = stdout_json(&add);
    assert_eq!(add["status"], "ok");
    assert_eq!(add["tool"], "authority add");
    assert_eq!(add["source"], "source:codex");
    assert_eq!(add["max_authority"], "High");
    assert_eq!(add["issuer"], "owner");
    assert_eq!(add["scope"], "project:dent8");
    assert_eq!(add["issuer_enforced"], false);
    assert_eq!(add["scope_enforced"], false);

    let listed = run_dent8(&["--output", "json", "authority", "list"], &envs);
    assert_success(&listed, "authority list --output json after add");
    let listed = stdout_json(&listed);
    assert_eq!(listed["registry_present"], true);
    assert_eq!(listed["enforcement"], "deny_by_default");
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["sources"][0]["source"], "source:codex");
    assert_eq!(listed["sources"][0]["max_authority"], "High");
    assert_eq!(listed["sources"][0]["issuer"], "owner");
    assert_eq!(listed["sources"][0]["scope"], "project:dent8");

    let removed = run_dent8(
        &["--output", "json", "authority", "remove", "source:codex"],
        &envs,
    );
    assert_success(&removed, "authority remove --output json");
    let removed = stdout_json(&removed);
    assert_eq!(removed["status"], "ok");
    assert_eq!(removed["tool"], "authority remove");
    assert_eq!(removed["source"], "source:codex");

    let empty = run_dent8(&["--output", "json", "authority", "list"], &envs);
    assert_success(&empty, "authority list --output json after remove");
    let empty = stdout_json(&empty);
    assert_eq!(empty["registry_present"], true);
    assert_eq!(empty["enforcement"], "deny_by_default_empty");
    assert_eq!(empty["count"], 0);
}

#[test]
fn verify_json_reports_findings_on_stdout_with_nonzero_exit() {
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
                "--authority",
                "high",
                "--source",
                "user:alice",
            ],
            &envs,
        ),
        "assert source fact",
    );
    assert_success(
        &run_dent8(
            &[
                "derive",
                "person:alice",
                "shopping_item",
                "tea",
                "--from",
                "person:alice",
                "favorite_drink",
                "--authority",
                "medium",
                "--source",
                "assistant:local",
            ],
            &envs,
        ),
        "derive dependent fact",
    );
    assert_success(
        &run_dent8(
            &[
                "retract",
                "person:alice",
                "favorite_drink",
                "--authority",
                "high",
                "--source",
                "user:alice",
            ],
            &envs,
        ),
        "retract source fact",
    );

    let verify = run_dent8(&["--output", "json", "verify"], &envs);
    assert_eq!(verify.status.code(), Some(1));
    assert!(stderr(&verify).is_empty(), "{}", stderr(&verify));
    let verify = stdout_json(&verify);
    assert_eq!(verify["status"], "failed");
    assert_eq!(verify["ok"], false);
    assert!(
        verify["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .any(|finding| finding
                .as_str()
                .is_some_and(|text| text.contains("TAINTED"))),
        "{verify}"
    );
}

#[test]
fn json_output_fails_closed_for_unsupported_commands() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    let output = run_dent8(&["--output", "json", "hook", "native-memory-guard"], &envs);
    assert_eq!(output.status.code(), Some(2));
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("does not support `--output json` yet"));
}

#[test]
fn artifact_commands_emit_machine_readable_json() {
    let schema = run_dent8(&["--output", "json", "schema", "postgres"], &[]);
    assert_success(&schema, "schema postgres --output json");
    assert!(stderr(&schema).is_empty(), "{}", stderr(&schema));
    let schema = stdout_json(&schema);
    assert_eq!(schema["status"], "ok");
    assert_eq!(schema["tool"], "schema postgres");
    assert_eq!(schema["schema"], "postgres");
    assert!(
        schema["sql"]
            .as_str()
            .expect("postgres sql")
            .contains("dent8_event_log")
    );

    let completions = run_dent8(&["--output", "json", "completions", "bash"], &[]);
    assert_success(&completions, "completions bash --output json");
    assert!(stderr(&completions).is_empty(), "{}", stderr(&completions));
    let completions = stdout_json(&completions);
    assert_eq!(completions["status"], "ok");
    assert_eq!(completions["tool"], "completions");
    assert_eq!(completions["shell"], "bash");
    assert!(
        completions["script"]
            .as_str()
            .expect("completion script")
            .contains("dent8")
    );
}

#[cfg(not(feature = "export"))]
#[test]
fn export_json_reports_missing_feature() {
    let temp = TempDir::new();
    let out = temp.file("memory.parquet").to_string_lossy().into_owned();
    let exported = run_dent8(&["--output", "json", "export", &out], &[]);
    assert_eq!(exported.status.code(), Some(2));
    assert!(
        stdout(&exported).is_empty(),
        "export feature error should not write stdout:\n{}",
        stdout(&exported)
    );
    let exported = stderr_json(&exported);
    assert_eq!(exported["status"], "failed");
    assert_eq!(exported["tool"], "export");
    assert_eq!(exported["out"], out);
    assert!(
        exported["message"]
            .as_str()
            .expect("export message")
            .contains("--features export")
    );
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
fn positional_write_form_is_no_longer_accepted() {
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
    assert!(stdout(&init).contains("dent8 doctor --source source:local --write-check"));

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
    assert!(stdout.contains("write-check: accepted trusted diagnostic:doctor-"));
    assert!(stdout.contains("dent8.write_check=ok"));
    assert!(stdout.contains("rejected low-authority tampered value"));
    assert!(stdout.contains("verify OK"));
    let log_contents = fs::read_to_string(&log_path).expect("doctor write-check log");
    assert!(log_contents.contains("\"kind\":\"diagnostic\""));
    assert!(log_contents.contains("dent8.write_check"));
    assert!(!log_contents.contains("alice-doctor"));
}

#[test]
fn init_witness_adds_verification_config_without_signing_key() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();

    let init = run_dent8(&["init", "--dir", &dir, "--witness"], &[]);
    assert_success(&init, "init --witness");
    let stdout = stdout(&init);
    assert!(stdout.contains("witness:"));
    assert!(stdout.contains("verification config only"));

    let env = fs::read_to_string(temp.file(".dent8/env")).expect("env file");
    assert!(env.contains("DENT8_WITNESS_LOG="));
    assert!(env.contains("DENT8_WITNESS_PUBKEY="));
    assert!(
        !env.contains("DENT8_WITNESS_KEY="),
        "writer env must not receive the witness signing key"
    );
    assert!(
        temp.file(".dent8/witness.jsonl").exists(),
        "init should create the local witness-head log"
    );
}

#[cfg(not(feature = "witness"))]
#[test]
fn doctor_without_witness_feature_fails_closed_when_signed_heads_exist() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let witness_log = temp.file("witness.jsonl").to_string_lossy().into_owned();
    fs::write(&witness_log, "{}\n").expect("witness log");

    let doctor = run_dent8(
        &["doctor"],
        &[
            ("DENT8_LOG", log.as_str()),
            ("DENT8_WITNESS_LOG", witness_log.as_str()),
        ],
    );
    assert_eq!(doctor.status.code(), Some(1));
    assert!(
        stdout(&doctor).contains("signed heads are configured"),
        "{}",
        stdout(&doctor)
    );
}

#[cfg(feature = "witness")]
fn assert_alice_fact(log: &str, predicate: &str, value: &str, context: &str) {
    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                predicate,
                value,
                "--authority",
                "high",
                "--source",
                "user:alice",
            ],
            &[("DENT8_LOG", log)],
        ),
        context,
    );
}

#[cfg(feature = "witness")]
#[test]
fn witness_publish_is_idempotent_and_rejects_local_witness_rollback() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let key = temp.file("witness.key").to_string_lossy().into_owned();
    let pubkey = format!("{key}.pub");
    let witness_log = temp.file("witness.jsonl").to_string_lossy().into_owned();
    let published = temp
        .file("published-heads.jsonl")
        .to_string_lossy()
        .into_owned();

    assert_success(
        &run_dent8(&["witness", "keygen"], &[("DENT8_WITNESS_KEY", &key)]),
        "witness keygen",
    );
    let sign_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_WITNESS_KEY", key.as_str()),
        ("DENT8_WITNESS_LOG", witness_log.as_str()),
    ];
    let publish_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_WITNESS_LOG", witness_log.as_str()),
        ("DENT8_WITNESS_PUBKEY", pubkey.as_str()),
    ];

    assert_alice_fact(&log, "favorite_drink", "tea", "assert first fact");
    assert_success(&run_dent8(&["witness", "sign"], &sign_env), "first sign");
    let published_first = run_dent8(&["witness", "publish", &published], &publish_env);
    assert_success(&published_first, "publish first head");
    assert_eq!(line_count(&published), 1);

    let duplicate = run_dent8(&["witness", "publish", &published], &publish_env);
    assert_success(&duplicate, "publish duplicate head");
    assert!(stdout(&duplicate).contains("already published"));
    assert_eq!(line_count(&published), 1);

    let first_published_line = fs::read_to_string(&published)
        .expect("published heads")
        .lines()
        .next()
        .expect("first published head")
        .to_string();
    assert_alice_fact(&log, "favorite_snack", "apple", "assert second fact");
    assert_success(&run_dent8(&["witness", "sign"], &sign_env), "second sign");
    let published_second = run_dent8(&["witness", "publish", &published], &publish_env);
    assert_success(&published_second, "publish second head");
    assert_eq!(line_count(&published), 2);
    let local_witness_lines = fs::read_to_string(&witness_log)
        .expect("local witness log")
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    assert_eq!(local_witness_lines.len(), 2);

    let broken_published = temp
        .file("broken-published-heads.jsonl")
        .to_string_lossy()
        .into_owned();
    fs::write(
        &witness_log,
        format!("{}\n{}\n", local_witness_lines[1], local_witness_lines[0]),
    )
    .expect("reorder witness log");
    let broken_local = run_dent8(&["witness", "publish", &broken_published], &publish_env);
    assert_eq!(broken_local.status.code(), Some(1));
    assert!(
        stderr(&broken_local).contains("ROLLBACK"),
        "{}",
        stderr(&broken_local)
    );
    assert!(!std::path::Path::new(&broken_published).exists());

    fs::write(&witness_log, format!("{first_published_line}\n")).expect("rewind witness log");
    let rollback = run_dent8(&["witness", "publish", &published], &publish_env);
    assert_eq!(rollback.status.code(), Some(1));
    assert!(
        stderr(&rollback).contains("ahead of the local witness log"),
        "{}",
        stderr(&rollback)
    );
}

#[cfg(feature = "witness")]
#[test]
fn witness_verify_published_detects_rollback_even_if_local_witness_log_is_rewound() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let key = temp.file("witness.key").to_string_lossy().into_owned();
    let pubkey = format!("{key}.pub");
    let witness_log = temp.file("witness.jsonl").to_string_lossy().into_owned();
    let published = temp
        .file("published-heads.jsonl")
        .to_string_lossy()
        .into_owned();
    let sign_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_WITNESS_KEY", key.as_str()),
        ("DENT8_WITNESS_LOG", witness_log.as_str()),
    ];

    assert_success(
        &run_dent8(&["witness", "keygen"], &[("DENT8_WITNESS_KEY", &key)]),
        "witness keygen",
    );
    assert_alice_fact(&log, "favorite_drink", "tea", "assert alice drink");
    assert_success(&run_dent8(&["witness", "sign"], &sign_env), "witness sign");
    let head = run_dent8(
        &["witness", "head"],
        &[("DENT8_WITNESS_LOG", witness_log.as_str())],
    );
    assert_success(&head, "witness head");
    fs::write(&published, stdout(&head)).expect("published heads");

    let verify_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_WITNESS_PUBKEY", pubkey.as_str()),
    ];
    let verified = run_dent8(&["witness", "verify-published", &published], &verify_env);
    assert_success(&verified, "verify published head");
    assert!(
        stdout(&verified).contains("published signed tree head(s) verify"),
        "{}",
        stdout(&verified)
    );

    fs::write(&witness_log, "").expect("rewind local witness log");
    let verified_after_local_rollback =
        run_dent8(&["witness", "verify-published", &published], &verify_env);
    assert_success(
        &verified_after_local_rollback,
        "verify published head after local witness rollback",
    );

    assert_alice_fact(
        &log,
        "favorite_snack",
        "apple",
        "assert second witnessed fact",
    );
    assert_success(
        &run_dent8(&["witness", "sign"], &sign_env),
        "second witness sign",
    );
    let second_head = run_dent8(
        &["witness", "head"],
        &[("DENT8_WITNESS_LOG", witness_log.as_str())],
    );
    assert_success(&second_head, "second witness head");
    let mut published_contents = fs::read_to_string(&published).expect("published heads");
    published_contents.push_str(&stdout(&second_head));
    fs::write(&published, published_contents).expect("append second published head");

    assert_alice_fact(&log, "favorite_color", "green", "assert unwitnessed tail");
    let trailing = run_dent8(&["witness", "verify-published", &published], &verify_env);
    assert_success(&trailing, "verify published head with unwitnessed tail");
    assert!(
        stdout(&trailing).contains("WARN: 2 published signed tree head(s)")
            && stdout(&trailing).contains("trails current log 3 by 1 unwitnessed event(s)"),
        "{}",
        stdout(&trailing)
    );

    fs::write(&log, "").expect("rollback event log below published head");
    let rejected = run_dent8(&["witness", "verify-published", &published], &verify_env);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(
        stderr(&rejected).contains("ROLLBACK"),
        "{}",
        stderr(&rejected)
    );

    let empty = temp
        .file("empty-published.jsonl")
        .to_string_lossy()
        .into_owned();
    fs::write(&empty, "").expect("empty published heads");
    let empty_rejected = run_dent8(&["witness", "verify-published", &empty], &verify_env);
    assert_eq!(empty_rejected.status.code(), Some(1));
    assert!(
        stderr(&empty_rejected).contains("cannot prove external witness coverage"),
        "{}",
        stderr(&empty_rejected)
    );
}

#[cfg(feature = "witness")]
#[test]
fn witness_doctor_checks_writer_signer_separation() {
    let temp = TempDir::new();
    let key = temp.file("witness.key").to_string_lossy().into_owned();
    let pubkey = format!("{key}.pub");
    let witness_log = temp.file("witness.jsonl").to_string_lossy().into_owned();
    fs::write(&witness_log, "").expect("witness log");

    assert_success(
        &run_dent8(&["witness", "keygen"], &[("DENT8_WITNESS_KEY", &key)]),
        "witness keygen",
    );

    let writer_env = [
        ("DENT8_WITNESS_LOG", witness_log.as_str()),
        ("DENT8_WITNESS_PUBKEY", pubkey.as_str()),
    ];
    let writer = run_dent8(&["witness", "doctor", "writer"], &writer_env);
    assert_success(&writer, "witness doctor writer");
    let writer_stdout = stdout(&writer);
    assert!(
        writer_stdout.contains("witness writer env: DENT8_WITNESS_KEY is not set"),
        "{writer_stdout}"
    );

    let contaminated_writer = run_dent8(
        &["witness", "doctor", "writer"],
        &[
            ("DENT8_WITNESS_LOG", witness_log.as_str()),
            ("DENT8_WITNESS_PUBKEY", pubkey.as_str()),
            ("DENT8_WITNESS_KEY", key.as_str()),
        ],
    );
    assert_eq!(contaminated_writer.status.code(), Some(1));
    let contaminated_stdout = stdout(&contaminated_writer);
    assert!(
        contaminated_stdout.contains("FAIL  witness writer env: DENT8_WITNESS_KEY is set"),
        "{contaminated_stdout}"
    );

    let signer = run_dent8(
        &["witness", "doctor", "signer"],
        &[
            ("DENT8_WITNESS_LOG", witness_log.as_str()),
            ("DENT8_WITNESS_KEY", key.as_str()),
        ],
    );
    assert_success(&signer, "witness doctor signer");
    let signer_stdout = stdout(&signer);
    assert!(
        signer_stdout.contains("witness signer env: public key")
            && signer_stdout.contains("matches the signing key"),
        "{signer_stdout}"
    );
}

#[cfg(all(feature = "witness", unix))]
#[test]
fn witness_operator_split_demo_runs_against_test_binary() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/witness/demo.sh");
    let output = Command::new("bash")
        .arg(script)
        .env("DENT8", dent8_bin())
        .env("DENT8_STORE_URL", "postgres://poisoned-parent-env")
        .env("DENT8_LOG", "/poisoned/parent-memory.jsonl")
        .env("DENT8_AUTHORITY", "/poisoned/authority.json")
        .env("DENT8_REQUIRE_AUTHORITY", "1")
        .env("DENT8_TRUST", "/poisoned/trust.json")
        .env("DENT8_ACTIVE_GRANTS", "/poisoned/active-grants.json")
        .env("DENT8_REQUIRE_IDENTITY", "1")
        .env("DENT8_GRANT", "/poisoned/source.grant.json")
        .env("DENT8_IDENTITY_KEY", "/poisoned/source.key")
        .env("DENT8_ISSUER_KEY", "/poisoned/issuer.key")
        .env("DENT8_WITNESS_KEY", "/poisoned/witness.key")
        .env("DENT8_WITNESS_PUBKEY", "/poisoned/witness.key.pub")
        .env("DENT8_WITNESS_LOG", "/poisoned/witness.jsonl")
        .output()
        .expect("run witness demo");
    assert_success(&output, "examples/witness/demo.sh");
    let stdout = stdout(&output);
    assert!(
        stdout.contains("witness writer env: DENT8_WITNESS_KEY is not set")
            && stdout.contains("published witness head:")
            && stdout.contains("OK: externally published head detects event-log rollback")
            && stdout.contains("OK: witness demo complete"),
        "{stdout}"
    );
}

#[cfg(feature = "witness")]
#[test]
fn witness_doctor_reports_coverage_and_detects_rewritten_history() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let key = temp.file("witness.key").to_string_lossy().into_owned();
    let pubkey = format!("{key}.pub");
    let witness_log = temp.file("witness.jsonl").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(&["witness", "keygen"], &[("DENT8_WITNESS_KEY", &key)]),
        "witness keygen",
    );

    let write_env = [("DENT8_LOG", log.as_str())];
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
                "user:alice",
            ],
            &write_env,
        ),
        "assert alice drink",
    );

    assert_success(
        &run_dent8(
            &["witness", "sign"],
            &[
                ("DENT8_LOG", log.as_str()),
                ("DENT8_WITNESS_KEY", key.as_str()),
                ("DENT8_WITNESS_LOG", witness_log.as_str()),
            ],
        ),
        "witness sign",
    );

    let verify_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_WITNESS_LOG", witness_log.as_str()),
        ("DENT8_WITNESS_PUBKEY", pubkey.as_str()),
    ];
    let doctor = run_dent8(&["doctor"], &verify_env);
    assert_success(&doctor, "doctor with witnessed log");
    let doctor_stdout = stdout(&doctor);
    assert!(
        doctor_stdout.contains(
            "witness verify: 1 signed tree head(s) verify; latest witnessed count 1, current log 1"
        ),
        "{doctor_stdout}"
    );

    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_snack",
                "apple",
                "--authority",
                "high",
                "--source",
                "user:alice",
            ],
            &write_env,
        ),
        "assert unwitnessed tail",
    );
    let doctor = run_dent8(&["doctor"], &verify_env);
    assert_success(&doctor, "doctor with unwitnessed tail");
    let doctor_stdout = stdout(&doctor);
    assert!(
        doctor_stdout.contains("trails current log 2 by 1 unwitnessed event(s)"),
        "{doctor_stdout}"
    );

    let contents = fs::read_to_string(&log).expect("event log");
    assert!(contents.contains("tea"));
    fs::write(&log, contents.replacen("tea", "chai", 1)).expect("tamper event log");

    let verify = run_dent8(&["witness", "verify"], &verify_env);
    assert_eq!(verify.status.code(), Some(1));
    assert!(stderr(&verify).contains("TAMPER"), "{}", stderr(&verify));

    let doctor = run_dent8(&["doctor"], &verify_env);
    assert_eq!(doctor.status.code(), Some(1));
    let doctor_stdout = stdout(&doctor);
    assert!(
        doctor_stdout.contains("FAIL  witness verify: TAMPER"),
        "{doctor_stdout}"
    );
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

#[test]
fn init_rejects_agent_source_override() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let init = run_dent8(
        &[
            "init",
            "--dir",
            &dir,
            "--agent",
            "codex",
            "--source",
            "source:hecate",
        ],
        &[],
    );
    assert_eq!(init.status.code(), Some(2));
    assert!(stderr(&init).contains("cannot be used with"));
    assert!(
        !temp.file(".dent8").exists(),
        "conflicting init args should fail before creating config state"
    );
}

#[cfg(feature = "identity")]
#[test]
fn init_identity_bootstraps_a_usable_secure_local_setup() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    let init = run_dent8(
        &[
            "init",
            "--dir",
            &dir,
            "--source",
            "source:codex",
            "--identity",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&init, "init --identity");
    let stdout = stdout(&init);
    assert!(stdout.contains("identity env:"));
    assert!(stdout.contains(".dent8/identity-codex.env"));
    assert!(stdout.contains("dent8 doctor --source source:codex --write-check"));

    let env_path = temp.file(".dent8/env");
    let identity_env_path = temp.file(".dent8/identity-codex.env");
    let authority_path = temp.file(".dent8/authority.json");
    let trust_path = temp.file(".dent8/trust.json");
    let grant_path = temp.file(".dent8/grants/source_codex.grant.json");
    let key_path = temp.file(".dent8/identities/source_codex.key");
    let log_path = temp.file(".dent8/memory.jsonl");

    assert!(env_path.exists(), "init should write env");
    assert!(
        identity_env_path.exists(),
        "init should write identity-codex.env"
    );
    assert!(trust_path.exists(), "init should write trust registry");
    assert!(grant_path.exists(), "init should write source grant");
    assert!(key_path.exists(), "init should write source key");
    assert!(std::path::Path::new(&issuer_key).exists());
    assert!(
        !temp.file(".dent8/issuer.key").exists(),
        "issuer private key must stay outside the project bundle"
    );

    let authority = fs::read_to_string(&authority_path).expect("authority registry");
    assert!(authority.contains("source:codex"));
    let identity_env = fs::read_to_string(&identity_env_path).expect("identity env");
    assert!(identity_env.contains("DENT8_REQUIRE_IDENTITY=1"));
    assert!(identity_env.contains("DENT8_TRUST="));
    assert!(identity_env.contains("DENT8_ACTIVE_GRANTS="));
    assert!(identity_env.contains("DENT8_GRANT="));
    assert!(identity_env.contains("DENT8_IDENTITY_KEY="));

    let log = log_path.to_string_lossy().into_owned();
    let authority_path = authority_path.to_string_lossy().into_owned();
    let trust = trust_path.to_string_lossy().into_owned();
    let grant = grant_path.to_string_lossy().into_owned();
    let key = key_path.to_string_lossy().into_owned();
    let envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_AUTHORITY", authority_path.as_str()),
        ("DENT8_REQUIRE_AUTHORITY", "1"),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", grant.as_str()),
        ("DENT8_IDENTITY_KEY", key.as_str()),
        ("DENT8_REQUIRE_IDENTITY", "1"),
    ];
    assert_success(
        &run_dent8(
            &["doctor", "--source", "source:codex", "--write-check"],
            &envs,
        ),
        "doctor with init identity bundle",
    );
}

#[cfg(feature = "identity")]
#[test]
fn init_agent_profile_selects_source_and_implies_identity() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    let init = run_dent8(
        &[
            "init",
            "--dir",
            &dir,
            "--agent",
            "codex",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&init, "init --agent codex");
    let stdout = stdout(&init);
    assert!(stdout.contains("agent profile: examples/codex/"));
    assert!(stdout.contains("dent8 doctor --source source:codex --write-check"));
    assert!(stdout.contains(".dent8/identity-codex.env"));

    let authority = fs::read_to_string(temp.file(".dent8/authority.json"))
        .expect("authority registry from agent init");
    assert!(authority.contains("source:codex"));
    let env = fs::read_to_string(temp.file(".dent8/env")).expect("agent init env");
    assert!(env.contains("codex-memory.jsonl"));
    assert!(temp.file(".dent8/codex-memory.jsonl").exists());
    assert!(
        !temp.file(".dent8/memory.jsonl").exists(),
        "agent profile should not initialize a second default log"
    );
    assert!(temp.file(".dent8/identity-codex.env").exists());
    assert!(temp.file(".dent8/grants/source_codex.grant.json").exists());
    assert!(temp.file(".dent8/identities/source_codex.key").exists());
}

#[cfg(feature = "identity")]
#[test]
fn init_emits_machine_readable_json() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    let init = run_dent8(
        &[
            "--output",
            "json",
            "init",
            "--dir",
            &dir,
            "--agent",
            "codex",
            "--issuer-key",
            &issuer_key,
            "--witness",
        ],
        &[],
    );
    assert_success(&init, "init --output json --agent codex --witness");
    assert!(stderr(&init).is_empty(), "{}", stderr(&init));
    let init = stdout_json(&init);
    assert_eq!(init["status"], "ok");
    assert_eq!(init["tool"], "init");
    assert_eq!(init["dir"], dir);
    assert_eq!(init["source"], "source:codex");
    assert_eq!(init["agent"], "codex");
    assert_eq!(init["store"]["kind"], "file");
    assert_eq!(init["store"]["env_key"], "DENT8_LOG");
    assert!(
        init["store"]["env_value"]
            .as_str()
            .expect("store env value")
            .ends_with(".dent8/codex-memory.jsonl")
    );
    assert_eq!(
        init["authority"]["path"],
        temp.file(".dent8/authority.json")
            .to_string_lossy()
            .to_string()
    );
    assert_eq!(
        init["env"]["path"],
        temp.file(".dent8/env").to_string_lossy().to_string()
    );
    assert_eq!(init["identity"]["source"], "source:codex");
    assert_eq!(init["identity"]["issuer"], "owner");
    assert_eq!(init["identity"]["max_authority"], "High");
    assert_eq!(
        init["identity"]["issuer_key_path"],
        fs::canonicalize(&issuer_key)
            .expect("issuer key")
            .to_string_lossy()
            .to_string()
    );
    assert_eq!(
        init["identity"]["env_file"],
        fs::canonicalize(temp.file(".dent8/identity-codex.env"))
            .expect("identity env")
            .to_string_lossy()
            .to_string()
    );
    assert_eq!(
        init["witness"]["log_path"],
        temp.file(".dent8/witness.jsonl")
            .to_string_lossy()
            .to_string()
    );
    assert_eq!(init["witness"]["signing_key_configured"], false);
    assert!(
        init["mcp_install"].is_null(),
        "plain init should not report MCP install"
    );
    assert!(temp.file(".dent8/env").exists());
    assert!(temp.file(".dent8/identity-codex.env").exists());
    assert!(temp.file(".dent8/witness.jsonl").exists());
}

#[cfg(feature = "identity")]
#[test]
fn init_json_reports_mcp_check_state() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let config_path = temp.file(".codex/config.toml");

    let init = run_dent8(
        &[
            "--output",
            "json",
            "init",
            "--dir",
            &dir,
            "--agent",
            "codex",
            "--issuer-key",
            &issuer_key,
            "--install-mcp",
            "--mcp-check",
        ],
        &[],
    );
    assert_eq!(init.status.code(), Some(1));
    assert!(stderr(&init).is_empty(), "{}", stderr(&init));
    let init = stdout_json(&init);
    assert_eq!(init["status"], "needs_update");
    assert_eq!(init["exit_code"], 1);
    assert_eq!(init["mcp_install"]["status"], "needs_update");
    assert_eq!(init["mcp_install"]["mode"], "check");
    assert_eq!(
        init["mcp_install"]["config"]["path"],
        config_path.to_string_lossy().to_string()
    );
    assert_eq!(init["mcp_install"]["config"]["action"], "created");
    assert_eq!(init["mcp_install"]["config"]["changed"], true);
    assert_eq!(init["mcp_install"]["config"]["written"], false);
    assert!(
        init["mcp_install"]["config"]["contents"]
            .as_str()
            .expect("rendered config")
            .contains("[mcp_servers.dent8]")
    );
    assert!(temp.file(".dent8/env").exists());
    assert!(
        !config_path.exists(),
        "init --mcp-check should not write the MCP config"
    );
}

#[test]
fn init_json_reports_errors() {
    let init = run_dent8(&["--output", "json", "init", "--store", "postgres"], &[]);
    assert_eq!(init.status.code(), Some(1));
    assert!(stdout(&init).is_empty(), "{}", stdout(&init));
    let init = stderr_json(&init);
    assert_eq!(init["status"], "failed");
    assert_eq!(init["tool"], "init");
    assert_eq!(init["store"], "postgres");
    assert!(
        init["message"]
            .as_str()
            .expect("message")
            .contains("--store-url postgres://")
    );
}

#[test]
fn init_rejects_mcp_command_without_install_mcp() {
    let output = run_dent8(&["init", "--mcp-command", "/usr/local/bin/dent8"], &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--install-mcp"));
}

#[cfg(feature = "identity")]
#[test]
fn init_agent_codex_installs_mcp_config_and_prints_resulting_file() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let config_path = temp.file(".codex/config.toml");

    let init = run_dent8(
        &[
            "init",
            "--dir",
            &dir,
            "--agent",
            "codex",
            "--issuer-key",
            &issuer_key,
            "--install-mcp",
        ],
        &[],
    );
    assert_success(&init, "init --agent codex --install-mcp");
    let stdout = stdout(&init);
    assert!(stdout.contains("created MCP config:"));
    assert!(stdout.contains(&format!("--- {} ---", config_path.display())));

    let config = fs::read_to_string(&config_path).expect("codex mcp config");
    assert!(config.contains("[mcp_servers.dent8]"));
    assert!(config.contains("[mcp_servers.dent8.env]"));
    assert!(config.contains("command = \"dent8\""));
    assert!(config.contains("args = [\"mcp\", \"serve\"]"));
    assert!(config.contains("startup_timeout_sec = 20"));
    assert!(config.contains("tool_timeout_sec = 60"));
    assert!(config.contains(&format!(
        "DENT8_LOG = \"{}\"",
        temp.file(".dent8/codex-memory.jsonl").display()
    )));
    assert!(config.contains("DENT8_ACTIVE_GRANTS = "));
    assert!(config.contains("active-grants.json"));
    assert!(config.contains("DENT8_GRANT = "));
    assert!(config.contains("source_codex.grant.json"));
    assert!(config.contains("DENT8_IDENTITY_KEY = "));
    assert!(config.contains("source_codex.key"));
    assert!(
        stdout.contains(&config),
        "init should show the resulting config file"
    );
}

#[cfg(feature = "identity")]
#[test]
fn mcp_install_requires_per_source_identity_env() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex",
    );

    let per_source_env = temp.file(".dent8/identity-codex.env");
    fs::copy(&per_source_env, temp.file(".dent8/identity.env")).expect("seed old identity env");
    fs::remove_file(&per_source_env).expect("remove per-source identity env");

    let install = run_dent8(&["mcp", "install", "--agent", "codex", "--dir", &dir], &[]);
    assert_eq!(install.status.code(), Some(1));
    let output = format!("{}{}", stdout(&install), stderr(&install));
    assert!(
        output.contains("identity-codex.env")
            && output.contains("dent8 identity repair-env --dir")
            && output.contains("--source source:codex"),
        "mcp install should require the per-source identity env, not .dent8/identity.env; output:\n{output}"
    );
    assert!(
        !temp.file(".codex/config.toml").exists(),
        "failed install should not write an MCP config"
    );
}

#[cfg(feature = "identity")]
#[test]
fn mcp_install_local_bin_writes_wrapper_and_config() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    seed_local_mcp_target(&dir);

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex",
    );

    let install = run_dent8(
        &[
            "mcp",
            "install",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--local-bin",
        ],
        &[],
    );
    assert_success(&install, "mcp install --local-bin");
    let install_stdout = stdout(&install);
    assert!(install_stdout.contains("local MCP wrapper:"));
    assert!(install_stdout.contains(".dent8/target-sqlite/debug/dent8"));

    let wrapper = fs::read_to_string(temp.file(".dent8/bin/dent8")).expect("local wrapper");
    assert!(wrapper.contains("target-sqlite/debug/dent8"));
    assert!(
        !wrapper.contains("cargo run"),
        "local wrapper must not run Cargo during MCP startup"
    );

    let config = fs::read_to_string(temp.file(".codex/config.toml")).expect("codex mcp config");
    assert!(config.contains(&format!(
        "command = \"{}\"",
        temp.file(".dent8/bin/dent8").display()
    )));

    let checked = run_dent8(
        &[
            "mcp",
            "install",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--local-bin",
            "--check",
        ],
        &[],
    );
    assert_success(&checked, "mcp install --local-bin --check");
    assert!(stdout(&checked).contains("local MCP wrapper up to date:"));

    let checked_json = run_dent8(
        &[
            "--output",
            "json",
            "mcp",
            "install",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--local-bin",
            "--check",
        ],
        &[],
    );
    assert_success(
        &checked_json,
        "mcp install --local-bin --check --output json",
    );
    let checked_json = stdout_json(&checked_json);
    assert_eq!(checked_json["status"], "ok");
    assert_eq!(checked_json["tool"], "mcp install");
    assert_eq!(checked_json["agent"], "codex");
    assert_eq!(checked_json["mode"], "check");
    assert_eq!(checked_json["local_bin"], true);
    assert_eq!(
        checked_json["command_written"],
        temp.file(".dent8/bin/dent8").to_string_lossy().to_string()
    );
    assert_eq!(checked_json["local_binary"]["action"], "unchanged");
    assert_eq!(checked_json["local_binary"]["changed"], false);
    assert_eq!(checked_json["local_binary"]["target_executable"], true);
    assert_eq!(
        checked_json["local_binary"]["wrapper"],
        temp.file(".dent8/bin/dent8").to_string_lossy().to_string()
    );
    assert_eq!(checked_json["config"]["action"], "unchanged");
    assert_eq!(checked_json["config"]["changed"], false);
    assert_eq!(checked_json["config"]["written"], false);
}

#[cfg(feature = "identity")]
#[test]
fn mcp_install_local_bin_requires_prebuilt_target_before_writing() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex",
    );

    let install = run_dent8(
        &[
            "mcp",
            "install",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--local-bin",
        ],
        &[],
    );
    assert_eq!(install.status.code(), Some(1));
    assert!(stderr(&install).contains("local MCP binary target is missing or not executable"));
    assert!(
        !temp.file(".dent8/bin/dent8").exists(),
        "failed local-bin install should not leave a wrapper behind"
    );
    assert!(
        !temp.file(".codex/config.toml").exists(),
        "failed local-bin install should not patch MCP config"
    );
}

#[cfg(feature = "identity")]
#[test]
fn doctor_agent_accepts_local_bin_install() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    seed_local_mcp_target(&dir);

    let init = run_dent8(
        &[
            "init",
            "--dir",
            &dir,
            "--agent",
            "codex",
            "--issuer-key",
            &issuer_key,
            "--install-mcp",
            "--mcp-local-bin",
        ],
        &[],
    );
    assert_success(&init, "init --agent codex --install-mcp --mcp-local-bin");

    let doctor = run_dent8(
        &[
            "doctor",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--mcp-local-bin",
        ],
        &[],
    );
    assert_success(&doctor, "doctor --agent codex --mcp-local-bin");
    let stdout = stdout(&doctor);
    assert!(stdout.contains("local MCP wrapper:"));
    assert!(stdout.contains("local MCP binary: installed command can load the configured store"));
    assert!(stdout.contains("mcp smoke: initialize + tools/list OK"));
}

#[cfg(feature = "identity")]
#[test]
fn doctor_agent_reports_stale_local_bin_repair_command() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    seed_local_mcp_target(&dir);

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-local-bin",
            ],
            &[],
        ),
        "init --agent codex --install-mcp --mcp-local-bin",
    );
    fs::write(temp.file(".dent8/bin/dent8"), "#!/bin/sh\nexit 0\n").expect("stale wrapper");
    make_executable(&temp.file(".dent8/bin/dent8"));

    let doctor = run_dent8(
        &[
            "doctor",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--mcp-local-bin",
        ],
        &[],
    );
    assert_eq!(doctor.status.code(), Some(1));
    let stdout = stdout(&doctor);
    assert!(stdout.contains("local MCP wrapper:"));
    assert!(stdout.contains("is stale; repair with `dent8 doctor --agent codex --dir"));
    assert!(stdout.contains("--repair --mcp-local-bin`"));
    assert!(
        !stdout.contains("local MCP binary: installed command can load the configured store"),
        "{stdout}"
    );
    assert!(!stdout.contains("<profile>"), "{stdout}");
}

#[cfg(feature = "identity")]
#[test]
fn doctor_agent_checks_bundle_config_and_mcp_smoke() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "init --agent codex --install-mcp",
    );

    let doctor = run_dent8(
        &["doctor", "--agent", "codex", "--dir", &dir, "--write-check"],
        &[],
    );
    assert_success(&doctor, "doctor --agent codex --write-check");
    let stdout = stdout(&doctor);
    assert!(stdout.contains("agent: codex (source:codex)"));
    assert!(stdout.contains(".dent8 env: agent bundle is complete"));
    assert!(stdout.contains(&format!("command={mcp_command}")));
    assert!(stdout.contains("agent mcp config: up to date"));
    assert!(stdout.contains("source:codex max=High"));
    assert!(stdout.contains("identity source: grant source matches doctor source source:codex"));
    assert!(stdout.contains("mcp smoke: initialize + tools/list OK"));
    assert!(stdout.contains("mcp write-check: accepted trusted diagnostic:doctor-mcp-"));
    assert!(stdout.contains("dent8.write_check=ok"));
    assert!(
        !stdout.contains("  OK  write-check: accepted trusted diagnostic:doctor-"),
        "{stdout}"
    );
}

#[cfg(feature = "identity")]
#[test]
fn identity_repair_env_recovers_stale_agent_bundle_active_grants() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "init --agent codex --install-mcp",
    );

    let identity_env_path = temp.file(".dent8/identity-codex.env");
    let active_grants_path = temp.file(".dent8/active-grants.json");
    let stale_env = fs::read_to_string(&identity_env_path)
        .expect("identity env")
        .lines()
        .filter(|line| !line.starts_with("DENT8_ACTIVE_GRANTS="))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&identity_env_path, format!("{stale_env}\n")).expect("stale identity env");
    fs::remove_file(&active_grants_path).expect("remove active grants");

    let doctor = run_dent8(
        &["doctor", "--agent", "codex", "--dir", &dir, "--write-check"],
        &[],
    );
    assert_eq!(doctor.status.code(), Some(1));
    let doctor_stdout = stdout(&doctor);
    assert!(
        doctor_stdout.contains("generated dent8 env is missing DENT8_ACTIVE_GRANTS")
            && doctor_stdout.contains("dent8 identity repair-env --dir")
            && doctor_stdout.contains("--source source:codex"),
        "{doctor_stdout}"
    );

    let repair = run_dent8(
        &[
            "identity",
            "repair-env",
            "--dir",
            &dir,
            "--source",
            "source:codex",
        ],
        &[],
    );
    assert_success(&repair, "identity repair-env");
    let repair_stdout = stdout(&repair);
    assert!(
        repair_stdout.contains("repaired signed identity env for source:codex")
            && repair_stdout.contains("restored current grant entry from signed grant"),
        "{repair_stdout}"
    );
    let repaired_env = fs::read_to_string(&identity_env_path).expect("repaired identity env");
    assert!(repaired_env.contains("DENT8_ACTIVE_GRANTS="));
    assert!(active_grants_path.exists());

    let doctor = run_dent8(
        &["doctor", "--agent", "codex", "--dir", &dir, "--write-check"],
        &[],
    );
    assert_success(&doctor, "doctor after identity repair-env");
    assert!(
        stdout(&doctor).contains("mcp write-check: accepted trusted diagnostic:doctor-mcp-"),
        "{}",
        stdout(&doctor)
    );
}

#[cfg(feature = "identity")]
#[test]
fn doctor_agent_reports_stale_mcp_config_repair_command() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "init --agent codex --install-mcp",
    );

    let config_path = temp.file(".codex/config.toml");
    let stale_config = fs::read_to_string(&config_path)
        .expect("codex config")
        .lines()
        .filter(|line| !line.trim_start().starts_with("DENT8_ACTIVE_GRANTS ="))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&config_path, format!("{stale_config}\n")).expect("stale codex config");

    let doctor = run_dent8(
        &["doctor", "--agent", "codex", "--dir", &dir, "--write-check"],
        &[],
    );
    assert_eq!(doctor.status.code(), Some(1));
    let stdout = stdout(&doctor);
    assert!(
        stdout.contains("installed env does not match generated bundle")
            && stdout.contains("DENT8_ACTIVE_GRANTS is missing")
            && stdout.contains("dent8 mcp install --agent codex --dir")
            && stdout.contains("--command"),
        "{stdout}"
    );
}

#[cfg(feature = "identity")]
#[test]
fn doctor_agent_repair_refreshes_stale_env_and_mcp_config() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "init --agent codex --install-mcp",
    );

    let identity_env_path = temp.file(".dent8/identity-codex.env");
    let active_grants_path = temp.file(".dent8/active-grants.json");
    let stale_env = fs::read_to_string(&identity_env_path)
        .expect("identity env")
        .lines()
        .filter(|line| !line.starts_with("DENT8_ACTIVE_GRANTS="))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&identity_env_path, format!("{stale_env}\n")).expect("stale identity env");
    fs::remove_file(&active_grants_path).expect("remove active grants");

    let config_path = temp.file(".codex/config.toml");
    let stale_config = fs::read_to_string(&config_path)
        .expect("codex config")
        .lines()
        .filter(|line| !line.trim_start().starts_with("DENT8_ACTIVE_GRANTS ="))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&config_path, format!("{stale_config}\n")).expect("stale codex config");

    let doctor = run_dent8(
        &[
            "doctor",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--repair",
            "--write-check",
        ],
        &[],
    );
    assert_success(&doctor, "doctor --agent codex --repair --write-check");
    let stdout = stdout(&doctor);
    assert!(
        stdout.contains("agent env repair: repaired signed identity env for source:codex")
            && stdout.contains("agent mcp config repair: updated MCP config:")
            && stdout.contains("mcp write-check: accepted trusted diagnostic:doctor-mcp-"),
        "{stdout}"
    );
    let repaired_env = fs::read_to_string(&identity_env_path).expect("repaired identity env");
    let repaired_config = fs::read_to_string(&config_path).expect("repaired codex config");
    assert!(active_grants_path.exists());
    assert!(repaired_env.contains("DENT8_ACTIVE_GRANTS="));
    assert!(repaired_config.contains("DENT8_ACTIVE_GRANTS = "));
}

#[cfg(feature = "identity")]
#[test]
fn identity_repair_env_refuses_to_replace_a_different_active_grant() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--source",
                "source:codex",
                "--identity",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --identity",
    );

    fs::write(
        temp.file(".dent8/active-grants.json"),
        r#"{"sources":{"source:codex":{"grant_signature":"00","public_key":"00"}}}"#,
    )
    .expect("poison active grant registry");

    let repair = run_dent8(
        &[
            "identity",
            "repair-env",
            "--dir",
            &dir,
            "--source",
            "source:codex",
        ],
        &[],
    );
    assert_eq!(repair.status.code(), Some(1));
    assert!(
        stderr(&repair).contains("already has a different current grant"),
        "{}",
        stderr(&repair)
    );
}

#[cfg(feature = "identity")]
#[test]
fn doctor_agent_mcp_write_check_works_for_json_config_profiles() {
    for (agent, source, config_path) in [
        ("claude-code", "source:claude-code", ".mcp.json"),
        ("cursor", "source:cursor", ".cursor/mcp.json"),
        ("grok-build", "source:grok-build", ".mcp.json"),
        ("gemini", "source:gemini", ".gemini/settings.json"),
        ("cascade", "source:cascade", ".windsurf/mcp_config.json"),
    ] {
        let temp = TempDir::new();
        let dir = temp.file(".dent8").to_string_lossy().into_owned();
        let expected_config = temp.file(config_path);
        let issuer_key = temp
            .file(&format!("{agent}-owner.key"))
            .to_string_lossy()
            .into_owned();
        let mcp_command = dent8_bin().to_string_lossy().into_owned();
        assert_success(
            &run_dent8(
                &[
                    "init",
                    "--dir",
                    &dir,
                    "--agent",
                    agent,
                    "--issuer-key",
                    &issuer_key,
                    "--install-mcp",
                    "--mcp-command",
                    &mcp_command,
                ],
                &[],
            ),
            &format!("init --agent {agent} --install-mcp"),
        );
        assert!(
            expected_config.exists(),
            "{agent} should install MCP config at {}",
            expected_config.display()
        );

        let doctor = run_dent8(
            &["doctor", "--agent", agent, "--dir", &dir, "--write-check"],
            &[],
        );
        assert_installed_agent_doctor_ok(&doctor, agent, source, &mcp_command);
        let doctor_stdout = stdout(&doctor);
        assert!(
            doctor_stdout.contains(&expected_config.display().to_string()),
            "doctor should read {} for {agent}; stdout:\n{}",
            expected_config.display(),
            doctor_stdout
        );
    }
}

#[cfg(feature = "identity")]
#[test]
fn mcp_install_rejects_second_agent_on_another_agents_file_log() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "init --agent codex --install-mcp",
    );
    add_claude_code_identity(&temp, &dir, &issuer_key);

    let install = run_dent8(
        &[
            "mcp",
            "install",
            "--agent",
            "claude-code",
            "--dir",
            &dir,
            "--command",
            &mcp_command,
        ],
        &[],
    );
    assert_eq!(install.status.code(), Some(1));
    let output = format!("{}{}", stdout(&install), stderr(&install));
    assert!(
        output.contains("expects claude-memory.jsonl") && output.contains("DENT8_STORE_URL"),
        "file dev stores should stay per-agent unless a shared backend is configured; output:\n{output}"
    );
}

#[cfg(feature = "identity")]
#[test]
fn agent_add_rejects_file_store_bundle() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex",
    );

    let added = run_dent8(
        &[
            "agent",
            "add",
            "--agent",
            "claude-code",
            "--dir",
            &dir,
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_eq!(added.status.code(), Some(1));
    let output = format!("{}{}", stdout(&added), stderr(&added));
    assert!(
        output.contains("DENT8_STORE_URL") && output.contains("file-dev bundle"),
        "agent add should require a shared backend; output:\n{output}"
    );
    assert!(
        !temp.file(".dent8/identity-claude-code.env").exists(),
        "agent add should fail before creating a second identity on a file-dev bundle"
    );
}

#[cfg(feature = "identity")]
#[test]
fn agent_add_error_emits_machine_readable_json() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex",
    );

    let added = run_dent8(
        &[
            "--output",
            "json",
            "agent",
            "add",
            "--agent",
            "claude-code",
            "--dir",
            &dir,
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_eq!(added.status.code(), Some(1));
    assert!(
        stdout(&added).is_empty(),
        "failed JSON command should not write stdout:\n{}",
        stdout(&added)
    );
    let error = stderr_json(&added);
    assert_eq!(error["status"], "failed");
    assert_eq!(error["tool"], "agent add");
    assert_eq!(error["agent"], "claude-code");
    assert_eq!(error["dir"], dir);
    assert!(
        error["message"]
            .as_str()
            .expect("error message")
            .contains("file-dev bundle")
    );
    assert!(
        !temp.file(".dent8/identity-claude-code.env").exists(),
        "agent add should fail before creating a second identity on a file-dev bundle"
    );
}

#[cfg(all(feature = "identity", feature = "sqlite"))]
#[test]
fn doctor_passes_for_multiple_agents_on_shared_sqlite_store() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--store",
                "sqlite",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "init --agent codex --store sqlite --install-mcp",
    );
    assert_success(
        &run_dent8(
            &[
                "agent",
                "add",
                "--agent",
                "claude-code",
                "--dir",
                &dir,
                "--issuer-key",
                &issuer_key,
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "agent add --agent claude-code",
    );
    assert!(
        temp.file(".dent8/identity-claude-code.env").exists(),
        "agent add should create a per-source identity env"
    );

    let repeated = run_dent8(
        &[
            "agent",
            "add",
            "--agent",
            "claude-code",
            "--dir",
            &dir,
            "--issuer-key",
            &issuer_key,
            "--mcp-command",
            &mcp_command,
        ],
        &[],
    );
    assert_success(&repeated, "repeat agent add --agent claude-code");
    assert!(
        stdout(&repeated).contains("identity: reused grant"),
        "repeat agent add should repair/reuse identity, not rotate it; stdout:\n{}",
        stdout(&repeated)
    );

    for agent in ["codex", "claude-code"] {
        let doctor = run_dent8(
            &["doctor", "--agent", agent, "--dir", &dir, "--write-check"],
            &[],
        );
        assert_success(&doctor, &format!("doctor --agent {agent} in shared bundle"));
        let doctor_stdout = stdout(&doctor);
        assert!(
            doctor_stdout.contains("agent mcp config: up to date")
                && doctor_stdout.contains("mcp write-check: accepted trusted"),
            "doctor should validate installed MCP env for {agent}; stdout:\n{doctor_stdout}"
        );
    }
}

#[cfg(all(feature = "identity", feature = "sqlite"))]
#[test]
fn agent_add_emits_machine_readable_json() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--store",
                "sqlite",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex --store sqlite",
    );

    let added = run_dent8(
        &[
            "--output",
            "json",
            "agent",
            "add",
            "--agent",
            "claude-code",
            "--dir",
            &dir,
            "--issuer-key",
            &issuer_key,
            "--mcp-command",
            &mcp_command,
        ],
        &[],
    );
    assert_success(&added, "agent add --output json");
    assert!(stderr(&added).is_empty(), "{}", stderr(&added));
    let added = stdout_json(&added);
    assert_eq!(added["status"], "ok");
    assert_eq!(added["tool"], "agent add");
    assert_eq!(added["agent"], "claude-code");
    assert_eq!(added["source"], "source:claude-code");
    assert_eq!(
        added["store_url"],
        format!("sqlite://{}", temp.file(".dent8/dent8.db").display())
    );
    assert_eq!(added["authority"]["max_authority"], "High");
    assert_eq!(added["identity"]["reused"], false);
    assert_eq!(
        added["identity"]["env_file"],
        fs::canonicalize(temp.file(".dent8/identity-claude-code.env"))
            .expect("identity env path")
            .to_string_lossy()
            .to_string()
    );
    assert_eq!(added["mcp_install"]["status"], "ok");
    assert_eq!(added["mcp_install"]["command_written"], mcp_command);
    assert_eq!(added["mcp_install"]["config"]["written"], true);
    assert!(
        temp.file(".dent8/identity-claude-code.env").exists(),
        "agent add should create a per-source identity env"
    );
}

#[cfg(all(feature = "identity", feature = "sqlite"))]
#[test]
fn agent_add_preserves_existing_authority_ceiling_when_reused() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--store",
                "sqlite",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex --store sqlite",
    );
    assert_success(
        &run_dent8(
            &[
                "agent",
                "add",
                "--agent",
                "claude-code",
                "--dir",
                &dir,
                "--issuer-key",
                &issuer_key,
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "agent add --agent claude-code",
    );

    let authority = temp
        .file(".dent8/authority.json")
        .to_string_lossy()
        .into_owned();
    assert_success(
        &run_dent8(
            &["authority", "add", "source:claude-code", "medium"],
            &[("DENT8_AUTHORITY", authority.as_str())],
        ),
        "lower claude-code authority ceiling",
    );

    let repeated = run_dent8(
        &[
            "agent",
            "add",
            "--agent",
            "claude-code",
            "--dir",
            &dir,
            "--issuer-key",
            &issuer_key,
            "--mcp-command",
            &mcp_command,
        ],
        &[],
    );
    assert_success(
        &repeated,
        "repeat agent add after manual authority lowering",
    );
    assert!(
        stdout(&repeated).contains("authority ceiling=Medium"),
        "agent add should preserve the existing lowered ceiling unless --authority is explicit; stdout:\n{}",
        stdout(&repeated)
    );
    let registry: Value =
        serde_json::from_str(&fs::read_to_string(&authority).expect("authority registry"))
            .expect("authority registry json");
    assert_eq!(
        registry["sources"]["source:claude-code"]["max_authority"], "Medium",
        "repeat agent add must not silently raise an existing authority ceiling"
    );
}

#[cfg(feature = "identity")]
fn add_claude_code_identity(temp: &TempDir, dir: &str, issuer_key: &str) {
    let authority = temp
        .file(".dent8/authority.json")
        .to_string_lossy()
        .into_owned();
    assert_success(
        &run_dent8(
            &["authority", "add", "source:claude-code", "high"],
            &[("DENT8_AUTHORITY", authority.as_str())],
        ),
        "authority add source:claude-code",
    );
    let claude_key = temp.file(".dent8/identities/source_claude-code.key");
    assert_success(
        &run_dent8(
            &[
                "identity",
                "agent-keygen",
                "source:claude-code",
                "--out",
                claude_key.to_string_lossy().as_ref(),
            ],
            &[],
        ),
        "identity agent-keygen source:claude-code",
    );
    let claude_grant = temp.file(".dent8/grants/source_claude-code.grant.json");
    assert_success(
        &run_dent8(
            &[
                "identity",
                "grant-issue",
                "source:claude-code",
                "--public-key",
                temp.file(".dent8/identities/source_claude-code.key.pub")
                    .to_string_lossy()
                    .as_ref(),
                "--max",
                "high",
                "--issuer",
                "owner",
                "--issuer-key",
                issuer_key,
                "--out",
                claude_grant.to_string_lossy().as_ref(),
                "--scope",
                "*",
            ],
            &[],
        ),
        "identity grant-issue source:claude-code",
    );
    assert_success(
        &run_dent8(
            &[
                "identity",
                "repair-env",
                "--dir",
                dir,
                "--source",
                "source:claude-code",
            ],
            &[],
        ),
        "identity repair-env source:claude-code",
    );
}

#[cfg(feature = "identity")]
#[test]
fn doctor_agent_mcp_write_check_works_for_hecate_task_config() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("hecate-owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();
    let config_path = temp.file("hecate-task.json");
    let config = config_path.to_string_lossy().into_owned();
    fs::write(
        &config_path,
        serde_json::json!({
            "working_directory": temp.path.to_string_lossy(),
            "mcp_servers": [
                { "name": "other", "command": "other-agent", "args": [] }
            ],
        })
        .to_string(),
    )
    .expect("seed hecate task config");
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "hecate",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent hecate",
    );
    assert_success(
        &run_dent8(
            &[
                "mcp",
                "install",
                "--agent",
                "hecate",
                "--dir",
                &dir,
                "--config",
                &config,
                "--command",
                &mcp_command,
            ],
            &[],
        ),
        "mcp install --agent hecate --config",
    );

    let doctor = run_dent8(
        &[
            "doctor",
            "--agent",
            "hecate",
            "--dir",
            &dir,
            "--mcp-config",
            &config,
            "--write-check",
        ],
        &[],
    );
    assert_installed_agent_doctor_ok(&doctor, "hecate", "source:hecate", &mcp_command);
    let stdout = stdout(&doctor);
    assert!(stdout.contains(&format!("cwd={}", temp.path.display())));
}

#[cfg(feature = "identity")]
#[test]
fn doctor_agent_smokes_the_configured_mcp_command() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let missing_command = temp.file("missing-dent8").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &missing_command,
            ],
            &[],
        ),
        "init --agent codex --install-mcp with missing command",
    );

    let doctor = run_dent8(&["doctor", "--agent", "codex", "--dir", &dir], &[]);
    assert_eq!(doctor.status.code(), Some(1));
    let stdout = stdout(&doctor);
    assert!(stdout.contains("agent mcp config: up to date"));
    assert!(stdout.contains("mcp smoke: could not start"));
    assert!(stdout.contains(&missing_command));
}

#[cfg(all(feature = "identity", unix))]
#[test]
fn doctor_agent_smokes_installed_cwd_and_custom_env() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let wrapper = temp.file("dent8-wrapper.sh");
    fs::write(
        &wrapper,
        "#!/bin/sh\nset -eu\ntest -f cwd-marker\nexec \"$DENT8_REAL\" \"$@\"\n",
    )
    .expect("write wrapper");
    let mut permissions = fs::metadata(&wrapper)
        .expect("wrapper metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&wrapper, permissions).expect("chmod wrapper");
    fs::write(temp.file("cwd-marker"), "here\n").expect("write cwd marker");

    let wrapper_command = wrapper.to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &wrapper_command,
            ],
            &[],
        ),
        "init --agent codex --install-mcp with wrapper",
    );

    let config_path = temp.file(".codex/config.toml");
    let config = fs::read_to_string(&config_path).expect("codex config");
    let cwd_line = format!(
        "args = [\"mcp\", \"serve\"]\ncwd = \"{}\"",
        toml_basic_string(&temp.path.to_string_lossy())
    );
    let real_bin = format!(
        "\nDENT8_REAL = \"{}\"\n",
        toml_basic_string(&dent8_bin().to_string_lossy())
    );
    let config = config.replace("args = [\"mcp\", \"serve\"]", &cwd_line) + &real_bin;
    fs::write(&config_path, config).expect("rewrite codex config with cwd");

    let doctor = run_dent8(&["doctor", "--agent", "codex", "--dir", &dir], &[]);
    assert_success(&doctor, "doctor --agent codex with configured cwd");
    let stdout = stdout(&doctor);
    assert!(stdout.contains(&format!("command={wrapper_command}")));
    assert!(stdout.contains(&format!("cwd={}", temp.path.display())));
    assert!(stdout.contains("agent mcp config: up to date"));
    assert!(stdout.contains("mcp smoke: initialize + tools/list OK"));
}

#[cfg(all(feature = "identity", unix))]
#[test]
fn doctor_agent_mcp_smoke_times_out_hanging_command() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                "/bin/sh",
            ],
            &[],
        ),
        "init --agent codex --install-mcp with hanging command",
    );

    let config_path = temp.file(".codex/config.toml");
    let config = fs::read_to_string(&config_path).expect("codex config");
    let config = config.replace(
        "args = [\"mcp\", \"serve\"]",
        "args = [\"-c\", \"exec sleep 60\"]",
    );
    fs::write(&config_path, config).expect("rewrite codex config with hanging command");

    let doctor = run_dent8(
        &["doctor", "--agent", "codex", "--dir", &dir],
        &[("DENT8_MCP_SMOKE_TIMEOUT_MS", "150")],
    );
    assert_eq!(doctor.status.code(), Some(1));
    let stdout = stdout(&doctor);
    assert!(stdout.contains("agent mcp config: up to date"));
    assert!(stdout.contains("mcp smoke: `/bin/sh -c exec sleep 60` timed out after 150ms"));
}

#[cfg(feature = "identity")]
#[test]
fn mcp_install_patches_json_config_and_preserves_other_servers() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "gemini",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent gemini",
    );

    let config_path = temp.file(".gemini/settings.json");
    fs::create_dir_all(config_path.parent().expect("settings parent"))
        .expect("create gemini config dir");
    fs::write(
        &config_path,
        r#"{
  "theme": "dark",
  "mcpServers": {
    "other": {
      "command": "other-agent",
      "args": ["serve"]
    }
  }
}
"#,
    )
    .expect("seed gemini settings");

    let installed = run_dent8(&["mcp", "install", "--agent", "gemini", "--dir", &dir], &[]);
    assert_success(&installed, "mcp install --agent gemini");
    let stdout = stdout(&installed);
    assert!(stdout.contains("updated MCP config:"));
    assert!(stdout.contains(&format!("--- {} ---", config_path.display())));

    let first = fs::read_to_string(&config_path).expect("patched gemini settings");
    let parsed = serde_json::from_str::<Value>(&first).expect("patched JSON parses");
    assert_eq!(parsed["theme"], "dark");
    assert_eq!(parsed["mcpServers"]["other"]["command"], "other-agent");
    let dent8 = &parsed["mcpServers"]["dent8"];
    assert_eq!(dent8["command"], "dent8");
    assert_eq!(dent8["args"], serde_json::json!(["mcp", "serve"]));
    assert_eq!(dent8["timeout"], 30_000);
    assert_eq!(dent8["trust"], false);
    assert!(
        dent8["env"]["DENT8_LOG"]
            .as_str()
            .expect("DENT8_LOG")
            .ends_with(".dent8/gemini-memory.jsonl")
    );
    assert!(
        dent8["env"]["DENT8_GRANT"]
            .as_str()
            .expect("DENT8_GRANT")
            .ends_with(".dent8/grants/source_gemini.grant.json")
    );
    assert!(
        dent8["env"]["DENT8_ACTIVE_GRANTS"]
            .as_str()
            .expect("DENT8_ACTIVE_GRANTS")
            .ends_with(".dent8/active-grants.json")
    );
    assert!(
        stdout.contains(&first),
        "install should show the resulting config file"
    );

    assert_success(
        &run_dent8(&["mcp", "install", "--agent", "gemini", "--dir", &dir], &[]),
        "idempotent mcp install --agent gemini",
    );
    let second = fs::read_to_string(&config_path).expect("repatched gemini settings");
    assert_eq!(first, second, "mcp install should be idempotent");
}

#[cfg(feature = "identity")]
#[test]
fn mcp_install_dry_run_and_check_do_not_write() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex",
    );
    let config_path = temp.file(".codex/config.toml");

    let dry_run = run_dent8(
        &[
            "mcp",
            "install",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--command",
            "/usr/local/bin/dent8",
            "--dry-run",
        ],
        &[],
    );
    assert_success(&dry_run, "mcp install --dry-run");
    let dry_run_stdout = stdout(&dry_run);
    assert!(dry_run_stdout.contains("would create MCP config:"));
    assert!(dry_run_stdout.contains("command = \"/usr/local/bin/dent8\""));
    assert!(dry_run_stdout.contains("DENT8_LOG"));
    assert!(
        !config_path.exists(),
        "dry-run should not create the MCP config file"
    );

    let stale_check = run_dent8(
        &[
            "mcp", "install", "--agent", "codex", "--dir", &dir, "--check",
        ],
        &[],
    );
    assert_eq!(stale_check.status.code(), Some(1));
    assert!(stdout(&stale_check).contains("MCP config needs update:"));
    assert!(
        !config_path.exists(),
        "check should not create the MCP config file"
    );

    assert_success(
        &run_dent8(&["mcp", "install", "--agent", "codex", "--dir", &dir], &[]),
        "mcp install --agent codex",
    );
    let up_to_date_check = run_dent8(
        &[
            "mcp", "install", "--agent", "codex", "--dir", &dir, "--check",
        ],
        &[],
    );
    assert_success(&up_to_date_check, "mcp install --check after install");
    assert!(stdout(&up_to_date_check).contains("MCP config up to date:"));
}

#[cfg(feature = "identity")]
#[test]
fn mcp_install_json_reports_dry_run_and_check_state() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex",
    );
    let config_path = temp.file(".codex/config.toml");

    let dry_run_json = run_dent8(
        &[
            "--output",
            "json",
            "mcp",
            "install",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--command",
            "/usr/local/bin/dent8",
            "--dry-run",
        ],
        &[],
    );
    assert_success(&dry_run_json, "mcp install --dry-run --output json");
    assert_mcp_install_dry_run_json(&stdout_json(&dry_run_json), &config_path);
    assert!(
        !config_path.exists(),
        "JSON dry-run should not create the MCP config file"
    );

    let stale_check_json = run_dent8(
        &[
            "--output", "json", "mcp", "install", "--agent", "codex", "--dir", &dir, "--check",
        ],
        &[],
    );
    assert_eq!(stale_check_json.status.code(), Some(1));
    assert!(
        stderr(&stale_check_json).is_empty(),
        "{}",
        stderr(&stale_check_json)
    );
    assert_mcp_install_needs_update_json(&stdout_json(&stale_check_json));
    assert!(
        !config_path.exists(),
        "JSON check should not create the MCP config file"
    );

    assert_success(
        &run_dent8(&["mcp", "install", "--agent", "codex", "--dir", &dir], &[]),
        "mcp install --agent codex",
    );

    let up_to_date_json = run_dent8(
        &[
            "--output", "json", "mcp", "install", "--agent", "codex", "--dir", &dir, "--check",
        ],
        &[],
    );
    assert_success(&up_to_date_json, "mcp install --check --output json");
    let up_to_date_json = stdout_json(&up_to_date_json);
    assert_mcp_install_up_to_date_json(&up_to_date_json);
}

#[cfg(feature = "identity")]
fn assert_mcp_install_dry_run_json(output: &Value, config_path: &Path) {
    assert_eq!(output["status"], "ok");
    assert_eq!(output["tool"], "mcp install");
    assert_eq!(output["agent"], "codex");
    assert_eq!(output["mode"], "dry-run");
    assert_eq!(output["requested_command"], "/usr/local/bin/dent8");
    assert_eq!(output["command_written"], "/usr/local/bin/dent8");
    assert_eq!(
        output["config"]["path"],
        config_path.to_string_lossy().to_string()
    );
    assert_eq!(output["config"]["action"], "created");
    assert_eq!(output["config"]["changed"], true);
    assert_eq!(output["config"]["written"], false);
    assert!(
        output["config"]["contents"]
            .as_str()
            .expect("rendered config")
            .contains("command = \"/usr/local/bin/dent8\"")
    );
    assert!(
        output["local_binary"].is_null(),
        "non-local-bin install should not report local binary metadata"
    );
}

#[cfg(feature = "identity")]
fn assert_mcp_install_needs_update_json(output: &Value) {
    assert_eq!(output["status"], "needs_update");
    assert_eq!(output["mode"], "check");
    assert_eq!(output["exit_code"], 1);
    assert_eq!(output["config"]["action"], "created");
    assert_eq!(output["config"]["changed"], true);
    assert_eq!(output["config"]["written"], false);
}

#[cfg(feature = "identity")]
fn assert_mcp_install_up_to_date_json(output: &Value) {
    assert_eq!(output["status"], "ok");
    assert_eq!(output["config"]["action"], "unchanged");
    assert_eq!(output["config"]["changed"], false);
    assert_eq!(output["config"]["written"], false);
}

#[cfg(feature = "identity")]
#[test]
fn mcp_install_requires_explicit_config_for_custom_dent8_dir_name() {
    let temp = TempDir::new();
    let dir = temp.file("dent8-custom").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent codex --dir dent8-custom",
    );

    let inferred = run_dent8(&["mcp", "install", "--agent", "codex", "--dir", &dir], &[]);
    assert_eq!(inferred.status.code(), Some(1));
    assert!(stderr(&inferred).contains("cannot infer an MCP config path"));
    assert!(stderr(&inferred).contains("--config"));

    let config_path = temp.file(".codex/config.toml");
    let config = config_path.to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "mcp", "install", "--agent", "codex", "--dir", &dir, "--config", &config,
            ],
            &[],
        ),
        "mcp install --config with custom dent8 dir",
    );
    assert!(config_path.exists());
}

#[cfg(feature = "identity")]
#[test]
fn init_install_mcp_reports_partial_success_when_config_patch_fails() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let config_path = temp.file(".codex/config.toml");
    fs::create_dir_all(config_path.parent().expect("codex config parent"))
        .expect("create codex config dir");
    fs::write(&config_path, "not = [valid\n").expect("seed invalid codex config");

    let init = run_dent8(
        &[
            "init",
            "--dir",
            &dir,
            "--agent",
            "codex",
            "--issuer-key",
            &issuer_key,
            "--install-mcp",
        ],
        &[],
    );
    assert_eq!(init.status.code(), Some(1));
    let stdout = stdout(&init);
    assert!(stdout.contains("initialized dent8 in"));
    assert!(stdout.contains("MCP install failed:"));
    assert!(stdout.contains("cannot parse TOML MCP config"));
    assert!(stdout.contains("Run: dent8 mcp install --agent codex"));
    assert!(
        temp.file(".dent8/env").exists(),
        "init should still complete"
    );
    assert!(temp.file(".dent8/identity-codex.env").exists());
    assert_eq!(
        fs::read_to_string(&config_path).expect("codex config after failed patch"),
        "not = [valid\n",
        "failed MCP install should not rewrite invalid config"
    );
}

#[cfg(feature = "identity")]
#[test]
fn mcp_install_hecate_requires_explicit_config_path() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "hecate",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent hecate",
    );

    let installed = run_dent8(&["mcp", "install", "--agent", "hecate", "--dir", &dir], &[]);
    assert_eq!(installed.status.code(), Some(1));
    assert!(stderr(&installed).contains("needs --config"));
}

#[cfg(feature = "identity")]
#[test]
fn init_agent_profiles_match_documented_source_and_slug_paths() {
    let profiles = [
        (
            "codex",
            "source:codex",
            "source_codex",
            "codex-memory.jsonl",
        ),
        (
            "claude-code",
            "source:claude-code",
            "source_claude-code",
            "claude-memory.jsonl",
        ),
        (
            "cursor",
            "source:cursor",
            "source_cursor",
            "cursor-memory.jsonl",
        ),
        (
            "grok-build",
            "source:grok-build",
            "source_grok-build",
            "grok-build-memory.jsonl",
        ),
        (
            "gemini",
            "source:gemini",
            "source_gemini",
            "gemini-memory.jsonl",
        ),
        (
            "cascade",
            "source:cascade",
            "source_cascade",
            "cascade-memory.jsonl",
        ),
        (
            "hecate",
            "source:hecate",
            "source_hecate",
            "hecate-memory.jsonl",
        ),
    ];

    for (agent, source, slug, log_name) in profiles {
        let temp = TempDir::new();
        let dir = temp.file(".dent8").to_string_lossy().into_owned();
        let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
        let init = run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                agent,
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        );
        assert_success(&init, &format!("init --agent {agent}"));
        let authority = fs::read_to_string(temp.file(".dent8/authority.json"))
            .expect("authority registry from agent init");
        assert!(
            authority.contains(source),
            "{agent} should grant {source}, got {authority}"
        );
        assert!(
            temp.file(&format!(".dent8/grants/{slug}.grant.json"))
                .exists(),
            "{agent} should write documented grant slug {slug}"
        );
        assert!(
            temp.file(&format!(".dent8/identities/{slug}.key")).exists(),
            "{agent} should write documented source key slug {slug}"
        );
        let env = fs::read_to_string(temp.file(".dent8/env"))
            .expect("generated profile env should be readable");
        assert!(
            env.contains(log_name),
            "{agent} env should use documented log name {log_name}, got {env}"
        );
        assert!(
            temp.file(&format!(".dent8/{log_name}")).exists(),
            "{agent} should initialize documented file log {log_name}"
        );
    }
}

#[cfg(feature = "identity")]
#[test]
fn init_identity_preflights_existing_identity_before_writing_authority() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8");
    fs::create_dir_all(&dir).expect("create dent8 dir");
    fs::write(dir.join("identity-codex.env"), "already here\n").expect("seed identity env");
    let dir_arg = dir.to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    let init = run_dent8(
        &[
            "init",
            "--dir",
            &dir_arg,
            "--source",
            "source:codex",
            "--identity",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_eq!(init.status.code(), Some(1));
    assert!(stderr(&init).contains("refusing to overwrite identity bootstrap output"));
    assert!(
        !temp.file(".dent8/authority.json").exists(),
        "identity preflight failure should not create authority registry"
    );
    assert!(
        !temp.file(".dent8/memory.jsonl").exists(),
        "identity preflight failure should not create a log"
    );
    assert!(
        !temp.file(".dent8/env").exists(),
        "identity preflight failure should not create env"
    );
}

#[cfg(not(feature = "identity"))]
#[test]
fn init_identity_explains_feature_gate_without_identity_build() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let init = run_dent8(&["init", "--dir", &dir, "--identity"], &[]);
    assert_eq!(init.status.code(), Some(1));
    assert!(stderr(&init).contains("--features identity"));
    assert!(
        !temp.file(".dent8").exists(),
        "feature-gated identity init should fail before creating config state"
    );
}

#[cfg(not(feature = "identity"))]
#[test]
fn identity_command_explains_feature_gate_without_identity_build() {
    let output = run_dent8(&["identity", "trust-list"], &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("--features identity"));
}

#[cfg(not(feature = "identity"))]
#[test]
fn doctor_fails_when_identity_is_configured_without_identity_build() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let trust = temp.file("trust.json").to_string_lossy().into_owned();
    let output = run_dent8(&["doctor"], &[("DENT8_LOG", &log), ("DENT8_TRUST", &trust)]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stdout(&output).contains("without `--features identity`"));
}

#[cfg(feature = "identity")]
#[test]
fn identity_bootstrap_rejects_project_local_issuer_key() {
    let temp = TempDir::new();
    let rejected_dir = temp.file("rejected-dent8");
    let rejected_dir_str = rejected_dir.to_string_lossy().into_owned();
    let rejected_issuer = rejected_dir
        .join("issuer.key")
        .to_string_lossy()
        .into_owned();
    let rejected = run_dent8(
        &[
            "identity",
            "bootstrap",
            "--dir",
            &rejected_dir_str,
            "--source",
            "source:codex",
            "--issuer-key",
            &rejected_issuer,
        ],
        &[],
    );
    assert_eq!(rejected.status.code(), Some(1));
    assert!(stderr(&rejected).contains("inside"));
    assert!(
        !rejected_dir.exists(),
        "failed bootstrap should clean directories it created"
    );
}

#[cfg(feature = "identity")]
#[test]
fn identity_bootstrap_writes_bundle_that_doctor_and_writes_use() {
    let temp = TempDir::new();
    let dir = temp.file("dent8");
    let dir_str = dir.to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key");
    let issuer_key_str = issuer_key.to_string_lossy().into_owned();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();

    let bootstrapped = run_dent8(
        &[
            "identity",
            "bootstrap",
            "--dir",
            &dir_str,
            "--source",
            "source:codex",
            "--issuer-key",
            &issuer_key_str,
        ],
        &[],
    );
    assert_success(&bootstrapped, "identity bootstrap");
    assert!(stdout(&bootstrapped).contains("bootstrapped signed identity"));

    let trust = dir.join("trust.json").to_string_lossy().into_owned();
    let active_grants = dir.join("active-grants.json");
    let grant = dir
        .join("grants/source_codex.grant.json")
        .to_string_lossy()
        .into_owned();
    let key = dir
        .join("identities/source_codex.key")
        .to_string_lossy()
        .into_owned();
    let env = dir.join("identity-codex.env");
    assert!(env.exists(), "bootstrap should write identity-codex.env");
    assert!(
        issuer_key.exists(),
        "bootstrap should write the issuer key outside the bundle"
    );
    assert!(
        !dir.join("issuer.key").exists(),
        "bootstrap must not write issuer private keys into the agent bundle"
    );
    assert!(
        std::path::Path::new(&grant).exists(),
        "bootstrap should write grant"
    );
    assert!(
        active_grants.exists(),
        "bootstrap should write active grant registry"
    );
    assert!(
        std::path::Path::new(&key).exists(),
        "bootstrap should write source key"
    );

    assert_success(
        &run_dent8(
            &["identity", "grant-verify", &grant],
            &[("DENT8_TRUST", &trust)],
        ),
        "bootstrap grant verify",
    );

    let identity_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", grant.as_str()),
        ("DENT8_IDENTITY_KEY", key.as_str()),
        ("DENT8_REQUIRE_IDENTITY", "1"),
    ];
    let doctor = run_dent8(
        &["doctor", "--source", "source:codex", "--write-check"],
        &identity_env,
    );
    assert_success(&doctor, "doctor with bootstrapped identity");
    assert!(stdout(&doctor).contains("identity key:"));
    assert!(stdout(&doctor).contains("write-check: accepted trusted"));

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
        "signed write from bootstrapped identity",
    );
}

#[cfg(feature = "identity")]
#[test]
#[allow(clippy::too_many_lines)]
fn identity_lifecycle_commands_emit_machine_readable_json() {
    let temp = TempDir::new();
    let dir = temp.file("dent8");
    let dir_str = dir.to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    let bootstrapped = run_dent8(
        &[
            "--output",
            "json",
            "identity",
            "bootstrap",
            "--dir",
            &dir_str,
            "--source",
            "source:codex",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&bootstrapped, "identity bootstrap --output json");
    assert!(
        stderr(&bootstrapped).is_empty(),
        "{}",
        stderr(&bootstrapped)
    );
    let bootstrapped = stdout_json(&bootstrapped);
    let canonical_dir = fs::canonicalize(&dir)
        .expect("identity bundle dir")
        .to_string_lossy()
        .to_string();
    assert_eq!(bootstrapped["status"], "ok");
    assert_eq!(bootstrapped["tool"], "identity bootstrap");
    assert_eq!(bootstrapped["dir"], canonical_dir);
    assert_eq!(bootstrapped["source"], "source:codex");
    assert_eq!(bootstrapped["issuer"], "owner");
    assert_eq!(bootstrapped["max_authority"], "High");
    assert_eq!(
        bootstrapped["env_file"],
        fs::canonicalize(dir.join("identity-codex.env"))
            .expect("identity env")
            .to_string_lossy()
            .to_string()
    );
    assert!(dir.join("identity-codex.env").exists());

    fs::remove_file(dir.join("active-grants.json")).expect("remove active grants");
    let repaired = run_dent8(
        &[
            "--output",
            "json",
            "identity",
            "repair-env",
            "--dir",
            &dir_str,
            "--source",
            "source:codex",
        ],
        &[],
    );
    assert_success(&repaired, "identity repair-env --output json");
    assert!(stderr(&repaired).is_empty(), "{}", stderr(&repaired));
    let repaired = stdout_json(&repaired);
    assert_eq!(repaired["status"], "ok");
    assert_eq!(repaired["tool"], "identity repair-env");
    assert_eq!(repaired["source"], "source:codex");
    assert_eq!(repaired["repaired_active_grant"], true);
    assert!(dir.join("active-grants.json").exists());

    let rotated = run_dent8(
        &[
            "--output",
            "json",
            "identity",
            "rotate-source",
            "--dir",
            &dir_str,
            "--source",
            "source:codex",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&rotated, "identity rotate-source --output json");
    assert!(stderr(&rotated).is_empty(), "{}", stderr(&rotated));
    let rotated = stdout_json(&rotated);
    assert_eq!(rotated["status"], "ok");
    assert_eq!(rotated["tool"], "identity rotate-source");
    assert_eq!(rotated["source"], "source:codex");
    assert_eq!(rotated["old_source_key_backup_removed"], true);
    let old_grant_backup = rotated["old_grant_backup"]
        .as_str()
        .expect("old grant backup");
    assert!(
        Path::new(old_grant_backup).exists(),
        "rotation should keep the old grant backup"
    );
    assert_eq!(
        rotated["env_file"],
        fs::canonicalize(dir.join("identity-codex.env"))
            .expect("rotated identity env")
            .to_string_lossy()
            .to_string()
    );
}

#[cfg(feature = "identity")]
#[test]
#[allow(clippy::too_many_lines)]
fn identity_artifact_commands_emit_machine_readable_json() {
    let temp = TempDir::new();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let source_key = temp.file("codex.key").to_string_lossy().into_owned();
    let trust = temp.file("trust.json").to_string_lossy().into_owned();
    let grant = temp.file("codex.grant.json").to_string_lossy().into_owned();

    let issuer_keygen = run_dent8(
        &[
            "--output",
            "json",
            "identity",
            "issuer-keygen",
            "--out",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&issuer_keygen, "identity issuer-keygen --output json");
    assert!(
        stderr(&issuer_keygen).is_empty(),
        "{}",
        stderr(&issuer_keygen)
    );
    let issuer_keygen = stdout_json(&issuer_keygen);
    assert_eq!(issuer_keygen["status"], "ok");
    assert_eq!(issuer_keygen["tool"], "identity issuer-keygen");
    assert_eq!(issuer_keygen["private_key_path"], issuer_key);
    assert!(temp.file("owner.key.pub").exists());

    let agent = run_dent8(
        &[
            "--output",
            "json",
            "identity",
            "agent-keygen",
            "source:codex",
            "--out",
            &source_key,
        ],
        &[],
    );
    assert_success(&agent, "identity agent-keygen --output json");
    assert!(stderr(&agent).is_empty(), "{}", stderr(&agent));
    let agent = stdout_json(&agent);
    assert_eq!(agent["status"], "ok");
    assert_eq!(agent["tool"], "identity agent-keygen");
    assert_eq!(agent["source"], "source:codex");
    assert!(temp.file("codex.key.pub").exists());

    let issuer_pub = temp.file("owner.key.pub").to_string_lossy().into_owned();
    let trusted = run_dent8(
        &[
            "--output",
            "json",
            "identity",
            "trust-add",
            "owner",
            &issuer_pub,
        ],
        &[("DENT8_TRUST", &trust)],
    );
    assert_success(&trusted, "identity trust-add --output json");
    assert!(stderr(&trusted).is_empty(), "{}", stderr(&trusted));
    let trusted = stdout_json(&trusted);
    assert_eq!(trusted["status"], "ok");
    assert_eq!(trusted["tool"], "identity trust-add");
    assert_eq!(trusted["issuer"], "owner");
    assert_eq!(trusted["path"], trust);

    let listed = run_dent8(
        &["--output", "json", "identity", "trust-list"],
        &[("DENT8_TRUST", &trust)],
    );
    assert_success(&listed, "identity trust-list --output json");
    assert!(stderr(&listed).is_empty(), "{}", stderr(&listed));
    let listed = stdout_json(&listed);
    assert_eq!(listed["status"], "ok");
    assert_eq!(listed["tool"], "identity trust-list");
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["issuers"][0]["issuer"], "owner");

    let source_pub = temp.file("codex.key.pub").to_string_lossy().into_owned();
    let grant_issued = run_dent8(
        &[
            "--output",
            "json",
            "identity",
            "grant-issue",
            "source:codex",
            "--public-key",
            &source_pub,
            "--max",
            "high",
            "--issuer",
            "owner",
            "--issuer-key",
            &issuer_key,
            "--out",
            &grant,
        ],
        &[],
    );
    assert_success(&grant_issued, "identity grant-issue --output json");
    assert!(
        stderr(&grant_issued).is_empty(),
        "{}",
        stderr(&grant_issued)
    );
    let grant_issued = stdout_json(&grant_issued);
    assert_eq!(grant_issued["status"], "ok");
    assert_eq!(grant_issued["tool"], "identity grant-issue");
    assert_eq!(grant_issued["source"], "source:codex");
    assert_eq!(grant_issued["issuer"], "owner");
    assert_eq!(grant_issued["max_authority"], "High");
    assert!(temp.file("codex.grant.json").exists());

    let verified = run_dent8(
        &["--output", "json", "identity", "grant-verify", &grant],
        &[("DENT8_TRUST", &trust)],
    );
    assert_success(&verified, "identity grant-verify --output json");
    assert!(stderr(&verified).is_empty(), "{}", stderr(&verified));
    let verified = stdout_json(&verified);
    assert_eq!(verified["status"], "ok");
    assert_eq!(verified["tool"], "identity grant-verify");
    assert_eq!(verified["path"], grant);
    assert_eq!(verified["source"], "source:codex");
    assert_eq!(verified["max_authority"], "High");
}

#[cfg(feature = "identity")]
#[test]
fn identity_env_filename_sanitizes_source_suffix() {
    let temp = TempDir::new();
    let dir = temp.file("dent8");
    let dir_str = dir.to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    let bootstrapped = run_dent8(
        &[
            "identity",
            "bootstrap",
            "--dir",
            &dir_str,
            "--source",
            "source:team/codex",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&bootstrapped, "identity bootstrap with source slash");
    assert!(
        dir.join("identity-team_codex.env").exists(),
        "source suffix should be flattened into one env filename"
    );
    assert!(
        !dir.join("identity-team").exists(),
        "source suffix must not create nested env directories"
    );
}

#[cfg(feature = "identity")]
#[test]
fn identity_status_reports_bundle_and_expiry() {
    let temp = TempDir::new();
    let dir = temp.file("dent8");
    let dir_str = dir.to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &dir_str,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
                "--expires-at-ms",
                "4102444800000",
            ],
            &[],
        ),
        "identity bootstrap with expiry",
    );

    let status = run_dent8(
        &[
            "identity",
            "status",
            "--dir",
            &dir_str,
            "--source",
            "source:codex",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&status, "identity status");
    let status_stdout = stdout(&status);
    assert!(status_stdout.contains("identity status"), "{status_stdout}");
    assert!(status_stdout.contains("bundle:"), "{status_stdout}");
    assert!(status_stdout.contains("trust:"), "{status_stdout}");
    assert!(status_stdout.contains("grant:"), "{status_stdout}");
    assert!(
        status_stdout.contains("source=source:codex"),
        "{status_stdout}"
    );
    assert!(status_stdout.contains("max=High"), "{status_stdout}");
    assert!(
        status_stdout.contains("grant expiry: expires at 4102444800000"),
        "{status_stdout}"
    );
    assert!(status_stdout.contains("source key:"), "{status_stdout}");
    assert!(status_stdout.contains("issuer key:"), "{status_stdout}");

    let inferred_status = run_dent8(
        &[
            "identity",
            "status",
            "--dir",
            &dir_str,
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&inferred_status, "identity status infers active env");
    assert!(stdout(&inferred_status).contains("source=source:codex"));

    let status_json = run_dent8(
        &[
            "--output",
            "json",
            "identity",
            "status",
            "--dir",
            &dir_str,
            "--source",
            "source:codex",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&status_json, "identity status --output json");
    let status_json = stdout_json(&status_json);
    assert_eq!(status_json["status"], "ok");
    assert_eq!(status_json["tool"], "identity status");
    assert_eq!(status_json["ok"], true);
    assert_eq!(status_json["dir"], dir_str);
    assert_eq!(status_json["source"], "source:codex");
    assert_eq!(status_json["issuer_key"], issuer_key);
    assert!(
        status_json["checks"]
            .as_array()
            .expect("identity checks")
            .iter()
            .any(|check| check["message"]
                .as_str()
                .is_some_and(|message| message.contains("grant:")
                    && message.contains("source=source:codex")
                    && message.contains("max=High"))),
        "{status_json}"
    );
}

#[cfg(feature = "identity")]
#[test]
#[allow(clippy::too_many_lines)]
fn identity_rotate_source_rekeys_active_paths_and_rejects_old_key() {
    let temp = TempDir::new();
    let dir = temp.file("dent8");
    let dir_str = dir.to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &dir_str,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "identity bootstrap before rotation",
    );

    let trust = dir.join("trust.json").to_string_lossy().into_owned();
    let grant = dir
        .join("grants/source_codex.grant.json")
        .to_string_lossy()
        .into_owned();
    let key_path = dir.join("identities/source_codex.key");
    let key = key_path.to_string_lossy().into_owned();
    let old_key = read_file(&key_path);
    let copied_old_key = temp.file("copied-old-source.key");
    fs::copy(&key_path, &copied_old_key).expect("copy old key before rotation");
    make_owner_only(&copied_old_key);

    let rotated = run_dent8(
        &[
            "identity",
            "rotate-source",
            "--dir",
            &dir_str,
            "--source",
            "source:codex",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_success(&rotated, "identity rotate-source");
    let rotate_stdout = stdout(&rotated);
    assert!(
        rotate_stdout.contains("rotated source identity for source:codex"),
        "{rotate_stdout}"
    );
    assert_ne!(
        read_file(&key_path),
        old_key,
        "rotation should replace the active source private key"
    );

    assert_no_backup(&dir.join("identities"), "source_codex.key.old.");
    let old_grant_backup = find_backup(&dir.join("grants"), "source_codex.grant.json.old.");
    assert!(
        dir.join("identity-codex.env").exists(),
        "rotation should rewrite identity-codex.env at the stable path"
    );
    assert!(
        fs::read_to_string(dir.join("identity-codex.env"))
            .expect("rotated identity env")
            .contains("DENT8_IDENTITY_KEY="),
        "rotated env should still point at the active key path"
    );

    let active_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", grant.as_str()),
        ("DENT8_IDENTITY_KEY", key.as_str()),
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
            &active_env,
        ),
        "signed write with rotated key",
    );

    let copied_old_key = copied_old_key.to_string_lossy().into_owned();
    let old_key_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", grant.as_str()),
        ("DENT8_IDENTITY_KEY", copied_old_key.as_str()),
        ("DENT8_REQUIRE_IDENTITY", "1"),
    ];
    let rejected = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_color",
            "blue",
            "--authority",
            "high",
            "--source",
            "source:codex",
        ],
        &old_key_env,
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert!(stderr(&rejected).contains("identity key does not match"));

    let old_grant_backup = old_grant_backup.to_string_lossy().into_owned();
    let old_pair_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", old_grant_backup.as_str()),
        ("DENT8_IDENTITY_KEY", copied_old_key.as_str()),
        ("DENT8_REQUIRE_IDENTITY", "1"),
    ];
    let stale_pair = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_city",
            "paris",
            "--authority",
            "high",
            "--source",
            "source:codex",
        ],
        &old_pair_env,
    );
    assert_eq!(stale_pair.status.code(), Some(2));
    assert!(stderr(&stale_pair).contains("not active"));

    assert_success(
        &run_dent8(
            &[
                "identity",
                "status",
                "--dir",
                &dir_str,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "identity status after rotation",
    );
}

#[cfg(feature = "identity")]
#[test]
#[allow(clippy::too_many_lines)]
fn identity_rotate_source_can_replace_an_expired_grant() {
    let temp = TempDir::new();
    let dir = temp.file("dent8");
    let dir_str = dir.to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &dir_str,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
                "--expires-at-ms",
                "1",
            ],
            &[],
        ),
        "identity bootstrap expired grant",
    );

    let trust = dir.join("trust.json").to_string_lossy().into_owned();
    let grant = dir
        .join("grants/source_codex.grant.json")
        .to_string_lossy()
        .into_owned();
    let key = dir
        .join("identities/source_codex.key")
        .to_string_lossy()
        .into_owned();
    let identity_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", grant.as_str()),
        ("DENT8_IDENTITY_KEY", key.as_str()),
        ("DENT8_REQUIRE_IDENTITY", "1"),
    ];

    let expired_write = run_dent8(
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
    );
    assert_eq!(expired_write.status.code(), Some(2));
    assert!(stderr(&expired_write).contains("expired at 1"));

    let expired_status = run_dent8(
        &[
            "identity",
            "status",
            "--dir",
            &dir_str,
            "--source",
            "source:codex",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_eq!(expired_status.status.code(), Some(1));
    assert!(stdout(&expired_status).contains("grant expiry: expired at 1"));

    let expired_json = run_dent8(
        &[
            "--output",
            "json",
            "identity",
            "status",
            "--dir",
            &dir_str,
            "--source",
            "source:codex",
            "--issuer-key",
            &issuer_key,
        ],
        &[],
    );
    assert_eq!(expired_json.status.code(), Some(1));
    assert!(
        stderr(&expired_json).is_empty(),
        "{}",
        stderr(&expired_json)
    );
    let expired_json = stdout_json(&expired_json);
    assert_eq!(expired_json["status"], "failed");
    assert_eq!(expired_json["tool"], "identity status");
    assert_eq!(expired_json["ok"], false);
    assert!(
        expired_json["checks"]
            .as_array()
            .expect("identity checks")
            .iter()
            .any(|check| check["ok"] == false
                && check["message"]
                    .as_str()
                    .is_some_and(|message| message.contains("expired at 1"))),
        "{expired_json}"
    );

    assert_success(
        &run_dent8(
            &[
                "identity",
                "rotate-source",
                "--dir",
                &dir_str,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
                "--expires-at-ms",
                "4102444800000",
            ],
            &[],
        ),
        "identity rotate-source expired grant",
    );
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
        "signed write after expired grant rotation",
    );
}

#[cfg(feature = "identity")]
#[test]
#[allow(clippy::similar_names)]
fn identity_bootstrap_can_share_one_explicit_issuer_across_projects() {
    let temp = TempDir::new();
    let project_a = temp.file("project-a");
    let project_b = temp.file("project-b");
    fs::create_dir_all(&project_a).expect("create project a");
    fs::create_dir_all(&project_b).expect("create project b");
    let issuer_key = temp
        .file("home/.config/dent8/projects/shared/issuer.key")
        .to_string_lossy()
        .into_owned();

    assert_success(
        &run_dent8_in(
            &project_a,
            &[
                "identity",
                "bootstrap",
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "project a identity bootstrap",
    );
    assert_success(
        &run_dent8_in(
            &project_b,
            &[
                "identity",
                "bootstrap",
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "project b identity bootstrap",
    );

    let bundle_a = project_a.join(".dent8");
    let bundle_b = project_b.join(".dent8");
    let trust_a = bundle_a.join("trust.json");
    let trust_b = bundle_b.join("trust.json");
    let grant_a = bundle_a.join("grants/source_codex.grant.json");
    let grant_b = bundle_b.join("grants/source_codex.grant.json");
    let source_key_a = bundle_a.join("identities/source_codex.key");
    let source_key_b = bundle_b.join("identities/source_codex.key");

    assert!(std::path::Path::new(&issuer_key).exists());
    assert!(std::path::Path::new(&format!("{issuer_key}.pub")).exists());
    assert!(
        !bundle_a.join("issuer.key").exists(),
        "project a must not contain the issuer private key"
    );
    assert!(
        !bundle_b.join("issuer.key").exists(),
        "project b must not contain the issuer private key"
    );
    assert_eq!(
        read_file(&trust_a),
        read_file(&trust_b),
        "shared issuer key should produce matching trust registries"
    );
    assert_ne!(
        read_file(&source_key_a),
        read_file(&source_key_b),
        "each project should still get its own source private key"
    );

    let trust_a_str = trust_a.to_string_lossy().into_owned();
    let grant_a_str = grant_a.to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &["identity", "grant-verify", &grant_a_str],
            &[("DENT8_TRUST", &trust_a_str)],
        ),
        "project a grant verify",
    );

    let trust_b_str = trust_b.to_string_lossy().into_owned();
    let grant_b_str = grant_b.to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &["identity", "grant-verify", &grant_b_str],
            &[("DENT8_TRUST", &trust_b_str)],
        ),
        "project b grant verify",
    );
}

#[cfg(feature = "identity")]
#[test]
#[allow(clippy::similar_names, clippy::too_many_lines)]
fn identity_bootstrap_project_specific_issuer_keys_isolate_trust_roots() {
    let temp = TempDir::new();
    let project_a = temp.file("project-a");
    let project_b = temp.file("project-b");
    fs::create_dir_all(&project_a).expect("create project a");
    fs::create_dir_all(&project_b).expect("create project b");
    let issuer_key_a = temp
        .file("home/.config/dent8/projects/project-a/issuer.key")
        .to_string_lossy()
        .into_owned();
    let issuer_key_b = temp
        .file("home/.config/dent8/projects/project-b/issuer.key")
        .to_string_lossy()
        .into_owned();

    assert_success(
        &run_dent8_in(
            &project_a,
            &[
                "identity",
                "bootstrap",
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key_a,
            ],
            &[],
        ),
        "project a identity bootstrap",
    );
    assert_success(
        &run_dent8_in(
            &project_b,
            &[
                "identity",
                "bootstrap",
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key_b,
            ],
            &[],
        ),
        "project b identity bootstrap",
    );

    let bundle_a = project_a.join(".dent8");
    let bundle_b = project_b.join(".dent8");
    let trust_a = bundle_a.join("trust.json");
    let trust_b = bundle_b.join("trust.json");
    let grant_a = bundle_a.join("grants/source_codex.grant.json");
    let grant_b = bundle_b.join("grants/source_codex.grant.json");
    let source_key_a = bundle_a.join("identities/source_codex.key");
    let source_key_b = bundle_b.join("identities/source_codex.key");

    assert_ne!(
        read_file(std::path::Path::new(&issuer_key_a)),
        read_file(std::path::Path::new(&issuer_key_b)),
        "project-specific issuer private keys should differ"
    );
    assert_ne!(
        read_file(std::path::Path::new(&format!("{issuer_key_a}.pub"))),
        read_file(std::path::Path::new(&format!("{issuer_key_b}.pub"))),
        "project-specific issuer public keys should differ"
    );
    assert_ne!(
        read_file(&trust_a),
        read_file(&trust_b),
        "project-specific issuer keys should produce isolated trust roots"
    );
    assert_ne!(
        read_file(&source_key_a),
        read_file(&source_key_b),
        "each project should get its own source private key"
    );

    let trust_a_str = trust_a.to_string_lossy().into_owned();
    let trust_b_str = trust_b.to_string_lossy().into_owned();
    let grant_a_str = grant_a.to_string_lossy().into_owned();
    let grant_b_str = grant_b.to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &["identity", "grant-verify", &grant_a_str],
            &[("DENT8_TRUST", &trust_a_str)],
        ),
        "project a grant verify",
    );
    assert_success(
        &run_dent8(
            &["identity", "grant-verify", &grant_b_str],
            &[("DENT8_TRUST", &trust_b_str)],
        ),
        "project b grant verify",
    );

    let project_b_grant_with_project_a_trust = run_dent8(
        &["identity", "grant-verify", &grant_b_str],
        &[("DENT8_TRUST", &trust_a_str)],
    );
    assert_eq!(project_b_grant_with_project_a_trust.status.code(), Some(1));
    assert!(
        stderr(&project_b_grant_with_project_a_trust).contains("grant signature does not verify")
    );

    let project_a_grant_with_project_b_trust = run_dent8(
        &["identity", "grant-verify", &grant_a_str],
        &[("DENT8_TRUST", &trust_b_str)],
    );
    assert_eq!(project_a_grant_with_project_b_trust.status.code(), Some(1));
    assert!(
        stderr(&project_a_grant_with_project_b_trust).contains("grant signature does not verify")
    );
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
    run_dent8_inner(None, args, envs)
}

#[cfg(feature = "identity")]
fn run_dent8_in(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    run_dent8_inner(Some(cwd), args, envs)
}

fn run_dent8_inner(cwd: Option<&Path>, args: &[&str], envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(dent8_bin());
    command
        .args(args)
        .env_remove("DENT8_STORE_URL")
        .env_remove("DENT8_LOG")
        .env_remove("DENT8_AUTHORITY")
        .env_remove("DENT8_REQUIRE_AUTHORITY");
    command
        .env_remove("DENT8_TRUST")
        .env_remove("DENT8_ACTIVE_GRANTS")
        .env_remove("DENT8_GRANT")
        .env_remove("DENT8_IDENTITY_KEY")
        .env_remove("DENT8_ISSUER_KEY")
        .env_remove("DENT8_REQUIRE_IDENTITY")
        .env_remove("DENT8_WITNESS_KEY")
        .env_remove("DENT8_WITNESS_PUBKEY")
        .env_remove("DENT8_WITNESS_LOG");
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
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

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            stdout(output),
            stderr(output)
        )
    })
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stderr_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stderr).unwrap_or_else(|error| {
        panic!(
            "stderr is not JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            stdout(output),
            stderr(output)
        )
    })
}

#[cfg(feature = "witness")]
fn line_count(path: &str) -> usize {
    fs::read_to_string(path)
        .expect("read file")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

#[cfg(feature = "identity")]
fn assert_installed_agent_doctor_ok(output: &Output, agent: &str, source: &str, mcp_command: &str) {
    assert_success(output, &format!("doctor --agent {agent} --write-check"));
    let stdout = stdout(output);
    assert!(
        stdout.contains(&format!("agent: {agent} ({source})")),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("command={mcp_command}")),
        "{stdout}"
    );
    assert!(stdout.contains("agent mcp config: up to date"), "{stdout}");
    assert!(
        stdout.contains(&format!(
            "identity source: grant source matches doctor source {source}"
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains("mcp smoke: initialize + tools/list OK"),
        "{stdout}"
    );
    assert!(
        stdout.contains("mcp write-check: accepted trusted diagnostic:doctor-mcp-"),
        "{stdout}"
    );
}

#[cfg(feature = "identity")]
fn read_file(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[cfg(feature = "identity")]
fn find_backup(dir: &Path, prefix: &str) -> PathBuf {
    fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        })
        .unwrap_or_else(|| panic!("missing backup with prefix {prefix} in {}", dir.display()))
}

#[cfg(feature = "identity")]
fn assert_no_backup(dir: &Path, prefix: &str) {
    let found = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("read {}: {error}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix))
        });
    assert!(
        found.is_none(),
        "unexpected backup with prefix {prefix} in {}: {:?}",
        dir.display(),
        found
    );
}

#[cfg(feature = "identity")]
fn make_owner_only(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|error| panic!("chmod 0600 {}: {error}", path.display()));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(feature = "identity")]
fn seed_local_mcp_target(dir: &str) {
    let target = Path::new(dir).join("target-sqlite/debug/dent8");
    fs::create_dir_all(target.parent().expect("local target parent"))
        .unwrap_or_else(|error| panic!("create {}: {error}", target.display()));
    fs::copy(dent8_bin(), &target)
        .unwrap_or_else(|error| panic!("copy local target {}: {error}", target.display()));
    make_executable(&target);
}

#[cfg(feature = "identity")]
fn make_executable(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .unwrap_or_else(|error| panic!("chmod 0755 {}: {error}", path.display()));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

#[cfg(all(feature = "identity", unix))]
fn toml_basic_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
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
