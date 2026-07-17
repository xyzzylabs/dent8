use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU32, Ordering},
};

use serde_json::Value;

#[cfg(any(feature = "sqlite", feature = "postgres"))]
use std::{
    collections::BTreeSet,
    sync::{Arc, Barrier},
};

#[test]
fn eval_accepts_a_reviewed_legitimate_trace_in_text_and_json() {
    let trace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../evals/traces/synthetic_revision.example.json");
    let trace = trace.to_string_lossy();

    let text = run_dent8(&["eval", "--trace", &trace], &[]);
    assert_success(&text, "eval reviewed trace");
    assert!(
        stdout(&text).contains("Reviewed legitimate-traffic traces")
            && stdout(&text).contains("trace:synthetic-revision-example")
            && stdout(&text).contains("false positives=0"),
        "{}",
        stdout(&text)
    );

    let json = run_dent8(&["eval", "--trace", &trace, "--output", "json"], &[]);
    assert_success(&json, "eval reviewed trace JSON");
    let payload: Value = serde_json::from_slice(&json.stdout).expect("eval JSON");
    assert_eq!(payload["status"], "ok");
    assert_eq!(payload["reviewed_legitimate_traffic"]["provided"], true);
    assert_eq!(payload["reviewed_legitimate_traffic"]["trace_count"], 1);
    assert_eq!(
        payload["reviewed_legitimate_traffic"]["captured_trace_count"],
        0
    );
    assert_eq!(
        payload["reviewed_legitimate_traffic"]["synthetic_trace_count"],
        1
    );
    assert_eq!(payload["reviewed_legitimate_traffic"]["false_positives"], 0);
    assert_eq!(
        payload["reviewed_legitimate_traffic"]["traces"][0]["operations"][1]["admitted"],
        true
    );
}

#[test]
fn checked_in_captured_agent_traces_stay_clean() {
    let trace_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../evals/traces");
    let traces = [
        "claude-code-msrv.redacted.json",
        "cursor-roadmap.redacted.json",
        "grok-build-mcp.redacted.json",
    ];
    let mut args = vec!["eval".to_owned(), "--output".to_owned(), "json".to_owned()];
    for trace in traces {
        args.push("--trace".to_owned());
        args.push(trace_dir.join(trace).to_string_lossy().into_owned());
    }
    let args = args.iter().map(String::as_str).collect::<Vec<_>>();

    let output = run_dent8(&args, &[]);
    assert_success(&output, "eval checked-in captured traces");
    let payload: Value = serde_json::from_slice(&output.stdout).expect("eval JSON");
    let traffic = &payload["reviewed_legitimate_traffic"];
    assert_eq!(traffic["captured_trace_count"], 3);
    assert_eq!(traffic["captured_operation_count"], 3);
    assert_eq!(traffic["captured_false_positives"], 0);
    assert_eq!(traffic["synthetic_trace_count"], 0);
}

#[test]
fn eval_refuses_to_count_the_same_trace_twice() {
    let trace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../evals/traces/synthetic_revision.example.json");
    let trace = trace.to_string_lossy();

    let output = run_dent8(
        &["eval", "--trace", &trace, "--trace", &trace, "-o", "json"],
        &[],
    );
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let payload: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(payload["status"], "invalid");
    assert!(
        payload["message"]
            .as_str()
            .is_some_and(|message| message.contains("duplicate trace_id"))
    );
}

#[test]
fn eval_rejects_a_persisted_log_disguised_as_a_reviewed_trace() {
    let temp = TempDir::new();
    let trace = temp.file("not-a-trace.json");
    fs::write(&trace, r#"{"event_id":"event:0"}"#).expect("write invalid trace");
    let trace = trace.to_string_lossy();

    let output = run_dent8(&["eval", "--trace", &trace, "--output", "json"], &[]);
    assert_eq!(output.status.code(), Some(2), "{}", stdout(&output));
    let payload: Value = serde_json::from_slice(&output.stdout).expect("error JSON");
    assert_eq!(payload["status"], "invalid");
    assert_eq!(payload["code"], "invalid-argument");
    assert!(
        payload["message"]
            .as_str()
            .is_some_and(|message| message.contains("invalid legitimate-traffic trace"))
    );
}

#[test]
fn eval_capture_requires_review_and_preserves_rejected_attempts() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl");
    let capture = temp.file("session.capture.jsonl");
    let draft = temp.file("session.review.json");
    let trace = temp.file("session.trace.json");
    let log = log.to_string_lossy().into_owned();
    let capture_text = capture.to_string_lossy().into_owned();
    let envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_EVAL_CAPTURE", capture_text.as_str()),
        ("DENT8_EVAL_AGENT", "codex"),
        ("DENT8_EVAL_SESSION", "session:test"),
    ];

    let admitted = run_dent8(
        &[
            "assert",
            "branch:main",
            "status",
            "clean",
            "--authority",
            "low",
            "--source",
            "source:agent",
        ],
        &envs,
    );
    assert_success(&admitted, "captured admitted write");
    let rejected = run_dent8(
        &[
            "assert",
            "branch:main",
            "status",
            "dirty",
            "--authority",
            "low",
            "--source",
            "source:agent",
        ],
        &envs,
    );
    assert_eq!(rejected.status.code(), Some(1), "{}", stderr(&rejected));

    let capture_jsonl = fs::read_to_string(&capture).expect("capture journal");
    assert_private_file(&capture);
    let records = capture_jsonl.lines().collect::<Vec<_>>();
    assert_eq!(records.len(), 3, "header plus two attempts");
    assert!(records[1].contains(r#""decision":"admitted""#));
    assert!(records[2].contains(r#""decision":"rejected""#));
    assert!(records[2].contains(r#""code":"uniqueness-violation""#));

    let capture_arg = capture.to_string_lossy();
    let draft_arg = draft.to_string_lossy();
    let prepared = run_dent8(&["eval", "prepare", &capture_arg, "--out", &draft_arg], &[]);
    assert_success(&prepared, "prepare capture review");
    assert_private_file(&draft);

    let trace_arg = trace.to_string_lossy();
    let incomplete = run_dent8(&["eval", "finalize", &draft_arg, "--out", &trace_arg], &[]);
    assert_eq!(incomplete.status.code(), Some(2));
    assert!(stderr(&incomplete).contains("still requires review"));

    let mut review: Value =
        serde_json::from_str(&fs::read_to_string(&draft).expect("draft")).expect("draft JSON");
    assert_eq!(
        review["operations"][0]["baseline_events"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
    assert_eq!(
        review["operations"][1]["baseline_events"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    review["review"]["reviewer"] = Value::String("human:owner".to_string());
    review["review"]["basis"] = Value::String("normal branch-status updates".to_string());
    for operation in review["operations"]
        .as_array_mut()
        .expect("review operations")
    {
        operation["classification"] = Value::String("legitimate".to_string());
    }
    fs::write(
        &draft,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&review).expect("serialize review")
        ),
    )
    .expect("write reviewed draft");

    let finalized = run_dent8(&["eval", "finalize", &draft_arg, "--out", &trace_arg], &[]);
    assert_success(&finalized, "finalize reviewed trace");

    let evaluated = run_dent8(&["eval", "--trace", &trace_arg, "-o", "json"], &[]);
    assert_eq!(evaluated.status.code(), Some(1), "{}", stdout(&evaluated));
    let report: Value = serde_json::from_slice(&evaluated.stdout).expect("eval JSON");
    assert_eq!(report["reviewed_legitimate_traffic"]["operation_count"], 2);
    assert_eq!(report["reviewed_legitimate_traffic"]["false_positives"], 1);
    assert_eq!(
        report["reviewed_legitimate_traffic"]["traces"][0]["operations"][1]["rejection_category"],
        "uniqueness-violation"
    );
}

/// PROOF (the closed bypass): an UNSIGNED write claiming authority ABOVE the agent tier is now
/// REJECTED by default — no identity configured, no opt-in flag. This is the exact
/// `--authority high --source source:human` label trick the security review used; before this
/// change it was trusted, now it fails closed. A `--authority medium --source source:ci` variant
/// is rejected too. This must FAIL (be rejected) here and would have PASSED (been trusted) before.
#[test]
fn unsigned_above_agent_write_is_rejected_by_default() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    for (authority, source) in [("high", "source:human"), ("medium", "source:ci")] {
        let rejected = run_dent8(
            &[
                "assert",
                "repo:app",
                "notes",
                "hello",
                "--authority",
                authority,
                "--source",
                source,
            ],
            &envs,
        );
        assert_eq!(
            rejected.status.code(),
            Some(2),
            "unsigned {authority} write must be rejected: {}",
            stdout(&rejected)
        );
        assert!(
            stderr(&rejected).contains("above the agent tier")
                && stderr(&rejected).contains("requires a valid signed identity"),
            "{}",
            stderr(&rejected)
        );
        // Nothing was persisted: the fail-closed gate runs before the store is touched.
        assert!(
            !std::path::Path::new(&log).exists()
                || !fs::read_to_string(&log)
                    .unwrap_or_default()
                    .contains("hello"),
            "a rejected above-agent write must not reach the log"
        );
    }
}

/// PROOF (the honest path works out of the box): after a DEFAULT `dent8 init` — which now
/// provisions a signing identity — the same above-agent write SUCCEEDS (signed), and the persisted
/// event carries a valid attestation that `verify` accepts.
#[cfg(feature = "sqlite")]
#[test]
fn signed_above_agent_write_accepted_after_default_init() {
    let temp = TempDir::new();
    let root = temp.path.clone();
    fs::create_dir(root.join(".git")).expect("create .git");
    let dir = root.join(".dent8").to_string_lossy().into_owned();

    let init = run_dent8(&["init", "--dir", &dir], &[]);
    assert_success(&init, "default init provisions identity");

    // Source the env init wrote (it now carries the signed-identity vars) and make a High write.
    let env_file = fs::read_to_string(root.join(".dent8").join("env")).expect("env file");
    let pairs: Vec<(String, String)> = env_file
        .lines()
        .filter_map(|line| line.split_once('='))
        .filter(|(key, _)| key.starts_with("DENT8_"))
        .map(|(key, value)| (key.to_string(), value.trim().trim_matches('\'').to_string()))
        .collect();
    let envs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();

    let asserted = run_dent8(
        &[
            "assert",
            "repo:myproj",
            "deploy_target",
            "production",
            "--authority",
            "high",
            "--source",
            "source:local",
        ],
        &envs,
    );
    assert_success(&asserted, "signed above-agent write after default init");

    // The persisted event carries a write attestation and `verify` accepts it.
    let store_log = root.join(".dent8").join("memory.jsonl");
    let contents = fs::read_to_string(&store_log).expect("read store");
    assert!(
        contents.contains("attestation"),
        "signed event must carry an attestation: {contents}"
    );
    let verify = run_dent8(&["verify"], &envs);
    assert_success(&verify, "verify signed above-agent write");
    assert!(
        stdout(&verify).contains("write attestation(s) verify"),
        "{}",
        stdout(&verify)
    );
}

/// PROOF (agent-tier stays permissive): an agent-tier write (Low / `source:agent`) with NO signing
/// identity configured still succeeds — ordinary local/agent use is unchanged.
#[test]
fn agent_tier_unsigned_write_still_works() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    let accepted = run_dent8(
        &[
            "assert",
            "repo:app",
            "notes",
            "hello",
            "--authority",
            "low",
            "--source",
            "source:agent",
        ],
        &envs,
    );
    assert_success(
        &accepted,
        "agent-tier unsigned write must still be accepted",
    );
    assert!(
        stdout(&accepted).contains("ACCEPTED"),
        "{}",
        stdout(&accepted)
    );
}

/// `dent8 doctor --agent claude-code` reports the native-memory guard posture even when NO signing
/// identity is configured: the guard depends only on the hook config, so a missing identity is a
/// WARN (not a hard error) and the command still exits cleanly with the guard reported.
#[test]
fn doctor_agent_reports_guard_posture_without_identity() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();

    // A project with the enforced guard installed but NO signing identity provisioned.
    let init = run_dent8(&["init", "--dir", &dir, "--no-identity"], &[]);
    assert_success(&init, "init --no-identity (guard on, identity off)");
    assert!(
        !temp.file(".dent8/trust.json").exists(),
        "--no-identity must not provision a signing identity"
    );

    let doctor = run_dent8(&["doctor", "--agent", "claude-code", "--dir", &dir], &[]);
    assert_success(&doctor, "doctor --agent claude-code with no identity");
    let report = stdout(&doctor);
    assert!(
        report.contains("native-memory guard is enforced"),
        "doctor must report the guard posture without identity: {report}"
    );
}

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
            "low",
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
fn a_subdir_write_with_unset_env_uses_the_discovered_dent8_store() {
    let temp = TempDir::new();
    let root = temp.path.clone();
    // `repo.database` has a High authority floor, so this write must be a signed above-agent write.
    // Provide signing WITHOUT DENT8_LOG so the store is still resolved by discovery.
    let id = SigningId::provision(&temp, "source:local", "unused");

    // Discovery is confined to the enclosing git repo, so mark <root> as a repo root.
    fs::create_dir(root.join(".git")).expect("create .git repo marker");

    // Initialize a project store at <root>/.dent8 with no env sourced.
    let init = run_dent8_in(&root, &["init"], &[]);
    assert_success(&init, "init");
    let store_log = root.join(".dent8").join("memory.jsonl");
    assert!(
        store_log.exists(),
        "init should create the .dent8 store log"
    );

    // From a nested subdirectory, with every DENT8_* var unset, a write must discover the
    // project's .dent8 store upward (within the enclosing repo) instead of silently creating a
    // parallel ./dent8-log.jsonl in the cwd — the old first-run footgun.
    let subdir = root.join("nested").join("deeper");
    fs::create_dir_all(&subdir).expect("create subdir");
    let asserted = run_dent8_in(
        &subdir,
        &[
            "assert",
            "repo:app",
            "database",
            "postgres",
            "--authority",
            "high",
            "--source",
            "source:local",
        ],
        &id.signing_only(),
    );
    assert_success(&asserted, "assert from subdir");

    // The write landed in the discovered store, and NOT in a parallel cwd log.
    assert!(
        !subdir.join("dent8-log.jsonl").exists(),
        "must not create a parallel ./dent8-log.jsonl in the subdir"
    );
    assert!(
        !root.join("dent8-log.jsonl").exists(),
        "must not create a parallel ./dent8-log.jsonl in the project root either"
    );
    let store_contents = fs::read_to_string(&store_log).expect("read discovered store");
    assert!(
        store_contents.contains("postgres"),
        "the discovered store must hold the write: {store_contents}"
    );

    // A read from the subdir sees the same discovered store.
    let explained = run_dent8_in(&subdir, &["explain", "repo:app", "database"], &[]);
    assert_success(&explained, "explain from subdir");
    assert!(stdout(&explained).contains("postgres"));
}

#[test]
fn a_planted_ancestor_dent8_store_outside_a_repo_is_not_adopted() {
    // Security PoC for the bounded-discovery fix. An attacker plants a `.dent8/` in an ancestor
    // of the victim's cwd (e.g. `/tmp/.dent8` when the victim runs under `/tmp`). Before the fix,
    // unbounded upward discovery silently adopted it as BOTH the store and the authority registry
    // (attacker-controlled store path + a `source:agent` ceiling it could lift). With discovery
    // confined to the enclosing git repo — and NO repo in bounds here — only the cwd's own
    // `.dent8/` is considered, so the planted ancestor store is never touched.
    let temp = TempDir::new();
    let root = temp.path.clone();
    // `repo.database` has a High authority floor → signed above-agent write; no DENT8_LOG so the
    // store still resolves by discovery (here, the cwd fallback).
    let id = SigningId::provision(&temp, "source:local", "unused");

    // Plant a poisoned store in the ancestor: a `memory.jsonl` a naive adopt would append to, and
    // an `env` whose DENT8_LOG would redirect writes to an attacker-chosen path.
    let planted = root.join(".dent8");
    fs::create_dir(&planted).expect("create planted .dent8");
    fs::write(planted.join("memory.jsonl"), "").expect("plant memory.jsonl");
    let poisoned_log = root.join("poisoned-memory.jsonl");
    fs::write(
        planted.join("env"),
        format!("DENT8_LOG={}\n", poisoned_log.display()),
    )
    .expect("plant env");

    // Write from a subdirectory with NO git repo anywhere in bounds and every DENT8_* var unset.
    let work = root.join("work");
    fs::create_dir(&work).expect("create work dir");
    let asserted = run_dent8_in(
        &work,
        &[
            "assert",
            "repo:app",
            "database",
            "postgres",
            "--authority",
            "high",
            "--source",
            "source:local",
        ],
        &id.signing_only(),
    );
    assert_success(&asserted, "assert from non-repo subdir");

    // The planted ancestor store must NOT be adopted: neither its `memory.jsonl` nor its env's
    // redirected log received the write.
    assert_eq!(
        fs::read_to_string(planted.join("memory.jsonl")).expect("read planted store"),
        "",
        "planted ancestor .dent8/memory.jsonl must stay empty — not adopted"
    );
    assert!(
        !poisoned_log.exists(),
        "planted .dent8/env DENT8_LOG must not be honored"
    );
    // With no repo and no cwd-local store, the write falls back to the legacy cwd default log.
    let local_log = work.join("dent8-log.jsonl");
    assert!(
        local_log.exists(),
        "write should fall back to the cwd's own log, not the planted ancestor store"
    );
    assert!(
        fs::read_to_string(&local_log)
            .expect("read local log")
            .contains("postgres"),
        "the fallback cwd log must hold the write"
    );
}

#[test]
fn discovery_is_confined_to_the_enclosing_git_repo() {
    // A planted `.dent8/` ABOVE the repo root must not leak in: discovery scans only from the cwd
    // up to and including the enclosing repo root. The repo's own `.dent8/` is still discovered
    // from a nested subdirectory.
    let temp = TempDir::new();
    let outside = temp.path.clone();
    // `repo.database` has a High authority floor → signed above-agent write; no DENT8_LOG so the
    // store still resolves by discovery.
    let id = SigningId::provision(&temp, "source:local", "unused");

    // Planted, attacker-controlled store ABOVE the repo.
    let planted = outside.join(".dent8");
    fs::create_dir(&planted).expect("create planted .dent8");
    fs::write(planted.join("memory.jsonl"), "").expect("plant memory.jsonl");

    // The real repo, one level down, marked with `.git`, with its own initialized store.
    let repo = outside.join("repo");
    fs::create_dir(&repo).expect("create repo");
    fs::create_dir(repo.join(".git")).expect("create .git");
    let init = run_dent8_in(&repo, &["init"], &[]);
    assert_success(&init, "init in repo");
    let repo_store = repo.join(".dent8").join("memory.jsonl");
    assert!(repo_store.exists(), "init should create the repo store");

    // From a nested subdir of the repo, a write discovers the repo store (bounded at the repo
    // root) and never escapes upward to the planted ancestor store.
    let subdir = repo.join("src").join("deep");
    fs::create_dir_all(&subdir).expect("create subdir");
    let asserted = run_dent8_in(
        &subdir,
        &[
            "assert",
            "repo:app",
            "database",
            "postgres",
            "--authority",
            "high",
            "--source",
            "source:local",
        ],
        &id.signing_only(),
    );
    assert_success(&asserted, "assert from repo subdir");

    assert!(
        fs::read_to_string(&repo_store)
            .expect("read repo store")
            .contains("postgres"),
        "the write must land in the enclosing repo's store"
    );
    assert_eq!(
        fs::read_to_string(planted.join("memory.jsonl")).expect("read planted store"),
        "",
        "the planted store above the repo root must never be adopted"
    );
}

// A DB-backed store URL is only meaningful when an async backend is compiled in.
#[cfg(feature = "sqlite")]
#[test]
fn a_discovered_store_url_selects_the_db_backend_when_the_process_env_is_unset() {
    // An unsourced run in a repo whose `.dent8/env` sets DENT8_STORE_URL (a SQLite backend) must
    // use that backend rather than forking a parallel `memory.jsonl` file log inside `.dent8/`.
    let temp = TempDir::new();
    let root = temp.path.clone();
    fs::create_dir(root.join(".git")).expect("create .git");
    // `repo.database` has a High authority floor → signed above-agent write; no DENT8_LOG/URL so the
    // store still resolves by discovery (the sqlite backend from .dent8/env).
    let id = SigningId::provision(&temp, "source:local", "unused");

    // Initialize a SQLite-backed project store; `init` records DENT8_STORE_URL in `.dent8/env`
    // (the db file itself is created lazily on the first backend write).
    let init = run_dent8_in(&root, &["init", "--store", "sqlite"], &[]);
    assert_success(&init, "init --store sqlite");
    let db = root.join(".dent8").join("dent8.db");
    let env = fs::read_to_string(root.join(".dent8").join("env")).expect("read env");
    assert!(
        env.contains("DENT8_STORE_URL=") && env.contains("sqlite://"),
        "init should record DENT8_STORE_URL in .dent8/env: {env}"
    );

    // From a subdir with EVERY DENT8_* var unset, a write must go to the discovered SQLite
    // backend selected by the `.dent8/env` DENT8_STORE_URL.
    let subdir = root.join("nested");
    fs::create_dir(&subdir).expect("create subdir");
    let asserted = run_dent8_in(
        &subdir,
        &[
            "assert",
            "repo:app",
            "database",
            "postgres",
            "--authority",
            "high",
            "--source",
            "source:local",
        ],
        &id.signing_only(),
    );
    assert_success(&asserted, "assert into discovered sqlite backend");

    // The write went to the discovered SQLite backend (its db file now exists) — not a file log.
    assert!(
        db.exists(),
        "the discovered sqlite backend db must hold the write"
    );
    // No parallel file log anywhere — no forked memory.jsonl inside `.dent8/`.
    assert!(
        !root.join(".dent8").join("memory.jsonl").exists(),
        "must not fork a parallel memory.jsonl when a DB backend is discovered"
    );
    assert!(
        !subdir.join("dent8-log.jsonl").exists() && !root.join("dent8-log.jsonl").exists(),
        "must not create a parallel cwd log"
    );

    // Reading from the subdir (still unsourced) sees the write through the same discovered
    // backend, proving the store URL — not a file — is what resolution honored.
    let explained = run_dent8_in(&subdir, &["explain", "repo:app", "database"], &[]);
    assert_success(&explained, "explain from discovered sqlite backend");
    assert!(
        stdout(&explained).contains("postgres"),
        "{}",
        stdout(&explained)
    );
}

#[test]
fn init_seeds_the_default_authority_profile_in_a_single_registry() {
    let temp = TempDir::new();
    let root = temp.path.clone();

    let init = run_dent8_in(&root, &["init"], &[]);
    assert_success(&init, "init");

    let registry_path = root.join(".dent8").join("authority.json");
    let read_sources = || -> Value {
        let raw = fs::read_to_string(&registry_path).expect("read registry");
        serde_json::from_str::<Value>(&raw)
            .expect("parse registry")
            .get("sources")
            .cloned()
            .expect("sources object")
    };

    // A fresh init seeds the shipped default profile AND keeps its own source:local grant, all
    // in the one discovered registry — no second `authority defaults` step required.
    let sources = read_sources();
    for src in ["source:local", "source:human", "source:ci", "source:agent"] {
        assert!(
            sources.get(src).is_some(),
            "init registry must contain {src}: {sources}"
        );
    }
    let seeded_count = sources.as_object().expect("sources map").len();

    // `authority defaults` with unset env must touch that SAME discovered registry (merge-only,
    // idempotent) rather than writing a divergent ./dent8-authority.json in the cwd.
    let defaults = run_dent8_in(&root, &["authority", "defaults"], &[]);
    assert_success(&defaults, "authority defaults");
    assert!(
        !root.join("dent8-authority.json").exists(),
        "authority defaults must not create a parallel ./dent8-authority.json"
    );
    let after = read_sources();
    assert_eq!(
        after.as_object().expect("sources map").len(),
        seeded_count,
        "merge-only defaults must not add or duplicate sources"
    );
    assert!(
        after.get("source:local").is_some(),
        "source:local grant must be kept (merge-only): {after}"
    );
}

#[test]
fn assert_with_ttl_sets_the_fact_ttl_and_enforces_the_ceiling() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    // The seeds are High (above-agent) writes and now require a signed identity for source:local.
    let id = SigningId::provision(&temp, "source:local", &log);
    let envs = id.env_for(&log);

    // A within-ceiling --ttl on an unregistered predicate is admitted and the persisted fact
    // carries a finite DurationMillis TTL (30 days).
    let ok = run_dent8(
        &[
            "assert",
            "repo:app",
            "note",
            "temporary",
            "--authority",
            "high",
            "--source",
            "source:local",
            "--ttl",
            "30d",
        ],
        &envs,
    );
    assert_success(&ok, "assert --ttl 30d");
    let contents = fs::read_to_string(&log).expect("read log");
    let thirty_days_ms = (30u64 * 86_400_000).to_string();
    assert!(
        contents.contains("DurationMillis") && contents.contains(&thirty_days_ms),
        "the fact must carry a finite {thirty_days_ms}ms TTL: {contents}"
    );

    // A --ttl past the 90-day retention ceiling is rejected on write (Item 3 + Item 4).
    let rejected = run_dent8(
        &[
            "assert",
            "repo:app",
            "note",
            "toolong",
            "--authority",
            "high",
            "--source",
            "source:local",
            "--ttl",
            "120d",
        ],
        &envs,
    );
    assert!(
        !rejected.status.success(),
        "assert --ttl 120d must be rejected, stdout: {}",
        stdout(&rejected)
    );
    assert!(
        stderr(&rejected).contains("exceeds the retention"),
        "rejection must cite the retention ceiling: {}",
        stderr(&rejected)
    );

    // A bad --ttl value is a usage error, not a silent no-op.
    let bad = run_dent8(
        &[
            "assert",
            "repo:app",
            "note",
            "x",
            "--authority",
            "high",
            "--source",
            "source:local",
            "--ttl",
            "90",
        ],
        &envs,
    );
    assert!(!bad.status.success(), "a unit-less --ttl must be rejected");
}

#[test]
fn facts_list_hides_diagnostics_by_default_and_supports_filters() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];
    // `repo.database` has a High authority floor, so that fact must be a signed above-agent write
    // (source:codex). The personal + diagnostic facts are on unregistered predicates and this test
    // asserts stream URIs/counts (not authority), so they stay at the agent tier.
    let id_codex = SigningId::provision(&temp, "source:codex", &log);

    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_drink",
                "tea",
                "--authority",
                "low",
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
            &id_codex.env_for(&log),
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
                "low",
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
fn context_emits_only_believed_facts_as_annotated_markdown() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];
    // Above-agent writes (medium/high) require signed identities; sign each source into the log.
    let id_ci = SigningId::provision(&temp, "source:ci", &log);
    let id_human = SigningId::provision(&temp, "source:human", &log);

    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "uses_database",
                "postgres",
                "--authority",
                "medium",
                "--source",
                "source:ci",
            ],
            &id_ci.env_for(&log),
        ),
        "seed context fact (ci)",
    );
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "deploy_target",
                "staging",
                "--authority",
                "high",
                "--source",
                "source:human",
            ],
            &id_human.env_for(&log),
        ),
        "seed context fact (human)",
    );
    // Revise one fact and terminally remove the other's sibling stream, so the pack must
    // show only the current beliefs.
    assert_success(
        &run_dent8(
            &[
                "supersede",
                "repo:app",
                "uses_database",
                "sqlite",
                "--authority",
                "high",
                "--source",
                "source:human",
            ],
            &id_human.env_for(&log),
        ),
        "supersede context fact",
    );
    assert_success(
        &run_dent8(
            &[
                "retract",
                "repo:app",
                "deploy_target",
                "--authority",
                "high",
                "--source",
                "source:human",
            ],
            &id_human.env_for(&log),
        ),
        "retract context fact",
    );

    let context = run_dent8(&["context"], &envs);
    assert_success(&context, "context");
    let markdown = stdout(&context);
    assert!(markdown.contains("## Project facts (dent8)"), "{markdown}");
    assert!(markdown.contains("### repo:app"), "{markdown}");
    assert!(
        markdown.contains("- `uses_database` = \"sqlite\""),
        "{markdown}"
    );
    assert!(
        markdown.contains("authority: high, source: source:human"),
        "{markdown}"
    );
    assert!(
        markdown.contains("ref: dent8://repo/app/uses_database"),
        "{markdown}"
    );
    // The superseded value and the retracted stream are history, not context.
    assert!(!markdown.contains("\"postgres\""), "{markdown}");
    assert!(!markdown.contains("deploy_target"), "{markdown}");

    let json = run_dent8(&["--output", "json", "context"], &envs);
    assert_success(&json, "context --output json");
    let json = stdout_json(&json);
    assert_eq!(json["status"], "ok");
    assert_eq!(json["tool"], "context");
    assert_eq!(json["count"], 1);
    assert_eq!(json["facts"][0]["predicate"], "uses_database");
    assert_eq!(json["facts"][0]["value"]["text"], "sqlite");
    assert_eq!(json["facts"][0]["authority"], "high");
    assert_eq!(json["facts"][0]["source"], "source:human");
    assert_eq!(json["facts"][0]["freshness"], "fresh");
    assert_eq!(json["omitted"]["stale"], 0);
}

#[test]
fn context_omits_stale_facts_by_default_and_flags_contested_ones() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    // A believed fact whose asserted validity already lapsed (ADR 0016) reads stale.
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "release_branch",
                "release-1.0",
                "--authority",
                "low",
                "--source",
                "source:human",
                "--valid-to",
                "1000",
            ],
            &envs,
        ),
        "assert stale fact",
    );
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "uses_database",
                "postgres",
                "--authority",
                "low",
                "--source",
                "source:ci",
            ],
            &envs,
        ),
        "assert fresh fact",
    );
    assert_success(
        &run_dent8(
            &[
                "contradict",
                "repo:app",
                "uses_database",
                "sqlite",
                "--authority",
                "low",
                "--source",
                "source:codex",
            ],
            &envs,
        ),
        "contradict fresh fact",
    );

    let context = run_dent8(&["context"], &envs);
    assert_success(&context, "context with stale + contested facts");
    let markdown = stdout(&context);
    assert!(!markdown.contains("release_branch"), "{markdown}");
    assert!(
        markdown.contains("1 believed fact(s) omitted (1 stale, 0 not yet valid)"),
        "{markdown}"
    );
    assert!(markdown.contains("[contested — "), "{markdown}");

    let included = run_dent8(&["context", "--include-stale"], &envs);
    assert_success(&included, "context --include-stale");
    let included = stdout(&included);
    assert!(included.contains("release_branch"), "{included}");
    assert!(included.contains("[stale — "), "{included}");

    // A pack carrying a live dispute reads `contested`, not `ok`.
    let json = stdout_json(&run_dent8(&["--output", "json", "context"], &envs));
    assert_eq!(json["status"], "contested");
}

#[test]
fn capture_flushes_a_proposals_file_through_the_firewall() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let proposals = temp.file("proposals.jsonl").to_string_lossy().into_owned();
    // The High proposal is an above-agent write and now requires a signed identity; capture runs as
    // one identity (source:human), so the whole batch is attributed/signed under it. The low
    // supersession therefore also carries source:human so it is judged by the firewall's authority
    // gate (insufficient authority: low < high) rather than an identity mismatch.
    let id = SigningId::provision(&temp, "source:human", &log);
    let envs = id.env_for(&log);

    fs::write(
        &proposals,
        concat!(
            r#"{"subject": "repo:app", "predicate": "uses_database", "value": "postgres", "authority": "high", "source": "source:human"}"#,
            "\n",
            r#"{"op": "supersede", "subject": "repo:app", "predicate": "uses_database", "value": "mysql", "authority": "low", "source": "source:human"}"#,
            "\n",
            r#"{"subject": "repo:app", "predicate": "build_tool", "value": "cargo"}"#,
            "\n",
        ),
    )
    .expect("write proposals");

    let captured = run_dent8(&["capture", &proposals, "--consume"], &envs);
    // The low-authority supersession is refused, and the batch says so with exit 1.
    assert_eq!(captured.status.code(), Some(1), "{}", stderr(&captured));
    let report = stderr(&captured);
    assert!(
        report.contains("captured 3 proposal(s): 2 accepted, 0 contested, 1 rejected, 0 invalid"),
        "{report}"
    );
    assert!(report.contains("insufficient authority"), "{report}");
    // --consume truncated the queue so the next hook firing does not replay it.
    assert_eq!(line_count(&proposals), 0);

    // The accepted writes persisted through the same firewall path as `dent8 assert`.
    let explained = run_dent8(&["explain", "repo:app", "uses_database"], &envs);
    assert_success(&explained, "explain after capture");
    assert!(stdout(&explained).contains("value         : \"postgres\""));
    // The unattributed proposal fell back to the configured signed grant's default source.
    let fallback = run_dent8(&["replay", "repo:app", "build_tool"], &envs);
    assert_success(&fallback, "replay captured fallback fact");
    assert!(
        stdout(&fallback).contains("source:human"),
        "{}",
        stdout(&fallback)
    );
}

#[test]
fn capture_reads_stdin_and_reports_json() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    let input = concat!(
        r#"{"subject": "repo:app", "predicate": "build_tool", "value": "cargo"}"#,
        "\n",
        "not json\n",
    );
    let captured = run_dent8_stdin(&["--output", "json", "capture"], input, &envs);
    // A malformed line dominates the batch status (exit 2), but the good line still landed.
    assert_eq!(captured.status.code(), Some(2), "{}", stdout(&captured));
    let json = stdout_json(&captured);
    assert_eq!(json["status"], "invalid");
    assert_eq!(json["tool"], "capture");
    assert_eq!(json["total"], 2);
    assert_eq!(json["accepted"], 1);
    assert_eq!(json["invalid"], 1);
    assert_eq!(json["results"][0]["status"], "accepted");
    assert_eq!(json["results"][1]["status"], "invalid");

    let explained = run_dent8(&["explain", "repo:app", "build_tool"], &envs);
    assert_success(&explained, "explain after stdin capture");
    assert!(stdout(&explained).contains("value         : \"cargo\""));
}

#[test]
fn mcp_resources_read_records_retrieval_and_honors_opt_out() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &log);
    let envs = id.env_for(&log);

    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "uses_database",
                "postgres",
                "--authority",
                "high",
                "--source",
                "source:human",
            ],
            &envs,
        ),
        "seed mcp retrieval fact",
    );

    // Default: resources/read appends fact.retrieved with the stable MCP purpose.
    let requests = [
        r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"dent8://repo/app/uses_database"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"replay","arguments":{"subject":"repo:app","predicate":"uses_database"}}}"#,
    ]
    .join("\n");
    let mcp = run_dent8_mcp(&format!("{requests}\n"), &envs);
    let mcp_out = stdout(&mcp);
    assert!(
        mcp.status.success(),
        "mcp serve failed\nstdout:\n{mcp_out}\nstderr:\n{}",
        String::from_utf8_lossy(&mcp.stderr)
    );
    let lines: Vec<&str> = mcp_out.lines().filter(|l| !l.is_empty()).collect();
    assert!(
        lines.len() >= 2,
        "expected read + replay responses, got: {mcp_out}"
    );
    let read: Value = serde_json::from_str(lines[0]).expect("read response json");
    assert!(
        read.get("error").is_none(),
        "resources/read must succeed: {read}"
    );
    let replay: Value = serde_json::from_str(lines[1]).expect("replay response json");
    let replay_text = replay["result"]["content"][0]["text"]
        .as_str()
        .expect("replay text");
    assert!(
        replay_text.contains("mcp:resources/read"),
        "default resources/read must audit: {replay_text}"
    );

    // Opt-out: a second read with DENT8_MCP_RECORD_RETRIEVAL=0 must not add another audit.
    let before = stdout_json(&run_dent8(
        &["--output", "json", "replay", "repo:app", "uses_database"],
        &envs,
    ));
    let before_count = before["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter(|e| e["kind"] == "fact.retrieved")
        .count();

    let opt_out_envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_MCP_RECORD_RETRIEVAL", "0"),
    ];
    let opt_out = run_dent8_mcp(
        &format!(
            "{}\n",
            r#"{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"dent8://repo/app/uses_database"}}"#
        ),
        &opt_out_envs,
    );
    assert!(
        opt_out.status.success(),
        "opt-out mcp serve failed\nstdout:\n{}\nstderr:\n{}",
        stdout(&opt_out),
        String::from_utf8_lossy(&opt_out.stderr)
    );
    let after = stdout_json(&run_dent8(
        &["--output", "json", "replay", "repo:app", "uses_database"],
        &envs,
    ));
    let after_count = after["events"]
        .as_array()
        .expect("events")
        .iter()
        .filter(|e| e["kind"] == "fact.retrieved")
        .count();
    assert_eq!(
        before_count, after_count,
        "opt-out must not append another fact.retrieved"
    );
}

#[test]
fn context_record_retrieval_appends_audit_events() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    // Only the High seed needs a signed identity. The retrieval audit itself is agent-tier and
    // deliberately unattributed (the reader is an agent), so it runs WITHOUT the grant configured —
    // otherwise the audit would inherit the grant's source instead of falling back to source:agent.
    let id = SigningId::provision(&temp, "source:human", &log);
    let envs = [("DENT8_LOG", log.as_str())];

    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "uses_database",
                "postgres",
                "--authority",
                "high",
                "--source",
                "source:human",
            ],
            &id.env_for(&log),
        ),
        "seed retrieval fact",
    );

    // A plain context read records nothing.
    let plain = stdout_json(&run_dent8(&["--output", "json", "context"], &envs));
    assert_eq!(plain["recorded_retrievals"], Value::Null);

    // With --record-retrieval every emitted fact gains a fact.retrieved audit event.
    let audited = run_dent8(
        &[
            "--output",
            "json",
            "context",
            "--record-retrieval",
            "--purpose",
            "session-start",
        ],
        &envs,
    );
    assert_success(&audited, "context --record-retrieval");
    let audited = stdout_json(&audited);
    assert_eq!(audited["status"], "ok");
    assert_eq!(audited["count"], 1);
    assert_eq!(audited["recorded_retrievals"], 1);

    // The audit event is on the fact's stream, replayable with its purpose, and recorded
    // as the unattributed agent tier (context takes no --source; the reader is an agent).
    let replayed = stdout_json(&run_dent8(
        &["--output", "json", "replay", "repo:app", "uses_database"],
        &envs,
    ));
    let events = replayed["events"].as_array().expect("events array");
    let retrieved = events
        .iter()
        .find(|event| event["kind"] == "fact.retrieved")
        .expect("a fact.retrieved event");
    assert_eq!(retrieved["details"]["purpose"], "session-start");
    assert_eq!(retrieved["source"], "source:agent");
    assert_eq!(retrieved["authority"], "low");
    // Retrieval is an audit event: the believed fact is untouched.
    assert_eq!(replayed["current"]["value"]["text"], "postgres");

    // The audited log still verifies, and the markdown pack stays a pure context block
    // (the audit rides on the store, not in the injected text).
    assert_success(
        &run_dent8(&["verify"], &envs),
        "verify after retrieval audit",
    );
    let markdown = run_dent8(&["context", "--record-retrieval"], &envs);
    assert_success(&markdown, "context --record-retrieval markdown");
    let markdown = stdout(&markdown);
    assert!(markdown.contains("## Project facts (dent8)"), "{markdown}");
    assert!(!markdown.contains("retriev"), "{markdown}");
}

#[test]
fn capture_keep_failed_preserves_rejected_lines_on_consume() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let proposals = temp.file("proposals.jsonl").to_string_lossy().into_owned();
    // Capture runs as one signed identity (source:human) so the High proposal is a valid signed
    // above-agent write; the low supersession also carries source:human so it is refused by the
    // firewall's authority gate (low < high), not an identity mismatch.
    let id = SigningId::provision(&temp, "source:human", &log);
    let envs = id.env_for(&log);

    fs::write(
        &proposals,
        concat!(
            r#"{"subject": "repo:app", "predicate": "uses_database", "value": "postgres", "authority": "high", "source": "source:human"}"#,
            "\n",
            r#"{"op": "supersede", "subject": "repo:app", "predicate": "uses_database", "value": "mysql", "authority": "low", "source": "source:human"}"#,
            "\n",
            "not json\n",
        ),
    )
    .expect("write proposals");

    let captured = run_dent8(
        &[
            "--output",
            "json",
            "capture",
            &proposals,
            "--consume",
            "--keep-failed",
        ],
        &envs,
    );
    // The malformed line dominates the batch status (exit 2); the rejection is line 2.
    assert_eq!(captured.status.code(), Some(2), "{}", stdout(&captured));
    let json = stdout_json(&captured);
    assert_eq!(json["accepted"], 1);
    assert_eq!(json["rejected"], 1);
    assert_eq!(json["invalid"], 1);
    assert_eq!(json["consumed"], proposals.as_str());
    assert_eq!(json["kept_failed"], 2);

    // The accepted line is gone; the rejected + malformed lines survive for retry.
    let remaining = fs::read_to_string(&proposals).expect("read proposals");
    assert_eq!(line_count(&proposals), 2, "{remaining}");
    assert!(remaining.contains("\"op\": \"supersede\""), "{remaining}");
    assert!(remaining.contains("not json"), "{remaining}");
    assert!(!remaining.contains("\"postgres\""), "{remaining}");

    // Without --keep-failed the same consume truncates everything, as before.
    let flushed = run_dent8(&["capture", &proposals, "--consume"], &envs);
    assert_eq!(flushed.status.code(), Some(2), "{}", stderr(&flushed));
    assert!(
        stderr(&flushed).contains("consumed"),
        "{}",
        stderr(&flushed)
    );
    assert_eq!(line_count(&proposals), 0);

    // --keep-failed without --consume is a usage error.
    let usage = run_dent8(&["capture", &proposals, "--keep-failed"], &envs);
    assert_eq!(usage.status.code(), Some(2), "{}", stderr(&usage));
}

#[test]
#[allow(clippy::too_many_lines)] // one linear scenario: grant -> scope -> delegate -> tamper
fn scoped_and_issuer_capped_grants_are_enforced_end_to_end() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let registry = temp.file("authority.json").to_string_lossy().into_owned();
    let envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_AUTHORITY", registry.as_str()),
    ];
    // The successful in-scope writes are above-agent (medium) and must clear the identity gate too
    // (which runs after the registry scope/ceiling check), so sign source:lead and source:bot. The
    // rejected writes fail at the registry check first, so they need no signing.
    let id_lead = SigningId::provision(&temp, "source:lead", &log);
    let id_bot = SigningId::provision(&temp, "source:bot", &log);
    let mut lead_env = id_lead.env_for(&log);
    lead_env.push(("DENT8_AUTHORITY", registry.as_str()));
    let mut bot_env = id_bot.env_for(&log);
    bot_env.push(("DENT8_AUTHORITY", registry.as_str()));

    // A lead scoped to repo:app, and a bot whose grant is issued by that lead.
    assert_success(
        &run_dent8(
            &[
                "authority",
                "add",
                "source:lead",
                "medium",
                "operator",
                "repo:app",
            ],
            &envs,
        ),
        "add scoped lead grant",
    );
    assert_success(
        &run_dent8(
            &[
                "authority",
                "add",
                "source:bot",
                "low",
                "source:lead",
                "repo:app",
            ],
            &envs,
        ),
        "add issuer-capped bot grant",
    );

    // The scope admits writes about its subject...
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "uses_database",
                "postgres",
                "--authority",
                "medium",
                "--source",
                "source:lead",
            ],
            &lead_env,
        ),
        "in-scope write",
    );
    // ...and rejects writes about any other subject.
    let outside = run_dent8(
        &[
            "assert",
            "repo:other",
            "uses_database",
            "postgres",
            "--authority",
            "medium",
            "--source",
            "source:lead",
        ],
        &envs,
    );
    assert_eq!(outside.status.code(), Some(1), "{}", stderr(&outside));
    assert!(
        stderr(&outside).contains("authority scope"),
        "{}",
        stderr(&outside)
    );

    // authority add refuses a delegation the issuer cannot make: above its ceiling...
    let escalated = run_dent8(
        &["authority", "add", "source:bot2", "high", "source:lead"],
        &envs,
    );
    assert_eq!(escalated.status.code(), Some(2), "{}", stderr(&escalated));
    assert!(
        stderr(&escalated).contains("cannot delegate"),
        "{}",
        stderr(&escalated)
    );
    // ...or a self-issued grant.
    let self_issued = run_dent8(
        &["authority", "add", "source:loop", "low", "source:loop"],
        &envs,
    );
    assert_eq!(
        self_issued.status.code(),
        Some(2),
        "{}",
        stderr(&self_issued)
    );
    assert!(
        stderr(&self_issued).contains("no self-escalation"),
        "{}",
        stderr(&self_issued)
    );

    // A hand-edited registry cannot smuggle self-escalation past the write gate: raise the
    // bot's recorded ceiling above its issuer's and the write is still capped by the issuer.
    let mut edited: Value =
        serde_json::from_str(&fs::read_to_string(&registry).expect("read registry"))
            .expect("parse registry");
    edited["sources"]["source:bot"]["max_authority"] = Value::String("high".to_string());
    fs::write(
        &registry,
        serde_json::to_string_pretty(&edited).expect("serialize registry"),
    )
    .expect("write registry");
    let laundered = run_dent8(
        &[
            "assert",
            "repo:app",
            "build_tool",
            "cargo",
            "--authority",
            "high",
            "--source",
            "source:bot",
        ],
        &envs,
    );
    assert_eq!(laundered.status.code(), Some(1), "{}", stderr(&laundered));
    assert!(
        stderr(&laundered).contains("cannot delegate"),
        "{}",
        stderr(&laundered)
    );
    // Within the issuer's ceiling and scope the bot still writes.
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "build_tool",
                "cargo",
                "--authority",
                "medium",
                "--source",
                "source:bot",
            ],
            &bot_env,
        ),
        "delegated in-scope write",
    );
}

#[test]
fn doctor_write_check_probes_within_a_subject_scoped_grant() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let registry = temp.file("authority.json").to_string_lossy().into_owned();
    // The write-check probes at the source's ceiling (High, above the agent tier), so a signed
    // identity for source:scoped must be configured alongside the authority registry.
    let id = SigningId::provision(&temp, "source:scoped", &log);
    let mut envs = id.env_for(&log);
    envs.push(("DENT8_AUTHORITY", registry.as_str()));
    envs.push(("DENT8_REQUIRE_AUTHORITY", "1"));

    assert_success(
        &run_dent8(
            &[
                "authority",
                "add",
                "source:scoped",
                "high",
                "operator",
                "repo:app",
            ],
            &envs,
        ),
        "add subject-scoped grant",
    );

    // A correctly-scoped source passes doctor: the probe targets the scoped subject (the
    // one subject the source may write about), not an out-of-scope diagnostic: subject.
    let doctor = run_dent8(
        &["doctor", "--source", "source:scoped", "--write-check"],
        &envs,
    );
    assert_success(&doctor, "doctor --write-check for a scoped source");
    let report = stdout(&doctor);
    assert!(
        report.contains("write-check: accepted trusted repo:app dent8.write_check."),
        "{report}"
    );
    assert!(
        report.contains("rejected below-ceiling tampered value"),
        "{report}"
    );
    // The probe retracts its own fact so nothing is left believed.
    assert!(report.contains("probe retracted"), "{report}");
    // The probe never persisted an out-of-scope write.
    let log_contents = fs::read_to_string(&log).expect("write-check log");
    assert!(
        !log_contents.contains("\"kind\":\"diagnostic\""),
        "{log_contents}"
    );

    // Repeatable: a second run probes under a fresh per-run predicate.
    assert_success(
        &run_dent8(
            &["doctor", "--source", "source:scoped", "--write-check"],
            &envs,
        ),
        "second doctor --write-check for a scoped source",
    );

    // The scoped probe streams stay hidden from browse surfaces like diagnostic: ones.
    let listed = run_dent8(&["facts", "list"], &envs);
    assert_success(&listed, "facts list after scoped write-check");
    let listed_stdout = stdout(&listed);
    assert!(
        !listed_stdout.contains("dent8.write_check"),
        "{listed_stdout}"
    );
    assert!(
        listed_stdout.contains("diagnostic stream(s) hidden"),
        "{listed_stdout}"
    );

    // An unauthorized source still fails the write-check.
    let unauthorized = run_dent8(
        &["doctor", "--source", "source:evil", "--write-check"],
        &envs,
    );
    assert_eq!(
        unauthorized.status.code(),
        Some(1),
        "{}",
        stdout(&unauthorized)
    );
    let unauthorized = stdout(&unauthorized);
    assert!(
        unauthorized.contains("FAIL  write-check:"),
        "{unauthorized}"
    );
    assert!(unauthorized.contains("authority ceiling"), "{unauthorized}");
}

#[test]
fn doctor_write_check_asserts_at_the_source_ceiling_and_retracts() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let registry = temp.file("authority.json").to_string_lossy().into_owned();
    // The write-check probes at the source's ceiling (Medium, above the agent tier), so a signed
    // identity for source:mid must be configured alongside the authority registry.
    let id = SigningId::provision(&temp, "source:mid", &log);
    let mut envs = id.env_for(&log);
    envs.push(("DENT8_AUTHORITY", registry.as_str()));
    envs.push(("DENT8_REQUIRE_AUTHORITY", "1"));

    // A source whose granted ceiling is *below* `high`.
    assert_success(
        &run_dent8(
            &["authority", "add", "source:mid", "medium", "operator"],
            &envs,
        ),
        "add a medium-ceiling grant",
    );

    // It passes write-check: the probe asserts at the source's own ceiling (medium), not the
    // old hardcoded high, and the reject sub-check runs one level below (low).
    let doctor = run_dent8(
        &["doctor", "--source", "source:mid", "--write-check"],
        &envs,
    );
    assert_success(&doctor, "doctor --write-check for a medium-ceiling source");
    let report = stdout(&doctor);
    assert!(
        report.contains("dent8.write_check=ok at medium"),
        "{report}"
    );
    assert!(
        report.contains("rejected below-ceiling tampered value"),
        "{report}"
    );
    assert!(report.contains("probe retracted"), "{report}");

    // After the run the probe fact is retracted, not left believed: the diagnostic stream is
    // surfaced (with --include-diagnostics) as no-longer-believed rather than fresh.
    let listed = run_dent8(&["facts", "list", "--include-diagnostics"], &envs);
    assert_success(
        &listed,
        "facts list --include-diagnostics after write-check",
    );
    let listed_stdout = stdout(&listed);
    assert!(
        listed_stdout.contains("dent8.write_check") && listed_stdout.contains("no longer believed"),
        "{listed_stdout}"
    );
}

#[test]
fn authority_remove_refuses_to_orphan_dependent_grants_without_force() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let registry = temp.file("authority.json").to_string_lossy().into_owned();
    let envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_AUTHORITY", registry.as_str()),
    ];
    // The one real write here (the delegated bot's Medium assertion) is above-agent and needs a
    // signed identity for source:bot; the registry commands themselves need none.
    let id_bot = SigningId::provision(&temp, "source:bot", &log);
    let mut bot_env = id_bot.env_for(&log);
    bot_env.push(("DENT8_AUTHORITY", registry.as_str()));

    assert_success(
        &run_dent8(&["authority", "add", "source:lead", "high"], &envs),
        "add lead grant",
    );
    assert_success(
        &run_dent8(
            &["authority", "add", "source:bot", "medium", "source:lead"],
            &envs,
        ),
        "add delegated bot grant",
    );

    // Removing the issuer would loosen its delegate to an operator root: refused.
    let refused = run_dent8(&["authority", "remove", "source:lead"], &envs);
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    let refused = stderr(&refused);
    assert!(refused.contains("source:bot"), "{refused}");
    assert!(refused.contains("--force"), "{refused}");
    // The refusal changed nothing: the delegate still writes within its grant.
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "uses_database",
                "postgres",
                "--authority",
                "medium",
                "--source",
                "source:bot",
            ],
            &bot_env,
        ),
        "delegated write after refused removal",
    );

    // --force cascades the revocation down the delegation chain.
    let forced = run_dent8(
        &[
            "--output",
            "json",
            "authority",
            "remove",
            "source:lead",
            "--force",
        ],
        &envs,
    );
    assert_success(&forced, "authority remove --force");
    let forced = stdout_json(&forced);
    assert_eq!(forced["status"], "ok");
    assert_eq!(forced["source"], "source:lead");
    assert_eq!(forced["also_revoked"][0], "source:bot");

    // The orphaned delegate authorizes nothing until re-parented: deny-by-default.
    let orphaned = run_dent8(
        &[
            "assert",
            "repo:app",
            "build_tool",
            "cargo",
            "--authority",
            "low",
            "--source",
            "source:bot",
        ],
        &envs,
    );
    assert_eq!(orphaned.status.code(), Some(1), "{}", stderr(&orphaned));
    assert!(
        stderr(&orphaned).contains("authority ceiling"),
        "{}",
        stderr(&orphaned)
    );

    // A grant nothing depends on is removed without --force, exactly as before.
    assert_success(
        &run_dent8(&["authority", "add", "source:solo", "low"], &envs),
        "add standalone grant",
    );
    assert_success(
        &run_dent8(&["authority", "remove", "source:solo"], &envs),
        "remove standalone grant",
    );
}

#[test]
fn authority_add_refuses_an_issuer_cycle_in_both_insertion_orders() {
    let temp = TempDir::new();
    let registry = temp.file("authority.json").to_string_lossy().into_owned();
    let envs = [("DENT8_AUTHORITY", registry.as_str())];

    // Order one: a names b as issuer (an operator root so far)...
    assert_success(
        &run_dent8(&["authority", "add", "source:a", "high", "source:b"], &envs),
        "add a issued by b",
    );
    // ...so adding b issued by a would complete the cycle: refused.
    let refused = run_dent8(&["authority", "add", "source:b", "high", "source:a"], &envs);
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("issuer cycle"),
        "{}",
        stderr(&refused)
    );

    // The reverse insertion order is refused the same way.
    fs::remove_file(&registry).expect("reset registry");
    assert_success(
        &run_dent8(&["authority", "add", "source:b", "high", "source:a"], &envs),
        "add b issued by a",
    );
    let refused = run_dent8(&["authority", "add", "source:a", "high", "source:b"], &envs);
    assert_eq!(refused.status.code(), Some(2), "{}", stderr(&refused));
    assert!(
        stderr(&refused).contains("issuer cycle"),
        "{}",
        stderr(&refused)
    );
}

#[test]
fn authority_defaults_seeds_the_human_ci_agent_profile() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let registry = temp.file("authority.json").to_string_lossy().into_owned();
    let envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_AUTHORITY", registry.as_str()),
    ];

    // An operator's pre-existing grant must survive the seeding (merge, not overwrite).
    assert_success(
        &run_dent8(&["authority", "add", "source:human", "canonical"], &envs),
        "pre-existing human grant",
    );
    let seeded = run_dent8(&["--output", "json", "authority", "defaults"], &envs);
    assert_success(&seeded, "authority defaults");
    let seeded = stdout_json(&seeded);
    assert_eq!(seeded["status"], "ok");
    assert_eq!(seeded["tool"], "authority defaults");
    let profile = seeded["profile"].as_array().expect("profile array");
    let entry = |source: &str| {
        profile
            .iter()
            .find(|entry| entry["source"] == source)
            .unwrap_or_else(|| panic!("{source} missing from profile"))
    };
    assert_eq!(entry("source:human")["action"], "kept");
    assert_eq!(entry("source:human")["max_authority"], "canonical");
    assert_eq!(entry("source:ci")["action"], "added");
    assert_eq!(entry("source:ci")["max_authority"], "medium");
    assert_eq!(entry("source:agent")["action"], "added");
    assert_eq!(entry("source:agent")["max_authority"], "low");

    // The profile is enforced: an agent-tier source cannot mint high authority...
    let laundered = run_dent8(
        &[
            "assert",
            "repo:app",
            "uses_database",
            "postgres",
            "--authority",
            "high",
            "--source",
            "source:agent",
        ],
        &envs,
    );
    assert_eq!(laundered.status.code(), Some(1), "{}", stderr(&laundered));
    assert!(
        stderr(&laundered).contains("authority ceiling"),
        "{}",
        stderr(&laundered)
    );
    // ...while unattributed capture enters exactly at the agent tier and is admitted.
    let captured = run_dent8_stdin(
        &["capture"],
        concat!(
            r#"{"subject": "repo:app", "predicate": "uses_database", "value": "postgres"}"#,
            "\n"
        ),
        &envs,
    );
    assert_success(&captured, "capture under the default profile");
    assert!(
        stdout(&captured).contains("1 accepted"),
        "{}",
        stdout(&captured)
    );
}

#[test]
fn native_scan_reports_agent_memory_files_and_receipt_markers() {
    let temp = TempDir::new();
    fs::create_dir_all(temp.file(".cursor/rules")).expect("create cursor rules dir");
    fs::write(
        temp.file("AGENTS.md"),
        "Stable facts live in dent8.\nreceipt: dent8://repo/app/deploy_target\n",
    )
    .expect("write AGENTS.md");
    fs::write(
        temp.file(".cursor/rules/project.mdc"),
        "Remember: deploy target is staging.\n",
    )
    .expect("write cursor rule");
    fs::write(
        temp.file("notes.txt"),
        "AGENTS.md is mentioned but not a native file\n",
    )
    .expect("write unrelated note");

    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let scan = run_dent8(
        &[
            "--output", "json", "native", "scan", "--agent", "codex", "--dir", &dir,
        ],
        &[],
    );
    assert_success(&scan, "native scan --output json");
    let scan = stdout_json(&scan);
    assert_eq!(scan["status"], "ok");
    assert_eq!(scan["tool"], "native scan");
    assert_eq!(scan["agent"], "codex");
    assert_eq!(scan["guard"]["status"], "missing");
    assert_eq!(scan["summary"]["files"], 2);
    assert_eq!(scan["summary"]["with_receipt_markers"], 1);
    assert_eq!(scan["summary"]["without_receipt_markers"], 1);

    let files = scan["files"].as_array().expect("files array");
    let agents = files
        .iter()
        .find(|file| file["relative_path"] == "AGENTS.md")
        .expect("AGENTS.md entry");
    assert_eq!(agents["kind"], "agent_instructions");
    assert_eq!(agents["has_receipt_marker"], true);
    assert!(
        agents["sha256"]
            .as_str()
            .is_some_and(|hash| hash.len() == 64)
    );

    let cursor = files
        .iter()
        .find(|file| file["relative_path"] == ".cursor/rules/project.mdc")
        .expect("cursor rule entry");
    assert_eq!(cursor["kind"], "cursor_rules");
    assert_eq!(cursor["has_receipt_marker"], false);
}

#[test]
fn native_reconcile_verifies_dent8_receipt_references() {
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
                "low",
                "--source",
                "user:alice",
            ],
            &envs,
        ),
        "assert alice fact",
    );
    fs::write(
        temp.file("AGENTS.md"),
        "Alice's current drink receipt: dent8://person/alice/favorite_drink\n",
    )
    .expect("write AGENTS.md");

    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let reconciled = run_dent8(
        &[
            "--output",
            "json",
            "native",
            "reconcile",
            "--agent",
            "codex",
            "--dir",
            &dir,
        ],
        &envs,
    );
    assert_success(&reconciled, "native reconcile --output json");
    let reconciled = stdout_json(&reconciled);
    assert_eq!(reconciled["status"], "ok");
    assert_eq!(reconciled["tool"], "native reconcile");
    assert_eq!(reconciled["summary"]["references"], 1);
    assert_eq!(reconciled["summary"]["ok"], 1);
    assert_eq!(reconciled["summary"]["failures"], 0);
    assert_eq!(reconciled["summary"]["files_with_references"], 1);

    let reference = reconciled["references"]
        .as_array()
        .expect("references array")
        .first()
        .expect("first reference");
    assert_eq!(reference["status"], "ok");
    assert_eq!(
        reference["reference"]["uri"],
        "dent8://person/alice/favorite_drink"
    );
    assert_eq!(reference["receipt"]["value"]["text"], "tea");
}

#[test]
fn native_reconcile_reports_missing_and_invalid_receipts() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];
    fs::write(
        temp.file("AGENTS.md"),
        "Missing: dent8://person/bob/favorite_drink\nBroken: dent8://broken\n",
    )
    .expect("write AGENTS.md");

    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let reconciled = run_dent8(
        &[
            "--output",
            "json",
            "native",
            "reconcile",
            "--agent",
            "codex",
            "--dir",
            &dir,
        ],
        &envs,
    );
    assert_eq!(reconciled.status.code(), Some(1));
    let reconciled = stdout_json(&reconciled);
    assert_eq!(reconciled["status"], "failed");
    assert_eq!(reconciled["summary"]["references"], 2);
    assert_eq!(reconciled["summary"]["failures"], 2);
    assert_eq!(reconciled["summary"]["missing"], 1);
    assert_eq!(reconciled["summary"]["invalid"], 1);

    let statuses = reconciled["references"]
        .as_array()
        .expect("references array")
        .iter()
        .map(|reference| reference["status"].as_str().expect("status"))
        .collect::<Vec<_>>();
    assert!(statuses.contains(&"missing"), "{statuses:?}");
    assert!(statuses.contains(&"invalid"), "{statuses:?}");
}

#[test]
#[allow(clippy::too_many_lines)]
fn read_audit_commands_emit_machine_readable_json() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    // Asserts authority round-trips as `high`, so this is a signed above-agent write (source:alice).
    let id = SigningId::provision(&temp, "source:alice", &log);
    let envs = id.env_for(&log);

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
                "source:alice",
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
    assert_eq!(explain["authority"], "high");
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

    // With one undisputed fact, `conflicts` is empty and reports `ok` — the other branch of the
    // status fix (a non-empty result reports `contested`).
    let conflicts = run_dent8(&["--output", "json", "conflicts"], &envs);
    assert_success(&conflicts, "conflicts --output json");
    let conflicts = stdout_json(&conflicts);
    assert_eq!(conflicts["status"], "ok");
    assert_eq!(conflicts["count"], 0);

    let snapshot = run_dent8(&["--output", "json", "snapshot"], &envs);
    assert_success(&snapshot, "snapshot --output json");
    let snapshot = stdout_json(&snapshot);
    assert_eq!(snapshot["status"], "ok");
    assert_eq!(snapshot["tool"], "snapshot");
    assert_eq!(snapshot["runtime_status"]["tool"], "runtime_status");
    assert_eq!(snapshot["summary"]["facts"], 1);
    assert_eq!(snapshot["summary"]["hidden_diagnostics_count"], 0);
    assert_eq!(snapshot["summary"]["integrity_verified"], true);
    assert_eq!(snapshot["summary"]["conflicts"], 0);
    assert_eq!(
        snapshot["facts"]["facts"][0]["uri"],
        "dent8://person/alice/favorite_drink"
    );
    assert_eq!(snapshot["verify"]["tool"], "verify");
    assert_eq!(snapshot["conflicts"]["tool"], "conflicts");

    // Signing is configured, so doctor's identity check needs the matching --source.
    let doctor = run_dent8(
        &["--output", "json", "doctor", "--source", "source:alice"],
        &envs,
    );
    assert_success(&doctor, "doctor --output json");
    let doctor = stdout_json(&doctor);
    assert_eq!(doctor["status"], "ok");
    assert_eq!(doctor["tool"], "doctor");
    assert_eq!(doctor["ok"], true);
    assert_doctor_json_groups(&doctor);
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

fn assert_doctor_json_groups(doctor: &Value) {
    assert_eq!(doctor["summary"]["fail"], 0);
    assert!(
        doctor["sections"]["ok"]
            .as_array()
            .expect("doctor ok checks")
            .iter()
            .any(|check| check["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("verify: OK"))),
        "{doctor}"
    );
    assert!(
        doctor["sections"]["skip"]
            .as_array()
            .expect("doctor skipped checks")
            .iter()
            .any(|check| {
                check["status"] == "skip"
                    && check["message"]
                        .as_str()
                        .is_some_and(|message| message.starts_with("write-check: not requested"))
            }),
        "{doctor}"
    );
}

#[test]
fn doctor_optional_write_check_is_a_skip_not_a_warning() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    let doctor = run_dent8(&["doctor"], &envs);
    assert_success(&doctor, "doctor");
    let stdout = stdout(&doctor);
    assert!(
        stdout.contains("SKIP  write-check: not requested"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("WARN  write-check:"),
        "optional write-check should not look like a warning:\n{stdout}"
    );
}

#[test]
fn whatif_refolds_under_a_counterfactual_policy() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    // A trusted fact, then an equal-authority supersession from a rumor source — admitted.
    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_drink",
                "tea",
                "--authority",
                "low",
                "--source",
                "user:alice",
            ],
            &envs,
        ),
        "assert tea",
    );
    assert_success(
        &run_dent8(
            &[
                "supersede",
                "person:alice",
                "favorite_drink",
                "coffee",
                "--authority",
                "low",
                "--source",
                "note:rumor",
            ],
            &envs,
        ),
        "supersede coffee",
    );

    // Counterfactual: what would we believe if the rumor source were distrusted?
    let whatif = run_dent8(
        &[
            "--output",
            "json",
            "whatif",
            "person:alice",
            "favorite_drink",
            "--distrust",
            "note:rumor",
        ],
        &envs,
    );
    assert_success(&whatif, "whatif --output json");
    let whatif = stdout_json(&whatif);
    assert_eq!(whatif["schema_version"], 1);
    assert_eq!(whatif["status"], "ok");
    assert_eq!(whatif["tool"], "whatif");
    assert_eq!(whatif["changed"], true);
    assert_eq!(whatif["policy"]["distrusted_sources"][0], "note:rumor");
    assert_eq!(whatif["base"][0]["value"]["text"], "coffee");
    assert_eq!(whatif["counterfactual"][0]["value"]["text"], "tea");
    assert!(
        !whatif["diffs"].as_array().expect("diffs").is_empty(),
        "{whatif}"
    );

    // Text mode reads as a report; the real fold is untouched (read-only).
    let text = run_dent8(
        &[
            "whatif",
            "person:alice",
            "favorite_drink",
            "--distrust",
            "note:rumor",
        ],
        &envs,
    );
    assert_success(&text, "whatif text");
    assert!(stdout(&text).contains("under policy"), "{}", stdout(&text));
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
    assert_eq!(stdout_json(&explain)["value"]["text"], "coffee");

    // No policy knob -> invalid, with the machine-readable code.
    let vacuous = run_dent8(
        &[
            "--output",
            "json",
            "whatif",
            "person:alice",
            "favorite_drink",
        ],
        &envs,
    );
    assert_eq!(vacuous.status.code(), Some(2));
    let vacuous = stdout_json(&vacuous);
    assert_eq!(vacuous["status"], "invalid");
    assert_eq!(vacuous["code"], "invalid-argument");
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
                "low",
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
    assert_eq!(replay["events"][0]["kind"], "fact.asserted");
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
    // A live dispute reports `contested`, not `ok` — the count and the status must agree.
    assert_eq!(conflicts["status"], "contested");
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
    assert_eq!(eval["comparison"]["ok"], true);
    assert_eq!(eval["comparison"]["axis_count"], 6);
    assert_eq!(eval["comparison"]["dent8_hold_count"], 6);
    let axes = eval["comparison"]["axes"]
        .as_array()
        .expect("comparison axes");
    assert_eq!(axes.len(), 6);
    assert!(
        axes.iter().all(|axis| {
            if axis["family"] == "positive_control" {
                axis["dent8_holds"] == true
                    && axis["zep_holds"] == true
                    && axis["mem0_holds"] == true
            } else {
                axis["dent8_holds"] == true
                    && axis["zep_holds"] == false
                    && axis["mem0_holds"] == false
            }
        }),
        "{eval}"
    );
}

// The demo initializes a `--store sqlite` project (the stock-install story), so the binary
// under test must carry the sqlite feature — a --no-default-features build cannot run it.
#[cfg(feature = "sqlite")]
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
    // The assertion round-trips its authority as `high`, so it is a signed above-agent write
    // (signed identities are source:*-scoped, so the writer is source:alice). The weak
    // supersession stays an unsigned agent-tier write so the firewall's authority arbitration —
    // not the identity gate — rejects it (code `insufficient-authority`).
    let id = SigningId::provision(&temp, "source:alice", &log);

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
            "source:alice",
        ],
        &id.env_for(&log),
    );
    assert_success(&asserted, "assert --output json");
    let asserted = stdout_json(&asserted);
    assert_eq!(asserted["schema_version"], 1);
    assert_eq!(asserted["status"], "accepted");
    assert_eq!(asserted["tool"], "assert");
    assert_eq!(asserted["accepted"], true);
    assert_eq!(asserted["subject"]["key"], "alice");
    assert_eq!(asserted["predicate"], "favorite_drink");
    assert_eq!(asserted["value"]["text"], "tea");
    assert_eq!(asserted["authority"], "high");
    assert_eq!(asserted["source"], "source:alice");

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
    // Error JSON goes to stdout (a nonzero exit signals failure); stderr stays clean.
    assert!(stderr(&rejected).is_empty(), "{}", stderr(&rejected));
    let rejected = serde_json::from_slice::<Value>(&rejected.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            stdout(&rejected),
            stderr(&rejected)
        )
    });
    assert_eq!(rejected["schema_version"], 1);
    assert_eq!(rejected["status"], "rejected");
    // The machine-readable cause: a low-authority supersession classifies from the typed
    // firewall error, so an agent branches on the token instead of parsing the prose.
    assert_eq!(rejected["code"], "insufficient-authority");
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
                "low",
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
            "--basis",
            "person:alice",
            "favorite_drink",
            "--authority",
            "low",
            "--source",
            "assistant:local",
        ],
        &envs,
    );
    assert_success(&derived, "derive --output json");
    let derived = stdout_json(&derived);
    assert_eq!(derived["status"], "accepted");
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
    assert_eq!(add["max_authority"], "high");
    assert_eq!(add["issuer"], "owner");
    assert_eq!(add["scope"], "project:dent8");
    assert_eq!(add["issuer_enforced"], true);
    assert_eq!(add["scope_enforced"], true);

    let listed = run_dent8(&["--output", "json", "authority", "list"], &envs);
    assert_success(&listed, "authority list --output json after add");
    let listed = stdout_json(&listed);
    assert_eq!(listed["registry_present"], true);
    assert_eq!(listed["enforcement"], "deny_by_default");
    assert_eq!(listed["count"], 1);
    assert_eq!(listed["sources"][0]["source"], "source:codex");
    assert_eq!(listed["sources"][0]["max_authority"], "high");
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
                "low",
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
                "--basis",
                "person:alice",
                "favorite_drink",
                "--authority",
                "low",
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
                "low",
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
    assert_eq!(verify["status"], "integrity_issues");
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

    let snapshot = run_dent8(&["--output", "json", "snapshot"], &envs);
    assert_eq!(snapshot.status.code(), Some(1));
    assert!(stderr(&snapshot).is_empty(), "{}", stderr(&snapshot));
    let snapshot = stdout_json(&snapshot);
    assert_eq!(snapshot["status"], "integrity_issues");
    assert_eq!(snapshot["verify"]["ok"], false);
    assert!(
        snapshot["verify"]["findings"]
            .as_array()
            .expect("snapshot verify findings")
            .iter()
            .any(|finding| finding
                .as_str()
                .is_some_and(|text| text.contains("TAINTED"))),
        "{snapshot}"
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
    assert!(stderr(&output).contains("has no `--output json` result"));

    let daemon_serve = run_dent8(&["--output", "json", "daemon", "serve"], &envs);
    assert_eq!(daemon_serve.status.code(), Some(2));
    assert!(stdout(&daemon_serve).is_empty());
    assert!(stderr(&daemon_serve).contains("has no `--output json` result"));

    // `witness serve` DOES stream NDJSON now; even its setup failure (no signing key here)
    // is a machine-readable line on stderr, not prose.
    {
        let witness_serve = run_dent8(&["--output", "json", "witness", "serve"], &envs);
        assert_eq!(witness_serve.status.code(), Some(1));
        assert!(stdout(&witness_serve).is_empty());
        let error: Value = serde_json::from_str(stderr(&witness_serve).trim())
            .expect("serve setup failure should be one JSON line");
        assert_eq!(error["event"], "error", "{}", stderr(&witness_serve));
        assert_eq!(error["tool"], "witness serve");
    }
}

/// The sorted `(subject, predicate, value-display)` tuples the store currently believes, read
/// through `dent8 context -o json`. Used to assert import/export round-trip stability.
fn believed_facts(log: &str) -> Vec<(String, String, String)> {
    let envs = [("DENT8_LOG", log)];
    let context = run_dent8(&["--output", "json", "context"], &envs);
    assert_success(&context, "context -o json");
    let json = stdout_json(&context);
    let mut facts: Vec<(String, String, String)> = json["facts"]
        .as_array()
        .expect("facts array")
        .iter()
        .map(|fact| {
            (
                format!(
                    "{}:{}",
                    fact["subject"]["kind"].as_str().unwrap_or_default(),
                    fact["subject"]["key"].as_str().unwrap_or_default()
                ),
                fact["predicate"].as_str().unwrap_or_default().to_string(),
                fact["value"]["display"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect();
    facts.sort();
    facts
}

#[test]
fn export_target_writes_a_managed_block_and_import_round_trips() {
    let temp = TempDir::new();
    let source_log = temp.file("source.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &source_log);
    let claude = temp.file("CLAUDE.md");
    let claude_path = claude.to_string_lossy().into_owned();

    // Seed the source store with two believed facts through the normal firewall path.
    for (predicate, value, authority) in [
        ("test_command", "cargo test --workspace", "high"),
        ("uses_database", "postgres", "medium"),
    ] {
        let asserted = run_dent8(
            &[
                "assert",
                "repo:demo",
                predicate,
                value,
                "--authority",
                authority,
                "--source",
                "source:human",
            ],
            &id.env_for(&source_log),
        );
        assert_success(&asserted, "seed assert");
    }

    // Hand-authored prose the export must not disturb.
    fs::write(&claude, "# CLAUDE.md\n\nHand-authored intro.\n").expect("seed CLAUDE.md");

    let exported = run_dent8(
        &[
            "--output",
            "json",
            "export",
            "--target",
            claude_path.as_str(),
        ],
        &id.env_for(&source_log),
    );
    assert_success(&exported, "export --target");
    let exported = stdout_json(&exported);
    assert_eq!(exported["tool"], "export");
    assert_eq!(exported["format"], "native-memory");
    assert_eq!(exported["facts_written"], 2);
    assert_eq!(exported["block"], "appended");

    let file = fs::read_to_string(&claude).expect("read exported CLAUDE.md");
    assert!(
        file.starts_with("# CLAUDE.md\n\nHand-authored intro.\n"),
        "{file}"
    );
    assert!(file.contains("BEGIN dent8 managed block"), "{file}");
    assert!(file.contains("dent8://repo/demo/test_command"), "{file}");
    assert!(file.contains("= \"cargo test --workspace\""), "{file}");

    // Import into a fresh store and confirm the believed set matches the source store.
    let imported_log = temp.file("imported.jsonl").to_string_lossy().into_owned();
    let imported = run_dent8(
        &["--output", "json", "import", claude_path.as_str()],
        &id.env_for(&imported_log),
    );
    assert_success(&imported, "import");
    let imported = stdout_json(&imported);
    assert_eq!(imported["imported"], 2, "{imported}");
    assert_eq!(imported["accepted"], 2, "{imported}");
    assert_eq!(
        believed_facts(&source_log),
        believed_facts(&imported_log),
        "import must reconstruct the source store's believed facts"
    );

    // Round-trip stability: export the imported store to a new file, import again into a third
    // store; the believed set is identical (stable).
    let claude2 = temp.file("CLAUDE2.md");
    let claude2_path = claude2.to_string_lossy().into_owned();
    let export2 = run_dent8(
        &["export", "--target", claude2_path.as_str()],
        &id.env_for(&imported_log),
    );
    assert_success(&export2, "second export");
    let third_log = temp.file("third.jsonl").to_string_lossy().into_owned();
    let import2 = run_dent8(&["import", claude2_path.as_str()], &id.env_for(&third_log));
    assert_success(&import2, "second import");
    assert_eq!(
        believed_facts(&imported_log),
        believed_facts(&third_log),
        "round-trip (import -> export -> import) must be stable"
    );
}

#[test]
fn export_target_is_idempotent_and_preserves_surrounding_prose() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &log);
    let claude = temp.file("CLAUDE.md");

    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "test_command",
            "cargo test",
            "--authority",
            "high",
            "--source",
            "source:human",
        ],
        &id.env_for(&log),
    );
    assert_success(&asserted, "seed assert");

    // A file that already carries a managed block wedged between human prose.
    let before = "# Title\n\nPrologue prose.\n\n";
    let stale_block = "<!-- BEGIN dent8 managed block (generated by `dent8 export`; edits inside are overwritten) -->\nSTALE — must be replaced\n<!-- END dent8 managed block -->";
    let after = "\n## Epilogue\n\nClosing prose that must survive.\n";
    fs::write(&claude, format!("{before}{stale_block}{after}")).expect("seed CLAUDE.md");

    let claude_path = claude.to_string_lossy().into_owned();
    let refreshed = run_dent8(
        &[
            "--output",
            "json",
            "export",
            "--target",
            claude_path.as_str(),
        ],
        &id.env_for(&log),
    );
    assert_success(&refreshed, "export refresh");
    assert_eq!(stdout_json(&refreshed)["block"], "refreshed");

    let file = fs::read_to_string(&claude).expect("read refreshed file");
    assert!(
        file.starts_with(before),
        "prose before block not preserved:\n{file}"
    );
    assert!(
        file.ends_with(after),
        "prose after block not preserved:\n{file}"
    );
    assert!(
        !file.contains("STALE"),
        "stale block content leaked:\n{file}"
    );
    assert!(file.contains("dent8://repo/demo/test_command"), "{file}");

    // Export again: the file is byte-for-byte identical (no wall-clock drift in the block).
    let first = file;
    let again = run_dent8(
        &["export", "--target", claude_path.as_str()],
        &id.env_for(&log),
    );
    assert_success(&again, "second export");
    let second = fs::read_to_string(&claude).expect("read second export");
    assert_eq!(first, second, "export must be idempotent");
}

#[test]
fn export_target_refuses_a_stray_begin_sentinel_and_leaves_the_file_unchanged() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &log);
    let claude = temp.file("CLAUDE.md");
    let envs = id.env_for(&log);

    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "db",
            "postgres",
            "--authority",
            "high",
            "--source",
            "source:human",
        ],
        &envs,
    );
    assert_success(&asserted, "seed assert");

    // A file with an orphan BEGIN sentinel (no matching END) wrapping human content. Appending a
    // second block here would let a later export match the orphan BEGIN and delete the content
    // between it and the new END — so export must refuse and leave the file byte-for-byte intact.
    let orphan = "# CLAUDE.md\n\n<!-- BEGIN dent8 managed block (generated by `dent8 export`; edits inside are overwritten) -->\nprecious human content\n";
    fs::write(&claude, orphan).expect("seed CLAUDE.md");
    let before = read_file(&claude);

    let claude_path = claude.to_string_lossy().into_owned();
    let exported = run_dent8(
        &[
            "--output",
            "json",
            "export",
            "--target",
            claude_path.as_str(),
        ],
        &envs,
    );
    assert_eq!(exported.status.code(), Some(1), "{}", stderr(&exported));
    assert_eq!(stdout_json(&exported)["status"], "rejected");
    assert_eq!(
        read_file(&claude),
        before,
        "a refused export must leave the file byte-for-byte unchanged"
    );
}

#[test]
fn export_import_round_trips_a_value_containing_the_receipt_token() {
    let temp = TempDir::new();
    let source_log = temp.file("source.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &source_log);
    let claude = temp.file("CLAUDE.md");
    let claude_path = claude.to_string_lossy().into_owned();

    // A Text value that itself contains the literal receipt-comment token.
    let tricky = "a value with a  <!-- dent8 receipt look-alike inside";
    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "note",
            tricky,
            "--authority",
            "high",
            "--source",
            "source:human",
        ],
        &id.env_for(&source_log),
    );
    assert_success(&asserted, "seed tricky fact");

    let exported = run_dent8(
        &["export", "--target", claude_path.as_str()],
        &id.env_for(&source_log),
    );
    assert_success(&exported, "export");

    let imported_log = temp.file("imported.jsonl").to_string_lossy().into_owned();
    let imported = run_dent8(
        &["--output", "json", "import", claude_path.as_str()],
        &id.env_for(&imported_log),
    );
    assert_success(&imported, "import");
    assert_eq!(
        stdout_json(&imported)["accepted"],
        1,
        "{}",
        stdout(&imported)
    );
    assert_eq!(
        believed_facts(&source_log),
        believed_facts(&imported_log),
        "a value containing the receipt token must survive import->export->import intact"
    );
    // And the recovered value is exactly the original (not truncated at the look-alike token).
    assert_eq!(believed_facts(&imported_log)[0].2, format!("{tricky:?}"));
}

#[test]
fn export_ignores_a_fenced_example_block_and_appends_fresh() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &log);
    let claude = temp.file("CLAUDE.md");
    let envs = id.env_for(&log);

    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "test_command",
            "cargo test",
            "--authority",
            "high",
            "--source",
            "source:human",
        ],
        &envs,
    );
    assert_success(&asserted, "seed assert");

    // A file whose only BEGIN/END sentinels live inside a fenced example (as docs/native-memory.md
    // does). The fenced pair must be ignored → treated as "no live block" → fresh block appended,
    // and the fenced example interior must survive byte-for-byte.
    let fenced = "# CLAUDE.md\n\nExample of the managed block:\n\n```text\n<!-- BEGIN dent8 managed block (generated by `dent8 export`; edits inside are overwritten) -->\nEXAMPLE BODY — must not be overwritten\n<!-- END dent8 managed block -->\n```\n";
    fs::write(&claude, fenced).expect("seed CLAUDE.md");

    let claude_path = claude.to_string_lossy().into_owned();
    let exported = run_dent8(
        &[
            "--output",
            "json",
            "export",
            "--target",
            claude_path.as_str(),
        ],
        &envs,
    );
    assert_success(&exported, "export past fenced example");
    assert_eq!(stdout_json(&exported)["block"], "appended");

    let file = String::from_utf8(read_file(&claude)).expect("utf8");
    assert!(
        file.starts_with(fenced),
        "fenced example not preserved:\n{file}"
    );
    assert!(
        file.contains("EXAMPLE BODY — must not be overwritten"),
        "fenced example interior overwritten:\n{file}"
    );
    assert!(
        file.contains("dent8://repo/demo/test_command"),
        "fresh managed block not appended:\n{file}"
    );
}

#[test]
fn export_refreshes_the_real_block_and_preserves_a_fenced_example() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &log);
    let claude = temp.file("CLAUDE.md");
    let envs = id.env_for(&log);

    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "test_command",
            "cargo test",
            "--authority",
            "high",
            "--source",
            "source:human",
        ],
        &envs,
    );
    assert_success(&asserted, "seed assert");

    // A real (non-fenced) managed block ahead of a fenced example of the same sentinels.
    let real = "<!-- BEGIN dent8 managed block (generated by `dent8 export`; edits inside are overwritten) -->\nSTALE — must be replaced\n<!-- END dent8 managed block -->";
    let fenced = "\n\n## Example\n\n```text\n<!-- BEGIN dent8 managed block (generated by `dent8 export`; edits inside are overwritten) -->\nFENCED SAMPLE — must survive\n<!-- END dent8 managed block -->\n```\n";
    fs::write(&claude, format!("# CLAUDE.md\n\n{real}{fenced}")).expect("seed CLAUDE.md");

    let claude_path = claude.to_string_lossy().into_owned();
    let exported = run_dent8(
        &[
            "--output",
            "json",
            "export",
            "--target",
            claude_path.as_str(),
        ],
        &envs,
    );
    assert_success(&exported, "refresh real block");
    assert_eq!(stdout_json(&exported)["block"], "refreshed");

    let file = String::from_utf8(read_file(&claude)).expect("utf8");
    assert!(!file.contains("STALE"), "stale real block leaked:\n{file}");
    assert!(
        file.contains("dent8://repo/demo/test_command"),
        "real block not refreshed:\n{file}"
    );
    assert!(
        file.contains("FENCED SAMPLE — must survive"),
        "fenced example overwritten:\n{file}"
    );
    assert!(
        file.ends_with(fenced),
        "fenced example not preserved:\n{file}"
    );
}

#[test]
fn export_into_a_crlf_file_emits_a_crlf_block_and_round_trips() {
    let temp = TempDir::new();
    let source_log = temp.file("source.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &source_log);
    let claude = temp.file("CLAUDE.md");
    let claude_path = claude.to_string_lossy().into_owned();

    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "test_command",
            "cargo test --workspace",
            "--authority",
            "high",
            "--source",
            "source:human",
        ],
        &id.env_for(&source_log),
    );
    assert_success(&asserted, "seed assert");

    // A CRLF target file: the emitted managed block must use CRLF so the file stays consistent.
    fs::write(&claude, "# CLAUDE.md\r\n\r\nHand-authored intro.\r\n").expect("seed CRLF CLAUDE.md");

    let exported = run_dent8(
        &["export", "--target", claude_path.as_str()],
        &id.env_for(&source_log),
    );
    assert_success(&exported, "export into CRLF file");

    let bytes = read_file(&claude);
    let file = String::from_utf8(bytes).expect("utf8");
    assert!(
        file.starts_with("# CLAUDE.md\r\n\r\nHand-authored intro.\r\n"),
        "existing CRLF prose not preserved:\n{file:?}"
    );
    assert!(
        file.contains("edits inside are overwritten) -->\r\n"),
        "managed block BEGIN line did not use CRLF:\n{file:?}"
    );
    assert!(
        file.contains("<!-- END dent8 managed block -->"),
        "END sentinel missing:\n{file:?}"
    );
    // No lone LF anywhere: every `\n` must be preceded by `\r`.
    assert!(
        !file
            .bytes()
            .zip(file.bytes().skip(1))
            .any(|(a, b)| a != b'\r' && b == b'\n')
            && !file.starts_with('\n'),
        "block introduced a lone LF (mixed endings):\n{file:?}"
    );

    // CRLF round-trip: import the CRLF file, re-export, import again — believed set is stable.
    let imported_log = temp.file("imported.jsonl").to_string_lossy().into_owned();
    let imported = run_dent8(
        &["--output", "json", "import", claude_path.as_str()],
        &id.env_for(&imported_log),
    );
    assert_success(&imported, "import CRLF file");
    assert_eq!(
        stdout_json(&imported)["accepted"],
        1,
        "{}",
        stdout(&imported)
    );
    assert_eq!(
        believed_facts(&source_log),
        believed_facts(&imported_log),
        "CRLF export must import back to the same believed facts"
    );
}

#[test]
fn export_refuses_a_file_that_ends_inside_an_unclosed_fence_and_never_grows_it() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &log);
    let claude = temp.file("CLAUDE.md");
    let envs = id.env_for(&log);

    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "test_command",
            "cargo test",
            "--authority",
            "high",
            "--source",
            "source:human",
        ],
        &envs,
    );
    assert_success(&asserted, "seed assert");

    // An UNCLOSED ``` fence before a real managed block: the never-closed fence swallows the real
    // block, so the fence-aware scan sees zero live sentinels. Appending would nest a fresh block
    // inside the open fence, and each repeated export would append again (growing 1→2→3…). Export
    // must REFUSE (nonzero exit) and leave the file byte-for-byte unchanged.
    let unclosed = "# CLAUDE.md\n\n```text\nexample snippet\n<!-- BEGIN dent8 managed block (generated by `dent8 export`; edits inside are overwritten) -->\nOLD\n<!-- END dent8 managed block -->\n";
    fs::write(&claude, unclosed).expect("seed CLAUDE.md");
    let before = read_file(&claude);

    let claude_path = claude.to_string_lossy().into_owned();
    for attempt in 0..2 {
        let exported = run_dent8(
            &[
                "--output",
                "json",
                "export",
                "--target",
                claude_path.as_str(),
            ],
            &envs,
        );
        assert_eq!(
            exported.status.code(),
            Some(1),
            "export {attempt} must be refused: {}",
            stderr(&exported)
        );
        let json = stdout_json(&exported);
        assert_eq!(json["status"], "rejected");
        // Repeated exports must not grow the file: it stays byte-for-byte identical.
        assert_eq!(
            read_file(&claude),
            before,
            "a refused export must leave the file unchanged (attempt {attempt})"
        );
    }
}

#[test]
fn export_target_flags_contested_facts() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let claude = temp.file("AGENTS.md");
    let envs = [("DENT8_LOG", log.as_str())];

    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "db",
            "postgres",
            "--authority",
            "low",
            "--source",
            "source:human",
        ],
        &envs,
    );
    assert_success(&asserted, "assert");
    let contradicted = run_dent8(
        &[
            "contradict",
            "repo:demo",
            "db",
            "mysql",
            "--authority",
            "low",
            "--source",
            "source:ci",
        ],
        &envs,
    );
    assert_success(&contradicted, "contradict");

    let claude_path = claude.to_string_lossy().into_owned();
    let exported = run_dent8(&["export", "--target", claude_path.as_str()], &envs);
    assert_success(&exported, "export contested");
    let file = fs::read_to_string(&claude).expect("read AGENTS.md");
    assert!(
        file.contains("[contested"),
        "contested fact must be flagged:\n{file}"
    );
}

#[test]
fn import_applies_all_three_rules_and_reports_skips() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    // The managed-block fact re-imports at `authority=medium source=source:human` (an above-agent
    // write on `repo.test_command`, whose Medium floor forbids lowering it), so import runs under a
    // signed source:human identity; the unattributed facts inherit that signed grant's defaults.
    let id = SigningId::provision(&temp, "source:human", &log);
    let file = temp.file("CLAUDE.md");
    let contents = concat!(
        "# Project notes\n",
        "Free prose that must be skipped.\n",
        "\n",
        "Durable: dent8://repo/demo/build_tool = \"cargo\"\n",
        "\n",
        "```dent8\n",
        "{\"subject\":\"repo:demo\",\"predicate\":\"uses_database\",\"value\":\"postgres\"}\n",
        "```\n",
        "\n",
        "<!-- BEGIN dent8 managed block (generated by `dent8 export`; edits inside are overwritten) -->\n",
        "### repo:demo\n",
        "- `dent8://repo/demo/test_command` = \"cargo test\"  <!-- dent8 receipt fact=fact:repo:demo:test_command:1 event_hash=abc authority=medium source=source:human -->\n",
        "<!-- END dent8 managed block -->\n",
    );
    fs::write(&file, contents).expect("seed import file");

    let file_path = file.to_string_lossy().into_owned();
    let imported = run_dent8(
        &["--output", "json", "import", file_path.as_str()],
        &id.env_for(&log),
    );
    assert_success(&imported, "import three rules");
    let imported = stdout_json(&imported);
    assert_eq!(imported["accepted"], 3, "{imported}");
    assert!(
        imported["skipped"].as_u64().expect("skipped") >= 2,
        "{imported}"
    );
    let rules: Vec<&str> = imported["results"]
        .as_array()
        .expect("results")
        .iter()
        .map(|r| r["rule"].as_str().unwrap_or_default())
        .collect();
    assert!(rules.contains(&"inline-marker"), "{imported}");
    assert!(rules.contains(&"dent8-block"), "{imported}");
    assert!(rules.contains(&"managed-block"), "{imported}");
}

#[test]
fn import_dry_run_writes_nothing() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let file = temp.file("CLAUDE.md");
    fs::write(&file, "Durable: dent8://repo/demo/build_tool = \"cargo\"\n")
        .expect("seed import file");

    let file_path = file.to_string_lossy().into_owned();
    let dry = run_dent8(
        &[
            "--output",
            "json",
            "import",
            "--dry-run",
            file_path.as_str(),
        ],
        &[("DENT8_LOG", log.as_str())],
    );
    assert_success(&dry, "import --dry-run");
    let dry = stdout_json(&dry);
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["accepted"], 0, "{dry}");
    assert!(
        !std::path::Path::new(&log).exists(),
        "dry run must not create the store"
    );
}

#[test]
fn import_cannot_bypass_the_authority_ceiling() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let authority = temp.file("authority.json");
    fs::write(
        &authority,
        r#"{"sources":{"source:agent":{"max_authority":"low"},"source:human":{"max_authority":"high"}}}"#,
    )
    .expect("seed authority registry");
    let authority_path = authority.to_string_lossy().into_owned();
    // The High seed is an above-agent write and needs a signed source:human identity; the
    // over-ceiling proposal (source:agent) is refused at the registry ceiling before the identity
    // gate, so capture and import still reject it with the identical message.
    let id = SigningId::provision(&temp, "source:human", &log);
    let mut envs = id.env_for(&log);
    envs.push(("DENT8_AUTHORITY", authority_path.as_str()));

    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "db",
            "postgres",
            "--authority",
            "high",
            "--source",
            "source:human",
        ],
        &envs,
    );
    assert_success(&asserted, "seed high fact");

    let over_ceiling = r#"{"op":"supersede","subject":"repo:demo","predicate":"db","value":"mysql","authority":"high","source":"source:agent"}"#;

    // The same proposal through `capture` — the reference funnel.
    let captured = run_dent8_stdin(&["--output", "json", "capture"], over_ceiling, &envs);
    let captured = stdout_json(&captured);
    let capture_message = captured["results"][0]["message"]
        .as_str()
        .expect("capture message")
        .to_string();

    // The same proposal through `import` (fenced dent8 block) — must be rejected identically.
    let file = temp.file("CLAUDE.md");
    fs::write(&file, format!("```dent8\n{over_ceiling}\n```\n")).expect("seed import file");
    let file_path = file.to_string_lossy().into_owned();
    let imported = run_dent8(&["--output", "json", "import", file_path.as_str()], &envs);
    assert_eq!(imported.status.code(), Some(1), "{}", stderr(&imported));
    let imported = stdout_json(&imported);
    assert_eq!(imported["rejected"], 1, "{imported}");
    assert_eq!(imported["accepted"], 0, "{imported}");
    assert_eq!(
        imported["results"][0]["message"]
            .as_str()
            .expect("import message"),
        capture_message,
        "import must be rejected with the same OpError as capture"
    );
}

#[test]
fn native_memory_guard_blocks_raw_writes_but_export_block_is_recognized() {
    let temp = TempDir::new();
    let root = temp.path.clone();
    fs::create_dir(root.join(".git")).expect("mark repo root");
    let dir = root.join(".dent8");
    fs::create_dir(&dir).expect("create .dent8");
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let id = SigningId::provision(&temp, "source:human", &log);
    let envs = id.env_for(&log);

    // (i) The PreToolUse guard still exits 2 on a raw agent Write of arbitrary prose to CLAUDE.md.
    let payload = r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/repo/CLAUDE.md","content":"just arbitrary prose"}}"#;
    let guarded = run_dent8_stdin(
        &["hook", "native-memory-guard"],
        payload,
        &[
            ("DENT8_HOOK_MODE", "guard-native-memory-write"),
            ("DENT8_HOOK_ENFORCE", "1"),
            ("DENT8_LOG", log.as_str()),
        ],
    );
    assert_eq!(guarded.status.code(), Some(2), "{}", stderr(&guarded));
    assert!(stdout(&guarded).is_empty(), "guard must not write stdout");

    // (ii) A dent8-managed export block is recognized as receipt-bearing by the audit path.
    let asserted = run_dent8(
        &[
            "assert",
            "repo:demo",
            "test_command",
            "cargo test",
            "--authority",
            "high",
            "--source",
            "source:human",
        ],
        &envs,
    );
    assert_success(&asserted, "seed fact");
    let claude = root.join("CLAUDE.md");
    let claude_path = claude.to_string_lossy().into_owned();
    let exported = run_dent8(&["export", "--target", claude_path.as_str()], &envs);
    assert_success(&exported, "export managed block");

    let root_path = root.to_string_lossy().into_owned();
    let dir_path = dir.to_string_lossy().into_owned();
    let scan = run_dent8(
        &[
            "--output",
            "json",
            "native",
            "scan",
            "--agent",
            "claude-code",
            "--root",
            root_path.as_str(),
            "--dir",
            dir_path.as_str(),
        ],
        &envs,
    );
    assert_success(&scan, "native scan");
    let scan = stdout_json(&scan);
    let claude_file = scan["files"]
        .as_array()
        .expect("scan files")
        .iter()
        .find(|file| {
            file["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("CLAUDE.md"))
        })
        .expect("CLAUDE.md in scan");
    assert_eq!(
        claude_file["has_receipt_marker"], true,
        "the managed block must read as receipt-bearing: {scan}"
    );
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
        stderr(&exported).is_empty(),
        "export feature error JSON goes to stdout, not stderr:\n{}",
        stderr(&exported)
    );
    let exported = stdout_json(&exported);
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
    // The believed incumbent is a High (above-agent) write and needs a signed identity
    // (source:alice). The weak challenger stays an unsigned agent-tier write so it reaches — and is
    // refused by — the firewall's authority arbitration (not the identity gate).
    let id = SigningId::provision(&temp, "source:alice", &log);

    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_drink",
                "tea",
                "--authority=high",
                "--source=source:alice",
            ],
            &id.env_for(&log),
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
fn valid_time_intervals_bound_freshness_and_validate() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    // A fact with an asserted validity window in the past: fresh inside the window
    // (judged with --valid-at), stale at and after its valid_to.
    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_drink",
                "tea",
                "--authority=low",
                "--source=user:alice",
                "--valid-from=1000",
                "--valid-to=2000",
            ],
            &envs,
        ),
        "assert with validity window",
    );
    let inside = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "person:alice",
            "favorite_drink",
            "--valid-at",
            "1500",
        ],
        &envs,
    );
    assert_success(&inside, "explain inside window");
    let receipt = stdout_json(&inside);
    assert_eq!(receipt["fresh"], true, "{}", stdout(&inside));
    assert_eq!(receipt["expires_at"], 2000);
    let after = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "person:alice",
            "favorite_drink",
            "--valid-at",
            "2000",
        ],
        &envs,
    );
    assert_eq!(
        stdout_json(&after)["fresh"],
        false,
        "expiry is inclusive at the validity bound"
    );
    // At wall-clock now (far past the window) the text read is headline-stale.
    let now_read = run_dent8(&["explain", "person:alice", "favorite_drink"], &envs);
    assert_success(&now_read, "explain now");
    assert!(stdout(&now_read).contains("stale"), "{}", stdout(&now_read));

    // An empty/inverted interval is rejected at the firewall.
    let inverted = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_snack",
            "apple",
            "--authority=low",
            "--source=user:alice",
            "--valid-from=2000",
            "--valid-to=1000",
        ],
        &envs,
    );
    assert_eq!(inverted.status.code(), Some(1));
    assert!(
        stderr(&inverted).contains("valid_to must be after valid_from"),
        "{}",
        stderr(&inverted)
    );
}

#[test]
fn a_future_valid_from_reads_not_yet_valid() {
    // ADR 0016 lower bound: a fact whose valid_from is in the future is not-yet-valid, so it
    // reads as not-fresh (distinct from stale) until then.
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:proj",
                "feature",
                "enabled",
                "--authority=low",
                "--source=user:owner",
                "--valid-from=5000",
            ],
            &envs,
        ),
        "assert with a future valid_from",
    );

    // Read before valid_from: not yet valid, not fresh — and NOT the stale wording.
    let before = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "repo:proj",
            "feature",
            "--valid-at",
            "1000",
        ],
        &envs,
    );
    assert_success(&before, "explain before valid_from");
    let receipt = stdout_json(&before);
    assert_eq!(receipt["fresh"], false, "{}", stdout(&before));
    assert_eq!(receipt["not_yet_valid"], true);
    assert_eq!(receipt["valid_from"], 5000);
    let before_text = run_dent8(
        &["explain", "repo:proj", "feature", "--valid-at", "1000"],
        &envs,
    );
    assert!(
        stdout(&before_text).contains("not yet valid") && !stdout(&before_text).contains("stale"),
        "{}",
        stdout(&before_text)
    );

    // Read at/after valid_from: fresh again.
    let after = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "repo:proj",
            "feature",
            "--valid-at",
            "5000",
        ],
        &envs,
    );
    assert_eq!(stdout_json(&after)["fresh"], true, "{}", stdout(&after));
    assert_eq!(stdout_json(&after)["not_yet_valid"], false);

    // A valid_to expiry now reads "no longer valid" (accurate), not the old "TTL elapsed".
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:proj",
                "window",
                "open",
                "--authority=low",
                "--source=user:owner",
                "--valid-from=1000",
                "--valid-to=2000",
            ],
            &envs,
        ),
        "assert a bounded window",
    );
    let expired = run_dent8(
        &["explain", "repo:proj", "window", "--valid-at", "5000"],
        &envs,
    );
    assert!(
        stdout(&expired).contains("no longer valid") && !stdout(&expired).contains("TTL elapsed"),
        "{}",
        stdout(&expired)
    );
}

#[test]
fn facts_list_flags_freshness_and_derive_stamps_validity() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];

    // A fresh fact, and a derived fact stamped with an already-elapsed validity window —
    // proving `derive` threads --valid-from/--valid-to (ADR 0016) onto the derived assertion.
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:proj",
                "db",
                "postgres",
                "--authority=low",
                "--source=user:o",
            ],
            &envs,
        ),
        "assert source",
    );
    assert_success(
        &run_dent8(
            &[
                "derive",
                "repo:proj",
                "summary",
                "uses-postgres",
                "--basis",
                "repo:proj",
                "db",
                "--authority=low",
                "--source=user:o",
                "--valid-from=1000",
                "--valid-to=2000",
            ],
            &envs,
        ),
        "derive with a bounded (elapsed) validity window",
    );

    // `facts list` flags freshness per stream: db fresh, summary stale (past valid_to).
    let text = run_dent8(&["facts", "list"], &envs);
    assert_success(&text, "facts list");
    assert!(
        stdout(&text).contains("/summary  (repo:proj summary)  [stale]")
            && stdout(&text).contains("/db  (repo:proj db)\n"),
        "{}",
        stdout(&text)
    );

    let json = run_dent8(&["--output", "json", "facts", "list"], &envs);
    assert_success(&json, "facts list json");
    let facts = stdout_json(&json);
    let freshness = |pred: &str| {
        facts["facts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["predicate"] == pred)
            .unwrap_or_else(|| panic!("missing {pred}"))["freshness"]
            .as_str()
            .unwrap()
            .to_string()
    };
    assert_eq!(freshness("db"), "fresh");
    assert_eq!(freshness("summary"), "stale");
}

#[test]
fn as_of_reads_travel_to_the_store_as_it_stood() {
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
                "--authority=low",
                "--source=user:alice",
            ],
            &envs,
        ),
        "assert",
    );
    let mid = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("in i64 range");
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert_success(
        &run_dent8(
            &[
                "supersede",
                "person:alice",
                "favorite_drink",
                "coffee",
                "--authority=low",
                "--source=user:alice",
            ],
            &envs,
        ),
        "supersede",
    );

    // Now: the revision is believed. As of `mid`: the original is, and the replay shows
    // exactly the one event the store held then.
    let now_read = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "person:alice",
            "favorite_drink",
        ],
        &envs,
    );
    assert_eq!(stdout_json(&now_read)["value"]["text"], "coffee");
    let mid_arg = mid.to_string();
    let then_read = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "person:alice",
            "favorite_drink",
            "--as-of",
            &mid_arg,
        ],
        &envs,
    );
    assert_success(&then_read, "explain as-of");
    let receipt = stdout_json(&then_read);
    assert_eq!(receipt["value"]["text"], "tea", "{}", stdout(&then_read));
    assert_eq!(receipt["lifecycle"], "Active");
    let then_replay = run_dent8(
        &[
            "replay",
            "person:alice",
            "favorite_drink",
            "--as-of",
            &mid_arg,
        ],
        &envs,
    );
    assert_success(&then_replay, "replay as-of");
    assert!(
        stdout(&then_replay).contains("(1 events)") && stdout(&then_replay).contains("believed"),
        "{}",
        stdout(&then_replay)
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one linear lifecycle: reject -> record -> dedup -> opt out
fn rejected_challenges_entrench_the_incumbent_and_are_replayable() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];
    // The believed incumbent is a High (above-agent) write needing a signed identity
    // (source:alice); the weak challengers stay unsigned agent-tier writes so the firewall's
    // arbitration refuses and records them (not the identity gate).
    let id = SigningId::provision(&temp, "source:alice", &log);

    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_drink",
                "tea",
                "--authority=high",
                "--source=source:alice",
            ],
            &id.env_for(&log),
        ),
        "assert",
    );

    // A low-authority supersession is rejected — and the loss is now evidence (ADR 0015).
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
        stderr(&rejected).contains("recorded the survived challenge"),
        "{}",
        stderr(&rejected)
    );

    let replayed = run_dent8(&["replay", "person:alice", "favorite_drink"], &envs);
    assert_success(&replayed, "replay");
    assert!(
        stdout(&replayed).contains("survived") && stdout(&replayed).contains("Supersession"),
        "{}",
        stdout(&replayed)
    );

    // The same challenger losing again does not double-count; a second challenger does.
    let again = run_dent8(
        &[
            "retract",
            "person:alice",
            "favorite_drink",
            "--authority",
            "low",
            "--source",
            "note:old",
        ],
        &envs,
    );
    assert_eq!(again.status.code(), Some(1));
    let second = run_dent8(
        &[
            "retract",
            "person:alice",
            "favorite_drink",
            "--authority",
            "low",
            "--source",
            "note:other",
        ],
        &envs,
    );
    assert_eq!(second.status.code(), Some(1));

    let explained = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "person:alice",
            "favorite_drink",
        ],
        &envs,
    );
    assert_success(&explained, "explain json");
    let receipt = stdout_json(&explained);
    assert_eq!(receipt["survived_challenges"], 2, "{}", stdout(&explained));
    assert_eq!(receipt["value"]["text"], "tea");

    // The record stream still verifies, and opting out stops recording.
    assert_success(&run_dent8(&["verify"], &envs), "verify");
    let muted = run_dent8(
        &[
            "retract",
            "person:alice",
            "favorite_drink",
            "--authority",
            "low",
            "--source",
            "note:third",
        ],
        &[
            ("DENT8_LOG", log.as_str()),
            ("DENT8_RECORD_CHALLENGES", "0"),
        ],
    );
    assert_eq!(muted.status.code(), Some(1));
    assert!(
        !stderr(&muted).contains("recorded the survived challenge"),
        "{}",
        stderr(&muted)
    );
    let recount = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "person:alice",
            "favorite_drink",
        ],
        &envs,
    );
    assert_eq!(stdout_json(&recount)["survived_challenges"], 2);
}

#[test]
fn the_entrenchment_gate_rejects_a_weaker_corroborated_replacement() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    // High (above-agent) writes now require signed identities, and signed identities are
    // source:*-scoped — so the two High backers write as source:alice/source:bob (was
    // user:alice/user:bob), each with its own signed bundle over the shared store log.
    let id_alice = SigningId::provision(&temp, "source:alice", &log);
    let id_bob = SigningId::provision(&temp, "source:bob", &log);
    let id_web = SigningId::provision(&temp, "source:web", &log);
    let mut gated = id_web.env_for(&log);
    gated.push(("DENT8_ENTRENCHMENT_GATE", "1"));

    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_drink",
                "tea",
                "--authority=high",
                "--source=source:alice",
            ],
            &id_alice.env_for(&log),
        ),
        "assert",
    );
    assert_success(
        &run_dent8(
            &[
                "reinforce",
                "person:alice",
                "favorite_drink",
                "--authority=high",
                "--source=source:bob",
            ],
            &id_bob.env_for(&log),
        ),
        "reinforce",
    );

    // Two High backers vs a fresh single-source equal-authority replacement: under the
    // gate that is an unearned supersession — rejected and recorded.
    let rejected = run_dent8(
        &[
            "supersede",
            "person:alice",
            "favorite_drink",
            "coffee",
            "--authority",
            "high",
            "--source",
            "source:web",
        ],
        &gated,
    );
    assert_eq!(rejected.status.code(), Some(1), "{}", stderr(&rejected));
    assert!(
        stderr(&rejected).contains("unearned supersession")
            && stderr(&rejected).contains("recorded the survived challenge"),
        "{}",
        stderr(&rejected)
    );
    let explained = run_dent8(
        &[
            "--output",
            "json",
            "explain",
            "person:alice",
            "favorite_drink",
        ],
        &id_web.env_for(&log),
    );
    assert_eq!(stdout_json(&explained)["value"]["text"], "tea");
    assert_eq!(stdout_json(&explained)["survived_challenges"], 1);

    // Without the gate the same equal-authority revision is admitted (default semantics).
    assert_success(
        &run_dent8(
            &[
                "supersede",
                "person:alice",
                "favorite_drink",
                "coffee",
                "--authority",
                "high",
                "--source",
                "source:web",
            ],
            &id_web.env_for(&log),
        ),
        "ungated supersede",
    );
}

#[test]
fn a_survived_challenge_hardens_a_fact_against_a_fresh_replacement() {
    // ADR 0017: survived challenges now count in the opt-in gate. Isolated from
    // corroboration via a Canonical incumbent with a single backer: contradicting it is a
    // rejected hard-alarm recorded as a survived challenge, and that survival alone (corr
    // stays 1) then makes a fresh equal-authority replacement unearned.
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    // Every write here is Canonical (above-agent) and must be signed to clear the identity gate and
    // reach arbitration; each source gets its own signed bundle over the shared store logs. The
    // incumbent asserter is source:owner (was user:owner — signed identities are source:*-scoped).
    let id_owner = SigningId::provision(&temp, "source:owner", &log);
    let id_web = SigningId::provision(&temp, "source:web", &log);
    let id_web2 = SigningId::provision(&temp, "source:web2", &log);
    let mut gated = id_web2.env_for(&log);
    gated.push(("DENT8_ENTRENCHMENT_GATE", "1"));

    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:proj",
                "database",
                "postgres",
                "--authority=canonical",
                "--source=source:owner",
            ],
            &id_owner.env_for(&log),
        ),
        "assert canonical",
    );

    // Before any survived challenge, earned entrenchment is 1 (the lone asserter), so the
    // gate admits an equal-authority replacement. Prove that on a separate clean stream.
    let temp0 = TempDir::new();
    let log0 = temp0.file("memory.jsonl").to_string_lossy().into_owned();
    let mut gated0 = id_web.env_for(&log0);
    gated0.push(("DENT8_ENTRENCHMENT_GATE", "1"));
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:proj",
                "database",
                "postgres",
                "--authority=canonical",
                "--source=source:owner",
            ],
            &id_owner.env_for(&log0),
        ),
        "assert canonical (control)",
    );
    assert_success(
        &run_dent8(
            &[
                "supersede",
                "repo:proj",
                "database",
                "mysql",
                "--authority=canonical",
                "--source=source:web",
            ],
            &gated0,
        ),
        "un-challenged fact yields to an equal-authority replacement",
    );

    // Back to the main stream: contradict the Canonical incumbent. A canonical contradiction
    // is a rejected hard-alarm, recorded as a survived challenge at Canonical.
    let contradicted = run_dent8(
        &[
            "contradict",
            "repo:proj",
            "database",
            "mysql",
            "--authority=canonical",
            "--source=source:web",
        ],
        &id_web.env_for(&log),
    );
    assert_eq!(
        contradicted.status.code(),
        Some(1),
        "{}",
        stderr(&contradicted)
    );
    assert!(
        stderr(&contradicted).contains("recorded the survived challenge"),
        "{}",
        stderr(&contradicted)
    );

    // Now the incumbent has corroboration 1 but earned entrenchment 2 (1 backer + 1 survived
    // Canonical challenge). A fresh Canonical replacement is rejected *purely* because it
    // survived a challenge — the message spells out the split.
    let blocked = run_dent8(
        &[
            "supersede",
            "repo:proj",
            "database",
            "mysql",
            "--authority=canonical",
            "--source=source:web2",
        ],
        &gated,
    );
    assert_eq!(blocked.status.code(), Some(1), "{}", stderr(&blocked));
    assert!(
        stderr(&blocked)
            .contains("earned entrenchment 2 at Canonical (1 corroborating source(s) + 1 survived challenge(s))"),
        "{}",
        stderr(&blocked)
    );
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
    assert!(stderr(&output).contains("missing --authority"));
    assert!(stderr(&output).contains("DENT8_GRANT"));

    let output = run_dent8(
        &[
            "assert",
            "person:alice",
            "favorite_drink",
            "tea",
            "--authority",
            "high",
        ],
        &envs,
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("missing --source"));
    assert!(stderr(&output).contains("DENT8_GRANT"));
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
            "low",
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
    assert!(stdout(&init).contains(
        "dent8 assert repo:myproj deploy_target production --authority high --source source:local"
    ));
    assert!(stdout(&init).contains("dent8 explain repo:myproj deploy_target"));
    assert!(stdout(&init).contains("dent8 doctor --source source:local --write-check"));

    let env_path = temp.file(".dent8/env");
    let authority_path = temp.file(".dent8/authority.json");
    let log_path = temp.file(".dent8/memory.jsonl");
    let env_file = fs::read_to_string(&env_path).expect("env file");
    assert!(env_file.contains("DENT8_REQUIRE_AUTHORITY=1"));
    assert!(env_file.contains("DENT8_LOG="));
    assert!(env_file.contains("DENT8_AUTHORITY="));
    // A default `dent8 init` now provisions a signing identity by default so above-agent writes
    // work out of the box: the env carries the signed-identity vars and the bundle files exist.
    assert!(env_file.contains("DENT8_REQUIRE_IDENTITY=1"), "{env_file}");
    assert!(env_file.contains("DENT8_TRUST="), "{env_file}");
    assert!(env_file.contains("DENT8_GRANT="), "{env_file}");
    assert!(env_file.contains("DENT8_IDENTITY_KEY="), "{env_file}");
    assert!(
        temp.file(".dent8/grants/source_local.grant.json").exists(),
        "init should provision a signed grant for the default source"
    );
    assert!(temp.file(".dent8/identities/source_local.key").exists());

    let authority = fs::read_to_string(&authority_path).expect("authority registry");
    assert!(authority.contains("source:local"));
    assert!(authority.contains("high"));
    assert!(log_path.exists(), "init should create the file dev log");

    let log = log_path.to_string_lossy().into_owned();
    let authority = authority_path.to_string_lossy().into_owned();
    let trust = temp
        .file(".dent8/trust.json")
        .to_string_lossy()
        .into_owned();
    let grant = temp
        .file(".dent8/grants/source_local.grant.json")
        .to_string_lossy()
        .into_owned();
    let key = temp
        .file(".dent8/identities/source_local.key")
        .to_string_lossy()
        .into_owned();
    let active_grants = temp
        .file(".dent8/active-grants.json")
        .to_string_lossy()
        .into_owned();
    // The write-check probes at source:local's High ceiling, which now requires the signed identity
    // init provisioned — exactly the out-of-the-box honest above-agent path.
    let doctor = run_dent8(
        &["doctor", "--write-check"],
        &[
            ("DENT8_LOG", &log),
            ("DENT8_AUTHORITY", &authority),
            ("DENT8_REQUIRE_AUTHORITY", "1"),
            ("DENT8_TRUST", &trust),
            ("DENT8_GRANT", &grant),
            ("DENT8_IDENTITY_KEY", &key),
            ("DENT8_ACTIVE_GRANTS", &active_grants),
            ("DENT8_REQUIRE_IDENTITY", "1"),
        ],
    );
    assert_success(&doctor, "doctor --write-check");
    let stdout = stdout(&doctor);
    assert!(stdout.contains("write-check: accepted trusted diagnostic:doctor-"));
    assert!(stdout.contains("dent8.write_check=ok"));
    assert!(stdout.contains("rejected below-ceiling tampered value"));
    assert!(stdout.contains("verify OK"));
    assert!(stdout.contains("probe retracted"));
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

fn assert_alice_fact(log: &str, predicate: &str, value: &str, context: &str) {
    // Agent-tier authority: these personal facts on unregistered predicates are fixtures for the
    // witness/chain tests, which do not assert authority — and `user:alice` is not a signable
    // (source:*) identity, so an above-agent write here could not be signed anyway.
    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                predicate,
                value,
                "--authority",
                "low",
                "--source",
                "user:alice",
            ],
            &[("DENT8_LOG", log)],
        ),
        context,
    );
}

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
    let broken_local_json = run_dent8(
        &["--output", "json", "witness", "publish", &broken_published],
        &publish_env,
    );
    assert_eq!(broken_local_json.status.code(), Some(1));
    assert_eq!(
        stdout_json(&broken_local_json)["status"],
        "rollback",
        "{}",
        stderr(&broken_local_json)
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

#[test]
fn witness_commands_emit_machine_readable_json() {
    let fixture = WitnessJsonFixture::new();
    assert_witness_keygen_json(&fixture);
    assert_alice_fact(&fixture.log, "favorite_drink", "tea", "assert first fact");
    assert_witness_sign_head_and_verify_json(&fixture);
    assert_witness_publish_json(&fixture);
    assert_witness_doctor_and_trailing_json(&fixture);
}

struct WitnessJsonFixture {
    _temp: TempDir,
    log: String,
    key: String,
    pubkey: String,
    witness_log: String,
    published: String,
}

impl WitnessJsonFixture {
    fn new() -> Self {
        let temp = TempDir::new();
        let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
        let key = temp.file("witness.key").to_string_lossy().into_owned();
        let pubkey = format!("{key}.pub");
        let witness_log = temp.file("witness.jsonl").to_string_lossy().into_owned();
        let published = temp
            .file("published-heads.jsonl")
            .to_string_lossy()
            .into_owned();
        Self {
            _temp: temp,
            log,
            key,
            pubkey,
            witness_log,
            published,
        }
    }

    fn sign_env(&self) -> [(&str, &str); 3] {
        [
            ("DENT8_LOG", self.log.as_str()),
            ("DENT8_WITNESS_KEY", self.key.as_str()),
            ("DENT8_WITNESS_LOG", self.witness_log.as_str()),
        ]
    }

    fn verify_env(&self) -> [(&str, &str); 3] {
        [
            ("DENT8_LOG", self.log.as_str()),
            ("DENT8_WITNESS_LOG", self.witness_log.as_str()),
            ("DENT8_WITNESS_PUBKEY", self.pubkey.as_str()),
        ]
    }
}

fn assert_witness_keygen_json(fixture: &WitnessJsonFixture) {
    let keygen = run_dent8(
        &["--output", "json", "witness", "keygen"],
        &[("DENT8_WITNESS_KEY", fixture.key.as_str())],
    );
    assert_success(&keygen, "witness keygen --output json");
    assert!(stderr(&keygen).is_empty(), "{}", stderr(&keygen));
    let keygen = stdout_json(&keygen);
    assert_eq!(keygen["status"], "ok");
    assert_eq!(keygen["tool"], "witness keygen");
    assert_eq!(keygen["key_path"], fixture.key);
    assert_eq!(keygen["public_key_path"], fixture.pubkey);
    assert_eq!(keygen["writer_must_not_inherit_key"], true);
}

#[test]
fn witness_accepts_the_output_flag_after_the_subcommand() {
    // Real subcommands (not a trailing catch-all) mean the global `--output` works *after* the
    // subcommand too, via clap global-arg propagation — the shared contract every command has.
    let temp = TempDir::new();
    let key = temp.file("witness.key").to_string_lossy().into_owned();
    let keygen = run_dent8(
        &["witness", "keygen", "--output", "json"],
        &[("DENT8_WITNESS_KEY", key.as_str())],
    );
    assert_success(&keygen, "witness keygen --output json (trailing)");
    assert!(stderr(&keygen).is_empty(), "{}", stderr(&keygen));
    let keygen = stdout_json(&keygen);
    assert_eq!(keygen["status"], "ok");
    assert_eq!(keygen["tool"], "witness keygen");
}

fn assert_witness_sign_head_and_verify_json(fixture: &WitnessJsonFixture) {
    let sign_env = fixture.sign_env();
    let verify_env = fixture.verify_env();
    let sign = run_dent8(&["--output", "json", "witness", "sign"], &sign_env);
    assert_success(&sign, "witness sign --output json");
    let sign = stdout_json(&sign);
    assert_eq!(sign["status"], "ok");
    assert_eq!(sign["tool"], "witness sign");
    assert_eq!(sign["signed_head"]["event_count"], 1);
    assert_eq!(sign["witness_log_path"], fixture.witness_log);

    let head = run_dent8(
        &["--output", "json", "witness", "head"],
        &[("DENT8_WITNESS_LOG", fixture.witness_log.as_str())],
    );
    assert_success(&head, "witness head --output json");
    let head = stdout_json(&head);
    assert_eq!(head["status"], "ok");
    assert_eq!(head["latest_head"]["event_count"], 1);
    assert!(
        head["jsonl"]
            .as_str()
            .is_some_and(|line| line.starts_with('{'))
    );

    let verify = run_dent8(&["--output", "json", "witness", "verify"], &verify_env);
    assert_success(&verify, "witness verify --output json");
    let verify = stdout_json(&verify);
    assert_eq!(verify["status"], "ok");
    assert_eq!(verify["tool"], "witness verify");
    assert_eq!(verify["coverage"], "complete");
    assert_eq!(verify["latest_witnessed_count"], 1);
    assert_eq!(verify["current_event_count"], 1);
}

fn assert_witness_publish_json(fixture: &WitnessJsonFixture) {
    let verify_env = fixture.verify_env();
    let publish = run_dent8(
        &["--output", "json", "witness", "publish", &fixture.published],
        &verify_env,
    );
    assert_success(&publish, "witness publish --output json");
    let publish = stdout_json(&publish);
    assert_eq!(publish["status"], "ok");
    assert_eq!(publish["action"], "appended");
    assert_eq!(publish["coverage"], "complete");
    assert_eq!(publish["published_heads_path"], fixture.published);
    assert_eq!(publish["published_signed_head_count"], 1);

    let duplicate = run_dent8(
        &["--output", "json", "witness", "publish", &fixture.published],
        &verify_env,
    );
    assert_success(&duplicate, "duplicate witness publish --output json");
    let duplicate = stdout_json(&duplicate);
    assert_eq!(duplicate["action"], "already_published");
    assert_eq!(duplicate["published_signed_head_count"], 1);

    let published_verify = run_dent8(
        &[
            "--output",
            "json",
            "witness",
            "verify-published",
            &fixture.published,
        ],
        &verify_env,
    );
    assert_success(&published_verify, "witness verify-published --output json");
    let published_verify = stdout_json(&published_verify);
    assert_eq!(published_verify["status"], "ok");
    assert_eq!(published_verify["level"], "ok");
    assert_eq!(published_verify["coverage"], "complete");
}

fn assert_witness_doctor_and_trailing_json(fixture: &WitnessJsonFixture) {
    let verify_env = fixture.verify_env();
    let writer_doctor = run_dent8(
        &["--output", "json", "witness", "doctor", "writer"],
        &verify_env,
    );
    assert_success(&writer_doctor, "witness doctor writer --output json");
    let writer_doctor = stdout_json(&writer_doctor);
    assert_eq!(writer_doctor["status"], "ok");
    assert_eq!(writer_doctor["tool"], "witness doctor");
    assert_eq!(writer_doctor["role"], "writer");
    assert_eq!(writer_doctor["summary"]["fail"], 0);
    assert!(
        writer_doctor["sections"]["ok"]
            .as_array()
            .expect("ok checks")
            .iter()
            .any(|check| check["message"]
                .as_str()
                .is_some_and(|message| message.contains("DENT8_WITNESS_KEY is not set"))),
        "{writer_doctor}"
    );

    assert_alice_fact(
        &fixture.log,
        "favorite_snack",
        "apple",
        "assert unwitnessed tail",
    );
    let trailing = run_dent8(
        &[
            "--output",
            "json",
            "witness",
            "verify-published",
            &fixture.published,
        ],
        &verify_env,
    );
    assert_success(&trailing, "witness verify-published trailing --output json");
    let trailing = stdout_json(&trailing);
    assert_eq!(trailing["status"], "ok");
    assert_eq!(trailing["level"], "warn");
    assert_eq!(trailing["coverage"], "trailing");
    assert_eq!(trailing["unwitnessed_events"], 1);
}

#[cfg(unix)]
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

#[test]
#[allow(clippy::too_many_lines)] // one linear scenario: sign -> grow -> tamper -> verify/doctor
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
                "low",
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
                "low",
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

    // The JSON fault carries the machine-readable verdict (a monitor must distinguish a
    // tamper alarm from a config failure without parsing prose), and `--output json` works in
    // either position around the raw witness args.
    for args in [
        ["--output", "json", "witness", "verify"].as_slice(),
        ["witness", "verify", "--output", "json"].as_slice(),
    ] {
        let verify_json = run_dent8(args, &verify_env);
        assert_eq!(verify_json.status.code(), Some(1), "{args:?}");
        let fault = stdout_json(&verify_json);
        assert_eq!(fault["status"], "tamper", "{fault:#}");
        assert_eq!(fault["tool"], "witness verify");
    }

    // A benign setup failure stays `failed` — distinct from the tamper verdict above.
    let missing = run_dent8(
        &[
            "--output",
            "json",
            "witness",
            "verify-published",
            "/no/such/published-heads.jsonl",
        ],
        &verify_env,
    );
    assert_eq!(missing.status.code(), Some(1));
    let fault = stdout_json(&missing);
    assert_eq!(fault["status"], "failed", "{fault:#}");

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
    assert_eq!(init["identity"]["max_authority"], "high");
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
    assert!(stderr(&init).is_empty(), "{}", stderr(&init));
    let init = stdout_json(&init);
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
    assert!(wrapper.contains("cargo build -p dent8-cli --features sqlite"));
    assert!(!wrapper.contains("cargo run"));

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

#[test]
fn mcp_install_can_write_daemon_proxy_config() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let socket = temp.file("dent8.sock").to_string_lossy().into_owned();

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
            "--daemon-socket",
            &socket,
        ],
        &[],
    );
    assert_success(&install, "mcp install --daemon-socket");

    let config = fs::read_to_string(temp.file(".codex/config.toml")).expect("codex mcp config");
    assert!(config.contains("command = \"dent8\""));
    assert!(
        config.contains(&format!(
            "args = [\"mcp\", \"proxy\", \"--socket\", \"{socket}\"]"
        )),
        "{config}"
    );

    let checked = run_dent8(
        &[
            "mcp",
            "install",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--daemon-socket",
            &socket,
            "--check",
        ],
        &[],
    );
    assert_success(&checked, "mcp install --daemon-socket --check");

    let serve_check = run_dent8(
        &[
            "mcp", "install", "--agent", "codex", "--dir", &dir, "--check",
        ],
        &[],
    );
    assert_eq!(serve_check.status.code(), Some(1));
    assert!(
        stdout(&serve_check).contains("MCP config needs update:"),
        "{}",
        stdout(&serve_check)
    );
}

#[test]
fn mcp_install_json_reports_daemon_proxy_args() {
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
                "claude-code",
                "--store",
                "sqlite",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "init --agent claude-code --store sqlite",
    );

    let dry_run_json = run_dent8(
        &[
            "--output",
            "json",
            "mcp",
            "install",
            "--agent",
            "claude-code",
            "--dir",
            &dir,
            "--use-daemon",
            "--dry-run",
        ],
        &[],
    );
    assert_success(
        &dry_run_json,
        "mcp install --use-daemon --dry-run --output json",
    );
    let output = stdout_json(&dry_run_json);
    assert_eq!(output["status"], "ok");
    assert_eq!(output["use_daemon"], true);
    assert_eq!(output["daemon_socket"], Value::Null);
    assert_eq!(
        output["requested_args"],
        serde_json::json!(["mcp", "proxy"])
    );
    assert_eq!(output["args_written"], serde_json::json!(["mcp", "proxy"]));
    let rendered = serde_json::from_str::<Value>(
        output["config"]["contents"]
            .as_str()
            .expect("rendered config"),
    )
    .expect("rendered config JSON parses");
    assert_eq!(
        rendered["mcpServers"]["dent8"]["args"],
        serde_json::json!(["mcp", "proxy"])
    );
}

#[test]
#[cfg(all(unix, feature = "async-store"))]
#[allow(clippy::too_many_lines)] // one linear daemon-proxy failure scenario plus JSON contract checks
fn doctor_agent_reports_unreachable_daemon_proxy_config() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();
    let socket = temp
        .file("missing-daemon.sock")
        .to_string_lossy()
        .into_owned();
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
                "--mcp-daemon-socket",
                &socket,
            ],
            &[],
        ),
        "init daemon proxy bundle",
    );

    let doctor = run_dent8(
        &["doctor", "--agent", "codex", "--dir", &dir, "--write-check"],
        &[],
    );
    assert_eq!(doctor.status.code(), Some(1));
    let stdout = stdout(&doctor);
    assert!(
        stdout.contains("agent mcp config: up to date")
            && stdout.contains("mcp smoke: daemon proxy: cannot reach the dent8 daemon at")
            && stdout.contains(&socket)
            && stdout.contains("dent8 daemon serve --socket")
            && stdout.contains("mcp write-check: skipped because MCP smoke failed"),
        "{stdout}"
    );

    let doctor_json = run_dent8(
        &[
            "--output",
            "json",
            "doctor",
            "--agent",
            "codex",
            "--dir",
            &dir,
            "--write-check",
        ],
        &[],
    );
    assert_eq!(doctor_json.status.code(), Some(1));
    let doctor_json = stdout_json(&doctor_json);
    assert_eq!(doctor_json["status"], "failed");
    assert_eq!(doctor_json["mcp_runtime"]["status"], "failed");
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["path"],
        temp.file(".codex/config.toml")
            .to_string_lossy()
            .to_string()
    );
    assert_eq!(doctor_json["mcp_runtime"]["config"]["command"], mcp_command);
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["args"],
        serde_json::json!(["mcp", "proxy", "--socket", socket.as_str()])
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["store"]["backend"],
        "sqlite"
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["transport"]["mode"],
        "daemon_proxy"
    );
    assert_eq!(doctor_json["mcp_runtime"]["transport"]["status"], "failed");
    assert_eq!(doctor_json["mcp_runtime"]["transport"]["socket"], socket);
    assert_eq!(
        doctor_json["mcp_runtime"]["transport"]["socket_source"],
        "args"
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["transport"]["authenticated_source"],
        Value::Null
    );
    assert!(
        doctor_json["mcp_runtime"]["transport"]["error"]
            .as_str()
            .is_some_and(|message| message.contains("daemon proxy: cannot reach")),
        "{doctor_json}"
    );
    assert!(
        doctor_json["mcp_runtime"]["transport"]["start_command"]
            .as_str()
            .is_some_and(|command| command.contains(&socket)),
        "{doctor_json}"
    );
    assert!(
        doctor_json["mcp_runtime"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("daemon proxy: cannot reach")),
        "{doctor_json}"
    );
    assert!(
        doctor_json["sections"]["skip"]
            .as_array()
            .expect("skip sections")
            .iter()
            .any(|check| check["message"].as_str().is_some_and(
                |message| message == "mcp write-check: skipped because MCP smoke failed"
            )),
        "{doctor_json}"
    );
}

#[test]
#[cfg(all(unix, feature = "async-store"))]
fn doctor_agent_smokes_reachable_daemon_proxy_config() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();
    let socket = temp.file("dent8.sock");
    let socket_arg = socket.to_string_lossy().into_owned();
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
                "--mcp-use-daemon",
            ],
            &[],
        ),
        "init daemon proxy bundle",
    );

    let mut env = read_test_env_file(&temp.file(".dent8/env"));
    env.extend(read_test_env_file(&temp.file(".dent8/identity-codex.env")));
    let mut daemon = spawn_daemon(&socket_arg, &env);
    wait_for_socket(&socket, &mut daemon);

    let doctor = run_dent8(
        &["doctor", "--agent", "codex", "--dir", &dir, "--write-check"],
        &[("DENT8_DAEMON_SOCKET", &socket_arg)],
    );
    assert_success(
        &doctor,
        "doctor --agent codex --write-check through daemon proxy",
    );
    let stdout = stdout(&doctor);
    assert!(
        stdout.contains(&format!(
            "daemon proxy: reachable at {socket_arg}, authenticated as source:codex"
        )) && stdout.contains("mcp write-check: accepted trusted diagnostic:doctor-mcp-"),
        "{stdout}"
    );

    let doctor_json = run_dent8(
        &[
            "doctor", "--agent", "codex", "--dir", &dir, "--output", "json",
        ],
        &[("DENT8_DAEMON_SOCKET", &socket_arg)],
    );
    assert_success(
        &doctor_json,
        "doctor --agent codex --output json through daemon proxy",
    );
    let doctor_json = stdout_json(&doctor_json);
    assert_eq!(doctor_json["status"], "ok");
    assert_eq!(doctor_json["mcp_runtime"]["status"], "ok");
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["args"],
        serde_json::json!(["mcp", "proxy"])
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["store"]["backend"],
        "sqlite"
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["transport"]["mode"],
        "daemon_proxy"
    );
    assert_eq!(doctor_json["mcp_runtime"]["transport"]["status"], "ok");
    assert_eq!(
        doctor_json["mcp_runtime"]["transport"]["socket"],
        socket_arg
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["transport"]["socket_source"],
        "process_env"
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["transport"]["authenticated_source"],
        "source:codex"
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["transport"]["error"],
        Value::Null
    );
    assert!(
        doctor_json["mcp_runtime"]["runtime_status"]["identity"]["source"] == "source:codex",
        "{doctor_json}"
    );
}

#[test]
#[cfg(all(unix, feature = "async-store"))]
fn daemon_status_reports_unreachable_socket() {
    let temp = TempDir::new();
    let socket = temp
        .file("missing-daemon.sock")
        .to_string_lossy()
        .into_owned();

    let status = run_dent8(&["daemon", "status", "--socket", &socket], &[]);
    assert_eq!(status.status.code(), Some(1));
    let stdout = stdout(&status);
    assert!(
        stdout.contains("dent8 daemon status")
            && stdout.contains("FAIL  daemon: cannot reach the dent8 daemon at")
            && stdout.contains(&socket)
            && stdout.contains("dent8 daemon serve --socket"),
        "{stdout}"
    );

    let status_json = run_dent8(
        &["--output", "json", "daemon", "status", "--socket", &socket],
        &[],
    );
    assert_eq!(status_json.status.code(), Some(1));
    let status_json = stdout_json(&status_json);
    assert_eq!(status_json["status"], "failed");
    assert_eq!(status_json["tool"], "daemon status");
    assert_eq!(status_json["socket"], socket);
    assert_eq!(status_json["reachable"], false);
    assert!(
        status_json["start_command"]
            .as_str()
            .is_some_and(|command| command.contains("dent8 daemon serve --socket")),
        "{status_json}"
    );
}

#[test]
#[cfg(all(unix, feature = "async-store"))]
fn daemon_status_reports_reachable_runtime_and_auth() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--store",
                "sqlite",
                "--source",
                "source:owner",
                "--identity",
            ],
            &[("DENT8_ISSUER_KEY", &issuer_key)],
        ),
        "init daemon bundle",
    );

    let mut env = read_test_env_file(&temp.file(".dent8/env"));
    env.extend(read_test_env_file(&temp.file(".dent8/identity-owner.env")));
    let socket = temp.file("dent8.sock");
    let socket_arg = socket.to_string_lossy().into_owned();
    let mut daemon = spawn_daemon(&socket_arg, &env);
    wait_for_socket(&socket, &mut daemon);

    let read_only = run_dent8(&["daemon", "status", "--socket", &socket_arg], &[]);
    assert_success(&read_only, "daemon status read-only");
    let read_only_stdout = stdout(&read_only);
    assert!(
        read_only_stdout.contains("OK  daemon: reachable")
            && read_only_stdout
                .contains("SKIP  auth: DENT8_GRANT and DENT8_IDENTITY_KEY are not set"),
        "{read_only_stdout}"
    );

    let via_env = run_dent8(
        &["daemon", "status"],
        &[("DENT8_DAEMON_SOCKET", &socket_arg)],
    );
    assert_success(&via_env, "daemon status via DENT8_DAEMON_SOCKET");
    assert!(
        stdout(&via_env).contains(&socket_arg),
        "{}",
        stdout(&via_env)
    );

    let env_refs = env_refs(&env);
    let status = run_dent8(
        &[
            "--output",
            "json",
            "daemon",
            "status",
            "--socket",
            &socket_arg,
        ],
        &env_refs,
    );
    assert_success(&status, "daemon status --output json");
    let status = stdout_json(&status);
    assert_eq!(status["status"], "ok");
    assert_eq!(status["reachable"], true);
    assert_eq!(status["runtime_status"]["store"]["backend"], "sqlite");
    assert_eq!(status["auth"]["status"], "ok");
    assert_eq!(status["auth"]["source"], "source:owner");
}

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
    assert!(stdout.contains("mcp smoke: initialize + tools/list + runtime_status OK"));
}

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
    assert!(stdout.contains("source:codex max=high"));
    assert!(stdout.contains("identity source: grant source matches doctor source source:codex"));
    assert!(stdout.contains("mcp smoke: initialize + tools/list + runtime_status OK"));
    assert!(stdout.contains("mcp server version:"));
    assert!(stdout.contains("mcp write-check: accepted trusted diagnostic:doctor-mcp-"));
    assert!(stdout.contains("dent8.write_check=ok"));
    assert!(
        !stdout.contains("  OK  write-check: accepted trusted diagnostic:doctor-"),
        "{stdout}"
    );

    let doctor_json = run_dent8(
        &[
            "doctor", "--agent", "codex", "--dir", &dir, "--output", "json",
        ],
        &[],
    );
    assert_success(&doctor_json, "doctor --agent codex --output json");
    let doctor_json = stdout_json(&doctor_json);
    assert_eq!(doctor_json["status"], "ok");
    assert_eq!(doctor_json["mcp_runtime"]["status"], "ok");
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["path"],
        temp.file(".codex/config.toml")
            .to_string_lossy()
            .to_string()
    );
    assert_eq!(doctor_json["mcp_runtime"]["config"]["command"], mcp_command);
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["args"],
        serde_json::json!(["mcp", "serve"])
    );
    assert_eq!(doctor_json["mcp_runtime"]["config"]["cwd"], Value::Null);
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["expected_source"],
        "source:codex"
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["store"]["backend"],
        "file"
    );
    assert_eq!(doctor_json["mcp_runtime"]["transport"]["mode"], "stdio");
    assert_eq!(doctor_json["mcp_runtime"]["transport"]["status"], "ok");
    assert_eq!(
        doctor_json["mcp_runtime"]["transport"]["socket"],
        Value::Null
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["runtime_status"]["tool"],
        "runtime_status"
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["runtime_status"]["store"]["backend"],
        "file"
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["runtime_status"]["identity"]["source"],
        "source:codex"
    );
}

#[cfg(unix)]
#[test]
fn doctor_agent_warns_when_mcp_server_version_differs() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let fake_mcp = temp.file("fake-dent8-mcp.sh");
    fs::write(
        &fake_mcp,
        r#"#!/bin/sh
set -eu
cat >/dev/null
printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"dent8","version":"0.0.1"}}}'
printf '%s\n' '{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"runtime_status"},{"name":"assert"},{"name":"explain"},{"name":"verify"}]}}'
printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"isError\":false,\"content\":[],\"structuredContent\":{\"tool\":\"runtime_status\",\"status\":\"ok\",\"schema_version\":1,\"server\":{\"version\":\"0.0.1\",\"binary_path\":\"$0\"},\"store\":{\"backend\":\"file\",\"event_count\":0,\"file_log_path\":\"$DENT8_LOG\"},\"identity\":{\"source\":\"source:codex\"}}}}"
"#,
    )
    .expect("write fake MCP server");
    make_executable(&fake_mcp);

    let fake_command = fake_mcp.to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--store",
                "file",
                "--agent",
                "codex",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &fake_command,
            ],
            &[],
        ),
        "init --agent codex --install-mcp with fake MCP server",
    );

    let doctor = run_dent8(&["doctor", "--agent", "codex", "--dir", &dir], &[]);
    assert_success(&doctor, "doctor --agent codex with stale MCP server");
    let stdout = stdout(&doctor);
    assert!(
        stdout.contains("WARN  mcp server version: 0.0.1"),
        "{stdout}"
    );
    assert!(
        stdout.contains("doctor is "),
        "expected doctor version in warning:\n{stdout}"
    );
    assert!(
        stdout.contains("reinstall or repair the agent MCP config"),
        "{stdout}"
    );
}

#[test]
fn doctor_agent_reports_native_memory_bypass_guard_posture() {
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
                // Opt out of the default guard install so the "before" state is genuinely
                // unguarded; this test then verifies doctor's missing→enforced transition when the
                // sample hook is installed manually.
                "--no-native-memory-guard",
                "--install-mcp",
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "init --agent codex --install-mcp",
    );

    let missing = run_dent8(&["doctor", "--agent", "codex", "--dir", &dir], &[]);
    assert_success(&missing, "doctor --agent codex before hook install");
    let missing_stdout = stdout(&missing);
    assert!(
        missing_stdout.contains("WARN  bypass guard: no native-memory guard found at")
            && missing_stdout.contains(".codex/hooks.json")
            && missing_stdout.contains("examples/agent-hooks/codex"),
        "{missing_stdout}"
    );

    let hook_path = temp.file(".codex/hooks.json");
    fs::write(
        &hook_path,
        include_str!("../../../examples/agent-hooks/codex/hooks.sample.json"),
    )
    .expect("install codex hook sample");

    let guarded = run_dent8(
        &[
            "--output", "json", "doctor", "--agent", "codex", "--dir", &dir,
        ],
        &[],
    );
    assert_success(&guarded, "doctor --agent codex after hook install");
    let guarded = stdout_json(&guarded);
    assert!(
        guarded["sections"]["ok"]
            .as_array()
            .expect("ok sections")
            .iter()
            .any(|check| check["message"].as_str().is_some_and(
                |message| message.contains("bypass guard: native-memory guard is enforced")
            )),
        "{guarded}"
    );
    assert!(
        guarded["sections"]["warn"]
            .as_array()
            .expect("warn sections")
            .iter()
            .all(|check| !check["message"]
                .as_str()
                .is_some_and(|message| message.starts_with("bypass guard:"))),
        "{guarded}"
    );
}

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

#[test]
fn doctor_agent_mcp_write_check_works_for_json_config_profiles() {
    for (agent, source, config_path) in [
        ("claude-code", "source:claude-code", ".mcp.json"),
        ("cursor", "source:cursor", ".cursor/mcp.json"),
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

#[test]
fn doctor_agent_mcp_write_check_works_for_grok_native_toml_config() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let expected_config = temp.file(".grok/config.toml");
    let issuer_key = temp.file("grok-owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "grok-build",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "init --agent grok-build --install-mcp",
    );
    assert!(
        expected_config.exists(),
        "grok-build should install MCP config at {}",
        expected_config.display()
    );
    let config = fs::read_to_string(&expected_config).expect("read grok native MCP config");
    assert!(config.contains("[mcp_servers.dent8]"));
    assert!(config.contains("[mcp_servers.dent8.env]"));
    assert!(config.contains("DENT8_GRANT = "));
    assert!(config.contains("grants/source_grok-build.grant.json"));
    assert!(config.contains("DENT8_IDENTITY_KEY = "));
    assert!(config.contains("identities/source_grok-build.key"));

    let doctor = run_dent8(
        &[
            "doctor",
            "--agent",
            "grok-build",
            "--dir",
            &dir,
            "--write-check",
        ],
        &[],
    );
    assert_installed_agent_doctor_ok(&doctor, "grok-build", "source:grok-build", &mcp_command);
    let doctor_stdout = stdout(&doctor);
    assert!(
        doctor_stdout.contains(&expected_config.display().to_string()),
        "doctor should read {} for grok-build; stdout:\n{}",
        expected_config.display(),
        doctor_stdout
    );
}

#[test]
fn doctor_agent_grok_build_accepts_explicit_mcp_json_config() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let expected_config = temp.file(".mcp.json");
    let expected_config_arg = expected_config.to_string_lossy().into_owned();
    let issuer_key = temp.file("grok-owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "grok-build",
                "--issuer-key",
                &issuer_key,
                "--install-mcp",
                "--mcp-command",
                &mcp_command,
                "--mcp-config",
                &expected_config_arg,
            ],
            &[],
        ),
        "init --agent grok-build --install-mcp --mcp-config .mcp.json",
    );
    assert!(
        expected_config.exists(),
        "grok-build should support explicit MCP JSON config at {}",
        expected_config.display()
    );
    let config = fs::read_to_string(&expected_config).expect("read grok MCP JSON config");
    assert!(config.contains("\"mcpServers\""));
    assert!(config.contains("\"DENT8_GRANT\""));
    assert!(config.contains("grants/source_grok-build.grant.json"));
    assert!(config.contains("\"DENT8_IDENTITY_KEY\""));
    assert!(config.contains("identities/source_grok-build.key"));

    let doctor = run_dent8(
        &[
            "doctor",
            "--agent",
            "grok-build",
            "--dir",
            &dir,
            "--mcp-config",
            &expected_config_arg,
            "--write-check",
        ],
        &[],
    );
    assert_installed_agent_doctor_ok(&doctor, "grok-build", "source:grok-build", &mcp_command);
}

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
        stderr(&added).is_empty(),
        "failed JSON command writes its error JSON to stdout, not stderr:\n{}",
        stderr(&added)
    );
    let error = stdout_json(&added);
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

#[cfg(feature = "sqlite")]
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

    assert_shared_sqlite_all_agents_json(&doctor_all_agents_json(&dir, true, false));
    assert_shared_sqlite_all_agents_json(&doctor_all_agents_json(&dir, true, true));
}

#[cfg(feature = "sqlite")]
#[test]
fn concurrent_cli_asserts_on_shared_sqlite_store_get_unique_event_ids() {
    let temp = TempDir::new();
    let store_url = format!("sqlite://{}", temp.file("dent8.db").display());
    assert_concurrent_cli_asserts_get_unique_event_ids(&store_url, "sqlite-project", "sqlite");
}

#[cfg(feature = "postgres")]
#[test]
fn concurrent_cli_asserts_on_shared_postgres_store_get_unique_event_ids() {
    let Ok(store_url) = std::env::var("DATABASE_URL") else {
        eprintln!("skipping Postgres CLI concurrency test: DATABASE_URL is not set");
        return;
    };
    if store_url.is_empty() {
        eprintln!("skipping Postgres CLI concurrency test: DATABASE_URL is empty");
        return;
    }

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos();
    let subject_key_prefix = format!("postgres-project-{}-{nonce}", std::process::id());
    assert_concurrent_cli_asserts_get_unique_event_ids(&store_url, &subject_key_prefix, "postgres");
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
#[allow(clippy::too_many_lines)]
fn assert_concurrent_cli_asserts_get_unique_event_ids(
    store_url: &str,
    subject_key_prefix: &str,
    backend_label: &str,
) {
    const WRITERS: usize = 8;

    let envs = [("DENT8_STORE_URL", store_url)];

    assert_success(
        &run_dent8(&["facts", "list"], &envs),
        &format!("pre-migrate {backend_label} store"),
    );

    // `repo.database` has a High floor, so the racing writes must be signed; the writers target
    // distinct subjects, so one shared signed identity (source:concurrent) authorizes them all.
    let bundle = TempDir::new();
    let id = SigningId::provision(&bundle, "source:concurrent", "unused");
    let (trust, grant, key, active_grants) = (
        id.trust.clone(),
        id.grant.clone(),
        id.key.clone(),
        id.active_grants.clone(),
    );

    let barrier = Arc::new(Barrier::new(WRITERS));
    let mut handles = Vec::new();
    for index in 0..WRITERS {
        let barrier = Arc::clone(&barrier);
        let store_url = store_url.to_owned();
        let subject_key_prefix = subject_key_prefix.to_owned();
        let backend_label = backend_label.to_owned();
        let (trust, grant, key, active_grants) = (
            trust.clone(),
            grant.clone(),
            key.clone(),
            active_grants.clone(),
        );
        handles.push(std::thread::spawn(move || {
            let subject = format!("repo:{subject_key_prefix}-{index}");
            let value = format!("database-{backend_label}-{index}");
            barrier.wait();
            run_dent8(
                &[
                    "assert",
                    &subject,
                    "database",
                    &value,
                    "--authority",
                    "high",
                    "--source",
                    "source:concurrent",
                ],
                &[
                    ("DENT8_STORE_URL", store_url.as_str()),
                    ("DENT8_TRUST", trust.as_str()),
                    ("DENT8_GRANT", grant.as_str()),
                    ("DENT8_IDENTITY_KEY", key.as_str()),
                    ("DENT8_ACTIVE_GRANTS", active_grants.as_str()),
                    ("DENT8_REQUIRE_IDENTITY", "1"),
                ],
            )
        }));
    }

    for (index, handle) in handles.into_iter().enumerate() {
        let output = handle.join().expect("writer thread should not panic");
        assert_success(&output, &format!("concurrent writer {index}"));
    }

    let mut event_ids = BTreeSet::new();
    for index in 0..WRITERS {
        let subject_key = format!("{subject_key_prefix}-{index}");
        let subject = format!("repo:{subject_key}");
        let listed = run_dent8(
            &[
                "--output",
                "json",
                "facts",
                "list",
                "--kind",
                "repo",
                "--key",
                &subject_key,
                "--predicate",
                "database",
            ],
            &envs,
        );
        assert_success(
            &listed,
            &format!("{backend_label} facts list for writer {index}"),
        );
        let listed = stdout_json(&listed);
        assert_eq!(listed["count"], 1, "{listed}");
        assert_eq!(listed["facts"][0]["subject"]["key"], subject_key.as_str());

        let replay = run_dent8(&["--output", "json", "replay", &subject, "database"], &envs);
        assert_success(&replay, &format!("{backend_label} replay writer {index}"));
        let replay = stdout_json(&replay);
        assert_eq!(replay["event_count"], 1, "{replay}");
        let event_id = replay["events"][0]["event_id"]
            .as_str()
            .expect("event id")
            .to_string();
        assert!(
            event_ids.insert(event_id.clone()),
            "duplicate event id {event_id} in {replay}"
        );
    }
    assert_eq!(event_ids.len(), WRITERS);

    assert_success(
        &run_dent8(&["verify"], &envs),
        &format!("verify shared {backend_label} log"),
    );
}

/// Concurrent writers against the **default file store** must serialize through the firewall.
///
/// Eight `dent8 assert` processes race on the SAME subject+predicate at High authority. Under
/// serialized arbitration only the first can land a fresh believed fact; every later writer
/// sees it and is rejected ("already has a believed fact"). So exactly one assert may succeed,
/// the resulting log stays well-formed, and a subsequent read shows exactly one fact.
///
/// Before the exclusive-lock fix this bypassed the firewall: with no lock across
/// `load_store → arbitrate → append_events`, several processes loaded the same empty snapshot,
/// each passed arbitration, and each appended — producing multiple fresh believed facts for one
/// predicate (and colliding `event:0` ids) that `validate_unique_log` then rejects on the next
/// load, bricking the store. This test fails in that world (>1 success and/or the read errors)
/// and passes only with the lock. Cross-process timing means the *old* bypass is demonstrated
/// probabilistically, but the *fixed* invariants asserted here hold deterministically.
#[test]
fn concurrent_cli_asserts_on_shared_file_store_serialize_through_the_firewall() {
    const WRITERS: usize = 8;

    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];
    // `repo.database` has a High authority floor, so the racing writes must be signed above-agent
    // writes. They all sign as ONE source (source:contended) — the race is over the same
    // subject/predicate, so a single signed identity is enough and arbitration still admits exactly
    // one winner regardless of source.
    let id = SigningId::provision(&temp, "source:contended", &log);
    let (trust, grant, key, active_grants) = (
        id.trust.clone(),
        id.grant.clone(),
        id.key.clone(),
        id.active_grants.clone(),
    );

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS));
    let mut handles = Vec::new();
    for index in 0..WRITERS {
        let barrier = std::sync::Arc::clone(&barrier);
        let log = log.clone();
        let (trust, grant, key, active_grants) = (
            trust.clone(),
            grant.clone(),
            key.clone(),
            active_grants.clone(),
        );
        handles.push(std::thread::spawn(move || {
            let value = format!("database-{index}");
            barrier.wait();
            run_dent8(
                &[
                    "assert",
                    "repo:contended",
                    "database",
                    &value,
                    "--authority",
                    "high",
                    "--source",
                    "source:contended",
                ],
                &[
                    ("DENT8_LOG", log.as_str()),
                    ("DENT8_TRUST", trust.as_str()),
                    ("DENT8_GRANT", grant.as_str()),
                    ("DENT8_IDENTITY_KEY", key.as_str()),
                    ("DENT8_ACTIVE_GRANTS", active_grants.as_str()),
                    ("DENT8_REQUIRE_IDENTITY", "1"),
                ],
            )
        }));
    }

    let mut successes = 0usize;
    for handle in handles {
        let output = handle.join().expect("writer thread should not panic");
        if output.status.success() {
            successes += 1;
        }
    }

    // Serialized arbitration admits exactly one fresh believed fact for the contended predicate.
    assert_eq!(
        successes, 1,
        "exactly one concurrent writer may win; {successes} succeeded — the firewall was bypassed"
    );

    // The log must not be bricked: a subsequent read (which re-runs `validate_unique_log`)
    // succeeds and surfaces exactly one believed fact.
    let listed = run_dent8(
        &[
            "--output",
            "json",
            "facts",
            "list",
            "--kind",
            "repo",
            "--key",
            "contended",
            "--predicate",
            "database",
        ],
        &envs,
    );
    assert_success(&listed, "facts list after concurrent file-store writers");
    let listed = stdout_json(&listed);
    assert_eq!(listed["count"], 1, "{listed}");

    // Exactly one line was appended, and the global chain verifies.
    assert_eq!(
        line_count(&log),
        1,
        "the firewall must admit exactly one append under contention"
    );
    assert_success(
        &run_dent8(&["verify"], &envs),
        "verify shared file log after concurrent writers",
    );
}

/// A single corrupt line in the file store must be **non-fatal**: it is skipped, reported on
/// stderr, and the surrounding valid events still load. One torn/garbage line cannot brick the
/// whole store.
#[test]
fn a_corrupt_line_in_the_file_store_is_skipped_and_reported_not_fatal() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let envs = [("DENT8_LOG", log.as_str())];
    // `repo.database` has a High authority floor, so the seeds must be signed above-agent writes;
    // sign each source into the shared store log. (Reads need no identity, so they keep `envs`.)
    let id_a = SigningId::provision(&temp, "source:a", &log);
    let id_b = SigningId::provision(&temp, "source:b", &log);

    // Two valid events (distinct predicates so both stay believed).
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "database",
                "postgres",
                "--authority",
                "high",
                "--source",
                "source:a",
            ],
            &id_a.env_for(&log),
        ),
        "seed valid event 1",
    );
    assert_success(
        &run_dent8(
            &[
                "assert",
                "repo:app",
                "language",
                "rust",
                "--authority",
                "high",
                "--source",
                "source:b",
            ],
            &id_b.env_for(&log),
        ),
        "seed valid event 2",
    );

    // Splice a garbage line between the two valid ones: valid / corrupt / valid.
    let contents = fs::read_to_string(&log).expect("read seeded log");
    let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
    assert_eq!(lines.len(), 2, "expected two seeded event lines");
    lines.insert(1, "{ this is not valid json !!!".to_string());
    fs::write(&log, format!("{}\n", lines.join("\n"))).expect("rewrite log with corrupt line");

    // A read must succeed (not a hard error / brick) and surface BOTH valid facts.
    let listed = run_dent8(
        &[
            "--output", "json", "facts", "list", "--kind", "repo", "--key", "app",
        ],
        &envs,
    );
    assert_success(&listed, "facts list over a log with one corrupt line");
    let json = stdout_json(&listed);
    assert_eq!(json["count"], 2, "both valid facts must survive: {json}");

    // The skip is reported on stderr (never silently swallowed), naming the corrupt line number.
    let warning = stderr(&listed);
    assert!(
        warning.contains("skipped 1 corrupt line(s)") && warning.contains("lines: 2"),
        "stderr must report the skipped corrupt line: {warning:?}"
    );
}

#[cfg(feature = "sqlite")]
#[test]
fn doctor_all_agents_prefers_grok_native_config_over_sidecar() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let mcp_command = dent8_bin().to_string_lossy().into_owned();
    let grok_native_config = temp
        .file(".grok/config.toml")
        .to_string_lossy()
        .into_owned();
    let grok_sidecar_config = temp
        .file(".dent8/mcp-grok-build.json")
        .to_string_lossy()
        .into_owned();

    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--agent",
                "claude-code",
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
        "init --agent claude-code --store sqlite --install-mcp",
    );
    assert_success(
        &run_dent8(
            &[
                "agent",
                "add",
                "--agent",
                "grok-build",
                "--dir",
                &dir,
                "--issuer-key",
                &issuer_key,
                "--mcp-command",
                &mcp_command,
            ],
            &[],
        ),
        "agent add --agent grok-build",
    );
    assert_success(
        &run_dent8(
            &[
                "mcp",
                "install",
                "--agent",
                "grok-build",
                "--dir",
                &dir,
                "--command",
                &mcp_command,
                "--config",
                &grok_sidecar_config,
            ],
            &[],
        ),
        "mcp install --agent grok-build --config .dent8/mcp-grok-build.json",
    );

    let all = run_dent8(
        &[
            "doctor", "--agent", "all", "--dir", &dir, "--output", "json",
        ],
        &[],
    );
    assert_success(&all, "doctor --agent all with native Grok config");
    let all = stdout_json(&all);
    assert_eq!(all["status"], "ok", "{all}");
    let agents = all["agents"].as_array().expect("agents");
    let claude = agents
        .iter()
        .find(|run| run["agent"] == "claude-code")
        .unwrap_or_else(|| panic!("missing claude-code in {all}"));
    assert_eq!(claude["status"], "ok", "{claude}");
    let grok = agents
        .iter()
        .find(|run| run["agent"] == "grok-build")
        .unwrap_or_else(|| panic!("missing grok-build in {all}"));
    assert_eq!(grok["status"], "ok", "{grok}");
    assert_eq!(
        grok["report"]["mcp_runtime"]["runtime_status"]["identity"]["source"], "source:grok-build",
        "{grok}"
    );
    assert!(
        grok["report"]["checks"]
            .as_array()
            .is_some_and(|checks| checks.iter().any(|check| check["message"]
                .as_str()
                .is_some_and(|message| message.contains(&grok_native_config)))),
        "{grok}"
    );
}

#[cfg(feature = "sqlite")]
fn doctor_all_agents_json(dir: &str, write_check: bool, agent_all: bool) -> Value {
    let mut args = vec!["doctor"];
    if agent_all {
        args.extend(["--agent", "all"]);
    } else {
        args.push("--all-agents");
    }
    args.extend(["--dir", dir]);
    if write_check {
        args.push("--write-check");
    }
    args.extend(["--output", "json"]);
    let output = run_dent8(&args, &[]);
    assert_success(
        &output,
        if agent_all {
            "doctor --agent all --output json"
        } else {
            "doctor --all-agents --output json"
        },
    );
    stdout_json(&output)
}

#[cfg(feature = "sqlite")]
fn assert_shared_sqlite_all_agents_json(all: &Value) {
    assert_eq!(all["status"], "ok");
    let agents = all["agents"].as_array().expect("agents");
    assert_eq!(agents.len(), 7);
    for (agent, source) in [
        ("codex", "source:codex"),
        ("claude-code", "source:claude-code"),
    ] {
        let run = agents
            .iter()
            .find(|run| run["agent"] == agent)
            .unwrap_or_else(|| panic!("missing {agent} in {all}"));
        assert_eq!(run["status"], "ok", "{run}");
        assert_eq!(
            run["report"]["mcp_runtime"]["runtime_status"]["store"]["backend"],
            "sqlite"
        );
        assert_eq!(
            run["report"]["mcp_runtime"]["runtime_status"]["identity"]["source"],
            source
        );
    }
    let skipped = agents
        .iter()
        .filter(|run| run["status"] == "skipped")
        .count();
    assert_eq!(skipped, 5, "{all}");
}

#[cfg(feature = "sqlite")]
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
    assert_eq!(added["authority"]["max_authority"], "high");
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

#[cfg(feature = "sqlite")]
#[test]
fn agent_add_can_install_daemon_proxy_config() {
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
            "cursor",
            "--dir",
            &dir,
            "--issuer-key",
            &issuer_key,
            "--mcp-use-daemon",
        ],
        &[],
    );
    assert_success(&added, "agent add --mcp-use-daemon");
    let added = stdout_json(&added);
    assert_eq!(added["status"], "ok");
    assert_eq!(
        added["mcp_install"]["args_written"],
        serde_json::json!(["mcp", "proxy"])
    );
    assert_eq!(added["requested"]["mcp_use_daemon"], true);

    let config = fs::read_to_string(temp.file(".cursor/mcp.json")).expect("cursor mcp config");
    let parsed = serde_json::from_str::<Value>(&config).expect("cursor mcp JSON");
    assert_eq!(
        parsed["mcpServers"]["dent8"]["args"],
        serde_json::json!(["mcp", "proxy"])
    );
}

#[cfg(feature = "sqlite")]
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
        stdout(&repeated).contains("authority ceiling=medium"),
        "agent add should preserve the existing lowered ceiling unless --authority is explicit; stdout:\n{}",
        stdout(&repeated)
    );
    let registry: Value =
        serde_json::from_str(&fs::read_to_string(&authority).expect("authority registry"))
            .expect("authority registry json");
    assert_eq!(
        registry["sources"]["source:claude-code"]["max_authority"], "medium",
        "repeat agent add must not silently raise an existing authority ceiling"
    );
}

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

    let doctor_json = run_dent8(
        &[
            "doctor", "--agent", "codex", "--dir", &dir, "--output", "json",
        ],
        &[],
    );
    assert_eq!(doctor_json.status.code(), Some(1));
    let doctor_json = stdout_json(&doctor_json);
    assert_eq!(doctor_json["mcp_runtime"]["status"], "failed");
    assert_eq!(
        doctor_json["mcp_runtime"]["config"]["command"],
        missing_command
    );
    assert_eq!(doctor_json["mcp_runtime"]["transport"]["mode"], "stdio");
    assert_eq!(doctor_json["mcp_runtime"]["transport"]["status"], "failed");
    assert!(
        doctor_json["mcp_runtime"]["transport"]["error"]
            .as_str()
            .is_some_and(|error| {
                error.contains("could not start") && error.contains("missing-dent8")
            }),
        "{doctor_json}"
    );
}

#[cfg(unix)]
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
    assert!(stdout.contains("mcp smoke: initialize + tools/list + runtime_status OK"));
}

#[cfg(unix)]
#[test]
fn doctor_agent_mcp_smoke_rejects_wrong_runtime_store() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("owner.key").to_string_lossy().into_owned();
    let wrong_log = temp.file("wrong-memory.jsonl");
    let wrapper = temp.file("dent8-wrong-store-wrapper.sh");
    fs::write(
        &wrapper,
        "#!/bin/sh\nset -eu\nexport DENT8_LOG=\"$DENT8_WRONG_LOG\"\nunset DENT8_STORE_URL\nexec \"$DENT8_REAL\" \"$@\"\n",
    )
    .expect("write wrapper");
    make_executable(&wrapper);

    let wrapper_command = wrapper.to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--store",
                "file",
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
        "init --agent codex --store file --install-mcp with wrapper",
    );

    let config_path = temp.file(".codex/config.toml");
    let config = fs::read_to_string(&config_path).expect("codex config");
    let real_bin = format!(
        "\nDENT8_REAL = \"{}\"\nDENT8_WRONG_LOG = \"{}\"\n",
        toml_basic_string(&dent8_bin().to_string_lossy()),
        toml_basic_string(&wrong_log.to_string_lossy()),
    );
    fs::write(&config_path, config + &real_bin).expect("rewrite codex config with wrapper env");

    let doctor = run_dent8(&["doctor", "--agent", "codex", "--dir", &dir], &[]);
    assert_eq!(doctor.status.code(), Some(1));
    let stdout = stdout(&doctor);
    assert!(stdout.contains("agent mcp config: up to date"), "{stdout}");
    assert!(
        stdout.contains("mcp smoke: runtime_status file log mismatch"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&wrong_log.to_string_lossy().to_string()),
        "{stdout}"
    );

    let doctor_json = run_dent8(
        &[
            "doctor", "--agent", "codex", "--dir", &dir, "--output", "json",
        ],
        &[],
    );
    assert_eq!(doctor_json.status.code(), Some(1));
    let doctor_json = stdout_json(&doctor_json);
    assert_eq!(doctor_json["status"], "failed");
    assert_eq!(doctor_json["mcp_runtime"]["status"], "failed");
    assert!(
        doctor_json["mcp_runtime"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("runtime_status file log mismatch")),
        "{doctor_json}"
    );
    assert_eq!(
        doctor_json["mcp_runtime"]["runtime_status"]["store"]["file_log_path"],
        wrong_log.to_string_lossy().as_ref()
    );

    let all_json = run_dent8(
        &["doctor", "--all-agents", "--dir", &dir, "--output", "json"],
        &[],
    );
    assert_eq!(all_json.status.code(), Some(1));
    let all_json = stdout_json(&all_json);
    assert_eq!(all_json["status"], "failed");
    let codex = all_json["agents"]
        .as_array()
        .expect("agents")
        .iter()
        .find(|run| run["agent"] == "codex")
        .unwrap_or_else(|| panic!("missing codex in {all_json}"));
    assert_eq!(codex["status"], "failed", "{codex}");
    assert!(
        codex["report"]["mcp_runtime"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("runtime_status file log mismatch")),
        "{codex}"
    );
}

#[cfg(unix)]
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

#[test]
#[cfg(all(unix, feature = "async-store"))]
fn mcp_proxy_bridges_stdio_to_authenticated_daemon() {
    let temp = TempDir::new();
    let dir = temp.file(".dent8").to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "init",
                "--dir",
                &dir,
                "--store",
                "sqlite",
                "--source",
                "source:owner",
                "--identity",
            ],
            &[("DENT8_ISSUER_KEY", &issuer_key)],
        ),
        "init daemon bundle",
    );

    let mut env = read_test_env_file(&temp.file(".dent8/env"));
    env.extend(read_test_env_file(&temp.file(".dent8/identity-owner.env")));
    let socket = temp.file("dent8.sock");
    let socket_arg = socket.to_string_lossy().into_owned();

    let mut daemon = spawn_daemon(&socket_arg, &env);
    wait_for_socket(&socket, &mut daemon);

    let input = json_rpc_lines(&[
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "assert", "arguments": {
                "subject": "person:alice",
                "predicate": "favorite_drink",
                "value": "tea"
            }}
        }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "supersede", "arguments": {
                "subject": "person:alice",
                "predicate": "favorite_drink",
                "value": "coffee",
                "authority": "low"
            }}
        }),
        serde_json::json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "verify", "arguments": {} }
        }),
    ]);

    let proxied = run_dent8_mcp_proxy(&socket_arg, &input, &env);
    assert_success(&proxied, "mcp proxy");
    let responses = stdout(&proxied)
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("proxy response JSON"))
        .collect::<Vec<_>>();
    assert_eq!(
        responses.len(),
        4,
        "notification should not produce a response: {responses:#?}"
    );
    assert_eq!(
        json_response(&responses, 1)["result"]["serverInfo"]["name"],
        "dent8"
    );
    assert_eq!(
        json_response(&responses, 2)["result"]["structuredContent"]["status"],
        "accepted"
    );
    assert_eq!(
        json_response(&responses, 3)["result"]["structuredContent"]["status"],
        "rejected"
    );
    assert_eq!(
        json_response(&responses, 4)["result"]["structuredContent"]["status"],
        "ok"
    );
    assert!(
        json_response(&responses, 4)["result"]["content"][0]["text"]
            .as_str()
            .expect("verify text")
            .contains("write attestation(s) verify"),
        "{:#?}",
        json_response(&responses, 4)
    );
}

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

fn assert_mcp_install_needs_update_json(output: &Value) {
    assert_eq!(output["status"], "needs_update");
    assert_eq!(output["mode"], "check");
    assert_eq!(output["exit_code"], 1);
    assert_eq!(output["config"]["action"], "created");
    assert_eq!(output["config"]["changed"], true);
    assert_eq!(output["config"]["written"], false);
}

fn assert_mcp_install_up_to_date_json(output: &Value) {
    assert_eq!(output["status"], "ok");
    assert_eq!(output["config"]["action"], "unchanged");
    assert_eq!(output["config"]["changed"], false);
    assert_eq!(output["config"]["written"], false);
}

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

#[test]
#[allow(clippy::too_many_lines)]
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
            &["assert", "person:alice", "favorite_drink", "tea"],
            &identity_env,
        ),
        "signed write defaults source and authority from bootstrapped identity",
    );

    let defaulted_json = run_dent8(
        &[
            "--output",
            "json",
            "assert",
            "person:alice",
            "favorite_color",
            "blue",
        ],
        &identity_env,
    );
    assert_success(&defaulted_json, "defaulted signed write json");
    let defaulted_json = stdout_json(&defaulted_json);
    assert_eq!(defaulted_json["source"], "source:codex");
    assert_eq!(defaulted_json["authority"], "high");

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "assert",
            "arguments": {
                "subject": "repo:myproj",
                "predicate": "database",
                "value": "sqlite"
            }
        }
    });
    let mcp = run_dent8_mcp(&format!("{request}\n"), &identity_env);
    assert_success(&mcp, "stdio MCP signed write defaults source and authority");
    let response: Value = serde_json::from_str(stdout(&mcp).trim()).unwrap_or_else(|error| {
        panic!(
            "mcp stdout is not one JSON response: {error}\nstdout:\n{}\nstderr:\n{}",
            stdout(&mcp),
            stderr(&mcp)
        )
    });
    assert!(response.get("error").is_none(), "{response:#}");
    assert_eq!(response["result"]["isError"], false);
    assert_eq!(
        response["result"]["structuredContent"]["source"],
        "source:codex"
    );
    assert_eq!(response["result"]["structuredContent"]["authority"], "high");
}

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
    assert_eq!(bootstrapped["max_authority"], "high");
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

#[test]
#[allow(clippy::too_many_lines)]
fn repair_env_restores_active_grant_for_a_key_that_is_not_a_bundle_file() {
    // The remote-teammate flow: the source key is born on another machine (or in an OS
    // keychain), so only its PUBLIC key reaches the issuer, who runs grant-issue and then
    // repair-env to register the active grant. The bundle never holds the private key.
    let temp = TempDir::new();
    let dir = temp.file(".dent8");
    let dir_str = dir.to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &dir_str,
                "--source",
                "source:owner",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "bootstrap",
    );
    // The teammate's key lives OUTSIDE the bundle (their machine); only the .pub travels.
    let remote_key = temp
        .file("elsewhere-carol.key")
        .to_string_lossy()
        .into_owned();
    assert_success(
        &run_dent8(
            &[
                "identity",
                "agent-keygen",
                "source:carol",
                "--out",
                &remote_key,
            ],
            &[],
        ),
        "remote keygen",
    );
    let grant_out = dir
        .join("grants/source_carol.grant.json")
        .to_string_lossy()
        .into_owned();
    assert_success(
        &run_dent8(
            &[
                "identity",
                "grant-issue",
                "source:carol",
                "--public-key",
                &format!("{remote_key}.pub"),
                "--max",
                "medium",
                "--issuer",
                "owner",
                "--issuer-key",
                &issuer_key,
                "--out",
                &grant_out,
            ],
            &[],
        ),
        "grant-issue",
    );
    // repair-env restores the active-grant entry and honestly skips the env rewrite.
    let repaired = run_dent8(
        &[
            "identity",
            "repair-env",
            "--dir",
            &dir_str,
            "--source",
            "source:carol",
        ],
        &[],
    );
    assert_success(&repaired, "repair-env for a remote key");
    let text = stdout(&repaired);
    assert!(
        text.contains("restored current grant entry"),
        "should restore the active grant: {text}"
    );
    assert!(
        text.contains("not rewritten"),
        "should skip the env for a non-bundle key: {text}"
    );
    let registry = std::fs::read_to_string(dir.join("active-grants.json")).expect("registry");
    assert!(
        registry.contains("source:carol"),
        "active grant registered: {registry}"
    );
    // Idempotent: a second run finds the entry current and restores nothing.
    let again = run_dent8(
        &[
            "identity",
            "repair-env",
            "--dir",
            &dir_str,
            "--source",
            "source:carol",
        ],
        &[],
    );
    assert_success(&again, "repair-env rerun");
    assert!(!stdout(&again).contains("restored current grant entry"));
}

#[test]
fn identity_keygen_rejects_malformed_keychain_references() {
    // Validation runs before any OS keychain is touched, so these behave identically on
    // every platform (the happy path needs a real macOS keychain and stays out of CI).
    let empty = run_dent8(
        &[
            "identity",
            "agent-keygen",
            "source:me",
            "--out",
            "keychain:",
        ],
        &[],
    );
    assert!(!empty.status.success(), "empty account must fail");
    assert!(
        stderr(&empty).contains("needs an account name"),
        "{}",
        stderr(&empty)
    );

    let invalid = run_dent8(
        &[
            "identity",
            "agent-keygen",
            "source:me",
            "--out",
            "keychain:bad account",
        ],
        &[],
    );
    assert!(!invalid.status.success(), "invalid account must fail");
    assert!(
        stderr(&invalid).contains("may only contain"),
        "{}",
        stderr(&invalid)
    );
}

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
    assert_eq!(grant_issued["max_authority"], "high");
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
    assert_eq!(verified["max_authority"], "high");
}

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
    assert!(status_stdout.contains("max=high"), "{status_stdout}");
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
                    && message.contains("max=high"))),
        "{status_json}"
    );
}

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
    assert!(stderr(&too_high).contains("may assert at most high"));

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

#[test]
fn witness_covers_the_grant_log_and_detects_truncated_revocations() {
    let temp = TempDir::new();
    let bundle = temp.file("bundle").to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let wkey = temp.file("witness.key").to_string_lossy().into_owned();
    let wlog = temp.file("witness.jsonl").to_string_lossy().into_owned();
    let gwlog = temp
        .file("witness-grants.jsonl")
        .to_string_lossy()
        .into_owned();

    assert_success(
        &run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &bundle,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "bootstrap",
    );
    let trust = format!("{bundle}/trust.json");
    let envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_WITNESS_KEY", wkey.as_str()),
        ("DENT8_WITNESS_LOG", wlog.as_str()),
        ("DENT8_WITNESS_GRANTS_LOG", gwlog.as_str()),
    ];
    assert_success(&run_dent8(&["witness", "keygen"], &envs), "witness keygen");

    // Signing covers BOTH lanes: the event head and the grant-log head (discovered via the
    // trust registry's sibling grant log the bootstrap created).
    let sign = run_dent8(&["witness", "sign"], &envs);
    assert_success(&sign, "witness sign");
    assert!(
        stdout(&sign).contains("signed grant-log head: count=1"),
        "{}",
        stdout(&sign)
    );
    let verify = run_dent8(&["witness", "verify"], &envs);
    assert_success(&verify, "witness verify");
    assert!(
        stdout(&verify).contains("1 grant-log head(s) verify"),
        "{}",
        stdout(&verify)
    );

    // Revoke (a second grant record), witness it, verify.
    assert_success(
        &run_dent8(
            &[
                "identity",
                "revoke",
                "--source",
                "source:codex",
                "--dir",
                &bundle,
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "revoke",
    );
    let sign = run_dent8(&["witness", "sign"], &envs);
    assert_success(&sign, "witness sign #2");
    assert!(
        stdout(&sign).contains("signed grant-log head: count=2"),
        "{}",
        stdout(&sign)
    );
    assert_success(&run_dent8(&["witness", "verify"], &envs), "verify #2");

    // The attack the lane exists for: truncate the revocation off the grant log's tail.
    // The chain still validates (a prefix is a valid chain) — only the witnessed head
    // betrays it.
    let grant_log = format!("{bundle}/grant-log.jsonl");
    let contents = fs::read_to_string(&grant_log).expect("grant log");
    let first_line = contents.lines().next().expect("first record");
    fs::write(&grant_log, format!("{first_line}\n")).expect("truncate grant log");

    let truncated = run_dent8(&["witness", "verify"], &envs);
    assert_eq!(truncated.status.code(), Some(1), "{}", stderr(&truncated));
    assert!(
        stderr(&truncated).contains("ROLLBACK") && stderr(&truncated).contains("grant log"),
        "{}",
        stderr(&truncated)
    );
    let truncated_json = run_dent8(&["--output", "json", "witness", "verify"], &envs);
    assert_eq!(truncated_json.status.code(), Some(1));
    assert_eq!(
        stdout_json(&truncated_json)["status"],
        "rollback",
        "{}",
        stderr(&truncated_json)
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one linear lifecycle: publish -> revoke -> scrub -> catch
fn witness_publishes_grant_log_heads_and_detects_scrubbed_history() {
    let temp = TempDir::new();
    let bundle = temp.file("bundle").to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let wkey = temp.file("witness.key").to_string_lossy().into_owned();
    let pubkey = format!("{wkey}.pub");
    let wlog = temp.file("witness.jsonl").to_string_lossy().into_owned();
    let gwlog = temp
        .file("witness-grants.jsonl")
        .to_string_lossy()
        .into_owned();
    let published = temp.file("published.jsonl").to_string_lossy().into_owned();
    let published_grants = temp
        .file("published-grants.jsonl")
        .to_string_lossy()
        .into_owned();

    assert_success(
        &run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &bundle,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "bootstrap",
    );
    let trust = format!("{bundle}/trust.json");
    let envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_WITNESS_KEY", wkey.as_str()),
        ("DENT8_WITNESS_PUBKEY", pubkey.as_str()),
        ("DENT8_WITNESS_LOG", wlog.as_str()),
        ("DENT8_WITNESS_GRANTS_LOG", gwlog.as_str()),
    ];
    assert_success(&run_dent8(&["witness", "keygen"], &envs), "witness keygen");
    assert_success(&run_dent8(&["witness", "sign"], &envs), "witness sign");

    // Publishing only the event lane says so out loud — silent half-coverage is the failure
    // mode the lane exists to end.
    let event_only = run_dent8(&["witness", "publish", &published], &envs);
    assert_success(&event_only, "event-only publish");
    assert!(
        stdout(&event_only).contains("not being published"),
        "{}",
        stdout(&event_only)
    );

    // Publish both lanes; a second run is idempotent.
    let both = run_dent8(
        &[
            "witness",
            "publish",
            &published,
            "--grants",
            &published_grants,
        ],
        &envs,
    );
    assert_success(&both, "publish with --grants");
    assert!(
        stdout(&both).contains("published grant-log head: count=1"),
        "{}",
        stdout(&both)
    );
    let again = run_dent8(
        &[
            "witness",
            "publish",
            &published,
            "--grants",
            &published_grants,
        ],
        &envs,
    );
    assert_success(&again, "republish with --grants");
    assert!(
        stdout(&again).contains("grant-log head at count 1 is already published"),
        "{}",
        stdout(&again)
    );
    assert_eq!(line_count(&published_grants), 1);

    let checked = run_dent8(
        &[
            "witness",
            "verify-published",
            &published,
            "--grants",
            &published_grants,
            "--output",
            "json",
        ],
        &envs,
    );
    assert_success(&checked, "verify-published with --grants");
    let checked_json = stdout_json(&checked);
    assert_eq!(checked_json["status"], "ok", "{}", stdout(&checked));
    assert_eq!(checked_json["grants"]["latest_published_record_count"], 1);
    assert_eq!(checked_json["grants"]["coverage"], "complete");

    // Revoke (record #2), witness it, publish it.
    assert_success(
        &run_dent8(
            &[
                "identity",
                "revoke",
                "--source",
                "source:codex",
                "--dir",
                &bundle,
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "revoke",
    );
    assert_success(&run_dent8(&["witness", "sign"], &envs), "sign #2");
    let second = run_dent8(
        &[
            "witness",
            "publish",
            &published,
            "--grants",
            &published_grants,
        ],
        &envs,
    );
    assert_success(&second, "publish revocation head");
    assert!(
        stdout(&second).contains("published grant-log head: count=2"),
        "{}",
        stdout(&second)
    );

    // The attack the published sequence exists for: the writer scrubs the revocation from
    // the grant log AND deletes the local grants-witness file. Only the published copy —
    // retained outside the writer's control — still knows history reached 2 records.
    let grant_log = format!("{bundle}/grant-log.jsonl");
    let contents = fs::read_to_string(&grant_log).expect("grant log");
    let first_line = contents.lines().next().expect("first record");
    fs::write(&grant_log, format!("{first_line}\n")).expect("truncate grant log");
    fs::remove_file(&gwlog).expect("scrub local grants-witness log");

    let caught = run_dent8(
        &[
            "witness",
            "verify-published",
            &published,
            "--grants",
            &published_grants,
        ],
        &envs,
    );
    assert_eq!(caught.status.code(), Some(1), "{}", stderr(&caught));
    assert!(
        stderr(&caught).contains("ROLLBACK") && stderr(&caught).contains("truncated away"),
        "{}",
        stderr(&caught)
    );
    let caught_json = run_dent8(
        &[
            "--output",
            "json",
            "witness",
            "verify-published",
            &published,
            "--grants",
            &published_grants,
        ],
        &envs,
    );
    assert_eq!(caught_json.status.code(), Some(1));
    assert_eq!(
        stdout_json(&caught_json)["status"],
        "rollback",
        "{}",
        stderr(&caught_json)
    );

    // Publish refuses to regress the external sequence too: re-signing the scrubbed state
    // yields a head at count 1, behind the published count 2.
    assert_success(&run_dent8(&["witness", "sign"], &envs), "sign scrubbed");
    let regress = run_dent8(
        &[
            "witness",
            "publish",
            &published,
            "--grants",
            &published_grants,
        ],
        &envs,
    );
    assert_eq!(regress.status.code(), Some(1), "{}", stderr(&regress));
    assert!(
        stderr(&regress).contains("ROLLBACK: published grant-log heads"),
        "{}",
        stderr(&regress)
    );
}

#[test]
fn witness_serve_covers_the_grant_log_and_signs_only_on_change() {
    let temp = TempDir::new();
    let bundle = temp.file("bundle").to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let wkey = temp.file("witness.key").to_string_lossy().into_owned();
    let wlog = temp.file("witness.jsonl").to_string_lossy().into_owned();
    let gwlog = temp
        .file("witness-grants.jsonl")
        .to_string_lossy()
        .into_owned();

    assert_success(
        &run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &bundle,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "bootstrap",
    );
    let trust = format!("{bundle}/trust.json");
    let envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_WITNESS_KEY", wkey.as_str()),
        ("DENT8_WITNESS_LOG", wlog.as_str()),
        ("DENT8_WITNESS_GRANTS_LOG", gwlog.as_str()),
    ];
    assert_success(&run_dent8(&["witness", "keygen"], &envs), "witness keygen");

    // The cadence signer covers BOTH lanes on its first tick (a bounded run: 1 head).
    let first = run_dent8(&["witness", "serve", "1", "1"], &envs);
    assert_success(&first, "serve #1");
    assert!(
        stdout(&first).contains("signed head: count=0")
            && stdout(&first).contains("signed grant-log head: count=1"),
        "{}",
        stdout(&first)
    );

    // Both lanes grow; the next bounded run witnesses both.
    assert_success(
        &run_dent8(
            &[
                "identity",
                "revoke",
                "--source",
                "source:codex",
                "--dir",
                &bundle,
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "revoke",
    );
    assert_alice_fact(&log, "favorite_drink", "tea", "grow the event log");
    let second = run_dent8(&["witness", "serve", "1", "1"], &envs);
    assert_success(&second, "serve #2");
    assert!(
        stdout(&second).contains("signed grant-log head: count=2"),
        "{}",
        stdout(&second)
    );

    // Event growth WITHOUT grant-log change: the lane is seeded from disk and stays quiet —
    // a 5s cadence must not bloat the grants-witness file with identical heads.
    assert_alice_fact(&log, "favorite_snack", "apple", "grow the event log again");
    let third = run_dent8(&["witness", "serve", "1", "1"], &envs);
    assert_success(&third, "serve #3");
    assert!(!stdout(&third).contains("grant-log"), "{}", stdout(&third));
    assert_eq!(line_count(&gwlog), 2);

    let verify = run_dent8(&["witness", "verify"], &envs);
    assert_success(&verify, "verify");
    assert!(
        stdout(&verify).contains("2 grant-log head(s) verify"),
        "{}",
        stdout(&verify)
    );
}

#[test]
fn witness_serve_streams_ndjson() {
    let temp = TempDir::new();
    let bundle = temp.file("bundle").to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let wkey = temp.file("witness.key").to_string_lossy().into_owned();
    let wlog = temp.file("witness.jsonl").to_string_lossy().into_owned();
    let gwlog = temp
        .file("witness-grants.jsonl")
        .to_string_lossy()
        .into_owned();

    assert_success(
        &run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &bundle,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "bootstrap",
    );
    let trust = format!("{bundle}/trust.json");
    let envs = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_WITNESS_KEY", wkey.as_str()),
        ("DENT8_WITNESS_LOG", wlog.as_str()),
        ("DENT8_WITNESS_GRANTS_LOG", gwlog.as_str()),
    ];
    assert_success(&run_dent8(&["witness", "keygen"], &envs), "witness keygen");

    // One bounded tick, both lanes: stdout is the signed-head record stream (one compact
    // JSON line per head), lifecycle lines go to stderr.
    let run = run_dent8(&["witness", "serve", "1", "1", "--output", "json"], &envs);
    assert_success(&run, "serve ndjson");
    let heads: Vec<Value> = stdout(&run)
        .lines()
        .map(|line| serde_json::from_str(line).expect("stdout should be NDJSON"))
        .collect();
    assert_eq!(heads.len(), 2, "{}", stdout(&run));
    assert_eq!(heads[0]["event"], "head_signed");
    assert_eq!(heads[0]["tool"], "witness serve");
    assert_eq!(heads[0]["lane"], "events");
    assert_eq!(heads[0]["head"]["event_count"], 0);
    assert_eq!(heads[0]["signed_total"], 1);
    assert_eq!(heads[1]["event"], "head_signed");
    assert_eq!(heads[1]["lane"], "grants");
    assert_eq!(heads[1]["head"]["record_count"], 1);
    let lifecycle: Vec<Value> = stderr(&run)
        .lines()
        .map(|line| serde_json::from_str(line).expect("stderr should be NDJSON"))
        .collect();
    let first = lifecycle.first().expect("started line");
    assert_eq!(first["event"], "started", "{}", stderr(&run));
    assert_eq!(first["interval_seconds"], 1);
    assert_eq!(first["max_heads"], 1);
    let last = lifecycle.last().expect("stopped line");
    assert_eq!(last["event"], "stopped");
    assert_eq!(last["reason"], "max_heads_reached");
    assert_eq!(last["signed_heads"], 1);
}

#[test]
#[allow(clippy::too_many_lines)] // one linear lifecycle: issue -> rotate -> revoke -> backfill
fn grant_history_decides_entitlement_across_rotation_and_revocation() {
    let temp = TempDir::new();
    let bundle = temp.file("bundle").to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();

    assert_success(
        &run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &bundle,
                "--source",
                "source:codex",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "bootstrap",
    );
    let trust = format!("{bundle}/trust.json");
    let grants = format!("{bundle}/grants/source_codex.grant.json");
    let key = format!("{bundle}/identities/source_codex.key");
    let identity_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", grants.as_str()),
        ("DENT8_IDENTITY_KEY", key.as_str()),
        ("DENT8_REQUIRE_IDENTITY", "1"),
    ];
    let write = |predicate: &str| {
        run_dent8(
            &[
                "assert",
                "person:alice",
                predicate,
                "tea",
                "--authority",
                "high",
                "--source",
                "source:codex",
            ],
            &identity_env,
        )
    };

    // 1. Bootstrap recorded the issuance: the first attested write is ENTITLED.
    assert_success(&write("favorite_drink"), "attested write #1");
    let verify = run_dent8(&["verify"], &identity_env);
    assert_success(&verify, "verify #1");
    assert!(
        stdout(&verify)
            .contains("1 write attestation(s) verify (1 entitled at write time, 0 unknown"),
        "{}",
        stdout(&verify)
    );

    // 2. Rotation revokes the old grant and issues a new one — as history, not erasure:
    //    the OLD event stays entitled (it predates the revocation), the new one is entitled
    //    under the new grant.
    assert_success(
        &run_dent8(
            &[
                "identity",
                "rotate-source",
                "--source",
                "source:codex",
                "--dir",
                &bundle,
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "rotate",
    );
    assert_success(&write("favorite_snack"), "attested write #2 (new key)");
    let verify = run_dent8(&["verify"], &identity_env);
    assert_success(&verify, "verify #2");
    assert!(
        stdout(&verify)
            .contains("2 write attestation(s) verify (2 entitled at write time, 0 unknown"),
        "{}",
        stdout(&verify)
    );

    // 3. Revocation without replacement: the write path fails closed, and history still
    //    vouches for everything written before the revocation.
    assert_success(
        &run_dent8(
            &[
                "identity",
                "revoke",
                "--source",
                "source:codex",
                "--dir",
                &bundle,
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "revoke",
    );
    let rejected = write("favorite_color");
    assert_eq!(rejected.status.code(), Some(2), "{}", stderr(&rejected));
    let verify = run_dent8(&["verify"], &identity_env);
    assert_success(&verify, "verify #3 (history outlives revocation)");
    assert!(
        stdout(&verify)
            .contains("2 write attestation(s) verify (2 entitled at write time, 0 unknown"),
        "{}",
        stdout(&verify)
    );

    // 4. Backfill honesty: a log seeded AFTER the writes must make them UNKNOWN, never
    //    fabricate entitlement (records are stamped now, not backdated).
    fs::remove_file(format!("{bundle}/grant-log.jsonl")).expect("drop grant log");
    assert_success(
        &run_dent8(
            &[
                "identity",
                "backfill-grant-log",
                "--dir",
                &bundle,
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        ),
        "backfill",
    );
    let verify = run_dent8(&["verify"], &identity_env);
    assert_success(&verify, "verify #4 (backfilled history is honest)");
    assert!(
        stdout(&verify)
            .contains("2 write attestation(s) verify (0 entitled at write time, 2 unknown"),
        "{}",
        stdout(&verify)
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one linear scenario: bootstrap -> attest -> verify -> tamper
fn writes_carry_attestations_that_verify_and_detect_tamper() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    let trust = temp.file("trust.json").to_string_lossy().into_owned();
    let issuer_key = temp.file("issuer.key").to_string_lossy().into_owned();
    let source_key = temp.file("codex.key").to_string_lossy().into_owned();
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
                &source_key,
            ],
            &[],
        ),
        "source keygen",
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
                &format!("{source_key}.pub"),
                "--max",
                "high",
                "--issuer",
                "owner",
                "--issuer-key",
                &issuer_key,
                "--scope",
                "*",
                "--out",
                &grant,
            ],
            &[],
        ),
        "grant issue",
    );

    let identity_env = [
        ("DENT8_LOG", log.as_str()),
        ("DENT8_TRUST", trust.as_str()),
        ("DENT8_GRANT", grant.as_str()),
        ("DENT8_IDENTITY_KEY", source_key.as_str()),
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
        "attested write",
    );

    // The persisted event carries the attestation, bound to the grant's public key (ADR 0013).
    let line = fs::read_to_string(&log).expect("event log");
    let event: Value =
        serde_json::from_str(line.lines().next().expect("one event")).expect("stored event JSON");
    let attestation = &event["provenance"]["attestation"];
    assert_eq!(attestation["algorithm"], "ed25519", "{attestation:#}");
    let grant_pubkey = fs::read_to_string(format!("{source_key}.pub")).expect("source pubkey");
    assert_eq!(
        attestation["public_key"].as_str().expect("public key"),
        grant_pubkey.trim()
    );

    // `verify` re-checks the signature and reports the count.
    let verify = run_dent8(&["verify"], &identity_env);
    assert_success(&verify, "verify attested log");
    assert!(
        stdout(&verify).contains("1 write attestation(s) verify"),
        "{}",
        stdout(&verify)
    );

    // Tampering with an attested event's content breaks its signature — the file dev store
    // now DETECTS a content edit (previously undetectable without a witness).
    let contents = fs::read_to_string(&log).expect("event log");
    fs::write(&log, contents.replacen("tea", "chai", 1)).expect("tamper event log");
    let tampered = run_dent8(&["verify"], &identity_env);
    assert_eq!(tampered.status.code(), Some(1));
    assert!(
        stderr(&tampered).contains("ATTESTATION:"),
        "{}",
        stderr(&tampered)
    );
    assert!(stderr(&tampered).contains("does not verify"));

    // Unconfigured dev mode still writes plain, unattested events — at the agent tier, which stays
    // permissive without signing (an unsigned *above-agent* write is now rejected outright).
    let plain_log = temp.file("plain.jsonl").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(
            &[
                "assert",
                "person:alice",
                "favorite_drink",
                "tea",
                "--authority",
                "low",
                "--source",
                "source:agent",
            ],
            &[("DENT8_LOG", plain_log.as_str())],
        ),
        "unattested dev-mode write",
    );
    let line = fs::read_to_string(&plain_log).expect("plain log");
    assert!(
        !line.contains("attestation"),
        "dev-mode event must not carry an attestation: {line}"
    );
}

/// Security artifacts (grants, trust/active-grant/authority registries, witness heads) are
/// deserialized strictly: an unknown field is unsigned noise at best and tampering at worst,
/// so it must fail loudly ("corrupt …") instead of being silently ignored.
#[test]
fn security_artifacts_reject_unknown_fields() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();

    // Authority registry with an injected unknown key.
    let authority = temp.file("authority.json").to_string_lossy().into_owned();
    fs::write(
        &authority,
        r#"{"sources":{"source:codex":{"max_authority":"high","backdoor":true}}}"#,
    )
    .expect("write authority");
    let write = run_dent8(
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
        &[
            ("DENT8_LOG", log.as_str()),
            ("DENT8_AUTHORITY", authority.as_str()),
        ],
    );
    assert_eq!(write.status.code(), Some(2), "{}", stderr(&write));
    assert!(stderr(&write).contains("corrupt authority registry"));

    // Trust registry with an unknown top-level field.
    let trust = temp.file("trust.json").to_string_lossy().into_owned();
    fs::write(
        &trust,
        r#"{"issuers":{"owner":{"public_key":"aa"}},"extra":1}"#,
    )
    .expect("write trust");
    let with_trust = run_dent8(
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
        &[("DENT8_LOG", log.as_str()), ("DENT8_TRUST", trust.as_str())],
    );
    assert_eq!(with_trust.status.code(), Some(2), "{}", stderr(&with_trust));
    assert!(stderr(&with_trust).contains("corrupt identity trust registry"));

    // Witness head with an unsigned extra field.
    let witness_log = temp.file("witness.jsonl").to_string_lossy().into_owned();
    fs::write(
        &witness_log,
        format!(
            "{{\"event_count\":0,\"head\":null,\"signature\":\"{}\",\"extra\":1}}\n",
            "ab".repeat(64)
        ),
    )
    .expect("write witness log");
    let key = temp.file("witness.key").to_string_lossy().into_owned();
    assert_success(
        &run_dent8(&["witness", "keygen"], &[("DENT8_WITNESS_KEY", &key)]),
        "witness keygen",
    );
    let verify = run_dent8(
        &["witness", "verify"],
        &[
            ("DENT8_LOG", log.as_str()),
            ("DENT8_WITNESS_LOG", witness_log.as_str()),
            ("DENT8_WITNESS_PUBKEY", &format!("{key}.pub")),
        ],
    );
    assert_eq!(verify.status.code(), Some(1), "{}", stderr(&verify));
    assert!(
        stderr(&verify).contains("corrupt signed tree head"),
        "{}",
        stderr(&verify)
    );
}

// ---- Content-check hook (DENT8_CONTENT_CHECK; docs/content-check.md) ------------------
//
// These tests exec `/bin/sh` scanner scripts, so they are Unix-only (CI runs Linux). The
// unconfigured pass-through needs no test of its own: every other test in this file runs
// with DENT8_CONTENT_CHECK removed.

#[cfg(unix)]
mod content_check_hook {
    use std::os::unix::fs::PermissionsExt as _;

    use super::{
        SigningId, TempDir, assert_success, fs, json_response, json_rpc_lines, run_dent8,
        run_dent8_mcp, run_dent8_stdin, stderr, stdout,
    };
    use serde_json::Value;

    /// The content check runs AFTER the authority/identity gate, so a write must clear signing to
    /// reach the scanner. These tests exercise the scanner over one signed source (source:owner);
    /// this builds its signed env plus any extra vars (the scanner config) for a given store `log`.
    fn owner_env<'a>(
        id: &'a SigningId,
        log: &'a str,
        extra: &[(&'a str, &'a str)],
    ) -> Vec<(&'a str, &'a str)> {
        let mut env = id.env_for(log);
        env.extend_from_slice(extra);
        env
    }

    /// Write an executable scanner script into `temp` and return its path.
    fn scanner_script(temp: &TempDir, name: &str, body: &str) -> String {
        let path = temp.file(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write scanner");
        let mut perms = fs::metadata(&path).expect("stat scanner").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&path, perms).expect("chmod scanner");
        path.to_string_lossy().into_owned()
    }

    const REJECT_ALL: &str = "cat > /dev/null\nprintf '{\"verdict\":\"reject\",\"reason\":\"blocked by test scanner\"}\\n'";
    const TAINT_ALL: &str = "cat > /dev/null\nprintf '{\"verdict\":\"taint\",\"reason\":\"flagged by test scanner\"}\\n'";
    const ALLOW_ALL: &str = "cat > /dev/null\nprintf '{\"verdict\":\"allow\"}\\n'";
    const CRASH: &str = "cat > /dev/null\nexit 3";

    /// The no-bypass guarantee: with a reject-all scanner configured, every write entry
    /// point that introduces fact content — the value-writing CLI commands (`assert`,
    /// `supersede`, `contradict`, `derive`), `dent8 capture` proposals, and the MCP write
    /// tools — refuses the write, and nothing new lands in the log.
    #[test]
    #[allow(clippy::too_many_lines)] // one linear sweep over every write entry point
    fn a_reject_verdict_blocks_every_write_entry_point() {
        let temp = TempDir::new();
        let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
        // The seed and revisions are above-agent writes on `repo.database` (High floor), so they run
        // under one signed identity (source:owner); every write in this sweep uses it.
        let id = SigningId::provision(&temp, "source:owner", &log);
        let clean = id.env_for(&log);

        // Seed an incumbent with no scanner configured, so the revising entry points
        // (supersede/contradict/derive) have a believed fact to act on.
        assert_success(
            &run_dent8(
                &[
                    "assert",
                    "repo:app",
                    "database",
                    "postgres",
                    "--authority",
                    "high",
                    "--source",
                    "source:owner",
                ],
                &clean,
            ),
            "seed assert",
        );
        let seeded = fs::read_to_string(&log).expect("read seeded log");

        let scanner = scanner_script(&temp, "reject-all.sh", REJECT_ALL);
        let envs = owner_env(&id, &log, &[("DENT8_CONTENT_CHECK", scanner.as_str())]);

        // CLI write commands.
        let cli_writes: &[&[&str]] = &[
            &[
                "assert",
                "repo:app",
                "build_command",
                "make",
                "--authority",
                "high",
                "--source",
                "source:owner",
            ],
            &[
                "supersede",
                "repo:app",
                "database",
                "attacker-db",
                "--authority",
                "high",
                "--source",
                "source:owner",
            ],
            &[
                "contradict",
                "repo:app",
                "database",
                "attacker-db",
                "--authority",
                "high",
                "--source",
                "source:owner",
            ],
            &[
                "derive",
                "repo:app",
                "deploy_target",
                "deploy-to-postgres",
                "--basis",
                "repo:app",
                "database",
                "--authority",
                "high",
                "--source",
                "source:owner",
            ],
        ];
        for args in cli_writes {
            let output = run_dent8(args, &envs);
            assert_eq!(
                output.status.code(),
                Some(1),
                "{} must be rejected by the content check: {}",
                args[0],
                stdout(&output)
            );
            assert!(
                stderr(&output).contains("content check rejected"),
                "{}: {}",
                args[0],
                stderr(&output)
            );
        }

        // `dent8 capture` (stdin proposals) rides the same op layer.
        let captured = run_dent8_stdin(
            &["capture", "--source", "source:owner", "--authority", "high"],
            "{\"subject\": \"repo:app\", \"predicate\": \"note\", \"value\": \"poison\"}\n",
            &envs,
        );
        assert_eq!(
            captured.status.code(),
            Some(1),
            "capture must reject: {}",
            stdout(&captured)
        );
        assert!(
            stderr(&captured).contains("content check rejected"),
            "stdout: {}; stderr: {}",
            stdout(&captured),
            stderr(&captured)
        );

        // The MCP `assert` tool rides the same op layer.
        let input = json_rpc_lines(&[
            serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
            serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": { "name": "assert", "arguments": {
                    "subject": "repo:app",
                    "predicate": "note",
                    "value": "poison",
                    "authority": "high",
                    "source": "source:owner"
                }}
            }),
        ]);
        let served = run_dent8_mcp(&input, &envs);
        assert_success(&served, "mcp serve");
        let responses = stdout(&served)
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("mcp response JSON"))
            .collect::<Vec<_>>();
        let response = json_response(&responses, 2);
        assert_eq!(
            response["result"]["isError"], true,
            "MCP assert must be rejected: {response:#?}"
        );
        assert!(
            response["result"]["content"][0]["text"]
                .as_str()
                .expect("tool text")
                .contains("content check rejected"),
            "{response:#?}"
        );

        // Nothing new landed in the log through any entry point.
        assert_eq!(
            fs::read_to_string(&log).expect("read log"),
            seeded,
            "a rejected write must never reach the log"
        );

        // Value-less writes introduce no new content and stay admitted (the incumbent's
        // own text was already scanned when it was written).
        assert_success(
            &run_dent8(
                &[
                    "reinforce",
                    "repo:app",
                    "database",
                    "--authority",
                    "high",
                    "--source",
                    "source:owner",
                ],
                &envs,
            ),
            "value-less reinforce under a reject-all scanner",
        );
    }

    /// `taint` admits but marks (detect-only, like retraction taint): the write succeeds,
    /// and `verify` surfaces the flag instead of silently absorbing it.
    #[test]
    fn a_taint_verdict_admits_but_marks_and_verify_surfaces_it() {
        let temp = TempDir::new();
        let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
        let id = SigningId::provision(&temp, "source:owner", &log);
        let scanner = scanner_script(&temp, "taint-all.sh", TAINT_ALL);
        let envs = owner_env(&id, &log, &[("DENT8_CONTENT_CHECK", scanner.as_str())]);

        assert_success(
            &run_dent8(
                &[
                    "assert",
                    "repo:app",
                    "note",
                    "suspicious content",
                    "--authority",
                    "high",
                    "--source",
                    "source:owner",
                ],
                &envs,
            ),
            "taint verdict admits",
        );

        let verify = run_dent8(&["verify"], &envs);
        assert_eq!(verify.status.code(), Some(1), "{}", stdout(&verify));
        let report = stderr(&verify);
        assert!(report.contains("CONTENT-FLAGGED"), "{report}");
        assert!(report.contains("flagged by test scanner"), "{report}");

        // The fact itself is believed and explainable — detect-only, not removal.
        let explained = run_dent8(&["explain", "repo:app", "note"], &envs);
        assert_success(&explained, "explain a tainted fact");
        assert!(stdout(&explained).contains("suspicious content"));
    }

    /// Scanner failure policy: DEFAULT fail-closed (a configured scanner going dark must
    /// not silently readmit unchecked content); fail-open is an explicit opt-in and still
    /// marks the unscanned admit.
    #[test]
    fn a_broken_scanner_fails_closed_by_default_and_flags_on_opt_in_fail_open() {
        let temp = TempDir::new();
        let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
        let id = SigningId::provision(&temp, "source:owner", &log);
        let scanner = scanner_script(&temp, "crash.sh", CRASH);
        let args = [
            "assert",
            "repo:app",
            "note",
            "anything",
            "--authority",
            "high",
            "--source",
            "source:owner",
        ];

        let closed = run_dent8(
            &args,
            &owner_env(&id, &log, &[("DENT8_CONTENT_CHECK", scanner.as_str())]),
        );
        assert_eq!(closed.status.code(), Some(1), "{}", stdout(&closed));
        assert!(
            stderr(&closed).contains("content check failed closed"),
            "{}",
            stderr(&closed)
        );
        assert_eq!(
            fs::read_to_string(&log).unwrap_or_default(),
            "",
            "fail-closed must persist nothing"
        );

        let open_envs = owner_env(
            &id,
            &log,
            &[
                ("DENT8_CONTENT_CHECK", scanner.as_str()),
                ("DENT8_CONTENT_CHECK_FAIL_OPEN", "1"),
            ],
        );
        assert_success(&run_dent8(&args, &open_envs), "fail-open admits");
        let verify = run_dent8(&["verify"], &open_envs);
        assert_eq!(verify.status.code(), Some(1), "{}", stdout(&verify));
        assert!(
            stderr(&verify).contains("fail-open"),
            "the unscanned admit must stay visible: {}",
            stderr(&verify)
        );
    }

    /// A hung scanner is killed at the configured `DENT8_CONTENT_CHECK_TIMEOUT_MS` budget
    /// and counts as a scanner failure (fail-closed here).
    #[test]
    fn a_hung_scanner_is_killed_at_the_configured_timeout() {
        let temp = TempDir::new();
        let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
        let id = SigningId::provision(&temp, "source:owner", &log);
        let scanner = scanner_script(&temp, "hang.sh", "cat > /dev/null\nsleep 60");
        let envs = owner_env(
            &id,
            &log,
            &[
                ("DENT8_CONTENT_CHECK", scanner.as_str()),
                ("DENT8_CONTENT_CHECK_TIMEOUT_MS", "300"),
            ],
        );

        let started = std::time::Instant::now();
        let output = run_dent8(
            &[
                "assert",
                "repo:app",
                "note",
                "anything",
                "--authority",
                "high",
                "--source",
                "source:owner",
            ],
            &envs,
        );
        assert_eq!(output.status.code(), Some(1), "{}", stdout(&output));
        assert!(
            stderr(&output).contains("did not answer within"),
            "{}",
            stderr(&output)
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the write path must not wait out the scanner's sleep"
        );
    }

    /// An allow verdict is exact pass-through: the write lands and `verify` stays green.
    #[test]
    fn an_allow_verdict_admits_unchanged() {
        let temp = TempDir::new();
        let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
        let id = SigningId::provision(&temp, "source:owner", &log);
        let scanner = scanner_script(&temp, "allow-all.sh", ALLOW_ALL);
        let envs = owner_env(&id, &log, &[("DENT8_CONTENT_CHECK", scanner.as_str())]);

        assert_success(
            &run_dent8(
                &[
                    "assert",
                    "repo:app",
                    "note",
                    "clean",
                    "--authority",
                    "high",
                    "--source",
                    "source:owner",
                ],
                &envs,
            ),
            "allow verdict admits",
        );
        let verify = run_dent8(&["verify"], &envs);
        assert_success(&verify, "verify after an allowed write");
        assert!(
            !stdout(&verify).contains("CONTENT-FLAGGED"),
            "{}",
            stdout(&verify)
        );
    }
}

fn run_dent8(args: &[&str], envs: &[(&str, &str)]) -> Output {
    run_dent8_inner(None, args, envs)
}

#[cfg(unix)]
fn assert_private_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    assert_eq!(
        fs::metadata(path)
            .expect("private artifact metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[cfg(not(unix))]
fn assert_private_file(_path: &Path) {}

fn run_dent8_in(cwd: &Path, args: &[&str], envs: &[(&str, &str)]) -> Output {
    run_dent8_inner(Some(cwd), args, envs)
}

/// Run dent8 with `input` piped to stdin (for `capture` and other stdin-fed commands).
fn run_dent8_stdin(args: &[&str], input: &str, envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(dent8_bin());
    command
        .args(args)
        .env_remove("DENT8_STORE_URL")
        .env_remove("DENT8_LOG")
        .env_remove("DENT8_AUTHORITY")
        .env_remove("DENT8_REQUIRE_AUTHORITY")
        .env_remove("DENT8_TRUST")
        .env_remove("DENT8_ACTIVE_GRANTS")
        .env_remove("DENT8_GRANT")
        .env_remove("DENT8_IDENTITY_KEY")
        .env_remove("DENT8_ISSUER_KEY")
        .env_remove("DENT8_REQUIRE_IDENTITY")
        .env_remove("DENT8_CONTENT_CHECK")
        .env_remove("DENT8_CONTENT_CHECK_TIMEOUT_MS")
        .env_remove("DENT8_CONTENT_CHECK_FAIL_OPEN")
        .env_remove("DENT8_DAEMON_SOCKET")
        .env_remove("DENT8_EVAL_CAPTURE")
        .env_remove("DENT8_EVAL_AGENT")
        .env_remove("DENT8_EVAL_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn dent8");
    child
        .stdin
        .as_mut()
        .expect("dent8 stdin")
        .write_all(input.as_bytes())
        .expect("write dent8 stdin");
    drop(child.stdin.take());
    child.wait_with_output().expect("run dent8")
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
        .env_remove("DENT8_CONTENT_CHECK")
        .env_remove("DENT8_CONTENT_CHECK_TIMEOUT_MS")
        .env_remove("DENT8_CONTENT_CHECK_FAIL_OPEN")
        .env_remove("DENT8_DAEMON_SOCKET")
        .env_remove("DENT8_WITNESS_KEY")
        .env_remove("DENT8_WITNESS_PUBKEY")
        .env_remove("DENT8_WITNESS_LOG")
        .env_remove("DENT8_EVAL_CAPTURE")
        .env_remove("DENT8_EVAL_AGENT")
        .env_remove("DENT8_EVAL_SESSION");
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("run dent8")
}

fn run_dent8_mcp(input: &str, envs: &[(&str, &str)]) -> Output {
    let mut command = Command::new(dent8_bin());
    command
        .args(["mcp", "serve"])
        .env_remove("DENT8_STORE_URL")
        .env_remove("DENT8_LOG")
        .env_remove("DENT8_AUTHORITY")
        .env_remove("DENT8_REQUIRE_AUTHORITY")
        .env_remove("DENT8_TRUST")
        .env_remove("DENT8_ACTIVE_GRANTS")
        .env_remove("DENT8_GRANT")
        .env_remove("DENT8_IDENTITY_KEY")
        .env_remove("DENT8_ISSUER_KEY")
        .env_remove("DENT8_REQUIRE_IDENTITY")
        .env_remove("DENT8_CONTENT_CHECK")
        .env_remove("DENT8_CONTENT_CHECK_TIMEOUT_MS")
        .env_remove("DENT8_CONTENT_CHECK_FAIL_OPEN")
        .env_remove("DENT8_MCP_RECORD_RETRIEVAL")
        .env_remove("DENT8_WITNESS_KEY")
        .env_remove("DENT8_WITNESS_PUBKEY")
        .env_remove("DENT8_WITNESS_LOG")
        .env_remove("DENT8_EVAL_CAPTURE")
        .env_remove("DENT8_EVAL_AGENT")
        .env_remove("DENT8_EVAL_SESSION")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn dent8 mcp serve");
    child
        .stdin
        .as_mut()
        .expect("mcp stdin")
        .write_all(input.as_bytes())
        .expect("write mcp request");
    drop(child.stdin.take());
    child.wait_with_output().expect("run dent8 mcp serve")
}

#[cfg(all(unix, feature = "async-store"))]
fn run_dent8_mcp_proxy(socket: &str, input: &str, envs: &[(String, String)]) -> Output {
    let mut command = Command::new(dent8_bin());
    command
        .args(["mcp", "proxy", "--socket", socket])
        .env_remove("DENT8_STORE_URL")
        .env_remove("DENT8_LOG")
        .env_remove("DENT8_AUTHORITY")
        .env_remove("DENT8_REQUIRE_AUTHORITY")
        .env_remove("DENT8_TRUST")
        .env_remove("DENT8_ACTIVE_GRANTS")
        .env_remove("DENT8_GRANT")
        .env_remove("DENT8_IDENTITY_KEY")
        .env_remove("DENT8_ISSUER_KEY")
        .env_remove("DENT8_REQUIRE_IDENTITY")
        .env_remove("DENT8_CONTENT_CHECK")
        .env_remove("DENT8_CONTENT_CHECK_TIMEOUT_MS")
        .env_remove("DENT8_CONTENT_CHECK_FAIL_OPEN")
        .env_remove("DENT8_DAEMON_SOCKET")
        .env_remove("DENT8_WITNESS_KEY")
        .env_remove("DENT8_WITNESS_PUBKEY")
        .env_remove("DENT8_WITNESS_LOG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    let mut child = command.spawn().expect("spawn dent8 mcp proxy");
    child
        .stdin
        .as_mut()
        .expect("proxy stdin")
        .write_all(input.as_bytes())
        .expect("write proxy request");
    drop(child.stdin.take());
    child.wait_with_output().expect("run dent8 mcp proxy")
}

#[cfg(all(unix, feature = "async-store"))]
fn spawn_daemon(socket: &str, envs: &[(String, String)]) -> ChildGuard {
    let mut command = Command::new(dent8_bin());
    command
        .args(["daemon", "serve", "--socket", socket])
        .env_remove("DENT8_STORE_URL")
        .env_remove("DENT8_LOG")
        .env_remove("DENT8_AUTHORITY")
        .env_remove("DENT8_REQUIRE_AUTHORITY")
        .env_remove("DENT8_TRUST")
        .env_remove("DENT8_ACTIVE_GRANTS")
        .env_remove("DENT8_GRANT")
        .env_remove("DENT8_IDENTITY_KEY")
        .env_remove("DENT8_ISSUER_KEY")
        .env_remove("DENT8_REQUIRE_IDENTITY")
        .env_remove("DENT8_CONTENT_CHECK")
        .env_remove("DENT8_CONTENT_CHECK_TIMEOUT_MS")
        .env_remove("DENT8_CONTENT_CHECK_FAIL_OPEN")
        .env_remove("DENT8_DAEMON_SOCKET")
        .env_remove("DENT8_WITNESS_KEY")
        .env_remove("DENT8_WITNESS_PUBKEY")
        .env_remove("DENT8_WITNESS_LOG")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (key, value) in envs {
        command.env(key, value);
    }
    ChildGuard::new(command.spawn().expect("spawn dent8 daemon"))
}

#[cfg(all(unix, feature = "async-store"))]
fn wait_for_socket(socket: &Path, daemon: &mut ChildGuard) {
    for _ in 0..50 {
        if socket.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let output = daemon.kill_and_output();
    panic!(
        "daemon did not create socket {}\nstdout:\n{}\nstderr:\n{}",
        socket.display(),
        output
            .as_ref()
            .map_or_else(|| "<unavailable>".to_string(), stdout),
        output
            .as_ref()
            .map_or_else(|| "<unavailable>".to_string(), stderr)
    );
}

#[cfg(all(unix, feature = "async-store"))]
fn read_test_env_file(path: &Path) -> Vec<(String, String)> {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let (key, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("{} is not KEY=VALUE: {line}", path.display()));
            Some((key.trim().to_string(), shell_unquote_for_test(value.trim())))
        })
        .collect()
}

#[cfg(all(unix, feature = "async-store"))]
fn env_refs(envs: &[(String, String)]) -> Vec<(&str, &str)> {
    envs.iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect()
}

#[cfg(all(unix, feature = "async-store"))]
fn shell_unquote_for_test(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        value[1..value.len() - 1].replace("'\\''", "'")
    } else {
        value.to_string()
    }
}

// Unix-only (not async-store-gated): the content-check hook tests drive the MCP
// server in every build flavor.
#[cfg(unix)]
fn json_rpc_lines(messages: &[Value]) -> String {
    let mut text = String::new();
    for message in messages {
        text.push_str(&serde_json::to_string(message).expect("serialize JSON-RPC message"));
        text.push('\n');
    }
    text
}

// Unix-only (not async-store-gated): the content-check hook tests drive the MCP
// server in every build flavor.
#[cfg(unix)]
fn json_response(responses: &[Value], id: i64) -> &Value {
    responses
        .iter()
        .find(|response| response["id"] == id)
        .unwrap_or_else(|| panic!("missing response id {id}: {responses:#?}"))
}

#[cfg(all(unix, feature = "async-store"))]
struct ChildGuard {
    child: Option<std::process::Child>,
}

#[cfg(all(unix, feature = "async-store"))]
impl ChildGuard {
    fn new(child: std::process::Child) -> Self {
        Self { child: Some(child) }
    }

    fn kill_and_output(&mut self) -> Option<Output> {
        let mut child = self.child.take()?;
        let _ = child.kill();
        child.wait_with_output().ok()
    }
}

#[cfg(all(unix, feature = "async-store"))]
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
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

fn line_count(path: &str) -> usize {
    fs::read_to_string(path)
        .expect("read file")
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

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
        stdout.contains("mcp smoke: initialize + tools/list + runtime_status OK"),
        "{stdout}"
    );
    assert!(
        stdout.contains("mcp write-check: accepted trusted diagnostic:doctor-mcp-"),
        "{stdout}"
    );
}

fn read_file(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

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

fn seed_local_mcp_target(dir: &str) {
    let target = Path::new(dir).join("target-sqlite/debug/dent8");
    fs::create_dir_all(target.parent().expect("local target parent"))
        .unwrap_or_else(|error| panic!("create {}: {error}", target.display()));
    fs::copy(dent8_bin(), &target)
        .unwrap_or_else(|error| panic!("copy local target {}: {error}", target.display()));
    make_executable(&target);
}

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

#[cfg(unix)]
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

/// A signed identity provisioned for a test. Above-agent authority (medium/high/canonical) now
/// requires a valid signed identity to be trusted, so a test that makes such writes provisions one
/// of these per source and threads [`SigningId::env_for`] into the `run_dent8` calls that write as
/// that source. The bundle authorizes `source` up to Canonical for every subject; each `SigningId`
/// is a self-contained bundle (its own trust root + issuer key + active grant), so several can
/// share one store log to cover a multi-source test.
struct SigningId {
    trust: String,
    grant: String,
    key: String,
    active_grants: String,
}

impl SigningId {
    /// Bootstrap a signed identity authorizing `source` (up to Canonical) in a fresh bundle under
    /// `temp`. The issuer key is written outside the bundle. `_log` is accepted for call-site
    /// readability (each write picks its store via [`SigningId::env_for`]).
    fn provision(temp: &TempDir, source: &str, _log: &str) -> Self {
        let slug = path_slug(source);
        let dir = temp.file(&format!("id-{slug}"));
        let dir_str = dir.to_string_lossy().into_owned();
        let issuer_key = temp
            .file(&format!("issuer-{slug}.key"))
            .to_string_lossy()
            .into_owned();
        let out = run_dent8(
            &[
                "identity",
                "bootstrap",
                "--dir",
                &dir_str,
                "--source",
                source,
                "--max",
                "canonical",
                "--issuer-key",
                &issuer_key,
            ],
            &[],
        );
        assert_success(&out, "identity bootstrap (test signing id)");
        Self {
            trust: dir.join("trust.json").to_string_lossy().into_owned(),
            grant: dir
                .join(format!("grants/{slug}.grant.json"))
                .to_string_lossy()
                .into_owned(),
            key: dir
                .join(format!("identities/{slug}.key"))
                .to_string_lossy()
                .into_owned(),
            active_grants: dir
                .join("active-grants.json")
                .to_string_lossy()
                .into_owned(),
        }
    }

    /// The process env that authorizes signed above-agent writes as this identity's source, pointed
    /// at store `log`. Pass as `&id.env_for(&log)` to `run_dent8`; a round-trip test can point one
    /// identity at several stores.
    fn env_for<'a>(&'a self, log: &'a str) -> Vec<(&'a str, &'a str)> {
        let mut env = self.signing_only();
        env.push(("DENT8_LOG", log));
        env
    }

    /// Just the signed-identity vars, with NO `DENT8_LOG`/`DENT8_STORE_URL`. Lets a discovery test
    /// leave the store unset (so the CLI resolves it by discovery) while still authorizing a signed
    /// above-agent write.
    fn signing_only(&self) -> Vec<(&str, &str)> {
        vec![
            ("DENT8_TRUST", self.trust.as_str()),
            ("DENT8_GRANT", self.grant.as_str()),
            ("DENT8_IDENTITY_KEY", self.key.as_str()),
            ("DENT8_ACTIVE_GRANTS", self.active_grants.as_str()),
            ("DENT8_REQUIRE_IDENTITY", "1"),
        ]
    }
}

/// Mirror of the CLI's `source_slug`: map any char outside `[A-Za-z0-9._-]` to `_`, so a test can
/// predict the on-disk grant/key file names a bootstrapped `source` produces.
fn path_slug(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}
