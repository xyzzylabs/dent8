use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU32, Ordering},
};

use serde_json::{Value, json};

const MCP_TOOLS: &[&str] = &[
    "list_facts",
    "verify",
    "conflicts",
    "assert",
    "supersede",
    "retract",
    "contradict",
    "reinforce",
    "expire",
    "derive",
    "explain",
    "replay",
];

#[test]
fn agent_example_configs_are_valid_and_use_distinct_sources() {
    let json_examples = [
        (
            "claude-code",
            include_str!("../../../examples/claude-code/mcp.sample.json"),
            "claude-memory.jsonl",
        ),
        (
            "cursor",
            include_str!("../../../examples/cursor/mcp.sample.json"),
            "cursor-memory.jsonl",
        ),
        (
            "grok-build",
            include_str!("../../../examples/grok-build/mcp.sample.json"),
            "grok-build-memory.jsonl",
        ),
    ];

    for (agent, raw, expected_log) in json_examples {
        let config = serde_json::from_str::<Value>(raw).expect("sample JSON parses");
        let server = &config["mcpServers"]["dent8"];
        assert_dent8_stdio_server(agent, server);
        assert!(
            server["env"]["DENT8_LOG"]
                .as_str()
                .expect("DENT8_LOG string")
                .contains(expected_log),
            "{agent} should keep a distinct dent8 log"
        );
    }

    let hecate = serde_json::from_str::<Value>(include_str!(
        "../../../examples/hecate/task-with-dent8.sample.json"
    ))
    .expect("Hecate task sample parses");
    let server = &hecate["mcp_servers"][0];
    assert_dent8_stdio_server("hecate", server);
    assert_eq!(server["name"], "dent8");
    assert_eq!(server["approval_policy"], "require_approval");
    assert!(
        server["env"]["DENT8_LOG"]
            .as_str()
            .expect("DENT8_LOG string")
            .contains("hecate-memory.jsonl")
    );

    let codex = include_str!("../../../examples/codex/config.sample.toml");
    assert!(codex.contains("[mcp_servers.dent8]"));
    assert!(codex.contains("command = \"dent8\""));
    assert!(codex.contains("args = [\"mcp\", \"serve\"]"));
    assert!(codex.contains("DENT8_LOG = \"/abs/path/to/project/.dent8/codex-memory.jsonl\""));
    assert!(codex.contains("DENT8_AUTHORITY = \"/abs/path/to/project/.dent8/authority.json\""));
    assert!(codex.contains("DENT8_REQUIRE_AUTHORITY = \"1\""));

    let source_ids = [
        ("examples/codex/README.md", "source:codex"),
        ("examples/claude-code/README.md", "source:claude-code"),
        ("examples/cursor/README.md", "source:cursor"),
        ("examples/grok-build/README.md", "source:grok-build"),
        ("examples/hecate/README.md", "source:hecate"),
    ];
    let unique_sources = source_ids
        .iter()
        .map(|(_, source)| *source)
        .collect::<HashSet<_>>();
    assert_eq!(
        unique_sources.len(),
        source_ids.len(),
        "agent examples must not collapse provenance into a generic source"
    );
    for (path, source) in source_ids {
        let text = read_repo_file(path);
        assert!(
            text.contains(source),
            "{path} should document the source id {source}"
        );
    }
}

#[test]
fn mcp_server_enforces_agent_authority_and_exposes_read_audit_tools() {
    let temp = TempDir::new();
    let authority_path = temp.file("authority.json");
    let log_path = temp.file("memory.jsonl");

    let authority = Command::new(dent8_bin())
        .args(["authority", "add", "source:codex", "high"])
        .env("DENT8_AUTHORITY", &authority_path)
        .env_remove("DENT8_DATABASE_URL")
        .env_remove("DENT8_STORE_URL")
        .output()
        .expect("run dent8 authority add");
    assert!(
        authority.status.success(),
        "authority add failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&authority.stdout),
        String::from_utf8_lossy(&authority.stderr)
    );

    let requests = [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "assert", "arguments": {
                "subject_kind": "repo",
                "subject_key": "myproj",
                "predicate": "database",
                "value": "postgres",
                "authority": "high",
                "source": "source:codex"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "supersede", "arguments": {
                "subject_kind": "repo",
                "subject_key": "myproj",
                "predicate": "database",
                "value": "mysql",
                "authority": "high",
                "source": "source:cursor"
            }}
        }),
        json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": "list_facts", "arguments": {} }
        }),
        json!({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": { "name": "verify", "arguments": {} }
        }),
    ]
    .into_iter()
    .map(|request| serde_json::to_string(&request).expect("serialize request"))
    .collect::<Vec<_>>()
    .join("\n");

    let output = run_mcp_server(
        &(requests + "\n"),
        &[
            ("DENT8_LOG", log_path.to_string_lossy().into_owned()),
            (
                "DENT8_AUTHORITY",
                authority_path.to_string_lossy().into_owned(),
            ),
            ("DENT8_REQUIRE_AUTHORITY", "1".to_string()),
        ],
    );
    let responses = output
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("JSON-RPC response"))
        .collect::<Vec<_>>();

    let init = response_with_id(&responses, 1);
    assert_eq!(init["result"]["serverInfo"]["name"], "dent8");
    let instructions = init["result"]["instructions"]
        .as_str()
        .expect("server instructions");
    assert!(instructions.contains("memory integrity firewall"));
    assert!(instructions.contains("list_facts"));

    let tools = response_with_id(&responses, 2)["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name"))
        .collect::<Vec<_>>();
    assert_eq!(tools, MCP_TOOLS);

    let accepted = response_with_id(&responses, 3);
    assert!(!tool_is_error(accepted));
    assert!(tool_text(accepted).contains("ACCEPTED"));

    let rejected = response_with_id(&responses, 4);
    assert!(tool_is_error(rejected));
    let rejected_text = tool_text(rejected);
    assert!(
        rejected_text.contains("authority ceiling"),
        "{rejected_text}"
    );
    assert!(rejected_text.contains("source:cursor"), "{rejected_text}");

    let facts = response_with_id(&responses, 5);
    assert!(!tool_is_error(facts));
    assert!(tool_text(facts).contains("dent8://repo/myproj/database"));

    let verify = response_with_id(&responses, 6);
    assert!(!tool_is_error(verify));
    assert!(tool_text(verify).contains("STRUCTURAL integrity holds"));
}

/// Run a `dent8` subcommand with a controlled environment (per-process, so no env races).
fn run_dent8(args: &[&str], envs: &[(&str, &str)]) -> std::process::Output {
    let mut command = Command::new(dent8_bin());
    command
        .args(args)
        .env_remove("DENT8_DATABASE_URL")
        .env_remove("DENT8_STORE_URL");
    for (key, value) in envs {
        command.env(key, value);
    }
    command.output().expect("run dent8")
}

/// ADR 0011, through the CLI surface: an explicit `expire` that under-ranks the incumbent is
/// rejected (a low-trust source cannot terminally close a high-authority fact by calling it
/// stale); an equal-authority expire is accepted.
#[test]
fn cli_expire_is_authority_gated() {
    let temp = TempDir::new();
    let log = temp.file("memory.jsonl").to_string_lossy().into_owned();
    // absent -> permissive dev mode
    let missing_registry = temp.file("authority.json").to_string_lossy().into_owned();
    let envs: &[(&str, &str)] = &[("DENT8_LOG", &log), ("DENT8_AUTHORITY", &missing_registry)];

    assert!(
        run_dent8(
            &[
                "assert",
                "repo",
                "p",
                "database",
                "postgres",
                "high",
                "source:owner"
            ],
            envs,
        )
        .status
        .success(),
        "high-authority assert should be accepted"
    );

    let low = run_dent8(
        &["expire", "repo", "p", "database", "low", "source:owner"],
        envs,
    );
    assert!(
        !low.status.success(),
        "a low-authority expire of a High fact must be rejected"
    );
    let stderr = String::from_utf8_lossy(&low.stderr);
    assert!(
        stderr.contains("insufficient authority"),
        "rejection should name the authority gate: {stderr}"
    );

    assert!(
        run_dent8(
            &["expire", "repo", "p", "database", "high", "source:owner"],
            envs,
        )
        .status
        .success(),
        "an equal-authority expire must be accepted"
    );
}

/// The bootstrap exemption: `dent8 authority add` and the diagnostic `authority list` must
/// keep working under `DENT8_REQUIRE_AUTHORITY=1` even with no registry yet — otherwise the
/// fail-closed flag would lock the operator out of creating or inspecting the registry.
#[test]
fn authority_add_and_list_work_under_require_authority() {
    let temp = TempDir::new();
    let authority = temp.file("authority.json");
    let authority_env = authority.to_string_lossy().into_owned();
    let required: &[(&str, &str)] = &[
        ("DENT8_AUTHORITY", &authority_env),
        ("DENT8_REQUIRE_AUTHORITY", "1"),
    ];

    // List before the registry exists must NOT error — it reports the fail-closed state.
    let list_before = run_dent8(&["authority", "list"], required);
    assert!(
        list_before.status.success(),
        "authority list must not be blocked by the fail-closed flag\nstderr:\n{}",
        String::from_utf8_lossy(&list_before.stderr)
    );
    assert!(
        String::from_utf8_lossy(&list_before.stdout).contains("BLOCKED"),
        "list should explain that writes are blocked until a registry exists: {}",
        String::from_utf8_lossy(&list_before.stdout)
    );

    // Add must bootstrap the registry despite the flag.
    assert!(
        run_dent8(&["authority", "add", "source:codex", "high"], required)
            .status
            .success(),
        "authority add must bootstrap the registry under the fail-closed flag"
    );
    assert!(authority.exists(), "the registry file should now exist");

    let list_after = run_dent8(&["authority", "list"], required);
    assert!(list_after.status.success());
    assert!(
        String::from_utf8_lossy(&list_after.stdout).contains("source:codex"),
        "list should show the granted source"
    );
}

fn assert_dent8_stdio_server(agent: &str, server: &Value) {
    assert!(
        server.is_object(),
        "{agent} sample should define a dent8 server object"
    );
    assert_eq!(server["args"], json!(["mcp", "serve"]));
    assert_eq!(server["env"]["DENT8_REQUIRE_AUTHORITY"], "1");
    assert!(
        server["env"]["DENT8_AUTHORITY"]
            .as_str()
            .expect("DENT8_AUTHORITY string")
            .contains("authority.json"),
        "{agent} should wire an authority registry"
    );
    assert!(
        server["command"]
            .as_str()
            .expect("command string")
            .contains("dent8"),
        "{agent} should launch dent8"
    );
}

fn run_mcp_server(input: &str, envs: &[(&str, String)]) -> String {
    let mut command = Command::new(dent8_bin());
    command
        .args(["mcp", "serve"])
        .env_remove("DENT8_DATABASE_URL")
        .env_remove("DENT8_STORE_URL")
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
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write JSON-RPC input");
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("wait for dent8 mcp serve");
    assert!(
        output.status.success(),
        "dent8 mcp serve failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("stdout is utf-8")
}

fn response_with_id(responses: &[Value], id: i64) -> &Value {
    responses
        .iter()
        .find(|response| response["id"] == id)
        .unwrap_or_else(|| panic!("missing JSON-RPC response id {id}: {responses:#?}"))
}

fn tool_is_error(response: &Value) -> bool {
    response["result"]["isError"]
        .as_bool()
        .expect("tool isError flag")
}

fn tool_text(response: &Value) -> &str {
    response["result"]["content"][0]["text"]
        .as_str()
        .expect("tool text")
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

fn read_repo_file(path: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(path),
    )
    .expect("read repo file")
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dent8-agent-integration-{}-{n}",
            std::process::id()
        ));
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
