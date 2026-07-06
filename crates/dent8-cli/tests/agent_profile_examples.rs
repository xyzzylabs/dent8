use serde_json::Value;

#[test]
fn gemini_and_cascade_mcp_samples_are_valid_and_use_distinct_logs() {
    let samples = [
        (
            "gemini",
            include_str!("../../../examples/gemini/settings.sample.json"),
            "gemini-memory.jsonl",
        ),
        (
            "cascade",
            include_str!("../../../examples/cascade/mcp_config.sample.json"),
            "cascade-memory.jsonl",
        ),
    ];

    for (agent, raw, expected_log) in samples {
        let config = serde_json::from_str::<Value>(raw).expect("sample JSON parses");
        let server = &config["mcpServers"]["dent8"];
        assert_eq!(server["command"], "dent8", "{agent} command");
        assert_eq!(server["args"], serde_json::json!(["mcp", "serve"]));
        assert!(
            server["env"]["DENT8_LOG"]
                .as_str()
                .expect("DENT8_LOG string")
                .contains(expected_log),
            "{agent} should keep a distinct dent8 log"
        );
        assert_eq!(server["env"]["DENT8_REQUIRE_AUTHORITY"], "1");
        assert_eq!(server["env"]["DENT8_REQUIRE_IDENTITY"], "1");
        assert!(server["env"]["DENT8_TRUST"].as_str().is_some());
        assert!(server["env"]["DENT8_GRANT"].as_str().is_some());
        assert!(server["env"]["DENT8_IDENTITY_KEY"].as_str().is_some());
    }
}

#[test]
fn gemini_and_cascade_docs_name_their_source_ids() {
    let docs = [
        (
            "examples/gemini/README.md",
            include_str!("../../../examples/gemini/README.md"),
            "source:gemini",
        ),
        (
            "examples/cascade/README.md",
            include_str!("../../../examples/cascade/README.md"),
            "source:cascade",
        ),
    ];

    for (path, text, source) in docs {
        assert!(
            text.contains(source),
            "{path} should document the source id {source}"
        );
    }
}

#[test]
fn vercel_ai_sdk_example_uses_dent8_mcp_and_source_id() {
    let readme = include_str!("../../../examples/vercel-ai-sdk/README.md");
    let script = include_str!("../../../examples/vercel-ai-sdk/dent8_memory_agent.ts");

    assert!(readme.contains("@ai-sdk/mcp"));
    assert!(readme.contains("source:vercel-ai-sdk"));
    assert!(script.contains("createMCPClient"));
    assert!(script.contains("StdioClientTransport"));
    assert!(script.contains("args: [\"mcp\", \"serve\"]"));
    assert!(script.contains("mcpClient.tools()"));
    assert!(script.contains("stepCountIs(8)"));
    assert!(script.contains("source:vercel-ai-sdk"));
    assert!(script.contains("DENT8_REQUIRE_IDENTITY"));
    assert!(script.contains("source_vercel-ai-sdk.grant.json"));
}

#[test]
fn operated_witness_example_retains_grant_log_heads() {
    let compose = include_str!("../../../examples/witness-operated/compose.yml");
    let publisher = include_str!("../../../examples/witness-operated/publisher.sh");
    let monitor = include_str!("../../../examples/witness-operated/monitor.sh");
    let systemd_signer =
        include_str!("../../../examples/witness-operated/systemd/dent8-witness-signer.service");
    let systemd_monitor =
        include_str!("../../../examples/witness-operated/systemd/dent8-witness-monitor.service");

    assert!(compose.contains("DENT8_WITNESS_GRANTS_LOG"));
    assert!(compose.contains("PUBLISHED_GRANTS"));
    assert!(publisher.contains("--grants"));
    assert!(publisher.contains("DENT8_WITNESS_GRANTS_LOG"));
    assert!(monitor.contains("--grants"));
    assert!(monitor.contains("PUBLISHED_GRANTS"));
    assert!(systemd_signer.contains("DENT8_WITNESS_GRANTS_LOG"));
    assert!(systemd_monitor.contains("--grants"));
    assert!(systemd_monitor.contains("PUBLISHED_GRANTS"));
}

#[test]
fn daemon_example_documents_authenticated_single_source_writes() {
    let readme = include_str!("../../../examples/daemon/README.md");
    let demo = include_str!("../../../examples/daemon/demo.sh");

    assert!(readme.contains("DENT8_DAEMON_SOCKET"));
    assert!(readme.contains("dent8/hello"));
    assert!(readme.contains("dent8/prove"));
    assert!(readme.contains("single-source"));
    assert!(readme.contains("offline-verifiable Ed25519 attestations"));
    assert!(demo.contains("DENT8_DAEMON_SOCKET"));
    assert!(demo.contains("many connections sharing one identity"));
}
