use serde_json::{Value, json};

use crate::{
    CliOutput, ContextArgs, FactsListArgs, log_path, mcp,
    ops::{self, OpError},
    print_json_stdout_with_code,
    status::Status,
    verify_json, verify_log,
};

/// Build the shared debugger/control-plane snapshot used by the CLI and MCP.
pub(crate) fn snapshot_text_and_json(
    path: &str,
    include_diagnostics: bool,
    include_context: bool,
    tool: &str,
) -> (String, Value) {
    let (_runtime_text, runtime_status) = mcp::runtime_status_parts(path);
    let facts = facts_payload(path, include_diagnostics);
    let verify = verify_payload(path);
    let conflicts = conflicts_payload(path);
    let context = if include_context {
        Some(context_payload(path, include_diagnostics))
    } else {
        None
    };
    let (witness_status, witness_unwitnessed, attention) =
        attention_from_runtime(&runtime_status, &verify, &conflicts);
    let status = snapshot_status(
        &runtime_status,
        &facts,
        &verify,
        &conflicts,
        &witness_status,
    );
    let summary = json!({
        "runtime_status": runtime_status["status"].as_str().unwrap_or(Status::Degraded.as_str()),
        "facts": count(&facts),
        "hidden_diagnostics_count": integer(&facts, "hidden_diagnostics_count"),
        "integrity_verified": verify["ok"].as_bool().unwrap_or(false),
        "conflicts": count(&conflicts),
        "include_diagnostics": include_diagnostics,
        "include_context": include_context,
        "witness_status": witness_status,
        "witness_unwitnessed_events": witness_unwitnessed,
        "attention": attention,
    });
    let mut structured = json!({
        "status": status,
        "tool": tool,
        "runtime_status": runtime_status,
        "facts": facts,
        "verify": verify,
        "conflicts": conflicts,
        "summary": summary,
    });
    if let Some(context) = context
        && let Some(object) = structured.as_object_mut()
    {
        object.insert("context".to_string(), context);
    }
    (format_snapshot(&structured), structured)
}

pub(crate) fn cmd_snapshot(args: &crate::SnapshotArgs, output: CliOutput) -> i32 {
    let (text, structured) = snapshot_text_and_json(
        &log_path(),
        args.include_diagnostics,
        args.include_context,
        "snapshot",
    );
    let code = match structured["status"].as_str() {
        Some("integrity_issues" | "degraded") => 1,
        _ => 0,
    };
    match output {
        CliOutput::Text => {
            println!("{text}");
            code
        }
        CliOutput::Json => print_json_stdout_with_code(&structured, code),
    }
}

fn facts_payload(path: &str, include_diagnostics: bool) -> Value {
    let filters = FactsListArgs {
        kind: None,
        key: None,
        predicate: None,
        include_diagnostics,
    };
    match ops::facts_list_outcome(path, &filters) {
        Ok(outcome) => ops::facts_list_json(&outcome),
        Err(error) => snapshot_error_json("facts list", &error),
    }
}

fn context_payload(path: &str, include_diagnostics: bool) -> Value {
    let args = ContextArgs {
        kind: None,
        key: None,
        predicate: None,
        include_stale: false,
        include_diagnostics,
        record_retrieval: false,
        purpose: "context-pack".to_string(),
    };
    match crate::context::context_outcome(path, &args) {
        Ok(outcome) => crate::context::context_json(&outcome),
        Err(error) => snapshot_error_json("context", &error),
    }
}

fn verify_payload(path: &str) -> Value {
    let (ok, report) = match verify_log(path) {
        Ok(report) => (true, report),
        Err(report) => (false, report),
    };
    verify_json(ok, &report)
}

fn conflicts_payload(path: &str) -> Value {
    match ops::conflicts_outcome(path) {
        Ok(conflicts) => ops::conflicts_json(&conflicts),
        Err(error) => snapshot_error_json("conflicts", &error),
    }
}

fn snapshot_error_json(tool: &str, error: &OpError) -> Value {
    let mut payload = ops::op_error_json(error);
    if let Some(object) = payload.as_object_mut() {
        object.insert("tool".to_string(), json!(tool));
    }
    payload
}

fn attention_from_runtime(
    runtime_status: &Value,
    verify: &Value,
    conflicts: &Value,
) -> (String, Option<u64>, Vec<String>) {
    let witness = &runtime_status["witness"];
    let witness_status = witness["load_status"]
        .as_str()
        .unwrap_or("unconfigured")
        .to_string();
    let mut attention = Vec::new();
    let mut unwitnessed = None;

    if let Some(messages) = witness["messages"].as_array() {
        for message in messages {
            let level = message["level"].as_str().unwrap_or("");
            let text = message["message"].as_str().unwrap_or("");
            if level == "WARN" || level == "FAIL" {
                attention.push(text.to_string());
            }
            if let Some(n) = parse_unwitnessed_count(text) {
                unwitnessed = Some(n);
            }
        }
    }

    if verify["ok"].as_bool() == Some(false) {
        attention.push(
            verify["summary"]
                .as_str()
                .or_else(|| verify["report"].as_str())
                .unwrap_or("integrity issues")
                .to_string(),
        );
    }

    let conflict_count = count(conflicts);
    if conflict_count > 0 {
        attention.push(format!("{conflict_count} contested fact stream(s)"));
    }

    (witness_status, unwitnessed, attention)
}

fn parse_unwitnessed_count(message: &str) -> Option<u64> {
    // "... by 3 unwitnessed event(s)"
    let marker = " by ";
    let start = message.find(marker)? + marker.len();
    let rest = &message[start..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() || !rest[digits.len()..].contains("unwitnessed") {
        return None;
    }
    digits.parse().ok()
}

fn snapshot_status(
    runtime_status: &Value,
    facts: &Value,
    verify: &Value,
    conflicts: &Value,
    witness_status: &str,
) -> &'static str {
    if verify["status"] == Status::IntegrityIssues.as_str() {
        return Status::IntegrityIssues.as_str();
    }
    if runtime_status["status"] == Status::Degraded.as_str()
        || facts["status"] != Status::Ok.as_str()
        || conflicts["status"] == Status::Invalid.as_str()
        || conflicts["status"] == Status::Rejected.as_str()
        || conflicts["status"] == Status::Failed.as_str()
        || witness_status == "failed"
        || witness_status == "warn"
    {
        return Status::Degraded.as_str();
    }
    if conflicts["status"] == Status::Contested.as_str() {
        return Status::Contested.as_str();
    }
    Status::Ok.as_str()
}

fn format_snapshot(snapshot: &Value) -> String {
    let summary = &snapshot["summary"];
    let store = &snapshot["runtime_status"]["store"];
    let store_backend = store["backend"].as_str().unwrap_or("unknown");
    let store_events = store["event_count"]
        .as_u64()
        .map_or_else(|| "unknown".to_string(), |count| count.to_string());
    let hidden = integer(summary, "hidden_diagnostics_count");
    let hidden_note = if hidden == 0 {
        String::new()
    } else {
        format!(", {hidden} hidden diagnostic")
    };
    let attention = summary["attention"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("; ")
        })
        .filter(|s| !s.is_empty())
        .map(|s| format!("\n  attention: {s}"))
        .unwrap_or_default();
    let witness = summary["witness_status"].as_str().unwrap_or("unconfigured");
    let unwitnessed = summary["witness_unwitnessed_events"]
        .as_u64()
        .map(|n| format!(" (unwitnessed={n})"))
        .unwrap_or_default();
    format!(
        "dent8 snapshot\n  status: {}\n  runtime: {}\n  store: {} (events={})\n  facts: {}{}\n  verify: {}\n  conflicts: {}\n  witness: {}{}{}\n",
        snapshot["status"].as_str().unwrap_or("unknown"),
        summary["runtime_status"].as_str().unwrap_or("unknown"),
        store_backend,
        store_events,
        integer(summary, "facts"),
        hidden_note,
        if summary["integrity_verified"].as_bool().unwrap_or(false) {
            "ok"
        } else {
            "integrity issues"
        },
        integer(summary, "conflicts"),
        witness,
        unwitnessed,
        attention,
    )
}

fn count(value: &Value) -> i64 {
    integer(value, "count")
}

fn integer(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}
