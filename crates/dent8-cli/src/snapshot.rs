use serde_json::{Value, json};

use crate::{
    CliOutput, FactsListArgs, log_path, mcp,
    ops::{self, OpError},
    print_json_stdout_with_code,
    status::Status,
    verify_json, verify_log,
};

/// Build the shared debugger/control-plane snapshot used by the CLI and MCP.
pub(crate) fn snapshot_text_and_json(
    path: &str,
    include_diagnostics: bool,
    tool: &str,
) -> (String, Value) {
    let (_runtime_text, runtime_status) = mcp::runtime_status_parts(path);
    let facts = facts_payload(path, include_diagnostics);
    let verify = verify_payload(path);
    let conflicts = conflicts_payload(path);
    let status = snapshot_status(&runtime_status, &facts, &verify, &conflicts);
    let summary = json!({
        "runtime_status": runtime_status["status"].as_str().unwrap_or(Status::Degraded.as_str()),
        "facts": count(&facts),
        "hidden_diagnostics_count": integer(&facts, "hidden_diagnostics_count"),
        "integrity_verified": verify["ok"].as_bool().unwrap_or(false),
        "conflicts": count(&conflicts),
        "include_diagnostics": include_diagnostics,
    });
    let structured = json!({
        "status": status,
        "tool": tool,
        "runtime_status": runtime_status,
        "facts": facts,
        "verify": verify,
        "conflicts": conflicts,
        "summary": summary,
    });
    (format_snapshot(&structured), structured)
}

pub(crate) fn cmd_snapshot(args: &crate::SnapshotArgs, output: CliOutput) -> i32 {
    let (text, structured) =
        snapshot_text_and_json(&log_path(), args.include_diagnostics, "snapshot");
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

fn snapshot_status(
    runtime_status: &Value,
    facts: &Value,
    verify: &Value,
    conflicts: &Value,
) -> &'static str {
    if verify["status"] == Status::IntegrityIssues.as_str() {
        return Status::IntegrityIssues.as_str();
    }
    if runtime_status["status"] == Status::Degraded.as_str()
        || facts["status"] != Status::Ok.as_str()
        || conflicts["status"] == Status::Invalid.as_str()
        || conflicts["status"] == Status::Rejected.as_str()
        || conflicts["status"] == Status::Failed.as_str()
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
    format!(
        "dent8 snapshot\n  status: {}\n  runtime: {}\n  store: {} (events={})\n  facts: {}{}\n  verify: {}\n  conflicts: {}\n",
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
    )
}

fn count(value: &Value) -> i64 {
    integer(value, "count")
}

fn integer(value: &Value, key: &str) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(0)
}
