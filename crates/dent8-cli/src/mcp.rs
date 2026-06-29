//! A minimal Model Context Protocol (MCP) server over stdio, exposing the dent8 firewall
//! to agent clients. Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP
//! stdio convention); the loop is synchronous, so no async runtime is needed.
//!
//! It speaks just enough MCP to be useful:
//! - `initialize`, `tools/list`, and `tools/call` for the full belief surface — `assert` /
//!   `supersede` / `retract` / `contradict` / `explain` / `replay` — which dispatch to the
//!   *same* shared `op_*` functions the CLI uses, so the firewall decision is identical on
//!   both surfaces;
//! - `resources/list` / `resources/read`, exposing each believed fact stream as a readable
//!   resource at `dent8://{kind}/{key}/{predicate}` (read returns the integrity receipt);
//! - **JSON-RPC 2.0 batches** — a top-level array of requests yields an array of responses
//!   (notifications omitted), per the spec.
//!
//! Notifications (e.g. `notifications/initialized`) are accepted silently.

use std::io::{BufRead, Write};

use serde_json::{Value, json};

use crate::{
    OpError, log_path, op_assert, op_contradict, op_expire, op_explain, op_list_subjects,
    op_reinforce, op_replay, op_retract, op_supersede, parse_authority, with_write_retry,
};

/// The MCP protocol revision we advertise (negotiated in `initialize`).
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Run the stdio server loop until EOF. Returns a process exit code.
pub fn serve() -> i32 {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let path = log_path();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                eprintln!("mcp: stdin error: {error}");
                return 1;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(request) => dispatch(&request, &path),
            Err(error) => Some(error_response(
                &Value::Null,
                -32700,
                &format!("parse error: {error}"),
            )),
        };
        if let Some(response) = response {
            let serialized = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
            if writeln!(stdout, "{serialized}").is_err() || stdout.flush().is_err() {
                return 1;
            }
        }
    }
    0
}

/// Dispatch one parsed JSON-RPC message: a single request object, or a **batch** (a
/// non-empty array of requests → an array of responses, omitting notifications; an empty
/// array is an invalid request). Returns `None` when there is nothing to send (a lone
/// notification, or a batch of only notifications).
fn dispatch(message: &Value, path: &str) -> Option<Value> {
    let Some(batch) = message.as_array() else {
        return handle(message, path);
    };
    if batch.is_empty() {
        return Some(error_response(
            &Value::Null,
            -32600,
            "invalid request: empty batch",
        ));
    }
    let responses: Vec<Value> = batch.iter().filter_map(|item| handle(item, path)).collect();
    // A batch containing only notifications gets no reply (JSON-RPC 2.0).
    if responses.is_empty() {
        None
    } else {
        Some(Value::Array(responses))
    }
}

/// Handle one JSON-RPC request object. Returns the response value, or `None` for a
/// notification (a request with no `id`, e.g. `notifications/initialized`).
fn handle(request: &Value, path: &str) -> Option<Value> {
    // Each message (or batch element) must be a single JSON-RPC object; batches are unwrapped
    // one level up in `dispatch`, so a nested array here is itself an invalid request.
    if !request.is_object() {
        return Some(error_response(
            &Value::Null,
            -32600,
            "invalid request: expected a JSON-RPC object",
        ));
    }
    // The id, when present, must be a string, number, or null.
    let id = request.get("id").cloned();
    if let Some(id) = &id
        && !(id.is_string() || id.is_number() || id.is_null())
    {
        return Some(error_response(
            &Value::Null,
            -32600,
            "invalid request: id must be a string, number, or null",
        ));
    }
    // A request object must carry a `method`; one without is an *invalid request* (whether
    // or not it has an id), not a silently-dropped notification.
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return Some(error_response(
            id.as_ref().unwrap_or(&Value::Null),
            -32600,
            "invalid request: missing method",
        ));
    };
    // A notification (a valid method, no id) gets **no response and no side effect**
    // (JSON-RPC 2.0): `?` returns `None` here, before the method dispatch, so an id-less
    // `tools/call` never executes.
    let id = id?;
    match method {
        "initialize" => Some(result_response(
            &id,
            &json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {}, "resources": {} },
                "serverInfo": { "name": "dent8", "version": env!("CARGO_PKG_VERSION") },
            }),
        )),
        "tools/list" => Some(result_response(&id, &json!({ "tools": tool_list() }))),
        "tools/call" => Some(handle_tool_call(&id, request.get("params"), path)),
        "resources/list" => Some(handle_resources_list(&id, path)),
        "resources/read" => Some(handle_resources_read(&id, request.get("params"), path)),
        _ => Some(error_response(
            &id,
            -32601,
            &format!("method not found: {method}"),
        )),
    }
}

/// A tool dispatch failure: `Unknown` is a protocol error (bad tool name), `Failed` is a
/// tool-execution error surfaced to the agent as an `isError` result.
enum ToolError {
    Unknown(String),
    Failed(String),
}

fn handle_tool_call(id: &Value, params: Option<&Value>, path: &str) -> Value {
    let Some(params) = params else {
        return error_response(id, -32602, "missing params");
    };
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match dispatch_tool(name, &arguments, path) {
        Ok(text) => result_response(id, &tool_content(&text, false)),
        Err(ToolError::Unknown(message)) => error_response(id, -32602, &message),
        Err(ToolError::Failed(message)) => result_response(id, &tool_content(&message, true)),
    }
}

/// `resources/list`: one resource per distinct fact stream in the log.
fn handle_resources_list(id: &Value, path: &str) -> Value {
    match op_list_subjects(path) {
        Ok(subjects) => {
            let resources: Vec<Value> = subjects
                .iter()
                .map(|(kind, key, predicate)| {
                    json!({
                        "uri": resource_uri(kind, key, predicate),
                        "name": format!("{kind}:{key} {predicate}"),
                        "description": format!(
                            "The believed (or terminal) value of `{predicate}` for {kind}:{key}, with its integrity receipt."
                        ),
                        "mimeType": "text/plain",
                    })
                })
                .collect();
            result_response(id, &json!({ "resources": resources }))
        }
        // A store-load failure is an internal error, not a bad request.
        Err(error) => error_response(id, -32603, error.message()),
    }
}

/// `resources/read`: resolve a `dent8://` uri to its integrity receipt.
fn handle_resources_read(id: &Value, params: Option<&Value>, path: &str) -> Value {
    let Some(uri) = params.and_then(|p| p.get("uri")).and_then(Value::as_str) else {
        return error_response(id, -32602, "missing params.uri");
    };
    let Some((kind, key, predicate)) = parse_resource_uri(uri) else {
        return error_response(id, -32602, &format!("not a dent8 resource uri: {uri}"));
    };
    match op_explain(path, &kind, &key, &predicate) {
        Ok(text) => result_response(
            id,
            &json!({
                "contents": [{ "uri": uri, "mimeType": "text/plain", "text": text }],
            }),
        ),
        // A well-formed uri naming a fact that does not exist is "resource not found"
        // (-32002); an invalid subject/predicate is a bad request (-32602).
        Err(OpError::Rejected(message) | OpError::Conflict(message)) => {
            error_response(id, -32002, &message)
        }
        Err(OpError::Invalid(message)) => error_response(id, -32602, &message),
    }
}

/// Build the canonical resource uri for a fact stream, percent-encoding each segment so any
/// admissible `kind`/`key`/`predicate` (which may contain `/`, `%`, spaces, or non-ASCII)
/// round-trips back through [`parse_resource_uri`].
fn resource_uri(kind: &str, key: &str, predicate: &str) -> String {
    format!(
        "dent8://{}/{}/{}",
        encode_segment(kind),
        encode_segment(key),
        encode_segment(predicate)
    )
}

/// Parse a `dent8://{kind}/{key}/{predicate}` uri into its three decoded segments. Returns
/// `None` unless there are exactly three non-empty, well-formed segments.
fn parse_resource_uri(uri: &str) -> Option<(String, String, String)> {
    let rest = uri.strip_prefix("dent8://")?;
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return None;
    }
    Some((
        decode_segment(parts[0])?,
        decode_segment(parts[1])?,
        decode_segment(parts[2])?,
    ))
}

/// Percent-encode a uri segment: unreserved characters (RFC 3986) pass through; every other
/// byte (including the `/` delimiter) becomes `%XX`.
fn encode_segment(segment: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(segment.len());
    for &byte in segment.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

/// Reverse of [`encode_segment`]. Returns `None` on a malformed `%`-escape or non-UTF-8.
fn decode_segment(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = (*bytes.get(index + 1)? as char).to_digit(16)?;
            let lo = (*bytes.get(index + 2)? as char).to_digit(16)?;
            out.push(u8::try_from(hi * 16 + lo).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn dispatch_tool(name: &str, arguments: &Value, path: &str) -> Result<String, ToolError> {
    let kind = || arg(arguments, "subject_kind");
    let key = || arg(arguments, "subject_key");
    let predicate = || arg(arguments, "predicate");
    match name {
        "assert" => {
            let (kind, key, predicate, value, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg(arguments, "value")?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            with_write_retry(|| {
                op_assert(path, &kind, &key, &predicate, &value, authority, &source)
            })
            .map_err(into_failed)
        }
        "supersede" => {
            let (kind, key, predicate, value, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg(arguments, "value")?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            with_write_retry(|| {
                op_supersede(path, &kind, &key, &predicate, &value, authority, &source)
            })
            .map_err(into_failed)
        }
        "retract" => {
            let (kind, key, predicate, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            with_write_retry(|| op_retract(path, &kind, &key, &predicate, authority, &source))
                .map_err(into_failed)
        }
        "reinforce" => {
            let (kind, key, predicate, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            with_write_retry(|| op_reinforce(path, &kind, &key, &predicate, authority, &source))
                .map_err(into_failed)
        }
        "expire" => {
            let (kind, key, predicate, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            with_write_retry(|| op_expire(path, &kind, &key, &predicate, authority, &source))
                .map_err(into_failed)
        }
        "contradict" => {
            let (kind, key, predicate, value, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg(arguments, "value")?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            with_write_retry(|| {
                op_contradict(path, &kind, &key, &predicate, &value, authority, &source)
            })
            .map_err(into_failed)
        }
        "explain" => op_explain(path, &kind()?, &key()?, &predicate()?).map_err(into_failed),
        "replay" => op_replay(path, &kind()?, &key()?, &predicate()?).map_err(into_failed),
        other => Err(ToolError::Unknown(format!("unknown tool: {other}"))),
    }
}

/// A required string argument, or a tool error naming the missing field.
fn arg(arguments: &Value, name: &str) -> Result<String, ToolError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ToolError::Failed(format!("missing required string argument: {name}")))
}

/// The required `authority` argument, parsed to a level.
fn arg_authority(arguments: &Value) -> Result<dent8_core::AuthorityLevel, ToolError> {
    let raw = arg(arguments, "authority")?;
    parse_authority(&raw).ok_or_else(|| {
        ToolError::Failed(format!(
            "unknown authority '{raw}' (expected: low | medium | high | canonical)"
        ))
    })
}

// By-value so it works as `map_err(into_failed)`.
#[allow(clippy::needless_pass_by_value)]
fn into_failed(error: OpError) -> ToolError {
    ToolError::Failed(error.message().to_string())
}

/// The advertised tools and their JSON-Schema inputs.
fn tool_list() -> Vec<Value> {
    let subject = json!({
        "subject_kind": { "type": "string", "description": "entity kind, e.g. repo" },
        "subject_key": { "type": "string", "description": "entity key, e.g. myproj" },
        "predicate": { "type": "string", "description": "fact name, e.g. database" },
    });
    let write = json!({
        "authority": { "type": "string", "enum": ["low", "medium", "high", "canonical"] },
        "source": { "type": "string", "description": "the writing source id" },
    });
    let value = json!({ "value": { "type": "string", "description": "the fact's value" } });
    let valued = merge(&subject, &merge(&value, &write));
    let write_only = merge(&subject, &write);
    let read = ["subject_kind", "subject_key", "predicate"];
    let valued_req = [
        "subject_kind",
        "subject_key",
        "predicate",
        "value",
        "authority",
        "source",
    ];
    let write_req = [
        "subject_kind",
        "subject_key",
        "predicate",
        "authority",
        "source",
    ];
    vec![
        tool(
            "assert",
            "Assert a project fact through the dent8 firewall (provenance + authority + freshness). Rejected if it cannot clear the predicate's policy.",
            &valued,
            &valued_req,
        ),
        tool(
            "supersede",
            "Revise the believed fact: assert a replacement that must out-rank every believed incumbent (a lower-authority revision is rejected).",
            &valued,
            &valued_req,
        ),
        tool(
            "retract",
            "Terminally remove the believed fact(s). Authority-gated: a retraction that under-ranks its incumbent is rejected.",
            &write_only,
            &write_req,
        ),
        tool(
            "contradict",
            "Flag a conflict (dissent): contest the believed fact, keeping both. Not authority-gated, except a canonical fact hard-alarms.",
            &valued,
            &valued_req,
        ),
        tool(
            "reinforce",
            "Corroborate the believed fact (raise earned entrenchment): record an additional source/authority backing the same value.",
            &write_only,
            &write_req,
        ),
        tool(
            "expire",
            "Mark the believed fact expired (lifecycle-natural close, e.g. policy retention). Moves it to the terminal Expired state.",
            &write_only,
            &write_req,
        ),
        tool(
            "explain",
            "Explain the currently believed (or terminal) fact for a subject+predicate, with its integrity receipt.",
            &subject,
            &read,
        ),
        tool(
            "replay",
            "Replay the full event history for a subject+predicate — why the fact is what it is.",
            &subject,
            &read,
        ),
    ]
}

fn tool(name: &str, description: &str, properties: &Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": { "type": "object", "properties": properties, "required": required },
    })
}

/// Shallow-merge two JSON objects (for composing tool input-schema properties).
fn merge(a: &Value, b: &Value) -> Value {
    let mut out = a.as_object().cloned().unwrap_or_default();
    if let Some(extra) = b.as_object() {
        for (key, value) in extra {
            out.insert(key.clone(), value.clone());
        }
    }
    Value::Object(out)
}

fn tool_content(text: &str, is_error: bool) -> Value {
    json!({ "content": [{ "type": "text", "text": text }], "isError": is_error })
}

fn result_response(id: &Value, result: &Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::{dispatch, handle};
    use serde_json::{Value, json};

    fn temp_log() -> (tempdir::Guard, String) {
        let dir = tempdir::Guard::new();
        let path = format!("{}/log.jsonl", dir.path());
        (dir, path)
    }

    #[test]
    fn initialize_advertises_tools_and_resources() {
        let request = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} });
        let response = handle(&request, "/tmp/unused.jsonl").expect("response");
        assert_eq!(response["result"]["serverInfo"]["name"], "dent8");
        assert!(response["result"]["capabilities"]["tools"].is_object());
        assert!(response["result"]["capabilities"]["resources"].is_object());
    }

    #[test]
    fn a_notification_gets_no_response() {
        let note = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle(&note, "/tmp/unused.jsonl").is_none());
    }

    #[test]
    fn a_batch_returns_an_array_of_responses_omitting_notifications() {
        let batch = json!([
            { "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} },
            { "jsonrpc": "2.0", "method": "notifications/initialized" },
            { "jsonrpc": "2.0", "id": 2, "method": "tools/list" },
        ]);
        let response = dispatch(&batch, "/tmp/unused.jsonl").expect("a batch reply");
        let array = response.as_array().expect("array reply");
        // Two requests answered; the notification produced no entry.
        assert_eq!(array.len(), 2);
        let ids: Vec<&Value> = array.iter().map(|r| &r["id"]).collect();
        assert_eq!(ids, [&json!(1), &json!(2)]);
    }

    #[test]
    fn a_batch_of_only_notifications_gets_no_response() {
        let batch = json!([{ "jsonrpc": "2.0", "method": "notifications/initialized" }]);
        assert!(dispatch(&batch, "/tmp/unused.jsonl").is_none());
    }

    #[test]
    fn an_empty_batch_is_an_invalid_request() {
        let response = dispatch(&json!([]), "/tmp/unused.jsonl").expect("response");
        assert_eq!(response["error"]["code"], -32600);
    }

    #[test]
    fn resources_list_and_read_round_trip() {
        let (_guard, path) = temp_log();
        // Assert a fact so there is a resource to enumerate.
        let (err, _) = call_tool(&path, "assert", database("postgres", "high"));
        assert!(!err);

        let list = handle(
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list" }),
            &path,
        )
        .expect("response");
        let resources = list["result"]["resources"].as_array().expect("resources");
        assert_eq!(resources.len(), 1);
        let uri = resources[0]["uri"].as_str().expect("uri");
        assert_eq!(uri, "dent8://repo/p/database");

        // Reading the resource returns the integrity receipt.
        let read = handle(
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "resources/read",
                "params": { "uri": uri },
            }),
            &path,
        )
        .expect("response");
        let text = read["result"]["contents"][0]["text"]
            .as_str()
            .expect("text");
        assert!(text.contains("postgres"), "{text}");
    }

    #[test]
    fn resources_read_rejects_a_bad_uri() {
        let (_guard, path) = temp_log();
        let response = handle(
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "resources/read",
                "params": { "uri": "http://example.com/x" },
            }),
            &path,
        )
        .expect("response");
        assert_eq!(response["error"]["code"], -32602);
    }

    #[test]
    fn resources_read_of_a_missing_fact_is_resource_not_found() {
        let (_guard, path) = temp_log();
        // A well-formed dent8 uri naming a fact that does not exist -> -32002, distinct from
        // the -32602 a malformed uri gets.
        let response = handle(
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "resources/read",
                "params": { "uri": "dent8://repo/absent/database" },
            }),
            &path,
        )
        .expect("response");
        assert_eq!(response["error"]["code"], -32002);
    }

    #[test]
    fn a_resource_uri_with_special_characters_round_trips() {
        let (_guard, path) = temp_log();
        // A subject key with a '/' and a predicate with a space must survive list -> read.
        let args = json!({
            "subject_kind": "repo", "subject_key": "a/b", "predicate": "db x",
            "value": "postgres", "authority": "high", "source": "owner",
        });
        let (err, _) = call_tool(&path, "assert", args);
        assert!(!err);

        let list = handle(
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list" }),
            &path,
        )
        .expect("response");
        let uri = list["result"]["resources"][0]["uri"]
            .as_str()
            .expect("uri")
            .to_string();
        assert!(uri.contains("%2F"), "the '/' must be encoded: {uri}");

        let read = handle(
            &json!({
                "jsonrpc": "2.0", "id": 2, "method": "resources/read",
                "params": { "uri": uri },
            }),
            &path,
        )
        .expect("response");
        let text = read["result"]["contents"][0]["text"]
            .as_str()
            .expect("text");
        assert!(text.contains("postgres"), "{text}");
    }

    #[test]
    fn a_request_object_without_a_method_is_an_invalid_request() {
        // Not a notification (which requires a method): a method-less frame is -32600, not
        // a silently-dropped message.
        let response =
            handle(&json!({ "jsonrpc": "2.0", "id": 7 }), "/tmp/unused.jsonl").expect("response");
        assert_eq!(response["error"]["code"], -32600);
    }

    /// Issue a tools/call and return `(isError, first text line)`.
    #[allow(clippy::needless_pass_by_value)]
    fn call_tool(path: &str, name: &str, arguments: Value) -> (bool, String) {
        let request = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
        let result = handle(&request, path).expect("response")["result"].clone();
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        (result["isError"].as_bool().unwrap_or(true), text)
    }

    fn database(value: &str, authority: &str) -> Value {
        json!({
            "subject_kind": "repo", "subject_key": "p", "predicate": "database",
            "value": value, "authority": authority, "source": "src",
        })
    }

    #[test]
    fn the_firewall_refuses_write_tools_over_mcp() {
        // The same arbitration that protects the CLI must reject these over MCP, and must
        // surface the rejection as a tool error (isError) — not a protocol error — so the
        // agent sees the reason.

        // A low-authority supersession of a High fact (repo.database floor is High).
        let (_g, path) = temp_log();
        assert!(!call_tool(&path, "assert", database("postgres", "high")).0);
        let (err, text) = call_tool(&path, "supersede", database("mysql", "low"));
        assert!(err, "low-authority supersede must be refused: {text}");

        // A low-authority retraction of a High fact.
        let (_g, path) = temp_log();
        assert!(!call_tool(&path, "assert", database("postgres", "high")).0);
        let (err, text) = call_tool(
            &path,
            "retract",
            json!({ "subject_kind": "repo", "subject_key": "p", "predicate": "database",
                    "authority": "low", "source": "src" }),
        );
        assert!(err, "low-authority retract must be refused: {text}");

        // A contradiction against a Canonical fact hard-alarms (not a soft contest).
        let (_g, path) = temp_log();
        assert!(!call_tool(&path, "assert", database("postgres", "canonical")).0);
        let (err, text) = call_tool(&path, "contradict", database("mysql", "low"));
        assert!(err, "canonical contradiction must hard-alarm: {text}");
    }

    #[test]
    fn an_id_less_tools_call_is_dropped_and_does_not_write() {
        // JSON-RPC: a notification (no id) gets no response — and a side-effecting
        // tools/call must NOT execute when sent as one.
        let (_guard, path) = temp_log();
        let note = json!({
            "jsonrpc": "2.0", "method": "tools/call",
            "params": { "name": "assert", "arguments": {
                "subject_kind": "repo", "subject_key": "myproj", "predicate": "database",
                "value": "postgres", "authority": "high", "source": "source:owner",
            }},
        });
        assert!(
            handle(&note, &path).is_none(),
            "id-less request must get no response"
        );
        assert!(
            !std::path::Path::new(&path).exists(),
            "id-less tools/call must not write the log"
        );
    }

    #[test]
    fn a_non_object_request_is_invalid() {
        let response = handle(&json!([1, 2, 3]), "/tmp/unused.jsonl").expect("response");
        assert_eq!(response["error"]["code"], -32600);
    }

    #[test]
    fn tools_list_includes_the_full_belief_surface() {
        let request = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
        let response = handle(&request, "/tmp/unused.jsonl").expect("response");
        let names: Vec<&str> = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "assert",
                "supersede",
                "retract",
                "contradict",
                "reinforce",
                "expire",
                "explain",
                "replay"
            ]
        );
    }

    #[test]
    fn the_full_lifecycle_round_trips_through_tool_calls() {
        let (_guard, path) = temp_log();
        let call = |id: i64, name: &str, args: Value| {
            let request = json!({
                "jsonrpc": "2.0", "id": id, "method": "tools/call",
                "params": { "name": name, "arguments": args },
            });
            let response = handle(&request, &path).expect("response");
            (
                response["result"]["isError"].as_bool().unwrap(),
                response["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            )
        };
        let subject = |extra: Value| {
            let mut base = json!({
                "subject_kind": "repo", "subject_key": "myproj", "predicate": "database",
            });
            for (k, v) in extra.as_object().unwrap() {
                base[k] = v.clone();
            }
            base
        };

        let (err, text) = call(
            1,
            "assert",
            subject(json!({ "value": "postgres", "authority": "high", "source": "owner" })),
        );
        assert!(!err && text.contains("ACCEPTED"), "{text}");
        let (err, text) = call(
            2,
            "supersede",
            subject(json!({ "value": "mysql", "authority": "high", "source": "owner" })),
        );
        assert!(!err && text.contains("superseded 1"), "{text}");
        let (err, text) = call(
            3,
            "contradict",
            subject(json!({ "value": "sqlite", "authority": "low", "source": "scanner" })),
        );
        assert!(!err && text.contains("CONTESTED"), "{text}");
        let (err, text) = call(
            4,
            "retract",
            subject(json!({ "authority": "high", "source": "owner" })),
        );
        assert!(!err && text.contains("retracted"), "{text}");
        let (err, text) = call(5, "explain", subject(json!({})));
        // After retracting all believed claims, explain falls back to the terminal claim
        // and reports it as no longer believed (a successful, audited read).
        assert!(!err && text.contains("no longer believed"), "{text}");
    }

    #[test]
    fn assert_then_explain_round_trips_through_tool_calls() {
        let (_guard, path) = temp_log();
        let assert = json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "assert", "arguments": {
                "subject_kind": "repo", "subject_key": "myproj", "predicate": "database",
                "value": "postgres", "authority": "high", "source": "source:owner",
            }},
        });
        let response = handle(&assert, &path).expect("response");
        assert_eq!(response["result"]["isError"], Value::Bool(false));
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("ACCEPTED"), "{text}");

        let explain = json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "explain", "arguments": {
                "subject_kind": "repo", "subject_key": "myproj", "predicate": "database",
            }},
        });
        let response = handle(&explain, &path).expect("response");
        assert_eq!(response["result"]["isError"], Value::Bool(false));
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("postgres"), "{text}");
    }

    #[test]
    fn a_low_authority_assert_is_a_tool_error_not_a_protocol_error() {
        let (_guard, path) = temp_log();
        // repo.database requires High; a Low assert is refused — surfaced as isError, not a
        // JSON-RPC error, so the agent sees the reason.
        let assert = json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": "assert", "arguments": {
                "subject_kind": "repo", "subject_key": "myproj", "predicate": "database",
                "value": "mysql", "authority": "low", "source": "source:web",
            }},
        });
        let response = handle(&assert, &path).expect("response");
        assert!(response.get("error").is_none());
        assert_eq!(response["result"]["isError"], Value::Bool(true));
    }

    #[test]
    fn an_unknown_tool_is_a_protocol_error() {
        let request = json!({
            "jsonrpc": "2.0", "id": 6, "method": "tools/call",
            "params": { "name": "nope", "arguments": {} },
        });
        let response = handle(&request, "/tmp/unused.jsonl").expect("response");
        assert_eq!(response["error"]["code"], -32602);
    }

    #[test]
    fn an_unknown_method_is_method_not_found() {
        let request = json!({ "jsonrpc": "2.0", "id": 7, "method": "bogus/method" });
        let response = handle(&request, "/tmp/unused.jsonl").expect("response");
        assert_eq!(response["error"]["code"], -32601);
    }

    /// A tiny temp-dir helper (no external dep): a unique directory removed on drop.
    mod tempdir {
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU32, Ordering};

        static COUNTER: AtomicU32 = AtomicU32::new(0);

        pub struct Guard {
            path: PathBuf,
        }

        impl Guard {
            pub fn new() -> Self {
                let n = COUNTER.fetch_add(1, Ordering::Relaxed);
                let pid = std::process::id();
                let path = std::env::temp_dir().join(format!("dent8-mcp-test-{pid}-{n}"));
                std::fs::create_dir_all(&path).expect("create temp dir");
                Self { path }
            }

            pub fn path(&self) -> String {
                self.path.to_string_lossy().into_owned()
            }
        }

        impl Drop for Guard {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }
}
