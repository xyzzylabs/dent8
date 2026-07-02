//! A minimal Model Context Protocol (MCP) server over stdio, exposing the dent8 firewall
//! to agent clients. Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP
//! stdio convention); the loop is synchronous, so no async runtime is needed.
//!
//! It speaks just enough MCP to be useful:
//! - `initialize`, `tools/list`, and `tools/call` for the full belief surface — `assert` /
//!   `supersede` / `retract` / `contradict` / `explain` / `replay` — plus read/audit tools
//!   (`list_facts`, `verify`, `conflicts`) which dispatch to the same shared `op_*`
//!   functions the CLI uses, so the firewall decision is identical on both surfaces;
//! - `resources/list` / `resources/read`, exposing each believed fact stream as a readable
//!   resource at `dent8://{kind}/{key}/{predicate}` (read returns the integrity receipt);
//! - **JSON-RPC 2.0 batches** — a top-level array of requests yields an array of responses
//!   (notifications omitted), per the spec.
//!
//! Notifications (e.g. `notifications/initialized`) are accepted silently.

use std::io::{BufRead, Write};

use dent8_core::{AuthorityLevel, ClaimEvent, ClaimEventKind, ClaimLifecycle, ClaimValue};
use dent8_store::{EventFilter, EventStore, IntegrityReceipt};
use serde_json::{Value, json};

use crate::{
    OpError, display_value, load_store, log_path, op_assert, op_conflicts, op_contradict,
    op_derive, op_expire, op_explain, op_explain_receipt, op_list_subjects, op_reinforce,
    op_replay, op_retract, op_supersede, parse_authority, short, verify_log, with_write_retry,
};

/// The latest MCP protocol revision this server prefers.
const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";
/// Older revisions this adapter still speaks without changing its response shape.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[LATEST_PROTOCOL_VERSION, "2025-06-18"];

/// Server-wide guidance consumed by MCP clients that support `instructions` (including Codex).
const SERVER_INSTRUCTIONS: &str = "\
dent8 is a memory integrity firewall for durable agent facts. Before relying on project facts, \
call list_facts or explain. Record stable facts with assert using truthful source and authority. \
Use supersede for corrections, contradict for disputes, derive for facts based on other facts. \
Treat rejected writes as safety signals; do not silently overwrite.";

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
                "protocolVersion": negotiated_protocol_version(request.get("params")),
                "capabilities": {
                    "tools": { "listChanged": false },
                    "resources": {},
                },
                "instructions": SERVER_INSTRUCTIONS,
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

fn negotiated_protocol_version(params: Option<&Value>) -> &'static str {
    let requested = params
        .and_then(|params| params.get("protocolVersion"))
        .and_then(Value::as_str);
    requested
        .and_then(|requested| {
            SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .copied()
                .find(|supported| *supported == requested)
        })
        .unwrap_or(LATEST_PROTOCOL_VERSION)
}

/// A tool dispatch failure: `Unknown` is a protocol error (bad tool name), `Failed` is a
/// tool-execution error surfaced to the agent as an `isError` result.
enum ToolError {
    Unknown(String),
    Invalid(String),
    Rejected(String),
    Failed(String),
}

impl ToolError {
    fn message(&self) -> &str {
        match self {
            Self::Unknown(message)
            | Self::Invalid(message)
            | Self::Rejected(message)
            | Self::Failed(message) => message,
        }
    }

    fn status(&self) -> &'static str {
        match self {
            Self::Unknown(_) | Self::Invalid(_) => "invalid",
            Self::Rejected(_) => "rejected",
            Self::Failed(_) => "failed",
        }
    }
}

/// A successful MCP tool result: human-facing text plus machine-facing fields for agents.
struct ToolOutput {
    text: String,
    structured: Value,
}

impl ToolOutput {
    fn new(text: impl Into<String>, structured: Value) -> Self {
        Self {
            text: text.into(),
            structured,
        }
    }
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
        Ok(output) => result_response(id, &tool_content(&output.text, false, &output.structured)),
        Err(ToolError::Unknown(message)) => error_response(id, -32602, &message),
        Err(error) => {
            let structured = error_structured(name, &arguments, &error);
            result_response(id, &tool_content(error.message(), true, &structured))
        }
    }
}

/// `resources/list`: one resource per distinct fact stream in the log.
fn handle_resources_list(id: &Value, path: &str) -> Value {
    match op_list_subjects(path, false) {
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
pub(crate) fn resource_uri(kind: &str, key: &str, predicate: &str) -> String {
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

// A flat one-arm-per-tool dispatch; grows with the tool set, not in complexity.
#[allow(clippy::too_many_lines)]
fn dispatch_tool(name: &str, arguments: &Value, path: &str) -> Result<ToolOutput, ToolError> {
    let kind = || arg(arguments, "subject_kind");
    let key = || arg(arguments, "subject_key");
    let predicate = || arg(arguments, "predicate");
    match name {
        "list_facts" => list_facts(path, arguments),
        // `verify_log` returns Err for integrity *findings* (taint, lineage, a corrupt log) as
        // well as for a genuine couldn't-run — but for an MCP agent those findings are the
        // audit's whole point, not a failed tool call. Surface the verdict text as a normal
        // result (the agent reads "INTEGRITY ISSUES" / "TAINTED" / "OK" from the content);
        // mapping it to isError would read as "verify itself broke," masking the alarm.
        "verify" => {
            let (verified, report) = match verify_log(path) {
                Ok(report) => (true, report),
                Err(report) => (false, report),
            };
            Ok(ToolOutput::new(
                report,
                json!({
                    "status": if verified { "ok" } else { "integrity_issues" },
                    "tool": "verify",
                    "integrity_verified": verified,
                }),
            ))
        }
        "conflicts" => {
            let text = op_conflicts(path).map_err(into_tool_error)?;
            Ok(ToolOutput::new(
                text.clone(),
                json!({
                    "status": if text.starts_with("no contested") { "ok" } else { "contested" },
                    "tool": "conflicts",
                    "message": text,
                }),
            ))
        }
        "assert" => {
            let (kind, key, predicate, value, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg(arguments, "value")?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            run_write_tool(
                "assert",
                "accepted",
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: Some(&value),
                    authority,
                    source: &source,
                },
                || op_assert(path, &kind, &key, &predicate, &value, authority, &source),
            )
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
            run_write_tool(
                "supersede",
                "accepted",
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: Some(&value),
                    authority,
                    source: &source,
                },
                || op_supersede(path, &kind, &key, &predicate, &value, authority, &source),
            )
        }
        "retract" => {
            let (kind, key, predicate, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            run_write_tool(
                "retract",
                "accepted",
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: None,
                    authority,
                    source: &source,
                },
                || op_retract(path, &kind, &key, &predicate, authority, &source),
            )
        }
        "reinforce" => {
            let (kind, key, predicate, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            run_write_tool(
                "reinforce",
                "accepted",
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: None,
                    authority,
                    source: &source,
                },
                || op_reinforce(path, &kind, &key, &predicate, authority, &source),
            )
        }
        "expire" => {
            let (kind, key, predicate, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            run_write_tool(
                "expire",
                "accepted",
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: None,
                    authority,
                    source: &source,
                },
                || op_expire(path, &kind, &key, &predicate, authority, &source),
            )
        }
        "derive" => {
            let (kind, key, predicate, value, authority, source) = (
                kind()?,
                key()?,
                predicate()?,
                arg(arguments, "value")?,
                arg_authority(arguments)?,
                arg(arguments, "source")?,
            );
            let (from_kind, from_key, from_predicate) = (
                arg(arguments, "from_kind")?,
                arg(arguments, "from_key")?,
                arg(arguments, "from_predicate")?,
            );
            let mut output = run_write_tool(
                "derive",
                "accepted",
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: Some(&value),
                    authority,
                    source: &source,
                },
                || {
                    op_derive(
                        path,
                        &kind,
                        &key,
                        &predicate,
                        &value,
                        authority,
                        &source,
                        &from_kind,
                        &from_key,
                        &from_predicate,
                    )
                },
            )?;
            if let Some(object) = output.structured.as_object_mut() {
                object.insert(
                    "derived_from".to_string(),
                    json!({
                        "subject": { "kind": from_kind, "key": from_key },
                        "predicate": from_predicate,
                    }),
                );
            }
            Ok(output)
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
            run_write_tool(
                "contradict",
                "contested",
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: Some(&value),
                    authority,
                    source: &source,
                },
                || op_contradict(path, &kind, &key, &predicate, &value, authority, &source),
            )
        }
        "explain" => {
            let (kind, key, predicate) = (kind()?, key()?, predicate()?);
            let text = op_explain(path, &kind, &key, &predicate).map_err(into_tool_error)?;
            let receipt =
                op_explain_receipt(path, &kind, &key, &predicate).map_err(into_tool_error)?;
            Ok(ToolOutput::new(
                text,
                explain_structured("explain", &receipt),
            ))
        }
        "replay" => {
            let (kind, key, predicate) = (kind()?, key()?, predicate()?);
            let text = op_replay(path, &kind, &key, &predicate).map_err(into_tool_error)?;
            let structured = match op_explain_receipt(path, &kind, &key, &predicate) {
                Ok(receipt) => explain_structured("replay", &receipt),
                Err(_) => json!({
                    "status": "ok",
                    "tool": "replay",
                    "subject": { "kind": kind, "key": key },
                    "predicate": predicate,
                }),
            };
            Ok(ToolOutput::new(text, structured))
        }
        other => Err(ToolError::Unknown(format!("unknown tool: {other}"))),
    }
}

fn list_facts(path: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
    let include_diagnostics = optional_bool(arguments, "include_diagnostics")?;
    let subjects = op_list_subjects(path, include_diagnostics).map_err(into_tool_error)?;
    let hidden_diagnostics_count = if include_diagnostics {
        0
    } else {
        let all_subjects = op_list_subjects(path, true).map_err(into_tool_error)?;
        all_subjects.len().saturating_sub(subjects.len())
    };
    if subjects.is_empty() {
        let hidden_note = if hidden_diagnostics_count == 0 {
            String::new()
        } else {
            format!(
                " ({hidden_diagnostics_count} diagnostic stream(s) hidden; pass include_diagnostics=true to show)"
            )
        };
        return Ok(ToolOutput::new(
            format!("no dent8 facts recorded yet{hidden_note}"),
            json!({
                "status": "ok",
                "tool": "list_facts",
                "count": 0,
                "facts": [],
                "include_diagnostics": include_diagnostics,
                "hidden_diagnostics_count": hidden_diagnostics_count,
            }),
        ));
    }
    let facts: Vec<Value> = subjects
        .iter()
        .map(|(kind, key, predicate)| {
            json!({
                "uri": resource_uri(kind, key, predicate),
                "subject": { "kind": kind, "key": key },
                "predicate": predicate,
            })
        })
        .collect();
    let lines: Vec<String> = facts
        .iter()
        .map(|fact| {
            let kind = fact["subject"]["kind"].as_str().unwrap_or("");
            let key = fact["subject"]["key"].as_str().unwrap_or("");
            let predicate = fact["predicate"].as_str().unwrap_or("");
            format!(
                "- {}  ({}:{} {})",
                fact["uri"].as_str().unwrap_or(""),
                kind,
                key,
                predicate
            )
        })
        .collect();
    let count = facts.len();
    Ok(ToolOutput::new(
        format!("{count} dent8 fact stream(s):\n{}", lines.join("\n")),
        json!({
            "status": "ok",
            "tool": "list_facts",
            "count": count,
            "facts": facts,
            "include_diagnostics": include_diagnostics,
            "hidden_diagnostics_count": hidden_diagnostics_count,
        }),
    ))
}

#[derive(Clone, Copy)]
struct WriteContext<'a> {
    subject_kind: &'a str,
    subject_key: &'a str,
    predicate: &'a str,
    attempted_value: Option<&'a str>,
    authority: AuthorityLevel,
    source: &'a str,
}

fn write_output(
    tool: &str,
    status: &str,
    path: &str,
    context: WriteContext<'_>,
    text: String,
    accepted_events: &[AcceptedEvent],
) -> ToolOutput {
    let mut structured = json!({
        "status": status,
        "tool": tool,
        "subject": { "kind": context.subject_kind, "key": context.subject_key },
        "predicate": context.predicate,
        "attempted_value": context.attempted_value,
        "authority": context.authority.name(),
        "source": context.source,
        "accepted_events": accepted_events.iter().map(AcceptedEvent::to_json).collect::<Vec<_>>(),
        "message": text,
    });
    if let Ok(receipt) = op_explain_receipt(
        path,
        context.subject_kind,
        context.subject_key,
        context.predicate,
    ) && let Some(object) = structured.as_object_mut()
    {
        object.insert("claim_id".to_string(), json!(receipt.claim_id.as_str()));
        object.insert("receipt_kind".to_string(), json!("current_state"));
        object.insert("event_hash".to_string(), json!(&receipt.event_hash));
        object.insert(
            "event_hash_kind".to_string(),
            json!("current_state_latest_event"),
        );
        object.insert(
            "event_hash_short".to_string(),
            json!(short(&receipt.event_hash)),
        );
        object.insert(
            "replay_position".to_string(),
            json!(receipt.replay_position),
        );
        object.insert(
            "current_value".to_string(),
            claim_value_structured(&receipt.value),
        );
        object.insert("current_receipt".to_string(), receipt_structured(&receipt));
        object.insert("receipt".to_string(), receipt_structured(&receipt));
    }
    ToolOutput::new(text, structured)
}

fn run_write_tool(
    tool: &str,
    status: &str,
    path: &str,
    context: WriteContext<'_>,
    mut op: impl FnMut() -> Result<String, OpError>,
) -> Result<ToolOutput, ToolError> {
    let before = all_events(path)?;
    let text = with_write_retry(&mut op).map_err(into_tool_error)?;
    let after = all_events(path)?;
    let accepted_events = accepted_events_since(&after, before.len())?;
    Ok(write_output(
        tool,
        status,
        path,
        context,
        text,
        &accepted_events,
    ))
}

fn all_events(path: &str) -> Result<Vec<ClaimEvent>, ToolError> {
    let store = load_store(path).map_err(ToolError::Failed)?;
    store
        .scan_events(&EventFilter::default())
        .map_err(|error| ToolError::Failed(error.to_string()))
}

fn accepted_events_since(
    events: &[ClaimEvent],
    start: usize,
) -> Result<Vec<AcceptedEvent>, ToolError> {
    let hashes = dent8_core::hash_chain(events)
        .map_err(|error| ToolError::Failed(format!("could not hash accepted events: {error}")))?;
    Ok(events
        .iter()
        .zip(hashes)
        .skip(start)
        .map(|(event, event_hash)| AcceptedEvent {
            event_id: event.event_id.as_str().to_string(),
            claim_id: event.claim_id.as_str().to_string(),
            kind: event_kind_name(&event.kind),
            subject_kind: event.subject.kind().to_string(),
            subject_key: event.subject.key().to_string(),
            predicate: event.predicate.as_str().to_string(),
            value: event.value.as_ref().map(claim_value_structured),
            authority: event.authority.level.name(),
            source: event.provenance.source.as_str().to_string(),
            event_hash,
        })
        .collect())
}

struct AcceptedEvent {
    event_id: String,
    claim_id: String,
    kind: &'static str,
    subject_kind: String,
    subject_key: String,
    predicate: String,
    value: Option<Value>,
    authority: &'static str,
    source: String,
    event_hash: String,
}

impl AcceptedEvent {
    fn to_json(&self) -> Value {
        json!({
            "event_id": self.event_id,
            "claim_id": self.claim_id,
            "kind": self.kind,
            "subject": {
                "kind": self.subject_kind,
                "key": self.subject_key,
            },
            "predicate": self.predicate,
            "value": self.value,
            "authority": self.authority,
            "source": self.source,
            "event_hash": self.event_hash,
            "event_hash_short": short(&self.event_hash),
        })
    }
}

fn explain_structured(tool: &str, receipt: &IntegrityReceipt) -> Value {
    json!({
        "status": receipt_status(receipt),
        "tool": tool,
        "claim_id": receipt.claim_id.as_str(),
        "subject": {
            "kind": receipt.subject.kind(),
            "key": receipt.subject.key(),
        },
        "predicate": receipt.predicate.as_str(),
        "current_value": claim_value_structured(&receipt.value),
        "event_hash": &receipt.event_hash,
        "event_hash_short": short(&receipt.event_hash),
        "replay_position": receipt.replay_position,
        "receipt_kind": "current_state",
        "current_receipt": receipt_structured(receipt),
        "receipt": receipt_structured(receipt),
    })
}

fn error_structured(tool: &str, arguments: &Value, error: &ToolError) -> Value {
    let mut structured = json!({
        "status": error.status(),
        "tool": tool,
        "rejection_reason": if matches!(error, ToolError::Rejected(_)) {
            Some(error.message())
        } else {
            None
        },
        "error_reason": error.message(),
    });
    if let Some(object) = structured.as_object_mut() {
        if let Some(subject_kind) = argument_string(arguments, "subject_kind") {
            let subject_key = argument_string(arguments, "subject_key").unwrap_or_default();
            object.insert(
                "subject".to_string(),
                json!({ "kind": subject_kind, "key": subject_key }),
            );
        }
        if let Some(predicate) = argument_string(arguments, "predicate") {
            object.insert("predicate".to_string(), json!(predicate));
        }
        if let Some(value) = argument_string(arguments, "value") {
            object.insert("attempted_value".to_string(), json!(value));
        }
        if let Some(authority) = argument_string(arguments, "authority") {
            if let Some(level) = parse_authority(&authority) {
                object.insert("authority".to_string(), json!(level.name()));
                object.insert("authority_raw".to_string(), json!(authority));
            } else {
                object.insert("authority".to_string(), json!(authority));
            }
        }
        if let Some(source) = argument_string(arguments, "source") {
            object.insert("source".to_string(), json!(source));
        }
    }
    structured
}

fn argument_string(arguments: &Value, name: &str) -> Option<String> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn receipt_status(receipt: &IntegrityReceipt) -> &'static str {
    if receipt.lifecycle == ClaimLifecycle::Contested {
        "contested"
    } else {
        "ok"
    }
}

fn receipt_structured(receipt: &IntegrityReceipt) -> Value {
    json!({
        "claim_id": receipt.claim_id.as_str(),
        "subject": {
            "kind": receipt.subject.kind(),
            "key": receipt.subject.key(),
        },
        "predicate": receipt.predicate.as_str(),
        "value": claim_value_structured(&receipt.value),
        "lifecycle": lifecycle_name(receipt.lifecycle),
        "authority": receipt.authority.name(),
        "fresh": receipt.fresh,
        "expires_at": receipt.expires_at.map(dent8_core::TimestampMillis::as_unix_millis),
        "evidence_count": receipt.evidence_count,
        "corroboration": receipt.corroboration,
        "superseded_by": receipt.superseded_by.as_ref().map(dent8_core::ClaimId::as_str),
        "contradicted_by": receipt
            .contradicted_by
            .iter()
            .map(dent8_core::ClaimId::as_str)
            .collect::<Vec<_>>(),
        "replay_position": receipt.replay_position,
        "event_hash": &receipt.event_hash,
        "event_hash_short": short(&receipt.event_hash),
        "chain_verified": receipt.chain_verified,
    })
}

fn lifecycle_name(lifecycle: ClaimLifecycle) -> &'static str {
    match lifecycle {
        ClaimLifecycle::Active => "Active",
        ClaimLifecycle::Contested => "Contested",
        ClaimLifecycle::Superseded => "Superseded",
        ClaimLifecycle::Retracted => "Retracted",
        ClaimLifecycle::Expired => "Expired",
    }
}

fn event_kind_name(kind: &ClaimEventKind) -> &'static str {
    match kind {
        ClaimEventKind::Asserted => "Asserted",
        ClaimEventKind::Superseded { .. } => "Superseded",
        ClaimEventKind::Contradicted { .. } => "Contradicted",
        ClaimEventKind::Retracted { .. } => "Retracted",
        ClaimEventKind::Expired { .. } => "Expired",
        ClaimEventKind::Reinforced { .. } => "Reinforced",
        ClaimEventKind::Retrieved { .. } => "Retrieved",
        ClaimEventKind::UsedInDecision { .. } => "UsedInDecision",
    }
}

fn claim_value_structured(value: &ClaimValue) -> Value {
    match value {
        ClaimValue::Text(text) => json!({
            "kind": "text",
            "text": text,
            "display": display_value(value),
        }),
        ClaimValue::Json(canonical) => json!({
            "kind": "json",
            "canonical": canonical.as_str(),
            "json": serde_json::from_str::<Value>(canonical.as_str()).ok(),
            "display": display_value(value),
        }),
        ClaimValue::Redacted => json!({
            "kind": "redacted",
            "display": display_value(value),
        }),
    }
}

/// A required string argument, or a tool error naming the missing field.
fn arg(arguments: &Value, name: &str) -> Result<String, ToolError> {
    arguments
        .get(name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| ToolError::Invalid(format!("missing required string argument: {name}")))
}

fn optional_bool(arguments: &Value, name: &str) -> Result<bool, ToolError> {
    match arguments.get(name) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(ToolError::Invalid(format!(
            "optional argument {name} must be a boolean"
        ))),
        None => Ok(false),
    }
}

/// The required `authority` argument, parsed to a level.
fn arg_authority(arguments: &Value) -> Result<dent8_core::AuthorityLevel, ToolError> {
    let raw = arg(arguments, "authority")?;
    parse_authority(&raw).ok_or_else(|| {
        ToolError::Invalid(format!(
            "unknown authority '{raw}' (expected: low | medium | high | canonical)"
        ))
    })
}

// By-value so it works as `map_err(into_tool_error)`.
#[allow(clippy::needless_pass_by_value)]
fn into_tool_error(error: OpError) -> ToolError {
    match error {
        OpError::Invalid(message) => ToolError::Invalid(message),
        OpError::Rejected(message) | OpError::Conflict(message) => ToolError::Rejected(message),
    }
}

/// The advertised tools and their JSON-Schema inputs.
// A flat tool registry; grows with the tool set, not in complexity.
#[allow(clippy::too_many_lines)]
fn tool_list() -> Vec<Value> {
    let empty = json!({});
    let list_facts = json!({
        "include_diagnostics": {
            "type": "boolean",
            "description": "include internal diagnostic fact streams such as doctor write-check probes"
        },
    });
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
    let from = json!({
        "from_kind": { "type": "string", "description": "source fact's entity kind" },
        "from_key": { "type": "string", "description": "source fact's entity key" },
        "from_predicate": { "type": "string", "description": "source fact's predicate" },
    });
    let derive_props = merge(&valued, &from);
    let read = ["subject_kind", "subject_key", "predicate"];
    let valued_req = [
        "subject_kind",
        "subject_key",
        "predicate",
        "value",
        "authority",
        "source",
    ];
    let derive_req = [
        "subject_kind",
        "subject_key",
        "predicate",
        "value",
        "authority",
        "source",
        "from_kind",
        "from_key",
        "from_predicate",
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
            "list_facts",
            "List known dent8 fact streams and their dent8:// resource URIs. Use before relying on project memory.",
            &list_facts,
            &[],
        ),
        tool(
            "verify",
            "Run dent8 integrity checks: structural/hash-chain verification where available, lineage checks, and taint detection.",
            &empty,
            &[],
        ),
        tool(
            "conflicts",
            "List contested facts that are currently in dispute and need resolution.",
            &empty,
            &[],
        ),
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
            "Terminally expire the believed fact (authority-gated policy close). TTL staleness remains read-time and non-mutating.",
            &write_only,
            &write_req,
        ),
        tool(
            "derive",
            "Assert a fact derived from another fact (named by its subject), recording a dependency edge. If that source is later retracted or expired, this derivative is flagged as tainted.",
            &derive_props,
            &derive_req,
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
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        },
        "outputSchema": output_schema_for(name),
    })
}

fn output_schema_for(name: &str) -> Value {
    match name {
        "list_facts" => with_tool_error_schema(name, list_facts_output_schema()),
        "verify" => with_tool_error_schema(name, verify_output_schema()),
        "conflicts" => with_tool_error_schema(name, conflicts_output_schema()),
        "assert" | "supersede" | "retract" | "reinforce" | "expire" => {
            with_tool_error_schema(name, write_output_schema(name, &["accepted"]))
        }
        "derive" => with_tool_error_schema(name, write_output_schema(name, &["accepted"])),
        "contradict" => with_tool_error_schema(name, write_output_schema(name, &["contested"])),
        "explain" | "replay" => with_tool_error_schema(name, read_output_schema(name)),
        _ => with_tool_error_schema(name, generic_output_schema(name)),
    }
}

fn with_tool_error_schema(tool: &str, success: Value) -> Value {
    let mut schema = serde_json::Map::new();
    schema.insert(
        "$schema".to_string(),
        json!("https://json-schema.org/draft/2020-12/schema"),
    );
    schema.insert(
        "oneOf".to_string(),
        Value::Array(vec![success, tool_error_output_schema(tool)]),
    );
    Value::Object(schema)
}

fn list_facts_output_schema() -> Value {
    object_schema(
        json!({
            "status": { "const": "ok" },
            "tool": { "const": "list_facts" },
            "count": { "type": "integer", "minimum": 0 },
            "include_diagnostics": { "type": "boolean" },
            "hidden_diagnostics_count": { "type": "integer", "minimum": 0 },
            "facts": {
                "type": "array",
                "items": object_schema(
                    json!({
                        "uri": { "type": "string" },
                        "subject": subject_output_schema(),
                        "predicate": { "type": "string" },
                    }),
                    &["uri", "subject", "predicate"],
                ),
            },
        }),
        &[
            "status",
            "tool",
            "count",
            "include_diagnostics",
            "hidden_diagnostics_count",
            "facts",
        ],
    )
}

fn verify_output_schema() -> Value {
    object_schema(
        json!({
            "status": { "enum": ["ok", "integrity_issues"] },
            "tool": { "const": "verify" },
            "integrity_verified": { "type": "boolean" },
        }),
        &["status", "tool", "integrity_verified"],
    )
}

fn conflicts_output_schema() -> Value {
    object_schema(
        json!({
            "status": { "enum": ["ok", "contested"] },
            "tool": { "const": "conflicts" },
            "message": { "type": "string" },
        }),
        &["status", "tool", "message"],
    )
}

fn write_output_schema(tool: &str, statuses: &[&str]) -> Value {
    object_schema(
        json!({
            "status": { "enum": statuses },
            "tool": { "const": tool },
            "subject": subject_output_schema(),
            "predicate": { "type": "string" },
            "attempted_value": nullable_string_schema(),
            "authority": authority_schema(),
            "source": { "type": "string" },
            "accepted_events": {
                "type": "array",
                "items": accepted_event_output_schema(),
            },
            "message": { "type": "string" },
            "claim_id": { "type": "string" },
            "receipt_kind": { "const": "current_state" },
            "event_hash": digest_schema(),
            "event_hash_kind": { "const": "current_state_latest_event" },
            "event_hash_short": { "type": "string" },
            "replay_position": { "type": "integer", "minimum": 0 },
            "current_value": claim_value_output_schema(),
            "current_receipt": receipt_output_schema(),
            "receipt": receipt_output_schema(),
            "derived_from": derived_from_output_schema(),
        }),
        &[
            "status",
            "tool",
            "subject",
            "predicate",
            "attempted_value",
            "authority",
            "source",
            "accepted_events",
            "message",
        ],
    )
}

fn read_output_schema(tool: &str) -> Value {
    object_schema(
        json!({
            "status": { "enum": ["ok", "contested"] },
            "tool": { "const": tool },
            "subject": subject_output_schema(),
            "predicate": { "type": "string" },
            "claim_id": { "type": "string" },
            "current_value": claim_value_output_schema(),
            "event_hash": digest_schema(),
            "event_hash_short": { "type": "string" },
            "replay_position": { "type": "integer", "minimum": 0 },
            "receipt_kind": { "const": "current_state" },
            "current_receipt": receipt_output_schema(),
            "receipt": receipt_output_schema(),
        }),
        &["status", "tool", "subject", "predicate"],
    )
}

fn generic_output_schema(tool: &str) -> Value {
    object_schema(
        json!({
            "status": { "type": "string" },
            "tool": { "const": tool },
        }),
        &["status", "tool"],
    )
}

fn tool_error_output_schema(tool: &str) -> Value {
    object_schema(
        json!({
            "status": { "enum": ["invalid", "rejected", "failed"] },
            "tool": { "const": tool },
            "rejection_reason": nullable_string_schema(),
            "error_reason": { "type": "string" },
            "subject": subject_output_schema(),
            "predicate": { "type": "string" },
            "attempted_value": { "type": "string" },
            "authority": {
                "anyOf": [
                    authority_schema(),
                    { "type": "string" }
                ]
            },
            "authority_raw": { "type": "string" },
            "source": { "type": "string" },
        }),
        &["status", "tool", "rejection_reason", "error_reason"],
    )
}

fn accepted_event_output_schema() -> Value {
    object_schema(
        json!({
            "event_id": { "type": "string" },
            "claim_id": { "type": "string" },
            "kind": {
                "enum": [
                    "Asserted",
                    "Superseded",
                    "Contradicted",
                    "Retracted",
                    "Expired",
                    "Reinforced",
                    "Retrieved",
                    "UsedInDecision"
                ]
            },
            "subject": subject_output_schema(),
            "predicate": { "type": "string" },
            "value": {
                "anyOf": [
                    claim_value_output_schema(),
                    { "type": "null" }
                ]
            },
            "authority": authority_schema(),
            "source": { "type": "string" },
            "event_hash": digest_schema(),
            "event_hash_short": { "type": "string" },
        }),
        &[
            "event_id",
            "claim_id",
            "kind",
            "subject",
            "predicate",
            "value",
            "authority",
            "source",
            "event_hash",
            "event_hash_short",
        ],
    )
}

fn receipt_output_schema() -> Value {
    object_schema(
        json!({
            "claim_id": { "type": "string" },
            "subject": subject_output_schema(),
            "predicate": { "type": "string" },
            "value": claim_value_output_schema(),
            "lifecycle": {
                "enum": ["Active", "Contested", "Superseded", "Retracted", "Expired"]
            },
            "authority": authority_schema(),
            "fresh": { "type": "boolean" },
            "expires_at": {
                "anyOf": [
                    { "type": "integer" },
                    { "type": "null" }
                ]
            },
            "evidence_count": { "type": "integer", "minimum": 0 },
            "corroboration": { "type": "integer", "minimum": 0 },
            "superseded_by": nullable_string_schema(),
            "contradicted_by": {
                "type": "array",
                "items": { "type": "string" },
            },
            "replay_position": { "type": "integer", "minimum": 0 },
            "event_hash": digest_schema(),
            "event_hash_short": { "type": "string" },
            "chain_verified": { "type": "boolean" },
        }),
        &[
            "claim_id",
            "subject",
            "predicate",
            "value",
            "lifecycle",
            "authority",
            "fresh",
            "expires_at",
            "evidence_count",
            "corroboration",
            "superseded_by",
            "contradicted_by",
            "replay_position",
            "event_hash",
            "event_hash_short",
            "chain_verified",
        ],
    )
}

fn claim_value_output_schema() -> Value {
    json!({
        "oneOf": [
            object_schema(
                json!({
                    "kind": { "const": "text" },
                    "text": { "type": "string" },
                    "display": { "type": "string" },
                }),
                &["kind", "text", "display"],
            ),
            object_schema(
                json!({
                    "kind": { "const": "json" },
                    "canonical": { "type": "string" },
                    "json": true,
                    "display": { "type": "string" },
                }),
                &["kind", "canonical", "json", "display"],
            ),
            object_schema(
                json!({
                    "kind": { "const": "redacted" },
                    "display": { "type": "string" },
                }),
                &["kind", "display"],
            ),
        ]
    })
}

fn derived_from_output_schema() -> Value {
    object_schema(
        json!({
            "subject": subject_output_schema(),
            "predicate": { "type": "string" },
        }),
        &["subject", "predicate"],
    )
}

fn subject_output_schema() -> Value {
    object_schema(
        json!({
            "kind": { "type": "string" },
            "key": { "type": "string" },
        }),
        &["kind", "key"],
    )
}

fn authority_schema() -> Value {
    json!({ "enum": ["Unknown", "Low", "Medium", "High", "Canonical"] })
}

fn digest_schema() -> Value {
    json!({
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    })
}

fn nullable_string_schema() -> Value {
    json!({
        "anyOf": [
            { "type": "string" },
            { "type": "null" }
        ]
    })
}

fn object_schema(properties: Value, required: &[&str]) -> Value {
    let mut schema = serde_json::Map::new();
    schema.insert("type".to_string(), json!("object"));
    schema.insert("properties".to_string(), properties);
    schema.insert("required".to_string(), json!(required));
    schema.insert("additionalProperties".to_string(), json!(false));
    Value::Object(schema)
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

fn tool_content(text: &str, is_error: bool, structured: &Value) -> Value {
    let structured_text = serde_json::to_string(structured).unwrap_or_else(|_| "{}".to_string());
    json!({
        "content": [
            { "type": "text", "text": text },
            { "type": "text", "text": structured_text },
        ],
        "structuredContent": structured,
        "isError": is_error,
    })
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
        assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(response["result"]["serverInfo"]["name"], "dent8");
        assert!(response["result"]["capabilities"]["tools"].is_object());
        assert_eq!(
            response["result"]["capabilities"]["tools"]["listChanged"],
            false
        );
        assert!(response["result"]["capabilities"]["resources"].is_object());
        let instructions = response["result"]["instructions"]
            .as_str()
            .expect("server instructions");
        assert!(instructions.contains("memory integrity firewall"));
        assert!(instructions.contains("list_facts"));
    }

    #[test]
    fn initialize_negotiates_a_supported_older_protocol_version() {
        let request = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2025-06-18" },
        });
        let response = handle(&request, "/tmp/unused.jsonl").expect("response");
        assert_eq!(response["result"]["protocolVersion"], "2025-06-18");
    }

    #[test]
    fn initialize_falls_forward_when_the_requested_protocol_is_unsupported() {
        let request = json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": { "protocolVersion": "2024-11-05" },
        });
        let response = handle(&request, "/tmp/unused.jsonl").expect("response");
        assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
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
    fn diagnostic_fact_streams_are_hidden_from_browse_surfaces_by_default() {
        let (_guard, path) = temp_log();
        let (err, text) = call_tool(&path, "assert", diagnostic("ok", "high"));
        assert!(!err, "{text}");
        let (err, text) = call_tool(&path, "assert", hidden_doctor_probe("tea", "high"));
        assert!(!err, "{text}");

        let facts = call_tool_result(&path, "list_facts", json!({}));
        assert_eq!(facts["structuredContent"]["count"], 0);
        assert_eq!(facts["structuredContent"]["hidden_diagnostics_count"], 2);
        let text = facts["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("diagnostic stream(s) hidden"), "{text}");
        assert!(!text.contains("dent8://diagnostic/doctor/dent8.write_check"));
        assert!(!text.contains("dent8://person/alice-doctor-hidden/favorite_drink"));

        let facts = call_tool_result(&path, "list_facts", json!({ "include_diagnostics": true }));
        assert_eq!(facts["structuredContent"]["count"], 2);
        assert_eq!(facts["structuredContent"]["include_diagnostics"], true);
        assert_eq!(
            facts["structuredContent"]["facts"][0]["uri"],
            "dent8://diagnostic/doctor/dent8.write_check"
        );
        assert_eq!(
            facts["structuredContent"]["facts"][1]["uri"],
            "dent8://person/alice-doctor-hidden/favorite_drink"
        );

        let resources = handle(
            &json!({ "jsonrpc": "2.0", "id": 1, "method": "resources/list" }),
            &path,
        )
        .expect("response");
        assert_eq!(
            resources["result"]["resources"]
                .as_array()
                .expect("resources")
                .len(),
            0
        );
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
        let (is_error, text) = call_tool_text(path, name, arguments);
        (is_error, text.lines().next().unwrap_or("").to_string())
    }

    #[allow(clippy::needless_pass_by_value)]
    fn call_tool_text(path: &str, name: &str, arguments: Value) -> (bool, String) {
        let result = call_tool_result(path, name, arguments);
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        (result["isError"].as_bool().unwrap_or(true), text)
    }

    #[allow(clippy::needless_pass_by_value)]
    fn call_tool_result(path: &str, name: &str, arguments: Value) -> Value {
        let request = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
        handle(&request, path).expect("response")["result"].clone()
    }

    fn advertised_output_schema(name: &str) -> Value {
        let request = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
        let response = handle(&request, "/tmp/unused.jsonl").expect("response");
        response["result"]["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap_or_else(|| panic!("missing tool: {name}"))["outputSchema"]
            .clone()
    }

    #[allow(clippy::needless_pass_by_value)]
    fn assert_tool_output_matches_schema(path: &str, name: &str, arguments: Value) -> Value {
        let result = call_tool_result(path, name, arguments);
        let structured = &result["structuredContent"];
        assert_matches_advertised_output_schema(name, structured);
        result
    }

    fn assert_matches_advertised_output_schema(name: &str, structured: &Value) {
        let schema = advertised_output_schema(name);
        if let Err(error) = validate_json_schema_subset(&schema, structured, "$") {
            panic!(
                "{name} structuredContent does not match advertised outputSchema: {error}\n\
                 structuredContent: {structured:#}\noutputSchema: {schema:#}"
            );
        }
    }

    #[allow(clippy::too_many_lines)]
    fn validate_json_schema_subset(
        schema: &Value,
        value: &Value,
        path: &str,
    ) -> Result<(), String> {
        if let Some(allowed) = schema.as_bool() {
            return if allowed {
                Ok(())
            } else {
                Err(format!("{path}: boolean schema false rejected the value"))
            };
        }
        let object = schema
            .as_object()
            .ok_or_else(|| format!("{path}: schema must be an object or boolean"))?;

        if let Some(one_of) = object.get("oneOf") {
            let schemas = one_of
                .as_array()
                .ok_or_else(|| format!("{path}: oneOf must be an array"))?;
            let mut matches = 0_u8;
            let mut first_error = None;
            for branch in schemas {
                match validate_json_schema_subset(branch, value, path) {
                    Ok(()) => matches = matches.saturating_add(1),
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            return match matches {
                1 => Ok(()),
                0 => Err(format!(
                    "{path}: matched no oneOf branch; first error: {}",
                    first_error.unwrap_or_else(|| "none".to_string())
                )),
                count => Err(format!("{path}: matched {count} oneOf branches")),
            };
        }

        if let Some(any_of) = object.get("anyOf") {
            let schemas = any_of
                .as_array()
                .ok_or_else(|| format!("{path}: anyOf must be an array"))?;
            let mut first_error = None;
            for branch in schemas {
                match validate_json_schema_subset(branch, value, path) {
                    Ok(()) => return Ok(()),
                    Err(error) => {
                        first_error.get_or_insert(error);
                    }
                }
            }
            return Err(format!(
                "{path}: matched no anyOf branch; first error: {}",
                first_error.unwrap_or_else(|| "none".to_string())
            ));
        }

        if let Some(expected) = object.get("const")
            && value != expected
        {
            return Err(format!("{path}: expected const {expected}, got {value}"));
        }

        if let Some(allowed) = object.get("enum") {
            let options = allowed
                .as_array()
                .ok_or_else(|| format!("{path}: enum must be an array"))?;
            if !options.iter().any(|option| option == value) {
                return Err(format!("{path}: {value} is not one of {allowed}"));
            }
        }

        if let Some(type_name) = object.get("type").and_then(Value::as_str) {
            validate_json_type(type_name, value, path)?;
        }

        if object.contains_key("properties")
            || object.contains_key("required")
            || matches!(object.get("additionalProperties"), Some(Value::Bool(false)))
        {
            validate_object_keywords(object, value, path)?;
        }

        if let Some(items_schema) = object.get("items") {
            let array = value
                .as_array()
                .ok_or_else(|| format!("{path}: expected array for items validation"))?;
            for (index, item) in array.iter().enumerate() {
                validate_json_schema_subset(items_schema, item, &format!("{path}[{index}]"))?;
            }
        }

        if let Some(minimum) = object.get("minimum") {
            validate_minimum(minimum, value, path)?;
        }

        if let Some(pattern) = object.get("pattern").and_then(Value::as_str) {
            validate_pattern(pattern, value, path)?;
        }

        Ok(())
    }

    fn validate_json_type(type_name: &str, value: &Value, path: &str) -> Result<(), String> {
        let matches = match type_name {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => is_json_integer(value),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            other => return Err(format!("{path}: unsupported schema type {other:?}")),
        };
        if matches {
            Ok(())
        } else {
            Err(format!("{path}: expected {type_name}, got {value}"))
        }
    }

    fn is_json_integer(value: &Value) -> bool {
        match value {
            Value::Number(number) => number.as_i64().is_some() || number.as_u64().is_some(),
            _ => false,
        }
    }

    fn validate_object_keywords(
        schema: &serde_json::Map<String, Value>,
        value: &Value,
        path: &str,
    ) -> Result<(), String> {
        let object = value
            .as_object()
            .ok_or_else(|| format!("{path}: expected object for object-keyword validation"))?;
        let properties = schema.get("properties").and_then(Value::as_object);

        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for field in required {
                let field = field
                    .as_str()
                    .ok_or_else(|| format!("{path}: required entries must be strings"))?;
                if !object.contains_key(field) {
                    return Err(format!("{path}: missing required property {field:?}"));
                }
            }
        }

        if let Some(properties) = properties {
            for (field, field_schema) in properties {
                if let Some(field_value) = object.get(field) {
                    validate_json_schema_subset(
                        field_schema,
                        field_value,
                        &format!("{path}.{field}"),
                    )?;
                }
            }
        }

        if matches!(schema.get("additionalProperties"), Some(Value::Bool(false))) {
            for field in object.keys() {
                if properties.is_none_or(|known| !known.contains_key(field)) {
                    return Err(format!("{path}: unexpected property {field:?}"));
                }
            }
        }

        Ok(())
    }

    fn validate_minimum(minimum: &Value, value: &Value, path: &str) -> Result<(), String> {
        let Some(minimum) = minimum.as_i64() else {
            return Err(format!("{path}: unsupported non-integer minimum {minimum}"));
        };
        if minimum != 0 {
            return Err(format!(
                "{path}: unsupported minimum {minimum}; tests only need 0"
            ));
        }
        match value {
            Value::Number(number)
                if number.as_u64().is_some()
                    || number.as_i64().is_some_and(|number| number >= 0) =>
            {
                Ok(())
            }
            _ => Err(format!("{path}: expected number >= {minimum}, got {value}")),
        }
    }

    fn validate_pattern(pattern: &str, value: &Value, path: &str) -> Result<(), String> {
        let text = value
            .as_str()
            .ok_or_else(|| format!("{path}: expected string for pattern validation"))?;
        match pattern {
            "^[0-9a-f]{64}$"
                if text.len() == 64
                    && text
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()) =>
            {
                Ok(())
            }
            "^[0-9a-f]{64}$" => Err(format!("{path}: value does not match {pattern}: {text:?}")),
            other => Err(format!("{path}: unsupported pattern {other:?}")),
        }
    }

    fn database(value: &str, authority: &str) -> Value {
        json!({
            "subject_kind": "repo", "subject_key": "p", "predicate": "database",
            "value": value, "authority": authority, "source": "src",
        })
    }

    fn diagnostic(value: &str, authority: &str) -> Value {
        json!({
            "subject_kind": "diagnostic",
            "subject_key": "doctor",
            "predicate": "dent8.write_check",
            "value": value,
            "authority": authority,
            "source": "src",
        })
    }

    fn hidden_doctor_probe(value: &str, authority: &str) -> Value {
        json!({
            "subject_kind": "person",
            "subject_key": "alice-doctor-hidden",
            "predicate": "favorite_drink",
            "value": value,
            "authority": authority,
            "source": "src",
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

        // A low-authority explicit expiration of a High fact.
        let (_g, path) = temp_log();
        assert!(!call_tool(&path, "assert", database("postgres", "high")).0);
        let (err, text) = call_tool(
            &path,
            "expire",
            json!({ "subject_kind": "repo", "subject_key": "p", "predicate": "database",
                    "authority": "low", "source": "src" }),
        );
        assert!(err, "low-authority expire must be refused: {text}");

        // A contradiction against a Canonical fact hard-alarms (not a soft contest).
        let (_g, path) = temp_log();
        assert!(!call_tool(&path, "assert", database("postgres", "canonical")).0);
        let (err, text) = call_tool(&path, "contradict", database("mysql", "low"));
        assert!(err, "canonical contradiction must hard-alarm: {text}");
    }

    #[test]
    fn malformed_tool_input_is_invalid_not_rejected() {
        let (_guard, path) = temp_log();
        let result = call_tool_result(
            &path,
            "assert",
            json!({
                "subject_kind": "repo", "subject_key": "p", "predicate": "database",
                "value": "postgres", "authority": "high",
            }),
        );
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["status"], "invalid");
        assert_eq!(result["structuredContent"]["tool"], "assert");
        assert!(result["structuredContent"]["rejection_reason"].is_null());
        assert!(
            result["structuredContent"]["error_reason"]
                .as_str()
                .unwrap()
                .contains("source")
        );
    }

    #[test]
    fn firewall_refusal_is_structured_as_rejected() {
        let (_guard, path) = temp_log();
        let result = call_tool_result(&path, "assert", database("postgres", "low"));
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["status"], "rejected");
        assert_eq!(result["structuredContent"]["authority"], "Low");
        assert!(
            result["structuredContent"]["rejection_reason"]
                .as_str()
                .unwrap()
                .contains("requires authority")
        );
    }

    #[test]
    fn multi_event_write_exposes_every_accepted_event() {
        let (_guard, path) = temp_log();
        assert!(!call_tool(&path, "assert", database("postgres", "high")).0);
        let result = call_tool_result(&path, "supersede", database("mysql", "high"));
        assert_eq!(result["isError"], false);
        let structured = &result["structuredContent"];
        assert_eq!(structured["status"], "accepted");
        assert_eq!(structured["receipt_kind"], "current_state");
        assert_eq!(structured["event_hash_kind"], "current_state_latest_event");
        let events = structured["accepted_events"].as_array().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["kind"], "Asserted");
        assert_eq!(events[1]["kind"], "Superseded");
        assert_eq!(events[0]["event_hash"].as_str().unwrap().len(), 64);
        assert_eq!(events[1]["event_hash"].as_str().unwrap().len(), 64);
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
        let tools = response["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
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
                "replay"
            ]
        );
        let list_facts = tools
            .iter()
            .find(|tool| tool["name"] == "list_facts")
            .unwrap();
        assert_eq!(list_facts["inputSchema"]["type"], "object");
        assert_eq!(list_facts["inputSchema"]["additionalProperties"], false);
        for tool in tools {
            assert!(
                tool["outputSchema"]["oneOf"].is_array(),
                "{} should advertise an output schema",
                tool["name"]
            );
        }
        let assert_tool = tools.iter().find(|tool| tool["name"] == "assert").unwrap();
        assert_eq!(
            assert_tool["outputSchema"]["oneOf"][0]["properties"]["accepted_events"]["type"],
            "array"
        );
        assert_eq!(
            assert_tool["outputSchema"]["oneOf"][1]["properties"]["status"]["enum"],
            json!(["invalid", "rejected", "failed"])
        );
        let verify_tool = tools.iter().find(|tool| tool["name"] == "verify").unwrap();
        assert_eq!(
            verify_tool["outputSchema"]["oneOf"][0]["properties"]["status"]["enum"],
            json!(["ok", "integrity_issues"])
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn structured_content_matches_advertised_output_schemas() {
        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(&path, "list_facts", json!({}));
        assert_tool_output_matches_schema(&path, "verify", json!({}));
        assert_tool_output_matches_schema(&path, "conflicts", json!({}));

        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(&path, "assert", database("postgres", "high"));
        let read_args = json!({
            "subject_kind": "repo",
            "subject_key": "p",
            "predicate": "database",
        });
        assert_tool_output_matches_schema(&path, "explain", read_args.clone());
        assert_tool_output_matches_schema(&path, "replay", read_args);
        assert_tool_output_matches_schema(&path, "supersede", database("mysql", "high"));

        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(&path, "assert", database("postgres", "high"));
        assert_tool_output_matches_schema(
            &path,
            "reinforce",
            json!({
                "subject_kind": "repo",
                "subject_key": "p",
                "predicate": "database",
                "authority": "high",
                "source": "src",
            }),
        );

        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(&path, "assert", database("postgres", "high"));
        assert_tool_output_matches_schema(
            &path,
            "retract",
            json!({
                "subject_kind": "repo",
                "subject_key": "p",
                "predicate": "database",
                "authority": "high",
                "source": "src",
            }),
        );

        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(&path, "assert", database("postgres", "high"));
        assert_tool_output_matches_schema(
            &path,
            "expire",
            json!({
                "subject_kind": "repo",
                "subject_key": "p",
                "predicate": "database",
                "authority": "high",
                "source": "src",
            }),
        );

        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(&path, "assert", database("postgres", "high"));
        assert_tool_output_matches_schema(
            &path,
            "derive",
            json!({
                "subject_kind": "service",
                "subject_key": "api",
                "predicate": "datastore",
                "value": "postgres",
                "authority": "high",
                "source": "src",
                "from_kind": "repo",
                "from_key": "p",
                "from_predicate": "database",
            }),
        );
        assert_tool_output_matches_schema(
            &path,
            "retract",
            json!({
                "subject_kind": "repo",
                "subject_key": "p",
                "predicate": "database",
                "authority": "high",
                "source": "src",
            }),
        );
        assert_tool_output_matches_schema(&path, "verify", json!({}));

        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(&path, "assert", database("postgres", "high"));
        assert_tool_output_matches_schema(&path, "contradict", database("mysql", "high"));
        assert_tool_output_matches_schema(&path, "conflicts", json!({}));

        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(
            &path,
            "assert",
            json!({
                "subject_kind": "repo",
                "subject_key": "p",
                "predicate": "database",
                "value": "postgres",
                "authority": "high",
            }),
        );
        assert_tool_output_matches_schema(&path, "assert", database("postgres", "low"));
    }

    #[test]
    fn structured_content_is_mirrored_as_json_text_for_compatibility() {
        let (_guard, path) = temp_log();
        let result = call_tool_result(&path, "assert", database("postgres", "high"));
        let mirrored: Value =
            serde_json::from_str(result["content"][1]["text"].as_str().unwrap()).unwrap();
        assert_eq!(mirrored, result["structuredContent"]);
    }

    #[test]
    fn read_audit_tools_are_useful_to_agents() {
        let (_guard, path) = temp_log();
        let (err, text) = call_tool_text(&path, "list_facts", json!({}));
        assert!(!err, "{text}");
        assert!(text.contains("no dent8 facts"), "{text}");

        let (err, text) = call_tool(&path, "assert", database("postgres", "high"));
        assert!(!err, "{text}");

        let (err, text) = call_tool_text(&path, "list_facts", json!({}));
        assert!(!err, "{text}");
        assert!(text.contains("dent8://repo/p/database"), "{text}");

        let (err, text) = call_tool(&path, "verify", json!({}));
        assert!(!err, "{text}");
        assert!(text.contains("STRUCTURAL integrity holds"), "{text}");

        let (err, text) = call_tool(&path, "conflicts", json!({}));
        assert!(!err, "{text}");
        assert!(text.contains("no contested facts"), "{text}");
    }

    #[test]
    fn verify_surfaces_a_finding_as_content_not_a_tool_error() {
        let (_guard, path) = temp_log();
        // A fact, a derivative of it, then retract the source → the derivative is tainted.
        assert!(!call_tool(&path, "assert", database("postgres", "high")).0);
        let (err, text) = call_tool(
            &path,
            "derive",
            json!({
                "subject_kind": "service", "subject_key": "api", "predicate": "datastore",
                "value": "pg", "authority": "high", "source": "src",
                "from_kind": "repo", "from_key": "p", "from_predicate": "database",
            }),
        );
        assert!(!err, "derive should be admitted: {text}");
        let (err, text) = call_tool(
            &path,
            "retract",
            json!({ "subject_kind": "repo", "subject_key": "p", "predicate": "database",
                    "authority": "high", "source": "src" }),
        );
        assert!(!err, "retract should be admitted: {text}");
        // `verify` found a taint, but the TOOL did not fail: isError must be false (the agent
        // reads the finding from the content), not true (which would read as "verify broke").
        let (err, text) = call_tool_text(&path, "verify", json!({}));
        assert!(
            !err,
            "verify must surface an integrity finding as content, not a tool error: {text}"
        );
        assert!(
            text.contains("TAINTED"),
            "verify should report the taint: {text}"
        );
        let result = call_tool_result(&path, "verify", json!({}));
        assert_eq!(result["structuredContent"]["status"], "integrity_issues");
        assert_eq!(result["structuredContent"]["integrity_verified"], false);
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
