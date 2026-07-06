//! A synchronous client for the local dent8 daemon (ADR 0018 PR 5): connect over the Unix
//! socket, complete the session-challenge handshake with the caller's own signed identity, then
//! run one write tool, or bridge stdio MCP through that authenticated connection. Used by the
//! CLI when `DENT8_DAEMON_SOCKET` routes writes to a shared daemon, and by `dent8 mcp proxy`
//! when an stdio-only MCP client should talk to that daemon.
//!
//! The transport is the same newline-delimited JSON-RPC the daemon already speaks; the client is
//! plain blocking `std::os::unix::net` (no async runtime — the CLI is synchronous). All crypto
//! stays in `identity`; this module only frames requests and maps the reply.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use serde_json::{Value, json};

use crate::ops::OpError;

/// Route one write tool call through the daemon and map its reply to the same
/// `Result<String, OpError>` a local `op_*` produces, so the CLI renders it identically. The
/// outer `Err` is a transport/handshake failure (unreachable daemon, auth failure, protocol
/// error), which the caller surfaces as an invalid-write outcome.
pub(crate) fn daemon_write(
    socket_path: &str,
    tool: &str,
    arguments: &Value,
) -> Result<Result<String, OpError>, String> {
    let mut session = Session::connect(socket_path)?;
    let call = request(
        3,
        "tools/call",
        json!({ "name": tool, "arguments": arguments }),
    );
    let reply = round_trip(&mut session.writer, &mut session.reader, &call)?;
    Ok(map_tool_reply(&reply))
}

/// Prove identity to the daemon *without* writing — the health probe behind `dent8 doctor`.
/// Returns the source the connection authenticated as; `Err` if the daemon is unreachable or
/// the handshake fails.
pub(crate) fn daemon_health(socket_path: &str) -> Result<String, String> {
    Ok(Session::connect(socket_path)?.source)
}

/// Same as [`daemon_health`], but authenticates with a generated MCP config's env instead of
/// the current process env. `dent8 doctor --agent` uses this to preflight installed
/// `dent8 mcp proxy` configs exactly as the agent will run them.
pub(crate) fn daemon_health_with_env(
    socket_path: &str,
    env: &BTreeMap<String, String>,
) -> Result<String, String> {
    let grant_path = env_map_path(env, "DENT8_GRANT")?;
    let key_path = env_map_path(env, "DENT8_IDENTITY_KEY")?;
    Ok(Session::connect_with_identity(socket_path, &grant_path, &key_path)?.source)
}

/// Bridge a stdio MCP client to an already-running local daemon. The proxy authenticates once
/// with the caller's source key, then forwards newline-delimited JSON-RPC frames between stdin /
/// stdout and the daemon connection. Notifications are forwarded without waiting for a reply, so
/// normal MCP clients can send `notifications/initialized` without deadlocking the proxy.
pub(crate) fn daemon_proxy(socket_path: &str) -> Result<(), String> {
    let mut session = Session::connect(socket_path)?;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("read stdin: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let expects_response = line_expects_response(&line);
        write_raw_line(&mut session.writer, &line)?;
        if expects_response {
            let response = read_raw_line(&mut session.reader)?;
            stdout
                .write_all(response.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|error| format!("write stdout: {error}"))?;
        }
    }
    Ok(())
}

/// An authenticated daemon connection: the socket halves plus the source it proved possession
/// of. Built by completing the session-challenge handshake with the caller's own identity.
struct Session {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
    source: String,
}

impl Session {
    fn connect(socket_path: &str) -> Result<Self, String> {
        let grant_path = env_path("DENT8_GRANT")?;
        let key_path = env_path("DENT8_IDENTITY_KEY")?;
        Self::connect_with_identity(socket_path, &grant_path, &key_path)
    }

    fn connect_with_identity(
        socket_path: &str,
        grant_path: &str,
        key_path: &str,
    ) -> Result<Self, String> {
        let stream = UnixStream::connect(socket_path)
            .map_err(|error| format!("cannot reach the dent8 daemon at {socket_path}: {error}"))?;
        let mut writer = stream
            .try_clone()
            .map_err(|error| format!("dent8 daemon socket: {error}"))?;
        let mut reader = BufReader::new(stream);

        let grant = load_grant(grant_path)?;
        let source = grant_field(&grant, &["grant", "source"])?;
        let public_key = grant_field(&grant, &["grant", "public_key"])?;
        let grant_signature = grant_field(&grant, &["signature"])?;

        // 1. hello -> single-use nonce.
        let hello = request(
            1,
            "dent8/hello",
            json!({ "source": source, "grant": grant }),
        );
        let reply = round_trip(&mut writer, &mut reader, &hello)?;
        let nonce = reply
            .get("result")
            .and_then(|result| result.get("nonce"))
            .and_then(Value::as_str)
            .ok_or_else(|| handshake_failure("dent8/hello", &reply))?;

        // 2. prove possession by signing the nonce with the source key.
        let signature = crate::identity::sign_session_challenge(
            nonce,
            &source,
            &public_key,
            &grant_signature,
            key_path,
        )?;
        let prove = request(2, "dent8/prove", json!({ "signature": signature }));
        let reply = round_trip(&mut writer, &mut reader, &prove)?;
        let authenticated = reply
            .get("result")
            .and_then(|result| result.get("authenticated"))
            .and_then(Value::as_bool)
            == Some(true);
        if !authenticated {
            return Err(handshake_failure("dent8/prove", &reply));
        }

        Ok(Self {
            writer,
            reader,
            source,
        })
    }
}

fn request(id: u32, method: &str, params: Value) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("jsonrpc".into(), "2.0".into());
    object.insert("id".into(), id.into());
    object.insert("method".into(), method.into());
    object.insert("params".into(), params);
    Value::Object(object)
}

/// Send one JSON-RPC request line and read one response line.
fn round_trip(
    writer: &mut UnixStream,
    reader: &mut BufReader<UnixStream>,
    request: &Value,
) -> Result<Value, String> {
    let mut line =
        serde_json::to_string(request).map_err(|error| format!("encode request: {error}"))?;
    line.push('\n');
    write_raw_line(writer, &line)?;
    let response = read_raw_line(reader)?;
    serde_json::from_str(&response).map_err(|error| format!("decode daemon response: {error}"))
}

fn write_raw_line(writer: &mut UnixStream, line: &str) -> Result<(), String> {
    writer
        .write_all(line.as_bytes())
        .and_then(|()| {
            if line.ends_with('\n') {
                Ok(())
            } else {
                writer.write_all(b"\n")
            }
        })
        .and_then(|()| writer.flush())
        .map_err(|error| format!("write to daemon: {error}"))
}

fn read_raw_line(reader: &mut BufReader<UnixStream>) -> Result<String, String> {
    let mut response = String::new();
    let read = reader
        .read_line(&mut response)
        .map_err(|error| format!("read from daemon: {error}"))?;
    if read == 0 {
        return Err("daemon closed the connection".to_string());
    }
    Ok(response)
}

fn line_expects_response(line: &str) -> bool {
    match serde_json::from_str::<Value>(line) {
        Ok(message) => message_expects_response(&message),
        Err(_) => true,
    }
}

fn message_expects_response(message: &Value) -> bool {
    let Some(batch) = message.as_array() else {
        return request_expects_response(message);
    };
    batch.is_empty() || batch.iter().any(request_expects_response)
}

fn request_expects_response(request: &Value) -> bool {
    let Some(object) = request.as_object() else {
        return true;
    };
    let Some(method) = object.get("method").and_then(Value::as_str) else {
        return true;
    };
    if matches!(method, "dent8/hello" | "dent8/prove") {
        return true;
    }
    object.contains_key("id")
}

/// Map a `tools/call` reply to the local write outcome. A JSON-RPC error (e.g. the read-only
/// gate before authentication) is an invalid write; otherwise `isError` + `status` distinguish a
/// firewall rejection (exit 1) from a malformed request (exit 2), and the human text is the
/// tool's own message — the same one a local `op_*` would print.
fn map_tool_reply(reply: &Value) -> Result<String, OpError> {
    if let Some(error) = reply.get("error") {
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("daemon error");
        return Err(OpError::Invalid(format!("daemon: {message}")));
    }
    let result = reply.get("result");
    let text = result
        .and_then(|result| result.get("content"))
        .and_then(|content| content.get(0))
        .and_then(|entry| entry.get("text"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let is_error = result
        .and_then(|result| result.get("isError"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !is_error {
        return Ok(text);
    }
    let status = result
        .and_then(|result| result.get("structuredContent"))
        .and_then(|structured| structured.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("rejected");
    match status {
        // `invalid` = a malformed request; `failed` = a store-load/scan failure the daemon hits
        // *before* the write commits (`run_write_tool` degrades post-commit read errors to a
        // best-effort empty receipt, so `failed` never marks a committed write). Both are the
        // couldn't-run class the local `op_*` classifies as `OpError::Invalid` (exit 2).
        "invalid" | "failed" => Err(OpError::Invalid(text)),
        _ => Err(OpError::Rejected(text)),
    }
}

fn handshake_failure(step: &str, reply: &Value) -> String {
    let detail = reply
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("unexpected response");
    format!("daemon {step} failed: {detail}")
}

fn load_grant(path: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read grant {path}: {error}"))?;
    serde_json::from_str(&text).map_err(|error| format!("invalid grant {path}: {error}"))
}

fn grant_field(grant: &Value, path: &[&str]) -> Result<String, String> {
    let mut cursor = grant;
    for key in path {
        cursor = cursor
            .get(key)
            .ok_or_else(|| format!("grant is missing {}", path.join(".")))?;
    }
    cursor
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| format!("grant {} is not a string", path.join(".")))
}

fn env_path(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} must be set to route writes through the daemon"))
}

fn env_map_path(env: &BTreeMap<String, String>, name: &str) -> Result<String, String> {
    env.get(name)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} must be set to route writes through the daemon"))
}

#[cfg(test)]
mod tests {
    use super::{map_tool_reply, message_expects_response};
    use crate::ops::OpError;
    use serde_json::json;

    #[test]
    fn an_accepted_write_maps_to_ok_with_the_tool_text() {
        let reply = json!({
            "result": { "isError": false, "content": [{ "type": "text", "text": "ACCEPTED  x" }] },
        });
        assert!(
            matches!(map_tool_reply(&reply), Ok(text) if text == "ACCEPTED  x"),
            "an accepted write must map to Ok with the tool text",
        );
    }

    #[test]
    fn a_firewall_rejection_maps_to_rejected_exit_1() {
        let reply = json!({
            "result": {
                "isError": true,
                "content": [{ "type": "text", "text": "REJECTED: insufficient authority" }],
                "structuredContent": { "status": "rejected" },
            },
        });
        assert!(
            matches!(map_tool_reply(&reply), Err(OpError::Rejected(text)) if text.contains("insufficient"))
        );
    }

    #[test]
    fn a_malformed_request_maps_to_invalid_exit_2() {
        let reply = json!({
            "result": {
                "isError": true,
                "content": [{ "type": "text", "text": "unknown authority" }],
                "structuredContent": { "status": "invalid" },
            },
        });
        assert!(matches!(map_tool_reply(&reply), Err(OpError::Invalid(_))));
    }

    #[test]
    fn a_jsonrpc_protocol_error_maps_to_invalid() {
        let reply =
            json!({ "error": { "code": -32601, "message": "tool 'assert' is not available" } });
        assert!(
            matches!(map_tool_reply(&reply), Err(OpError::Invalid(text)) if text.contains("daemon:"))
        );
    }

    #[test]
    fn a_daemon_store_failure_maps_to_invalid_exit_2() {
        // The daemon's `failed` status is a couldn't-load-the-store error before the write
        // commits — the same class the local op path returns as Invalid (exit 2), not a refusal.
        let reply = json!({
            "result": {
                "isError": true,
                "content": [{ "type": "text", "text": "corrupt event on line 3" }],
                "structuredContent": { "status": "failed" },
            },
        });
        assert!(matches!(map_tool_reply(&reply), Err(OpError::Invalid(_))));
    }

    #[test]
    fn an_error_flag_without_a_status_defaults_to_rejected() {
        // A firewall isError with no `status` is a refusal, not a usage error.
        let reply = json!({
            "result": { "isError": true, "content": [{ "type": "text", "text": "REJECTED: x" }] },
        });
        assert!(matches!(map_tool_reply(&reply), Err(OpError::Rejected(_))));
    }

    #[test]
    fn proxy_does_not_wait_for_json_rpc_notifications() {
        assert!(!message_expects_response(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        })));
        assert!(message_expects_response(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize"
        })));
        assert!(message_expects_response(&json!([
            { "jsonrpc": "2.0", "method": "notifications/initialized" },
            { "jsonrpc": "2.0", "id": 2, "method": "tools/list" }
        ])));
        assert!(!message_expects_response(&json!([
            { "jsonrpc": "2.0", "method": "notifications/initialized" }
        ])));
        assert!(message_expects_response(&json!([])));
        assert!(message_expects_response(&json!({
            "jsonrpc": "2.0",
            "method": "dent8/hello"
        })));
    }
}
