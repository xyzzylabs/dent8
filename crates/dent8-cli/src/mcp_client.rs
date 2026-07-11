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
use crate::status::ErrorCode;

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

/// Read-only daemon status over the unauthenticated MCP surface. This lets `dent8 daemon
/// status` distinguish "the socket is up and serving reads" from "this caller can write after
/// proving identity" without requiring identity env just to inspect the daemon.
pub(crate) fn daemon_runtime_status(socket_path: &str) -> Result<Value, String> {
    let stream = UnixStream::connect(socket_path)
        .map_err(|error| format!("cannot reach the dent8 daemon at {socket_path}: {error}"))?;
    let mut writer = stream
        .try_clone()
        .map_err(|error| format!("dent8 daemon socket: {error}"))?;
    let mut reader = BufReader::new(stream);

    let initialize = request(
        1,
        "initialize",
        json!({
            "protocolVersion": crate::mcp::LATEST_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "dent8 daemon status", "version": env!("CARGO_PKG_VERSION") },
        }),
    );
    let reply = round_trip(&mut writer, &mut reader, &initialize)?;
    if reply["result"]["serverInfo"]["name"] != "dent8" {
        return Err(format!(
            "daemon initialize did not return dent8 serverInfo: {reply}"
        ));
    }
    let initialized = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    });
    let mut initialized_line = serde_json::to_string(&initialized)
        .map_err(|error| format!("encode initialized notification: {error}"))?;
    initialized_line.push('\n');
    write_raw_line(&mut writer, &initialized_line)?;

    let call = request(
        2,
        "tools/call",
        json!({ "name": "runtime_status", "arguments": {} }),
    );
    let reply = round_trip(&mut writer, &mut reader, &call)?;
    let result = reply
        .get("result")
        .ok_or_else(|| format!("runtime_status missing result: {reply}"))?;
    if result
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true)
    {
        return Err(format!("runtime_status returned an error: {result}"));
    }
    result
        .get("structuredContent")
        .cloned()
        .ok_or_else(|| format!("runtime_status missing structuredContent: {result}"))
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
/// with the caller's source key, then pumps newline-delimited JSON-RPC frames **in both
/// directions independently**: stdin → daemon on this thread, daemon → stdout on a second.
/// Decoupling the directions is what lets server-initiated frames through — the daemon pushes
/// `notifications/resources/updated` for subscribed resources at its own pace, not lockstep
/// with requests (and client notifications like `notifications/initialized`, which get no
/// reply, cannot deadlock the pump either).
pub(crate) fn daemon_proxy(socket_path: &str) -> Result<(), String> {
    let session = Session::connect(socket_path)?;
    let Session {
        writer: mut daemon_writer,
        reader: mut daemon_reader,
        ..
    } = session;

    let downstream = std::thread::spawn(move || -> Result<(), String> {
        let mut stdout = std::io::stdout();
        loop {
            let mut line = String::new();
            match daemon_reader.read_line(&mut line) {
                // Daemon closed (e.g. it shut down, or our write half signalled EOF).
                Ok(0) => return Ok(()),
                Ok(_) => stdout
                    .write_all(line.as_bytes())
                    .and_then(|()| stdout.flush())
                    .map_err(|error| format!("write stdout: {error}"))?,
                Err(error) => return Err(format!("read from daemon: {error}")),
            }
        }
    });

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("read stdin: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        write_raw_line(&mut daemon_writer, &line)?;
    }
    // Client stdin closed: half-close toward the daemon so it sees EOF and closes in turn,
    // ending the downstream pump after any final frames drain.
    let _ = daemon_writer.shutdown(std::net::Shutdown::Write);
    downstream
        .join()
        .map_err(|_| "daemon reader thread panicked".to_string())?
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
        return Err(OpError::invalid(format!("daemon: {message}")));
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
    let structured = result.and_then(|result| result.get("structuredContent"));
    let status = structured
        .and_then(|structured| structured.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("rejected");
    // Lift the machine-readable cause out of the reply so a daemon-routed write carries the
    // same `code` a local one would; an unknown token (a newer daemon) degrades to the generic.
    let code = structured
        .and_then(|structured| structured.get("code"))
        .and_then(Value::as_str)
        .and_then(ErrorCode::from_wire);
    match status {
        // `invalid` = a malformed request; `failed` = a store-load/scan failure the daemon hits
        // *before* the write commits (`run_write_tool` degrades post-commit read errors to a
        // best-effort empty receipt, so `failed` never marks a committed write). Both are the
        // couldn't-run class the local `op_*` classifies as `OpError::invalid` (exit 2).
        "invalid" | "failed" => Err(OpError::invalid_as(
            code.unwrap_or(ErrorCode::InvalidArgument),
            text,
        )),
        _ => Err(OpError::rejected_as(
            code.unwrap_or(ErrorCode::Rejected),
            text,
        )),
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
    use super::map_tool_reply;
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
            matches!(map_tool_reply(&reply), Err(OpError::Rejected { message: text, .. }) if text.contains("insufficient"))
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
        assert!(matches!(
            map_tool_reply(&reply),
            Err(OpError::Invalid { .. })
        ));
    }

    #[test]
    fn a_jsonrpc_protocol_error_maps_to_invalid() {
        let reply =
            json!({ "error": { "code": -32601, "message": "tool 'assert' is not available" } });
        assert!(
            matches!(map_tool_reply(&reply), Err(OpError::Invalid { message: text, .. }) if text.contains("daemon:"))
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
        assert!(matches!(
            map_tool_reply(&reply),
            Err(OpError::Invalid { .. })
        ));
    }

    #[test]
    fn an_error_flag_without_a_status_defaults_to_rejected() {
        // A firewall isError with no `status` is a refusal, not a usage error.
        let reply = json!({
            "result": { "isError": true, "content": [{ "type": "text", "text": "REJECTED: x" }] },
        });
        assert!(matches!(
            map_tool_reply(&reply),
            Err(OpError::Rejected { .. })
        ));
    }
}
