//! A minimal Model Context Protocol (MCP) server over stdio, exposing the dent8 firewall
//! to agent clients. Transport is newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP
//! stdio convention); the loop is synchronous, so no async runtime is needed.
//!
//! It speaks just enough MCP to be useful:
//! - `initialize`, `tools/list`, and `tools/call` for the full belief surface — `assert` /
//!   `supersede` / `retract` / `contradict` / `explain` / `replay` — plus read/audit tools
//!   (`runtime_status`, `snapshot`, `list_facts`, `verify`, `conflicts`, `native_scan`,
//!   `native_reconcile`) which dispatch to the same shared `op_*`
//!   functions the CLI uses, so the firewall decision is identical on both surfaces;
//! - `resources/list` / `resources/read`, exposing each believed fact stream as a readable
//!   resource at `dent8://{kind}/{key}/{predicate}` (read returns the integrity receipt);
//! - **JSON-RPC 2.0 batches** — a top-level array of requests yields an array of responses
//!   (notifications omitted), per the spec.
//!
//! Notifications (e.g. `notifications/initialized`) are accepted silently.

use std::io::{BufRead, Write};

use clap::ValueEnum;
use dent8_core::{AuthorityLevel, FactEvent, FactEventKind, FactLifecycle, FactValue};
use dent8_store::{EventFilter, EventStore, IntegrityReceipt};
use serde_json::{Value, json};

use crate::ops::{
    OpError, op_assert, op_conflicts, op_contradict, op_derive, op_expire, op_explain,
    op_explain_receipt, op_reinforce, op_replay, op_retract, op_supersede, with_write_retry,
};
use crate::{
    InitAgent, WriteIdentity, authority_registry_path, authority_required, display_value,
    load_authority_registry_at, load_store, log_path, native, parse_authority, short,
    status::Status, store_url, verify_log, witness,
};

/// The latest MCP protocol revision this server prefers.
pub(crate) const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";
/// Older revisions this adapter still speaks without changing its response shape.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[LATEST_PROTOCOL_VERSION, "2025-06-18"];

/// Server-wide guidance consumed by MCP clients that support `instructions` (including Codex).
const SERVER_INSTRUCTIONS: &str = "\
dent8 is a memory integrity firewall for durable agent facts. Before relying on project facts, \
call snapshot (or runtime_status/list_facts for narrower checks), then explain as needed. Record stable facts with assert using truthful source and authority. \
When the connection has a signed source grant, write tools may omit source and authority. \
Use supersede for corrections, contradict for disputes, derive for facts based on other facts. \
Use native_scan/native_reconcile to audit provider-native memory/rules files when available. \
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
            Ok(request) => dispatch(&request, &path, &WriteIdentity::Env),
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

/// Route `dent8 mcp serve`: the stdio loop by default, or a local per-user Unix-socket daemon
/// with `--daemon` (ADR 0018) — the same JSON-RPC surface many agents can share over one
/// transport. Daemon reads are available immediately; writes require the per-connection
/// session-challenge handshake first.
pub fn serve_command(daemon: bool, socket: Option<&str>) -> i32 {
    if daemon {
        serve_daemon(socket)
    } else {
        serve()
    }
}

/// Run a stdio-to-daemon MCP bridge: authenticate to the local Unix-socket daemon once, then
/// forward the client's JSON-RPC frames over that single authenticated connection.
#[cfg(all(unix, feature = "async-store"))]
pub fn proxy_command(socket: Option<&str>) -> i32 {
    let socket_path = socket
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("DENT8_DAEMON_SOCKET")
                .filter(|value| !value.is_empty())
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| daemon_socket_path(None));
    match crate::mcp_client::daemon_proxy(&socket_path.to_string_lossy()) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("mcp proxy: {error}");
            1
        }
    }
}

/// Non-Unix or storage-backend-less builds cannot connect to the local Unix-socket daemon.
#[cfg(not(all(unix, feature = "async-store")))]
pub fn proxy_command(_socket: Option<&str>) -> i32 {
    eprintln!(
        "mcp: `proxy` needs a Unix build with a storage backend (e.g. the default \
         `sqlite` feature); use plain `dent8 mcp serve` for stdio"
    );
    1
}

/// Serve the belief surface over a local Unix-domain socket (ADR 0018): a per-user daemon that
/// dispatches each newline-delimited JSON-RPC request through the exact same [`dispatch`] the
/// stdio server uses, so the firewall decision is identical on both transports. Connections
/// are read-only until they prove the daemon's configured source identity with
/// `dent8/hello` + `dent8/prove`; authenticated writes are then attested server-side as that
/// source. Connections are refused unless the peer runs as the same OS user (defence in depth
/// atop the `0700` runtime dir). Returns a process exit code.
#[cfg(all(unix, feature = "async-store"))]
pub fn serve_daemon(socket: Option<&str>) -> i32 {
    use std::os::unix::fs::MetadataExt;

    let socket_path = daemon_socket_path(socket);
    if let Err(error) = prepare_socket_path(&socket_path) {
        eprintln!("mcp: {error}");
        return 1;
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("mcp: tokio runtime: {error}");
            return 1;
        }
    };

    runtime.block_on(async move {
        let listener = match tokio::net::UnixListener::bind(&socket_path) {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("mcp: cannot bind {}: {error}", socket_path.display());
                return 1;
            }
        };
        if let Err(error) = std::fs::set_permissions(
            &socket_path,
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        ) {
            eprintln!("mcp: cannot set 0600 on {}: {error}", socket_path.display());
            return 1;
        }
        // The socket file is owned by whoever bound it — us — so its owner uid is the daemon
        // uid without a libc `geteuid` dependency.
        let daemon_uid = match std::fs::metadata(&socket_path) {
            Ok(meta) => meta.uid(),
            Err(error) => {
                eprintln!("mcp: cannot stat {}: {error}", socket_path.display());
                return 1;
            }
        };
        let store_path = log_path();
        eprintln!("dent8 mcp daemon listening on {}", socket_path.display());
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let store_path = store_path.clone();
                    tokio::spawn(async move {
                        serve_connection(stream, store_path, daemon_uid).await;
                    });
                }
                Err(error) => {
                    // A transient accept error should not tear the daemon down; keep looping.
                    eprintln!("mcp: accept error: {error}");
                }
            }
        }
    })
}

/// The largest single JSON-RPC request frame the daemon will buffer (8 MiB — generous for the
/// belief surface). A frame that reaches this without a newline is rejected and the connection
/// closed, so a client cannot grow the read buffer unboundedly.
#[cfg(all(unix, feature = "async-store"))]
const MAX_FRAME_BYTES: u64 = 8 * 1024 * 1024;

/// One accepted connection: refuse a cross-user peer, then read newline-delimited JSON-RPC
/// and reply, running each (blocking) [`dispatch`] on the blocking pool so its throwaway
/// current-thread runtime does not nest inside this async worker.
#[cfg(all(unix, feature = "async-store"))]
async fn serve_connection(stream: tokio::net::UnixStream, store_path: String, daemon_uid: u32) {
    use tokio::io::AsyncBufReadExt;

    match stream.peer_cred() {
        Ok(cred) if cred.uid() == daemon_uid => {}
        Ok(cred) => {
            eprintln!("mcp: refused connection from uid {}", cred.uid());
            return;
        }
        Err(error) => {
            eprintln!("mcp: cannot read peer credentials: {error}");
            return;
        }
    }

    // The daemon's own signed identity, resolved once per connection from process env. A
    // connection authenticates *as this same-user source* (ADR 0018): the session challenge
    // proves the connecting party holds the key the daemon will attest its writes with. `None`
    // (or an unconfigured identity) leaves the connection read-only.
    let daemon_identity = crate::identity::IdentityContext::from_env()
        .ok()
        .map(std::sync::Arc::new);
    let mut session = HandshakeState::Fresh;

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read_half);
    loop {
        // Cap a single request frame: `read_line` accumulates into one `String`, so an unbounded
        // read lets a (same-user) client grow it toward OOM. `take` re-applies the limit each
        // iteration; an over-cap frame with no newline is rejected and the connection closed.
        let mut line = String::new();
        let read = tokio::io::AsyncReadExt::take(&mut reader, MAX_FRAME_BYTES)
            .read_line(&mut line)
            .await;
        let bytes = match read {
            Ok(0) => return,
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("mcp: connection read error: {error}");
                return;
            }
        };
        if bytes as u64 == MAX_FRAME_BYTES && !line.ends_with('\n') {
            let response = error_response(&Value::Null, -32700, "request frame too large");
            let _ = write_line(&mut write_half, &response).await;
            return;
        }
        if line.trim().is_empty() {
            continue;
        }
        let request = match serde_json::from_str::<Value>(&line) {
            Ok(request) => request,
            Err(error) => {
                let response =
                    error_response(&Value::Null, -32700, &format!("parse error: {error}"));
                if !write_line(&mut write_half, &response).await {
                    return;
                }
                continue;
            }
        };

        // The session-challenge handshake is handled inline (never dispatched to the store),
        // maintaining per-connection state so one connection can never present another's nonce.
        if let Some(method) = request.get("method").and_then(Value::as_str)
            && matches!(method, "dent8/hello" | "dent8/prove")
        {
            let response = handle_handshake(
                &mut session,
                method,
                &request,
                daemon_identity.as_ref(),
                crate::now_millis(),
            )
            .await;
            if !write_line(&mut write_half, &response).await {
                return;
            }
            continue;
        }

        // A normal request runs under this connection's current write identity: `Connection`
        // once authenticated (writes allowed, attested as that source), else `Unauthenticated`
        // (reads only — the gate in `handle` refuses writes).
        let write_identity = session.write_identity();

        let store_path = store_path.clone();
        let response = match tokio::task::spawn_blocking(move || {
            dispatch(&request, &store_path, &write_identity)
        })
        .await
        {
            Ok(response) => response,
            Err(error) => {
                eprintln!("mcp: dispatch task failed: {error}");
                return;
            }
        };
        let Some(response) = response else {
            continue;
        };
        if !write_line(&mut write_half, &response).await {
            return;
        }
    }
}

/// Write one JSON-RPC response as a newline-delimited line; `false` on a broken pipe.
#[cfg(all(unix, feature = "async-store"))]
async fn write_line(
    write_half: &mut (impl tokio::io::AsyncWrite + Unpin),
    response: &Value,
) -> bool {
    use tokio::io::AsyncWriteExt;
    let mut serialized = serde_json::to_string(response).unwrap_or_else(|_| "{}".to_string());
    serialized.push('\n');
    write_half.write_all(serialized.as_bytes()).await.is_ok() && write_half.flush().await.is_ok()
}

// ---- Session-challenge handshake (ADR 0018) -----------------------------------------------
//
// A daemon connection proves possession of its source key before it may write. `dent8/hello`
// names the source + grant; the daemon verifies the grant and issues a single-use, 30s,
// connection-scoped nonce; `dent8/prove` carries an Ed25519 signature over
// `framed(dent8.session-challenge.v1\0, {nonce, source, public_key, grant_signature})`. On
// success the connection's writes are attested with that source's (same-user) key — attestation
// stays server-side and unchanged (ADR 0013). All the crypto lives in `identity`.

/// A challenge is valid for 30 seconds — long enough for a client round-trip, short enough to
/// bound the replay window (the nonce is also single-use and connection-scoped).
#[cfg(all(unix, feature = "async-store"))]
const SESSION_CHALLENGE_TTL_MS: i64 = 30_000;

// Server-defined JSON-RPC error codes for the handshake, so a client can distinguish
// "retry the handshake" from "your grant is dead."
#[cfg(all(unix, feature = "async-store"))]
const SESSION_ERR_UNCONFIGURED: i64 = -32010;
#[cfg(all(unix, feature = "async-store"))]
const SESSION_ERR_HELLO: i64 = -32011;
#[cfg(all(unix, feature = "async-store"))]
const SESSION_ERR_SEQUENCE: i64 = -32012;
#[cfg(all(unix, feature = "async-store"))]
const SESSION_ERR_EXPIRED: i64 = -32013;
#[cfg(all(unix, feature = "async-store"))]
const SESSION_ERR_BAD_SIGNATURE: i64 = -32014;
#[cfg(all(unix, feature = "async-store"))]
const SESSION_ERR_INTERNAL: i64 = -32015;

/// The coarse client-facing reason for any hello-check failure, so the wire never reveals
/// *which* of grant / active-grant / key mismatched. The specific reason is logged server-side.
#[cfg(all(unix, feature = "async-store"))]
const SESSION_HELLO_REJECTED: &str =
    "hello rejected: not a valid, active grant for this daemon's source";

/// Per-connection handshake state, owned by the one `serve_connection` task (so a nonce is never
/// reachable from another connection). Every early return / failure lands in `Failed`, never a
/// reusable `Challenged`.
#[cfg(all(unix, feature = "async-store"))]
enum HandshakeState {
    /// No handshake attempted yet — reads allowed, writes refused.
    Fresh,
    /// A nonce has been issued and is awaiting exactly one `dent8/prove`.
    Challenged {
        nonce: String,
        hello: crate::identity::VerifiedHello,
        identity: std::sync::Arc<crate::identity::IdentityContext>,
        expires_at: i64,
    },
    /// Possession proven — writes are attested as this connection's source.
    Authenticated {
        identity: std::sync::Arc<crate::identity::IdentityContext>,
    },
    /// A failed or consumed handshake — reads allowed, writes refused, until a fresh hello.
    Failed,
}

#[cfg(all(unix, feature = "async-store"))]
impl HandshakeState {
    /// The write identity for a normal request in this state: a proven `Connection` once
    /// authenticated, else `Unauthenticated` (the gate refuses writes).
    fn write_identity(&self) -> WriteIdentity {
        match self {
            HandshakeState::Authenticated { identity } => {
                WriteIdentity::Connection(identity.clone())
            }
            _ => WriteIdentity::Unauthenticated,
        }
    }
}

/// Dispatch a `dent8/hello` or `dent8/prove` message, mutating the per-connection state. The
/// cheap state transitions stay on the reactor thread (they hold `&mut session`); the blocking
/// grant/signature verification is offloaded to the blocking pool by the handlers.
#[cfg(all(unix, feature = "async-store"))]
async fn handle_handshake(
    session: &mut HandshakeState,
    method: &str,
    request: &Value,
    daemon_identity: Option<&std::sync::Arc<crate::identity::IdentityContext>>,
    now: dent8_core::TimestampMillis,
) -> Value {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let params = request.get("params");
    match method {
        "dent8/hello" => handle_hello(session, &id, params, daemon_identity, now).await,
        "dent8/prove" => handle_prove(session, &id, params, now).await,
        _ => error_response(&id, -32601, "unknown handshake method"),
    }
}

/// `dent8/hello`: verify the presented grant against the daemon's own trust + key, then issue a
/// fresh single-use nonce. A fresh hello always resets the connection to `Challenged`. The grant
/// verification (file reads + Ed25519) runs on the blocking pool, off the reactor.
#[cfg(all(unix, feature = "async-store"))]
async fn handle_hello(
    session: &mut HandshakeState,
    id: &Value,
    params: Option<&Value>,
    daemon_identity: Option<&std::sync::Arc<crate::identity::IdentityContext>>,
    now: dent8_core::TimestampMillis,
) -> Value {
    let Some(daemon_identity) = daemon_identity.filter(|ctx| ctx.configured()) else {
        *session = HandshakeState::Failed;
        return error_response(
            id,
            SESSION_ERR_UNCONFIGURED,
            "this daemon has no signed identity configured; writes are unavailable",
        );
    };
    let Some(source) = params
        .and_then(|params| params.get("source"))
        .and_then(Value::as_str)
    else {
        *session = HandshakeState::Failed;
        return error_response(id, -32602, "dent8/hello requires a string `source`");
    };
    let Some(grant) = params.and_then(|params| params.get("grant")) else {
        *session = HandshakeState::Failed;
        return error_response(id, -32602, "dent8/hello requires a `grant` object");
    };
    // Offload the grant verification (trust/active-grant/key file reads + Ed25519) to the
    // blocking pool so the single-threaded reactor keeps serving other connections.
    let ctx = daemon_identity.clone();
    let (source, grant) = (source.to_string(), grant.clone());
    let verified = tokio::task::spawn_blocking(move || {
        crate::identity::verify_session_hello(&ctx, &grant, &source, now)
    })
    .await;
    match verified {
        Ok(Ok(hello)) => match crate::identity::session_nonce() {
            Ok(nonce) => {
                let expires_at = now
                    .as_unix_millis()
                    .saturating_add(SESSION_CHALLENGE_TTL_MS);
                let response = result_response(
                    id,
                    &json!({ "nonce": nonce, "expires_in_ms": SESSION_CHALLENGE_TTL_MS }),
                );
                *session = HandshakeState::Challenged {
                    nonce,
                    hello,
                    identity: daemon_identity.clone(),
                    expires_at,
                };
                response
            }
            Err(error) => {
                eprintln!("mcp: could not issue a session nonce: {error}");
                *session = HandshakeState::Failed;
                error_response(id, SESSION_ERR_INTERNAL, "could not issue a challenge")
            }
        },
        Ok(Err(detail)) => {
            eprintln!("mcp: dent8/hello rejected: {detail}");
            *session = HandshakeState::Failed;
            error_response(id, SESSION_ERR_HELLO, SESSION_HELLO_REJECTED)
        }
        Err(join_error) => {
            eprintln!("mcp: handshake verify task failed: {join_error}");
            *session = HandshakeState::Failed;
            error_response(id, SESSION_ERR_INTERNAL, "could not verify the handshake")
        }
    }
}

/// `dent8/prove`: verify the signature over the stored challenge. A `Challenged` nonce is
/// consumed here (it never returns to `Challenged`, pass or fail) so it is single-use. A prove
/// in any *other* state is out of sequence and leaves that state unchanged — a stray or replayed
/// prove never demotes an already-authenticated connection.
#[cfg(all(unix, feature = "async-store"))]
async fn handle_prove(
    session: &mut HandshakeState,
    id: &Value,
    params: Option<&Value>,
    now: dent8_core::TimestampMillis,
) -> Value {
    let (nonce, hello, identity, expires_at) =
        match std::mem::replace(session, HandshakeState::Failed) {
            HandshakeState::Challenged {
                nonce,
                hello,
                identity,
                expires_at,
            } => (nonce, hello, identity, expires_at),
            other => {
                // Not awaiting a prove: restore the prior state and reject out of sequence.
                *session = other;
                return error_response(
                    id,
                    SESSION_ERR_SEQUENCE,
                    "no active challenge; send dent8/hello first",
                );
            }
        };
    if now.as_unix_millis() > expires_at {
        return error_response(
            id,
            SESSION_ERR_EXPIRED,
            "challenge expired; resend dent8/hello",
        );
    }
    let Some(signature) = params
        .and_then(|params| params.get("signature"))
        .and_then(Value::as_str)
    else {
        return error_response(id, -32602, "dent8/prove requires a hex `signature`");
    };
    // Offload the Ed25519 verification to the blocking pool, consistent with hello and dispatch.
    let source = hello.source.clone();
    let signature = signature.to_string();
    let verified = tokio::task::spawn_blocking(move || {
        crate::identity::verify_session_prove(&hello, &nonce, &signature)
    })
    .await;
    match verified {
        Ok(Ok(())) => {
            let response = result_response(id, &json!({ "authenticated": true, "source": source }));
            *session = HandshakeState::Authenticated { identity };
            response
        }
        Ok(Err(detail)) => {
            eprintln!("mcp: dent8/prove rejected: {detail}");
            error_response(
                id,
                SESSION_ERR_BAD_SIGNATURE,
                "session challenge signature does not verify",
            )
        }
        Err(join_error) => {
            eprintln!("mcp: handshake verify task failed: {join_error}");
            error_response(id, SESSION_ERR_INTERNAL, "could not verify the handshake")
        }
    }
}

/// Resolve the daemon socket path: an explicit `--socket`, else `$XDG_RUNTIME_DIR/dent8/
/// dent8.sock`, else a fallback under the temp dir (`$TMPDIR`/`/tmp`) for platforms that
/// leave `$XDG_RUNTIME_DIR` unset (e.g. macOS, where `$TMPDIR` is already a per-user private
/// directory). The `dent8` subdir is created `0700` regardless, so the socket is never
/// world-reachable even under a shared `/tmp`.
#[cfg(all(unix, feature = "async-store"))]
pub(crate) fn daemon_socket_path(socket: Option<&str>) -> std::path::PathBuf {
    if let Some(socket) = socket {
        return std::path::PathBuf::from(socket);
    }
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("TMPDIR").filter(|value| !value.is_empty()))
        .map_or_else(
            || std::path::PathBuf::from("/tmp"),
            std::path::PathBuf::from,
        );
    base.join("dent8").join("dent8.sock")
}

/// Create the socket's parent dir `0700` and clear a stale socket left by a prior run. Refuses
/// to remove a path that exists and is *not* a socket, so a mistyped `--socket` never deletes
/// a real file.
#[cfg(all(unix, feature = "async-store"))]
fn prepare_socket_path(socket_path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt};

    if let Some(parent) = socket_path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|error| format!("cannot create socket dir {}: {error}", parent.display()))?;
    }
    match std::fs::symlink_metadata(socket_path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(socket_path).map_err(|error| {
                format!(
                    "cannot remove stale socket {}: {error}",
                    socket_path.display()
                )
            })
        }
        Ok(_) => Err(format!(
            "refusing to bind: {} exists and is not a socket",
            socket_path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot stat {}: {error}", socket_path.display())),
    }
}

/// Non-Unix or storage-backend-less builds have no `tokio` Unix socket — refuse `--daemon`
/// with a clear message rather than silently falling back to stdio.
#[cfg(not(all(unix, feature = "async-store")))]
pub fn serve_daemon(_socket: Option<&str>) -> i32 {
    eprintln!(
        "mcp: `--daemon` needs a Unix build with a storage backend (e.g. the default \
         `sqlite` feature); use plain `dent8 mcp serve` for stdio"
    );
    1
}

/// Whether a dispatch may execute writes. The stdio server is [`Access::Full`]; the local
/// daemon starts each connection as [`Access::ReadOnly`] and promotes only after the
/// session-challenge handshake, so a socket connection can never persist an event attested
/// with an unproven process identity.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Full,
    ReadOnly,
}

/// The seven belief-mutating tools, rejected up front under [`Access::ReadOnly`].
fn is_write_tool(name: &str) -> bool {
    matches!(
        name,
        "assert" | "supersede" | "retract" | "contradict" | "derive" | "reinforce" | "expire"
    )
}

/// The access a request identity grants, derived so the write gate and the identity seam can
/// never disagree: a proven identity (the CLI/stdio env, or a daemon connection) is [`Full`];
/// an unauthenticated daemon connection is [`ReadOnly`]. There is no way to be `Full` without a
/// `WriteIdentity` the identity seam accepts (ADR 0018).
fn access_for(identity: &WriteIdentity) -> Access {
    match identity {
        WriteIdentity::Env => Access::Full,
        WriteIdentity::Unauthenticated => Access::ReadOnly,
        #[cfg(all(unix, feature = "async-store"))]
        WriteIdentity::Connection(_) => Access::Full,
    }
}

/// Dispatch one parsed JSON-RPC message: a single request object, or a **batch** (a
/// non-empty array of requests → an array of responses, omitting notifications; an empty
/// array is an invalid request). Returns `None` when there is nothing to send (a lone
/// notification, or a batch of only notifications).
fn dispatch(message: &Value, path: &str, identity: &WriteIdentity) -> Option<Value> {
    let Some(batch) = message.as_array() else {
        return handle(message, path, identity);
    };
    if batch.is_empty() {
        return Some(error_response(
            &Value::Null,
            -32600,
            "invalid request: empty batch",
        ));
    }
    let responses: Vec<Value> = batch
        .iter()
        .filter_map(|item| handle(item, path, identity))
        .collect();
    // A batch containing only notifications gets no reply (JSON-RPC 2.0).
    if responses.is_empty() {
        None
    } else {
        Some(Value::Array(responses))
    }
}

/// Handle one JSON-RPC request object. Returns the response value, or `None` for a
/// notification (a request with no `id`, e.g. `notifications/initialized`).
fn handle(request: &Value, path: &str, identity: &WriteIdentity) -> Option<Value> {
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
        "tools/call" => {
            // Fail a write closed *before* dispatch under ReadOnly: an unauthenticated daemon
            // connection has not proven its identity, so a persisted write would carry the
            // daemon's own process attestation (ADR 0018). Reads are always allowed.
            if access_for(identity) == Access::ReadOnly
                && let Some(name) = request
                    .get("params")
                    .and_then(|params| params.get("name"))
                    .and_then(Value::as_str)
                && is_write_tool(name)
            {
                return Some(error_response(
                    &id,
                    -32601,
                    &format!(
                        "tool '{name}' writes belief state and is not available until this \
                         connection proves a source identity (dent8/hello)"
                    ),
                ));
            }
            Some(handle_tool_call(&id, request.get("params"), path, identity))
        }
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
            Self::Unknown(_) | Self::Invalid(_) => Status::Invalid.as_str(),
            Self::Rejected(_) => Status::Rejected.as_str(),
            Self::Failed(_) => Status::Failed.as_str(),
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

fn handle_tool_call(
    id: &Value,
    params: Option<&Value>,
    path: &str,
    identity: &WriteIdentity,
) -> Value {
    let Some(params) = params else {
        return error_response(id, -32602, "missing params");
    };
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    match dispatch_tool(name, &arguments, path, identity) {
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
    match crate::ops::op_list_subjects_with_freshness(path, false) {
        Ok(subjects) => {
            let resources: Vec<Value> = subjects
                .iter()
                .map(|(kind, key, predicate, freshness)| {
                    json!({
                        "uri": resource_uri(kind, key, predicate),
                        "name": format!("{kind}:{key} {predicate}{}", freshness.text_marker()),
                        "description": format!(
                            "The believed (or terminal) value of `{predicate}` for {kind}:{key} (currently {}), with its integrity receipt.",
                            freshness.json_name()
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
    match op_explain(
        path,
        &kind,
        &key,
        &predicate,
        crate::ops::ReadClock::default(),
    ) {
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
fn dispatch_tool(
    name: &str,
    arguments: &Value,
    path: &str,
    identity: &WriteIdentity,
) -> Result<ToolOutput, ToolError> {
    // One `subject` argument (`"kind:key"`, e.g. `person:alice`) mirrors the CLI grammar; the
    // `kind`/`key` closures split it so the per-tool destructuring below is unchanged.
    let subject = || arg_subject(arguments, "subject");
    let kind = || subject().map(|(kind, _)| kind);
    let key = || subject().map(|(_, key)| key);
    let predicate = || arg(arguments, "predicate");
    match name {
        "runtime_status" => Ok(runtime_status(path)),
        "snapshot" => {
            let include_diagnostics = optional_bool(arguments, "include_diagnostics")?;
            let (text, structured) =
                crate::snapshot::snapshot_text_and_json(path, include_diagnostics, "snapshot");
            Ok(ToolOutput::new(text, structured))
        }
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
                    "status": if verified { Status::Ok.as_str() } else { Status::IntegrityIssues.as_str() },
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
                    "status": if text.starts_with("no contested") { Status::Ok.as_str() } else { Status::Contested.as_str() },
                    "tool": "conflicts",
                    "message": text,
                }),
            ))
        }
        "native_scan" => native_scan(arguments),
        "native_reconcile" => native_reconcile(path, arguments),
        "assert" => {
            let meta = resolve_write_meta(arguments, identity)?;
            let (kind, key, predicate, value) =
                (kind()?, key()?, predicate()?, arg(arguments, "value")?);
            let validity = arg_validity(arguments)?;
            run_write_tool(
                "assert",
                Status::Accepted,
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: Some(&value),
                    authority: meta.authority,
                    source: &meta.source,
                },
                || {
                    op_assert(
                        path,
                        &kind,
                        &key,
                        &predicate,
                        &value,
                        meta.authority,
                        &meta.source,
                        validity,
                        identity,
                    )
                },
            )
        }
        "supersede" => {
            let meta = resolve_write_meta(arguments, identity)?;
            let (kind, key, predicate, value) =
                (kind()?, key()?, predicate()?, arg(arguments, "value")?);
            let validity = arg_validity(arguments)?;
            run_write_tool(
                "supersede",
                Status::Accepted,
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: Some(&value),
                    authority: meta.authority,
                    source: &meta.source,
                },
                || {
                    op_supersede(
                        path,
                        &kind,
                        &key,
                        &predicate,
                        &value,
                        meta.authority,
                        &meta.source,
                        validity,
                        identity,
                    )
                },
            )
        }
        "retract" => {
            let meta = resolve_write_meta(arguments, identity)?;
            let (kind, key, predicate) = (kind()?, key()?, predicate()?);
            run_write_tool(
                "retract",
                Status::Accepted,
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: None,
                    authority: meta.authority,
                    source: &meta.source,
                },
                || {
                    op_retract(
                        path,
                        &kind,
                        &key,
                        &predicate,
                        meta.authority,
                        &meta.source,
                        identity,
                    )
                },
            )
        }
        "reinforce" => {
            let meta = resolve_write_meta(arguments, identity)?;
            let (kind, key, predicate) = (kind()?, key()?, predicate()?);
            run_write_tool(
                "reinforce",
                Status::Accepted,
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: None,
                    authority: meta.authority,
                    source: &meta.source,
                },
                || {
                    op_reinforce(
                        path,
                        &kind,
                        &key,
                        &predicate,
                        meta.authority,
                        &meta.source,
                        identity,
                    )
                },
            )
        }
        "expire" => {
            let meta = resolve_write_meta(arguments, identity)?;
            let (kind, key, predicate) = (kind()?, key()?, predicate()?);
            run_write_tool(
                "expire",
                Status::Accepted,
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: None,
                    authority: meta.authority,
                    source: &meta.source,
                },
                || {
                    op_expire(
                        path,
                        &kind,
                        &key,
                        &predicate,
                        meta.authority,
                        &meta.source,
                        identity,
                    )
                },
            )
        }
        "derive" => {
            let meta = resolve_write_meta(arguments, identity)?;
            let (kind, key, predicate, value) =
                (kind()?, key()?, predicate()?, arg(arguments, "value")?);
            // The basis fact this derivative depends on: one `basis` subject (`"kind:key"`) plus
            // its predicate — mirrors the CLI's `--basis <subject> <predicate>`.
            let (from_kind, from_key) = arg_subject(arguments, "basis")?;
            let from_predicate = arg(arguments, "basis_predicate")?;
            let validity = arg_validity(arguments)?;
            let mut output = run_write_tool(
                "derive",
                Status::Accepted,
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: Some(&value),
                    authority: meta.authority,
                    source: &meta.source,
                },
                || {
                    op_derive(
                        path,
                        &kind,
                        &key,
                        &predicate,
                        &value,
                        meta.authority,
                        &meta.source,
                        &from_kind,
                        &from_key,
                        &from_predicate,
                        validity,
                        identity,
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
            let meta = resolve_write_meta(arguments, identity)?;
            let (kind, key, predicate, value) =
                (kind()?, key()?, predicate()?, arg(arguments, "value")?);
            let validity = arg_validity(arguments)?;
            run_write_tool(
                "contradict",
                Status::Contested,
                path,
                WriteContext {
                    subject_kind: &kind,
                    subject_key: &key,
                    predicate: &predicate,
                    attempted_value: Some(&value),
                    authority: meta.authority,
                    source: &meta.source,
                },
                || {
                    op_contradict(
                        path,
                        &kind,
                        &key,
                        &predicate,
                        &value,
                        meta.authority,
                        &meta.source,
                        validity,
                        identity,
                    )
                },
            )
        }
        "explain" => {
            let (kind, key, predicate) = (kind()?, key()?, predicate()?);
            let clock = arg_read_clock(arguments)?;
            let text = op_explain(path, &kind, &key, &predicate, clock).map_err(into_tool_error)?;
            let receipt = op_explain_receipt(path, &kind, &key, &predicate, clock)
                .map_err(into_tool_error)?;
            Ok(ToolOutput::new(
                text,
                explain_structured("explain", &receipt),
            ))
        }
        "replay" => {
            let (kind, key, predicate) = (kind()?, key()?, predicate()?);
            let clock = arg_read_clock(arguments)?;
            let text = op_replay(path, &kind, &key, &predicate, clock).map_err(into_tool_error)?;
            let structured = match op_explain_receipt(path, &kind, &key, &predicate, clock) {
                Ok(receipt) => explain_structured("replay", &receipt),
                Err(_) => json!({
                    "status": Status::Ok.as_str(),
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

fn runtime_status(path: &str) -> ToolOutput {
    let (text, structured) = runtime_status_parts(path);
    ToolOutput::new(text, structured)
}

pub(crate) fn runtime_status_parts(path: &str) -> (String, Value) {
    let store = runtime_store_status(path);
    let identity = runtime_identity_status();
    let authority = runtime_authority_status();
    let witness = runtime_witness_status();
    let top_status = if store.load_status == "failed"
        || authority.load_status == "failed"
        || identity.load_status == "failed"
        || witness.load_status == "failed"
    {
        Status::Degraded.as_str()
    } else {
        Status::Ok.as_str()
    };
    let text = runtime_status_text(&store, &identity, &authority, &witness);
    (
        text,
        json!({
            "status": top_status,
            "tool": "runtime_status",
            "server": {
                "name": "dent8",
                "version": env!("CARGO_PKG_VERSION"),
                "protocol_version": LATEST_PROTOCOL_VERSION,
                "pid": std::process::id(),
                "binary_path": std::env::current_exe()
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned()),
                "cwd": std::env::current_dir()
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned()),
            },
            "store": store.to_json(),
            "authority": authority.to_json(),
            "identity": identity.to_json(),
            "witness": witness.to_json(),
            "env": {
                "dent8_store_url_set": env_is_nonempty("DENT8_STORE_URL"),
                "dent8_log_set": env_is_nonempty("DENT8_LOG"),
                "dent8_authority_set": env_is_nonempty("DENT8_AUTHORITY"),
                "dent8_grant_set": env_is_nonempty("DENT8_GRANT"),
                "dent8_active_grants_set": env_is_nonempty("DENT8_ACTIVE_GRANTS"),
                "dent8_trust_set": env_is_nonempty("DENT8_TRUST"),
                "dent8_identity_key_set": env_is_nonempty("DENT8_IDENTITY_KEY"),
                "dent8_witness_log_set": env_is_nonempty("DENT8_WITNESS_LOG"),
                "dent8_witness_pubkey_set": env_is_nonempty("DENT8_WITNESS_PUBKEY"),
                "dent8_witness_key_set": env_is_nonempty("DENT8_WITNESS_KEY"),
            },
        }),
    )
}

#[derive(Debug)]
struct RuntimeStoreStatus {
    backend: String,
    url: Option<String>,
    path: Option<String>,
    file_log_path: String,
    event_count: Option<usize>,
    load_status: &'static str,
    load_error: Option<String>,
}

impl RuntimeStoreStatus {
    fn to_json(&self) -> Value {
        json!({
            "backend": self.backend,
            "url": self.url,
            "path": self.path,
            "file_log_path": self.file_log_path,
            "event_count": self.event_count,
            "load_status": self.load_status,
            "load_error": self.load_error,
        })
    }
}

fn runtime_store_status(path: &str) -> RuntimeStoreStatus {
    let url = store_url();
    let backend = url
        .as_deref()
        .and_then(|url| url.split_once(':').map(|(scheme, _)| scheme.to_string()))
        .unwrap_or_else(|| "file".to_string());
    let store_path = url
        .as_deref()
        .and_then(store_path_from_url)
        .or_else(|| (backend == "file").then(|| path.to_string()));
    match load_store(path) {
        Ok(store) => match store.scan_events(&EventFilter::default()) {
            Ok(events) => RuntimeStoreStatus {
                backend,
                url: url.as_deref().map(redact_url_credentials),
                path: store_path,
                file_log_path: path.to_string(),
                event_count: Some(events.len()),
                load_status: "ok",
                load_error: None,
            },
            Err(error) => RuntimeStoreStatus {
                backend,
                url: url.as_deref().map(redact_url_credentials),
                path: store_path,
                file_log_path: path.to_string(),
                event_count: None,
                load_status: "failed",
                load_error: Some(error.to_string()),
            },
        },
        Err(error) => RuntimeStoreStatus {
            backend,
            url: url.as_deref().map(redact_url_credentials),
            path: store_path,
            file_log_path: path.to_string(),
            event_count: None,
            load_status: "failed",
            load_error: Some(error),
        },
    }
}

fn store_path_from_url(url: &str) -> Option<String> {
    if let Some(path) = url.strip_prefix("sqlite://") {
        return Some(path.to_string());
    }
    None
}

fn redact_url_credentials(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let Some((userinfo, host_and_path)) = rest.split_once('@') else {
        return url.to_string();
    };
    if userinfo.is_empty() {
        url.to_string()
    } else {
        format!("{scheme}://<redacted>@{host_and_path}")
    }
}

#[derive(Debug)]
struct RuntimeAuthorityStatus {
    path: String,
    required: Option<bool>,
    configured: bool,
    source_count: Option<usize>,
    load_status: &'static str,
    load_error: Option<String>,
}

impl RuntimeAuthorityStatus {
    fn to_json(&self) -> Value {
        json!({
            "path": self.path,
            "required": self.required,
            "configured": self.configured,
            "source_count": self.source_count,
            "load_status": self.load_status,
            "load_error": self.load_error,
        })
    }
}

fn runtime_authority_status() -> RuntimeAuthorityStatus {
    let path = authority_registry_path();
    let required = match authority_required() {
        Ok(required) => required,
        Err(error) => {
            return RuntimeAuthorityStatus {
                path,
                required: None,
                configured: false,
                source_count: None,
                load_status: "failed",
                load_error: Some(error),
            };
        }
    };
    match load_authority_registry_at(&path, required) {
        Ok(Some(registry)) => RuntimeAuthorityStatus {
            path,
            required: Some(required),
            configured: true,
            source_count: Some(registry.sources.len()),
            load_status: "ok",
            load_error: None,
        },
        Ok(None) => RuntimeAuthorityStatus {
            path,
            required: Some(required),
            configured: false,
            source_count: Some(0),
            load_status: "missing",
            load_error: None,
        },
        Err(error) => RuntimeAuthorityStatus {
            path,
            required: Some(required),
            configured: false,
            source_count: None,
            load_status: "failed",
            load_error: Some(error),
        },
    }
}

#[derive(Debug)]
struct RuntimeIdentityStatus {
    configured: bool,
    source: Option<String>,
    max_authority: Option<&'static str>,
    trust_path: Option<String>,
    grant_path: Option<String>,
    active_grants_path: Option<String>,
    identity_key_configured: bool,
    load_status: &'static str,
    load_error: Option<String>,
}

impl RuntimeIdentityStatus {
    fn to_json(&self) -> Value {
        json!({
            "configured": self.configured,
            "source": self.source,
            "max_authority": self.max_authority,
            "trust_path": self.trust_path,
            "grant_path": self.grant_path,
            "active_grants_path": self.active_grants_path,
            "identity_key_configured": self.identity_key_configured,
            "load_status": self.load_status,
            "load_error": self.load_error,
        })
    }
}

fn runtime_identity_status() -> RuntimeIdentityStatus {
    let trust_path = nonempty_env("DENT8_TRUST");
    let grant_path = nonempty_env("DENT8_GRANT");
    let active_grants_path = nonempty_env("DENT8_ACTIVE_GRANTS");
    let identity_key_configured = env_is_nonempty("DENT8_IDENTITY_KEY");
    match crate::identity::IdentityContext::from_env() {
        Err(error) => RuntimeIdentityStatus {
            configured: false,
            source: None,
            max_authority: None,
            trust_path,
            grant_path,
            active_grants_path,
            identity_key_configured,
            load_status: "failed",
            load_error: Some(error),
        },
        Ok(ctx) if !ctx.configured() => RuntimeIdentityStatus {
            configured: false,
            source: None,
            max_authority: None,
            trust_path,
            grant_path,
            active_grants_path,
            identity_key_configured,
            load_status: "unconfigured",
            load_error: None,
        },
        Ok(ctx) => match ctx.write_defaults() {
            Ok(Some(defaults)) => RuntimeIdentityStatus {
                configured: true,
                source: Some(defaults.source),
                max_authority: Some(defaults.authority.name()),
                trust_path,
                grant_path,
                active_grants_path,
                identity_key_configured,
                load_status: "ok",
                load_error: None,
            },
            Ok(None) => RuntimeIdentityStatus {
                configured: true,
                source: None,
                max_authority: None,
                trust_path,
                grant_path,
                active_grants_path,
                identity_key_configured,
                load_status: "failed",
                load_error: Some("identity is configured, but DENT8_GRANT is not set".to_string()),
            },
            Err(error) => RuntimeIdentityStatus {
                configured: true,
                source: None,
                max_authority: None,
                trust_path,
                grant_path,
                active_grants_path,
                identity_key_configured,
                load_status: "failed",
                load_error: Some(error),
            },
        },
    }
}

#[derive(Debug)]
struct RuntimeWitnessStatus {
    configured: bool,
    log_path: Option<String>,
    pubkey_path: Option<String>,
    signing_key_present: bool,
    load_status: &'static str,
    messages: Vec<Value>,
}

impl RuntimeWitnessStatus {
    fn to_json(&self) -> Value {
        json!({
            "configured": self.configured,
            "log_path": self.log_path,
            "pubkey_path": self.pubkey_path,
            "signing_key_present": self.signing_key_present,
            "load_status": self.load_status,
            "messages": self.messages,
        })
    }
}

fn runtime_witness_status() -> RuntimeWitnessStatus {
    let lines = witness::doctor_status();
    let configured = env_is_nonempty("DENT8_WITNESS_LOG")
        || env_is_nonempty("DENT8_WITNESS_PUBKEY")
        || env_is_nonempty("DENT8_WITNESS_KEY");
    let load_status = if !configured {
        "unconfigured"
    } else if lines.iter().any(|line| !line.ok) {
        "failed"
    } else if lines.iter().any(|line| line.level == "WARN") {
        "warn"
    } else {
        "ok"
    };
    RuntimeWitnessStatus {
        configured,
        log_path: nonempty_env("DENT8_WITNESS_LOG"),
        pubkey_path: nonempty_env("DENT8_WITNESS_PUBKEY"),
        signing_key_present: env_is_nonempty("DENT8_WITNESS_KEY"),
        load_status,
        messages: lines
            .into_iter()
            .map(|line| json!({ "level": line.level, "message": line.message }))
            .collect(),
    }
}

fn runtime_status_text(
    store: &RuntimeStoreStatus,
    identity: &RuntimeIdentityStatus,
    authority: &RuntimeAuthorityStatus,
    witness: &RuntimeWitnessStatus,
) -> String {
    let store_count = store
        .event_count
        .map_or_else(|| "unknown".to_string(), |count| count.to_string());
    let store_target = store
        .url
        .as_deref()
        .or(store.path.as_deref())
        .unwrap_or("<none>");
    let identity_text = identity.source.as_ref().map_or_else(
        || identity.load_status.to_string(),
        |source| {
            format!(
                "source={source}, max_authority={}",
                identity.max_authority.unwrap_or("unknown")
            )
        },
    );
    let authority_text = authority.source_count.map_or_else(
        || authority.load_status.to_string(),
        |count| format!("{count} source(s)"),
    );
    let witness_text = witness
        .messages
        .first()
        .and_then(|message| message.get("message"))
        .and_then(Value::as_str)
        .unwrap_or(witness.load_status);
    format!(
        "dent8 runtime status\n  binary: {}\n  cwd: {}\n  store: {} ({}, events={store_count}, load={})\n  authority: {} ({authority_text})\n  identity: {identity_text}\n  witness: {witness_text}\n",
        std::env::current_exe().ok().map_or_else(
            || "<unknown>".to_string(),
            |path| path.display().to_string()
        ),
        std::env::current_dir().ok().map_or_else(
            || "<unknown>".to_string(),
            |path| path.display().to_string()
        ),
        store.backend,
        store_target,
        store.load_status,
        authority.path,
    )
}

fn env_is_nonempty(name: &str) -> bool {
    nonempty_env(name).is_some()
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn native_scan(arguments: &Value) -> Result<ToolOutput, ToolError> {
    let (agent, dent8_dir, root) = native_args(arguments)?;
    let scan = native::scan_from_options(agent, &dent8_dir, root.as_deref())
        .map_err(ToolError::Invalid)?;
    let structured = mcp_tool_structured(native::native_scan_json(&scan), "native_scan");
    Ok(ToolOutput::new(native::native_scan_text(&scan), structured))
}

fn native_reconcile(path: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
    let (agent, dent8_dir, root) = native_args(arguments)?;
    let clock = arg_read_clock(arguments)?;
    let reconcile = native::reconcile_from_options(agent, &dent8_dir, root.as_deref(), clock, path)
        .map_err(ToolError::Invalid)?;
    let structured = mcp_tool_structured(
        native::native_reconcile_json(&reconcile),
        "native_reconcile",
    );
    Ok(ToolOutput::new(
        native::native_reconcile_text(&reconcile),
        structured,
    ))
}

fn native_args(arguments: &Value) -> Result<(InitAgent, String, Option<String>), ToolError> {
    let agent = arg_agent(arguments)?;
    let dent8_dir = optional_string(arguments, "dir")?.unwrap_or_else(|| ".dent8".to_string());
    let root = optional_string(arguments, "root")?;
    Ok((agent, dent8_dir, root))
}

fn mcp_tool_structured(mut value: Value, tool: &str) -> Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("tool".to_string(), json!(tool));
    }
    value
}

fn list_facts(path: &str, arguments: &Value) -> Result<ToolOutput, ToolError> {
    let include_diagnostics = optional_bool(arguments, "include_diagnostics")?;
    // One store load: resolve every stream's freshness, then partition — visible streams and
    // the count of hidden diagnostic streams — instead of a second full pass just to count.
    let all = crate::ops::op_list_subjects_with_freshness(path, true).map_err(into_tool_error)?;
    let (subjects, hidden): (Vec<_>, Vec<_>) =
        all.into_iter().partition(|(kind, key, predicate, _)| {
            include_diagnostics || !crate::ops::is_diagnostic_fact_stream(kind, key, predicate)
        });
    let hidden_diagnostics_count = hidden.len();
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
                "status": Status::Ok.as_str(),
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
        .map(|(kind, key, predicate, freshness)| {
            json!({
                "uri": resource_uri(kind, key, predicate),
                "subject": { "kind": kind, "key": key },
                "predicate": predicate,
                "freshness": freshness.json_name(),
            })
        })
        .collect();
    let lines: Vec<String> = subjects
        .iter()
        .map(|(kind, key, predicate, freshness)| {
            format!(
                "- {}  ({kind}:{key} {predicate}){}",
                resource_uri(kind, key, predicate),
                freshness.text_marker(),
            )
        })
        .collect();
    let count = facts.len();
    Ok(ToolOutput::new(
        format!("{count} dent8 fact stream(s):\n{}", lines.join("\n")),
        json!({
            "status": Status::Ok.as_str(),
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
    status: Status,
    path: &str,
    context: WriteContext<'_>,
    text: String,
    accepted_events: &[AcceptedEvent],
) -> ToolOutput {
    let mut structured = json!({
        "status": status.as_str(),
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
        crate::ops::ReadClock::default(),
    ) && let Some(object) = structured.as_object_mut()
    {
        object.insert("fact_id".to_string(), json!(receipt.fact_id.as_str()));
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
            fact_value_structured(&receipt.value),
        );
        object.insert("current_receipt".to_string(), receipt_structured(&receipt));
        object.insert("receipt".to_string(), receipt_structured(&receipt));
    }
    ToolOutput::new(text, structured)
}

fn run_write_tool(
    tool: &str,
    status: Status,
    path: &str,
    context: WriteContext<'_>,
    mut op: impl FnMut() -> Result<String, OpError>,
) -> Result<ToolOutput, ToolError> {
    let before = all_events(path)?;
    let text = with_write_retry(&mut op).map_err(into_tool_error)?;
    // `op` has durably committed the write (via `append_events`). The accepted-events list is a
    // receipt enrichment only, so a transient re-read/hash failure here must NOT flip a committed
    // write to `failed` — degrade to an empty list, matching the local CLI path, which returns the
    // accepted receipt from `admit` in memory and never re-reads the store.
    let accepted_events = all_events(path)
        .and_then(|after| accepted_events_since(&after, before.len()))
        .unwrap_or_default();
    Ok(write_output(
        tool,
        status,
        path,
        context,
        text,
        &accepted_events,
    ))
}

fn all_events(path: &str) -> Result<Vec<FactEvent>, ToolError> {
    let store = load_store(path).map_err(ToolError::Failed)?;
    store
        .scan_events(&EventFilter::default())
        .map_err(|error| ToolError::Failed(error.to_string()))
}

fn accepted_events_since(
    events: &[FactEvent],
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
            fact_id: event.fact_id.as_str().to_string(),
            kind: event_kind_name(&event.kind),
            subject_kind: event.subject.kind().to_string(),
            subject_key: event.subject.key().to_string(),
            predicate: event.predicate.as_str().to_string(),
            value: event.value.as_ref().map(fact_value_structured),
            authority: event.authority.level.name(),
            source: event.provenance.source.as_str().to_string(),
            event_hash,
        })
        .collect())
}

struct AcceptedEvent {
    event_id: String,
    fact_id: String,
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
            "fact_id": self.fact_id,
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
        "fact_id": receipt.fact_id.as_str(),
        "subject": {
            "kind": receipt.subject.kind(),
            "key": receipt.subject.key(),
        },
        "predicate": receipt.predicate.as_str(),
        "current_value": fact_value_structured(&receipt.value),
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
        if let Some(subject) = argument_string(arguments, "subject") {
            // Echo the attempted subject back as `{kind, key}` (matching the success shape), even
            // if it is malformed — split on the first `:`, treating a colon-less value as all-kind.
            let (kind, key) = subject.split_once(':').unwrap_or((subject.as_str(), ""));
            object.insert("subject".to_string(), json!({ "kind": kind, "key": key }));
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
    if receipt.lifecycle == FactLifecycle::Contested {
        Status::Contested.as_str()
    } else {
        Status::Ok.as_str()
    }
}

fn receipt_structured(receipt: &IntegrityReceipt) -> Value {
    json!({
        "fact_id": receipt.fact_id.as_str(),
        "subject": {
            "kind": receipt.subject.kind(),
            "key": receipt.subject.key(),
        },
        "predicate": receipt.predicate.as_str(),
        "value": fact_value_structured(&receipt.value),
        "lifecycle": lifecycle_name(receipt.lifecycle),
        "authority": receipt.authority.name(),
        "fresh": receipt.fresh,
        "not_yet_valid": receipt.not_yet_valid,
        "valid_from": receipt.valid_from.map(dent8_core::TimestampMillis::as_unix_millis),
        "expires_at": receipt.expires_at.map(dent8_core::TimestampMillis::as_unix_millis),
        "evidence_count": receipt.evidence_count,
        "corroboration": receipt.corroboration,
        "survived_challenges": receipt.survived_challenges,
        "superseded_by": receipt.superseded_by.as_ref().map(dent8_core::FactId::as_str),
        "contradicted_by": receipt
            .contradicted_by
            .iter()
            .map(dent8_core::FactId::as_str)
            .collect::<Vec<_>>(),
        "replay_position": receipt.replay_position,
        "event_hash": &receipt.event_hash,
        "event_hash_short": short(&receipt.event_hash),
        "chain_verified": receipt.chain_verified,
    })
}

fn lifecycle_name(lifecycle: FactLifecycle) -> &'static str {
    match lifecycle {
        FactLifecycle::Active => "Active",
        FactLifecycle::Contested => "Contested",
        FactLifecycle::Superseded => "Superseded",
        FactLifecycle::Retracted => "Retracted",
        FactLifecycle::Expired => "Expired",
    }
}

fn event_kind_name(kind: &FactEventKind) -> &'static str {
    match kind {
        FactEventKind::Asserted => "Asserted",
        FactEventKind::Superseded { .. } => "Superseded",
        FactEventKind::Contradicted { .. } => "Contradicted",
        FactEventKind::Retracted { .. } => "Retracted",
        FactEventKind::Expired { .. } => "Expired",
        FactEventKind::Reinforced { .. } => "Reinforced",
        FactEventKind::Retrieved { .. } => "Retrieved",
        FactEventKind::UsedInDecision { .. } => "UsedInDecision",
        FactEventKind::ChallengeRejected { .. } => "ChallengeRejected",
    }
}

fn fact_value_structured(value: &FactValue) -> Value {
    match value {
        FactValue::Text(text) => json!({
            "kind": "text",
            "text": text,
            "display": display_value(value),
        }),
        FactValue::Json(canonical) => json!({
            "kind": "json",
            "canonical": canonical.as_str(),
            "json": serde_json::from_str::<Value>(canonical.as_str()).ok(),
            "display": display_value(value),
        }),
        FactValue::Redacted => json!({
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

#[derive(Clone, Debug)]
struct ResolvedWriteMeta {
    authority: AuthorityLevel,
    source: String,
}

/// Resolve provenance metadata for MCP writes. Explicit `authority` / `source` still work; if
/// either is omitted, a signed identity may provide the default (stdio env identity, or the
/// authenticated daemon connection identity). The final values still pass through the same
/// authority-ceiling and signed-identity checks in `op_*`.
fn resolve_write_meta(
    arguments: &Value,
    identity: &WriteIdentity,
) -> Result<ResolvedWriteMeta, ToolError> {
    let authority = optional_authority(arguments)?;
    let source = optional_string(arguments, "source")?;
    if let (Some(authority), Some(source)) = (authority, source.as_deref()) {
        return Ok(ResolvedWriteMeta {
            authority,
            source: source.to_string(),
        });
    }

    let defaults = write_defaults(identity)?;
    let authority = authority
        .or_else(|| defaults.as_ref().map(|defaults| defaults.authority))
        .ok_or_else(|| {
            ToolError::Invalid(
                "missing authority (or configure a signed source grant with DENT8_GRANT)"
                    .to_string(),
            )
        })?;
    let source = source
        .or_else(|| defaults.map(|defaults| defaults.source))
        .ok_or_else(|| {
            ToolError::Invalid(
                "missing source (or configure a signed source grant with DENT8_GRANT)".to_string(),
            )
        })?;

    Ok(ResolvedWriteMeta { authority, source })
}

fn write_defaults(
    identity: &WriteIdentity,
) -> Result<Option<crate::identity::WriteDefaults>, ToolError> {
    match identity {
        WriteIdentity::Env => crate::identity::IdentityContext::from_env()
            .map_err(ToolError::Invalid)?
            .write_defaults()
            .map_err(ToolError::Invalid),
        #[cfg(all(unix, feature = "async-store"))]
        WriteIdentity::Connection(ctx) => ctx.write_defaults().map_err(ToolError::Invalid),
        WriteIdentity::Unauthenticated => Ok(None),
    }
}

fn optional_string(arguments: &Value, name: &str) -> Result<Option<String>, ToolError> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(ToolError::Invalid(format!(
            "optional argument {name} must be a string"
        ))),
    }
}

fn arg_agent(arguments: &Value) -> Result<InitAgent, ToolError> {
    let raw = arg(arguments, "agent")?;
    InitAgent::from_str(&raw, true).map_err(|_| {
        ToolError::Invalid(format!(
            "unknown agent '{raw}' (expected: codex | claude-code | cursor | grok-build | gemini | cascade | hecate)"
        ))
    })
}

/// Parse a `"kind:key"` subject argument into its kind and key, mirroring the CLI's
/// `person:alice` grammar exactly (split on the first `:`, then validate via [`Subject::new`]).
/// `name` is the argument name, so a `derive` basis and the primary subject give distinct errors.
fn arg_subject(arguments: &Value, name: &str) -> Result<(String, String), ToolError> {
    let raw = arg(arguments, name)?;
    let Some((kind, key)) = raw.split_once(':') else {
        return Err(ToolError::Invalid(format!(
            "invalid {name} '{raw}' (expected <kind>:<key>, e.g. person:alice)"
        )));
    };
    dent8_core::Subject::new(kind, key).map_err(|error| {
        ToolError::Invalid(format!(
            "invalid {name} '{raw}' (expected <kind>:<key>): {error}"
        ))
    })?;
    Ok((kind.to_string(), key.to_string()))
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

/// An optional integer (unix millis) argument — `None` when absent, an error when present but
/// not an integer. Powers the valid-time / time-travel arguments (ADR 0016).
fn optional_i64(arguments: &Value, name: &str) -> Result<Option<i64>, ToolError> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or_else(|| {
            ToolError::Invalid(format!(
                "optional argument {name} must be an integer (unix millis)"
            ))
        }),
    }
}

/// The valid-time interval carried by the write tools (ADR 0016).
fn arg_validity(arguments: &Value) -> Result<crate::ops::Validity, ToolError> {
    Ok(crate::ops::Validity {
        from: optional_i64(arguments, "valid_from")?,
        to: optional_i64(arguments, "valid_to")?,
    })
}

/// The time-travel read clock carried by explain/replay (ADR 0016).
fn arg_read_clock(arguments: &Value) -> Result<crate::ops::ReadClock, ToolError> {
    Ok(crate::ops::ReadClock {
        as_of: optional_i64(arguments, "as_of")?,
        valid_at: optional_i64(arguments, "valid_at")?,
    })
}

fn optional_authority(arguments: &Value) -> Result<Option<AuthorityLevel>, ToolError> {
    optional_string(arguments, "authority")?
        .map(|raw| {
            parse_authority(&raw).ok_or_else(|| {
                ToolError::Invalid(format!(
                    "unknown authority '{raw}' (expected: low | medium | high | canonical)"
                ))
            })
        })
        .transpose()
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
        "subject": { "type": "string", "description": "subject as <kind>:<key>, e.g. repo:myproj" },
        "predicate": { "type": "string", "description": "fact name, e.g. database" },
    });
    let write = json!({
        "authority": { "type": "string", "enum": ["low", "medium", "high", "canonical"], "description": "optional authority level; defaults from the active signed grant when omitted" },
        "source": { "type": "string", "description": "optional writing source id; defaults from the active signed grant when omitted" },
    });
    let value = json!({ "value": { "type": "string", "description": "the fact's value" } });
    // Valid-time interval (ADR 0016), on the assertion a write creates. Optional; unix millis.
    let validity = json!({
        "valid_from": { "type": "integer", "description": "valid-time lower bound (unix millis): when the fact starts holding; also anchors TTL freshness" },
        "valid_to": { "type": "integer", "description": "valid-time upper bound (unix millis): when the fact stops holding; past it the fact reads stale like an elapsed TTL" },
    });
    // Time-travel read clock (ADR 0016). Optional; unix millis.
    let clock = json!({
        "as_of": { "type": "integer", "description": "fold only events recorded at or before this instant (unix millis) — the store as it stood then" },
        "valid_at": { "type": "integer", "description": "evaluate freshness/validity at this instant (unix millis) instead of now" },
    });
    let native_common = json!({
        "agent": {
            "type": "string",
            "enum": ["codex", "claude-code", "cursor", "grok-build", "gemini", "cascade", "hecate"],
            "description": "agent profile whose native memory/rules files should be audited"
        },
        "dir": {
            "type": "string",
            "description": "dent8 config directory; defaults to .dent8"
        },
        "root": {
            "type": "string",
            "description": "project root to scan; defaults to the parent of dir when dir is .dent8"
        },
    });
    let native_reconcile_props = merge(&native_common, &clock);
    let valued = merge(&subject, &merge(&value, &write));
    // Every assertion-creating tool takes the validity interval: assert/supersede/contradict
    // via `valued_vt`, and derive via `derive_props` (which merges it in) — matching the CLI's
    // --valid-from/--valid-to on all four (ADR 0016).
    let valued_vt = merge(&valued, &validity);
    let read_props = merge(&subject, &clock);
    let write_only = merge(&subject, &write);
    let basis = json!({
        "basis": { "type": "string", "description": "basis fact's subject as <kind>:<key>, e.g. repo:myproj" },
        "basis_predicate": { "type": "string", "description": "basis fact's predicate" },
    });
    let derive_props = merge(&valued_vt, &basis);
    let read = ["subject", "predicate"];
    let valued_req = ["subject", "predicate", "value"];
    let derive_req = ["subject", "predicate", "value", "basis", "basis_predicate"];
    let write_req = ["subject", "predicate"];
    vec![
        tool(
            "runtime_status",
            "Report the live MCP server runtime: binary, cwd, selected store URL/path, event count, authority, identity, and witness configuration. Call this before trusting project memory when debugging setup.",
            &empty,
            &[],
        ),
        tool(
            "snapshot",
            "Return one stable read/audit payload for debugger and control-plane clients: runtime status, facts, integrity verify, and conflicts.",
            &list_facts,
            &[],
        ),
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
            "native_scan",
            "Read-only audit of provider-native memory/rules files, including guard status and dent8 receipt markers.",
            &native_common,
            &["agent"],
        ),
        tool(
            "native_reconcile",
            "Read-only audit that reconciles dent8:// receipt references in provider-native memory/rules files against current dent8 state. Optional as_of/valid_at time-travel the read.",
            &native_reconcile_props,
            &["agent"],
        ),
        tool(
            "assert",
            "Assert a project fact through the dent8 firewall (provenance + authority + freshness). Rejected if it cannot clear the predicate's policy. Optional valid_from/valid_to set the fact's validity interval.",
            &valued_vt,
            &valued_req,
        ),
        tool(
            "supersede",
            "Revise the believed fact: assert a replacement that must out-rank every believed incumbent (a lower-authority revision is rejected). Optional valid_from/valid_to set the replacement's validity interval.",
            &valued_vt,
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
            "Flag a conflict (dissent): contest the believed fact, keeping both. Not authority-gated, except a canonical fact hard-alarms. Optional valid_from/valid_to set the opposing fact's validity interval.",
            &valued_vt,
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
            "Assert a fact derived from another fact (named by its subject), recording a dependency edge. If that source is later retracted or expired, this derivative is flagged as tainted. Optional valid_from/valid_to set the derived assertion's validity interval.",
            &derive_props,
            &derive_req,
        ),
        tool(
            "explain",
            "Explain the currently believed (or terminal) fact for a subject+predicate, with its integrity receipt. Optional as_of/valid_at time-travel the read.",
            &read_props,
            &read,
        ),
        tool(
            "replay",
            "Replay the full event history for a subject+predicate — why the fact is what it is. Optional as_of/valid_at time-travel the read.",
            &read_props,
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
        "runtime_status" => with_tool_error_schema(name, runtime_status_output_schema()),
        "snapshot" => with_tool_error_schema(name, snapshot_output_schema()),
        "list_facts" => with_tool_error_schema(name, list_facts_output_schema()),
        "verify" => with_tool_error_schema(name, verify_output_schema()),
        "conflicts" => with_tool_error_schema(name, conflicts_output_schema()),
        "native_scan" => with_tool_error_schema(name, native_scan_output_schema()),
        "native_reconcile" => with_tool_error_schema(name, native_reconcile_output_schema()),
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
    // Every emitted `structuredContent` is stamped with `schema_version` by
    // `crate::stamp_schema_version`; advertise it (required, fixed value) on both result arms so
    // the payload still conforms to the tool's `additionalProperties: false` output schema.
    schema.insert(
        "oneOf".to_string(),
        Value::Array(vec![
            with_schema_version_prop(success),
            with_schema_version_prop(tool_error_output_schema(tool)),
        ]),
    );
    Value::Object(schema)
}

/// Add the `schema_version` marker to a top-level result object schema — both its `properties`
/// (as a fixed `const`) and its `required` list — mirroring the runtime stamp applied by
/// [`crate::stamp_schema_version`]. Nested object schemas (e.g. `subject`) are left untouched,
/// since the stamp only lands on the top-level object.
fn with_schema_version_prop(schema: Value) -> Value {
    let Value::Object(mut object) = schema else {
        return schema;
    };
    if let Some(Value::Object(properties)) = object.get_mut("properties") {
        properties.insert(
            "schema_version".to_string(),
            json!({ "const": crate::SCHEMA_VERSION }),
        );
    }
    if let Some(Value::Array(required)) = object.get_mut("required") {
        required.push(json!("schema_version"));
    }
    Value::Object(object)
}

fn runtime_status_output_schema() -> Value {
    object_schema(
        json!({
            "status": { "enum": ["ok", "degraded"] },
            "tool": { "const": "runtime_status" },
            "server": runtime_server_output_schema(),
            "store": runtime_store_output_schema(),
            "authority": runtime_authority_output_schema(),
            "identity": runtime_identity_output_schema(),
            "witness": runtime_witness_output_schema(),
            "env": runtime_env_output_schema(),
        }),
        &[
            "status",
            "tool",
            "server",
            "store",
            "authority",
            "identity",
            "witness",
            "env",
        ],
    )
}

fn snapshot_output_schema() -> Value {
    object_schema(
        json!({
            "status": { "enum": ["ok", "degraded", "integrity_issues", "contested"] },
            "tool": { "const": "snapshot" },
            "runtime_status": runtime_status_output_schema(),
            "facts": {
                "type": "object",
                "additionalProperties": true,
            },
            "verify": {
                "type": "object",
                "additionalProperties": true,
            },
            "conflicts": {
                "type": "object",
                "additionalProperties": true,
            },
            "summary": object_schema(
                json!({
                    "runtime_status": { "enum": ["ok", "degraded"] },
                    "facts": { "type": "integer", "minimum": 0 },
                    "hidden_diagnostics_count": { "type": "integer", "minimum": 0 },
                    "integrity_verified": { "type": "boolean" },
                    "conflicts": { "type": "integer", "minimum": 0 },
                    "include_diagnostics": { "type": "boolean" },
                }),
                &[
                    "runtime_status",
                    "facts",
                    "hidden_diagnostics_count",
                    "integrity_verified",
                    "conflicts",
                    "include_diagnostics",
                ],
            ),
        }),
        &[
            "status",
            "tool",
            "runtime_status",
            "facts",
            "verify",
            "conflicts",
            "summary",
        ],
    )
}

fn runtime_server_output_schema() -> Value {
    object_schema(
        json!({
            "name": { "const": "dent8" },
            "version": { "type": "string" },
            "protocol_version": { "type": "string" },
            "pid": { "type": "integer", "minimum": 0 },
            "binary_path": nullable_string_schema(),
            "cwd": nullable_string_schema(),
        }),
        &[
            "name",
            "version",
            "protocol_version",
            "pid",
            "binary_path",
            "cwd",
        ],
    )
}

fn runtime_store_output_schema() -> Value {
    object_schema(
        json!({
            "backend": { "type": "string" },
            "url": nullable_string_schema(),
            "path": nullable_string_schema(),
            "file_log_path": { "type": "string" },
            "event_count": nullable_integer_schema(),
            "load_status": { "enum": ["ok", "failed"] },
            "load_error": nullable_string_schema(),
        }),
        &[
            "backend",
            "url",
            "path",
            "file_log_path",
            "event_count",
            "load_status",
            "load_error",
        ],
    )
}

fn runtime_authority_output_schema() -> Value {
    object_schema(
        json!({
            "path": { "type": "string" },
            "required": nullable_bool_schema(),
            "configured": { "type": "boolean" },
            "source_count": nullable_integer_schema(),
            "load_status": { "enum": ["ok", "missing", "failed"] },
            "load_error": nullable_string_schema(),
        }),
        &[
            "path",
            "required",
            "configured",
            "source_count",
            "load_status",
            "load_error",
        ],
    )
}

fn runtime_identity_output_schema() -> Value {
    object_schema(
        json!({
            "configured": { "type": "boolean" },
            "source": nullable_string_schema(),
            "max_authority": {
                "anyOf": [
                    authority_schema(),
                    { "type": "null" }
                ]
            },
            "trust_path": nullable_string_schema(),
            "grant_path": nullable_string_schema(),
            "active_grants_path": nullable_string_schema(),
            "identity_key_configured": { "type": "boolean" },
            "load_status": { "enum": ["ok", "unconfigured", "failed"] },
            "load_error": nullable_string_schema(),
        }),
        &[
            "configured",
            "source",
            "max_authority",
            "trust_path",
            "grant_path",
            "active_grants_path",
            "identity_key_configured",
            "load_status",
            "load_error",
        ],
    )
}

fn runtime_witness_output_schema() -> Value {
    object_schema(
        json!({
            "configured": { "type": "boolean" },
            "log_path": nullable_string_schema(),
            "pubkey_path": nullable_string_schema(),
            "signing_key_present": { "type": "boolean" },
            "load_status": { "enum": ["ok", "warn", "failed", "unconfigured"] },
            "messages": {
                "type": "array",
                "items": object_schema(
                    json!({
                        "level": { "enum": ["OK", "WARN", "FAIL"] },
                        "message": { "type": "string" },
                    }),
                    &["level", "message"],
                ),
            },
        }),
        &[
            "configured",
            "log_path",
            "pubkey_path",
            "signing_key_present",
            "load_status",
            "messages",
        ],
    )
}

fn runtime_env_output_schema() -> Value {
    object_schema(
        json!({
            "dent8_store_url_set": { "type": "boolean" },
            "dent8_log_set": { "type": "boolean" },
            "dent8_authority_set": { "type": "boolean" },
            "dent8_grant_set": { "type": "boolean" },
            "dent8_active_grants_set": { "type": "boolean" },
            "dent8_trust_set": { "type": "boolean" },
            "dent8_identity_key_set": { "type": "boolean" },
            "dent8_witness_log_set": { "type": "boolean" },
            "dent8_witness_pubkey_set": { "type": "boolean" },
            "dent8_witness_key_set": { "type": "boolean" },
        }),
        &[
            "dent8_store_url_set",
            "dent8_log_set",
            "dent8_authority_set",
            "dent8_grant_set",
            "dent8_active_grants_set",
            "dent8_trust_set",
            "dent8_identity_key_set",
            "dent8_witness_log_set",
            "dent8_witness_pubkey_set",
            "dent8_witness_key_set",
        ],
    )
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
                        "freshness": { "enum": ["fresh", "stale", "not_yet_valid", "no_longer_believed"] },
                    }),
                    &["uri", "subject", "predicate", "freshness"],
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

fn native_scan_output_schema() -> Value {
    object_schema(
        json!({
            "status": { "const": "ok" },
            "tool": { "const": "native_scan" },
            "agent": native_agent_schema(),
            "root": { "type": "string" },
            "dent8_dir": { "type": "string" },
            "guard": native_guard_output_schema(),
            "files": {
                "type": "array",
                "items": native_file_output_schema(),
            },
            "summary": object_schema(
                json!({
                    "files": { "type": "integer", "minimum": 0 },
                    "with_receipt_markers": { "type": "integer", "minimum": 0 },
                    "without_receipt_markers": { "type": "integer", "minimum": 0 },
                    "guard_protected": { "type": "boolean" },
                }),
                &["files", "with_receipt_markers", "without_receipt_markers", "guard_protected"],
            ),
        }),
        &[
            "status",
            "tool",
            "agent",
            "root",
            "dent8_dir",
            "guard",
            "files",
            "summary",
        ],
    )
}

fn native_reconcile_output_schema() -> Value {
    object_schema(
        json!({
            "status": { "enum": ["ok", "failed"] },
            "tool": { "const": "native_reconcile" },
            "agent": native_agent_schema(),
            "root": { "type": "string" },
            "dent8_dir": { "type": "string" },
            "guard": native_guard_output_schema(),
            "files": {
                "type": "array",
                "items": native_file_output_schema(),
            },
            "references": {
                "type": "array",
                "items": native_reconcile_reference_output_schema(),
            },
            "summary": object_schema(
                json!({
                    "files": { "type": "integer", "minimum": 0 },
                    "files_with_references": { "type": "integer", "minimum": 0 },
                    "unreferenced_files": {
                        "type": "array",
                        "items": { "type": "string" },
                    },
                    "references": { "type": "integer", "minimum": 0 },
                    "ok": { "type": "integer", "minimum": 0 },
                    "failures": { "type": "integer", "minimum": 0 },
                    "stale": { "type": "integer", "minimum": 0 },
                    "not_yet_valid": { "type": "integer", "minimum": 0 },
                    "contested": { "type": "integer", "minimum": 0 },
                    "no_longer_believed": { "type": "integer", "minimum": 0 },
                    "missing": { "type": "integer", "minimum": 0 },
                    "invalid": { "type": "integer", "minimum": 0 },
                    "guard_protected": { "type": "boolean" },
                }),
                &[
                    "files",
                    "files_with_references",
                    "unreferenced_files",
                    "references",
                    "ok",
                    "failures",
                    "stale",
                    "not_yet_valid",
                    "contested",
                    "no_longer_believed",
                    "missing",
                    "invalid",
                    "guard_protected",
                ],
            ),
        }),
        &[
            "status",
            "tool",
            "agent",
            "root",
            "dent8_dir",
            "guard",
            "files",
            "references",
            "summary",
        ],
    )
}

fn native_agent_schema() -> Value {
    json!({ "enum": ["codex", "claude-code", "cursor", "grok-build", "gemini", "cascade", "hecate"] })
}

fn native_guard_output_schema() -> Value {
    object_schema(
        json!({
            "status": { "enum": ["enforced", "advisory", "missing", "unreadable", "unvalidated"] },
            "protected": { "type": "boolean" },
            "path": nullable_string_schema(),
            "message": { "type": "string" },
        }),
        &["status", "protected", "path", "message"],
    )
}

fn native_file_output_schema() -> Value {
    object_schema(
        json!({
            "path": { "type": "string" },
            "relative_path": { "type": "string" },
            "kind": { "type": "string" },
            "size_bytes": { "type": "integer", "minimum": 0 },
            "modified_unix_ms": {
                "anyOf": [
                    { "type": "integer" },
                    { "type": "null" }
                ]
            },
            "sha256": {
                "anyOf": [
                    digest_schema(),
                    { "type": "null" }
                ]
            },
            "has_receipt_marker": { "type": "boolean" },
            "read_error": nullable_string_schema(),
        }),
        &[
            "path",
            "relative_path",
            "kind",
            "size_bytes",
            "modified_unix_ms",
            "sha256",
            "has_receipt_marker",
            "read_error",
        ],
    )
}

fn native_reconcile_reference_output_schema() -> Value {
    object_schema(
        json!({
            "file": object_schema(
                json!({
                    "relative_path": { "type": "string" },
                    "kind": { "type": "string" },
                }),
                &["relative_path", "kind"],
            ),
            "reference": object_schema(
                json!({
                    "uri": { "type": "string" },
                    "line": { "type": "integer", "minimum": 0 },
                    "column": { "type": "integer", "minimum": 0 },
                    "subject": {
                        "anyOf": [
                            subject_output_schema(),
                            { "type": "null" }
                        ]
                    },
                    "predicate": nullable_string_schema(),
                    "parse_error": nullable_string_schema(),
                }),
                &["uri", "line", "column", "subject", "predicate", "parse_error"],
            ),
            "status": {
                "enum": [
                    "ok",
                    "stale",
                    "not_yet_valid",
                    "contested",
                    "no_longer_believed",
                    "missing",
                    "invalid"
                ]
            },
            "ok": { "type": "boolean" },
            "message": { "type": "string" },
            "receipt": {
                "anyOf": [
                    native_receipt_output_schema(),
                    { "type": "null" }
                ]
            },
        }),
        &["file", "reference", "status", "ok", "message", "receipt"],
    )
}

fn native_receipt_output_schema() -> Value {
    object_schema(
        json!({
            "subject": subject_output_schema(),
            "predicate": { "type": "string" },
            "fact_id": { "type": "string" },
            "value": cli_fact_value_output_schema(),
            "lifecycle": {
                "enum": ["Active", "Contested", "Superseded", "Retracted", "Expired"]
            },
            "authority": authority_schema(),
            "fresh": { "type": "boolean" },
            "not_yet_valid": { "type": "boolean" },
            "valid_from": {
                "anyOf": [
                    { "type": "integer" },
                    { "type": "null" }
                ]
            },
            "expires_at": {
                "anyOf": [
                    { "type": "integer" },
                    { "type": "null" }
                ]
            },
            "evidence_count": { "type": "integer", "minimum": 0 },
            "corroboration": { "type": "integer", "minimum": 0 },
            "survived_challenges": { "type": "integer", "minimum": 0 },
            "superseded_by": nullable_string_schema(),
            "contradicted_by": {
                "type": "array",
                "items": { "type": "string" },
            },
            "replay_position": { "type": "integer", "minimum": 0 },
            "event_hash": digest_schema(),
            "chain_verified": { "type": "boolean" },
        }),
        &[
            "subject",
            "predicate",
            "fact_id",
            "value",
            "lifecycle",
            "authority",
            "fresh",
            "not_yet_valid",
            "valid_from",
            "expires_at",
            "evidence_count",
            "corroboration",
            "survived_challenges",
            "superseded_by",
            "contradicted_by",
            "replay_position",
            "event_hash",
            "chain_verified",
        ],
    )
}

fn cli_fact_value_output_schema() -> Value {
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
                    "json": { "type": "string" },
                    "display": { "type": "string" },
                }),
                &["kind", "json", "display"],
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
            "fact_id": { "type": "string" },
            "receipt_kind": { "const": "current_state" },
            "event_hash": digest_schema(),
            "event_hash_kind": { "const": "current_state_latest_event" },
            "event_hash_short": { "type": "string" },
            "replay_position": { "type": "integer", "minimum": 0 },
            "current_value": fact_value_output_schema(),
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
            "fact_id": { "type": "string" },
            "current_value": fact_value_output_schema(),
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
            "fact_id": { "type": "string" },
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
                    fact_value_output_schema(),
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
            "fact_id",
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
            "fact_id": { "type": "string" },
            "subject": subject_output_schema(),
            "predicate": { "type": "string" },
            "value": fact_value_output_schema(),
            "lifecycle": {
                "enum": ["Active", "Contested", "Superseded", "Retracted", "Expired"]
            },
            "authority": authority_schema(),
            "fresh": { "type": "boolean" },
            "not_yet_valid": { "type": "boolean" },
            "valid_from": {
                "anyOf": [
                    { "type": "integer" },
                    { "type": "null" }
                ]
            },
            "expires_at": {
                "anyOf": [
                    { "type": "integer" },
                    { "type": "null" }
                ]
            },
            "evidence_count": { "type": "integer", "minimum": 0 },
            "corroboration": { "type": "integer", "minimum": 0 },
            "survived_challenges": { "type": "integer", "minimum": 0 },
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
            "fact_id",
            "subject",
            "predicate",
            "value",
            "lifecycle",
            "authority",
            "fresh",
            "not_yet_valid",
            "valid_from",
            "expires_at",
            "evidence_count",
            "corroboration",
            "survived_challenges",
            "superseded_by",
            "contradicted_by",
            "replay_position",
            "event_hash",
            "event_hash_short",
            "chain_verified",
        ],
    )
}

fn fact_value_output_schema() -> Value {
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
    json!({ "enum": ["unknown", "low", "medium", "high", "canonical"] })
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

fn nullable_integer_schema() -> Value {
    json!({
        "anyOf": [
            { "type": "integer", "minimum": 0 },
            { "type": "null" }
        ]
    })
}

fn nullable_bool_schema() -> Value {
    json!({
        "anyOf": [
            { "type": "boolean" },
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
    // Stamp `schema_version` so MCP `structuredContent` carries the same shape marker as the
    // CLI's `--output json` (one shared constant across both machine surfaces).
    let structured = crate::stamp_schema_version(structured);
    let structured_text = serde_json::to_string(&structured).unwrap_or_else(|_| "{}".to_string());
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
    use super::{dispatch as raw_dispatch, handle as raw_handle};
    use crate::WriteIdentity;
    use serde_json::{Value, json};

    // The pre-daemon suite exercises the stdio surface, which always carries `WriteIdentity::Env`
    // (Full access). These shims pin that default so those tests read unchanged; the read-only
    // daemon tests call `raw_dispatch`/`raw_handle` with `WriteIdentity::Unauthenticated`.
    fn handle(request: &Value, path: &str) -> Option<Value> {
        raw_handle(request, path, &WriteIdentity::Env)
    }
    fn dispatch(message: &Value, path: &str) -> Option<Value> {
        raw_dispatch(message, path, &WriteIdentity::Env)
    }

    fn temp_log() -> (tempdir::Guard, String) {
        let dir = tempdir::Guard::new();
        let path = format!("{}/log.jsonl", dir.path());
        (dir, path)
    }

    fn native_project(path: &str, contents: &str) -> String {
        let root = std::path::Path::new(path)
            .parent()
            .expect("temp log parent");
        let dent8_dir = root.join(".dent8");
        std::fs::create_dir_all(&dent8_dir).expect("create dent8 dir");
        std::fs::write(root.join("AGENTS.md"), contents).expect("write native memory");
        dent8_dir.to_string_lossy().into_owned()
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
        assert!(instructions.contains("snapshot"));
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
            "subject": "repo:a/b", "predicate": "db x",
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
    #[test]
    fn write_tools_advertise_validity_and_read_tools_advertise_the_clock() {
        let list = json!({ "jsonrpc": "2.0", "id": 9, "method": "tools/list" });
        let tools = handle(&list, "/tmp/unused.jsonl").expect("response")["result"]["tools"]
            .as_array()
            .expect("tools")
            .clone();
        let props = |name: &str| {
            tools
                .iter()
                .find(|t| t["name"] == name)
                .unwrap_or_else(|| panic!("missing {name}"))["inputSchema"]["properties"]
                .clone()
        };
        // Every tool that creates an assertion advertises the validity interval.
        for w in ["assert", "supersede", "contradict", "derive"] {
            assert!(props(w)["valid_from"].is_object(), "{w} lacks valid_from");
            assert!(props(w)["valid_to"].is_object(), "{w} lacks valid_to");
        }
        // …but not the read clock.
        assert!(props("derive")["as_of"].is_null());
        for r in ["explain", "replay"] {
            assert!(props(r)["as_of"].is_object(), "{r} lacks as_of");
            assert!(props(r)["valid_at"].is_object(), "{r} lacks valid_at");
        }
        // Writes do not advertise the read clock, reads do not advertise validity.
        assert!(props("assert")["as_of"].is_null());
        assert!(props("explain")["valid_from"].is_null());
    }

    #[test]
    fn list_surfaces_flag_freshness() {
        let (_dir, path) = temp_log();
        call_tool(
            &path,
            "assert",
            json!({ "subject": "repo:p", "predicate": "db", "value": "postgres", "authority": "high", "source": "u" }),
        );
        call_tool(
            &path,
            "assert",
            json!({ "subject": "repo:p", "predicate": "window", "value": "open", "authority": "high", "source": "u", "valid_from": 1000, "valid_to": 2000 }),
        );

        // list_facts carries a per-stream freshness field (also validated against the schema).
        let result = assert_tool_output_matches_schema(&path, "list_facts", json!({}));
        let facts = result["structuredContent"]["facts"]
            .as_array()
            .expect("facts");
        let fresh_of = |pred: &str| {
            facts
                .iter()
                .find(|f| f["predicate"] == pred)
                .unwrap_or_else(|| panic!("missing {pred}"))["freshness"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(fresh_of("db"), "fresh");
        assert_eq!(fresh_of("window"), "stale");

        // resources/list flags the stale stream in its name.
        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "resources/list" });
        let resources = handle(&req, &path).expect("response")["result"]["resources"]
            .as_array()
            .expect("resources")
            .clone();
        let window = resources
            .iter()
            .find(|r| r["uri"].as_str().unwrap_or("").ends_with("/window"))
            .expect("window resource");
        assert!(
            window["name"].as_str().unwrap().contains("[stale]"),
            "{}",
            window["name"]
        );
    }

    #[test]
    fn mcp_validity_interval_and_time_travel_reads_work() {
        let (_dir, path) = temp_log();
        let (err, _) = call_tool(
            &path,
            "assert",
            json!({
                "subject": "repo:p", "predicate": "db",
                "value": "postgres", "authority": "high", "source": "user:o",
                "valid_from": 1000, "valid_to": 2000,
            }),
        );
        assert!(!err, "assert with validity should be accepted");

        // valid_at inside the window reads fresh; at/after the (inclusive) valid_to it is stale.
        let (_, inside) = call_tool_text(
            &path,
            "explain",
            json!({ "subject": "repo:p", "predicate": "db", "valid_at": 1500 }),
        );
        assert!(!inside.contains("stale"), "{inside}");
        let (_, after) = call_tool_text(
            &path,
            "explain",
            json!({ "subject": "repo:p", "predicate": "db", "valid_at": 2000 }),
        );
        assert!(after.contains("stale"), "{after}");

        // A non-integer valid_at is a tool error, not a silent default.
        let bad = call_tool_result(
            &path,
            "explain",
            json!({ "subject": "repo:p", "predicate": "db", "valid_at": "soon" }),
        );
        assert_eq!(bad["isError"], true);
    }

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
            "subject": "repo:p", "predicate": "database",
            "value": value, "authority": authority, "source": "src",
        })
    }

    fn diagnostic(value: &str, authority: &str) -> Value {
        json!({
            "subject": "diagnostic:doctor",
            "predicate": "dent8.write_check",
            "value": value,
            "authority": authority,
            "source": "src",
        })
    }

    fn hidden_doctor_probe(value: &str, authority: &str) -> Value {
        json!({
            "subject": "person:alice-doctor-hidden",
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
            json!({ "subject": "repo:p", "predicate": "database",
                    "authority": "low", "source": "src" }),
        );
        assert!(err, "low-authority retract must be refused: {text}");

        // A low-authority explicit expiration of a High fact.
        let (_g, path) = temp_log();
        assert!(!call_tool(&path, "assert", database("postgres", "high")).0);
        let (err, text) = call_tool(
            &path,
            "expire",
            json!({ "subject": "repo:p", "predicate": "database",
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
                "subject": "repo:p", "predicate": "database",
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

    #[cfg(all(unix, feature = "async-store"))]
    #[test]
    fn authenticated_connection_defaults_mcp_write_metadata_and_rejects_laundered_source() {
        let (guard, path) = temp_log();
        let identity = test_connection_identity(&guard);
        let write = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "assert", "arguments": {
                "subject": "repo:p", "predicate": "database", "value": "postgres"
            }},
        });
        let accepted = raw_handle(&write, &path, &identity).expect("accepted response");
        assert_eq!(
            accepted["result"]["isError"],
            Value::Bool(false),
            "{accepted}"
        );
        let structured = &accepted["result"]["structuredContent"];
        assert_eq!(structured["source"], "source:codex");
        assert_eq!(structured["authority"], "high");
        assert_eq!(
            structured["accepted_events"][0]["source"], "source:codex",
            "{structured}",
        );

        let laundered = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "assert", "arguments": {
                "subject": "person:alice",
                "predicate": "favorite_drink",
                "value": "tea",
                "source": "source:other"
            }},
        });
        let rejected = raw_handle(&laundered, &path, &identity).expect("rejected response");
        assert_eq!(
            rejected["result"]["isError"],
            Value::Bool(true),
            "{rejected}"
        );
        assert_eq!(rejected["result"]["structuredContent"]["status"], "invalid");
        assert!(
            rejected["result"]["structuredContent"]["error_reason"]
                .as_str()
                .unwrap()
                .contains("grant source"),
            "{rejected}",
        );
    }

    #[test]
    fn a_subject_without_a_colon_is_invalid() {
        let (_guard, path) = temp_log();
        let result = call_tool_result(
            &path,
            "assert",
            json!({
                "subject": "repo", "predicate": "database",
                "value": "postgres", "authority": "high", "source": "owner",
            }),
        );
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["status"], "invalid");
        assert!(
            result["structuredContent"]["error_reason"]
                .as_str()
                .unwrap()
                .contains("<kind>:<key>"),
            "{}",
            result["structuredContent"]["error_reason"]
        );
    }

    #[test]
    fn firewall_refusal_is_structured_as_rejected() {
        let (_guard, path) = temp_log();
        let result = call_tool_result(&path, "assert", database("postgres", "low"));
        assert_eq!(result["isError"], true);
        assert_eq!(result["structuredContent"]["status"], "rejected");
        assert_eq!(result["structuredContent"]["authority"], "low");
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
                "subject": "repo:myproj", "predicate": "database",
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
                "runtime_status",
                "snapshot",
                "list_facts",
                "verify",
                "conflicts",
                "native_scan",
                "native_reconcile",
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
        let assert_required = assert_tool["inputSchema"]["required"]
            .as_array()
            .expect("assert required");
        assert_eq!(
            assert_required,
            json!(["subject", "predicate", "value"])
                .as_array()
                .expect("expected required array"),
        );
        for optional in ["authority", "source"] {
            assert!(
                !assert_required.contains(&json!(optional)),
                "{optional} should be optional when signed identity can default it",
            );
        }
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
        let runtime_tool = tools
            .iter()
            .find(|tool| tool["name"] == "runtime_status")
            .unwrap();
        assert_eq!(
            runtime_tool["outputSchema"]["oneOf"][0]["properties"]["store"]["properties"]["event_count"],
            super::nullable_integer_schema(),
        );
        let snapshot_tool = tools
            .iter()
            .find(|tool| tool["name"] == "snapshot")
            .unwrap();
        assert_eq!(
            snapshot_tool["outputSchema"]["oneOf"][0]["properties"]["status"]["enum"],
            json!(["ok", "degraded", "integrity_issues", "contested"])
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn structured_content_matches_advertised_output_schemas() {
        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(&path, "runtime_status", json!({}));
        assert_tool_output_matches_schema(&path, "snapshot", json!({}));
        assert_tool_output_matches_schema(&path, "list_facts", json!({}));
        assert_tool_output_matches_schema(&path, "verify", json!({}));
        assert_tool_output_matches_schema(&path, "conflicts", json!({}));

        let (_guard, path) = temp_log();
        let dent8_dir = native_project(&path, "repo database receipt: dent8://repo/p/database\n");
        assert_tool_output_matches_schema(
            &path,
            "native_scan",
            json!({ "agent": "codex", "dir": dent8_dir.clone() }),
        );
        assert_tool_output_matches_schema(&path, "assert", database("postgres", "high"));
        assert_tool_output_matches_schema(
            &path,
            "native_reconcile",
            json!({ "agent": "codex", "dir": dent8_dir }),
        );

        let (_guard, path) = temp_log();
        assert_tool_output_matches_schema(&path, "assert", database("postgres", "high"));
        let read_args = json!({
            "subject": "repo:p",
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
                "subject": "repo:p",
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
                "subject": "repo:p",
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
                "subject": "repo:p",
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
                "subject": "service:api",
                "predicate": "datastore",
                "value": "postgres",
                "authority": "high",
                "source": "src",
                "basis": "repo:p", "basis_predicate": "database",
            }),
        );
        assert_tool_output_matches_schema(
            &path,
            "retract",
            json!({
                "subject": "repo:p",
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
                "subject": "repo:p",
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
    fn every_structured_result_carries_the_schema_version() {
        let (_guard, path) = temp_log();
        // A success and a rejection both carry the shared `schema_version` marker, matching the
        // CLI's `--output json`; the mirrored text arm agrees.
        let accepted = call_tool_result(&path, "assert", database("postgres", "high"));
        assert_eq!(
            accepted["structuredContent"]["schema_version"],
            json!(crate::SCHEMA_VERSION)
        );
        let mirrored: Value =
            serde_json::from_str(accepted["content"][1]["text"].as_str().unwrap()).unwrap();
        assert_eq!(mirrored["schema_version"], json!(crate::SCHEMA_VERSION));

        let rejected = call_tool_result(&path, "assert", database("mysql", "low"));
        assert_eq!(rejected["structuredContent"]["status"], "rejected");
        assert_eq!(
            rejected["structuredContent"]["schema_version"],
            json!(crate::SCHEMA_VERSION)
        );
    }

    #[test]
    fn read_audit_tools_are_useful_to_agents() {
        let (_guard, path) = temp_log();
        let (err, text) = call_tool_text(&path, "runtime_status", json!({}));
        assert!(!err, "{text}");
        assert!(text.contains("dent8 runtime status"), "{text}");

        let (err, text) = call_tool_text(&path, "snapshot", json!({}));
        assert!(!err, "{text}");
        assert!(text.contains("dent8 snapshot"), "{text}");

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

        let snapshot = call_tool_result(&path, "snapshot", json!({}));
        assert_eq!(snapshot["structuredContent"]["status"], "ok");
        assert_eq!(snapshot["structuredContent"]["summary"]["facts"], 1);
        assert_eq!(
            snapshot["structuredContent"]["facts"]["facts"][0]["uri"],
            "dent8://repo/p/database"
        );
    }

    #[test]
    fn native_audit_tools_resolve_receipts_against_the_mcp_store() {
        let (_guard, path) = temp_log();
        let dent8_dir = native_project(&path, "Project note: dent8://repo/p/database\n");

        let scan = call_tool_result(
            &path,
            "native_scan",
            json!({ "agent": "codex", "dir": dent8_dir.clone() }),
        );
        assert_eq!(scan["isError"], false, "{scan}");
        assert_eq!(scan["structuredContent"]["status"], "ok");
        assert_eq!(scan["structuredContent"]["summary"]["files"], 1);
        assert_eq!(
            scan["structuredContent"]["files"][0]["has_receipt_marker"],
            true
        );

        let (err, text) = call_tool(&path, "assert", database("postgres", "high"));
        assert!(!err, "{text}");
        let reconcile = call_tool_result(
            &path,
            "native_reconcile",
            json!({ "agent": "codex", "dir": dent8_dir }),
        );
        assert_eq!(reconcile["isError"], false, "{reconcile}");
        assert_eq!(reconcile["structuredContent"]["status"], "ok");
        assert_eq!(reconcile["structuredContent"]["summary"]["references"], 1);
        assert_eq!(reconcile["structuredContent"]["summary"]["ok"], 1);
        assert_eq!(
            reconcile["structuredContent"]["references"][0]["receipt"]["value"]["text"],
            "postgres"
        );
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
                "subject": "service:api", "predicate": "datastore",
                "value": "pg", "authority": "high", "source": "src",
                "basis": "repo:p", "basis_predicate": "database",
            }),
        );
        assert!(!err, "derive should be admitted: {text}");
        let (err, text) = call_tool(
            &path,
            "retract",
            json!({ "subject": "repo:p", "predicate": "database",
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
                "subject": "repo:myproj", "predicate": "database",
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
        // After retracting all believed facts, explain falls back to the terminal fact
        // and reports it as no longer believed (a successful, audited read).
        assert!(!err && text.contains("no longer believed"), "{text}");
    }

    #[test]
    fn assert_then_explain_round_trips_through_tool_calls() {
        let (_guard, path) = temp_log();
        let assert = json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "assert", "arguments": {
                "subject": "repo:myproj", "predicate": "database",
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
                "subject": "repo:myproj", "predicate": "database",
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
                "subject": "repo:myproj", "predicate": "database",
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

    #[test]
    fn readonly_access_serves_reads_but_rejects_writes() {
        let (_guard, path) = temp_log();
        // Seed a fact through the full surface so the read below has content to return.
        let seed = json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": { "name": "assert", "arguments": {
                "subject": "repo:myproj", "predicate": "database",
                "value": "postgres", "authority": "high", "source": "source:owner",
            }},
        });
        assert_eq!(
            raw_handle(&seed, &path, &WriteIdentity::Env).expect("seed")["result"]["isError"],
            Value::Bool(false),
        );

        // A read passes the gate and returns a normal result.
        let list = json!({
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": { "name": "snapshot", "arguments": {} },
        });
        let read = raw_dispatch(&list, &path, &WriteIdentity::Unauthenticated).expect("read reply");
        assert!(read.get("error").is_none(), "read must not error: {read}");
        assert_eq!(read["result"]["isError"], Value::Bool(false));

        let dent8_dir = native_project(
            &path,
            "Project note: dent8://repo/myproj/database should resolve through dent8.\n",
        );
        for name in ["native_scan", "native_reconcile"] {
            let native_read = json!({
                "jsonrpc": "2.0", "id": 3, "method": "tools/call",
                "params": { "name": name, "arguments": {
                    "agent": "codex",
                    "dir": dent8_dir.clone(),
                }},
            });
            let read = raw_dispatch(&native_read, &path, &WriteIdentity::Unauthenticated)
                .expect("native read reply");
            assert!(read.get("error").is_none(), "{name} must not error: {read}");
            assert_eq!(read["result"]["isError"], Value::Bool(false), "{read}");
        }

        // A write is refused *before* dispatch, as a protocol error, so nothing is persisted.
        let write = json!({
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": { "name": "supersede", "arguments": {
                "subject": "repo:myproj", "predicate": "database",
                "value": "mysql", "authority": "high", "source": "source:owner",
            }},
        });
        let refused =
            raw_dispatch(&write, &path, &WriteIdentity::Unauthenticated).expect("write reply");
        assert_eq!(refused["error"]["code"], -32601);
        assert!(
            refused["error"]["message"]
                .as_str()
                .unwrap()
                .contains("proves a source identity"),
            "{refused}",
        );

        // The refusal did not mutate belief: the seeded value still stands under Full.
        let explain = json!({
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": { "name": "explain", "arguments": {
                "subject": "repo:myproj", "predicate": "database",
            }},
        });
        let text = handle(&explain, &path).expect("explain")["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(text.contains("postgres"), "{text}");
    }

    #[cfg(all(unix, feature = "async-store"))]
    #[test]
    fn daemon_socket_path_prefers_explicit_socket() {
        let resolved = super::daemon_socket_path(Some("/run/custom/dent8.sock"));
        assert_eq!(resolved, std::path::PathBuf::from("/run/custom/dent8.sock"));
    }

    #[cfg(all(unix, feature = "async-store"))]
    #[test]
    fn daemon_connection_round_trips_a_read_over_the_socket() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (_guard, path) = temp_log();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (client, server) = tokio::net::UnixStream::pair().unwrap();
            // A socketpair peer runs as this process, so its uid is the daemon uid.
            let uid = server.peer_cred().unwrap().uid();
            let connection = tokio::spawn(super::serve_connection(server, path.clone(), uid));

            let (read_half, mut write_half) = client.into_split();
            let mut lines = BufReader::new(read_half).lines();

            let request = json!({
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": { "name": "verify", "arguments": {} },
            });
            write_half
                .write_all(format!("{request}\n").as_bytes())
                .await
                .unwrap();
            let reply: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert!(reply.get("error").is_none(), "verify should serve: {reply}");
            assert_eq!(reply["result"]["isError"], Value::Bool(false));

            // Closing the client end drives the connection loop to EOF and it returns cleanly.
            drop(write_half);
            drop(lines);
            connection.await.unwrap();
        });
    }

    /// `write_identity` grants `Connection` (writes allowed, attested as that source) only in
    /// the `Authenticated` state; every other state is `Unauthenticated` (read-only). This is
    /// the invariant the gate relies on.
    #[cfg(all(unix, feature = "async-store"))]
    #[test]
    fn write_identity_is_connection_only_when_authenticated() {
        use super::HandshakeState;
        assert!(matches!(
            HandshakeState::Fresh.write_identity(),
            WriteIdentity::Unauthenticated
        ));
        assert!(matches!(
            HandshakeState::Failed.write_identity(),
            WriteIdentity::Unauthenticated
        ));
        let identity = std::sync::Arc::new(test_identity_context(&tempdir::Guard::new()));
        assert!(matches!(
            HandshakeState::Authenticated { identity }.write_identity(),
            WriteIdentity::Connection(_)
        ));
    }

    /// A `dent8/prove` with no prior `dent8/hello` is out of sequence, and it does not demote the
    /// connection: a `Fresh` (or `Authenticated`) state is preserved, not knocked to `Failed`.
    #[cfg(all(unix, feature = "async-store"))]
    #[test]
    fn prove_without_a_challenge_is_out_of_sequence_and_preserves_state() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut session = super::HandshakeState::Fresh;
            let params = json!({ "signature": "00" });
            let response =
                super::handle_prove(&mut session, &json!(1), Some(&params), crate::now_millis())
                    .await;
            assert_eq!(response["error"]["code"], super::SESSION_ERR_SEQUENCE);
            assert!(
                matches!(session, super::HandshakeState::Fresh),
                "a stray prove must not demote the connection state",
            );
        });
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

    #[cfg(all(unix, feature = "async-store"))]
    fn test_connection_identity(dir: &tempdir::Guard) -> WriteIdentity {
        WriteIdentity::Connection(std::sync::Arc::new(test_identity_context(dir)))
    }

    #[cfg(all(unix, feature = "async-store"))]
    fn test_identity_context(dir: &tempdir::Guard) -> crate::identity::IdentityContext {
        let bundle = format!("{}/identity", dir.path());
        let issuer_key = format!("{}/issuer.key", dir.path());
        let output = crate::identity::bootstrap_bundle(
            &bundle,
            "source:codex",
            "owner",
            Some(&issuer_key),
            crate::CliAuthority::High,
            "*",
            None,
        )
        .expect("bootstrap signed identity");
        crate::identity::IdentityContext::from_test_parts(
            output.trust_file.to_string_lossy().into_owned(),
            output.grant_file.to_string_lossy().into_owned(),
            output.source_key_path.to_string_lossy().into_owned(),
        )
    }
}
