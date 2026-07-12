//! `dent8 ui` — the local **read-only debugger/control plane** (ADR 0020, steps 2+3): a
//! stable localhost read/audit API plus a web debugger served straight from the stock
//! binary. No separate write path exists by construction — every endpoint is a GET over
//! the same `op_*`/snapshot code the CLI and MCP use, so the UI can never bypass the
//! firewall (the ADR's hard constraint). The Tauri desktop shell remains the later
//! packaging step; it will wrap this same surface.
//!
//! Transport: a deliberately minimal hand-rolled HTTP/1.1 responder over tokio (the same
//! zero-new-deps discipline as the MCP server). It binds **127.0.0.1 only**, answers GET
//! only, validates the `Host` header against localhost forms (so a DNS-rebound hostname
//! resolving to 127.0.0.1 is refused), and closes the connection after each response. The
//! trust boundary is the OS user — identical to the local daemon (ADR 0018).

use serde_json::{Value, json};

use crate::ops::{OpError, replay_json, replay_outcome, whatif_json};

/// The dashboard page, embedded so the binary is self-contained (no assets, no CDN).
const INDEX_HTML: &str = include_str!("ui/index.html");

/// The largest request head we buffer before refusing (headers only — bodies are ignored).
const MAX_REQUEST_HEAD: usize = 16 * 1024;

/// Run the UI server until interrupted. Returns a process exit code.
pub(crate) fn run_ui(path: &str, port: u16, open_browser: bool) -> i32 {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("ui: tokio runtime: {error}");
            return 1;
        }
    };
    runtime.block_on(async {
        let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => listener,
            Err(error) => {
                eprintln!("ui: cannot bind 127.0.0.1:{port}: {error}");
                return 1;
            }
        };
        let bound = listener.local_addr().map_or(port, |addr| addr.port());
        let url = format!("http://127.0.0.1:{bound}/");
        eprintln!(
            "dent8 ui serving {url} (read-only; bound to localhost — the trust boundary is \
             this OS user). Ctrl-C to stop."
        );
        if open_browser {
            open_in_browser(&url);
        }
        loop {
            let (stream, _peer) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    eprintln!("ui: accept error: {error}");
                    continue;
                }
            };
            let store_path = path.to_string();
            tokio::spawn(async move {
                serve_connection(stream, &store_path).await;
            });
        }
    })
}

/// Best-effort platform browser launch; failure is a note, never an error.
fn open_in_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let launcher = ("open", vec![url]);
    #[cfg(target_os = "windows")]
    let launcher = ("cmd", vec!["/C", "start", "", url]);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let launcher = ("xdg-open", vec![url]);
    if std::process::Command::new(launcher.0)
        .args(launcher.1)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_err()
    {
        eprintln!("ui: could not open a browser automatically — visit {url}");
    }
}

/// Read one request head, dispatch it, write one response, close.
async fn serve_connection(mut stream: tokio::net::TcpStream, store_path: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut head = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let complete = loop {
        match stream.read(&mut chunk).await {
            Ok(read) if read > 0 => {
                head.extend_from_slice(&chunk[..read]);
                if head.windows(4).any(|window| window == b"\r\n\r\n") {
                    break true;
                }
                if head.len() > MAX_REQUEST_HEAD {
                    break false;
                }
            }
            _closed_or_error => break false,
        }
    };
    let response = if complete {
        respond(&String::from_utf8_lossy(&head), store_path).await
    } else {
        http_response(400, "application/json", error_body("malformed request"))
    };
    let _ = stream.write_all(&response).await;
    let _ = stream.shutdown().await;
}

/// Parse the head and produce a full HTTP response.
async fn respond(head: &str, store_path: &str) -> Vec<u8> {
    let Some(request) = Request::parse(head) else {
        return http_response(400, "application/json", error_body("malformed request"));
    };
    if !request.host_is_local() {
        return http_response(
            403,
            "application/json",
            error_body("the dent8 ui only answers localhost origins"),
        );
    }
    if request.method != "GET" {
        return http_response(
            405,
            "application/json",
            error_body("GET only (read-only UI)"),
        );
    }
    if request.path == "/" {
        return http_response(200, "text/html; charset=utf-8", INDEX_HTML.as_bytes());
    }
    // Every API handler re-reads the store through the same ops the CLI uses (blocking
    // I/O, plus their own throwaway runtimes for async backends) — run on the blocking
    // pool exactly like MCP dispatch.
    let store_path = store_path.to_string();
    let outcome = tokio::task::spawn_blocking(move || dispatch_api(&request, &store_path)).await;
    match outcome {
        Ok((status, body)) => http_response(
            status,
            "application/json",
            serde_json::to_string(&body).unwrap_or_default().as_bytes(),
        ),
        Err(_) => http_response(500, "application/json", error_body("handler panicked")),
    }
}

/// Route one API request. Returns (HTTP status, JSON body).
fn dispatch_api(request: &Request, store_path: &str) -> (u16, Value) {
    match request.path.as_str() {
        "/api/snapshot" => {
            let include_diagnostics = request.query_flag("include_diagnostics");
            let (_text, structured) =
                crate::snapshot::snapshot_text_and_json(store_path, include_diagnostics, "ui");
            (200, structured)
        }
        "/api/explain" => match request.subject_and_predicate() {
            Ok((kind, key, predicate)) => match crate::ops::op_explain_receipt(
                store_path,
                &kind,
                &key,
                &predicate,
                crate::ops::ReadClock::default(),
            ) {
                Ok(receipt) => (200, crate::receipt_json("ui explain", &receipt)),
                Err(error) => op_error_response(&error),
            },
            Err(message) => (400, error_json(&message)),
        },
        "/api/replay" => match request.subject_and_predicate() {
            Ok((kind, key, predicate)) => match replay_outcome(
                store_path,
                &kind,
                &key,
                &predicate,
                crate::ops::ReadClock::default(),
            ) {
                Ok(outcome) => (200, replay_json(&outcome)),
                Err(error) => op_error_response(&error),
            },
            Err(message) => (400, error_json(&message)),
        },
        "/api/whatif" => match whatif_request(request, store_path) {
            Ok(body) => (200, body),
            Err((status, body)) => (status, body),
        },
        "/api/activity" => activity_request(request, store_path),
        "/api/doctor" => {
            let report = crate::doctor::doctor_report(&crate::DoctorArgs::read_only());
            (200, crate::doctor::doctor_report_json(&report))
        }
        "/api/native" => native_request(request, store_path),
        "/api/witness" => (200, witness_status()),
        _ => (404, error_json("no such endpoint")),
    }
}

/// Witness coverage + tamper/rollback status — the same read-only `witness::doctor_status()`
/// lines the runtime summary distils to one line, surfaced in full (config, signed-head
/// count, unwitnessed tail, and any `TAMPER`/`ROLLBACK` finding). An unconfigured witness
/// (no `DENT8_WITNESS_LOG` / `DENT8_WITNESS_PUBKEY`) is a single WARN, not an error.
fn witness_status() -> Value {
    let lines = crate::witness::doctor_status();
    let mut ok = Vec::new();
    let mut warn = Vec::new();
    let mut fail = Vec::new();
    for line in &lines {
        let entry = json!({ "level": line.level, "message": line.message });
        match line.level {
            "OK" => ok.push(entry),
            "FAIL" => fail.push(entry),
            _ => warn.push(entry),
        }
    }
    let configured = crate::witness::is_configured();
    json!({
        "status": if fail.is_empty() { "ok" } else { "failed" },
        "tool": "ui witness",
        "configured": configured,
        "ok": fail.is_empty(),
        "summary": { "ok": ok.len(), "warn": warn.len(), "fail": fail.len() },
        "sections": { "ok": ok, "warn": warn, "fail": fail },
    })
}

/// The most recent events across the whole log, newest first — the ADR's "recent
/// accepted/rejected writes" view (rejected supersessions appear as the
/// `fact.challenge_rejected` events recorded on their incumbents).
fn activity_request(request: &Request, store_path: &str) -> (u16, Value) {
    use dent8_store::EventStore as _;
    let limit = request
        .query_first("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(50)
        .min(500);
    let store = match crate::load_store(store_path) {
        Ok(store) => store,
        Err(error) => return (503, error_json(&error)),
    };
    match store.scan_events(&dent8_store::EventFilter::default()) {
        Ok(events) => {
            let total = events.len();
            let recent: Vec<Value> = events
                .iter()
                .rev()
                .take(limit)
                .map(crate::ops::fact_event_json)
                .collect();
            (
                200,
                json!({
                    "status": "ok",
                    "tool": "ui activity",
                    "total_events": total,
                    "events": recent,
                }),
            )
        }
        Err(error) => (503, error_json(&error.to_string())),
    }
}

/// Native memory/rules audit for one agent profile — the same read-only scan/reconcile the
/// CLI and MCP expose.
fn native_request(request: &Request, store_path: &str) -> (u16, Value) {
    use clap::ValueEnum as _;
    let Some(agent_raw) = request.query_first("agent") else {
        return (400, error_json("missing ?agent=<profile>"));
    };
    let Ok(agent) = crate::InitAgent::from_str(&agent_raw, true) else {
        return (
            400,
            error_json(
                "unknown agent profile (expected: codex | claude-code | cursor | grok-build \
                 | gemini | cascade | hecate)",
            ),
        );
    };
    let dir = request
        .query_first("dir")
        .unwrap_or_else(|| ".dent8".to_string());
    match request
        .query_first("mode")
        .unwrap_or_else(|| "scan".to_string())
        .as_str()
    {
        "scan" => match crate::native::scan_from_options(agent, &dir, None) {
            Ok(scan) => (200, crate::native::native_scan_json(&scan)),
            Err(error) => (400, error_json(&error)),
        },
        "reconcile" => match crate::native::reconcile_from_options(
            agent,
            &dir,
            None,
            crate::ops::ReadClock::default(),
            store_path,
        ) {
            Ok(reconcile) => (200, crate::native::native_reconcile_json(&reconcile)),
            Err(error) => (400, error_json(&error)),
        },
        _ => (400, error_json("mode must be scan or reconcile")),
    }
}

/// Build the policy from query params and run the counterfactual.
fn whatif_request(request: &Request, store_path: &str) -> Result<Value, (u16, Value)> {
    let (kind, key, predicate) = request
        .subject_and_predicate()
        .map_err(|message| (400, error_json(&message)))?;
    let mut policy = dent8_core::EpistemicPolicy::identity();
    for source in request.query_all("distrust") {
        let source = dent8_core::SourceId::new(&source)
            .map_err(|error| (400, error_json(&format!("distrust: {error}"))))?;
        policy.distrusted_sources.insert(source);
    }
    if let Some(floor) = request.query_first("authority_floor") {
        policy.authority_floor = crate::parse_authority(&floor).ok_or_else(|| {
            (
                400,
                error_json("authority_floor: expected low|medium|high|canonical"),
            )
        })?;
    }
    if let Some(floor) = request.query_first("confidence_floor") {
        let millis: u16 = floor.parse().map_err(|_| {
            (
                400,
                error_json("confidence_floor: expected millis 0..=1000"),
            )
        })?;
        policy.confidence_floor = dent8_core::Confidence::from_millis(millis)
            .map_err(|error| (400, error_json(&format!("confidence_floor: {error}"))))?;
    }
    if policy.is_identity() {
        return Err((
            400,
            error_json(
                "whatif needs at least one policy knob (distrust, authority_floor, \
                 confidence_floor)",
            ),
        ));
    }
    match crate::ops::op_whatif(store_path, &kind, &key, &predicate, &policy) {
        Ok(outcome) => Ok(whatif_json(&outcome)),
        Err(error) => Err(op_error_response(&error)),
    }
}

fn op_error_response(error: &OpError) -> (u16, Value) {
    match error {
        OpError::Invalid { message, .. } => (400, error_json(message)),
        OpError::Rejected { message, .. } => (404, error_json(message)),
        OpError::Conflict(message) => (503, error_json(message)),
    }
}

fn error_json(message: &str) -> Value {
    json!({ "error": message })
}

fn error_body(message: &str) -> Vec<u8> {
    serde_json::to_string(&error_json(message))
        .unwrap_or_default()
        .into_bytes()
}

fn http_response(status: u16, content_type: &str, body: impl AsRef<[u8]>) -> Vec<u8> {
    let body = body.as_ref();
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// The parts of a request the UI cares about: method, decoded path, query pairs, Host.
#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    query: Vec<(String, String)>,
    host: Option<String>,
}

impl Request {
    fn parse(head: &str) -> Option<Self> {
        let mut lines = head.split("\r\n");
        let request_line = lines.next()?;
        let mut parts = request_line.split_ascii_whitespace();
        let method = parts.next()?.to_string();
        let target = parts.next()?;
        parts.next()?; // HTTP version present
        let (raw_path, raw_query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (target, None),
        };
        let query = raw_query
            .map(|raw| {
                raw.split('&')
                    .filter(|pair| !pair.is_empty())
                    .map(|pair| {
                        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                        (percent_decode(name), percent_decode(value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let host = lines
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.trim().to_string());
        Some(Self {
            method,
            path: percent_decode(raw_path),
            query,
            host,
        })
    }

    /// Only localhost forms may talk to the UI (refuses DNS-rebound hostnames).
    fn host_is_local(&self) -> bool {
        let Some(host) = &self.host else {
            return false;
        };
        let name = host
            .rsplit_once(':')
            .map_or(host.as_str(), |(name, _port)| name);
        matches!(name, "localhost" | "127.0.0.1" | "[::1]")
    }

    fn query_first(&self, name: &str) -> Option<String> {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }

    fn query_all(&self, name: &str) -> Vec<String> {
        self.query
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .collect()
    }

    fn query_flag(&self, name: &str) -> bool {
        self.query_first(name)
            .is_some_and(|value| !matches!(value.as_str(), "" | "0" | "false" | "no"))
    }

    /// The shared `subject=<kind>:<key>&predicate=<p>` pair every fact endpoint takes.
    fn subject_and_predicate(&self) -> Result<(String, String, String), String> {
        let subject = self
            .query_first("subject")
            .ok_or("missing ?subject=<kind>:<key>")?;
        let predicate = self
            .query_first("predicate")
            .ok_or("missing &predicate=<name>")?;
        let parsed: crate::CliSubject = subject.parse()?;
        Ok((parsed.kind, parsed.key, predicate))
    }
}

/// Minimal percent-decoding (plus `+` → space) for query strings. Operates on bytes so a
/// stray `%` before a multibyte character cannot split a codepoint.
fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let decoded = if bytes[index] == b'%' && index + 3 <= bytes.len() {
            std::str::from_utf8(&bytes[index + 1..index + 3])
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
        } else {
            None
        };
        match (bytes[index], decoded) {
            (_, Some(byte)) => {
                out.push(byte);
                index += 3;
            }
            (b'+', None) => {
                out.push(b' ');
                index += 1;
            }
            (byte, None) => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::{Request, percent_decode};

    #[test]
    fn parses_a_request_line_with_query_and_host() {
        let request = Request::parse(
            "GET /api/explain?subject=repo%3Ap&predicate=database&distrust=a&distrust=b \
             HTTP/1.1\r\nHost: 127.0.0.1:3368\r\nAccept: */*\r\n\r\n",
        )
        .expect("parses");
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/api/explain");
        assert_eq!(request.query_first("subject").as_deref(), Some("repo:p"));
        assert_eq!(request.query_all("distrust"), ["a", "b"]);
        assert!(request.host_is_local());
        let (kind, key, predicate) = request.subject_and_predicate().expect("subject");
        assert_eq!(
            (kind.as_str(), key.as_str(), predicate.as_str()),
            ("repo", "p", "database")
        );
    }

    #[test]
    fn refuses_non_local_hosts() {
        let request =
            Request::parse("GET / HTTP/1.1\r\nHost: rebind.example.com\r\n\r\n").expect("parses");
        assert!(!request.host_is_local());
        let missing = Request::parse("GET / HTTP/1.1\r\n\r\n").expect("parses");
        assert!(!missing.host_is_local());
        let v6 = Request::parse("GET / HTTP/1.1\r\nHost: [::1]:3368\r\n\r\n").expect("parses");
        assert!(v6.host_is_local());
    }

    #[test]
    fn percent_decoding_handles_escapes_plus_and_junk() {
        assert_eq!(percent_decode("repo%3Adent8"), "repo:dent8");
        assert_eq!(percent_decode("a+b"), "a b");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("bad%zzescape"), "bad%zzescape");
    }
}
