use serde_json::{Value, json};

use crate::{
    CliOutput, DaemonServeArgs, DaemonStatusArgs, print_json_stdout_with_code, shell_quote,
    status::Status,
};

pub(crate) fn cmd_daemon_serve(args: &DaemonServeArgs) -> i32 {
    crate::mcp::serve_daemon(args.socket.as_deref())
}

#[cfg(all(unix, feature = "async-store"))]
pub(crate) fn cmd_daemon_status(args: &DaemonStatusArgs, output: CliOutput) -> i32 {
    let socket = daemon_socket(args.socket.as_deref());
    let socket_text = socket.to_string_lossy().into_owned();
    match crate::mcp_client::daemon_runtime_status(&socket_text) {
        Ok(runtime_status) => {
            let auth = daemon_auth_status(&socket_text);
            let runtime_ok = runtime_status["status"] == Status::Ok.as_str();
            let auth_ok = auth["status"] != Status::Failed.as_str();
            let ok = runtime_ok && auth_ok;
            present_status(
                output,
                &DaemonStatusReport {
                    ok,
                    socket: socket_text,
                    runtime_status: Some(runtime_status),
                    auth,
                    error: None,
                },
            )
        }
        Err(error) => present_status(
            output,
            &DaemonStatusReport {
                ok: false,
                socket: socket_text,
                runtime_status: None,
                auth: json!({
                    "status": "skipped",
                    "source": Value::Null,
                    "message": "daemon is not reachable",
                }),
                error: Some(error),
            },
        ),
    }
}

#[cfg(not(all(unix, feature = "async-store")))]
pub(crate) fn cmd_daemon_status(args: &DaemonStatusArgs, output: CliOutput) -> i32 {
    let socket = args
        .socket
        .clone()
        .unwrap_or_else(|| "<unavailable>".to_string());
    present_status(
        output,
        &DaemonStatusReport {
            ok: false,
            socket,
            runtime_status: None,
            auth: json!({
                "status": "skipped",
                "source": Value::Null,
                "message": "daemon status needs a Unix build with a storage backend",
            }),
            error: Some(
                "daemon status needs a Unix build with a storage backend (for example the default sqlite feature)"
                    .to_string(),
            ),
        },
    )
}

#[cfg(all(unix, feature = "async-store"))]
fn daemon_socket(socket: Option<&str>) -> std::path::PathBuf {
    socket
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("DENT8_DAEMON_SOCKET")
                .filter(|value| !value.is_empty())
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| crate::mcp::daemon_socket_path(None))
}

#[cfg(all(unix, feature = "async-store"))]
fn daemon_auth_status(socket: &str) -> Value {
    let grant_set = env_nonempty("DENT8_GRANT");
    let key_set = env_nonempty("DENT8_IDENTITY_KEY");
    if !grant_set && !key_set {
        return json!({
            "status": "skipped",
            "source": Value::Null,
            "message": "DENT8_GRANT and DENT8_IDENTITY_KEY are not set; read-only daemon status checked",
        });
    }
    if !grant_set || !key_set {
        return json!({
            "status": Status::Failed.as_str(),
            "source": Value::Null,
            "message": "both DENT8_GRANT and DENT8_IDENTITY_KEY must be set to authenticate writes",
        });
    }
    match crate::mcp_client::daemon_health(socket) {
        Ok(source) => json!({
            "status": Status::Ok.as_str(),
            "source": source,
            "message": format!("authenticated as {source}"),
        }),
        Err(error) => json!({
            "status": Status::Failed.as_str(),
            "source": Value::Null,
            "message": error,
        }),
    }
}

#[cfg(all(unix, feature = "async-store"))]
fn env_nonempty(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
}

struct DaemonStatusReport {
    ok: bool,
    socket: String,
    runtime_status: Option<Value>,
    auth: Value,
    error: Option<String>,
}

fn present_status(output: CliOutput, report: &DaemonStatusReport) -> i32 {
    let code = i32::from(!report.ok);
    match output {
        CliOutput::Json => print_json_stdout_with_code(&status_json(report), code),
        CliOutput::Text => {
            print!("{}", status_text(report));
            code
        }
    }
}

fn status_json(report: &DaemonStatusReport) -> Value {
    json!({
        "status": if report.ok { Status::Ok.as_str() } else { Status::Failed.as_str() },
        "tool": "daemon status",
        "socket": report.socket,
        "reachable": report.runtime_status.is_some(),
        "start_command": daemon_start_command(&report.socket),
        "runtime_status": report.runtime_status,
        "auth": report.auth,
        "error": report.error,
    })
}

fn status_text(report: &DaemonStatusReport) -> String {
    let mut output = String::from("dent8 daemon status\n");
    status_line(&mut output, "OK", &format!("socket: {}", report.socket));
    if let Some(runtime) = &report.runtime_status {
        let runtime_level = if runtime["status"] == Status::Ok.as_str() {
            "OK"
        } else {
            "FAIL"
        };
        status_line(
            &mut output,
            runtime_level,
            &format!("daemon: reachable ({})", runtime_summary(runtime)),
        );
    } else {
        status_line(
            &mut output,
            "FAIL",
            &format!(
                "daemon: {}; start it with `{}`",
                report.error.as_deref().unwrap_or("not reachable"),
                daemon_start_command(&report.socket),
            ),
        );
    }
    let auth_status = report.auth["status"].as_str().unwrap_or("failed");
    let auth_level = match auth_status {
        "ok" => "OK",
        "skipped" => "SKIP",
        _ => "FAIL",
    };
    status_line(
        &mut output,
        auth_level,
        &format!(
            "auth: {}",
            report.auth["message"].as_str().unwrap_or("unknown")
        ),
    );
    output
}

fn runtime_summary(runtime: &Value) -> String {
    let pid = runtime["server"]["pid"]
        .as_u64()
        .map_or_else(|| "unknown".to_string(), |pid| pid.to_string());
    let backend = runtime["store"]["backend"].as_str().unwrap_or("unknown");
    let events = runtime["store"]["event_count"]
        .as_u64()
        .map_or_else(|| "unknown".to_string(), |events| events.to_string());
    format!("pid={pid}, store={backend}, events={events}")
}

fn status_line(output: &mut String, level: &str, message: &str) {
    output.push_str("  ");
    output.push_str(level);
    output.push_str("  ");
    output.push_str(message);
    output.push('\n');
}

fn daemon_start_command(socket: &str) -> String {
    format!("dent8 daemon serve --socket {}", shell_quote(socket))
}
