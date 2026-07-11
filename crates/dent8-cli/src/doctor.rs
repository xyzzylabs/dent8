//! `dent8 doctor`: the adoption/diagnosis surface. Checks the binary, store, authority,
//! signed identity, witness, MCP availability, and (opt-in) a trusted write-check probe;
//! `--agent` validates a generated bundle + its installed MCP config, smokes the exact
//! installed command over stdio JSON-RPC with a bounded timeout, and `--repair` refreshes
//! stale generated env/config via the machinery in [`crate::setup`].

use std::{
    io::{self, Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    str::FromStr,
    time::{Duration, Instant},
};

use dent8_core::AuthorityLevel;

use crate::identity;
use crate::setup::{
    LocalMcpBinary, append_mcp_install_transport_flags, install_mcp_config_prepared,
    is_executable_file, local_mcp_binary, local_mcp_build_command,
    local_mcp_missing_target_message, mcp_server_args, mcp_transport_from_args,
    render_local_mcp_wrapper,
};
use crate::witness;
use crate::{
    CliOutput, DEFAULT_MCP_SMOKE_TIMEOUT, DoctorArgs, InitAgent, absolute_path,
    authority_registry_path, authority_required, first_line, load_authority_registry_at,
    load_store, log_path, mcp_config, now_millis, ops, print_json_stdout, shell_quote, store_url,
    verify_log,
};

pub(crate) fn cmd_doctor(args: &DoctorArgs, output: CliOutput) -> i32 {
    let report = doctor_report(args);
    match output {
        CliOutput::Text => print!("{}", report.output),
        CliOutput::Json => {
            print_json_stdout(&doctor_report_json(&report));
        }
    }
    i32::from(!report.ok)
}

pub(crate) struct DoctorReport {
    output: String,
    ok: bool,
    mcp_runtime: Option<DoctorMcpRuntime>,
    agents: Vec<DoctorAgentRun>,
}

pub(crate) struct DoctorMcpRuntime {
    status: &'static str,
    message: String,
    runtime_status: Option<serde_json::Value>,
}

pub(crate) struct DoctorAgentRun {
    agent: InitAgent,
    status: &'static str,
    report: DoctorReport,
}

impl DoctorReport {
    fn new(output: String, ok: bool) -> Self {
        Self {
            output,
            ok,
            mcp_runtime: None,
            agents: Vec::new(),
        }
    }

    fn with_mcp_runtime(mut self, mcp_runtime: Option<DoctorMcpRuntime>) -> Self {
        self.mcp_runtime = mcp_runtime;
        self
    }

    fn with_agents(mut self, agents: Vec<DoctorAgentRun>) -> Self {
        self.agents = agents;
        self
    }
}

pub(crate) fn doctor_report_json(report: &DoctorReport) -> serde_json::Value {
    let checks = report
        .output
        .lines()
        .filter_map(parse_doctor_report_line)
        .collect::<Vec<_>>();
    let mut ok = Vec::new();
    let mut warn = Vec::new();
    let mut fail = Vec::new();
    let mut skip = Vec::new();
    for check in &checks {
        match check.level {
            "OK" => ok.push(doctor_check_json(check)),
            "WARN" => warn.push(doctor_check_json(check)),
            "FAIL" => fail.push(doctor_check_json(check)),
            "SKIP" => skip.push(doctor_check_json(check)),
            _ => {}
        }
    }
    let mut payload = serde_json::json!({
        "status": if report.ok { "ok" } else { "failed" },
        "tool": "doctor",
        "ok": report.ok,
        "summary": {
            "ok": ok.len(),
            "warn": warn.len(),
            "fail": fail.len(),
            "skip": skip.len(),
        },
        "sections": {
            "ok": ok,
            "warn": warn,
            "fail": fail,
            "skip": skip,
        },
        "checks": checks.iter().map(doctor_check_json).collect::<Vec<_>>(),
    });
    if let Some(mcp_runtime) = &report.mcp_runtime {
        payload["mcp_runtime"] = serde_json::json!({
            "status": mcp_runtime.status,
            "message": mcp_runtime.message,
            "runtime_status": mcp_runtime.runtime_status,
        });
    }
    if !report.agents.is_empty() {
        payload["agents"] = serde_json::Value::Array(
            report
                .agents
                .iter()
                .map(doctor_agent_run_json)
                .collect::<Vec<_>>(),
        );
    }
    payload
}

pub(crate) fn doctor_agent_run_json(agent: &DoctorAgentRun) -> serde_json::Value {
    serde_json::json!({
        "agent": agent.agent.cli_name(),
        "source": agent.agent.source(),
        "status": agent.status,
        "ok": agent.report.ok,
        "report": doctor_report_json(&agent.report),
    })
}

pub(crate) struct DoctorCheck<'a> {
    level: &'a str,
    message: &'a str,
}

pub(crate) fn parse_doctor_report_line(line: &str) -> Option<DoctorCheck<'_>> {
    let line = line.strip_prefix("  ")?;
    let (level, message) = line.split_once("  ")?;
    Some(DoctorCheck { level, message })
}

pub(crate) fn doctor_check_json(check: &DoctorCheck<'_>) -> serde_json::Value {
    serde_json::json!({
        "status": check.level.to_ascii_lowercase(),
        "level": check.level,
        "message": check.message,
    })
}

pub(crate) fn doctor_report(args: &DoctorArgs) -> DoctorReport {
    if args.all_agents {
        return doctor_all_agents_report(args);
    }
    if let Some(agent) = args.agent {
        return doctor_agent_report(args, agent);
    }

    let mut output = String::from("dent8 doctor\n");
    let mut ok = true;
    let source = args.source.as_deref().unwrap_or("source:local");

    doctor_line(
        &mut output,
        "OK",
        &format!(
            "binary: {}",
            std::env::current_exe().map_or_else(
                |error| format!("unknown ({error})"),
                |path| path.display().to_string(),
            )
        ),
    );

    if let Err(error) = doctor_store(&mut output) {
        ok = false;
        doctor_line(&mut output, "FAIL", &error);
    }
    if let Err(error) = doctor_authority(&mut output, source) {
        ok = false;
        doctor_line(&mut output, "FAIL", &error);
    }
    if !doctor_identity(&mut output, source) {
        ok = false;
    }
    if !doctor_witness(&mut output) {
        ok = false;
    }
    match verify_log(&log_path()) {
        Ok(message) => doctor_line(
            &mut output,
            "OK",
            &format!("verify: {}", first_line(&message)),
        ),
        Err(error) => {
            ok = false;
            doctor_line(&mut output, "FAIL", &format!("verify: {error}"));
        }
    }

    doctor_line(
        &mut output,
        "OK",
        "mcp: `dent8 mcp serve` is available over stdio",
    );

    if !doctor_daemon(&mut output) {
        ok = false;
    }

    if args.write_check {
        match doctor_write_check(source) {
            Ok(message) => doctor_line(&mut output, "OK", &message),
            Err(error) => {
                ok = false;
                doctor_line(&mut output, "FAIL", &format!("write-check: {error}"));
            }
        }
    } else {
        doctor_line(
            &mut output,
            "SKIP",
            "write-check: not requested (pass `--write-check` to run assert -> reject -> explain)",
        );
    }

    DoctorReport::new(output, ok)
}

pub(crate) fn doctor_all_agents_report(args: &DoctorArgs) -> DoctorReport {
    let mut output = String::from("dent8 doctor\n");
    let dir = std::path::PathBuf::from(&args.dir);
    let dir = match absolute_path(&dir) {
        Ok(dir) => dir,
        Err(error) => {
            doctor_line(&mut output, "FAIL", &error);
            return DoctorReport::new(output, false);
        }
    };
    doctor_line(
        &mut output,
        "OK",
        &format!("all-agents: dir: {}", dir.display()),
    );

    let mut agents = Vec::new();
    let mut checked = 0usize;
    let mut skipped = 0usize;
    let mut failed = 0usize;
    let mut agent_output = String::new();
    for &agent in InitAgent::all() {
        let run = doctor_all_agent_run(args, agent, &dir);
        match run.status {
            "ok" => checked += 1,
            "failed" => {
                checked += 1;
                failed += 1;
            }
            "skipped" => skipped += 1,
            _ => {}
        }
        agent_output.push_str(agent.cli_name());
        agent_output.push_str(":\n");
        agent_output.push_str(doctor_report_body(&run.report));
        agents.push(run);
    }

    let ok = failed == 0;
    let level = if ok { "OK" } else { "FAIL" };
    doctor_line(
        &mut output,
        level,
        &format!("all-agents: {checked} checked, {skipped} skipped, {failed} failed"),
    );
    output.push_str(&agent_output);
    DoctorReport::new(output, ok).with_agents(agents)
}

pub(crate) fn doctor_all_agent_run(
    args: &DoctorArgs,
    agent: InitAgent,
    dir: &std::path::Path,
) -> DoctorAgentRun {
    if let Some(reason) = doctor_all_agent_skip_reason(agent, dir) {
        let message = format!("{}: {reason}", agent.cli_name());
        return DoctorAgentRun {
            agent,
            status: "skipped",
            report: doctor_skip_report(&message),
        };
    }

    let agent_args = DoctorArgs {
        write_check: args.write_check,
        source: None,
        agent: Some(agent),
        all_agents: false,
        dir: dir.to_string_lossy().into_owned(),
        mcp_config: None,
        mcp_command: None,
        mcp_local_bin: false,
        repair: false,
    };
    let report = doctor_agent_report(&agent_args, agent);
    let status = if report.ok { "ok" } else { "failed" };
    DoctorAgentRun {
        agent,
        status,
        report,
    }
}

pub(crate) fn doctor_all_agent_skip_reason(
    agent: InitAgent,
    dir: &std::path::Path,
) -> Option<String> {
    let identity_env = match identity::identity_env_path_for_source(dir, agent.source()) {
        Ok(path) => path,
        Err(error) => return Some(format!("identity env path: {error}")),
    };
    if !identity_env.exists() {
        return Some(format!(
            "not installed (missing source identity env {})",
            identity_env.display()
        ));
    }

    let config_path = match mcp_config::default_project_config_path(agent, dir) {
        Ok(Some(path)) => path,
        Ok(None) => {
            return Some(
                "no default MCP config path; run `dent8 doctor --agent hecate --mcp-config PATH`"
                    .to_string(),
            );
        }
        Err(error) => return Some(error),
    };
    if !config_path.exists() {
        return Some(format!(
            "MCP config not installed at {}",
            config_path.display()
        ));
    }
    None
}

pub(crate) fn doctor_skip_report(message: &str) -> DoctorReport {
    let mut output = String::from("dent8 doctor\n");
    doctor_line(&mut output, "SKIP", message);
    DoctorReport::new(output, true)
}

pub(crate) fn doctor_report_body(report: &DoctorReport) -> &str {
    report
        .output
        .strip_prefix("dent8 doctor\n")
        .unwrap_or(&report.output)
}

/// Probe the local daemon (ADR 0018) when `DENT8_DAEMON_SOCKET` is set: connect and complete the
/// session-challenge handshake without writing, confirming the daemon is reachable and that this
/// caller's identity authenticates. A no-op when the var is unset (writes go to the local store).
#[cfg(all(unix, feature = "async-store"))]
fn doctor_daemon(output: &mut String) -> bool {
    let socket = std::env::var("DENT8_DAEMON_SOCKET")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let Some(socket) = socket else {
        doctor_line(
            output,
            "SKIP",
            "daemon: DENT8_DAEMON_SOCKET not set (CLI writes go to the local store)",
        );
        return true;
    };
    match crate::mcp_client::daemon_health(&socket) {
        Ok(source) => {
            doctor_line(
                output,
                "OK",
                &format!("daemon: reachable at {socket}, authenticated as {source}"),
            );
            true
        }
        Err(error) => {
            doctor_line(output, "FAIL", &format!("daemon: {error}"));
            false
        }
    }
}

/// Builds without the daemon client (non-Unix, or no `async-store`/`identity`) cannot route to a
/// daemon, so there is nothing to probe.
#[cfg(not(all(unix, feature = "async-store")))]
#[allow(clippy::ptr_arg)] // signature mirrors the daemon-capable variant
fn doctor_daemon(_output: &mut String) -> bool {
    true
}

pub(crate) fn doctor_agent_report(args: &DoctorArgs, agent: InitAgent) -> DoctorReport {
    let mut output = String::from("dent8 doctor\n");
    let mut ok = true;
    let dir = std::path::PathBuf::from(&args.dir);
    let dir = match absolute_path(&dir) {
        Ok(dir) => dir,
        Err(error) => {
            doctor_line(&mut output, "FAIL", &error);
            return DoctorReport::new(output, false);
        }
    };
    let source = agent.source();
    doctor_line(
        &mut output,
        "OK",
        &format!(
            "agent: {} ({source}); dir: {}",
            agent.cli_name(),
            dir.display()
        ),
    );

    if args.repair && !repair_agent_setup(&mut output, args, agent, &dir) {
        return DoctorReport::new(output, false);
    }

    let bundle_env =
        match load_doctor_agent_env(&mut output, agent, &dir, args.mcp_config.as_deref()) {
            Ok(env) => env,
            Err(error) => {
                doctor_line(&mut output, "FAIL", &error);
                return DoctorReport::new(output, false);
            }
        };

    let installed = match load_doctor_installed_server(&mut output, args, agent, &dir) {
        Ok(installed) => installed,
        Err(error) => {
            doctor_line(&mut output, "FAIL", &error);
            return DoctorReport::new(output, false);
        }
    };
    doctor_agent_bypass_guard(&mut output, agent, &dir);
    doctor_agent_native_scan(&mut output, agent, &dir);

    let expected_command = expected_doctor_mcp_command(args, &dir);
    match validate_installed_agent_config(&bundle_env, &installed, expected_command.as_deref()) {
        Ok(message) => doctor_line(&mut output, "OK", &message),
        Err(error) => {
            ok = false;
            let command = expected_command.as_deref().unwrap_or(&installed.command);
            let hint = agent_mcp_config_error_with_repair_hint(
                &error,
                agent,
                &dir,
                args.mcp_config.as_deref(),
                Some(command),
            );
            doctor_line(&mut output, "FAIL", &format!("agent mcp config: {hint}"));
        }
    }

    if !doctor_local_mcp_binary(
        &mut output,
        &installed,
        agent,
        &dir,
        args.mcp_config.as_deref(),
        &bundle_env,
        source,
    ) {
        ok = false;
    }

    ok &= doctor_agent_self_check(&mut output, &installed, source, !args.write_check);

    let (mcp_smoke_ok, mcp_runtime) = doctor_agent_mcp_smoke(&mut output, &installed, source);
    ok &= mcp_smoke_ok;

    if args.write_check && mcp_smoke_ok {
        ok &= doctor_agent_mcp_write_check(&mut output, &installed, source);
    } else if args.write_check {
        doctor_line(
            &mut output,
            "SKIP",
            "mcp write-check: skipped because MCP smoke failed",
        );
    }

    DoctorReport::new(output, ok).with_mcp_runtime(mcp_runtime)
}

pub(crate) fn doctor_agent_self_check(
    output: &mut String,
    installed: &mcp_config::InstalledServer,
    source: &str,
    include_write_check_skip: bool,
) -> bool {
    match run_doctor_with_env(source, false, &installed.env, include_write_check_skip) {
        Ok(child) => {
            output.push_str(&child);
            true
        }
        Err(error) => {
            doctor_line(output, "FAIL", &error);
            false
        }
    }
}

pub(crate) fn doctor_agent_mcp_smoke(
    output: &mut String,
    installed: &mcp_config::InstalledServer,
    source: &str,
) -> (bool, Option<DoctorMcpRuntime>) {
    match mcp_smoke_with_server(installed, source) {
        Ok(smoke) => {
            doctor_line(output, "OK", &smoke.message);
            doctor_agent_mcp_version(output, &smoke.runtime_status);
            (
                true,
                Some(DoctorMcpRuntime {
                    status: "ok",
                    message: smoke.message,
                    runtime_status: Some(smoke.runtime_status),
                }),
            )
        }
        Err(error) => {
            let message = format!("mcp smoke: {}", error.message);
            doctor_line(output, "FAIL", &message);
            (
                false,
                Some(DoctorMcpRuntime {
                    status: "failed",
                    message,
                    runtime_status: error.runtime_status,
                }),
            )
        }
    }
}

pub(crate) fn doctor_agent_mcp_version(output: &mut String, runtime_status: &serde_json::Value) {
    let current = env!("CARGO_PKG_VERSION");
    let version = runtime_status["server"]["version"].as_str();
    let binary = runtime_status["server"]["binary_path"].as_str();

    match (version, binary) {
        (Some(version), Some(binary)) if version == current => doctor_line(
            output,
            "OK",
            &format!("mcp server version: {version} ({binary})"),
        ),
        (Some(version), Some(binary)) => doctor_line(
            output,
            "WARN",
            &format!(
                "mcp server version: {version} ({binary}); doctor is {current} — reinstall or repair the agent MCP config if this is stale"
            ),
        ),
        (Some(version), None) if version == current => {
            doctor_line(output, "OK", &format!("mcp server version: {version}"));
        }
        (Some(version), None) => doctor_line(
            output,
            "WARN",
            &format!(
                "mcp server version: {version}; doctor is {current} — reinstall or repair the agent MCP config if this is stale"
            ),
        ),
        _ => doctor_line(
            output,
            "WARN",
            "mcp server version: unavailable from runtime_status",
        ),
    }
}

pub(crate) fn doctor_agent_mcp_write_check(
    output: &mut String,
    installed: &mcp_config::InstalledServer,
    source: &str,
) -> bool {
    match mcp_write_check_with_server(installed, source) {
        Ok(message) => {
            doctor_line(output, "OK", &message);
            true
        }
        Err(error) => {
            doctor_line(output, "FAIL", &format!("mcp write-check: {error}"));
            false
        }
    }
}

#[cfg(all(unix, feature = "async-store"))]
pub(crate) fn doctor_agent_mcp_proxy_preflight(
    server: &mcp_config::InstalledServer,
    expected_source: &str,
) -> Result<Option<String>, String> {
    let (uses_proxy, explicit_socket) = mcp_transport_from_args(&server.args);
    if !uses_proxy {
        return Ok(None);
    }
    let socket = explicit_socket
        .or_else(|| installed_env_value(server, "DENT8_DAEMON_SOCKET"))
        .map(std::path::PathBuf::from)
        .or_else(|| {
            std::env::var_os("DENT8_DAEMON_SOCKET")
                .filter(|value| !value.is_empty())
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(|| crate::mcp::daemon_socket_path(None));
    let socket_text = socket.to_string_lossy().into_owned();
    match crate::mcp_client::daemon_health_with_env(&socket_text, &server.env) {
        Ok(source) if source == expected_source => Ok(Some(format!(
            "daemon proxy: reachable at {socket_text}, authenticated as {source}"
        ))),
        Ok(source) => Err(format!(
            "daemon proxy identity mismatch at {socket_text}: expected {expected_source}, authenticated as {source}"
        )),
        Err(error) => Err(format!(
            "daemon proxy: {error}; start it with `{}` using the same .dent8/env and identity env, or reinstall with `dent8 mcp install --agent <profile> --daemon-socket PATH`",
            daemon_start_command(&socket),
        )),
    }
}

#[cfg(not(all(unix, feature = "async-store")))]
pub(crate) fn doctor_agent_mcp_proxy_preflight(
    server: &mcp_config::InstalledServer,
    _expected_source: &str,
) -> Result<Option<String>, String> {
    let (uses_proxy, _) = mcp_transport_from_args(&server.args);
    if uses_proxy {
        return Err(
            "daemon proxy config needs a Unix build with a storage backend; reinstall without --use-daemon or run a daemon-capable dent8 binary"
                .to_string(),
        );
    }
    Ok(None)
}

#[cfg(all(unix, feature = "async-store"))]
fn daemon_start_command(socket: &std::path::Path) -> String {
    format!(
        "dent8 daemon serve --socket {}",
        shell_quote(&socket.to_string_lossy())
    )
}

pub(crate) fn doctor_agent_bypass_guard(
    output: &mut String,
    agent: InitAgent,
    dir: &std::path::Path,
) {
    match inspect_agent_bypass_guard(agent, dir) {
        BypassGuardStatus::Enforced(path) => doctor_line(
            output,
            "OK",
            &format!(
                "bypass guard: native-memory guard is enforced in {}",
                path.display()
            ),
        ),
        BypassGuardStatus::Advisory(path) => doctor_line(
            output,
            "WARN",
            &format!(
                "bypass guard: native-memory guard exists in {} but is not enforced; set DENT8_HOOK_ENFORCE=1",
                path.display()
            ),
        ),
        BypassGuardStatus::Missing(path) => doctor_line(
            output,
            "WARN",
            &format!(
                "bypass guard: no native-memory guard found at {}; install the profile from examples/agent-hooks/{}",
                path.display(),
                agent.cli_name()
            ),
        ),
        BypassGuardStatus::Unreadable(path, error) => doctor_line(
            output,
            "WARN",
            &format!(
                "bypass guard: could not inspect {}: {error}",
                path.display()
            ),
        ),
        BypassGuardStatus::Unvalidated(reason) => {
            doctor_line(output, "WARN", &format!("bypass guard: {reason}"));
        }
    }
}

pub(crate) fn doctor_agent_native_scan(
    output: &mut String,
    agent: InitAgent,
    dir: &std::path::Path,
) {
    let root = match crate::native::native_scan_root_for_dir(dir) {
        Ok(root) => root,
        Err(error) => {
            doctor_line(
                output,
                "WARN",
                &format!("native memory scan: could not resolve project root: {error}"),
            );
            return;
        }
    };
    match crate::native::scan_agent_native_memory(agent, dir, &root) {
        Ok(scan) if scan.files.is_empty() => {
            doctor_line(
                output,
                "OK",
                "native memory scan: no native memory/rules files found",
            );
        }
        Ok(scan) => {
            let receipt_count = scan
                .files
                .iter()
                .filter(|file| file.has_receipt_marker)
                .count();
            let message = format!(
                "native memory scan: {} file(s) found ({} with dent8 receipt markers); {}",
                scan.files.len(),
                receipt_count,
                scan.guard.message,
            );
            if scan.guard.protected {
                doctor_line(output, "OK", &message);
            } else {
                doctor_line(output, "WARN", &message);
            }
        }
        Err(error) => {
            doctor_line(output, "WARN", &format!("native memory scan: {error}"));
        }
    }
}

pub(crate) enum BypassGuardStatus {
    Enforced(std::path::PathBuf),
    Advisory(std::path::PathBuf),
    Missing(std::path::PathBuf),
    Unreadable(std::path::PathBuf, String),
    Unvalidated(String),
}

pub(crate) fn inspect_agent_bypass_guard(
    agent: InitAgent,
    dir: &std::path::Path,
) -> BypassGuardStatus {
    let Some(path) = agent_hook_config_path(agent, dir) else {
        return BypassGuardStatus::Unvalidated(agent_hook_unvalidated_message(agent, dir));
    };
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return BypassGuardStatus::Missing(path);
        }
        Err(error) => return BypassGuardStatus::Unreadable(path, error.to_string()),
    };
    let parsed = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(parsed) => parsed,
        Err(error) => return BypassGuardStatus::Unreadable(path, format!("invalid JSON: {error}")),
    };
    let mut strings = Vec::new();
    collect_json_strings(&parsed, &mut strings);
    let has_guard = strings
        .iter()
        .any(|text| text.contains("dent8 hook native-memory-guard"));
    let has_write_mode = strings
        .iter()
        .any(|text| text.contains("DENT8_HOOK_MODE=guard-native-memory-write"));
    let enforced = strings.iter().any(|text| {
        let text = text.to_ascii_lowercase();
        text.contains("dent8_hook_enforce=1")
            || text.contains("dent8_hook_enforce=true")
            || text.contains("dent8_hook_enforce=yes")
            || text.contains("dent8_hook_enforce=on")
    });
    if has_guard && has_write_mode && enforced {
        BypassGuardStatus::Enforced(path)
    } else if has_guard {
        BypassGuardStatus::Advisory(path)
    } else {
        BypassGuardStatus::Missing(path)
    }
}

pub(crate) fn agent_hook_config_path(
    agent: InitAgent,
    dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let root = doctor_project_root_for(dir)?;
    match agent {
        InitAgent::Codex => Some(root.join(".codex/hooks.json")),
        InitAgent::ClaudeCode => Some(root.join(".claude/settings.json")),
        InitAgent::Gemini => Some(root.join(".gemini/settings.json")),
        InitAgent::Cascade => Some(root.join(".windsurf/hooks.json")),
        // Project-scoped only (not ~/.cursor or ~/.grok) — same dogfood rule as MCP.
        InitAgent::Cursor => Some(root.join(".cursor/hooks.json")),
        InitAgent::GrokBuild => Some(root.join(".grok/hooks/dent8.json")),
        InitAgent::Hecate => None,
    }
}

pub(crate) fn doctor_project_root_for(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    if dir.file_name().is_some_and(|name| name == ".dent8") {
        return dir.parent().map(std::path::Path::to_path_buf);
    }
    None
}

pub(crate) fn agent_hook_unvalidated_message(agent: InitAgent, dir: &std::path::Path) -> String {
    if doctor_project_root_for(dir).is_none() {
        return format!(
            "cannot infer a native-memory hook config path from --dir {}; use a .dent8 directory or inspect examples/agent-hooks/{} manually",
            dir.display(),
            agent.cli_name()
        );
    }
    match agent {
        InitAgent::Hecate => {
            "Hecate distributes policy to child agents; inspect the supervised child agent hook profile rather than one Hecate-local file".to_string()
        }
        InitAgent::Codex
        | InitAgent::ClaudeCode
        | InitAgent::Gemini
        | InitAgent::Cascade
        | InitAgent::Cursor
        | InitAgent::GrokBuild => {
            "native-memory hook profile is not validated for this agent".to_string()
        }
    }
}

pub(crate) fn collect_json_strings<'a>(value: &'a serde_json::Value, strings: &mut Vec<&'a str>) {
    match value {
        serde_json::Value::String(text) => strings.push(text),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_strings(item, strings);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_json_strings(item, strings);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

pub(crate) fn expected_doctor_mcp_command(
    args: &DoctorArgs,
    dir: &std::path::Path,
) -> Option<String> {
    if args.mcp_local_bin {
        return local_mcp_binary(dir)
            .ok()
            .map(|local| local.wrapper.to_string_lossy().into_owned());
    }
    args.mcp_command.clone()
}

pub(crate) fn load_doctor_agent_env(
    output: &mut String,
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
) -> Result<std::collections::BTreeMap<String, String>, String> {
    match mcp_config::load_agent_env(dir, agent) {
        Ok(env) => {
            doctor_line(
                output,
                "OK",
                ".dent8 env: agent bundle is complete and source-bound",
            );
            Ok(env)
        }
        Err(error) => {
            let hint = agent_env_error_with_repair_hint(&error, agent, dir, config);
            Err(format!("agent env: {hint}"))
        }
    }
}

pub(crate) fn load_doctor_installed_server(
    output: &mut String,
    args: &DoctorArgs,
    agent: InitAgent,
    dir: &std::path::Path,
) -> Result<mcp_config::InstalledServer, String> {
    match mcp_config::load_installed_server(
        agent,
        dir,
        args.mcp_config.as_deref().map(std::path::Path::new),
    ) {
        Ok(installed) => {
            doctor_line(
                output,
                "OK",
                &format!(
                    "agent mcp config: {} command={} args={:?}{}",
                    installed.path.display(),
                    installed.command,
                    installed.args,
                    installed
                        .cwd
                        .as_ref()
                        .map(|cwd| format!(" cwd={}", cwd.display()))
                        .unwrap_or_default()
                ),
            );
            Ok(installed)
        }
        Err(error) => {
            let expected = expected_doctor_mcp_command(args, dir);
            let hint = agent_mcp_config_error_with_repair_hint(
                &error,
                agent,
                dir,
                args.mcp_config.as_deref(),
                expected.as_deref(),
            );
            Err(format!("agent mcp config: {hint}"))
        }
    }
}

pub(crate) fn repair_agent_setup(
    output: &mut String,
    args: &DoctorArgs,
    agent: InitAgent,
    dir: &std::path::Path,
) -> bool {
    match repair_agent_identity_env(agent, dir) {
        Ok(message) => doctor_line(
            output,
            "OK",
            &format!("agent env repair: {}", first_line(&message)),
        ),
        Err(error) => {
            doctor_line(output, "FAIL", &format!("agent env repair: {error}"));
            return false;
        }
    }

    match repair_agent_mcp_config(args, agent, dir) {
        Ok(message) => doctor_line(
            output,
            "OK",
            &format!("agent mcp config repair: {}", first_line(&message)),
        ),
        Err(error) => {
            doctor_line(output, "FAIL", &format!("agent mcp config repair: {error}"));
            return false;
        }
    }

    true
}

pub(crate) fn repair_agent_identity_env(
    agent: InitAgent,
    dir: &std::path::Path,
) -> Result<String, String> {
    identity::repair_env_bundle(&dir.to_string_lossy(), agent.source())
}

pub(crate) fn repair_agent_mcp_config(
    args: &DoctorArgs,
    agent: InitAgent,
    dir: &std::path::Path,
) -> Result<String, String> {
    let use_local_bin = args.mcp_local_bin || installed_agent_uses_local_bin(args, agent, dir);
    let command = if use_local_bin {
        None
    } else {
        repair_agent_mcp_command(args, agent, dir)
    };
    install_mcp_config_prepared(
        agent,
        dir,
        args.mcp_config.as_deref(),
        command.as_deref(),
        use_local_bin,
        repair_agent_mcp_args(args, agent, dir),
        mcp_config::InstallMode::Write,
    )
}

pub(crate) fn repair_agent_mcp_command(
    args: &DoctorArgs,
    agent: InitAgent,
    dir: &std::path::Path,
) -> Option<String> {
    args.mcp_command.clone().or_else(|| {
        mcp_config::load_installed_server(
            agent,
            dir,
            args.mcp_config.as_deref().map(std::path::Path::new),
        )
        .ok()
        .map(|installed| installed.command)
    })
}

pub(crate) fn installed_agent_uses_local_bin(
    args: &DoctorArgs,
    agent: InitAgent,
    dir: &std::path::Path,
) -> bool {
    let Ok(local) = local_mcp_binary(dir) else {
        return false;
    };
    mcp_config::load_installed_server(
        agent,
        dir,
        args.mcp_config.as_deref().map(std::path::Path::new),
    )
    .ok()
    .is_some_and(|installed| std::path::Path::new(&installed.command) == local.wrapper)
}

pub(crate) fn agent_env_error_with_repair_hint(
    error: &str,
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
) -> String {
    if error.contains("generated dent8 env is missing DENT8_ACTIVE_GRANTS") {
        format!(
            "{error}; repair with `{}` or repair only the generated identity env with \
             `dent8 identity repair-env --dir {} --source {}`",
            doctor_agent_repair_command(agent, dir, config, None),
            shell_quote(&dir.to_string_lossy()),
            agent.source()
        )
    } else {
        error.to_string()
    }
}

pub(crate) fn repair_agent_mcp_args(
    args: &DoctorArgs,
    agent: InitAgent,
    dir: &std::path::Path,
) -> Vec<String> {
    mcp_config::load_installed_server(
        agent,
        dir,
        args.mcp_config.as_deref().map(std::path::Path::new),
    )
    .ok()
    .map_or_else(|| mcp_server_args(false, None), |installed| installed.args)
}

pub(crate) fn agent_mcp_config_error_with_repair_hint(
    error: &str,
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
    command: Option<&str>,
) -> String {
    format!(
        "{error}; repair with `{}` or rerun `{}`",
        mcp_install_repair_command(agent, dir, config, command),
        doctor_agent_repair_command(agent, dir, config, command)
    )
}

pub(crate) fn mcp_install_repair_command(
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
    command: Option<&str>,
) -> String {
    let mut command_line = format!(
        "dent8 mcp install --agent {} --dir {}",
        agent.cli_name(),
        shell_quote(&dir.to_string_lossy())
    );
    if let Some(config) = config {
        command_line.push_str(" --config ");
        command_line.push_str(&shell_quote(config));
    }
    if let Some(command) = command {
        if command_is_local_mcp_wrapper(dir, command) {
            command_line.push_str(" --local-bin");
        } else {
            command_line.push_str(" --command ");
            command_line.push_str(&shell_quote(command));
        }
    }
    if let Ok(installed) =
        mcp_config::load_installed_server(agent, dir, config.map(std::path::Path::new))
    {
        let (use_daemon, daemon_socket) = mcp_transport_from_args(&installed.args);
        append_mcp_install_transport_flags(&mut command_line, use_daemon, daemon_socket);
    }
    command_line
}

pub(crate) fn doctor_agent_repair_command(
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
    command: Option<&str>,
) -> String {
    let mut command_line = format!(
        "dent8 doctor --agent {} --dir {} --repair",
        agent.cli_name(),
        shell_quote(&dir.to_string_lossy())
    );
    if let Some(config) = config {
        command_line.push_str(" --mcp-config ");
        command_line.push_str(&shell_quote(config));
    }
    if let Some(command) = command {
        if command_is_local_mcp_wrapper(dir, command) {
            command_line.push_str(" --mcp-local-bin");
        } else {
            command_line.push_str(" --mcp-command ");
            command_line.push_str(&shell_quote(command));
        }
    }
    command_line
}

pub(crate) fn command_is_local_mcp_wrapper(dir: &std::path::Path, command: &str) -> bool {
    local_mcp_binary(dir)
        .ok()
        .is_some_and(|local| std::path::Path::new(command) == local.wrapper)
}

pub(crate) fn validate_installed_agent_config(
    bundle_env: &std::collections::BTreeMap<String, String>,
    installed: &mcp_config::InstalledServer,
    expected_command: Option<&str>,
) -> Result<String, String> {
    if let Some(expected) = expected_command
        && installed.command != expected
    {
        return Err(format!(
            "installed command is {}, expected {expected}",
            installed.command
        ));
    }

    let mismatches = bundle_env
        .iter()
        .filter_map(|(key, expected)| match installed.env.get(key) {
            Some(actual) if actual == expected => None,
            Some(actual) => Some(format!("{key}={actual} (expected {expected})")),
            None => Some(format!("{key} is missing")),
        })
        .collect::<Vec<_>>();
    if !mismatches.is_empty() {
        return Err(format!(
            "installed env does not match generated bundle: {}",
            mismatches.join("; ")
        ));
    }

    let mut message =
        "agent mcp config: up to date (installed env matches generated bundle)".to_string();
    if let Some(expected) = expected_command {
        message.push_str("; command matches ");
        message.push_str(expected);
    }
    Ok(message)
}

pub(crate) fn doctor_local_mcp_binary(
    output: &mut String,
    installed: &mcp_config::InstalledServer,
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
    env: &std::collections::BTreeMap<String, String>,
    source: &str,
) -> bool {
    let Ok(local) = local_mcp_binary(dir) else {
        return true;
    };
    if std::path::Path::new(&installed.command) != local.wrapper {
        return true;
    }

    let wrapper_ok = doctor_local_mcp_wrapper(output, &local, agent, dir, config);
    let target_ok = doctor_local_mcp_target(output, &local);
    let mut ok = wrapper_ok && target_ok;

    if !ok {
        return ok;
    }

    if local_mcp_command_loads_store(installed, env, source) {
        doctor_line(
            output,
            "OK",
            "local MCP binary: installed command can load the configured store",
        );
    } else {
        ok = false;
        doctor_line(
            output,
            "FAIL",
            "local MCP binary: installed command cannot load the configured store; rebuild with the backend feature required by DENT8_STORE_URL",
        );
    }

    if env.contains_key("DENT8_WITNESS_LOG") || env.contains_key("DENT8_WITNESS_PUBKEY") {
        if local_mcp_command_has_witness(installed, env) {
            doctor_line(
                output,
                "OK",
                "local MCP binary: witness writer checks are available",
            );
        } else {
            ok = false;
            doctor_line(
                output,
                "FAIL",
                "local MCP binary: witness checks failed; rebuild with `--features sqlite`",
            );
        }
    }

    ok
}

pub(crate) fn doctor_local_mcp_wrapper(
    output: &mut String,
    local: &LocalMcpBinary,
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
) -> bool {
    let expected = render_local_mcp_wrapper(local);
    match std::fs::read_to_string(&local.wrapper) {
        Ok(actual) if actual == expected => {
            doctor_line(
                output,
                "OK",
                &format!(
                    "local MCP wrapper: {} (matches dent8 template)",
                    local.wrapper.display()
                ),
            );
            true
        }
        Ok(_) => {
            let wrapper_command = local.wrapper.to_string_lossy();
            let repair = doctor_agent_repair_command(agent, dir, config, Some(&wrapper_command));
            doctor_line(
                output,
                "FAIL",
                &format!(
                    "local MCP wrapper: {} is stale; repair with `{repair}`",
                    local.wrapper.display(),
                ),
            );
            false
        }
        Err(error) => {
            doctor_line(
                output,
                "FAIL",
                &format!(
                    "local MCP wrapper: cannot read {}: {error}",
                    local.wrapper.display()
                ),
            );
            false
        }
    }
}

pub(crate) fn doctor_local_mcp_target(output: &mut String, local: &LocalMcpBinary) -> bool {
    if !is_executable_file(&local.target) {
        doctor_line(output, "FAIL", &local_mcp_missing_target_message(local));
        return false;
    }
    doctor_line(
        output,
        "OK",
        &format!("local MCP binary: {}", local.target.display()),
    );
    if local_mcp_target_is_stale(local) {
        doctor_line(
            output,
            "WARN",
            &format!(
                "local MCP binary: {} is older than workspace Rust sources; rebuild with `{}`",
                local.target.display(),
                local_mcp_build_command(local)
            ),
        );
    }
    true
}

pub(crate) fn local_mcp_command_loads_store(
    installed: &mcp_config::InstalledServer,
    env: &std::collections::BTreeMap<String, String>,
    source: &str,
) -> bool {
    let mut command = Command::new(&installed.command);
    command.args(["doctor", "--source", source]);
    apply_dent8_env(&mut command, env);
    if let Some(cwd) = installed.cwd.as_ref() {
        command.current_dir(cwd);
    }
    command.output().is_ok_and(|output| output.status.success())
}

pub(crate) fn local_mcp_command_has_witness(
    installed: &mcp_config::InstalledServer,
    env: &std::collections::BTreeMap<String, String>,
) -> bool {
    let mut command = Command::new(&installed.command);
    command.args(["witness", "doctor", "writer"]);
    apply_dent8_env(&mut command, env);
    if let Some(cwd) = installed.cwd.as_ref() {
        command.current_dir(cwd);
    }
    command.output().is_ok_and(|output| output.status.success())
}

pub(crate) fn local_mcp_target_is_stale(local: &LocalMcpBinary) -> bool {
    let Ok(target_mtime) = std::fs::metadata(&local.target).and_then(|meta| meta.modified()) else {
        return false;
    };
    latest_workspace_rust_mtime(&local.repo).is_some_and(|latest| target_mtime < latest)
}

pub(crate) fn latest_workspace_rust_mtime(repo: &std::path::Path) -> Option<std::time::SystemTime> {
    let mut latest = None;
    for path in [
        repo.join("Cargo.toml"),
        repo.join("Cargo.lock"),
        repo.join("crates"),
    ] {
        collect_latest_rust_mtime(&path, &mut latest);
    }
    latest
}

pub(crate) fn collect_latest_rust_mtime(
    path: &std::path::Path,
    latest: &mut Option<std::time::SystemTime>,
) {
    let Ok(metadata) = std::fs::metadata(path) else {
        return;
    };
    if metadata.is_file() {
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            return;
        };
        if (path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("rs"))
            || name == "Cargo.toml"
            || name == "Cargo.lock")
            && let Ok(modified) = metadata.modified()
            && latest.is_none_or(|current| current < modified)
        {
            *latest = Some(modified);
        }
        return;
    }
    if !metadata.is_dir() {
        return;
    }
    if is_non_runtime_rust_dir(path) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        collect_latest_rust_mtime(&entry.path(), latest);
    }
}

fn is_non_runtime_rust_dir(path: &std::path::Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "tests" | "benches" | "examples"))
}

pub(crate) fn run_doctor_with_env(
    source: &str,
    write_check: bool,
    env: &std::collections::BTreeMap<String, String>,
    include_write_check_skip: bool,
) -> Result<String, String> {
    let mut command = Command::new(
        std::env::current_exe().map_err(|error| format!("doctor: current exe: {error}"))?,
    );
    command.args(["doctor", "--source", source]);
    if write_check {
        command.arg("--write-check");
    }
    apply_dent8_env(&mut command, env);
    let output = command
        .output()
        .map_err(|error| format!("doctor subprocess failed to start: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "doctor subprocess failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut forwarded = String::new();
    for line in stdout
        .lines()
        .skip_while(|line| line.trim() == "dent8 doctor")
    {
        if !include_write_check_skip
            && (line.contains("write-check: skipped")
                || line.contains("write-check: not requested"))
        {
            continue;
        }
        forwarded.push_str(line);
        forwarded.push('\n');
    }
    Ok(forwarded)
}

pub(crate) struct McpSmokeReport {
    message: String,
    runtime_status: serde_json::Value,
}

pub(crate) struct McpSmokeError {
    message: String,
    runtime_status: Option<serde_json::Value>,
}

pub(crate) fn mcp_smoke_with_server(
    server: &mcp_config::InstalledServer,
    expected_source: &str,
) -> Result<McpSmokeReport, McpSmokeError> {
    let proxy_note = doctor_agent_mcp_proxy_preflight(server, expected_source)
        .map_err(McpSmokeError::without_runtime)?;
    let responses = mcp_exchange_with_server(
        server,
        &[
            mcp_initialize_request(1),
            mcp_initialized_notification(),
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
            }),
            mcp_tool_call(3, "runtime_status", &serde_json::json!({})),
        ],
        "mcp smoke",
    )
    .map_err(McpSmokeError::without_runtime)?;
    if responses.len() != 3 {
        return Err(McpSmokeError::without_runtime(format!(
            "expected 3 JSON-RPC responses, got {}",
            responses.len()
        )));
    }
    if responses[0]["result"]["serverInfo"]["name"] != "dent8" {
        return Err(McpSmokeError::without_runtime(
            "initialize did not return dent8 serverInfo".to_string(),
        ));
    }
    let tools = responses[1]["result"]["tools"].as_array().ok_or_else(|| {
        McpSmokeError::without_runtime("tools/list did not return a tools array".to_string())
    })?;
    for expected in ["runtime_status", "assert", "explain", "verify"] {
        if !tools
            .iter()
            .any(|tool| tool["name"].as_str() == Some(expected))
        {
            return Err(McpSmokeError::without_runtime(format!(
                "tools/list is missing {expected}"
            )));
        }
    }
    let runtime_status = mcp_runtime_status_result(&responses[2], server, expected_source)
        .map_err(|error| {
            McpSmokeError::new(
                error,
                mcp_runtime_status_payload(&responses[2]).ok().cloned(),
            )
        })?;
    let backend = runtime_status["store"]["backend"]
        .as_str()
        .unwrap_or("unknown");
    let events = runtime_status["store"]["event_count"]
        .as_u64()
        .map_or_else(|| "unknown".to_string(), |count| count.to_string());
    let proxy_suffix = proxy_note.map_or_else(String::new, |note| format!(", {note}"));
    Ok(McpSmokeReport {
        message: format!(
            "mcp smoke: initialize + tools/list + runtime_status OK ({} tool(s), store={backend}, events={events}{proxy_suffix})",
            tools.len(),
        ),
        runtime_status: runtime_status.clone(),
    })
}

impl McpSmokeError {
    fn new(message: String, runtime_status: Option<serde_json::Value>) -> Self {
        Self {
            message,
            runtime_status,
        }
    }

    fn without_runtime(message: String) -> Self {
        Self::new(message, None)
    }
}

pub(crate) fn mcp_runtime_status_result<'a>(
    response: &'a serde_json::Value,
    server: &mcp_config::InstalledServer,
    expected_source: &str,
) -> Result<&'a serde_json::Value, String> {
    let structured = mcp_runtime_status_payload(response)?;
    if structured["status"] != "ok" {
        return Err(format!(
            "runtime_status reported degraded runtime: {structured}"
        ));
    }
    validate_mcp_runtime_store(server, structured)?;
    validate_mcp_runtime_identity(structured, expected_source)?;
    Ok(structured)
}

pub(crate) fn mcp_runtime_status_payload(
    response: &serde_json::Value,
) -> Result<&serde_json::Value, String> {
    let result = mcp_tool_result(response, "runtime_status")?;
    if result["isError"].as_bool() != Some(false) {
        return Err(format!("runtime_status returned a tool error: {result}"));
    }
    let structured = result
        .get("structuredContent")
        .ok_or_else(|| format!("runtime_status missing structuredContent: {result}"))?;
    if structured["tool"] != "runtime_status" {
        return Err(format!(
            "runtime_status returned wrong tool payload: {structured}"
        ));
    }
    Ok(structured)
}

pub(crate) fn validate_mcp_runtime_store(
    server: &mcp_config::InstalledServer,
    runtime_status: &serde_json::Value,
) -> Result<(), String> {
    let store = &runtime_status["store"];
    let actual_backend = store["backend"].as_str().unwrap_or("unknown");
    if let Some(url) = installed_env_value(server, "DENT8_STORE_URL") {
        let expected_backend = url.split_once(':').map_or(url, |(scheme, _)| scheme);
        if actual_backend != expected_backend {
            return Err(format!(
                "runtime_status store backend mismatch: expected {expected_backend} from DENT8_STORE_URL, got {actual_backend}"
            ));
        }
        let expected_url = redact_runtime_url(url);
        let actual_url = store["url"].as_str().unwrap_or("<missing>");
        if actual_url != expected_url {
            return Err(format!(
                "runtime_status store URL mismatch: expected {expected_url}, got {actual_url}"
            ));
        }
        if let Some(expected_path) = url.strip_prefix("sqlite://") {
            let actual_path = store["path"].as_str().unwrap_or("<missing>");
            if actual_path != expected_path {
                return Err(format!(
                    "runtime_status sqlite path mismatch: expected {expected_path}, got {actual_path}"
                ));
            }
        }
        return Ok(());
    }
    if let Some(expected_log) = installed_env_value(server, "DENT8_LOG") {
        if actual_backend != "file" {
            return Err(format!(
                "runtime_status store backend mismatch: expected file from DENT8_LOG, got {actual_backend}"
            ));
        }
        let actual_log = store["file_log_path"].as_str().unwrap_or("<missing>");
        if actual_log != expected_log {
            return Err(format!(
                "runtime_status file log mismatch: expected {expected_log}, got {actual_log}"
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_mcp_runtime_identity(
    runtime_status: &serde_json::Value,
    expected_source: &str,
) -> Result<(), String> {
    let actual_source = runtime_status["identity"]["source"]
        .as_str()
        .unwrap_or("<missing>");
    if actual_source != expected_source {
        return Err(format!(
            "runtime_status identity source mismatch: expected {expected_source}, got {actual_source}"
        ));
    }
    Ok(())
}

pub(crate) fn installed_env_value<'a>(
    server: &'a mcp_config::InstalledServer,
    key: &str,
) -> Option<&'a str> {
    server
        .env
        .get(key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
}

pub(crate) fn redact_runtime_url(url: &str) -> String {
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

/// The JSON-RPC request sequence for an MCP write-check: initialize, the `ok` assert at the
/// source ceiling, an optional below-ceiling supersede (present iff `reject` is `Some`),
/// explain, verify, and the self-cleanup retract. The `initialized` notification draws no
/// response, so the caller expects `requests.len() - 1` responses.
fn mcp_write_check_requests(
    probe: &WriteCheckProbe,
    source: &str,
    reject: Option<AuthorityLevel>,
) -> Vec<serde_json::Value> {
    let ceiling_name = probe.ceiling.name();
    let mut requests = vec![
        mcp_initialize_request(1),
        mcp_initialized_notification(),
        mcp_tool_call(
            2,
            "assert",
            &mcp_value_fact_args(probe, "ok", ceiling_name, source),
        ),
    ];
    let mut next_id = 3;
    if let Some(reject_authority) = reject {
        requests.push(mcp_tool_call(
            next_id,
            "supersede",
            &mcp_value_fact_args(probe, "tampered", reject_authority.name(), source),
        ));
        next_id += 1;
    }
    requests.push(mcp_tool_call(
        next_id,
        "explain",
        &mcp_read_fact_args(probe),
    ));
    next_id += 1;
    requests.push(mcp_tool_call(next_id, "verify", &serde_json::json!({})));
    next_id += 1;
    requests.push(mcp_tool_call(
        next_id,
        "retract",
        &mcp_retract_args(probe, ceiling_name, source),
    ));
    requests
}

pub(crate) fn mcp_write_check_with_server(
    server: &mcp_config::InstalledServer,
    source: &str,
) -> Result<String, String> {
    let run_id = format!(
        "doctor-mcp-{}-{}",
        std::process::id(),
        now_millis().as_unix_millis()
    );
    // Resolve the probe target against the *installed server's* env — its authority
    // registry and signed grant, not the doctor process's — since the write runs there.
    let registry_path = server
        .env
        .get("DENT8_AUTHORITY")
        .cloned()
        .unwrap_or_else(authority_registry_path);
    let identity_scope = server
        .env
        .get("DENT8_GRANT")
        .and_then(|path| identity::grant_scope_for_source(path, source));
    let identity_ceiling = server
        .env
        .get("DENT8_GRANT")
        .and_then(|path| identity::grant_authority_for_source(path, source));
    let probe = WriteCheckProbe::for_source(
        source,
        &run_id,
        &registry_path,
        identity_scope,
        identity_ceiling,
    );
    let ceiling_name = probe.ceiling.name();

    // Assert at the source's own ceiling; supersede one level below it (a genuine rejection)
    // when there is a level below; retract the probe fact so nothing is left believed. The
    // reject sub-check is skipped when the ceiling is already the minimum level.
    let reject = authority_below(probe.ceiling);
    let requests = mcp_write_check_requests(&probe, source, reject);

    let responses = mcp_exchange_with_server(server, &requests, "mcp write-check")?;
    // The `initialized` notification draws no response, so the count is requests minus one.
    let expected = requests.len() - 1;
    if responses.len() != expected {
        return Err(format!(
            "expected {expected} JSON-RPC responses, got {}",
            responses.len()
        ));
    }
    if responses[0]["result"]["serverInfo"]["name"] != "dent8" {
        return Err("initialize did not return dent8 serverInfo".to_string());
    }

    let asserted = mcp_tool_result(&responses[1], "assert")?;
    if asserted["isError"].as_bool() != Some(false)
        || asserted["structuredContent"]["status"] != "accepted"
    {
        return Err(format!("trusted assert was not accepted: {asserted}"));
    }

    // Response order tracks the id-bearing requests: assert is index 1; the optional supersede,
    // then explain, verify, and retract follow in sequence.
    let mut idx = 2;
    let reject_note = if reject.is_some() {
        let superseded = mcp_tool_result(&responses[idx], "supersede")?;
        idx += 1;
        if superseded["isError"].as_bool() != Some(true)
            || superseded["structuredContent"]["status"] != "rejected"
        {
            return Err(format!(
                "below-ceiling supersede was not rejected: {superseded}"
            ));
        }
        "rejected below-ceiling tampered value"
    } else {
        "reject sub-check skipped (source ceiling is the minimum level)"
    };

    let explained = mcp_tool_result(&responses[idx], "explain")?;
    idx += 1;
    if explained["isError"].as_bool() != Some(false) {
        return Err(format!("explain failed: {explained}"));
    }
    if explained["structuredContent"]["current_value"]["text"] != "ok" {
        return Err(format!(
            "expected trusted value ok to remain; got {}",
            explained["structuredContent"]["current_value"]
        ));
    }

    let verified = mcp_tool_result(&responses[idx], "verify")?;
    idx += 1;
    if verified["isError"].as_bool() != Some(false)
        || verified["structuredContent"]["integrity_verified"] != true
    {
        return Err(format!("verify failed or reported findings: {verified}"));
    }

    let retracted = mcp_tool_result(&responses[idx], "retract")?;
    if retracted["isError"].as_bool() != Some(false)
        || retracted["structuredContent"]["status"] != "accepted"
    {
        return Err(format!(
            "write-check probe cleanup (retract) was not accepted: {retracted}"
        ));
    }

    Ok(format!(
        "mcp write-check: accepted trusted {} {}=ok at {ceiling_name}, {reject_note}, explain+verify OK, probe retracted",
        probe.subject(),
        probe.predicate
    ))
}

pub(crate) fn mcp_exchange_with_server(
    server: &mcp_config::InstalledServer,
    requests: &[serde_json::Value],
    operation: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let mut command = Command::new(&server.command);
    command
        .args(&server.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &server.cwd {
        command.current_dir(cwd);
    }
    apply_dent8_env(&mut command, &server.env);
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start `{}`: {error}", server.display_command()))?;
    {
        let stdin = child
            .stdin
            .as_mut()
            .ok_or_else(|| "could not open mcp stdin".to_string())?;
        let requests = format!(
            "{}\n",
            requests
                .iter()
                .map(serde_json::Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
        stdin
            .write_all(requests.as_bytes())
            .map_err(|error| format!("could not write {operation} request: {error}"))?;
    }
    drop(child.stdin.take());
    let timeout = mcp_smoke_timeout();
    let output = wait_with_output_timeout(child, timeout)
        .map_err(|error| format!("could not wait for {operation}: {error}"))?;
    if output.timed_out {
        return Err(format!(
            "`{}` timed out after {} during {operation}\nstderr:\n{}",
            server.display_command(),
            format_duration(timeout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if !output.status.success() {
        return Err(format!(
            "`{}` exited {}\nstderr:\n{}",
            server.display_command(),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let responses = stdout
        .lines()
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid JSON-RPC response: {error}"))?;
    Ok(responses)
}

pub(crate) fn mcp_initialize_request(id: u64) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "dent8-doctor",
                "version": env!("CARGO_PKG_VERSION"),
            },
        },
    })
}

pub(crate) fn mcp_initialized_notification() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
}

pub(crate) fn mcp_tool_call(
    id: u64,
    name: &str,
    arguments: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
        },
    })
}

pub(crate) fn mcp_value_fact_args(
    probe: &WriteCheckProbe,
    value: &str,
    authority: &str,
    source: &str,
) -> serde_json::Value {
    let mut args = mcp_read_fact_args(probe);
    let object = args
        .as_object_mut()
        .expect("mcp_read_fact_args returns object");
    object.insert("value".to_string(), serde_json::json!(value));
    object.insert("authority".to_string(), serde_json::json!(authority));
    object.insert("source".to_string(), serde_json::json!(source));
    args
}

pub(crate) fn mcp_read_fact_args(probe: &WriteCheckProbe) -> serde_json::Value {
    serde_json::json!({
        "subject": probe.subject(),
        "predicate": probe.predicate,
    })
}

pub(crate) fn mcp_retract_args(
    probe: &WriteCheckProbe,
    authority: &str,
    source: &str,
) -> serde_json::Value {
    let mut args = mcp_read_fact_args(probe);
    let object = args
        .as_object_mut()
        .expect("mcp_read_fact_args returns object");
    object.insert("authority".to_string(), serde_json::json!(authority));
    object.insert("source".to_string(), serde_json::json!(source));
    args
}

pub(crate) fn mcp_tool_result<'a>(
    response: &'a serde_json::Value,
    tool_name: &str,
) -> Result<&'a serde_json::Value, String> {
    if let Some(error) = response.get("error") {
        return Err(format!("{tool_name} returned protocol error: {error}"));
    }
    response
        .get("result")
        .ok_or_else(|| format!("{tool_name} response is missing result: {response}"))
}

pub(crate) struct TimedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
}

pub(crate) fn mcp_smoke_timeout() -> Duration {
    std::env::var("DENT8_MCP_SMOKE_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .filter(|timeout| !timeout.is_zero())
        .unwrap_or(DEFAULT_MCP_SMOKE_TIMEOUT)
}

pub(crate) fn wait_with_output_timeout(
    mut child: Child,
    timeout: Duration,
) -> io::Result<TimedCommandOutput> {
    let stdout = child.stdout.take().map(read_pipe_in_thread);
    let stderr = child.stderr.take().map(read_pipe_in_thread);
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        let now = Instant::now();
        if now >= deadline {
            timed_out = true;
            match child.kill() {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
                Err(error) => return Err(error),
            }
            break child.wait()?;
        }
        let remaining = deadline.saturating_duration_since(now);
        std::thread::sleep(remaining.min(Duration::from_millis(25)));
    };
    Ok(TimedCommandOutput {
        status,
        stdout: join_reader(stdout, "stdout")?,
        stderr: join_reader(stderr, "stderr")?,
        timed_out,
    })
}

pub(crate) fn read_pipe_in_thread<R>(mut reader: R) -> std::thread::JoinHandle<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut output = Vec::new();
        reader.read_to_end(&mut output)?;
        Ok(output)
    })
}

pub(crate) fn join_reader(
    handle: Option<std::thread::JoinHandle<io::Result<Vec<u8>>>>,
    pipe_name: &'static str,
) -> io::Result<Vec<u8>> {
    match handle {
        Some(handle) => handle
            .join()
            .map_err(|_| io::Error::other(format!("mcp smoke {pipe_name} reader panicked")))?,
        None => Ok(Vec::new()),
    }
}

pub(crate) fn format_duration(duration: Duration) -> String {
    if duration.as_millis().is_multiple_of(1_000) {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

pub(crate) fn apply_dent8_env(
    command: &mut Command,
    env: &std::collections::BTreeMap<String, String>,
) {
    for key in [
        "DENT8_STORE_URL",
        "DENT8_LOG",
        "DENT8_AUTHORITY",
        "DENT8_REQUIRE_AUTHORITY",
        "DENT8_TRUST",
        "DENT8_ACTIVE_GRANTS",
        "DENT8_GRANT",
        "DENT8_IDENTITY_KEY",
        "DENT8_REQUIRE_IDENTITY",
        "DENT8_WITNESS_KEY",
        "DENT8_WITNESS_PUBKEY",
        "DENT8_WITNESS_LOG",
    ] {
        command.env_remove(key);
    }
    for (key, value) in env {
        command.env(key, value);
    }
}

pub(crate) fn doctor_store(output: &mut String) -> Result<(), String> {
    if let Some(url) = store_url() {
        let scheme = store_scheme(&url);
        doctor_line(
            output,
            "OK",
            &format!("store: DENT8_STORE_URL={url} (scheme={scheme})"),
        );
        load_store(&log_path()).map(|store| {
            doctor_line(
                output,
                "OK",
                &format!("store load: {} event(s)", store.len()),
            );
        })?;
    } else {
        let path = log_path();
        if let Some(parent) = parent_dir(&path)
            && !parent.exists()
        {
            return Err(format!(
                "file store parent does not exist: {}",
                parent.display()
            ));
        }
        let store = load_store(&path)?;
        let detail = if std::path::Path::new(&path).exists() {
            format!("file dev store: {path} ({} event(s))", store.len())
        } else {
            format!("file dev store: {path} (will be created on first write)")
        };
        doctor_line(output, "OK", &detail);
    }
    Ok(())
}

pub(crate) fn doctor_authority(output: &mut String, source: &str) -> Result<(), String> {
    let required = authority_required()?;
    let path = authority_registry_path();
    match load_authority_registry_at(&path, required)? {
        Some(registry) => {
            let grant = registry.sources.get(source);
            let source_note = match grant {
                Some(grant) => format!("; {source} max={}", grant.max_authority),
                None => format!("; {source} is not granted"),
            };
            let level = if grant.is_some() { "OK" } else { "WARN" };
            doctor_line(
                output,
                level,
                &format!(
                    "authority: {path} ({} source(s){source_note})",
                    registry.sources.len()
                ),
            );
        }
        None if required => {
            return Err(format!(
                "authority: DENT8_REQUIRE_AUTHORITY=1 but no registry exists at {path}"
            ));
        }
        None => doctor_line(
            output,
            "WARN",
            &format!("authority: no registry at {path}; dev mode is permissive"),
        ),
    }
    Ok(())
}

pub(crate) fn doctor_identity(output: &mut String, source: &str) -> bool {
    let mut ok = true;
    for line in identity::doctor_status(source, now_millis()) {
        if !line.ok {
            ok = false;
        }
        doctor_line(output, line.level, &line.message);
    }
    ok
}

pub(crate) fn doctor_witness(output: &mut String) -> bool {
    let mut ok = true;
    for line in witness::doctor_status() {
        if !line.ok {
            ok = false;
        }
        doctor_line(output, line.level, &line.message);
    }
    ok
}

/// The level immediately below `level` in the authority lattice, or `None` when `level` is
/// already the minimum (`Unknown`). The write-check reject sub-check supersedes at this level
/// so it is genuinely *below* the assert and still exercises the anti-laundering rejection.
fn authority_below(level: AuthorityLevel) -> Option<AuthorityLevel> {
    use AuthorityLevel::{Canonical, High, Low, Medium, Unknown};
    match level {
        Unknown => None,
        Low => Some(Unknown),
        Medium => Some(Low),
        High => Some(Medium),
        Canonical => Some(High),
    }
}

/// Where a write-check probe writes, and at what authority. By default a throwaway
/// `diagnostic:` subject; when the probed source is **subject-scoped** (by its
/// authority-registry grant chain or its signed identity grant), the scoped subject itself
/// with a per-run unique probe predicate — the probe must stay a legitimately-authorized
/// write, so it targets the one subject the source may write about instead of bypassing or
/// weakening the scope gate (a scoped source must never be able to persist an out-of-scope
/// write, not even a diagnostic one). Scope resolution is best-effort: an unreadable
/// registry/grant or a malformed scope falls back to the default subject and lets the write
/// gate report the real rejection.
///
/// The probe asserts at the **source's own granted ceiling** (the authority-registry grant if
/// the source is listed, else the signed identity's max authority, else `High` as a last
/// resort) rather than a hardcoded `high`, so a healthy source whose ceiling is below `high`
/// still passes write-check. The reject sub-check supersedes one level *below* that ceiling so
/// it stays a genuine rejection; when the ceiling is already the minimum level there is nothing
/// below it, so that sub-check is skipped (noted in the result).
///
/// **Residue:** the event log is append-only — an admitted probe fact cannot be truly deleted.
/// So the probe **retracts its own `ok` fact** once the checks complete: the fact falls to a
/// terminal (no-longer-believed) state instead of lingering as live "current" state, and browse
/// surfaces (which already hide `dent8.write_check*` streams) stay clean. Each run still appends
/// to a fresh per-run stream, but per-run retraction bounds the *believed* residue to nothing.
pub(crate) struct WriteCheckProbe {
    subject_kind: String,
    subject_key: String,
    predicate: String,
    ceiling: AuthorityLevel,
}

impl WriteCheckProbe {
    fn for_source(
        source: &str,
        run_id: &str,
        registry_path: &str,
        identity_scope: Option<String>,
        identity_ceiling: Option<AuthorityLevel>,
    ) -> Self {
        let registry = load_authority_registry_at(registry_path, false)
            .ok()
            .flatten();
        // Effective ceiling: the registry grant if the source is listed, else the signed
        // identity's max authority, else High (the historical default) as a last resort.
        let ceiling = registry
            .as_ref()
            .and_then(|registry| crate::source_registry_ceiling(registry, source))
            .or(identity_ceiling)
            .unwrap_or(AuthorityLevel::High);
        let scoped = registry
            .as_ref()
            .and_then(|registry| crate::scoped_probe_subject(registry, source).map(str::to_string))
            .or(identity_scope);
        match scoped.and_then(|subject| crate::CliSubject::from_str(&subject).ok()) {
            Some(subject) => Self {
                subject_kind: subject.kind,
                subject_key: subject.key,
                predicate: format!("dent8.write_check.{run_id}"),
                ceiling,
            },
            None => Self {
                subject_kind: "diagnostic".to_string(),
                subject_key: run_id.to_string(),
                predicate: "dent8.write_check".to_string(),
                ceiling,
            },
        }
    }

    fn subject(&self) -> String {
        format!("{}:{}", self.subject_kind, self.subject_key)
    }
}

pub(crate) fn doctor_write_check(source: &str) -> Result<String, String> {
    let run_id = format!(
        "doctor-{}-{}",
        std::process::id(),
        now_millis().as_unix_millis()
    );
    let probe = WriteCheckProbe::for_source(
        source,
        &run_id,
        &authority_registry_path(),
        identity::env_grant_scope(source),
        identity::env_grant_authority(source),
    );
    ops::op_assert(
        &log_path(),
        &probe.subject_kind,
        &probe.subject_key,
        &probe.predicate,
        "ok",
        probe.ceiling,
        source,
        ops::Validity::default(),
        &crate::WriteIdentity::Env,
    )
    .map_err(|error| error.message().to_string())?;

    // Supersede one level below the assert so the attempt is a genuine anti-laundering
    // rejection. When the ceiling is already the minimum level there is nothing below it, so
    // the sub-check is skipped.
    let reject_note = match authority_below(probe.ceiling) {
        Some(reject_authority) => {
            match ops::op_supersede(
                &log_path(),
                &probe.subject_kind,
                &probe.subject_key,
                &probe.predicate,
                "tampered",
                reject_authority,
                source,
                ops::Validity::default(),
                &crate::WriteIdentity::Env,
            ) {
                Ok(message) => {
                    return Err(format!(
                        "below-ceiling override was accepted unexpectedly: {message}"
                    ));
                }
                Err(ops::OpError::Rejected { .. }) => "rejected below-ceiling tampered value",
                Err(error) => return Err(error.message().to_string()),
            }
        }
        None => "reject sub-check skipped (source ceiling is the minimum level)",
    };

    let explained = ops::op_explain(
        &log_path(),
        &probe.subject_kind,
        &probe.subject_key,
        &probe.predicate,
        ops::ReadClock::default(),
    )
    .map_err(|error| error.message().to_string())?;
    if !explained.contains("value         : \"ok\"") {
        return Err(format!(
            "expected trusted value ok to remain; got:\n{explained}"
        ));
    }
    verify_log(&log_path())?;

    // Clean up after ourselves: the log is append-only, so retract the probe fact at the same
    // ceiling authority that asserted it. The fact falls to a terminal state instead of
    // lingering as live current state, keeping browse surfaces clean across repeated runs.
    ops::op_retract(
        &log_path(),
        &probe.subject_kind,
        &probe.subject_key,
        &probe.predicate,
        probe.ceiling,
        source,
        &crate::WriteIdentity::Env,
    )
    .map_err(|error| {
        format!(
            "write-check probe cleanup (retract) failed: {}",
            error.message()
        )
    })?;

    Ok(format!(
        "write-check: accepted trusted {} {}=ok at {}, {reject_note}, verify OK, probe retracted",
        probe.subject(),
        probe.predicate,
        probe.ceiling,
    ))
}

pub(crate) fn doctor_line(output: &mut String, level: &str, message: &str) {
    output.push_str("  ");
    output.push_str(level);
    output.push_str("  ");
    output.push_str(message);
    output.push('\n');
}

pub(crate) fn store_scheme(url: &str) -> &str {
    url.split_once(':').map_or("", |(scheme, _)| scheme)
}

pub(crate) fn parent_dir(path: &str) -> Option<&std::path::Path> {
    let parent = std::path::Path::new(path).parent()?;
    if parent.as_os_str().is_empty() {
        None
    } else {
        Some(parent)
    }
}

#[cfg(test)]
mod tests {
    use super::latest_workspace_rust_mtime;
    use std::fs;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    #[test]
    fn latest_workspace_rust_mtime_ignores_integration_tests() {
        let root = temp_repo_dir();
        let src = root.join("crates/dent8-cli/src");
        let tests = root.join("crates/dent8-cli/tests");
        fs::create_dir_all(&src).expect("create src dir");
        fs::create_dir_all(&tests).expect("create tests dir");
        fs::write(root.join("Cargo.toml"), "[workspace]\n").expect("write workspace manifest");
        fs::write(src.join("main.rs"), "fn main() {}\n").expect("write runtime source");
        std::thread::sleep(Duration::from_millis(20));
        fs::write(tests.join("cli_usage.rs"), "#[test]\nfn cli() {}\n")
            .expect("write integration test");

        let runtime_mtime = fs::metadata(src.join("main.rs"))
            .and_then(|meta| meta.modified())
            .expect("runtime mtime");
        let test_mtime = fs::metadata(tests.join("cli_usage.rs"))
            .and_then(|meta| meta.modified())
            .expect("test mtime");
        assert!(
            runtime_mtime < test_mtime,
            "test fixture needs the integration test to be newer"
        );
        assert_eq!(
            latest_workspace_rust_mtime(&root),
            Some(runtime_mtime),
            "integration tests should not make the MCP runtime binary look stale"
        );

        fs::remove_dir_all(root).expect("remove temp repo");
    }

    fn temp_repo_dir() -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before epoch")
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("dent8-doctor-test-{}-{nonce}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path).expect("clear stale temp repo");
        }
        path
    }
}
