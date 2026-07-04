//! `dent8 doctor`: the adoption/diagnosis surface. Checks the binary, store, authority,
//! signed identity, witness, MCP availability, and (opt-in) a trusted write-check probe;
//! `--agent` validates a generated bundle + its installed MCP config, smokes the exact
//! installed command over stdio JSON-RPC with a bounded timeout, and `--repair` refreshes
//! stale generated env/config via the machinery in [`crate::setup`].

use std::{
    io::{self, Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

use dent8_core::AuthorityLevel;

#[cfg(not(feature = "identity"))]
use crate::env_flag;
#[cfg(feature = "identity")]
use crate::identity;
use crate::setup::{
    LocalMcpBinary, install_mcp_config_prepared, is_executable_file, local_mcp_binary,
    local_mcp_build_command, local_mcp_missing_target_message, render_local_mcp_wrapper,
};
#[cfg(feature = "witness")]
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
    serde_json::json!({
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

    DoctorReport { output, ok }
}

pub(crate) fn doctor_agent_report(args: &DoctorArgs, agent: InitAgent) -> DoctorReport {
    let mut output = String::from("dent8 doctor\n");
    let mut ok = true;
    let dir = std::path::PathBuf::from(&args.dir);
    let dir = match absolute_path(&dir) {
        Ok(dir) => dir,
        Err(error) => {
            doctor_line(&mut output, "FAIL", &error);
            return DoctorReport { output, ok: false };
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
        return DoctorReport { output, ok: false };
    }

    let bundle_env =
        match load_doctor_agent_env(&mut output, agent, &dir, args.mcp_config.as_deref()) {
            Ok(env) => env,
            Err(error) => {
                doctor_line(&mut output, "FAIL", &error);
                return DoctorReport { output, ok: false };
            }
        };

    let installed = match load_doctor_installed_server(&mut output, args, agent, &dir) {
        Ok(installed) => installed,
        Err(error) => {
            doctor_line(&mut output, "FAIL", &error);
            return DoctorReport { output, ok: false };
        }
    };

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

    match run_doctor_with_env(source, false, &installed.env, !args.write_check) {
        Ok(child) => {
            output.push_str(&child);
        }
        Err(error) => {
            ok = false;
            doctor_line(&mut output, "FAIL", &error);
        }
    }

    match mcp_smoke_with_server(&installed) {
        Ok(message) => doctor_line(&mut output, "OK", &message),
        Err(error) => {
            ok = false;
            doctor_line(&mut output, "FAIL", &format!("mcp smoke: {error}"));
        }
    }

    if args.write_check {
        match mcp_write_check_with_server(&installed, source) {
            Ok(message) => doctor_line(&mut output, "OK", &message),
            Err(error) => {
                ok = false;
                doctor_line(&mut output, "FAIL", &format!("mcp write-check: {error}"));
            }
        }
    }

    DoctorReport { output, ok }
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

#[cfg(feature = "identity")]
pub(crate) fn repair_agent_identity_env(
    agent: InitAgent,
    dir: &std::path::Path,
) -> Result<String, String> {
    identity::repair_env_bundle(&dir.to_string_lossy(), agent.source())
}

#[cfg(not(feature = "identity"))]
pub(crate) fn repair_agent_identity_env(
    agent: InitAgent,
    dir: &std::path::Path,
) -> Result<String, String> {
    let _ = (agent, dir);
    Err("`dent8 doctor --agent --repair` requires a build with `--features identity`".to_string())
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
                "local MCP binary: witness checks failed; rebuild with `--features sqlite,witness`",
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
    let Ok(entries) = std::fs::read_dir(path) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        collect_latest_rust_mtime(&entry.path(), latest);
    }
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

pub(crate) fn mcp_smoke_with_server(
    server: &mcp_config::InstalledServer,
) -> Result<String, String> {
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
        ],
        "mcp smoke",
    )?;
    if responses.len() != 2 {
        return Err(format!(
            "expected 2 JSON-RPC responses, got {}",
            responses.len()
        ));
    }
    if responses[0]["result"]["serverInfo"]["name"] != "dent8" {
        return Err("initialize did not return dent8 serverInfo".to_string());
    }
    let tools = responses[1]["result"]["tools"]
        .as_array()
        .ok_or_else(|| "tools/list did not return a tools array".to_string())?;
    for expected in ["assert", "explain", "verify"] {
        if !tools
            .iter()
            .any(|tool| tool["name"].as_str() == Some(expected))
        {
            return Err(format!("tools/list is missing {expected}"));
        }
    }
    Ok(format!(
        "mcp smoke: initialize + tools/list OK ({} tool(s))",
        tools.len()
    ))
}

pub(crate) fn mcp_write_check_with_server(
    server: &mcp_config::InstalledServer,
    source: &str,
) -> Result<String, String> {
    let subject_key = format!(
        "doctor-mcp-{}-{}",
        std::process::id(),
        now_millis().as_unix_millis()
    );
    let responses = mcp_exchange_with_server(
        server,
        &[
            mcp_initialize_request(1),
            mcp_initialized_notification(),
            mcp_tool_call(
                2,
                "assert",
                &mcp_value_fact_args(&subject_key, "ok", "high", source),
            ),
            mcp_tool_call(
                3,
                "supersede",
                &mcp_value_fact_args(&subject_key, "tampered", "low", source),
            ),
            mcp_tool_call(4, "explain", &mcp_read_fact_args(&subject_key)),
            mcp_tool_call(5, "verify", &serde_json::json!({})),
        ],
        "mcp write-check",
    )?;
    if responses.len() != 5 {
        return Err(format!(
            "expected 5 JSON-RPC responses, got {}",
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

    let superseded = mcp_tool_result(&responses[2], "supersede")?;
    if superseded["isError"].as_bool() != Some(true)
        || superseded["structuredContent"]["status"] != "rejected"
    {
        return Err(format!(
            "low-authority supersede was not rejected: {superseded}"
        ));
    }

    let explained = mcp_tool_result(&responses[3], "explain")?;
    if explained["isError"].as_bool() != Some(false) {
        return Err(format!("explain failed: {explained}"));
    }
    if explained["structuredContent"]["current_value"]["text"] != "ok" {
        return Err(format!(
            "expected trusted value ok to remain; got {}",
            explained["structuredContent"]["current_value"]
        ));
    }

    let verified = mcp_tool_result(&responses[4], "verify")?;
    if verified["isError"].as_bool() != Some(false)
        || verified["structuredContent"]["integrity_verified"] != true
    {
        return Err(format!("verify failed or reported findings: {verified}"));
    }

    Ok(format!(
        "mcp write-check: accepted trusted diagnostic:{subject_key} dent8.write_check=ok, rejected low-authority tampered value, explain+verify OK"
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
    subject_key: &str,
    value: &str,
    authority: &str,
    source: &str,
) -> serde_json::Value {
    let mut args = mcp_read_fact_args(subject_key);
    let object = args
        .as_object_mut()
        .expect("mcp_read_fact_args returns object");
    object.insert("value".to_string(), serde_json::json!(value));
    object.insert("authority".to_string(), serde_json::json!(authority));
    object.insert("source".to_string(), serde_json::json!(source));
    args
}

pub(crate) fn mcp_read_fact_args(subject_key: &str) -> serde_json::Value {
    serde_json::json!({
        "subject_kind": "diagnostic",
        "subject_key": subject_key,
        "predicate": "dent8.write_check",
    })
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
                Some(grant) => format!("; {source} max={:?}", grant.max_authority),
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

#[cfg(feature = "identity")]
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

#[cfg(not(feature = "identity"))]
pub(crate) fn doctor_identity(output: &mut String, _source: &str) -> bool {
    let required = match env_flag("DENT8_REQUIRE_IDENTITY") {
        Ok(required) => required,
        Err(error) => {
            doctor_line(output, "FAIL", &format!("identity: {error}"));
            return false;
        }
    };
    let configured = required
        || env_present("DENT8_TRUST")
        || env_present("DENT8_GRANT")
        || env_present("DENT8_IDENTITY_KEY")
        || std::path::Path::new("dent8-trust.json").exists();
    if configured {
        doctor_line(
            output,
            "FAIL",
            "identity: configured, but this binary was built without `--features identity`",
        );
        false
    } else {
        doctor_line(
            output,
            "WARN",
            "identity: not configured (optional; build with `--features identity` to enable signed source identity)",
        );
        true
    }
}

#[cfg(feature = "witness")]
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

#[cfg(not(feature = "witness"))]
pub(crate) fn doctor_witness(output: &mut String) -> bool {
    let configured = env_present("DENT8_WITNESS_LOG")
        || env_present("DENT8_WITNESS_PUBKEY")
        || env_present("DENT8_WITNESS_KEY")
        || std::path::Path::new("dent8-witness.jsonl").exists();
    if !configured {
        doctor_line(
            output,
            "WARN",
            "witness: not configured (optional; build with `--features witness` for signed tree heads)",
        );
        return true;
    }

    let log =
        std::env::var("DENT8_WITNESS_LOG").unwrap_or_else(|_| "dent8-witness.jsonl".to_string());
    match std::fs::read_to_string(&log) {
        Ok(contents) if contents.lines().any(|line| !line.trim().is_empty()) => {
            doctor_line(
                output,
                "FAIL",
                "witness: signed heads are configured, but this binary was built without `--features witness`",
            );
            false
        }
        Ok(_) => {
            doctor_line(
                output,
                "WARN",
                "witness: configured but no signed heads verified by this non-witness build",
            );
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            doctor_line(
                output,
                "WARN",
                "witness: configured but no signed heads verified by this non-witness build",
            );
            true
        }
        Err(error) => {
            doctor_line(
                output,
                "FAIL",
                &format!(
                    "witness: cannot read configured witness log {log}: {error}; rebuild with `--features witness` to verify signed heads"
                ),
            );
            false
        }
    }
}

#[cfg(any(not(feature = "identity"), not(feature = "witness")))]
pub(crate) fn env_present(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

pub(crate) fn doctor_write_check(source: &str) -> Result<String, String> {
    let subject_key = format!(
        "doctor-{}-{}",
        std::process::id(),
        now_millis().as_unix_millis()
    );
    ops::op_assert(
        &log_path(),
        "diagnostic",
        &subject_key,
        "dent8.write_check",
        "ok",
        AuthorityLevel::High,
        source,
        ops::Validity::default(),
        &crate::WriteIdentity::Env,
    )
    .map_err(|error| error.message().to_string())?;

    match ops::op_supersede(
        &log_path(),
        "diagnostic",
        &subject_key,
        "dent8.write_check",
        "tampered",
        AuthorityLevel::Low,
        source,
        ops::Validity::default(),
        &crate::WriteIdentity::Env,
    ) {
        Ok(message) => {
            return Err(format!(
                "low-authority override was accepted unexpectedly: {message}"
            ));
        }
        Err(ops::OpError::Rejected(_)) => {}
        Err(error) => return Err(error.message().to_string()),
    }

    let explained = ops::op_explain(
        &log_path(),
        "diagnostic",
        &subject_key,
        "dent8.write_check",
        ops::ReadClock::default(),
    )
    .map_err(|error| error.message().to_string())?;
    if !explained.contains("value         : \"ok\"") {
        return Err(format!(
            "expected trusted value ok to remain; got:\n{explained}"
        ));
    }
    verify_log(&log_path())?;
    Ok(format!(
        "write-check: accepted trusted diagnostic:{subject_key} dent8.write_check=ok, rejected low-authority tampered value, verify OK"
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
