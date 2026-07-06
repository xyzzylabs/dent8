//! Project **setup and onboarding**: `dent8 init` (env file, authority registry, store
//! profile, optional signed-identity bundle + witness paths), `dent8 agent add` (a second
//! agent joining an existing shared bundle), and `dent8 mcp install` (patching a known
//! agent's MCP config, optionally via the repo-local prebuilt-binary wrapper). Doctor's
//! repair paths reuse the prepared-install machinery here; cross-cutting path/quote
//! utilities stay in the crate root.

use dent8_core::AuthorityLevel;

use crate::{
    AgentAddArgs, CliOutput, InitAgent, InitArgs, InitStore, McpInstallArgs, SourceGrant,
    absolute_path, load_authority_registry_at, mcp_config, path_string,
    print_json_stdout_with_code, save_authority_registry_at, shell_quote, write_atomic,
};
#[cfg(feature = "identity")]
use crate::{CliAuthority, SourceRegistry, identity};

pub(crate) fn cmd_init(args: &InitArgs, output: CliOutput) -> i32 {
    match init_project(args) {
        Ok(outcome) => match output {
            CliOutput::Text => {
                println!("{}", outcome.message);
                outcome.exit_code
            }
            CliOutput::Json => {
                print_json_stdout_with_code(&init_json(args, &outcome), outcome.exit_code)
            }
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stdout_with_code(&init_error_json(args, &error), 1),
        },
    }
}

pub(crate) fn cmd_mcp_install(args: &McpInstallArgs, output: CliOutput) -> i32 {
    let dir = std::path::PathBuf::from(&args.dir);
    let mode = mcp_install_mode(args.dry_run, args.check);
    match install_mcp_config_prepared_detail(
        args.agent,
        &dir,
        args.config.as_deref(),
        args.command.as_deref(),
        args.local_bin,
        mode,
    ) {
        Ok(outcome) => match output {
            CliOutput::Text => {
                println!("{}", outcome.message());
                outcome.exit_code()
            }
            CliOutput::Json => {
                print_json_stdout_with_code(&mcp_install_json(args, &outcome), outcome.exit_code())
            }
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => {
                print_json_stdout_with_code(&mcp_install_error_json(args, mode, &error), 1)
            }
        },
    }
}

pub(crate) fn cmd_agent_add(args: &AgentAddArgs, output: CliOutput) -> i32 {
    #[cfg(not(feature = "identity"))]
    {
        let message = "`dent8 agent add` requires signed source identity; default builds include \
                       it, or rebuild this binary with `--features identity`";
        match output {
            CliOutput::Text => {
                eprintln!("{message}");
                1
            }
            CliOutput::Json => print_json_stdout_with_code(&agent_add_error_json(args, message), 1),
        }
    }

    #[cfg(feature = "identity")]
    match agent_add_inner(args) {
        Ok(outcome) => match output {
            CliOutput::Text => {
                println!("{}", outcome.message());
                outcome.exit_code()
            }
            CliOutput::Json => {
                print_json_stdout_with_code(&agent_add_json(args, &outcome), outcome.exit_code())
            }
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stdout_with_code(&agent_add_error_json(args, &error), 1),
        },
    }
}

#[cfg(feature = "identity")]
pub(crate) struct AgentAddBundle {
    dir: std::path::PathBuf,
    store_url: String,
    authority_path: std::path::PathBuf,
    registry: SourceRegistry,
}

#[cfg(feature = "identity")]
pub(crate) struct AgentAddOutcome {
    agent: InitAgent,
    dir: std::path::PathBuf,
    store_url: String,
    authority_path: std::path::PathBuf,
    authority_ceiling: AuthorityLevel,
    identity: identity::SourceIdentityOutput,
    mcp_install: McpInstallAttempt,
}

#[cfg(feature = "identity")]
impl AgentAddOutcome {
    fn message(&self) -> String {
        let mut message = agent_add_base_message(
            self.agent,
            &self.dir,
            &self.store_url,
            &self.authority_path,
            &self.identity,
            self.authority_ceiling,
        );
        message.push_str("\n\n");
        message.push_str(&self.mcp_install.message());
        if self.mcp_install.result.is_ok() {
            message.push_str("\n\nNext:\n  dent8 doctor --agent ");
            message.push_str(self.agent.cli_name());
            message.push_str(" --dir ");
            message.push_str(&shell_quote(&self.dir.to_string_lossy()));
            message.push_str(" --write-check");
        }
        message
    }

    fn exit_code(&self) -> i32 {
        self.mcp_install.exit_code()
    }
}

#[cfg(feature = "identity")]
pub(crate) fn agent_add_inner(args: &AgentAddArgs) -> Result<AgentAddOutcome, String> {
    validate_agent_add_args(args)?;
    let mut bundle = load_agent_add_bundle(args)?;
    let source = args.agent.source();
    let identity = identity::add_source_to_bundle(
        &bundle.dir.to_string_lossy(),
        source,
        args.issuer.as_deref(),
        args.issuer_key.as_deref(),
        args.authority.unwrap_or(CliAuthority::High),
        &args.identity_scope,
        args.identity_expires_at_ms,
    )?;
    let existing_ceiling = bundle
        .registry
        .sources
        .get(source)
        .map(|grant| grant.max_authority);
    let authority_ceiling = args
        .authority
        .map(CliAuthority::level)
        .or(existing_ceiling)
        .unwrap_or(identity.max_authority);
    if authority_ceiling > identity.max_authority {
        return Err(format!(
            "existing signed identity for {source} has max={}, below requested authority \
             ceiling {:?}; rotate or reissue the source grant before raising the authority \
             ceiling",
            identity.max_authority, authority_ceiling
        ));
    }

    bundle.registry.sources.insert(
        source.to_string(),
        SourceGrant {
            max_authority: authority_ceiling,
            issuer: Some(identity.issuer.clone()),
            scope: Some(identity.scope.clone()),
        },
    );
    save_authority_registry_at(&bundle.authority_path.to_string_lossy(), &bundle.registry)?;

    let mcp_install = mcp_install_attempt(
        args.agent,
        &bundle.dir,
        args.mcp_config.clone(),
        args.mcp_command.clone(),
        args.mcp_local_bin,
        mcp_config::InstallMode::Write,
    );
    Ok(AgentAddOutcome {
        agent: args.agent,
        dir: bundle.dir,
        store_url: bundle.store_url,
        authority_path: bundle.authority_path,
        authority_ceiling,
        identity,
        mcp_install,
    })
}

#[cfg(feature = "identity")]
pub(crate) fn validate_agent_add_args(args: &AgentAddArgs) -> Result<(), String> {
    if args
        .mcp_command
        .as_deref()
        .is_some_and(|command| command.trim().is_empty())
    {
        return Err("MCP command must not be empty".to_string());
    }
    if args.agent == InitAgent::Hecate && args.mcp_config.is_none() {
        return Err(
            "`dent8 agent add --agent hecate` needs --mcp-config PATH because Hecate task \
             MCP config lives in a task/UI payload, not a stable project file"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(feature = "identity")]
pub(crate) fn load_agent_add_bundle(args: &AgentAddArgs) -> Result<AgentAddBundle, String> {
    let dir = absolute_path(&std::path::PathBuf::from(&args.dir))?;
    let env_path = dir.join("env");
    let env = mcp_config::read_env_file(&env_path).map_err(|error| {
        format!(
            "{error}; run `dent8 init --agent <profile> --store sqlite` or \
             `dent8 init --agent <profile> --store postgres --store-url <url>` first"
        )
    })?;
    let store_url = shared_store_url_from_bundle_env(&env, &env_path)?;
    let authority_raw = bundle_env_required(&env, "DENT8_AUTHORITY")?;
    let authority_path = bundle_env_path_value(authority_raw, &dir);
    let registry =
        load_authority_registry_at(&authority_path.to_string_lossy(), false)?.unwrap_or_default();
    Ok(AgentAddBundle {
        dir,
        store_url,
        authority_path,
        registry,
    })
}

#[cfg(feature = "identity")]
pub(crate) fn shared_store_url_from_bundle_env(
    env: &std::collections::BTreeMap<String, String>,
    env_path: &std::path::Path,
) -> Result<String, String> {
    match bundle_env_required(env, "DENT8_STORE_URL") {
        Ok(url) => Ok(url.to_string()),
        Err(_)
            if env
                .get("DENT8_LOG")
                .is_some_and(|value| !value.trim().is_empty()) =>
        {
            Err(format!(
                "{} is a file-dev bundle (DENT8_LOG is set). `dent8 agent add` requires \
                 DENT8_STORE_URL so multiple agents share one SQLite/Postgres backend while \
                 keeping per-agent identity env values distinct. Re-run init with \
                 `--store sqlite` or configure `--store postgres --store-url <url>`.",
                env_path.display()
            ))
        }
        Err(error) => Err(error),
    }
}

#[cfg(feature = "identity")]
pub(crate) fn agent_add_base_message(
    agent: InitAgent,
    dir: &std::path::Path,
    store_url: &str,
    authority_path: &std::path::Path,
    identity: &identity::SourceIdentityOutput,
    authority_ceiling: AuthorityLevel,
) -> String {
    let identity_action = if identity.reused { "reused" } else { "created" };
    format!(
        "added dent8 agent {} in {}\n  source: {} authority ceiling={}\n  store: {}\n  authority: {}\n  identity: {identity_action} grant {} (max={}, source key: {}, env: {}, active grants: {})",
        agent.cli_name(),
        dir.display(),
        identity.source,
        authority_ceiling,
        store_url,
        authority_path.display(),
        identity.grant_file.display(),
        identity.max_authority,
        identity.source_key_path.display(),
        identity.env_file.display(),
        identity.active_grants_file.display(),
    )
}

#[cfg(feature = "identity")]
pub(crate) fn agent_add_json(args: &AgentAddArgs, outcome: &AgentAddOutcome) -> serde_json::Value {
    serde_json::json!({
        "status": agent_add_status(outcome),
        "tool": "agent add",
        "exit_code": outcome.exit_code(),
        "agent": outcome.agent.cli_name(),
        "dir": path_string(&outcome.dir),
        "source": outcome.identity.source.as_str(),
        "store_url": outcome.store_url.as_str(),
        "authority": {
            "path": path_string(&outcome.authority_path),
            "source": outcome.identity.source.as_str(),
            "max_authority": outcome.authority_ceiling.name(),
        },
        "identity": {
            "source": outcome.identity.source.as_str(),
            "issuer": outcome.identity.issuer.as_str(),
            "max_authority": outcome.identity.max_authority.name(),
            "scope": outcome.identity.scope.as_str(),
            "active_grants_file": path_string(&outcome.identity.active_grants_file),
            "grant_file": path_string(&outcome.identity.grant_file),
            "source_key_path": path_string(&outcome.identity.source_key_path),
            "env_file": path_string(&outcome.identity.env_file),
            "reused": outcome.identity.reused,
        },
        "mcp_install": mcp_install_attempt_json(&outcome.mcp_install),
        "next": {
            "doctor_command": format!(
                "dent8 doctor --agent {} --dir {} --write-check",
                outcome.agent.cli_name(),
                shell_quote(&outcome.dir.to_string_lossy())
            ),
        },
        "message": outcome.message(),
        "requested": {
            "agent": args.agent.cli_name(),
            "dir": args.dir.as_str(),
            "authority": args.authority.map(|authority| authority.level().name()),
            "issuer": args.issuer.as_deref(),
            "issuer_key": args.issuer_key.as_deref(),
            "identity_scope": args.identity_scope.as_str(),
            "identity_expires_at_ms": args.identity_expires_at_ms,
            "mcp_config": args.mcp_config.as_deref(),
            "mcp_command": args.mcp_command.as_deref(),
            "mcp_local_bin": args.mcp_local_bin,
        },
    })
}

#[cfg(feature = "identity")]
pub(crate) fn agent_add_status(outcome: &AgentAddOutcome) -> &'static str {
    if outcome.mcp_install.result.is_ok() {
        "ok"
    } else {
        "partial"
    }
}

pub(crate) fn agent_add_error_json(args: &AgentAddArgs, message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "agent add",
        "agent": args.agent.cli_name(),
        "dir": args.dir.as_str(),
        "message": message,
    })
}

#[cfg(feature = "identity")]
pub(crate) fn bundle_env_required<'a>(
    env: &'a std::collections::BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, String> {
    env.get(key)
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("generated dent8 env is missing {key}"))
}

#[cfg(feature = "identity")]
pub(crate) fn bundle_env_path_value(raw: &str, bundle_dir: &std::path::Path) -> std::path::PathBuf {
    let path = std::path::PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        bundle_dir.join(path)
    }
}

pub(crate) struct InitOutcome {
    message: String,
    exit_code: i32,
    dir: std::path::PathBuf,
    source: String,
    agent: Option<InitAgent>,
    authority_path: std::path::PathBuf,
    authority_level: AuthorityLevel,
    env_path: std::path::PathBuf,
    store: InitStoreOutput,
    identity: InitIdentityOutput,
    witness: InitWitnessOutput,
    mcp_install: Option<McpInstallAttempt>,
}

pub(crate) struct InitStoreOutput {
    kind: InitStore,
    env_key: &'static str,
    env_value: String,
    summary: String,
}

pub(crate) struct McpInstallAttempt {
    agent: InitAgent,
    dir: std::path::PathBuf,
    config: Option<String>,
    command: Option<String>,
    local_bin: bool,
    mode: mcp_config::InstallMode,
    result: Result<PreparedMcpInstall, String>,
}

impl McpInstallAttempt {
    fn message(&self) -> String {
        match &self.result {
            Ok(install) => install.message(),
            Err(error) => {
                let mut message = format!(
                    "MCP install failed: {error}\nRun: dent8 mcp install --agent {} --dir {}",
                    self.agent.cli_name(),
                    shell_quote(&self.dir.to_string_lossy())
                );
                if let Some(config) = self.config.as_deref() {
                    message.push_str(" --config ");
                    message.push_str(&shell_quote(config));
                }
                message
            }
        }
    }

    fn exit_code(&self) -> i32 {
        self.result
            .as_ref()
            .map_or(1, PreparedMcpInstall::exit_code)
    }
}

pub(crate) fn init_project(args: &InitArgs) -> Result<InitOutcome, String> {
    let dir = std::path::PathBuf::from(&args.dir);
    let dir = absolute_path(&dir)?;
    let source = init_source(args);
    let bootstrap_identity = args.identity || args.agent.is_some();
    #[cfg(not(feature = "identity"))]
    if bootstrap_identity {
        return Err(
            "`dent8 init --identity` requires signed source identity; default builds include it, \
             or rebuild this binary with `--features identity`"
                .to_string(),
        );
    }
    let authority_path = dir.join("authority.json");
    let env_path = dir.join("env");
    if env_path.exists() && !args.force {
        return Err(format!(
            "{} already exists; pass `--force` to rewrite the generated env file",
            env_path.display()
        ));
    }

    preflight_identity(args, &dir, &source, bootstrap_identity)?;

    std::fs::create_dir_all(&dir)
        .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;

    let store = init_store_output(args.store, args.store_url.as_deref(), &dir, args.agent)?;
    if args.store == InitStore::File {
        let log_path = init_file_log_path(&dir, args.agent);
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map_err(|error| format!("cannot create {}: {error}", log_path.display()))?;
    }

    let authority_path_str = authority_path.to_string_lossy().into_owned();
    let mut registry = load_authority_registry_at(&authority_path_str, false)?.unwrap_or_default();
    registry.sources.insert(
        source.clone(),
        SourceGrant {
            max_authority: args.authority.level(),
            issuer: None,
            scope: None,
        },
    );
    save_authority_registry_at(&authority_path_str, &registry)?;

    let identity = init_identity(args, &dir, &source, bootstrap_identity)?;
    let witness = init_witness(args, &dir)?;
    let env_contents = init_env_contents(&env_path, &authority_path, &store, &witness);
    write_atomic(&env_path.to_string_lossy(), &env_contents)?;

    let mut message = init_base_message(
        &dir,
        &authority_path,
        &source,
        args.authority.level(),
        &store,
        &env_path,
        &identity,
        &witness,
        args.agent,
    );
    let mcp_install = init_mcp_install(args, &dir)?;
    let exit_code = mcp_install.as_ref().map_or(0, McpInstallAttempt::exit_code);
    if let Some(install) = mcp_install.as_ref() {
        message.push_str("\n\n");
        message.push_str(&install.message());
    }
    Ok(InitOutcome {
        message,
        exit_code,
        dir,
        source,
        agent: args.agent,
        authority_path,
        authority_level: args.authority.level(),
        env_path,
        store,
        identity,
        witness,
        mcp_install,
    })
}

pub(crate) fn init_env_contents(
    env_path: &std::path::Path,
    authority_path: &std::path::Path,
    store: &InitStoreOutput,
    witness: &InitWitnessOutput,
) -> String {
    format!(
        "# dent8 local environment\n\
         # Load with: set -a; . {}; set +a\n\
         DENT8_AUTHORITY={}\n\
         DENT8_REQUIRE_AUTHORITY=1\n\
         {}\n\
         {}",
        shell_quote(&env_path.to_string_lossy()),
        shell_quote(&authority_path.to_string_lossy()),
        store.env_line(),
        witness.env_lines,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn init_base_message(
    dir: &std::path::Path,
    authority_path: &std::path::Path,
    source: &str,
    authority: AuthorityLevel,
    store: &InitStoreOutput,
    env_path: &std::path::Path,
    identity: &InitIdentityOutput,
    witness: &InitWitnessOutput,
    agent: Option<InitAgent>,
) -> String {
    let agent_summary = agent.map_or(String::new(), |agent| {
        format!("\n  agent profile: {}", agent.example_path())
    });
    let agent_next = agent.map_or(String::new(), |agent| {
        format!("\n\nAgent wiring:\n  see {}", agent.example_path())
    });
    format!(
        "initialized dent8 in {}\n  authority: {} (granted {} max={})\n  store: {}\n  env: {}{}{}{}\n\nNext:\n  set -a\n  . {}{}\n  set +a\n  dent8 doctor --source {} --write-check{}",
        dir.display(),
        authority_path.display(),
        source,
        authority,
        store.summary,
        env_path.display(),
        identity.summary,
        witness.summary,
        agent_summary,
        shell_quote(&env_path.to_string_lossy()),
        identity.env_load,
        source,
        agent_next,
    )
}

pub(crate) fn init_mcp_install(
    args: &InitArgs,
    dir: &std::path::Path,
) -> Result<Option<McpInstallAttempt>, String> {
    if !args.mcp.install_mcp {
        return Ok(None);
    }
    let agent = args
        .agent
        .ok_or_else(|| "`dent8 init --install-mcp` requires --agent".to_string())?;
    let mode = mcp_install_mode(args.mcp.mcp_dry_run, args.mcp.mcp_check);
    Ok(Some(mcp_install_attempt(
        agent,
        dir,
        args.mcp.mcp_config.clone(),
        args.mcp.mcp_command.clone(),
        args.mcp.mcp_local_bin,
        mode,
    )))
}

pub(crate) fn mcp_install_attempt(
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<String>,
    command: Option<String>,
    local_bin: bool,
    mode: mcp_config::InstallMode,
) -> McpInstallAttempt {
    let result = install_mcp_config_prepared_detail(
        agent,
        dir,
        config.as_deref(),
        command.as_deref(),
        local_bin,
        mode,
    );
    McpInstallAttempt {
        agent,
        dir: dir.to_path_buf(),
        config,
        command,
        local_bin,
        mode,
        result,
    }
}

pub(crate) fn init_json(args: &InitArgs, outcome: &InitOutcome) -> serde_json::Value {
    serde_json::json!({
        "status": init_status(outcome),
        "tool": "init",
        "exit_code": outcome.exit_code,
        "dir": path_string(&outcome.dir),
        "source": outcome.source.as_str(),
        "agent": outcome.agent.map(InitAgent::cli_name),
        "authority": {
            "path": path_string(&outcome.authority_path),
            "source": outcome.source.as_str(),
            "max_authority": outcome.authority_level.name(),
        },
        "store": {
            "kind": outcome.store.kind.name(),
            "env_key": outcome.store.env_key,
            "env_value": outcome.store.env_value.as_str(),
            "summary": outcome.store.summary.as_str(),
        },
        "env": {
            "path": path_string(&outcome.env_path),
            "load_command": format!("set -a; . {}; set +a", shell_quote(&outcome.env_path.to_string_lossy())),
        },
        "identity": init_identity_json(&outcome.identity),
        "witness": init_witness_json(&outcome.witness),
        "mcp_install": outcome.mcp_install.as_ref().map(mcp_install_attempt_json),
        "next": {
            "doctor_command": format!("dent8 doctor --source {} --write-check", outcome.source),
            "agent_example": outcome.agent.map(InitAgent::example_path),
        },
        "message": outcome.message.as_str(),
        "requested": {
            "dir": args.dir.as_str(),
            "store": args.store.name(),
            "store_url": args.store_url.as_deref(),
            "source": args.source.as_deref(),
            "agent": args.agent.map(InitAgent::cli_name),
            "identity": args.identity,
            "install_mcp": args.mcp.install_mcp,
        },
    })
}

pub(crate) fn init_status(outcome: &InitOutcome) -> &'static str {
    match outcome.mcp_install.as_ref() {
        Some(install) if install.result.is_err() => "partial",
        Some(install)
            if install
                .result
                .as_ref()
                .is_ok_and(|mcp| mcp_install_status(mcp) == "needs_update") =>
        {
            "needs_update"
        }
        _ => "ok",
    }
}

pub(crate) fn init_error_json(args: &InitArgs, message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "init",
        "dir": args.dir.as_str(),
        "source": args.source.as_deref(),
        "agent": args.agent.map(InitAgent::cli_name),
        "store": args.store.name(),
        "store_url": args.store_url.as_deref(),
        "install_mcp": args.mcp.install_mcp,
        "message": message,
    })
}

pub(crate) fn init_identity_json(identity: &InitIdentityOutput) -> serde_json::Value {
    if !identity.enabled {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "source": identity.source.as_deref(),
        "issuer": identity.issuer.as_deref(),
        "max_authority": identity.max_authority.map(AuthorityLevel::name),
        "scope": identity.scope.as_deref(),
        "issuer_key_path": identity.issuer_key_path.as_ref().map(|path| path_string(path)),
        "trust_file": identity.trust_file.as_ref().map(|path| path_string(path)),
        "active_grants_file": identity.active_grants_file.as_ref().map(|path| path_string(path)),
        "grant_file": identity.grant_file.as_ref().map(|path| path_string(path)),
        "source_key_path": identity.source_key_path.as_ref().map(|path| path_string(path)),
        "env_file": identity.env_file.as_ref().map(|path| path_string(path)),
    })
}

pub(crate) fn init_witness_json(witness: &InitWitnessOutput) -> serde_json::Value {
    if !witness.enabled {
        return serde_json::Value::Null;
    }
    serde_json::json!({
        "log_path": witness.log_path.as_ref().map(|path| path_string(path)),
        "pubkey_path": witness.pubkey_path.as_ref().map(|path| path_string(path)),
        "signing_key_configured": false,
    })
}

pub(crate) fn mcp_install_attempt_json(install: &McpInstallAttempt) -> serde_json::Value {
    match &install.result {
        Ok(outcome) => serde_json::json!({
            "status": mcp_install_status(outcome),
            "tool": "mcp install",
            "agent": install.agent.cli_name(),
            "dir": path_string(&install.dir),
            "mode": install.mode.name(),
            "dry_run": install.mode == mcp_config::InstallMode::DryRun,
            "check": install.mode == mcp_config::InstallMode::Check,
            "requested_command": install.command.as_deref(),
            "command_written": outcome.prepared.command.as_str(),
            "local_bin": install.local_bin,
            "exit_code": outcome.exit_code(),
            "config": {
                "path": outcome.config.path().display().to_string(),
                "action": outcome.config.action_name(),
                "changed": outcome.config.changed(),
                "written": outcome.config.written(),
                "contents": outcome.config.contents(),
            },
            "local_binary": outcome
                .prepared
                .local_bin
                .as_ref()
                .map(local_mcp_binary_json),
        }),
        Err(message) => serde_json::json!({
            "status": "failed",
            "tool": "mcp install",
            "agent": install.agent.cli_name(),
            "dir": path_string(&install.dir),
            "mode": install.mode.name(),
            "dry_run": install.mode == mcp_config::InstallMode::DryRun,
            "check": install.mode == mcp_config::InstallMode::Check,
            "requested_command": install.command.as_deref(),
            "local_bin": install.local_bin,
            "exit_code": 1,
            "message": message.as_str(),
        }),
    }
}

pub(crate) fn install_mcp_config_prepared(
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
    command: Option<&str>,
    local_bin: bool,
    mode: mcp_config::InstallMode,
) -> Result<String, String> {
    install_mcp_config_prepared_detail(agent, dir, config, command, local_bin, mode)
        .map(|install| install.message())
}

pub(crate) fn install_mcp_config_prepared_detail(
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
    command: Option<&str>,
    local_bin: bool,
    mode: mcp_config::InstallMode,
) -> Result<PreparedMcpInstall, String> {
    let prepared = prepare_mcp_command(dir, command, local_bin, mode)?;
    let dir = absolute_path(dir)?;
    let config = mcp_config::install(&mcp_config::InstallOptions {
        agent,
        dent8_dir: dir,
        config_path: config.map(std::path::PathBuf::from),
        command: prepared.command.clone(),
        mode,
    })?;
    Ok(PreparedMcpInstall { prepared, config })
}

pub(crate) struct PreparedMcpInstall {
    prepared: PreparedMcpCommand,
    config: mcp_config::InstallResult,
}

impl PreparedMcpInstall {
    fn message(&self) -> String {
        self.prepared.message.as_ref().map_or_else(
            || self.config.message(),
            |message| format!("{message}\n\n{}", self.config.message()),
        )
    }

    fn exit_code(&self) -> i32 {
        self.config.exit_code().max(self.prepared.exit_code)
    }
}

pub(crate) struct PreparedMcpCommand {
    command: String,
    message: Option<String>,
    exit_code: i32,
    local_bin: Option<PreparedLocalMcpBinary>,
}

pub(crate) struct PreparedLocalMcpBinary {
    wrapper: std::path::PathBuf,
    target: std::path::PathBuf,
    repo: std::path::PathBuf,
    action: &'static str,
    changed: bool,
    target_executable: bool,
    build_command: String,
}

pub(crate) fn mcp_install_json(
    args: &McpInstallArgs,
    outcome: &PreparedMcpInstall,
) -> serde_json::Value {
    serde_json::json!({
        "status": mcp_install_status(outcome),
        "tool": "mcp install",
        "agent": args.agent.cli_name(),
        "dir": args.dir.as_str(),
        "mode": outcome.config.mode_name(),
        "dry_run": args.dry_run,
        "check": args.check,
        "requested_command": args.command.as_deref(),
        "command_written": outcome.prepared.command.as_str(),
        "local_bin": args.local_bin,
        "exit_code": outcome.exit_code(),
        "config": {
            "path": outcome.config.path().display().to_string(),
            "action": outcome.config.action_name(),
            "changed": outcome.config.changed(),
            "written": outcome.config.written(),
            "contents": outcome.config.contents(),
        },
        "local_binary": outcome
            .prepared
            .local_bin
            .as_ref()
            .map(local_mcp_binary_json),
    })
}

pub(crate) fn mcp_install_status(outcome: &PreparedMcpInstall) -> &'static str {
    if outcome.exit_code() == 0 {
        "ok"
    } else if outcome.config.mode_name() == "check" {
        "needs_update"
    } else {
        "failed"
    }
}

pub(crate) fn local_mcp_binary_json(local: &PreparedLocalMcpBinary) -> serde_json::Value {
    serde_json::json!({
        "wrapper": local.wrapper.display().to_string(),
        "target": local.target.display().to_string(),
        "repo": local.repo.display().to_string(),
        "action": local.action,
        "changed": local.changed,
        "target_executable": local.target_executable,
        "build_command": local.build_command.as_str(),
    })
}

pub(crate) fn mcp_install_error_json(
    args: &McpInstallArgs,
    mode: mcp_config::InstallMode,
    message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "mcp install",
        "agent": args.agent.cli_name(),
        "dir": args.dir.as_str(),
        "mode": mode.name(),
        "dry_run": args.dry_run,
        "check": args.check,
        "requested_command": args.command.as_deref(),
        "local_bin": args.local_bin,
        "message": message,
    })
}

pub(crate) struct LocalMcpBinary {
    pub(crate) wrapper: std::path::PathBuf,
    pub(crate) target: std::path::PathBuf,
    pub(crate) repo: std::path::PathBuf,
}

pub(crate) fn prepare_mcp_command(
    dir: &std::path::Path,
    command: Option<&str>,
    local_bin: bool,
    mode: mcp_config::InstallMode,
) -> Result<PreparedMcpCommand, String> {
    if !local_bin {
        let command = command.unwrap_or("dent8");
        if command.trim().is_empty() {
            return Err("MCP command must not be empty".to_string());
        }
        return Ok(PreparedMcpCommand {
            command: command.to_string(),
            message: None,
            exit_code: 0,
            local_bin: None,
        });
    }

    let local = local_mcp_binary(dir)?;
    let expected = render_local_mcp_wrapper(&local);
    let existing = match std::fs::read_to_string(&local.wrapper) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("cannot read {}: {error}", local.wrapper.display())),
    };
    let changed = existing.as_deref() != Some(expected.as_str());
    let action = match (existing.is_some(), changed) {
        (false, _) => "created",
        (true, true) => "updated",
        (true, false) => "unchanged",
    };
    let target_ok = is_executable_file(&local.target);

    if mode == mcp_config::InstallMode::Write && !target_ok {
        return Err(local_mcp_missing_target_message(&local));
    }

    if mode == mcp_config::InstallMode::Write && changed {
        if let Some(parent) = local.wrapper.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        write_atomic(&local.wrapper.to_string_lossy(), &expected)?;
        restrict_executable_owner_only(&local.wrapper)?;
    }

    let (header, exit_code) = match mode {
        mcp_config::InstallMode::Write => (
            format!("{} local MCP wrapper: {}", action, local.wrapper.display()),
            0,
        ),
        mcp_config::InstallMode::DryRun => (
            format!(
                "{} local MCP wrapper: {}",
                dry_run_local_bin_action(action),
                local.wrapper.display()
            ),
            0,
        ),
        mcp_config::InstallMode::Check if !changed && target_ok => (
            format!("local MCP wrapper up to date: {}", local.wrapper.display()),
            0,
        ),
        mcp_config::InstallMode::Check => (
            format!(
                "local MCP wrapper needs update: {}",
                local.wrapper.display()
            ),
            1,
        ),
    };
    let build_command = local_mcp_build_command(&local);
    let mut message = format!(
        "{header}\n  target: {}\n  build: {}",
        local.target.display(),
        build_command
    );
    if !target_ok {
        message.push_str("\n  status: target is missing or not executable");
    }

    Ok(PreparedMcpCommand {
        command: local.wrapper.to_string_lossy().into_owned(),
        message: Some(message),
        exit_code,
        local_bin: Some(PreparedLocalMcpBinary {
            wrapper: local.wrapper,
            target: local.target,
            repo: local.repo,
            action,
            changed,
            target_executable: target_ok,
            build_command,
        }),
    })
}

pub(crate) fn dry_run_local_bin_action(action: &str) -> &'static str {
    match action {
        "created" => "would create",
        "updated" => "would update",
        "unchanged" => "would leave unchanged",
        _ => "prepared",
    }
}

pub(crate) fn local_mcp_binary(dir: &std::path::Path) -> Result<LocalMcpBinary, String> {
    let dir = absolute_path(dir)?;
    let repo = dir
        .parent()
        .ok_or_else(|| format!("{} has no parent project directory", dir.display()))?
        .to_path_buf();
    Ok(LocalMcpBinary {
        wrapper: dir.join("bin/dent8"),
        target: dir.join("target-sqlite/debug/dent8"),
        repo,
    })
}

pub(crate) fn render_local_mcp_wrapper(local: &LocalMcpBinary) -> String {
    format!(
        "#!/bin/sh\n\
         set -eu\n\n\
         repo={}\n\
         cd \"$repo\"\n\n\
         bin={}\n\
         if [ ! -x \"$bin\" ]; then\n\
         \x20 echo \"dent8 dogfood binary is missing: $bin\" >&2\n\
         \x20 echo \"build it with: {}\" >&2\n\
         \x20 exit 127\n\
         fi\n\n\
         exec \"$bin\" \"$@\"\n",
        shell_quote(&local.repo.to_string_lossy()),
        shell_quote(&local.target.to_string_lossy()),
        local_mcp_build_command(local).replace('"', "\\\""),
    )
}

pub(crate) fn local_mcp_build_command(local: &LocalMcpBinary) -> String {
    format!(
        "CARGO_TARGET_DIR={} cargo build -p dent8 --features sqlite,witness",
        shell_quote(
            &local
                .target
                .parent()
                .and_then(std::path::Path::parent)
                .unwrap_or(&local.repo)
                .to_string_lossy()
        )
    )
}

pub(crate) fn local_mcp_missing_target_message(local: &LocalMcpBinary) -> String {
    format!(
        "local MCP binary target is missing or not executable: {}; build it with `{}`",
        local.target.display(),
        local_mcp_build_command(local)
    )
}

pub(crate) fn is_executable_file(path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

pub(crate) fn restrict_executable_owner_only(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot chmod 0700 {}: {error}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

pub(crate) fn mcp_install_mode(dry_run: bool, check: bool) -> mcp_config::InstallMode {
    match (dry_run, check) {
        (true, _) => mcp_config::InstallMode::DryRun,
        (false, true) => mcp_config::InstallMode::Check,
        (false, false) => mcp_config::InstallMode::Write,
    }
}

#[cfg_attr(not(feature = "identity"), allow(clippy::unnecessary_wraps))]
pub(crate) fn preflight_identity(
    args: &InitArgs,
    dir: &std::path::Path,
    source: &str,
    enabled: bool,
) -> Result<(), String> {
    #[cfg(feature = "identity")]
    {
        if enabled {
            identity::preflight_bootstrap_bundle(
                &dir.to_string_lossy(),
                source,
                &args.issuer,
                args.issuer_key.as_deref(),
                &args.identity_scope,
            )?;
        }
        Ok(())
    }
    #[cfg(not(feature = "identity"))]
    {
        let _ = (args, dir, source, enabled);
        Ok(())
    }
}

pub(crate) struct InitIdentityOutput {
    enabled: bool,
    summary: String,
    env_load: String,
    source: Option<String>,
    issuer: Option<String>,
    max_authority: Option<AuthorityLevel>,
    scope: Option<String>,
    issuer_key_path: Option<std::path::PathBuf>,
    trust_file: Option<std::path::PathBuf>,
    active_grants_file: Option<std::path::PathBuf>,
    grant_file: Option<std::path::PathBuf>,
    source_key_path: Option<std::path::PathBuf>,
    env_file: Option<std::path::PathBuf>,
}

#[cfg_attr(not(feature = "identity"), allow(clippy::unnecessary_wraps))]
pub(crate) fn init_identity(
    args: &InitArgs,
    dir: &std::path::Path,
    source: &str,
    enabled: bool,
) -> Result<InitIdentityOutput, String> {
    #[cfg(feature = "identity")]
    {
        if !enabled {
            return Ok(InitIdentityOutput {
                enabled: false,
                summary: String::new(),
                env_load: String::new(),
                source: None,
                issuer: None,
                max_authority: None,
                scope: None,
                issuer_key_path: None,
                trust_file: None,
                active_grants_file: None,
                grant_file: None,
                source_key_path: None,
                env_file: None,
            });
        }
        let identity = identity::bootstrap_bundle(
            &dir.to_string_lossy(),
            source,
            &args.issuer,
            args.issuer_key.as_deref(),
            args.authority,
            &args.identity_scope,
            args.identity_expires_at_ms,
        )?;
        let env_load = format!(
            "\n  . {}",
            shell_quote(&identity.env_file.to_string_lossy())
        );
        let summary = format!(
            "\n  identity: {} (source key: {})\n  identity env: {}",
            identity.grant_file.display(),
            identity.source_key_path.display(),
            identity.env_file.display(),
        );
        Ok(InitIdentityOutput {
            enabled: true,
            summary,
            env_load,
            source: Some(identity.source),
            issuer: Some(identity.issuer),
            max_authority: Some(identity.max_authority),
            scope: Some(identity.scope),
            issuer_key_path: Some(identity.issuer_key_path),
            trust_file: Some(identity.trust_file),
            active_grants_file: Some(identity.active_grants_file),
            grant_file: Some(identity.grant_file),
            source_key_path: Some(identity.source_key_path),
            env_file: Some(identity.env_file),
        })
    }
    #[cfg(not(feature = "identity"))]
    {
        let _ = (args, dir, source, enabled);
        Ok(InitIdentityOutput {
            enabled: false,
            summary: String::new(),
            env_load: String::new(),
            source: None,
            issuer: None,
            max_authority: None,
            scope: None,
            issuer_key_path: None,
            trust_file: None,
            active_grants_file: None,
            grant_file: None,
            source_key_path: None,
            env_file: None,
        })
    }
}

pub(crate) struct InitWitnessOutput {
    enabled: bool,
    summary: String,
    env_lines: String,
    log_path: Option<std::path::PathBuf>,
    pubkey_path: Option<std::path::PathBuf>,
}

pub(crate) fn init_witness(
    args: &InitArgs,
    dir: &std::path::Path,
) -> Result<InitWitnessOutput, String> {
    let enabled = args.witness || args.witness_log.is_some() || args.witness_pubkey.is_some();
    if !enabled {
        return Ok(InitWitnessOutput {
            enabled: false,
            summary: String::new(),
            env_lines: String::new(),
            log_path: None,
            pubkey_path: None,
        });
    }

    let log_path = init_optional_path(
        args.witness_log.as_deref(),
        dir.join("witness.jsonl"),
        "witness log",
    )?;
    let pubkey_path = init_optional_path(
        args.witness_pubkey.as_deref(),
        dir.join("witness.key.pub"),
        "witness public key",
    )?;

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("cannot create {}: {error}", log_path.display()))?;
    if let Some(parent) = pubkey_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }

    Ok(InitWitnessOutput {
        enabled: true,
        summary: format!(
            "\n  witness: {} (public key: {}; verification config only)",
            log_path.display(),
            pubkey_path.display()
        ),
        env_lines: format!(
            "DENT8_WITNESS_LOG={}\nDENT8_WITNESS_PUBKEY={}\n",
            shell_quote(&log_path.to_string_lossy()),
            shell_quote(&pubkey_path.to_string_lossy())
        ),
        log_path: Some(log_path),
        pubkey_path: Some(pubkey_path),
    })
}

pub(crate) fn init_optional_path(
    value: Option<&str>,
    default: std::path::PathBuf,
    label: &str,
) -> Result<std::path::PathBuf, String> {
    value.map_or(Ok(default), |path| {
        absolute_path(std::path::Path::new(path)).map_err(|error| format!("{label}: {error}"))
    })
}

pub(crate) fn init_source(args: &InitArgs) -> String {
    args.source
        .clone()
        .or_else(|| args.agent.map(|agent| agent.source().to_string()))
        .unwrap_or_else(|| "source:local".to_string())
}

impl InitStoreOutput {
    fn env_line(&self) -> String {
        format!("{}={}", self.env_key, shell_quote(&self.env_value))
    }
}

pub(crate) fn init_store_output(
    store: InitStore,
    store_url: Option<&str>,
    dir: &std::path::Path,
    agent: Option<InitAgent>,
) -> Result<InitStoreOutput, String> {
    match store {
        InitStore::File => {
            let log = init_file_log_path(dir, agent);
            let env_value = log.to_string_lossy().into_owned();
            Ok(InitStoreOutput {
                kind: store,
                env_key: "DENT8_LOG",
                env_value,
                summary: format!("file dev log at {}", log.display()),
            })
        }
        InitStore::Sqlite => {
            let url = store_url.map_or_else(
                || format!("sqlite://{}", dir.join("dent8.db").display()),
                str::to_string,
            );
            Ok(InitStoreOutput {
                kind: store,
                env_key: "DENT8_STORE_URL",
                env_value: url.clone(),
                summary: format!("SQLite backend at {url} (included in the stock build)"),
            })
        }
        InitStore::Postgres => {
            let Some(url) = store_url else {
                return Err(
                    "`dent8 init --store postgres` needs `--store-url postgres://...`".to_string(),
                );
            };
            Ok(InitStoreOutput {
                kind: store,
                env_key: "DENT8_STORE_URL",
                env_value: url.to_string(),
                summary: format!(
                    "Postgres backend at {url} (requires `--features postgres` build)"
                ),
            })
        }
    }
}

pub(crate) fn init_file_log_path(
    dir: &std::path::Path,
    agent: Option<InitAgent>,
) -> std::path::PathBuf {
    dir.join(agent.map_or("memory.jsonl", InitAgent::file_log_name))
}
