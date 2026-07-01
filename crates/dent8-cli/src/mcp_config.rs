use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::{InitAgent, write_atomic};

pub(crate) struct InstallOptions {
    pub(crate) agent: InitAgent,
    pub(crate) dent8_dir: PathBuf,
    pub(crate) config_path: Option<PathBuf>,
    pub(crate) command: String,
    pub(crate) mode: InstallMode,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum InstallMode {
    Write,
    DryRun,
    Check,
}

pub(crate) struct InstallResult {
    action: ConfigAction,
    mode: InstallMode,
    path: PathBuf,
    contents: String,
}

impl InstallResult {
    pub(crate) fn message(&self) -> String {
        let header = match self.mode {
            InstallMode::Write => format!(
                "{} MCP config: {}",
                self.action.write_verb(),
                self.path.display()
            ),
            InstallMode::DryRun => {
                format!(
                    "{} MCP config: {}",
                    self.action.dry_run_verb(),
                    self.path.display()
                )
            }
            InstallMode::Check => {
                if self.action == ConfigAction::Unchanged {
                    format!("MCP config up to date: {}", self.path.display())
                } else {
                    format!("MCP config needs update: {}", self.path.display())
                }
            }
        };
        let label = match self.mode {
            InstallMode::Write => self.path.display().to_string(),
            InstallMode::DryRun => format!("{} (dry run)", self.path.display()),
            InstallMode::Check if self.action == ConfigAction::Unchanged => {
                format!("{} (current)", self.path.display())
            }
            InstallMode::Check => format!("{} (expected)", self.path.display()),
        };
        format!("{header}\n\n--- {label} ---\n{}", self.contents)
    }

    pub(crate) fn exit_code(&self) -> i32 {
        i32::from(self.mode == InstallMode::Check && self.action != ConfigAction::Unchanged)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum ConfigAction {
    Created,
    Updated,
    Unchanged,
}

impl ConfigAction {
    fn write_verb(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Updated => "updated",
            Self::Unchanged => "unchanged",
        }
    }

    fn dry_run_verb(self) -> &'static str {
        match self {
            Self::Created => "would create",
            Self::Updated => "would update",
            Self::Unchanged => "would leave unchanged",
        }
    }
}

#[derive(Copy, Clone)]
enum ConfigFormat {
    CodexToml,
    McpServersJson,
    HecateTaskJson,
}

pub(crate) fn install(options: &InstallOptions) -> Result<InstallResult, String> {
    if options.command.trim().is_empty() {
        return Err("MCP command must not be empty".to_string());
    }
    let dent8_dir = absolute_path(&options.dent8_dir)?;
    let env = load_agent_env(&dent8_dir, options.agent)?;
    let target = target_config_path(options.agent, options.config_path.as_deref(), &dent8_dir)?;
    let format = config_format(options.agent);
    let existing = match std::fs::read_to_string(&target) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("cannot read {}: {error}", target.display())),
    };
    let rendered = match format {
        ConfigFormat::CodexToml => patch_codex_toml(
            existing.as_deref().unwrap_or_default(),
            &options.command,
            &env,
        )?,
        ConfigFormat::McpServersJson => patch_mcp_servers_json(
            existing.as_deref().unwrap_or_default(),
            options.agent,
            &options.command,
            &env,
        )?,
        ConfigFormat::HecateTaskJson => patch_hecate_task_json(
            existing.as_deref().unwrap_or_default(),
            &options.command,
            &env,
        )?,
    };

    let changed = existing.as_deref() != Some(rendered.as_str());
    let action = match (existing.is_some(), changed) {
        (false, _) => ConfigAction::Created,
        (true, true) => ConfigAction::Updated,
        (true, false) => ConfigAction::Unchanged,
    };

    if options.mode == InstallMode::Write && changed {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        write_atomic(&target.to_string_lossy(), &rendered)?;
    }

    Ok(InstallResult {
        action,
        mode: options.mode,
        path: target,
        contents: rendered,
    })
}

pub(crate) fn load_agent_env(
    dir: &Path,
    agent: InitAgent,
) -> Result<BTreeMap<String, String>, String> {
    let env_path = dir.join("env");
    let identity_env_path = dir.join("identity.env");
    let mut env = read_env_file(&env_path).map_err(|error| {
        format!(
            "{error}; run `dent8 init --agent {}` before installing MCP config",
            agent.cli_name()
        )
    })?;
    let identity_env = read_env_file(&identity_env_path).map_err(|error| {
        format!(
            "{error}; run `dent8 init --agent {}` before installing MCP config",
            agent.cli_name()
        )
    })?;
    env.extend(identity_env);

    for key in [
        "DENT8_AUTHORITY",
        "DENT8_REQUIRE_AUTHORITY",
        "DENT8_TRUST",
        "DENT8_REQUIRE_IDENTITY",
        "DENT8_GRANT",
        "DENT8_IDENTITY_KEY",
    ] {
        require_env_key(&env, key)?;
    }
    if !env.contains_key("DENT8_LOG") && !env.contains_key("DENT8_STORE_URL") {
        return Err(format!(
            "{} must define DENT8_LOG or DENT8_STORE_URL",
            env_path.display()
        ));
    }
    if let Some(log) = env.get("DENT8_LOG")
        && !log.ends_with(agent.file_log_name())
    {
        return Err(format!(
            "{} points at {log}, but --agent {} expects {}",
            env_path.display(),
            agent.cli_name(),
            agent.file_log_name()
        ));
    }

    let slug = agent.source_slug();
    let expected_grant = format!("grants/{slug}.grant.json");
    let expected_key = format!("identities/{slug}.key");
    let grant = require_env_key(&env, "DENT8_GRANT")?;
    let key = require_env_key(&env, "DENT8_IDENTITY_KEY")?;
    if !grant.ends_with(&expected_grant) {
        return Err(format!(
            "DENT8_GRANT points at {grant}, but --agent {} expects a {expected_grant} grant",
            agent.cli_name()
        ));
    }
    if !key.ends_with(&expected_key) {
        return Err(format!(
            "DENT8_IDENTITY_KEY points at {key}, but --agent {} expects an {expected_key} key",
            agent.cli_name()
        ));
    }

    Ok(env)
}

fn require_env_key<'a>(env: &'a BTreeMap<String, String>, key: &str) -> Result<&'a String, String> {
    env.get(key)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("generated dent8 env is missing {key}"))
}

fn read_env_file(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut env = BTreeMap::new();
    for (line_no, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "{}:{} is not a KEY=VALUE line",
                path.display(),
                line_no + 1
            ));
        };
        env.insert(key.trim().to_string(), shell_unquote(value.trim()));
    }
    Ok(env)
}

fn shell_unquote(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        value[1..value.len() - 1].replace("'\\''", "'")
    } else {
        value.to_string()
    }
}

fn target_config_path(
    agent: InitAgent,
    override_path: Option<&Path>,
    dent8_dir: &Path,
) -> Result<PathBuf, String> {
    if let Some(path) = override_path {
        return absolute_path(path);
    }
    let root = project_root_for(dent8_dir).ok_or_else(|| {
        format!(
            "cannot infer an MCP config path from --dir {}; use a .dent8 directory or pass --config PATH (`dent8 init` uses --mcp-config PATH)",
            dent8_dir.display()
        )
    })?;
    default_config_path(agent, &root).ok_or_else(|| {
        "`dent8 mcp install --agent hecate` needs --config because Hecate MCP servers live in a task/UI payload, not a stable project config file".to_string()
    })
}

fn project_root_for(dent8_dir: &Path) -> Option<PathBuf> {
    if dent8_dir.file_name().is_some_and(|name| name == ".dent8")
        && let Some(parent) = dent8_dir.parent()
    {
        return Some(parent.to_path_buf());
    }
    None
}

fn default_config_path(agent: InitAgent, root: &Path) -> Option<PathBuf> {
    match agent {
        InitAgent::Codex => Some(root.join(".codex/config.toml")),
        InitAgent::ClaudeCode | InitAgent::GrokBuild => Some(root.join(".mcp.json")),
        InitAgent::Cursor => Some(root.join(".cursor/mcp.json")),
        InitAgent::Gemini => Some(root.join(".gemini/settings.json")),
        InitAgent::Cascade => Some(root.join(".windsurf/mcp_config.json")),
        InitAgent::Hecate => None,
    }
}

fn config_format(agent: InitAgent) -> ConfigFormat {
    match agent {
        InitAgent::Codex => ConfigFormat::CodexToml,
        InitAgent::Hecate => ConfigFormat::HecateTaskJson,
        InitAgent::ClaudeCode
        | InitAgent::Cursor
        | InitAgent::GrokBuild
        | InitAgent::Gemini
        | InitAgent::Cascade => ConfigFormat::McpServersJson,
    }
}

fn patch_codex_toml(
    existing: &str,
    command: &str,
    env: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut doc = if existing.trim().is_empty() {
        DocumentMut::new()
    } else {
        existing
            .parse::<DocumentMut>()
            .map_err(|error| format!("cannot parse TOML MCP config: {error}"))?
    };

    let mut server = Table::new();
    server["command"] = value(command);
    let mut args = Array::new();
    args.push("mcp");
    args.push("serve");
    server["args"] = value(args);
    server["startup_timeout_sec"] = value(20);
    server["tool_timeout_sec"] = value(60);
    let mut env_table = Table::new();
    for (key, value_text) in env {
        env_table[key] = value(value_text.as_str());
    }
    server["env"] = Item::Table(env_table);

    let root = doc.as_table_mut();
    let mcp_servers = ensure_table(root, "mcp_servers");
    mcp_servers["dent8"] = Item::Table(server);
    Ok(ensure_trailing_newline(doc.to_string()))
}

fn ensure_table<'a>(table: &'a mut Table, key: &str) -> &'a mut Table {
    if !table.contains_key(key) || !table[key].is_table() {
        table[key] = Item::Table(Table::new());
    }
    table[key]
        .as_table_mut()
        .expect("table item should be a table")
}

fn patch_mcp_servers_json(
    existing: &str,
    agent: InitAgent,
    command: &str,
    env: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut root = parse_json_object(existing, "MCP config")?;
    let servers = object_entry(root.as_object_mut().expect("root object"), "mcpServers")?;
    servers.insert(
        "dent8".to_string(),
        mcp_server_json(agent, command, env, false),
    );
    serde_json::to_string_pretty(&root)
        .map(ensure_trailing_newline)
        .map_err(|error| format!("cannot serialize MCP config: {error}"))
}

fn patch_hecate_task_json(
    existing: &str,
    command: &str,
    env: &BTreeMap<String, String>,
) -> Result<String, String> {
    let mut root = parse_json_object(existing, "Hecate config")?;
    let object = root.as_object_mut().expect("root object");
    let servers = object
        .entry("mcp_servers")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| "Hecate config field mcp_servers must be an array".to_string())?;
    let server = mcp_server_json(InitAgent::Hecate, command, env, true);
    if let Some(existing) = servers
        .iter_mut()
        .find(|value| value.get("name").and_then(Value::as_str) == Some("dent8"))
    {
        *existing = server;
    } else {
        servers.push(server);
    }
    serde_json::to_string_pretty(&root)
        .map(ensure_trailing_newline)
        .map_err(|error| format!("cannot serialize Hecate config: {error}"))
}

fn parse_json_object(existing: &str, label: &str) -> Result<Value, String> {
    if existing.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    let value = serde_json::from_str::<Value>(existing)
        .map_err(|error| format!("cannot parse {label} JSON: {error}"))?;
    if !value.is_object() {
        return Err(format!("{label} JSON root must be an object"));
    }
    Ok(value)
}

fn object_entry<'a>(
    object: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>, String> {
    object
        .entry(key)
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| format!("{key} must be an object"))
}

fn mcp_server_json(
    agent: InitAgent,
    command: &str,
    env: &BTreeMap<String, String>,
    hecate_shape: bool,
) -> Value {
    let mut server = Map::new();
    if hecate_shape {
        server.insert("name".to_string(), json!("dent8"));
    }
    server.insert("command".to_string(), json!(command));
    server.insert("args".to_string(), json!(["mcp", "serve"]));
    server.insert("env".to_string(), json!(env));
    match agent {
        InitAgent::ClaudeCode => {
            server.insert("timeout".to_string(), json!(60_000));
        }
        InitAgent::Gemini => {
            server.insert("timeout".to_string(), json!(30_000));
            server.insert("trust".to_string(), json!(false));
        }
        InitAgent::Hecate => {
            server.insert("approval_policy".to_string(), json!("require_approval"));
        }
        InitAgent::Codex | InitAgent::Cursor | InitAgent::GrokBuild | InitAgent::Cascade => {}
    }
    Value::Object(server)
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map_err(|error| format!("cannot read current directory: {error}"))
            .map(|cwd| cwd.join(path))
    }
}

fn ensure_trailing_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}
