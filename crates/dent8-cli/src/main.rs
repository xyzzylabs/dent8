use std::{
    io::IsTerminal,
    str::FromStr,
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use clap::builder::styling::{AnsiColor, Styles};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use dent8_core::{
    ActorId, AuthorityLevel, ClaimEvent, ClaimId, ClaimLifecycle, ClaimValue, EntityRef, Predicate,
    TimestampMillis,
};
#[cfg(test)]
use dent8_core::{
    Authority, ClaimEventId, ClaimEventKind, Confidence, Evidence, EvidenceId, EvidenceKind,
    Provenance, Ttl,
};
#[cfg(test)]
use dent8_store::StoreError;
use dent8_store::{
    EventFilter, EventStore, InMemoryEventStore, IntegrityReceipt, LineageIssue, PredicateRegistry,
    replay_entity, tainted_claims,
};
use dent8_store_postgres::{EVENT_LOG_SCHEMA_SQL, MATERIALIZATION_SCHEMA_SQL};

mod doctor;
mod hook;
#[cfg(feature = "identity")]
mod identity;
mod mcp;
mod mcp_config;
mod ops;
mod setup;
#[cfg(feature = "witness")]
mod witness;

const DEFAULT_MCP_SMOKE_TIMEOUT: Duration = Duration::from_secs(10);
const JSON_SUPPORTED_COMMANDS: &str = "assert, supersede, retract, contradict, derive, reinforce, \
                                      expire, explain, replay, facts list, verify, conflicts, \
                                      eval, init, agent add, authority, identity <subcommand>, \
                                      doctor, completions, export, witness <subcommand>, schema \
                                      postgres, mcp install";

fn main() {
    let code = run(std::env::args().skip(1));
    std::process::exit(code);
}

fn run(raw_args: impl IntoIterator<Item = String>) -> i32 {
    let raw_args: Vec<String> = raw_args.into_iter().collect();
    let color = requested_color(&raw_args).unwrap_or(CliColor::Auto);
    set_color(color);

    let argv = std::iter::once("dent8".to_string()).chain(raw_args);
    let command = Cli::command()
        .color(color.clap_choice())
        .styles(cli_styles());
    match command
        .try_get_matches_from(argv)
        .and_then(|matches| Cli::from_arg_matches(&matches))
    {
        Ok(cli) => run_cli(cli),
        Err(error) => {
            let _ = error.print();
            error.exit_code()
        }
    }
}

fn run_cli(cli: Cli) -> i32 {
    set_color(cli.color);
    if let Some(command) = cli.command.as_ref()
        && cli.output == CliOutput::Json
        && !command.supports_json_output()
    {
        eprintln!(
            "`dent8 {}` does not support `--output json` yet (supported: {JSON_SUPPORTED_COMMANDS})",
            command.cli_name()
        );
        return 2;
    }
    match cli.command {
        None => {
            if cli.output == CliOutput::Json {
                eprintln!(
                    "`dent8 --output json` requires a command (supported: {JSON_SUPPORTED_COMMANDS})"
                );
                return 2;
            }
            let mut command = Cli::command()
                .color(cli.color.clap_choice())
                .styles(cli_styles());
            let _ = command.print_help();
            println!();
            0
        }
        Some(CliCommand::Verify) => cmd_verify(cli.output),
        Some(CliCommand::Conflicts) => ops::cmd_conflicts(cli.output),
        Some(CliCommand::Eval) => cmd_eval(cli.output),
        Some(CliCommand::Init(args)) => setup::cmd_init(&args, cli.output),
        Some(CliCommand::Agent(args)) => match args.command {
            AgentCommand::Add(args) => setup::cmd_agent_add(&args, cli.output),
        },
        Some(CliCommand::Doctor(args)) => doctor::cmd_doctor(&args, cli.output),
        Some(CliCommand::Completions(args)) => cmd_completions(args.shell, cli.output),
        Some(CliCommand::Export(args)) => {
            #[cfg(feature = "export")]
            {
                cmd_export(&args.out, cli.output)
            }
            #[cfg(not(feature = "export"))]
            {
                cmd_export_unavailable(&args.out, cli.output)
            }
        }
        Some(CliCommand::Assert(args)) => ops::cmd_assert(&args, cli.output),
        Some(CliCommand::Derive(args)) => ops::cmd_derive(&args, cli.output),
        Some(CliCommand::Supersede(args)) => ops::cmd_supersede(&args, cli.output),
        Some(CliCommand::Retract(args)) => ops::cmd_retract(&args, cli.output),
        Some(CliCommand::Reinforce(args)) => ops::cmd_reinforce(&args, cli.output),
        Some(CliCommand::Expire(args)) => ops::cmd_expire(&args, cli.output),
        Some(CliCommand::Contradict(args)) => ops::cmd_contradict(&args, cli.output),
        Some(CliCommand::Explain(args)) => ops::cmd_explain(&args, cli.output),
        Some(CliCommand::Replay(args)) => ops::cmd_replay(&args, cli.output),
        Some(CliCommand::Facts(args)) => match args.command {
            FactsCommand::List(args) => ops::cmd_facts_list(&args, cli.output),
        },
        Some(CliCommand::Authority(args)) => match args.command {
            AuthorityCommand::List => cmd_authority_list(cli.output),
            AuthorityCommand::Add(args) => cmd_authority_add(
                &args.source,
                args.max.level(),
                args.issuer.as_deref(),
                args.scope.as_deref(),
                cli.output,
            ),
            AuthorityCommand::Remove(args) => cmd_authority_remove(&args.source, cli.output),
        },
        Some(CliCommand::Identity(args)) => run_identity(&args.command, cli.output),
        Some(CliCommand::Hook(args)) => match args.command {
            HookCommand::NativeMemoryGuard => hook::cmd_hook_native_memory_guard(),
        },
        Some(CliCommand::Mcp(args)) => match args.command {
            McpCommand::Serve => mcp::serve(),
            McpCommand::Install(args) => setup::cmd_mcp_install(&args, cli.output),
        },
        Some(CliCommand::Schema(args)) => match args.command {
            SchemaCommand::Postgres => cmd_schema_postgres(cli.output),
        },
        Some(CliCommand::Witness(args)) => run_witness(&args.args, cli.output),
    }
}

const CLI_AFTER_HELP: &str = "\
Subject is written as <kind>:<key>, e.g. person:alice or repo:dent8.
Example: dent8 assert person:alice favorite_drink tea --authority high --source user:alice

Storage: a JSON-lines dev log by default (DENT8_LOG, default ./dent8-log.jsonl), or an
async backend selected by DENT8_STORE_URL, dispatched by scheme (postgres:// needs
--features postgres). authority is one of: low | medium | high | canonical.
Authority ceiling: a source may assert at most its registered max. Enforced once a registry
exists (DENT8_AUTHORITY, default ./dent8-authority.json) — then deny-by-default: an unlisted
source is blocked from writing. Without a registry the CLI is permissive (dev mode), unless
DENT8_REQUIRE_AUTHORITY=1 is set. The registry is host-local config, independent of the event
backend. issuer/scope are recorded but NOT enforced in v0. See docs/STATUS.md.";

fn cli_styles() -> Styles {
    Styles::styled()
        .header(AnsiColor::Green.on_default().bold())
        .usage(AnsiColor::Green.on_default().bold())
        .literal(AnsiColor::Cyan.on_default().bold())
        .placeholder(AnsiColor::Yellow.on_default())
        .valid(AnsiColor::Green.on_default())
        .invalid(AnsiColor::Red.on_default().bold())
        .error(AnsiColor::Red.on_default().bold())
}

#[derive(Parser, Debug)]
#[command(
    name = "dent8",
    version,
    about = "A memory firewall for coding agents",
    after_help = CLI_AFTER_HELP,
    styles = cli_styles(),
    disable_help_subcommand = true
)]
struct Cli {
    /// When to use terminal colors.
    #[arg(long, global = true, value_enum, default_value_t = CliColor::Auto)]
    color: CliColor,
    /// Output format for supported read/audit commands.
    #[arg(long, global = true, value_enum, default_value_t = CliOutput::Text)]
    output: CliOutput,
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Assert a fact through the firewall, persisted to the log.
    #[command(
        override_usage = "dent8 assert <SUBJECT> <PREDICATE> <VALUE> --authority <AUTHORITY> --source <SOURCE>"
    )]
    Assert(ValueWriteArgs),
    /// Revise the believed fact, rejected if it cannot out-rank the incumbent.
    #[command(
        override_usage = "dent8 supersede <SUBJECT> <PREDICATE> <NEW_VALUE> --authority <AUTHORITY> --source <SOURCE>"
    )]
    Supersede(ValueWriteArgs),
    /// Remove the believed fact, rejected if it cannot out-rank the incumbent.
    #[command(
        override_usage = "dent8 retract <SUBJECT> <PREDICATE> --authority <AUTHORITY> --source <SOURCE>"
    )]
    Retract(FactWriteArgs),
    /// Flag a conflict (dissent): contest the fact, keep both.
    #[command(
        override_usage = "dent8 contradict <SUBJECT> <PREDICATE> <OPPOSING_VALUE> --authority <AUTHORITY> --source <SOURCE>"
    )]
    Contradict(ValueWriteArgs),
    /// Assert a fact derived from another fact, recording a dependency edge.
    #[command(
        override_usage = "dent8 derive <SUBJECT> <PREDICATE> <VALUE> --from <SOURCE_SUBJECT> <SOURCE_PREDICATE> --authority <AUTHORITY> --source <SOURCE>"
    )]
    Derive(DeriveWriteArgs),
    /// Corroborate the believed fact without restating its value.
    #[command(
        override_usage = "dent8 reinforce <SUBJECT> <PREDICATE> --authority <AUTHORITY> --source <SOURCE>"
    )]
    Reinforce(FactWriteArgs),
    /// Terminally expire the believed fact.
    #[command(
        override_usage = "dent8 expire <SUBJECT> <PREDICATE> --authority <AUTHORITY> --source <SOURCE>"
    )]
    Expire(FactWriteArgs),
    /// Explain the believed fact, with an integrity receipt.
    Explain(ReadFactArgs),
    /// Replay the full event history for a fact.
    Replay(ReadFactArgs),
    /// Browse fact streams known to dent8.
    Facts(FactsArgs),
    /// Check log integrity.
    Verify,
    /// List contested facts.
    Conflicts,
    /// Run the adversarial corpus.
    Eval,
    /// Bootstrap a local dent8 project configuration.
    Init(InitArgs),
    /// Add an agent profile to an existing shared dent8 bundle.
    Agent(AgentArgs),
    /// Diagnose the current dent8 setup.
    Doctor(DoctorArgs),
    /// Generate shell completion scripts.
    #[command(visible_aliases = ["completion", "autocomplete"])]
    Completions(CompletionsArgs),
    /// Export the log to Parquet for `DuckDB` analysis.
    Export(ExportArgs),
    /// Manage the source -> authority ceiling.
    Authority(AuthorityArgs),
    /// Manage signed source identity keys and grants.
    Identity(IdentityArgs),
    /// Provider hook helpers.
    Hook(HookArgs),
    /// Emit/verify Ed25519 signed tree heads.
    Witness(WitnessArgs),
    /// Print schemas.
    Schema(SchemaArgs),
    /// Serve dent8 over MCP.
    Mcp(McpArgs),
}

impl CliCommand {
    fn supports_json_output(&self) -> bool {
        match self {
            Self::Witness(_) => true,
            _ => matches!(
                self,
                Self::Assert(_)
                    | Self::Supersede(_)
                    | Self::Retract(_)
                    | Self::Contradict(_)
                    | Self::Derive(_)
                    | Self::Reinforce(_)
                    | Self::Expire(_)
                    | Self::Explain(_)
                    | Self::Replay(_)
                    | Self::Facts(_)
                    | Self::Verify
                    | Self::Conflicts
                    | Self::Eval
                    | Self::Init(_)
                    | Self::Agent(AgentArgs {
                        command: AgentCommand::Add(_),
                    })
                    | Self::Authority(_)
                    | Self::Identity(_)
                    | Self::Doctor(_)
                    | Self::Completions(_)
                    | Self::Export(_)
                    | Self::Schema(_)
                    | Self::Mcp(McpArgs {
                        command: McpCommand::Install(_),
                    })
            ),
        }
    }

    fn cli_name(&self) -> &'static str {
        match self {
            Self::Assert(_) => "assert",
            Self::Supersede(_) => "supersede",
            Self::Retract(_) => "retract",
            Self::Contradict(_) => "contradict",
            Self::Derive(_) => "derive",
            Self::Reinforce(_) => "reinforce",
            Self::Expire(_) => "expire",
            Self::Explain(_) => "explain",
            Self::Replay(_) => "replay",
            Self::Facts(_) => "facts",
            Self::Verify => "verify",
            Self::Conflicts => "conflicts",
            Self::Eval => "eval",
            Self::Init(_) => "init",
            Self::Agent(_) => "agent",
            Self::Doctor(_) => "doctor",
            Self::Completions(_) => "completions",
            Self::Export(_) => "export",
            Self::Authority(_) => "authority",
            Self::Identity(_) => "identity",
            Self::Hook(_) => "hook",
            Self::Witness(_) => "witness",
            Self::Schema(_) => "schema",
            Self::Mcp(_) => "mcp",
        }
    }
}

#[derive(Args, Debug)]
struct ValueWriteArgs {
    /// Fact subject, written as <kind>:<key> (for example person:alice).
    subject: CliSubject,
    /// Predicate within the subject's fact stream.
    #[arg(value_parser = parse_predicate)]
    predicate: String,
    /// Text value to assert.
    value: String,
    /// Claimed authority level.
    #[arg(long, short = 'a', value_enum)]
    authority: CliAuthority,
    /// Provenance source for this write.
    #[arg(long, short = 's', value_parser = parse_source)]
    source: String,
}

#[derive(Args, Debug)]
struct FactWriteArgs {
    /// Fact subject, written as <kind>:<key> (for example person:alice).
    subject: CliSubject,
    /// Predicate within the subject's fact stream.
    #[arg(value_parser = parse_predicate)]
    predicate: String,
    /// Claimed authority level.
    #[arg(long, short = 'a', value_enum)]
    authority: CliAuthority,
    /// Provenance source for this write.
    #[arg(long, short = 's', value_parser = parse_source)]
    source: String,
}

#[derive(Args, Debug)]
struct DeriveWriteArgs {
    /// Fact subject, written as <kind>:<key> (for example person:alice).
    subject: CliSubject,
    /// Predicate within the subject's fact stream.
    #[arg(value_parser = parse_predicate)]
    predicate: String,
    /// Text value to assert.
    value: String,
    /// Source fact to derive from: <source-subject> <source-predicate>.
    #[arg(long, required = true, num_args = 2, value_names = ["SOURCE_SUBJECT", "SOURCE_PREDICATE"])]
    from: Vec<String>,
    /// Claimed authority level.
    #[arg(long, short = 'a', value_enum)]
    authority: CliAuthority,
    /// Provenance source for this write.
    #[arg(long, short = 's', value_parser = parse_source)]
    source: String,
}

#[derive(Args, Debug)]
struct ReadFactArgs {
    /// Fact subject, written as <kind>:<key> (for example person:alice).
    subject: CliSubject,
    /// Predicate within the subject's fact stream.
    #[arg(value_parser = parse_predicate)]
    predicate: String,
}

#[derive(Args, Debug)]
struct FactsArgs {
    #[command(subcommand)]
    command: FactsCommand,
}

#[derive(Subcommand, Debug)]
enum FactsCommand {
    /// List fact streams, hiding internal diagnostic streams by default.
    List(FactsListArgs),
}

#[derive(Args, Debug)]
struct FactsListArgs {
    /// Only show facts with this subject kind.
    #[arg(long, value_name = "KIND", value_parser = parse_non_empty_filter)]
    kind: Option<String>,
    /// Only show facts with this subject key.
    #[arg(long, value_name = "KEY", value_parser = parse_non_empty_filter)]
    key: Option<String>,
    /// Only show facts with this predicate.
    #[arg(long, value_name = "PREDICATE", value_parser = parse_predicate)]
    predicate: Option<String>,
    /// Include dent8 internal diagnostic streams, such as doctor write-check facts.
    #[arg(long)]
    include_diagnostics: bool,
}

#[derive(Args, Debug)]
struct ExportArgs {
    /// Parquet output path.
    #[arg(default_value = "dent8-events.parquet", value_name = "OUT")]
    out: String,
}

#[derive(Args, Debug)]
struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    shell: Shell,
}

#[derive(Args, Debug)]
struct InitArgs {
    /// Directory for dent8's local project config.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// Agent profile shortcut. Implies --identity and selects the default source id.
    #[arg(long, value_enum, conflicts_with = "source")]
    agent: Option<InitAgent>,
    /// Store profile to write into the env file.
    #[arg(long, value_enum, default_value = "file")]
    store: InitStore,
    /// Store URL for non-file backends.
    #[arg(long, value_name = "URL")]
    store_url: Option<String>,
    /// Source to grant in the authority registry. Defaults from --agent, or source:local.
    #[arg(long, value_parser = parse_source)]
    source: Option<String>,
    /// Maximum authority for the granted source.
    #[arg(long, value_enum, default_value = "high")]
    authority: CliAuthority,
    /// Also bootstrap signed source identity for this source.
    #[arg(long)]
    identity: bool,
    /// Stable issuer name used inside the signed identity grant.
    #[arg(long, default_value = "owner")]
    issuer: String,
    /// Operator issuer signing-key path. Defaults outside the project bundle.
    #[arg(long, value_name = "PATH")]
    issuer_key: Option<String>,
    /// Signed identity subject scope: "*" or exact <kind>:<key>.
    #[arg(long, default_value = "*", value_name = "SCOPE")]
    identity_scope: String,
    /// Optional signed identity expiration as Unix milliseconds.
    #[arg(long, value_name = "MILLIS")]
    identity_expires_at_ms: Option<i64>,
    /// Add witness verification paths to the generated env file.
    #[arg(long)]
    witness: bool,
    /// Witness signed-head log path. Implies --witness.
    #[arg(long, value_name = "PATH")]
    witness_log: Option<String>,
    /// Witness public verifying key path. Implies --witness.
    #[arg(long, value_name = "PATH")]
    witness_pubkey: Option<String>,
    #[command(flatten)]
    mcp: InitMcpArgs,
    /// Overwrite the generated env file if it already exists.
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
struct InitMcpArgs {
    /// Patch the selected agent's MCP config after init and show the resulting file.
    #[arg(long, requires = "agent")]
    install_mcp: bool,
    /// MCP config file to patch when --install-mcp is set.
    #[arg(long, value_name = "PATH", requires = "install_mcp")]
    mcp_config: Option<String>,
    /// Command written into the installed MCP config.
    #[arg(
        long,
        value_name = "COMMAND",
        requires = "install_mcp",
        conflicts_with = "mcp_local_bin"
    )]
    mcp_command: Option<String>,
    /// Use .dent8/bin/dent8, a wrapper around a prebuilt .dent8/target-sqlite/debug/dent8.
    #[arg(long, requires = "install_mcp")]
    mcp_local_bin: bool,
    /// Render the MCP config change after init without writing it.
    #[arg(long, requires = "install_mcp", conflicts_with = "mcp_check")]
    mcp_dry_run: bool,
    /// Check whether the MCP config is already installed after init without writing it.
    #[arg(long, requires = "install_mcp")]
    mcp_check: bool,
}

#[derive(Args, Debug)]
struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Subcommand, Debug)]
enum AgentCommand {
    /// Add an agent to an existing shared dent8 bundle.
    Add(AgentAddArgs),
}

#[derive(Args, Debug)]
struct AgentAddArgs {
    /// Agent profile to add.
    #[arg(long, value_enum)]
    agent: InitAgent,
    /// Directory for dent8's local project config.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// Maximum authority for this agent's source. New identities default to high; reused ones
    /// default to the signed grant's max.
    #[arg(long, value_enum)]
    authority: Option<CliAuthority>,
    /// Trusted issuer name to use. Omit when the bundle has exactly one trusted issuer.
    #[arg(long, value_name = "ISSUER")]
    issuer: Option<String>,
    /// Operator issuer signing-key path. Defaults outside the project bundle.
    #[arg(long, value_name = "PATH")]
    issuer_key: Option<String>,
    /// Signed identity subject scope: "*" or exact <kind>:<key>.
    #[arg(long, default_value = "*", value_name = "SCOPE")]
    identity_scope: String,
    /// Optional signed identity expiration as Unix milliseconds.
    #[arg(long, value_name = "MILLIS")]
    identity_expires_at_ms: Option<i64>,
    /// MCP config file to patch.
    #[arg(long, visible_alias = "config", value_name = "PATH")]
    mcp_config: Option<String>,
    /// Command written into the installed MCP config.
    #[arg(
        long,
        visible_alias = "command",
        value_name = "COMMAND",
        conflicts_with = "mcp_local_bin"
    )]
    mcp_command: Option<String>,
    /// Use .dent8/bin/dent8, a wrapper around a prebuilt .dent8/target-sqlite/debug/dent8.
    #[arg(long)]
    mcp_local_bin: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum InitAgent {
    Codex,
    ClaudeCode,
    Cursor,
    GrokBuild,
    Gemini,
    Cascade,
    Hecate,
}

impl InitAgent {
    fn cli_name(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::GrokBuild => "grok-build",
            Self::Gemini => "gemini",
            Self::Cascade => "cascade",
            Self::Hecate => "hecate",
        }
    }

    fn source(self) -> &'static str {
        match self {
            Self::Codex => "source:codex",
            Self::ClaudeCode => "source:claude-code",
            Self::Cursor => "source:cursor",
            Self::GrokBuild => "source:grok-build",
            Self::Gemini => "source:gemini",
            Self::Cascade => "source:cascade",
            Self::Hecate => "source:hecate",
        }
    }

    fn example_path(self) -> &'static str {
        match self {
            Self::Codex => "examples/codex/",
            Self::ClaudeCode => "examples/claude-code/",
            Self::Cursor => "examples/cursor/",
            Self::GrokBuild => "examples/grok-build/",
            Self::Gemini => "examples/gemini/",
            Self::Cascade => "examples/cascade/",
            Self::Hecate => "examples/hecate/",
        }
    }

    fn file_log_name(self) -> &'static str {
        match self {
            Self::Codex => "codex-memory.jsonl",
            Self::ClaudeCode => "claude-memory.jsonl",
            Self::Cursor => "cursor-memory.jsonl",
            Self::GrokBuild => "grok-build-memory.jsonl",
            Self::Gemini => "gemini-memory.jsonl",
            Self::Cascade => "cascade-memory.jsonl",
            Self::Hecate => "hecate-memory.jsonl",
        }
    }

    fn source_slug(self) -> String {
        self.source()
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                    ch
                } else {
                    '_'
                }
            })
            .collect()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum InitStore {
    File,
    Sqlite,
    Postgres,
}

impl InitStore {
    fn name(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

#[derive(Args, Debug)]
struct DoctorArgs {
    /// Also run an explicit assert -> rejected supersede -> explain -> verify write check.
    #[arg(long)]
    write_check: bool,
    /// High-authority source to use for --write-check.
    #[arg(long, value_parser = parse_source)]
    source: Option<String>,
    /// Agent profile to diagnose from its generated .dent8 bundle and MCP config.
    #[arg(long, value_enum, conflicts_with = "source")]
    agent: Option<InitAgent>,
    /// Directory for dent8's local project config when --agent is set.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// MCP config file to check when --agent is set.
    #[arg(long, value_name = "PATH", requires = "agent")]
    mcp_config: Option<String>,
    /// Command expected in the installed MCP config when --agent is set.
    #[arg(
        long,
        value_name = "COMMAND",
        requires = "agent",
        conflicts_with = "mcp_local_bin"
    )]
    mcp_command: Option<String>,
    /// Repair/check against .dent8/bin/dent8, a wrapper around .dent8/target-sqlite/debug/dent8.
    #[arg(long, requires = "agent")]
    mcp_local_bin: bool,
    /// Repair stale generated identity/MCP agent setup before checking it.
    #[arg(long, requires = "agent")]
    repair: bool,
}

#[derive(Args, Debug)]
struct AuthorityArgs {
    #[command(subcommand)]
    command: AuthorityCommand,
}

#[derive(Subcommand, Debug)]
enum AuthorityCommand {
    /// List source authority grants.
    List,
    /// Add or replace a source authority ceiling.
    Add(AuthorityAddArgs),
    /// Remove a source authority grant.
    Remove(AuthorityRemoveArgs),
}

#[derive(Args, Debug)]
struct AuthorityAddArgs {
    #[arg(value_parser = parse_source)]
    source: String,
    #[arg(value_enum)]
    max: CliAuthority,
    issuer: Option<String>,
    scope: Option<String>,
}

#[derive(Args, Debug)]
struct AuthorityRemoveArgs {
    #[arg(value_parser = parse_source)]
    source: String,
}

#[derive(Args, Debug)]
struct IdentityArgs {
    #[command(subcommand)]
    command: IdentityCommand,
}

#[derive(Subcommand, Debug)]
enum IdentityCommand {
    /// Bootstrap a local signed-identity bundle.
    Bootstrap(IdentityBootstrapArgs),
    /// Inspect the active signed-identity bundle.
    Status(IdentityStatusArgs),
    /// Repair generated identity env/active-grant files from the current signed grant.
    RepairEnv(IdentityRepairEnvArgs),
    /// Rotate a source key and issue a replacement grant.
    RotateSource(IdentityRotateSourceArgs),
    /// Generate an issuer/admin signing key.
    IssuerKeygen(IdentityKeygenArgs),
    /// Generate a source/agent signing key.
    AgentKeygen(IdentityAgentKeygenArgs),
    /// Trust an issuer public key.
    TrustAdd(IdentityTrustAddArgs),
    /// List trusted issuer public keys.
    TrustList,
    /// Issue a signed source grant.
    GrantIssue(IdentityGrantIssueArgs),
    /// Revoke a source's current grant without a replacement (ADR 0014).
    Revoke(IdentityRevokeArgs),
    /// Seed grant-log `issued` records for grants that predate the log (ADR 0014).
    BackfillGrantLog(IdentityBackfillGrantLogArgs),
    /// Verify a signed source grant against the local trust registry.
    GrantVerify(IdentityGrantVerifyArgs),
}

#[derive(Args, Debug)]
struct IdentityBootstrapArgs {
    /// Directory for the identity bundle.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// Source id this grant will authorize.
    #[arg(long, default_value = "source:local", value_parser = parse_source)]
    source: String,
    /// Stable issuer name used inside the grant.
    #[arg(long, default_value = "owner")]
    issuer: String,
    /// Operator issuer signing-key path. Defaults outside the project bundle.
    #[arg(long, value_name = "PATH")]
    issuer_key: Option<String>,
    /// Maximum authority this source key may claim.
    #[arg(long, value_enum, default_value = "high")]
    max: CliAuthority,
    /// Subject scope: "*" or exact <kind>:<key>.
    #[arg(long, default_value = "*", value_name = "SCOPE")]
    scope: String,
    /// Optional expiration as Unix milliseconds.
    #[arg(long, value_name = "MILLIS")]
    expires_at_ms: Option<i64>,
}

#[derive(Args, Debug)]
struct IdentityStatusArgs {
    /// Directory for the identity bundle.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// Expected source id for the active grant.
    #[arg(long, value_parser = parse_source)]
    source: Option<String>,
    /// Operator issuer signing-key path to sanity-check.
    #[arg(long, value_name = "PATH")]
    issuer_key: Option<String>,
    /// Warn when the grant expires within this many days.
    #[arg(long, default_value_t = 14)]
    expires_warning_days: u64,
}

#[derive(Args, Debug)]
struct IdentityRepairEnvArgs {
    /// Directory for the identity bundle.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// Source id whose generated identity env should be repaired.
    #[arg(long, value_parser = parse_source)]
    source: String,
}

#[derive(Args, Debug)]
struct IdentityRotateSourceArgs {
    /// Directory for the identity bundle.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// Source id whose key/grant should be rotated.
    #[arg(long, value_parser = parse_source)]
    source: String,
    /// Operator issuer signing-key path. Defaults outside the project bundle.
    #[arg(long, value_name = "PATH")]
    issuer_key: Option<String>,
    /// Replacement grant authority ceiling. Defaults to the current grant's ceiling.
    #[arg(long, value_enum)]
    max: Option<CliAuthority>,
    /// Replacement grant subject scope. Defaults to the current grant's scope.
    #[arg(long, value_name = "SCOPE")]
    scope: Option<String>,
    /// Replacement grant expiration as Unix milliseconds. Defaults to the current grant's expiration.
    #[arg(long, value_name = "MILLIS")]
    expires_at_ms: Option<i64>,
}

#[derive(Args, Debug)]
struct IdentityRevokeArgs {
    /// Source id whose current grant should be revoked, e.g. source:codex.
    #[arg(long, value_name = "SOURCE")]
    source: String,
    /// Identity bundle directory.
    #[arg(long, default_value = ".dent8")]
    dir: String,
    /// Operator issuer signing-key path. Defaults outside the project bundle.
    #[arg(long, value_name = "PATH")]
    issuer_key: Option<String>,
}

#[derive(Args, Debug)]
struct IdentityBackfillGrantLogArgs {
    /// Identity bundle directory.
    #[arg(long, default_value = ".dent8")]
    dir: String,
    /// Operator issuer signing-key path. Defaults outside the project bundle.
    #[arg(long, value_name = "PATH")]
    issuer_key: Option<String>,
}

#[derive(Args, Debug)]
struct IdentityKeygenArgs {
    /// Private signing-key path to create. The public key is written to <out>.pub.
    #[arg(long, value_name = "PATH")]
    out: String,
}

#[derive(Args, Debug)]
struct IdentityAgentKeygenArgs {
    /// Source id this key will represent.
    #[arg(value_parser = parse_source)]
    source: String,
    /// Private signing-key path to create. The public key is written to <out>.pub.
    #[arg(long, value_name = "PATH")]
    out: String,
}

#[derive(Args, Debug)]
struct IdentityTrustAddArgs {
    /// Stable issuer name used inside grants.
    issuer: String,
    /// Issuer public-key file.
    #[arg(value_name = "ISSUER_PUBKEY")]
    public_key: String,
}

#[derive(Args, Debug)]
struct IdentityGrantIssueArgs {
    /// Source id to grant.
    #[arg(value_parser = parse_source)]
    source: String,
    /// Source/agent public-key file.
    #[arg(long, value_name = "SOURCE_PUBKEY")]
    public_key: String,
    /// Maximum authority this source key may claim.
    #[arg(long, value_enum)]
    max: CliAuthority,
    /// Issuer name. Must match a trusted issuer name on verification.
    #[arg(long)]
    issuer: String,
    /// Issuer private signing-key path.
    #[arg(long, value_name = "ISSUER_KEY")]
    issuer_key: String,
    /// Grant JSON path to create.
    #[arg(long, value_name = "PATH")]
    out: String,
    /// Optional subject scope: "*" or exact <kind>:<key>.
    #[arg(long, value_name = "SCOPE")]
    scope: Option<String>,
    /// Optional expiration as Unix milliseconds.
    #[arg(long, value_name = "MILLIS")]
    expires_at_ms: Option<i64>,
}

#[derive(Args, Debug)]
struct IdentityGrantVerifyArgs {
    /// Grant JSON path.
    grant: String,
}

#[derive(Args, Debug)]
struct HookArgs {
    #[command(subcommand)]
    command: HookCommand,
}

#[derive(Subcommand, Debug)]
enum HookCommand {
    /// Verify on session boundaries and guard native memory/rules writes.
    NativeMemoryGuard,
}

#[derive(Args, Debug)]
struct SchemaArgs {
    #[command(subcommand)]
    command: SchemaCommand,
}

#[derive(Subcommand, Debug)]
enum SchemaCommand {
    /// Print the Postgres schema.
    Postgres,
}

#[derive(Args, Debug)]
struct McpArgs {
    #[command(subcommand)]
    command: McpCommand,
}

#[derive(Subcommand, Debug)]
enum McpCommand {
    /// Expose the belief surface over stdio JSON-RPC.
    Serve,
    /// Patch an agent MCP config with dent8 and show the resulting file.
    Install(McpInstallArgs),
}

#[derive(Args, Debug)]
struct McpInstallArgs {
    /// Agent profile whose MCP config should be patched.
    #[arg(long, value_enum)]
    agent: InitAgent,
    /// Directory for dent8's local project config.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// MCP config file to patch. Defaults to the agent's project-local config path.
    #[arg(long, value_name = "PATH")]
    config: Option<String>,
    /// Command written into the installed MCP config.
    #[arg(long, value_name = "COMMAND", conflicts_with = "local_bin")]
    command: Option<String>,
    /// Use .dent8/bin/dent8, a wrapper around a prebuilt .dent8/target-sqlite/debug/dent8.
    #[arg(long)]
    local_bin: bool,
    /// Render the resulting file without writing it.
    #[arg(long, conflicts_with = "check")]
    dry_run: bool,
    /// Exit 0 only when the existing config already matches the generated dent8 entry.
    #[arg(long)]
    check: bool,
}

#[derive(Args, Debug)]
struct WitnessArgs {
    /// Passed through to the witness feature implementation.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

static COLOR_MODE: AtomicU8 = AtomicU8::new(0);

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliColor {
    Auto,
    Always,
    Never,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
enum CliOutput {
    Text,
    Json,
}

impl CliColor {
    fn clap_choice(self) -> clap::ColorChoice {
        match self {
            Self::Auto => clap::ColorChoice::Auto,
            Self::Always => clap::ColorChoice::Always,
            Self::Never => clap::ColorChoice::Never,
        }
    }
}

fn set_color(color: CliColor) {
    let mode = match color {
        CliColor::Auto => 0,
        CliColor::Always => 1,
        CliColor::Never => 2,
    };
    COLOR_MODE.store(mode, Ordering::Relaxed);
}

fn requested_color(args: &[String]) -> Option<CliColor> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == "--" {
            return None;
        }
        if let Some(value) = arg.strip_prefix("--color=") {
            return parse_cli_color(value);
        }
        if arg == "--color" {
            return iter.next().and_then(|value| parse_cli_color(value));
        }
    }
    None
}

fn parse_cli_color(value: &str) -> Option<CliColor> {
    match value.to_ascii_lowercase().as_str() {
        "auto" => Some(CliColor::Auto),
        "always" => Some(CliColor::Always),
        "never" => Some(CliColor::Never),
        _ => None,
    }
}

#[derive(Copy, Clone, Debug)]
enum CliStream {
    Stdout,
    Stderr,
}

fn color_enabled(stream: CliStream) -> bool {
    match COLOR_MODE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ if std::env::var_os("NO_COLOR").is_some() => false,
        _ => match stream {
            CliStream::Stdout => std::io::stdout().is_terminal(),
            CliStream::Stderr => std::io::stderr().is_terminal(),
        },
    }
}

fn paint_status(message: &str, stream: CliStream) -> String {
    if !color_enabled(stream) {
        return message.to_string();
    }
    for (prefix, style) in [
        ("ACCEPTED", "\x1b[32;1m"),
        ("REJECTED", "\x1b[31;1m"),
        ("CONTESTED", "\x1b[33;1m"),
        ("OK:", "\x1b[32;1m"),
        ("INTEGRITY FAILURE", "\x1b[31;1m"),
        ("INTEGRITY ISSUES", "\x1b[31;1m"),
    ] {
        if let Some(rest) = message.strip_prefix(prefix) {
            return format!("{style}{prefix}\x1b[0m{rest}");
        }
    }
    message.to_string()
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliAuthority {
    Low,
    Medium,
    High,
    Canonical,
}

impl CliAuthority {
    fn level(self) -> AuthorityLevel {
        match self {
            Self::Low => AuthorityLevel::Low,
            Self::Medium => AuthorityLevel::Medium,
            Self::High => AuthorityLevel::High,
            Self::Canonical => AuthorityLevel::Canonical,
        }
    }
}

fn parse_authority(value: &str) -> Option<AuthorityLevel> {
    match value.to_ascii_lowercase().as_str() {
        "low" => Some(AuthorityLevel::Low),
        "medium" => Some(AuthorityLevel::Medium),
        "high" => Some(AuthorityLevel::High),
        "canonical" => Some(AuthorityLevel::Canonical),
        _ => None,
    }
}

#[derive(Clone, Debug)]
struct CliSubject {
    kind: String,
    key: String,
}

impl FromStr for CliSubject {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let Some((kind, key)) = raw.split_once(':') else {
            return Err(format!(
                "invalid subject '{raw}' (expected <kind>:<key>, e.g. person:alice)"
            ));
        };
        EntityRef::new(kind, key)
            .map_err(|error| format!("invalid subject '{raw}' (expected <kind>:<key>): {error}"))?;
        Ok(Self {
            kind: kind.to_string(),
            key: key.to_string(),
        })
    }
}

fn parse_predicate(raw: &str) -> Result<String, String> {
    Predicate::new(raw).map_err(|error| format!("invalid predicate '{raw}': {error}"))?;
    Ok(raw.to_string())
}

fn parse_non_empty_filter(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        Err("filter value must not be empty".to_string())
    } else {
        Ok(raw.to_string())
    }
}

fn parse_source(raw: &str) -> Result<String, String> {
    ActorId::new(raw).map_err(|error| format!("invalid source '{raw}': {error}"))?;
    Ok(raw.to_string())
}

fn run_identity(command: &IdentityCommand, output: CliOutput) -> i32 {
    #[cfg(not(feature = "identity"))]
    {
        let _ = command;
        match output {
            CliOutput::Text => {
                eprintln!("`dent8 identity` requires a build with `--features identity`");
                2
            }
            CliOutput::Json => {
                let tool = match command {
                    IdentityCommand::Bootstrap(_) => "identity bootstrap",
                    IdentityCommand::Status(_) => "identity status",
                    IdentityCommand::RepairEnv(_) => "identity repair-env",
                    IdentityCommand::RotateSource(_) => "identity rotate-source",
                    IdentityCommand::IssuerKeygen(_) => "identity issuer-keygen",
                    IdentityCommand::AgentKeygen(_) => "identity agent-keygen",
                    IdentityCommand::TrustAdd(_) => "identity trust-add",
                    IdentityCommand::TrustList => "identity trust-list",
                    IdentityCommand::GrantIssue(_) => "identity grant-issue",
                    IdentityCommand::GrantVerify(_) => "identity grant-verify",
                    IdentityCommand::Revoke(_) => "identity revoke",
                    IdentityCommand::BackfillGrantLog(_) => "identity backfill-grant-log",
                };
                print_json_stderr(
                    &serde_json::json!({
                        "status": "failed",
                        "tool": tool,
                        "message": "`dent8 identity` requires a build with `--features identity`",
                    }),
                    2,
                )
            }
        }
    }
    #[cfg(feature = "identity")]
    match command {
        IdentityCommand::Bootstrap(args) => identity::bootstrap(
            &args.dir,
            &args.source,
            &args.issuer,
            args.issuer_key.as_deref(),
            args.max,
            &args.scope,
            args.expires_at_ms,
            output,
        ),
        IdentityCommand::Status(args) => identity::status(
            &args.dir,
            args.source.as_deref(),
            args.issuer_key.as_deref(),
            args.expires_warning_days,
            output,
        ),
        IdentityCommand::RepairEnv(args) => identity::repair_env(&args.dir, &args.source, output),
        IdentityCommand::RotateSource(args) => identity::rotate_source(
            &args.dir,
            &args.source,
            args.issuer_key.as_deref(),
            args.max,
            args.scope.as_deref(),
            args.expires_at_ms,
            output,
        ),
        IdentityCommand::IssuerKeygen(args) => identity::issuer_keygen(&args.out, output),
        IdentityCommand::AgentKeygen(args) => {
            identity::agent_keygen(&args.source, &args.out, output)
        }
        IdentityCommand::TrustAdd(args) => {
            identity::trust_add(&args.issuer, &args.public_key, output)
        }
        IdentityCommand::TrustList => identity::trust_list(output),
        IdentityCommand::GrantIssue(args) => identity::grant_issue(
            &args.source,
            &args.public_key,
            args.max,
            &args.issuer,
            &args.issuer_key,
            &args.out,
            args.scope.as_deref(),
            args.expires_at_ms,
            output,
        ),
        IdentityCommand::GrantVerify(args) => identity::grant_verify(&args.grant, output),
        IdentityCommand::Revoke(args) => {
            identity::revoke(&args.dir, &args.source, args.issuer_key.as_deref(), output)
        }
        IdentityCommand::BackfillGrantLog(args) => {
            identity::backfill_grant_log(&args.dir, args.issuer_key.as_deref(), output)
        }
    }
}

/// Dispatch `dent8 witness <sub>`. Feature-gated: without `--features witness` the command
/// exists only to explain how to enable it.
fn run_witness(args: &[String], output: CliOutput) -> i32 {
    // `witness` takes raw args (clap's trailing catch-all), so a trailing `--output json` —
    // the position every clap-native command accepts — would otherwise be swallowed as an
    // unknown subcommand token and die with a usage error. Strip an embedded `--output` here
    // and let it override the global flag.
    let (args, output) = match extract_witness_output(args, output) {
        Ok(extracted) => extracted,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let args = args.as_slice();
    #[cfg(not(feature = "witness"))]
    {
        let _ = args;
        match output {
            CliOutput::Text => {
                eprintln!("`dent8 witness` requires a build with `--features witness`");
                2
            }
            CliOutput::Json => print_json_stderr(
                &serde_json::json!({
                    "status": "failed",
                    "tool": "witness",
                    "required_feature": "witness",
                    "message": "`dent8 witness` requires a build with `--features witness`",
                }),
                2,
            ),
        }
    }
    #[cfg(feature = "witness")]
    match args {
        [sub] if sub == "keygen" => witness::keygen(output),
        [sub] if sub == "sign" => witness::sign(output),
        [sub] if sub == "verify" => witness::verify(output),
        [sub, rest @ ..] if sub == "verify-published" => witness::verify_published(rest, output),
        [sub] if sub == "head" => witness::head(output),
        [sub, rest @ ..] if sub == "publish" => witness::publish(rest, output),
        [sub, rest @ ..] if sub == "serve" => witness::serve(rest, output),
        [sub, rest @ ..] if sub == "doctor" => witness::doctor(rest, output),
        _ => witness_usage_error(output),
    }
}

/// Pull an embedded `--output <text|json>` / `--output=<text|json>` out of the raw witness
/// args. Returns the remaining args and the effective output (embedded wins over the global
/// flag); errors on a missing or invalid value, mirroring clap's own diagnostics.
fn extract_witness_output(
    args: &[String],
    global: CliOutput,
) -> Result<(Vec<String>, CliOutput), String> {
    let mut remaining = Vec::with_capacity(args.len());
    let mut output = global;
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(value) = arg.strip_prefix("--output=") {
            output = parse_witness_output_value(value)?;
        } else if arg == "--output" {
            let Some(value) = iter.next() else {
                return Err(
                    "error: a value is required for '--output <OUTPUT>' but none was supplied \
                     [possible values: text, json]"
                        .to_string(),
                );
            };
            output = parse_witness_output_value(value)?;
        } else {
            remaining.push(arg.clone());
        }
    }
    Ok((remaining, output))
}

fn parse_witness_output_value(value: &str) -> Result<CliOutput, String> {
    match value {
        "text" => Ok(CliOutput::Text),
        "json" => Ok(CliOutput::Json),
        other => Err(format!(
            "error: invalid value '{other}' for '--output <OUTPUT>' [possible values: text, json]"
        )),
    }
}

#[cfg(feature = "witness")]
fn witness_usage_error(output: CliOutput) -> i32 {
    let usage = "dent8 witness <keygen | sign | verify | verify-published \
                 <published-heads.jsonl> [--grants <published-grants.jsonl>] | head | publish \
                 <published-heads.jsonl> [--grants <published-grants.jsonl>] | serve \
                 [interval-seconds] [max-heads] | doctor <writer|signer|both>>";
    match output {
        CliOutput::Text => {
            eprintln!("usage: {usage}");
            2
        }
        CliOutput::Json => print_json_stderr(
            &serde_json::json!({
                "status": "invalid",
                "tool": "witness",
                "usage": usage,
                "message": "invalid witness command",
            }),
            2,
        ),
    }
}

fn cmd_completions(shell: Shell, output: CliOutput) -> i32 {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    let mut script = Vec::new();
    generate(shell, &mut command, name, &mut script);
    let script = String::from_utf8(script).expect("completion scripts should be UTF-8");
    match output {
        CliOutput::Text => {
            print!("{script}");
            0
        }
        CliOutput::Json => print_json_stdout(&serde_json::json!({
            "status": "ok",
            "tool": "completions",
            "shell": completion_shell_name(shell),
            "script": script,
        })),
    }
}

fn completion_shell_name(shell: Shell) -> &'static str {
    match shell {
        Shell::Bash => "bash",
        Shell::Elvish => "elvish",
        Shell::Fish => "fish",
        Shell::PowerShell => "powershell",
        Shell::Zsh => "zsh",
        _ => "unknown",
    }
}

fn cmd_schema_postgres(output: CliOutput) -> i32 {
    // Print exactly the schema `migrate()` deploys (the event-log table + the materialized
    // projection/edges), so an operator who pre-creates it gets the tables the runtime actually
    // uses (a richer per-column layout is possible later).
    let sql = format!("{EVENT_LOG_SCHEMA_SQL}{MATERIALIZATION_SCHEMA_SQL}");
    match output {
        CliOutput::Text => {
            print!("{sql}");
            0
        }
        CliOutput::Json => print_json_stdout(&serde_json::json!({
            "status": "ok",
            "tool": "schema postgres",
            "schema": "postgres",
            "sql": sql,
        })),
    }
}

fn display_value(value: &ClaimValue) -> String {
    match value {
        ClaimValue::Text(text) => format!("\"{text}\""),
        ClaimValue::Json(json) => format!("json:{}", json.as_str()),
        ClaimValue::Redacted => "<redacted>".to_string(),
    }
}

/// The read-time headline verdict for an explained fact: a terminal fact is no longer
/// believed; a still-`Active` fact past its TTL is **stale** (threat-model T4) — an agent
/// must not act on it as current. Fresh `Active` facts get no annotation. The receipt body
/// (value, `expires_at`) is always shown for the audit trail.
fn read_annotation(lifecycle: ClaimLifecycle, fresh: bool) -> String {
    if lifecycle.is_terminal() {
        format!("  [no longer believed — {lifecycle:?}]")
    } else if !fresh {
        "  [stale — TTL elapsed]".to_string()
    } else {
        String::new()
    }
}

fn format_receipt(r: &IntegrityReceipt) -> String {
    let value = display_value(&r.value);
    let superseded = r
        .superseded_by
        .as_ref()
        .map_or_else(|| "-".to_string(), ToString::to_string);
    let expires_at = r
        .expires_at
        .map_or_else(|| "never".to_string(), |at| at.as_unix_millis().to_string());
    format!(
        "    value         : {value}\n    \
         lifecycle     : {:?}\n    \
         authority     : {:?}\n    \
         fresh         : {}\n    \
         expires_at    : {expires_at}\n    \
         evidence      : {}\n    \
         corroboration : {}\n    \
         survived      : {} challenge(s)\n    \
         superseded_by : {superseded}\n    \
         contradicted  : {}\n    \
         replay pos    : {}\n    \
         event_hash    : {}\n    \
         chain verified: {}",
        r.lifecycle,
        r.authority,
        r.fresh,
        r.evidence_count,
        r.corroboration,
        r.survived_challenges,
        r.contradicted_by.len(),
        r.replay_position,
        short(&r.event_hash),
        r.chain_verified,
    )
}

fn claim_value_json(value: &ClaimValue) -> serde_json::Value {
    match value {
        ClaimValue::Text(text) => serde_json::json!({
            "kind": "text",
            "text": text,
            "display": display_value(value),
        }),
        ClaimValue::Json(json) => serde_json::json!({
            "kind": "json",
            "json": json.as_str(),
            "display": display_value(value),
        }),
        ClaimValue::Redacted => serde_json::json!({
            "kind": "redacted",
            "display": display_value(value),
        }),
    }
}

fn receipt_fields_json(receipt: &IntegrityReceipt) -> serde_json::Value {
    serde_json::json!({
        "subject": {
            "kind": receipt.subject.kind(),
            "key": receipt.subject.key(),
        },
        "predicate": receipt.predicate.as_str(),
        "claim_id": receipt.claim_id.as_str(),
        "value": claim_value_json(&receipt.value),
        "lifecycle": format!("{:?}", receipt.lifecycle),
        "authority": receipt.authority.name(),
        "fresh": receipt.fresh,
        "expires_at": receipt.expires_at.map(TimestampMillis::as_unix_millis),
        "evidence_count": receipt.evidence_count,
        "corroboration": receipt.corroboration,
        "survived_challenges": receipt.survived_challenges,
        "superseded_by": receipt.superseded_by.as_ref().map(ClaimId::as_str),
        "contradicted_by": receipt
            .contradicted_by
            .iter()
            .map(ClaimId::as_str)
            .collect::<Vec<_>>(),
        "replay_position": receipt.replay_position,
        "event_hash": receipt.event_hash,
        "chain_verified": receipt.chain_verified,
    })
}

fn receipt_json(tool: &str, receipt: &IntegrityReceipt) -> serde_json::Value {
    let mut value = receipt_fields_json(receipt);
    let object = value
        .as_object_mut()
        .expect("receipt fields should serialize as an object");
    object.insert("status".to_string(), serde_json::json!("ok"));
    object.insert("tool".to_string(), serde_json::json!(tool));
    value
}

fn short(hash: &str) -> String {
    format!("{}…", &hash[..hash.len().min(12)])
}

// ---- Persistent file-backed commands -------------------------------------------------
//
// `dent8 assert …` and `dent8 explain …` persist to a JSON-lines event log (one
// serialized `ClaimEvent` per line) so commands compose across separate invocations.
// Each invocation rehydrates the store via the trusted-reload path, runs the firewall +
// registry on a new write, and appends the admitted event. This is a *local* dev store;
// operational, transactional backends are selected by DENT8_STORE_URL.

const DEFAULT_LOG: &str = "dent8-log.jsonl";
const DEFAULT_AUTHORITY: &str = "dent8-authority.json";

fn log_path() -> String {
    std::env::var("DENT8_LOG").unwrap_or_else(|_| DEFAULT_LOG.to_string())
}

// ---- Source authority registry (authz: cap what a source may *claim*) ----------------
//
// dent8 otherwise trusts the caller-supplied `authority` argument. The registry maps a
// `source` to the highest authority it may assert; a write above that ceiling is **rejected**
// (not silently capped, so a laundering attempt stays visible in the error). Enforcement is
// **opt-in**: it activates once a registry exists (created by `dent8 authority add`); without
// one the CLI is permissive (dev mode). With one, a source not listed has an `Unknown` ceiling.

/// What a registered source is allowed to assert.
///
/// Strict deserialization (`deny_unknown_fields`): the authority registry is a security
/// artifact, and a silently-ignored unknown field (a typo'd `max_authorty`, an injected key)
/// must fail loudly rather than weaken enforcement.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceGrant {
    max_authority: AuthorityLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceRegistry {
    sources: std::collections::BTreeMap<String, SourceGrant>,
}

impl SourceRegistry {
    /// A registered source's ceiling, or `Unknown` (the floor) for an unregistered one.
    fn ceiling(&self, source: &str) -> AuthorityLevel {
        self.sources
            .get(source)
            .map_or(AuthorityLevel::Unknown, |grant| grant.max_authority)
    }
}

fn authority_registry_path() -> String {
    std::env::var("DENT8_AUTHORITY").unwrap_or_else(|_| DEFAULT_AUTHORITY.to_string())
}

/// What the write-boundary auth gate needs to know about a write: the subject (for grant
/// scope checks), the claimed authority (for ceiling checks), and the source. The full write
/// *content* is no longer carried here — the persisted per-event attestation (ADR 0013) signs
/// the whole event at the append boundary, which covers strictly more than any summary could.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "identity"), allow(dead_code))]
struct WriteAuth<'a> {
    subject_kind: &'a str,
    subject_key: &'a str,
    authority: AuthorityLevel,
    source: &'a str,
}

impl<'a> WriteAuth<'a> {
    fn new(
        subject_kind: &'a str,
        subject_key: &'a str,
        authority: AuthorityLevel,
        source: &'a str,
    ) -> Self {
        Self {
            subject_kind,
            subject_key,
            authority,
            source,
        }
    }

    #[cfg(feature = "identity")]
    fn subject(&self) -> String {
        format!("{}:{}", self.subject_kind, self.subject_key)
    }
}

fn parse_flag(name: &str, value: &str) -> Result<bool, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "" | "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!(
            "{name} must be a boolean flag: use 1/true/yes/on or 0/false/no/off"
        )),
    }
}

fn env_flag(name: &str) -> Result<bool, String> {
    match std::env::var(name) {
        Ok(value) => parse_flag(name, &value),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} must be valid UTF-8")),
    }
}

fn authority_required() -> Result<bool, String> {
    env_flag("DENT8_REQUIRE_AUTHORITY")
}

fn load_authority_registry_at(
    path: &str,
    required: bool,
) -> Result<Option<SourceRegistry>, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents)
            .map(Some)
            .map_err(|error| format!("{path}: corrupt authority registry: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && required => Err(format!(
            "authority registry required by DENT8_REQUIRE_AUTHORITY, but {path} does not exist; \
             create it with `dent8 authority add <source> <max>` or unset DENT8_REQUIRE_AUTHORITY"
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {path}: {error}")),
    }
}

/// Load the registry, or `None` when none exists and fail-closed mode is not enabled.
fn load_authority_registry() -> Result<Option<SourceRegistry>, String> {
    load_authority_registry_at(&authority_registry_path(), authority_required()?)
}

/// Load the registry for operator edits. Missing still means "create a new file" even when
/// `DENT8_REQUIRE_AUTHORITY` is set; otherwise the flag would prevent bootstrapping itself.
fn load_authority_registry_for_edit() -> Result<Option<SourceRegistry>, String> {
    load_authority_registry_at(&authority_registry_path(), false)
}

fn save_authority_registry(registry: &SourceRegistry) -> Result<(), String> {
    let path = authority_registry_path();
    save_authority_registry_at(&path, registry)
}

fn save_authority_registry_at(path: &str, registry: &SourceRegistry) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(registry).map_err(|error| format!("serialize: {error}"))?;
    // Atomic write: a torn save would corrupt the registry, and a corrupt registry fails
    // *closed* (every write is then blocked). Stage a sibling temp file, then rename it over
    // the target — rename is atomic within a filesystem. Concurrent writers remain
    // last-write-wins, which is acceptable for a human-managed config file.
    write_atomic(path, &format!("{json}\n"))
}

fn write_atomic(path: &str, contents: &str) -> Result<(), String> {
    let tmp = format!("{path}.tmp.{}", std::process::id());
    std::fs::write(&tmp, contents).map_err(|error| format!("cannot write {tmp}: {error}"))?;
    std::fs::rename(&tmp, path).map_err(|error| format!("cannot install {path}: {error}"))
}

/// The authz gate, run before the firewall on every write: reject a stated `authority` above
/// its `source`'s registered ceiling. A no-op only when no registry is configured and
/// `DENT8_REQUIRE_AUTHORITY` is not enabled.
fn enforce_source_ceiling(source: &str, requested: AuthorityLevel) -> Result<(), ops::OpError> {
    let registry = load_authority_registry().map_err(ops::OpError::Invalid)?;
    ceiling_check(registry.as_ref(), source, requested)
}

/// The write-boundary auth gate: source→authority ceiling first (authz), then optional
/// signed source identity (authn) when a trust root is configured.
fn enforce_write_authority(auth: &WriteAuth<'_>) -> Result<(), ops::OpError> {
    enforce_source_ceiling(auth.source, auth.authority)?;
    enforce_source_identity(auth).map_err(ops::OpError::Invalid)
}

#[cfg(feature = "identity")]
fn enforce_source_identity(auth: &WriteAuth<'_>) -> Result<(), String> {
    identity::enforce_write(auth, now_millis())
}

#[cfg(not(feature = "identity"))]
fn enforce_source_identity(_auth: &WriteAuth<'_>) -> Result<(), String> {
    let required = env_flag("DENT8_REQUIRE_IDENTITY")?;
    let trust_path =
        std::env::var("DENT8_TRUST").unwrap_or_else(|_| "dent8-trust.json".to_string());
    let configured = required
        || std::env::var_os("DENT8_GRANT").is_some()
        || std::env::var_os("DENT8_IDENTITY_KEY").is_some()
        || std::path::Path::new(&trust_path).exists();
    if configured {
        return Err(
            "signed source identity is configured, but this binary was built without \
             `--features identity`"
                .to_string(),
        );
    }
    Ok(())
}

/// The pure decision: reject `requested` above the source's ceiling. `None` registry is
/// permissive (dev mode); production can disable that path with `DENT8_REQUIRE_AUTHORITY`.
/// Rejection — not silent capping — keeps a laundering attempt visible. Only `max_authority`
/// is consulted: a grant's `issuer`/`scope` are recorded metadata, **not** enforced in v0
/// (scope does not restrict which predicates a source may write). An active registry is
/// deny-by-default — an unlisted source's ceiling is `Unknown`, below the lowest requestable
/// level (`Low`), so it is blocked from writing entirely.
fn ceiling_check(
    registry: Option<&SourceRegistry>,
    source: &str,
    requested: AuthorityLevel,
) -> Result<(), ops::OpError> {
    let Some(registry) = registry else {
        return Ok(());
    };
    let ceiling = registry.ceiling(source);
    if requested > ceiling {
        return Err(ops::OpError::Rejected(format!(
            "authority ceiling: source {source:?} may assert at most {ceiling:?}, but requested \
             {requested:?} (grant it with `dent8 authority add {source} <max>`)"
        )));
    }
    Ok(())
}

struct AuthorityListOutcome {
    path: String,
    required: bool,
    registry: Option<SourceRegistry>,
}

fn authority_list_outcome() -> Result<AuthorityListOutcome, String> {
    // A diagnostic/read command: load WITHOUT the fail-closed gate (like the edit commands),
    // so `authority list` can always report state — including "no registry yet" under
    // DENT8_REQUIRE_AUTHORITY, which is exactly when an operator needs to inspect it. (Only the
    // write gate `enforce_source_ceiling` consults the flag.)
    let required = authority_required()?;
    Ok(AuthorityListOutcome {
        path: authority_registry_path(),
        required,
        registry: load_authority_registry_for_edit()?,
    })
}

fn format_authority_list(outcome: &AuthorityListOutcome) -> String {
    match &outcome.registry {
        None if outcome.required => format!(
            "no authority registry at {} — but DENT8_REQUIRE_AUTHORITY is set, so every \
             write is BLOCKED until you create one with `dent8 authority add <source> <max>`.",
            outcome.path
        ),
        None => format!(
            "no authority registry at {} — enforcement is OFF (dev mode). Add a source \
             with `dent8 authority add <source> <max>`.",
            outcome.path
        ),
        Some(registry) if registry.sources.is_empty() => {
            "authority registry is empty — deny-by-default: every source is blocked from \
             writing until granted with `dent8 authority add <source> <max>`."
                .to_string()
        }
        Some(registry) => registry
            .sources
            .iter()
            .map(|(source, grant)| {
                let issuer = grant
                    .issuer
                    .as_deref()
                    .map_or_else(String::new, |issuer| format!("  issuer={issuer}"));
                let scope = grant
                    .scope
                    .as_deref()
                    .map_or_else(String::new, |scope| format!("  scope={scope}"));
                let note = if grant.issuer.is_some() || grant.scope.is_some() {
                    "  (issuer/scope recorded, NOT enforced in v0)"
                } else {
                    ""
                };
                format!(
                    "{source}  max={:?}{issuer}{scope}{note}",
                    grant.max_authority
                )
            })
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

fn authority_enforcement_state(outcome: &AuthorityListOutcome) -> &'static str {
    match &outcome.registry {
        None if outcome.required => "blocked_missing_registry",
        None => "off_dev_mode",
        Some(registry) if registry.sources.is_empty() => "deny_by_default_empty",
        Some(_) => "deny_by_default",
    }
}

fn authority_sources_json(registry: Option<&SourceRegistry>) -> Vec<serde_json::Value> {
    registry.map_or_else(Vec::new, |registry| {
        registry
            .sources
            .iter()
            .map(|(source, grant)| {
                serde_json::json!({
                    "source": source,
                    "max_authority": grant.max_authority.name(),
                    "issuer": grant.issuer,
                    "scope": grant.scope,
                    "issuer_enforced": false,
                    "scope_enforced": false,
                })
            })
            .collect()
    })
}

fn authority_list_json(outcome: &AuthorityListOutcome) -> serde_json::Value {
    let sources = authority_sources_json(outcome.registry.as_ref());
    serde_json::json!({
        "status": "ok",
        "tool": "authority list",
        "path": outcome.path,
        "require_authority": outcome.required,
        "registry_present": outcome.registry.is_some(),
        "enforcement": authority_enforcement_state(outcome),
        "count": sources.len(),
        "sources": sources,
    })
}

fn authority_error_json(tool: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": tool,
        "path": authority_registry_path(),
        "message": message,
    })
}

fn cmd_authority_list(output: CliOutput) -> i32 {
    match authority_list_outcome() {
        Ok(outcome) => match output {
            CliOutput::Text => {
                println!("{}", format_authority_list(&outcome));
                0
            }
            CliOutput::Json => print_json_stdout(&authority_list_json(&outcome)),
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                2
            }
            CliOutput::Json => {
                print_json_stderr(&authority_error_json("authority list", &error), 2)
            }
        },
    }
}

fn cmd_authority_add(
    source: &str,
    max_authority: AuthorityLevel,
    issuer: Option<&str>,
    scope: Option<&str>,
    output: CliOutput,
) -> i32 {
    let mut registry = match load_authority_registry_for_edit() {
        Ok(registry) => registry.unwrap_or_default(),
        Err(error) => {
            return match output {
                CliOutput::Text => {
                    eprintln!("{error}");
                    2
                }
                CliOutput::Json => {
                    print_json_stderr(&authority_error_json("authority add", &error), 2)
                }
            };
        }
    };
    registry.sources.insert(
        source.to_string(),
        SourceGrant {
            max_authority,
            issuer: issuer.map(str::to_string),
            scope: scope.map(str::to_string),
        },
    );
    match save_authority_registry(&registry) {
        Ok(()) => {
            let message = format!("granted {source} a max authority of {max_authority:?}");
            match output {
                CliOutput::Text => {
                    println!("{message}");
                    0
                }
                CliOutput::Json => print_json_stdout(&serde_json::json!({
                    "status": "ok",
                    "tool": "authority add",
                    "path": authority_registry_path(),
                    "source": source,
                    "max_authority": max_authority.name(),
                    "issuer": issuer,
                    "scope": scope,
                    "issuer_enforced": false,
                    "scope_enforced": false,
                    "message": message,
                })),
            }
        }
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stderr(&authority_error_json("authority add", &error), 1),
        },
    }
}

fn cmd_authority_remove(source: &str, output: CliOutput) -> i32 {
    let mut registry = match load_authority_registry_for_edit() {
        Ok(Some(registry)) => registry,
        Ok(None) => {
            let message = "no authority registry to remove from";
            return match output {
                CliOutput::Text => {
                    eprintln!("{message}");
                    1
                }
                CliOutput::Json => {
                    print_json_stderr(&authority_error_json("authority remove", message), 1)
                }
            };
        }
        Err(error) => {
            return match output {
                CliOutput::Text => {
                    eprintln!("{error}");
                    2
                }
                CliOutput::Json => {
                    print_json_stderr(&authority_error_json("authority remove", &error), 2)
                }
            };
        }
    };
    if registry.sources.remove(source).is_none() {
        let message = format!("{source} is not in the authority registry");
        return match output {
            CliOutput::Text => {
                eprintln!("{message}");
                1
            }
            CliOutput::Json => {
                print_json_stderr(&authority_error_json("authority remove", &message), 1)
            }
        };
    }
    match save_authority_registry(&registry) {
        Ok(()) => {
            let message = format!("revoked {source}");
            match output {
                CliOutput::Text => {
                    println!("{message}");
                    0
                }
                CliOutput::Json => print_json_stdout(&serde_json::json!({
                    "status": "ok",
                    "tool": "authority remove",
                    "path": authority_registry_path(),
                    "source": source,
                    "message": message,
                })),
            }
        }
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => {
                print_json_stderr(&authority_error_json("authority remove", &error), 1)
            }
        },
    }
}

fn path_string(path: &std::path::Path) -> String {
    path.display().to_string()
}

fn absolute_path(path: &std::path::Path) -> Result<std::path::PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map_err(|error| format!("cannot read current directory: {error}"))
            .map(|cwd| cwd.join(path))
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn first_line(message: &str) -> &str {
    message.lines().next().unwrap_or(message)
}

fn now_millis() -> TimestampMillis {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |delta| delta.as_millis());
    TimestampMillis::from_unix_millis(i64::try_from(ms).unwrap_or(i64::MAX))
}

/// Rehydrate the durable log via the trusted-reload path (no re-arbitration of
/// already-admitted events). A missing file is an empty log.
///
/// Because the trusted path performs no policy checks, this *also* re-validates the
/// invariant the writer is supposed to maintain — at most one fresh believed claim per
/// unique predicate — so a torn write or external edit that orphaned a believed claim is
/// rejected loudly rather than silently masked by `explain`.
fn load_store(path: &str) -> Result<InMemoryEventStore, String> {
    // Backend selection lives here (and in `append_events`) so every `op_*` is backend-aware
    // with no changes of its own. With `DENT8_STORE_URL` set and a matching backend feature,
    // reads/writes go to that operational store; otherwise to the file dev store.
    #[cfg(feature = "async-store")]
    if let Some(url) = store_url() {
        return backend_load(&url);
    }
    #[cfg(not(feature = "async-store"))]
    if store_url().is_some() {
        return Err(
            "DENT8_STORE_URL is set but this build has no async backend — \
             rebuild with `--features postgres` (or another backend)"
                .to_string(),
        );
    }
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("cannot read {path}: {error}")),
    };
    let mut events = Vec::new();
    for (line_no, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let event: ClaimEvent = serde_json::from_str(line)
            .map_err(|error| format!("{path}:{}: corrupt event: {error}", line_no + 1))?;
        events.push(event);
    }
    let store = InMemoryEventStore::from_trusted_events(events)
        .map_err(|error| format!("cannot load {path}: {error}"))?;
    validate_unique_log(&store, now_millis()).map_err(|error| format!("{path}: {error}"))?;
    Ok(store)
}

/// The event log as a raw, ordered `Vec<ClaimEvent>` — the same global append order
/// [`load_store`] reads, but **without** the trusted-reload integrity gate
/// (`validate_unique_log`). The witness must be the *authoritative* tamper oracle: it has to
/// render its own `TAMPER`/`ROLLBACK` verdict even on a log the integrity gate would reject,
/// rather than be preempted by that gate's error. A genuinely unparseable line is still a hard
/// error (nothing to witness).
#[cfg(feature = "witness")]
fn load_raw_events(path: &str) -> Result<Vec<ClaimEvent>, String> {
    #[cfg(feature = "async-store")]
    if let Some(url) = store_url() {
        return backend_scan_raw(&url);
    }
    #[cfg(not(feature = "async-store"))]
    if store_url().is_some() {
        return Err(
            "DENT8_STORE_URL is set but this build has no async backend — \
             rebuild with `--features postgres` (or another backend)"
                .to_string(),
        );
    }
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("cannot read {path}: {error}")),
    };
    let mut events = Vec::new();
    for (line_no, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let event: ClaimEvent = serde_json::from_str(line)
            .map_err(|error| format!("{path}:{}: corrupt event: {error}", line_no + 1))?;
        events.push(event);
    }
    Ok(events)
}

/// Raw ordered backend log for the witness: connect + self-migrate + scan, with **no**
/// integrity gate (see [`load_raw_events`]). Backend-agnostic via [`connect_backend`].
#[cfg(all(feature = "witness", feature = "async-store"))]
fn backend_scan_raw(url: &str) -> Result<Vec<ClaimEvent>, String> {
    use dent8_store::EventFilter;
    store_runtime()?.block_on(async {
        let store = connect_backend(url).await?;
        store
            .scan_events(&EventFilter::default())
            .await
            .map_err(|error| error.to_string())
    })
}

/// On-demand integrity check: re-verify the hash chain and the per-entity lineage.
/// Backend-aware. For **Postgres** it re-verifies the *stored* global chain (real
/// tamper-evidence — a mutated stored event is caught); for the **file dev store** it
/// re-folds and checks structural integrity (tamper-*resistance* over the file log is the
/// witness's job, not this).
/// The result of re-checking persisted write attestations (ADR 0013) during `verify`.
struct AttestationSummary {
    /// Events carrying an attestation.
    attested: usize,
    /// Whether this build can actually verify them (`identity` feature).
    verifiable: bool,
    /// Whether a grant log was present, enabling entitlement verdicts (ADR 0014).
    history: bool,
    /// Attested events whose (source, key) had an active covering grant at write time.
    entitled: usize,
    /// Attested events with no grant history for their key — honest, not a failure.
    unknown_entitlement: usize,
    /// One line per invalid attestation or entitlement violation.
    issues: Vec<String>,
}

impl AttestationSummary {
    /// The clause appended to a verify OK line: silent when nothing is attested, counts when
    /// attestations verify (with entitlement counts when a grant log is present), and an
    /// honest "present but unverifiable" note on a `--no-default-features` build.
    fn ok_clause(&self) -> String {
        if self.attested == 0 {
            String::new()
        } else if !self.verifiable {
            format!(
                ", {} write attestation(s) present but NOT verifiable in this build (rebuild \
                 with the identity feature)",
                self.attested
            )
        } else if self.history {
            format!(
                ", {} write attestation(s) verify ({} entitled at write time, {} unknown — no \
                 grant history)",
                self.attested, self.entitled, self.unknown_entitlement
            )
        } else {
            format!(", {} write attestation(s) verify", self.attested)
        }
    }
}

/// Re-verify every persisted write attestation (signature over the event content), and —
/// when a grant log is present (ADR 0014) — resolve each attested event's **entitlement at
/// write time** against the issuer-signed grant history.
#[cfg(feature = "identity")]
fn check_attestations(events: &[ClaimEvent]) -> AttestationSummary {
    let mut summary = AttestationSummary {
        attested: 0,
        verifiable: true,
        history: false,
        entitled: 0,
        unknown_entitlement: 0,
        issues: Vec::new(),
    };
    let history = match identity::load_grant_history_for_verify() {
        Ok(history) => {
            summary.history = history.is_some();
            history
        }
        Err(message) => {
            summary.issues.push(format!("GRANT LOG: {message}"));
            None
        }
    };
    for event in events {
        match identity::verify_event_attestation(event) {
            Ok(true) => {
                summary.attested += 1;
                if let (Some(records), Some(attestation)) =
                    (history.as_deref(), event.provenance.attestation.as_ref())
                {
                    let subject = format!("{}:{}", event.subject.kind(), event.subject.key());
                    match identity::entitlement_at(
                        records,
                        event.provenance.source.as_str(),
                        &attestation.public_key,
                        event.authority.level,
                        &subject,
                        event.provenance.recorded_at.as_unix_millis(),
                    ) {
                        identity::Entitlement::Entitled => summary.entitled += 1,
                        identity::Entitlement::Unknown => summary.unknown_entitlement += 1,
                        identity::Entitlement::Unentitled(reason) => {
                            summary.issues.push(format!(
                                "ENTITLEMENT: {}: {reason}",
                                event.event_id.as_str()
                            ));
                        }
                    }
                }
            }
            Ok(false) => {}
            Err(message) => {
                summary.attested += 1;
                summary.issues.push(format!("ATTESTATION: {message}"));
            }
        }
    }
    summary
}

/// Without the `identity` feature there is no Ed25519 verifier — count the attestations and
/// let the caller report them as present-but-unverified rather than silently claiming "OK".
#[cfg(not(feature = "identity"))]
fn check_attestations(events: &[ClaimEvent]) -> AttestationSummary {
    AttestationSummary {
        attested: events
            .iter()
            .filter(|event| event.provenance.attestation.is_some())
            .count(),
        verifiable: false,
        history: false,
        entitled: 0,
        unknown_entitlement: 0,
        issues: Vec::new(),
    }
}

fn verify_log(path: &str) -> Result<String, String> {
    #[cfg(feature = "async-store")]
    if let Some(url) = store_url() {
        return backend_verify(&url);
    }
    #[cfg(not(feature = "async-store"))]
    if store_url().is_some() {
        return Err(
            "DENT8_STORE_URL is set but this build has no async backend — \
             rebuild with `--features postgres` (or another backend)"
                .to_string(),
        );
    }
    // `load_store` already runs `validate_unique_log`, so a load error *is* an integrity
    // failure — surface it as one.
    let store = load_store(path).map_err(|error| format!("INTEGRITY FAILURE: {error}"))?;
    // The file store keeps no stored per-event hash, so re-folding only confirms the events
    // canonicalize cleanly — it is NOT a reference to detect a content edit against (a tampered
    // log just re-hashes to a different but self-consistent chain). Real tamper-detection over
    // the file log is `dent8 witness verify`; this command checks *structural* integrity.
    if !store.verify_chain() {
        return Err(format!(
            "INTEGRITY FAILURE: an event does not canonicalize ({} events)",
            store.len()
        ));
    }
    let subjects = store.subjects();
    let mut issues = Vec::new();
    for (subject, predicate) in &subjects {
        let filter = EventFilter {
            subject: Some(subject.clone()),
            predicate: Some(predicate.clone()),
            ..EventFilter::default()
        };
        let events = store
            .scan_events(&filter)
            .map_err(|error| error.to_string())?;
        if let Ok(projection) = replay_entity(&events) {
            for issue in projection.lineage_issues() {
                issues.push(format!(
                    "{}:{} {} — {issue:?}",
                    subject.kind(),
                    subject.key(),
                    predicate.as_str()
                ));
            }
        }
    }
    // Retraction taint (ADR 0010): a still-believed claim deriving from a retracted/expired
    // source is surviving poison — flag it across all entities.
    let all_events = store
        .scan_events(&EventFilter::default())
        .map_err(|error| error.to_string())?;
    for taint in tainted_claims(&all_events).map_err(|error| error.to_string())? {
        issues.push(format!(
            "TAINTED: {} derives from {} (now {:?})",
            taint.claim.as_str(),
            taint.root.as_str(),
            taint.root_lifecycle
        ));
    }
    // Signed write attestations (ADR 0013): re-verify each persisted signature. On the file
    // dev store this is the one *content-tamper* check available without a witness — an edit
    // to an attested event breaks its signature even though there is no stored hash.
    let attestations = check_attestations(&all_events);
    issues.extend(attestations.issues.iter().cloned());
    if !issues.is_empty() {
        return Err(format!(
            "INTEGRITY ISSUES ({} found):\n  {}",
            issues.len(),
            issues.join("\n  ")
        ));
    }
    Ok(format!(
        "OK: {} event(s) across {} entit(ies) — STRUCTURAL integrity holds (uniqueness + \
         lineage intact, no retraction taint, all events canonicalize){}. This does NOT \
         detect a content edit to *unattested* events: the file dev store keeps no stored \
         hash to compare against — use `dent8 witness verify` (or the Postgres backend) for \
         tamper-detection.",
        store.len(),
        subjects.len(),
        attestations.ok_clause()
    ))
}

/// Async-backend integrity check: re-verify the *stored* global hash chain (real
/// tamper-evidence — a mutated stored event is caught) and surface retraction taint.
/// Backend-agnostic via [`connect_backend`].
#[cfg(feature = "async-store")]
fn backend_verify(url: &str) -> Result<String, String> {
    use dent8_store::EventFilter;
    store_runtime()?.block_on(async {
        let store = connect_backend(url).await?;
        if !store
            .verify_chain()
            .await
            .map_err(|error| error.to_string())?
        {
            return Err(
                "INTEGRITY FAILURE: the stored global hash chain does not re-verify \
                        (a stored event was altered)"
                    .to_string(),
            );
        }
        let events = store
            .scan_events(&EventFilter::default())
            .await
            .map_err(|error| error.to_string())?;
        // Retraction taint (ADR 0010): surviving poison — a believed claim deriving from a
        // retracted/expired source.
        let tainted = tainted_claims(&events).map_err(|error| error.to_string())?;
        let mut lines: Vec<String> = tainted
            .iter()
            .map(|taint| {
                format!(
                    "TAINTED: {} derives from {} (now {:?})",
                    taint.claim.as_str(),
                    taint.root.as_str(),
                    taint.root_lifecycle
                )
            })
            .collect();
        // Signed write attestations (ADR 0013): re-verify each persisted signature.
        let attestations = check_attestations(&events);
        lines.extend(attestations.issues.iter().cloned());
        if !lines.is_empty() {
            return Err(format!(
                "INTEGRITY ISSUES ({} found):\n  {}",
                lines.len(),
                lines.join("\n  ")
            ));
        }
        Ok(format!(
            "OK: {} event(s) — the stored global hash chain re-verifies, no retraction taint{}. \
             (Tamper-resistance needs an external operated witness.)",
            events.len(),
            attestations.ok_clause()
        ))
    })
}

fn verify_json(ok: bool, report: &str) -> serde_json::Value {
    let findings = if ok {
        Vec::new()
    } else {
        report
            .lines()
            .skip(1)
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    serde_json::json!({
        "status": if ok { "ok" } else { "failed" },
        "tool": "verify",
        "ok": ok,
        "summary": first_line(report),
        "report": report,
        "findings": findings,
    })
}

fn cmd_verify(output: CliOutput) -> i32 {
    match (verify_log(&log_path()), output) {
        (Ok(report), CliOutput::Text) => {
            println!("{}", paint_status(&report, CliStream::Stdout));
            0
        }
        (Ok(report), CliOutput::Json) => print_json_stdout(&verify_json(true, &report)),
        (Err(message), CliOutput::Text) => {
            eprintln!("{}", paint_status(&message, CliStream::Stderr));
            1
        }
        (Err(message), CliOutput::Json) => {
            print_json_stdout(&verify_json(false, &message));
            1
        }
    }
}

/// Run the adversarial corpus and print the firewall-vs-recency-baseline contrast — the
/// self-demonstrating "why dent8" benchmark. Exits non-zero only if a scenario regresses.
fn cmd_eval(output: CliOutput) -> i32 {
    let results = dent8_evals::run_corpus();
    let demonstrated = results
        .iter()
        .filter(|result| result.demonstrates_defense())
        .count();
    let exit_code = i32::from(demonstrated != results.len());
    match output {
        CliOutput::Text => {
            println!(
                "dent8 adversarial corpus — {demonstrated}/{} scenarios demonstrate the firewall's \
                 defense:\nthe firewall blocks every attack a recency-only baseline (newest-write-wins, \
                 no authority/dependency) falls to.\n",
                results.len()
            );
            print!("{}", dent8_evals::summary_table());
            exit_code
        }
        CliOutput::Json => {
            print_json_stdout_with_code(&eval_json(&results, demonstrated), exit_code)
        }
    }
}

fn eval_json(results: &[dent8_evals::AttackResult], demonstrated: usize) -> serde_json::Value {
    let scenarios = results
        .iter()
        .map(|result| {
            serde_json::json!({
                "name": result.name,
                "family": result.family,
                "firewall_blocked": result.firewall_blocked,
                "baseline_compromised": result.baseline_compromised,
                "demonstrates_defense": result.demonstrates_defense(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": if demonstrated == results.len() { "ok" } else { "failed" },
        "tool": "eval",
        "scenario_count": results.len(),
        "demonstrated_count": demonstrated,
        "scenarios": scenarios,
    })
}

/// Export the whole event log to a flattened Parquet file for offline `DuckDB` analysis
/// (forensics, audit, replay-at-scale). Read-only and backend-aware via `load_store`, so it
/// snapshots the file *or* the Postgres log. Gated behind `--features export` so the stock
/// binary carries no arrow/parquet stack.
#[cfg(feature = "export")]
fn cmd_export(out: &str, output: CliOutput) -> i32 {
    let store = match load_store(&log_path()) {
        Ok(store) => store,
        Err(error) => {
            return match output {
                CliOutput::Text => {
                    eprintln!("{error}");
                    2
                }
                CliOutput::Json => print_json_stderr(&export_error_json(out, &error), 2),
            };
        }
    };
    let events = match store.scan_events(&EventFilter::default()) {
        Ok(events) => events,
        Err(error) => {
            let message = format!("cannot read the log: {error}");
            return match output {
                CliOutput::Text => {
                    eprintln!("{message}");
                    1
                }
                CliOutput::Json => print_json_stderr(&export_error_json(out, &message), 1),
            };
        }
    };
    let file = match std::fs::File::create(out) {
        Ok(file) => file,
        Err(error) => {
            let message = format!("cannot create {out}: {error}");
            return match output {
                CliOutput::Text => {
                    eprintln!("{message}");
                    1
                }
                CliOutput::Json => print_json_stderr(&export_error_json(out, &message), 1),
            };
        }
    };
    match dent8_export::export_events(&events, file) {
        Ok(()) => {
            let event_count = events.len();
            let message = export_message(out, event_count);
            match output {
                CliOutput::Text => {
                    println!("{message}");
                    0
                }
                CliOutput::Json => print_json_stdout(&serde_json::json!({
                    "status": "ok",
                    "tool": "export",
                    "out": out,
                    "format": "parquet",
                    "event_count": event_count,
                    "message": message,
                })),
            }
        }
        Err(error) => {
            let message = format!("export failed: {error}");
            match output {
                CliOutput::Text => {
                    eprintln!("{message}");
                    1
                }
                CliOutput::Json => print_json_stderr(&export_error_json(out, &message), 1),
            }
        }
    }
}

#[cfg(not(feature = "export"))]
fn cmd_export_unavailable(out: &str, output: CliOutput) -> i32 {
    let message = "`dent8 export` (Parquet for DuckDB) requires a build with `--features export`";
    match output {
        CliOutput::Text => {
            eprintln!("{message}");
            2
        }
        CliOutput::Json => print_json_stderr(&export_error_json(out, message), 2),
    }
}

#[cfg(feature = "export")]
fn export_message(out: &str, event_count: usize) -> String {
    format!(
        "exported {event_count} event(s) to {out}\n  query it with DuckDB, e.g.:\n    \
         duckdb -c \"SELECT source, count(*) AS writes FROM '{out}' GROUP BY 1 ORDER BY 2 DESC\"\n    \
         duckdb -c \"SELECT claim_id, UNNEST(derived_from) AS source_claim FROM '{out}' WHERE derived_from IS NOT NULL\"",
    )
}

fn export_error_json(out: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "export",
        "out": out,
        "format": "parquet",
        "message": message,
    })
}

/// The next event/claim sequence: one past the **highest** `event:{n}` id actually
/// present, not the log line-count — so a lost or surgically-removed line cannot make a
/// later command mint a colliding id (which would wedge the command and the reload).
fn next_seq(store: &InMemoryEventStore) -> usize {
    store.scan_events(&EventFilter::default()).map_or_else(
        |_| store.len(),
        |events| {
            events
                .iter()
                .filter_map(|event| event.event_id.as_str().strip_prefix("event:"))
                .filter_map(|n| n.parse::<usize>().ok())
                .max()
                .map_or(0, |max| max + 1)
        },
    )
}

/// Reject a log that already violates per-predicate uniqueness (more than one *fresh*
/// believed claim for a `unique` predicate). A legitimate stale + fresh pair is allowed
/// (only one is fresh); two fresh believed claims signal corruption (a torn write or an
/// external edit), which the trusted-reload path would otherwise accept silently.
fn validate_unique_log(store: &InMemoryEventStore, now: TimestampMillis) -> Result<(), String> {
    let registry = PredicateRegistry::coding_agent();
    let all = store
        .scan_events(&EventFilter::default())
        .map_err(|error| error.to_string())?;
    let mut seen = std::collections::HashSet::new();
    for event in &all {
        if !seen.insert(event.subject.clone()) {
            continue;
        }
        let filter = EventFilter {
            subject: Some(event.subject.clone()),
            ..EventFilter::default()
        };
        let entity = replay_entity(&store.scan_events(&filter).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        // A supersession whose replacement is *missing* (dangling) or *cyclic* silently
        // drops the fact — the symmetric corruption to a duplicated belief, which the
        // >1-fresh check below never catches (0 fresh). Flag only those. NOT
        // `SupersededByInvalidated`: a successor that was legitimately retracted or expired
        // (e.g. assert -> supersede -> retract) is a valid history, not corruption.
        if let Some(issue) = entity.lineage_issues().into_iter().find(|issue| {
            matches!(
                issue,
                LineageIssue::DanglingSupersession { .. } | LineageIssue::SupersessionCycle { .. }
            )
        }) {
            return Err(format!(
                "corrupt log: {} entity has a broken supersession lineage ({issue:?}) \
                 (possible external edit)",
                event.subject.kind()
            ));
        }
        let fresh: Vec<_> = entity
            .believed()
            .filter(|state| !state.is_expired_at(now))
            .collect();
        for state in &fresh {
            let group: Vec<_> = fresh
                .iter()
                .filter(|other| other.predicate == state.predicate)
                .collect();
            if group.len() <= 1
                || !registry
                    .policy_for(&event.subject, &state.predicate)
                    .is_some_and(|policy| policy.unique)
            {
                continue;
            }
            // A *surfaced* conflict (ADR 0009) is exactly the `Contested` claims plus the
            // contradictors they name; everything in that set is audited. Any *other*
            // believed claim is silent duplication — corruption a single contradiction must
            // not launder. So account for the contested claims + their contradictors, and
            // reject if any believed claim is left unaccounted-for.
            let mut accounted: Vec<&ClaimId> = Vec::new();
            for s in &group {
                if s.lifecycle == ClaimLifecycle::Contested {
                    accounted.push(&s.claim_id);
                    accounted.extend(s.contradicted_by.iter());
                }
            }
            let unaccounted = group
                .iter()
                .filter(|s| !accounted.contains(&&s.claim_id))
                .count();
            if unaccounted > 0 {
                return Err(format!(
                    "corrupt log: {}.{} has {unaccounted} fresh believed claim(s) not \
                     explained by a contest for a unique predicate (possible torn write or \
                     external edit)",
                    event.subject.kind(),
                    state.predicate.as_str(),
                ));
            }
        }
    }
    Ok(())
}

/// The outcome of a durable append. `Conflict` is the **retryable** Postgres optimistic-id
/// race — a concurrent writer committed our snapshot-derived `event:{n}` id first — which a
/// fresh-snapshot retry resolves; every other failure is terminal. The file dev store is
/// single-writer and never conflicts (so the variant is unused without the `postgres` feature).
enum WriteError {
    #[cfg_attr(not(feature = "postgres"), allow(dead_code))]
    Conflict(String),
    Other(String),
}

/// Append admitted events to the durable log as JSON lines in a **single write** so a
/// multi-event operation (e.g. a supersession's replacement + supersession events) lands
/// all-or-nothing at the file boundary. This is best-effort file atomicity for the dev
/// store; true transactional atomicity belongs to the async backends.
fn append_events(path: &str, events: &mut [ClaimEvent]) -> Result<(), WriteError> {
    use std::io::Write;
    // Sign the write attestations (ADR 0013) at this choke point — after every op-level
    // mutation, immediately before persistence — so each signature covers exactly the stored
    // content and the append's hash chain covers the attestation.
    attest_events(events).map_err(WriteError::Other)?;
    // An async backend commits the whole operation (assert / supersede / retract / contradict)
    // as one transaction via `append_many`; the file store just appends the lines. (A build
    // with no async backend that reaches here with a store URL set already errored in
    // `load_store`.)
    #[cfg(feature = "async-store")]
    if let Some(url) = store_url() {
        let refs: Vec<&ClaimEvent> = events.iter().collect();
        return backend_append(&url, &refs);
    }
    let mut buffer = String::new();
    for event in events.iter() {
        let line = serde_json::to_string(event)
            .map_err(|error| WriteError::Other(format!("serialize: {error}")))?;
        buffer.push_str(&line);
        buffer.push('\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| WriteError::Other(format!("cannot open {path}: {error}")))?;
    file.write_all(buffer.as_bytes())
        .map_err(|error| WriteError::Other(format!("cannot write {path}: {error}")))
}

/// Sign per-event write attestations when signed identity is configured (ADR 0013); a no-op
/// in unconfigured dev mode.
#[cfg(feature = "identity")]
fn attest_events(events: &mut [ClaimEvent]) -> Result<(), String> {
    identity::attest_events(events).map(|_| ())
}

/// Without the `identity` feature there is no signer. `enforce_source_identity` has already
/// failed closed if identity is *configured* in this build, so reaching here means dev mode —
/// events are simply written unattested.
#[cfg(not(feature = "identity"))]
#[allow(clippy::unnecessary_wraps)] // signature mirrors the identity variant
fn attest_events(_events: &mut [ClaimEvent]) -> Result<(), String> {
    Ok(())
}

/// The async-backend URL from `DENT8_STORE_URL` (dispatched by scheme). `None` selects the
/// file dev store. Always available (just env reads), so the file-only build can still detect
/// "a store URL is set but no backend is compiled in."
///
/// A set-but-empty (or whitespace-only) value counts as **unset** (`DENT8_STORE_URL=` does not
/// disable the file store); the value is trimmed so a quoted/padded `.env` entry still dispatches.
fn store_url() -> Option<String> {
    std::env::var("DENT8_STORE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// A throwaway current-thread runtime to bridge the sync CLI to an async backend. One per
/// storage call is fine for a single-operation CLI process, and the single thread is why
/// [`dent8_store::AsyncEventStore`] can be `?Send`.
#[cfg(feature = "async-store")]
fn store_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("tokio runtime: {error}"))
}

/// Connect to the async backend selected by the URL **scheme** and self-migrate. The single
/// place that maps a scheme to a concrete backend — adding a backend is one arm here, not a
/// change at every call site.
///
/// `async-store` is an umbrella feature enabled *by* a backend (e.g. `postgres`); enabling it
/// alone yields a build with no backend arms, where every store URL gets the "no matching
/// backend" error below — hence `unused_async` is allowed (the awaits live in the cfg'd arms).
#[cfg(feature = "async-store")]
#[allow(clippy::unused_async)]
async fn connect_backend(url: &str) -> Result<Box<dyn dent8_store::AsyncEventStore>, String> {
    // The scheme is everything before the first `:` (RFC 3986) and is case-insensitive, so
    // match on the lowercased scheme — but pass the *original* url to the driver (case is
    // significant in credentials/host/path).
    let scheme = url
        .split_once(':')
        .map_or("", |(scheme, _)| scheme)
        .to_ascii_lowercase();
    match scheme.as_str() {
        #[cfg(feature = "postgres")]
        "postgres" | "postgresql" => {
            use dent8_store_postgres::PostgresEventStore;
            let store = PostgresEventStore::connect(url)
                .await
                .map_err(|error| error.to_string())?;
            dent8_store::AsyncEventStore::migrate(&store)
                .await
                .map_err(|error| error.to_string())?;
            Ok(Box::new(store))
        }
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            use dent8_store_sqlite::SqliteEventStore;
            let store = SqliteEventStore::connect(url)
                .await
                .map_err(|error| error.to_string())?;
            dent8_store::AsyncEventStore::migrate(&store)
                .await
                .map_err(|error| error.to_string())?;
            Ok(Box::new(store))
        }
        _ => Err(format!(
            "unsupported store URL `{url}`: no matching backend in this build \
             (postgres:// needs `--features postgres`; sqlite:// is in default builds or \
             needs `--features sqlite` when defaults are disabled)"
        )),
    }
}

/// Load the whole backend log into an in-memory working store (the decide snapshot the `op_*`
/// functions read), connecting + self-migrating on the way. Backend-agnostic via
/// [`connect_backend`].
#[cfg(feature = "async-store")]
fn backend_load(url: &str) -> Result<InMemoryEventStore, String> {
    use dent8_store::EventFilter;
    store_runtime()?.block_on(async {
        let store = connect_backend(url).await?;
        let events = store
            .scan_events(&EventFilter::default())
            .await
            .map_err(|error| error.to_string())?;
        let working = InMemoryEventStore::from_trusted_events(events)
            .map_err(|error| format!("cannot load store log: {error}"))?;
        // Re-run the same integrity gate the file path enforces, so an operational backend is
        // at least as defensive: a torn/forged state (e.g. a direct SQL edit) is rejected, not
        // silently believed.
        validate_unique_log(&working, now_millis())?;
        Ok(working)
    })
}

/// Persist an accepted operation as **one transaction** (`append_many`), so a multi-event
/// supersede/retract/contradict commits atomically and is re-arbitrated by the durable
/// firewall. Backend-agnostic.
///
/// v0 concurrency: commits are serialized by the backend (Postgres' advisory lock; `SQLite`'s
/// `BEGIN IMMEDIATE` + `busy_timeout`), so concurrent writers wait rather than corrupt — but
/// event/claim ids are minted optimistically from a snapshot, so two writers racing the same
/// backend can collide. The loser gets a **retryable** conflict (a duplicate id, or — on
/// `SQLite` — a lock still held past the timeout), which [`with_write_retry`] re-runs.
#[cfg(feature = "async-store")]
fn backend_append(url: &str, events: &[&ClaimEvent]) -> Result<(), WriteError> {
    use dent8_store::StoreError;
    let owned: Vec<ClaimEvent> = events.iter().map(|&event| event.clone()).collect();
    store_runtime().map_err(WriteError::Other)?.block_on(async {
        let store = connect_backend(url).await.map_err(WriteError::Other)?;
        store
            .append_many(owned)
            .await
            .map_err(|error| match error {
                // A duplicate id under the optimistic scheme is a race, not corruption: signal it
                // as retryable so the caller re-snapshots and re-mints a non-colliding id.
                StoreError::Conflict(message) => WriteError::Conflict(message),
                other => WriteError::Other(other.to_string()),
            })?;
        Ok(())
    })
}

fn print_json_stdout(value: &serde_json::Value) -> i32 {
    print_json_stdout_with_code(value, 0)
}

fn print_json_stdout_with_code(value: &serde_json::Value, code: i32) -> i32 {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("CLI JSON output should serialize")
    );
    code
}

fn print_json_stderr(value: &serde_json::Value, code: i32) -> i32 {
    eprintln!(
        "{}",
        serde_json::to_string_pretty(value).expect("CLI JSON error output should serialize")
    );
    code
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn assert_event(
    event_id: &str,
    claim_id: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    value: &str,
    source: &str,
    authority: AuthorityLevel,
) -> ClaimEvent {
    let mut event = base(
        event_id,
        claim_id,
        subject_kind,
        subject_key,
        predicate,
        source,
        authority,
    );
    event.kind = ClaimEventKind::Asserted;
    event.value = Some(ClaimValue::Text(value.to_string()));
    event
}

#[cfg(test)]
fn base(
    event_id: &str,
    claim_id: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    source: &str,
    authority: AuthorityLevel,
) -> ClaimEvent {
    ClaimEvent {
        event_id: ClaimEventId::new(event_id).expect("event id"),
        claim_id: ClaimId::new(claim_id).expect("claim id"),
        kind: ClaimEventKind::Asserted,
        subject: EntityRef::new(subject_kind, subject_key).expect("entity"),
        predicate: Predicate::new(predicate).expect("predicate"),
        value: None,
        confidence: Confidence::from_millis(900).expect("confidence"),
        authority: Authority {
            level: authority,
            issuer: None,
            scope: None,
        },
        ttl: Ttl::Never,
        provenance: Provenance {
            source: dent8_core::SourceId::new(source).expect("source"),
            actor: ActorId::new("actor:test").expect("actor"),
            tool: Some("dent8-test".to_string()),
            run_id: None,
            input_digest: None,
            recorded_at: TimestampMillis::from_unix_millis(1),
            attestation: None,
        },
        evidence: vec![Evidence {
            id: EvidenceId::new("evidence:1").expect("evidence id"),
            kind: EvidenceKind::UserStatement,
            locator: source.to_string(),
            digest: None,
            summary: None,
        }],
        observed_at: None,
        valid_from: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authority_ceiling_rejects_writes_above_a_source_grant() {
        let mut registry = SourceRegistry::default();
        registry.sources.insert(
            "source:owner".to_string(),
            SourceGrant {
                max_authority: AuthorityLevel::High,
                issuer: None,
                scope: None,
            },
        );
        let check = |source, level| ceiling_check(Some(&registry), source, level);

        // At or below the grant is admitted.
        assert!(check("source:owner", AuthorityLevel::High).is_ok());
        assert!(check("source:owner", AuthorityLevel::Low).is_ok());
        // Above the grant is rejected (a low/medium source cannot mint canonical).
        assert!(matches!(
            check("source:owner", AuthorityLevel::Canonical),
            Err(ops::OpError::Rejected(_))
        ));
        // An unregistered source has an Unknown ceiling: anything above Unknown is rejected.
        assert!(matches!(
            check("source:web-scrape", AuthorityLevel::Low),
            Err(ops::OpError::Rejected(_))
        ));
        assert!(check("source:web-scrape", AuthorityLevel::Unknown).is_ok());
        // No registry configured -> permissive (dev mode).
        assert!(ceiling_check(None, "source:web-scrape", AuthorityLevel::Canonical).is_ok());
    }

    #[test]
    fn authority_required_fails_closed_when_the_registry_is_missing() {
        let path = std::env::temp_dir().join(format!(
            "dent8-authority-missing-{}-{}.json",
            std::process::id(),
            line!()
        ));
        let path = path.to_string_lossy().into_owned();
        let _ = std::fs::remove_file(&path);

        assert!(
            load_authority_registry_at(&path, false)
                .expect("optional registry may be absent")
                .is_none()
        );
        let error = load_authority_registry_at(&path, true)
            .expect_err("required missing registry fails closed");
        assert!(error.contains("DENT8_REQUIRE_AUTHORITY"), "{error}");
    }

    #[test]
    fn authority_required_flag_is_parsed_strictly() {
        assert!(parse_flag("DENT8_REQUIRE_AUTHORITY", "true").expect("true"));
        assert!(parse_flag("DENT8_REQUIRE_AUTHORITY", "1").expect("1"));
        assert!(!parse_flag("DENT8_REQUIRE_AUTHORITY", "off").expect("off"));
        assert!(parse_flag("DENT8_REQUIRE_AUTHORITY", "maybe").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn apply_dent8_env_scrubs_active_grants_unless_explicitly_installed() {
        let mut command = std::process::Command::new("sh");
        command
            .args(["-c", "printf '%s' \"${DENT8_ACTIVE_GRANTS-unset}\""])
            .env("DENT8_ACTIVE_GRANTS", "leaked-from-parent");
        doctor::apply_dent8_env(&mut command, &std::collections::BTreeMap::new());

        let output = command.output().expect("run shell");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "unset");

        let mut command = std::process::Command::new("sh");
        command
            .args(["-c", "printf '%s' \"$DENT8_ACTIVE_GRANTS\""])
            .env("DENT8_ACTIVE_GRANTS", "leaked-from-parent");
        let env = std::collections::BTreeMap::from([(
            "DENT8_ACTIVE_GRANTS".to_string(),
            "installed-active-grants.json".to_string(),
        )]);
        doctor::apply_dent8_env(&mut command, &env);

        let output = command.output().expect("run shell");
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "installed-active-grants.json"
        );
    }

    #[test]
    fn the_read_annotation_flags_stale_and_terminal_facts() {
        // A fresh, believed fact gets no annotation.
        assert!(read_annotation(ClaimLifecycle::Active, true).is_empty());
        // An Active fact past its TTL is flagged stale (the T4 read-surface verdict).
        assert!(read_annotation(ClaimLifecycle::Active, false).contains("stale"));
        // A terminal fact is flagged no-longer-believed...
        assert!(read_annotation(ClaimLifecycle::Superseded, true).contains("no longer believed"));
        // ...and that verdict wins even if it is also stale.
        assert!(read_annotation(ClaimLifecycle::Retracted, false).contains("no longer believed"));
    }

    /// A durable log with a hole at `event:2` — a line lost to a torn write or to manual /
    /// tool log surgery. The highest id present (`3`) and the line-count (`3`) coincide,
    /// which is exactly the case the old `seq = store.len()` got wrong.
    fn gapped_log() -> Vec<ClaimEvent> {
        vec![
            assert_event(
                "event:0",
                "claim:repo:a:database:0",
                "repo",
                "a",
                "database",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ),
            assert_event(
                "event:1",
                "claim:repo:b:lang:1",
                "repo",
                "b",
                "lang",
                "rust",
                "source:owner",
                AuthorityLevel::High,
            ),
            // event:2 is missing — the gap.
            assert_event(
                "event:3",
                "claim:repo:c:ci:3",
                "repo",
                "c",
                "ci",
                "green",
                "source:owner",
                AuthorityLevel::High,
            ),
        ]
    }

    /// Regression: the next sequence is one past the **highest** id actually present, not
    /// the line-count. After a gap the two diverge, and only the max-derived seq avoids
    /// minting an id that already exists.
    #[test]
    fn next_seq_is_one_past_the_highest_id_not_the_line_count() {
        let events = gapped_log();
        let store =
            InMemoryEventStore::from_trusted_events(events.clone()).expect("reload gap log");

        // The line-count — the pre-fix seq source — is 3, the trailing number of an id that
        // is already in the log. Deriving from the max id steps past it to 4.
        assert_eq!(store.len(), 3);
        assert_eq!(
            next_seq(&store),
            4,
            "next seq must be one past the highest id, not the line count"
        );
    }

    /// Regression: the id `assert` mints after a gap is unique, so the append + next reload
    /// does not wedge on a duplicate `event_id`.
    #[test]
    fn assert_after_a_gap_mints_a_non_colliding_event_id() {
        let mut events = gapped_log();
        let store =
            InMemoryEventStore::from_trusted_events(events.clone()).expect("reload gap log");

        let seq = next_seq(&store);
        events.push(assert_event(
            &format!("event:{seq}"),
            &format!("claim:repo:a:database:{seq}"),
            "repo",
            "a",
            "database",
            "mysql",
            "source:owner",
            AuthorityLevel::High,
        ));

        // The grown log reloads cleanly through the trusted path that would otherwise reject
        // a reused id with `StoreError::Conflict("duplicate event_id ...")`.
        assert!(
            InMemoryEventStore::from_trusted_events(events).is_ok(),
            "minted id must not collide with an existing event on reload"
        );
    }

    /// The bug this guards against: deriving the seq from the line-count reuses `event:3`
    /// after the gap, and the very next reload wedges the store with a duplicate-id conflict.
    #[test]
    fn line_count_seq_would_collide_after_a_gap() {
        let mut events = gapped_log();
        let store =
            InMemoryEventStore::from_trusted_events(events.clone()).expect("reload gap log");

        let buggy_seq = store.len(); // the pre-fix computation: 3
        events.push(assert_event(
            &format!("event:{buggy_seq}"),
            &format!("claim:repo:a:database:{buggy_seq}"),
            "repo",
            "a",
            "database",
            "mysql",
            "source:owner",
            AuthorityLevel::High,
        ));

        assert!(
            matches!(
                InMemoryEventStore::from_trusted_events(events),
                Err(StoreError::Conflict(_))
            ),
            "line-count seq reuses event:3 and must wedge the reload — this is the regression"
        );
    }

    /// Regression for the `supersede` write path: `build_revision` seeds its replacement +
    /// supersession ids from `next_seq`, so after a gap they continue past the highest id
    /// (`event:4`, `event:5`) instead of colliding, and the revised log reloads cleanly.
    #[test]
    fn supersede_after_a_gap_mints_unique_non_colliding_ids() {
        let mut events = gapped_log();
        let store =
            InMemoryEventStore::from_trusted_events(events.clone()).expect("reload gap log");

        let seq = next_seq(&store);
        let incumbents = vec![ClaimId::new("claim:repo:a:database:0").expect("claim id")];
        let (revision, _replacement) = ops::build_revision(
            seq,
            &incumbents,
            "repo",
            "a",
            "database",
            "mysql",
            "source:owner",
            AuthorityLevel::High,
            TimestampMillis::from_unix_millis(1),
        )
        .expect("build revision");

        let ids: Vec<&str> = revision.iter().map(|e| e.event_id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["event:4", "event:5"],
            "revision ids must continue past the highest existing id"
        );

        events.extend(revision);
        assert!(
            InMemoryEventStore::from_trusted_events(events).is_ok(),
            "revised log must reload without a duplicate-id conflict"
        );
    }
}
