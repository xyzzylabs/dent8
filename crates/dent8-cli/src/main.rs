use std::{
    io::{self, IsTerminal, Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    str::FromStr,
    sync::atomic::{AtomicU8, Ordering},
    time::{Duration, Instant},
};

use clap::builder::styling::{AnsiColor, Styles};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use dent8_core::{
    ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
    ClaimLifecycle, ClaimValue, Confidence, ContradictionBasis, EntityRef, Evidence, EvidenceId,
    EvidenceKind, Predicate, Provenance, RetractionReason, SupersessionReason, TimestampMillis,
    Ttl,
};
use dent8_store::{
    AppendReceipt, EventFilter, EventStore, InMemoryEventStore, IntegrityReceipt, LineageIssue,
    PredicateRegistry, StoreError, apply_policy_defaults, enforce_policy, replay_entity,
    tainted_claims,
};
use dent8_store_postgres::{EVENT_LOG_SCHEMA_SQL, MATERIALIZATION_SCHEMA_SQL};

#[cfg(feature = "identity")]
mod identity;
mod mcp;
mod mcp_config;
#[cfg(feature = "witness")]
mod witness;

const DEFAULT_MCP_SMOKE_TIMEOUT: Duration = Duration::from_secs(10);

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
    match cli.command {
        None => {
            let mut command = Cli::command()
                .color(cli.color.clap_choice())
                .styles(cli_styles());
            let _ = command.print_help();
            println!();
            0
        }
        Some(CliCommand::Demo) => {
            demo();
            0
        }
        Some(CliCommand::Verify) => cmd_verify(),
        Some(CliCommand::Conflicts) => cmd_conflicts(),
        Some(CliCommand::Eval) => cmd_eval(),
        Some(CliCommand::Init(args)) => cmd_init(&args),
        Some(CliCommand::Doctor(args)) => cmd_doctor(&args),
        Some(CliCommand::Completions(args)) => cmd_completions(args.shell),
        Some(CliCommand::Export(args)) => {
            #[cfg(feature = "export")]
            {
                cmd_export(&args.out)
            }
            #[cfg(not(feature = "export"))]
            {
                let _ = args;
                eprintln!(
                    "`dent8 export` (Parquet for DuckDB) requires a build with `--features export`"
                );
                2
            }
        }
        Some(CliCommand::Assert(args)) => cmd_assert(&args),
        Some(CliCommand::Derive(args)) => cmd_derive(&args),
        Some(CliCommand::Supersede(args)) => cmd_supersede(&args),
        Some(CliCommand::Retract(args)) => cmd_retract(&args),
        Some(CliCommand::Reinforce(args)) => cmd_reinforce(&args),
        Some(CliCommand::Expire(args)) => cmd_expire(&args),
        Some(CliCommand::Contradict(args)) => cmd_contradict(&args),
        Some(CliCommand::Explain(args)) => cmd_explain(&args),
        Some(CliCommand::Replay(args)) => cmd_replay(&args),
        Some(CliCommand::Authority(args)) => match args.command {
            AuthorityCommand::List => cmd_authority_list(),
            AuthorityCommand::Add(args) => cmd_authority_add(
                &args.source,
                args.max.level(),
                args.issuer.as_deref(),
                args.scope.as_deref(),
            ),
            AuthorityCommand::Remove(args) => cmd_authority_remove(&args.source),
        },
        Some(CliCommand::Identity(args)) => run_identity(&args.command),
        Some(CliCommand::Hook(args)) => match args.command {
            HookCommand::NativeMemoryGuard => cmd_hook_native_memory_guard(),
        },
        Some(CliCommand::Mcp(args)) => match args.command {
            McpCommand::Serve => mcp::serve(),
            McpCommand::Install(args) => cmd_mcp_install(&args),
        },
        Some(CliCommand::Schema(args)) => match args.command {
            SchemaCommand::Postgres => {
                // Print exactly the schema `migrate()` deploys (the event-log table + the
                // materialized projection/edges), so an operator who pre-creates it gets the
                // tables the runtime actually uses (a richer per-column layout is possible later).
                print!("{EVENT_LOG_SCHEMA_SQL}{MATERIALIZATION_SCHEMA_SQL}");
                0
            }
        },
        Some(CliCommand::Witness(args)) => run_witness(&args.args),
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
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Run the firewall + replay/explain loop in memory.
    Demo,
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
    /// Check log integrity.
    Verify,
    /// List contested facts.
    Conflicts,
    /// Run the adversarial corpus.
    Eval,
    /// Bootstrap a local dent8 project configuration.
    Init(InitArgs),
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
    #[command(flatten)]
    mcp: InitMcpArgs,
    /// Overwrite the generated env file if it already exists.
    #[arg(long)]
    force: bool,
}

#[derive(Args, Debug)]
struct InitMcpArgs {
    /// Patch the selected agent's MCP config after init and show the resulting file.
    #[arg(long, requires = "agent")]
    install_mcp: bool,
    /// MCP config file to patch when --install-mcp is set.
    #[arg(long, value_name = "PATH", requires = "install_mcp")]
    mcp_config: Option<String>,
    /// Command written into the installed MCP config.
    #[arg(long, value_name = "COMMAND", requires = "install_mcp")]
    mcp_command: Option<String>,
    /// Render the MCP config change after init without writing it.
    #[arg(long, requires = "install_mcp", conflicts_with = "mcp_check")]
    mcp_dry_run: bool,
    /// Check whether the MCP config is already installed after init without writing it.
    #[arg(long, requires = "install_mcp")]
    mcp_check: bool,
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
    #[arg(long, value_name = "COMMAND", requires = "agent")]
    mcp_command: Option<String>,
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
    #[arg(long, default_value = "dent8", value_name = "COMMAND")]
    command: String,
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

fn parse_source(raw: &str) -> Result<String, String> {
    ActorId::new(raw).map_err(|error| format!("invalid source '{raw}': {error}"))?;
    Ok(raw.to_string())
}

fn run_identity(command: &IdentityCommand) -> i32 {
    #[cfg(not(feature = "identity"))]
    {
        let _ = command;
        eprintln!("`dent8 identity` requires a build with `--features identity`");
        2
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
        ),
        IdentityCommand::IssuerKeygen(args) => identity::issuer_keygen(&args.out),
        IdentityCommand::AgentKeygen(args) => identity::agent_keygen(&args.source, &args.out),
        IdentityCommand::TrustAdd(args) => identity::trust_add(&args.issuer, &args.public_key),
        IdentityCommand::TrustList => identity::trust_list(),
        IdentityCommand::GrantIssue(args) => identity::grant_issue(
            &args.source,
            &args.public_key,
            args.max,
            &args.issuer,
            &args.issuer_key,
            &args.out,
            args.scope.as_deref(),
            args.expires_at_ms,
        ),
        IdentityCommand::GrantVerify(args) => identity::grant_verify(&args.grant),
    }
}

/// Dispatch `dent8 witness <sub>`. Feature-gated: without `--features witness` the command
/// exists only to explain how to enable it.
fn run_witness(args: &[String]) -> i32 {
    #[cfg(not(feature = "witness"))]
    {
        let _ = args;
        eprintln!("`dent8 witness` requires a build with `--features witness`");
        2
    }
    #[cfg(feature = "witness")]
    match args {
        [sub] if sub == "keygen" => witness::keygen(),
        [sub] if sub == "sign" => witness::sign(),
        [sub] if sub == "verify" => witness::verify(),
        [sub] if sub == "head" => witness::head(),
        [sub, rest @ ..] if sub == "serve" => witness::serve(rest),
        _ => {
            eprintln!(
                "usage: dent8 witness <keygen | sign | verify | head | \
                 serve [interval-seconds] [max-heads]>"
            );
            2
        }
    }
}

fn cmd_completions(shell: Shell) -> i32 {
    let mut command = Cli::command();
    let name = command.get_name().to_string();
    generate(shell, &mut command, name, &mut std::io::stdout());
    0
}

/// A runnable, self-contained demonstration of the firewall + replay/explain loop,
/// driven by the coding-agent predicate policy registry: a high-authority project fact
/// is asserted; a low-authority source is rejected by the predicate's authority floor; a
/// competing claim is rejected by uniqueness; and a `branch.status` fact goes stale on
/// its registered default TTL.
fn demo() {
    let registry = PredicateRegistry::coding_agent();
    let mut store = InMemoryEventStore::new();
    let now = TimestampMillis::from_unix_millis(4_000_000);

    println!("dent8 firewall demo — coding-agent policy registry (in-memory backend)\n");

    // [1] A trusted, high-authority project fact. repo.database requires High authority.
    match admit(
        &mut store,
        &registry,
        assert_event(
            "event:1",
            "claim:database",
            "repo",
            "myproj",
            "database",
            "postgres",
            "source:owner",
            AuthorityLevel::High,
        ),
        now,
    ) {
        Ok(receipt) => println!(
            "[1] assert    repo:myproj database = \"postgres\"  (authority=High, source=owner)\n    \
             -> ACCEPTED  seq={}  hash={}",
            receipt.global_sequence,
            short(&receipt.event_hash),
        ),
        Err(error) => println!("[1] unexpected rejection: {error}"),
    }

    // [2] A low-authority source cannot even register the fact: repo.database's policy
    // floor is High, so the assertion is rejected before it reaches the log.
    match admit(
        &mut store,
        &registry,
        assert_event(
            "event:2",
            "claim:attacker",
            "repo",
            "myproj",
            "database",
            "mysql",
            "source:web-scrape",
            AuthorityLevel::Low,
        ),
        now,
    ) {
        Ok(_) => println!("\n[2] low-authority assert unexpectedly ACCEPTED (bug)"),
        Err(error) => println!(
            "\n[2] assert    repo:myproj database = \"mysql\"     (authority=Low, source=web-scrape)\n    \
             -> REJECTED: {error}"
        ),
    }

    // [3] The trusted fact is unchanged and explainable.
    println!("\n[3] explain   repo:myproj database");
    print_receipt(&store, "claim:database", now);

    // [4] Freshness comes from the predicate's policy: branch.status carries a default
    // TTL, so a CI status goes stale on its own (no explicit TTL set on the assertion).
    let _ = admit(
        &mut store,
        &registry,
        assert_event(
            "event:3",
            "claim:branch",
            "branch",
            "main",
            "status",
            "ci-green",
            "source:ci",
            AuthorityLevel::Low,
        ),
        now,
    );
    println!(
        "\n[4] assert    branch:main status = \"ci-green\"   (branch.status default TTL applied)\n    \
         explain as-of now=4_000_000 (past the 1h TTL)"
    );
    print_receipt(&store, "claim:branch", now);

    // [5] Uniqueness: even a high-authority *competing* assertion is rejected — there may
    // be only one believed repo.database. Revise it with a supersession, don't duplicate.
    match admit(
        &mut store,
        &registry,
        assert_event(
            "event:4",
            "claim:rival",
            "repo",
            "myproj",
            "database",
            "mariadb",
            "source:owner",
            AuthorityLevel::High,
        ),
        now,
    ) {
        Ok(_) => println!("\n[5] competing assert unexpectedly ACCEPTED (bug)"),
        Err(error) => println!(
            "\n[5] assert    repo:myproj database = \"mariadb\"   (authority=High, source=owner)\n    \
             -> REJECTED: {error}"
        ),
    }

    println!(
        "\nEvery decision above came from a registered predicate policy: repo.database\n\
         requires High authority and is unique; branch.status carries a default freshness.\n\
         Trusted facts cannot be silently overridden or duplicated, and volatile facts expire."
    );
}

/// The registry-aware write path used by the demo: apply the predicate's default TTL,
/// enforce its policy (authority floor + uniqueness, freshness-aware as of `now`), then
/// write through the firewall.
fn admit(
    store: &mut InMemoryEventStore,
    registry: &PredicateRegistry,
    mut event: ClaimEvent,
    now: TimestampMillis,
) -> Result<AppendReceipt, StoreError> {
    apply_policy_defaults(registry, &mut event);
    enforce_policy(registry, store, &event, now)?;
    store.append(event)
}

fn print_receipt(store: &InMemoryEventStore, claim_id: &str, now: TimestampMillis) {
    let claim = ClaimId::new(claim_id).expect("claim id");
    match store.explain(&claim, now) {
        Ok(Some(r)) => println!("{}", format_receipt(&r)),
        Ok(None) => println!("    (no such claim)"),
        Err(error) => println!("    replay failed: {error}"),
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
        r.contradicted_by.len(),
        r.replay_position,
        short(&r.event_hash),
        r.chain_verified,
    )
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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SourceGrant {
    max_authority: AuthorityLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "identity"), allow(dead_code))]
struct WriteAuth<'a> {
    operation: &'a str,
    subject_kind: &'a str,
    subject_key: &'a str,
    predicate: &'a str,
    value: Option<&'a str>,
    authority: AuthorityLevel,
    source: &'a str,
    derived_from: Option<WriteAuthSource<'a>>,
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(feature = "identity"), allow(dead_code))]
struct WriteAuthSource<'a> {
    subject_kind: &'a str,
    subject_key: &'a str,
    predicate: &'a str,
}

impl<'a> WriteAuth<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        operation: &'a str,
        subject_kind: &'a str,
        subject_key: &'a str,
        predicate: &'a str,
        value: Option<&'a str>,
        authority: AuthorityLevel,
        source: &'a str,
    ) -> Self {
        Self {
            operation,
            subject_kind,
            subject_key,
            predicate,
            value,
            authority,
            source,
            derived_from: None,
        }
    }

    fn with_derived_from(
        mut self,
        subject_kind: &'a str,
        subject_key: &'a str,
        predicate: &'a str,
    ) -> Self {
        self.derived_from = Some(WriteAuthSource {
            subject_kind,
            subject_key,
            predicate,
        });
        self
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
fn enforce_source_ceiling(source: &str, requested: AuthorityLevel) -> Result<(), OpError> {
    let registry = load_authority_registry().map_err(OpError::Invalid)?;
    ceiling_check(registry.as_ref(), source, requested)
}

/// The write-boundary auth gate: source→authority ceiling first (authz), then optional
/// signed source identity (authn) when a trust root is configured.
fn enforce_write_authority(auth: &WriteAuth<'_>) -> Result<(), OpError> {
    enforce_source_ceiling(auth.source, auth.authority)?;
    enforce_source_identity(auth).map_err(OpError::Invalid)
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
) -> Result<(), OpError> {
    let Some(registry) = registry else {
        return Ok(());
    };
    let ceiling = registry.ceiling(source);
    if requested > ceiling {
        return Err(OpError::Rejected(format!(
            "authority ceiling: source {source:?} may assert at most {ceiling:?}, but requested \
             {requested:?} (grant it with `dent8 authority add {source} <max>`)"
        )));
    }
    Ok(())
}

fn cmd_authority_list() -> i32 {
    // A diagnostic/read command: load WITHOUT the fail-closed gate (like the edit commands),
    // so `authority list` can always report state — including "no registry yet" under
    // DENT8_REQUIRE_AUTHORITY, which is exactly when an operator needs to inspect it. (Only the
    // write gate `enforce_source_ceiling` consults the flag.)
    let required = match authority_required() {
        Ok(required) => required,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    match load_authority_registry_for_edit() {
        Ok(None) if required => {
            println!(
                "no authority registry at {} — but DENT8_REQUIRE_AUTHORITY is set, so every \
                 write is BLOCKED until you create one with `dent8 authority add <source> <max>`.",
                authority_registry_path()
            );
            0
        }
        Ok(None) => {
            println!(
                "no authority registry at {} — enforcement is OFF (dev mode). Add a source \
                 with `dent8 authority add <source> <max>`.",
                authority_registry_path()
            );
            0
        }
        Ok(Some(registry)) if registry.sources.is_empty() => {
            println!(
                "authority registry is empty — deny-by-default: every source is blocked from \
                 writing until granted with `dent8 authority add <source> <max>`."
            );
            0
        }
        Ok(Some(registry)) => {
            for (source, grant) in &registry.sources {
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
                println!(
                    "{source}  max={:?}{issuer}{scope}{note}",
                    grant.max_authority
                );
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            2
        }
    }
}

fn cmd_authority_add(
    source: &str,
    max_authority: AuthorityLevel,
    issuer: Option<&str>,
    scope: Option<&str>,
) -> i32 {
    let mut registry = match load_authority_registry_for_edit() {
        Ok(registry) => registry.unwrap_or_default(),
        Err(error) => {
            eprintln!("{error}");
            return 2;
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
            println!("granted {source} a max authority of {max_authority:?}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn cmd_authority_remove(source: &str) -> i32 {
    let mut registry = match load_authority_registry_for_edit() {
        Ok(Some(registry)) => registry,
        Ok(None) => {
            eprintln!("no authority registry to remove from");
            return 1;
        }
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    if registry.sources.remove(source).is_none() {
        eprintln!("{source} is not in the authority registry");
        return 1;
    }
    match save_authority_registry(&registry) {
        Ok(()) => {
            println!("revoked {source}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn cmd_init(args: &InitArgs) -> i32 {
    match init_project(args) {
        Ok(outcome) => {
            println!("{}", outcome.message);
            outcome.exit_code
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn cmd_mcp_install(args: &McpInstallArgs) -> i32 {
    let dir = std::path::PathBuf::from(&args.dir);
    let mode = mcp_install_mode(args.dry_run, args.check);
    match install_mcp_config(
        args.agent,
        &dir,
        args.config.as_deref(),
        &args.command,
        mode,
    ) {
        Ok(outcome) => {
            println!("{}", outcome.message);
            outcome.exit_code
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

struct CommandOutcome {
    message: String,
    exit_code: i32,
}

fn init_project(args: &InitArgs) -> Result<CommandOutcome, String> {
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

    let (store_line, store_summary) =
        init_store_line(args.store, args.store_url.as_deref(), &dir, args.agent)?;
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
    let agent_summary = args.agent.map_or(String::new(), |agent| {
        format!("\n  agent profile: {}", agent.example_path())
    });
    let agent_next = args.agent.map_or(String::new(), |agent| {
        format!("\n\nAgent wiring:\n  see {}", agent.example_path())
    });

    let env_contents = format!(
        "# dent8 local environment\n\
         # Load with: set -a; . {}; set +a\n\
         DENT8_AUTHORITY={}\n\
         DENT8_REQUIRE_AUTHORITY=1\n\
         {store_line}\n",
        shell_quote(&env_path.to_string_lossy()),
        shell_quote(&authority_path.to_string_lossy()),
    );
    write_atomic(&env_path.to_string_lossy(), &env_contents)?;

    let mut message = format!(
        "initialized dent8 in {}\n  authority: {} (granted {} max={:?})\n  store: {store_summary}\n  env: {}{}{}\n\nNext:\n  set -a\n  . {}{}\n  set +a\n  dent8 doctor --source {} --write-check{}",
        dir.display(),
        authority_path.display(),
        source,
        args.authority.level(),
        env_path.display(),
        identity.summary,
        agent_summary,
        shell_quote(&env_path.to_string_lossy()),
        identity.env_load,
        source,
        agent_next,
    );
    if let Some(exit_code) = append_init_mcp_install(args, &dir, &mut message)? {
        return Ok(CommandOutcome { message, exit_code });
    }
    Ok(CommandOutcome {
        message,
        exit_code: 0,
    })
}

fn append_init_mcp_install(
    args: &InitArgs,
    dir: &std::path::Path,
    message: &mut String,
) -> Result<Option<i32>, String> {
    if !args.mcp.install_mcp {
        return Ok(None);
    }
    let agent = args
        .agent
        .ok_or_else(|| "`dent8 init --install-mcp` requires --agent".to_string())?;
    let mode = mcp_install_mode(args.mcp.mcp_dry_run, args.mcp.mcp_check);
    match install_mcp_config(
        agent,
        dir,
        args.mcp.mcp_config.as_deref(),
        args.mcp.mcp_command.as_deref().unwrap_or("dent8"),
        mode,
    ) {
        Ok(install) => {
            message.push_str("\n\n");
            message.push_str(&install.message);
            Ok(Some(install.exit_code))
        }
        Err(error) => {
            message.push_str("\n\nMCP install failed: ");
            message.push_str(&error);
            message.push_str("\nRun: dent8 mcp install --agent ");
            message.push_str(agent.cli_name());
            if let Some(config) = args.mcp.mcp_config.as_deref() {
                message.push_str(" --config ");
                message.push_str(&shell_quote(config));
            }
            Ok(Some(1))
        }
    }
}

fn install_mcp_config(
    agent: InitAgent,
    dir: &std::path::Path,
    config: Option<&str>,
    command: &str,
    mode: mcp_config::InstallMode,
) -> Result<CommandOutcome, String> {
    let dir = absolute_path(dir)?;
    mcp_config::install(&mcp_config::InstallOptions {
        agent,
        dent8_dir: dir,
        config_path: config.map(std::path::PathBuf::from),
        command: command.to_string(),
        mode,
    })
    .map(|result| CommandOutcome {
        message: result.message(),
        exit_code: result.exit_code(),
    })
}

fn mcp_install_mode(dry_run: bool, check: bool) -> mcp_config::InstallMode {
    match (dry_run, check) {
        (true, _) => mcp_config::InstallMode::DryRun,
        (false, true) => mcp_config::InstallMode::Check,
        (false, false) => mcp_config::InstallMode::Write,
    }
}

#[cfg_attr(not(feature = "identity"), allow(clippy::unnecessary_wraps))]
fn preflight_identity(
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

struct InitIdentityOutput {
    summary: String,
    env_load: String,
}

#[cfg_attr(not(feature = "identity"), allow(clippy::unnecessary_wraps))]
fn init_identity(
    args: &InitArgs,
    dir: &std::path::Path,
    source: &str,
    enabled: bool,
) -> Result<InitIdentityOutput, String> {
    #[cfg(feature = "identity")]
    {
        if !enabled {
            return Ok(InitIdentityOutput {
                summary: String::new(),
                env_load: String::new(),
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
        Ok(InitIdentityOutput {
            summary: format!(
                "\n  identity: {} (source key: {})\n  identity env: {}",
                identity.grant_file.display(),
                identity.source_key_path.display(),
                identity.env_file.display(),
            ),
            env_load: format!(
                "\n  . {}",
                shell_quote(&identity.env_file.to_string_lossy())
            ),
        })
    }
    #[cfg(not(feature = "identity"))]
    {
        let _ = (args, dir, source, enabled);
        Ok(InitIdentityOutput {
            summary: String::new(),
            env_load: String::new(),
        })
    }
}

fn init_source(args: &InitArgs) -> String {
    args.source
        .clone()
        .or_else(|| args.agent.map(|agent| agent.source().to_string()))
        .unwrap_or_else(|| "source:local".to_string())
}

fn init_store_line(
    store: InitStore,
    store_url: Option<&str>,
    dir: &std::path::Path,
    agent: Option<InitAgent>,
) -> Result<(String, String), String> {
    match store {
        InitStore::File => {
            let log = init_file_log_path(dir, agent);
            let value = log.to_string_lossy();
            Ok((
                format!("DENT8_LOG={}", shell_quote(&value)),
                format!("file dev log at {}", log.display()),
            ))
        }
        InitStore::Sqlite => {
            let url = store_url.map_or_else(
                || format!("sqlite://{}", dir.join("dent8.db").display()),
                str::to_string,
            );
            Ok((
                format!("DENT8_STORE_URL={}", shell_quote(&url)),
                format!("SQLite backend at {url} (requires `--features sqlite` build)"),
            ))
        }
        InitStore::Postgres => {
            let Some(url) = store_url else {
                return Err(
                    "`dent8 init --store postgres` needs `--store-url postgres://...`".to_string(),
                );
            };
            Ok((
                format!("DENT8_STORE_URL={}", shell_quote(url)),
                format!("Postgres backend at {url} (requires `--features postgres` build)"),
            ))
        }
    }
}

fn init_file_log_path(dir: &std::path::Path, agent: Option<InitAgent>) -> std::path::PathBuf {
    dir.join(agent.map_or("memory.jsonl", InitAgent::file_log_name))
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

fn cmd_doctor(args: &DoctorArgs) -> i32 {
    let report = doctor_report(args);
    print!("{}", report.output);
    i32::from(!report.ok)
}

struct DoctorReport {
    output: String,
    ok: bool,
}

fn doctor_report(args: &DoctorArgs) -> DoctorReport {
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
            "WARN",
            "write-check: skipped (pass `--write-check` to run assert -> reject -> explain)",
        );
    }

    DoctorReport { output, ok }
}

fn doctor_agent_report(args: &DoctorArgs, agent: InitAgent) -> DoctorReport {
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

    let bundle_env = match mcp_config::load_agent_env(&dir, agent) {
        Ok(env) => {
            doctor_line(
                &mut output,
                "OK",
                ".dent8 env: agent bundle is complete and source-bound",
            );
            env
        }
        Err(error) => {
            doctor_line(&mut output, "FAIL", &format!("agent env: {error}"));
            return DoctorReport { output, ok: false };
        }
    };

    let installed = match mcp_config::load_installed_server(
        agent,
        &dir,
        args.mcp_config.as_deref().map(std::path::Path::new),
    ) {
        Ok(installed) => {
            doctor_line(
                &mut output,
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
            installed
        }
        Err(error) => {
            doctor_line(&mut output, "FAIL", &format!("agent mcp config: {error}"));
            return DoctorReport { output, ok: false };
        }
    };

    match validate_installed_agent_config(&bundle_env, &installed, args.mcp_command.as_deref()) {
        Ok(message) => doctor_line(&mut output, "OK", &message),
        Err(error) => {
            ok = false;
            doctor_line(&mut output, "FAIL", &format!("agent mcp config: {error}"));
        }
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

fn validate_installed_agent_config(
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

fn run_doctor_with_env(
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
        if !include_write_check_skip && line.contains("write-check: skipped") {
            continue;
        }
        forwarded.push_str(line);
        forwarded.push('\n');
    }
    Ok(forwarded)
}

fn mcp_smoke_with_server(server: &mcp_config::InstalledServer) -> Result<String, String> {
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

fn mcp_write_check_with_server(
    server: &mcp_config::InstalledServer,
    source: &str,
) -> Result<String, String> {
    let subject_key = format!(
        "alice-doctor-mcp-{}-{}",
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
                &mcp_value_fact_args(&subject_key, "tea", "high", source),
            ),
            mcp_tool_call(
                3,
                "supersede",
                &mcp_value_fact_args(&subject_key, "coffee", "low", source),
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
    if explained["structuredContent"]["current_value"]["text"] != "tea" {
        return Err(format!(
            "expected trusted value tea to remain; got {}",
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
        "mcp write-check: accepted trusted person:{subject_key} favorite_drink=tea, rejected low-authority coffee, explain+verify OK"
    ))
}

fn mcp_exchange_with_server(
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

fn mcp_initialize_request(id: u64) -> serde_json::Value {
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

fn mcp_initialized_notification() -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
    })
}

fn mcp_tool_call(id: u64, name: &str, arguments: &serde_json::Value) -> serde_json::Value {
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

fn mcp_value_fact_args(
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

fn mcp_read_fact_args(subject_key: &str) -> serde_json::Value {
    serde_json::json!({
        "subject_kind": "person",
        "subject_key": subject_key,
        "predicate": "favorite_drink",
    })
}

fn mcp_tool_result<'a>(
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

struct TimedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    timed_out: bool,
}

fn mcp_smoke_timeout() -> Duration {
    std::env::var("DENT8_MCP_SMOKE_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .filter(|timeout| !timeout.is_zero())
        .unwrap_or(DEFAULT_MCP_SMOKE_TIMEOUT)
}

fn wait_with_output_timeout(mut child: Child, timeout: Duration) -> io::Result<TimedCommandOutput> {
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

fn read_pipe_in_thread<R>(mut reader: R) -> std::thread::JoinHandle<io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut output = Vec::new();
        reader.read_to_end(&mut output)?;
        Ok(output)
    })
}

fn join_reader(
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

fn format_duration(duration: Duration) -> String {
    if duration.as_millis().is_multiple_of(1_000) {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn apply_dent8_env(command: &mut Command, env: &std::collections::BTreeMap<String, String>) {
    for key in [
        "DENT8_STORE_URL",
        "DENT8_LOG",
        "DENT8_AUTHORITY",
        "DENT8_REQUIRE_AUTHORITY",
        "DENT8_TRUST",
        "DENT8_GRANT",
        "DENT8_IDENTITY_KEY",
        "DENT8_REQUIRE_IDENTITY",
    ] {
        command.env_remove(key);
    }
    for (key, value) in env {
        command.env(key, value);
    }
}

fn doctor_store(output: &mut String) -> Result<(), String> {
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

fn doctor_authority(output: &mut String, source: &str) -> Result<(), String> {
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
fn doctor_identity(output: &mut String, source: &str) -> bool {
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
fn doctor_identity(output: &mut String, _source: &str) -> bool {
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

#[cfg(not(feature = "identity"))]
fn env_present(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

fn doctor_write_check(source: &str) -> Result<String, String> {
    let subject_key = format!(
        "alice-doctor-{}-{}",
        std::process::id(),
        now_millis().as_unix_millis()
    );
    op_assert(
        &log_path(),
        "person",
        &subject_key,
        "favorite_drink",
        "tea",
        AuthorityLevel::High,
        source,
    )
    .map_err(|error| error.message().to_string())?;

    match op_supersede(
        &log_path(),
        "person",
        &subject_key,
        "favorite_drink",
        "coffee",
        AuthorityLevel::Low,
        source,
    ) {
        Ok(message) => {
            return Err(format!(
                "low-authority override was accepted unexpectedly: {message}"
            ));
        }
        Err(OpError::Rejected(_)) => {}
        Err(error) => return Err(error.message().to_string()),
    }

    let explained = op_explain(&log_path(), "person", &subject_key, "favorite_drink")
        .map_err(|error| error.message().to_string())?;
    if !explained.contains("value         : \"tea\"") {
        return Err(format!(
            "expected trusted value tea to remain; got:\n{explained}"
        ));
    }
    verify_log(&log_path())?;
    Ok(format!(
        "write-check: accepted trusted person:{subject_key} favorite_drink=tea, rejected low-authority coffee, verify OK"
    ))
}

fn doctor_line(output: &mut String, level: &str, message: &str) {
    output.push_str("  ");
    output.push_str(level);
    output.push_str("  ");
    output.push_str(message);
    output.push('\n');
}

fn first_line(message: &str) -> &str {
    message.lines().next().unwrap_or(message)
}

fn store_scheme(url: &str) -> &str {
    url.split_once(':').map_or("", |(scheme, _)| scheme)
}

fn parent_dir(path: &str) -> Option<&std::path::Path> {
    let parent = std::path::Path::new(path).parent()?;
    if parent.as_os_str().is_empty() {
        None
    } else {
        Some(parent)
    }
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
    if !issues.is_empty() {
        return Err(format!(
            "INTEGRITY ISSUES ({} found):\n  {}",
            issues.len(),
            issues.join("\n  ")
        ));
    }
    Ok(format!(
        "OK: {} event(s) across {} entit(ies) — STRUCTURAL integrity holds (uniqueness + \
         lineage intact, no retraction taint, all events canonicalize). This does NOT detect a \
         content edit: the file dev store keeps no stored hash to compare against — use \
         `dent8 witness verify` (or the Postgres backend) for tamper-detection.",
        store.len(),
        subjects.len()
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
        if !tainted.is_empty() {
            let lines: Vec<String> = tainted
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
            return Err(format!(
                "INTEGRITY ISSUES ({} found):\n  {}",
                lines.len(),
                lines.join("\n  ")
            ));
        }
        Ok(format!(
            "OK: {} event(s) — the stored global hash chain re-verifies, no retraction taint. \
             (Tamper-resistance needs an external operated witness.)",
            events.len()
        ))
    })
}

fn cmd_verify() -> i32 {
    match verify_log(&log_path()) {
        Ok(report) => {
            println!("{}", paint_status(&report, CliStream::Stdout));
            0
        }
        Err(message) => {
            eprintln!("{}", paint_status(&message, CliStream::Stderr));
            1
        }
    }
}

/// Built-in helper for provider hook systems. It intentionally does not write native memory
/// files; it only runs `verify` or blocks writes that would bypass the claim-event firewall.
fn cmd_hook_native_memory_guard() -> i32 {
    let mode = std::env::var("DENT8_HOOK_MODE")
        .unwrap_or_else(|_| "guard-native-memory-write".to_string());

    if mode == "session-start" {
        return hook_verify("session start");
    }

    if mode != "guard-native-memory-write" && mode != "post-write-audit" {
        eprintln!("dent8 hook: unknown DENT8_HOOK_MODE={mode}");
        return 2;
    }

    // The payload could not be read or parsed, so we cannot tell whether a native memory file is
    // being written. The blocking guard fails closed under enforcement; the post-write audit
    // re-verifies the chain rather than assume nothing changed.
    let Some(payload) = read_hook_payload() else {
        return match mode.as_str() {
            "post-write-audit" => hook_verify("unreadable post-write hook payload"),
            _ if hook_enforced() => {
                eprintln!(
                    "dent8 hook: unreadable payload under DENT8_HOOK_ENFORCE — blocking (fail closed)."
                );
                2
            }
            _ => 0,
        };
    };

    let touched = native_memory_paths(&payload);
    if mode == "post-write-audit" {
        if touched.is_empty() {
            return 0;
        }
        return hook_verify(&format!(
            "native memory/rules changed: {}",
            touched.join(", ")
        ));
    }

    // guard-native-memory-write
    if touched.is_empty() {
        return 0;
    }

    eprintln!(
        "dent8 native memory/rules guard: direct writes to {} bypass the claim-event firewall. \
         Use dent8 MCP tools or an explicit reviewed export from dent8. Set \
         DENT8_ALLOW_NATIVE_MEMORY_WRITE=1 to bypass this local guard.",
        touched.join(", ")
    );

    if hook_allow_bypass() {
        return 0;
    }
    if hook_enforced() { 2 } else { 0 }
}

/// `DENT8_HOOK_ENFORCE` turns a guard hit (or an unreadable payload) into a blocking exit 2.
/// Parsed like every dent8 boolean (`1`/`true`/`yes`/`on`); a malformed value **fails closed**
/// (treated as enforcing) so a typo cannot silently disable enforcement.
fn hook_enforced() -> bool {
    match env_flag("DENT8_HOOK_ENFORCE") {
        Ok(value) => value,
        Err(message) => {
            eprintln!("dent8 hook: {message}");
            true
        }
    }
}

/// `DENT8_ALLOW_NATIVE_MEMORY_WRITE` is the explicit local bypass. A malformed value never grants
/// a bypass (treated as unset), so a typo cannot accidentally open the guard.
fn hook_allow_bypass() -> bool {
    match env_flag("DENT8_ALLOW_NATIVE_MEMORY_WRITE") {
        Ok(value) => value,
        Err(message) => {
            eprintln!("dent8 hook: {message}");
            false
        }
    }
}

/// Read the hook JSON from stdin. `Some(Null)` is an empty payload (nothing to guard); `None`
/// means stdin could not be read or did not parse as JSON, so callers can fail closed.
fn read_hook_payload() -> Option<serde_json::Value> {
    let mut raw = String::new();
    let mut stdin = std::io::stdin();
    if let Err(error) = std::io::Read::read_to_string(&mut stdin, &mut raw) {
        eprintln!("dent8 hook: could not read hook JSON: {error}");
        return None;
    }
    if raw.trim().is_empty() {
        return Some(serde_json::Value::Null);
    }
    match serde_json::from_str(&raw) {
        Ok(value) => Some(value),
        Err(error) => {
            eprintln!("dent8 hook: could not parse hook JSON: {error}");
            None
        }
    }
}

fn hook_verify(reason: &str) -> i32 {
    eprintln!("dent8 hook: verify ({reason})");
    match verify_log(&log_path()) {
        Ok(report) => {
            eprintln!("{report}");
            0
        }
        Err(message) => {
            eprintln!("{message}");
            1
        }
    }
}

fn native_memory_paths(payload: &serde_json::Value) -> Vec<String> {
    let mut paths = std::collections::BTreeSet::new();
    for candidate in hook_candidate_strings(payload) {
        let normalized = candidate.replace('\\', "/");
        if is_native_memory_path(&normalized) {
            paths.insert(normalized);
            continue;
        }
        // The candidate may be a shell command or an `apply_patch` body that *writes* a native
        // memory file with the path embedded (not as the whole string) — e.g. `echo x >> AGENTS.md`
        // or an `*** Update File: AGENTS.md` header. Pull out the write targets and check those.
        for target in embedded_write_targets(&normalized) {
            if is_native_memory_path(&target) {
                paths.insert(target);
            }
        }
    }
    paths.into_iter().collect()
}

/// Best-effort extraction of the file paths a shell command or `apply_patch` body **writes**:
/// `apply_patch` `*** Update/Add/Delete File:` / `*** Move to:` headers, and `>` / `>>` / `tee`
/// redirect targets. Deliberately conservative — it flags *write* targets, not mere mentions (so
/// `cat AGENTS.md` is not flagged), and does not model every shell write mechanism (`sed -i`,
/// `cp`, `mv`, an interpreter writing a file): the MCP/CLI firewall, not this hook, is the
/// integrity boundary. See `examples/agent-hooks/README.md`.
fn embedded_write_targets(text: &str) -> Vec<String> {
    let mut targets = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        for prefix in [
            "*** Update File: ",
            "*** Add File: ",
            "*** Delete File: ",
            "*** Move to: ",
        ] {
            if let Some(rest) = line.strip_prefix(prefix) {
                targets.push(unquote(rest.trim()));
            }
        }
    }
    let tokens: Vec<&str> = text.split_whitespace().collect();
    for (idx, token) in tokens.iter().enumerate() {
        if *token == ">" || *token == ">>" {
            // Spaced redirection: the next token is the destination file.
            if let Some(next) = tokens.get(idx + 1) {
                targets.push(unquote(next));
            }
        } else if let Some(rest) = token.strip_prefix(">>").or_else(|| token.strip_prefix('>')) {
            // Attached redirection: `>file` / `>>file`.
            if !rest.is_empty() {
                targets.push(unquote(rest));
            }
        } else if *token == "tee" {
            // `tee [-a] FILE`: the first non-flag argument is a write target.
            if let Some(arg) = tokens[idx + 1..].iter().find(|arg| !arg.starts_with('-')) {
                targets.push(unquote(arg));
            }
        }
    }
    targets
}

/// Strip surrounding shell quotes and normalize backslashes for path matching.
fn unquote(token: &str) -> String {
    token.trim_matches(['"', '\'']).replace('\\', "/")
}

fn hook_candidate_strings(value: &serde_json::Value) -> Vec<&str> {
    fn walk<'a>(value: &'a serde_json::Value, out: &mut Vec<&'a str>) {
        const PATH_KEYS: &[&str] = &[
            "absolute_path",
            "file",
            "filePath",
            "file_path",
            "new_path",
            "old_path",
            "path",
            "relative_path",
            "target_file",
        ];
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    if PATH_KEYS.contains(&key.as_str())
                        && let Some(path) = child.as_str()
                    {
                        out.push(path);
                    }
                    walk(child, out);
                }
            }
            serde_json::Value::Array(items) => {
                for child in items {
                    walk(child, out);
                }
            }
            serde_json::Value::String(text) if hook_string_looks_like_path(text) => {
                out.push(text);
            }
            _ => {}
        }
    }

    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

fn hook_string_looks_like_path(value: &str) -> bool {
    [
        "/",
        "\\",
        "AGENTS.md",
        "CLAUDE.md",
        "CLAUDE.local.md",
        "GEMINI.md",
        "MEMORY.md",
        ".cursor/rules",
        ".devin/rules",
        ".windsurf/rules",
        ".windsurfrules",
    ]
    .iter()
    .any(|marker| value.contains(marker))
}

fn is_native_memory_path(path: &str) -> bool {
    let path = path.trim_start_matches("./");
    let ends_with_named_file = [
        "AGENTS.md",
        "CLAUDE.md",
        "CLAUDE.local.md",
        "GEMINI.md",
        "MEMORY.md",
    ]
    .iter()
    .any(|name| {
        path == *name
            || path
                .strip_suffix(name)
                .is_some_and(|prefix| prefix.ends_with('/'))
    });
    if ends_with_named_file {
        return true;
    }

    if path == ".windsurfrules" || path.ends_with("/.windsurfrules") {
        return true;
    }

    let in_cursor_rules = path.starts_with(".cursor/rules/") || path.contains("/.cursor/rules/");
    let has_rule_ext = std::path::Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md") || ext.eq_ignore_ascii_case("mdc"));
    if in_cursor_rules && has_rule_ext {
        return true;
    }

    let in_devin_rules = path.starts_with(".devin/rules/") || path.contains("/.devin/rules/");
    let in_windsurf_rules =
        path.starts_with(".windsurf/rules/") || path.contains("/.windsurf/rules/");
    let has_md_ext = std::path::Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("md"));
    (in_devin_rules || in_windsurf_rules) && has_md_ext
}

/// Run the adversarial corpus and print the firewall-vs-recency-baseline contrast — the
/// self-demonstrating "why dent8" benchmark. Exits non-zero only if a scenario regresses.
fn cmd_eval() -> i32 {
    let results = dent8_evals::run_corpus();
    let demonstrated = results
        .iter()
        .filter(|result| result.demonstrates_defense())
        .count();
    println!(
        "dent8 adversarial corpus — {demonstrated}/{} scenarios demonstrate the firewall's \
         defense:\nthe firewall blocks every attack a recency-only baseline (newest-write-wins, \
         no authority/dependency) falls to.\n",
        results.len()
    );
    print!("{}", dent8_evals::summary_table());
    i32::from(demonstrated != results.len())
}

/// Export the whole event log to a flattened Parquet file for offline `DuckDB` analysis
/// (forensics, audit, replay-at-scale). Read-only and backend-aware via `load_store`, so it
/// snapshots the file *or* the Postgres log. Gated behind `--features export` so the stock
/// binary carries no arrow/parquet stack.
#[cfg(feature = "export")]
fn cmd_export(out: &str) -> i32 {
    let store = match load_store(&log_path()) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    let events = match store.scan_events(&EventFilter::default()) {
        Ok(events) => events,
        Err(error) => {
            eprintln!("cannot read the log: {error}");
            return 1;
        }
    };
    let file = match std::fs::File::create(out) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("cannot create {out}: {error}");
            return 1;
        }
    };
    match dent8_export::export_events(&events, file) {
        Ok(()) => {
            println!(
                "exported {} event(s) to {out}\n  query it with DuckDB, e.g.:\n    \
                 duckdb -c \"SELECT source, count(*) AS writes FROM '{out}' GROUP BY 1 ORDER BY 2 DESC\"\n    \
                 duckdb -c \"SELECT claim_id, UNNEST(derived_from) AS source_claim FROM '{out}' WHERE derived_from IS NOT NULL\"",
                events.len()
            );
            0
        }
        Err(error) => {
            eprintln!("export failed: {error}");
            1
        }
    }
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
fn append_events(path: &str, events: &[&ClaimEvent]) -> Result<(), WriteError> {
    use std::io::Write;
    // An async backend commits the whole operation (assert / supersede / retract / contradict)
    // as one transaction via `append_many`; the file store just appends the lines. (A build
    // with no async backend that reaches here with a store URL set already errored in
    // `load_store`.)
    #[cfg(feature = "async-store")]
    if let Some(url) = store_url() {
        return backend_append(&url, events);
    }
    let mut buffer = String::new();
    for event in events {
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
             (postgres:// needs `--features postgres`, sqlite:// needs `--features sqlite`)"
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

/// Build a validated `ClaimEvent` from CLI strings, returning a friendly error rather than
/// panicking on malformed input (unlike the demo's fixed-string builder). The `kind` and
/// `value` distinguish an assertion from a supersession; `claim_id` is the *subject* claim
/// of the event (the new claim for an assertion, the incumbent for a supersession).
#[allow(clippy::too_many_arguments)]
fn build_event(
    event_id: &str,
    claim_id: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    kind: ClaimEventKind,
    value: Option<ClaimValue>,
    source: &str,
    authority: AuthorityLevel,
    now: TimestampMillis,
) -> Result<ClaimEvent, String> {
    Ok(ClaimEvent {
        event_id: ClaimEventId::new(event_id).map_err(|e| format!("event id: {e}"))?,
        claim_id: ClaimId::new(claim_id).map_err(|e| format!("claim id: {e}"))?,
        kind,
        subject: EntityRef::new(subject_kind, subject_key).map_err(|e| format!("subject: {e}"))?,
        predicate: Predicate::new(predicate).map_err(|e| format!("predicate: {e}"))?,
        value,
        confidence: Confidence::from_millis(900).map_err(|e| format!("confidence: {e}"))?,
        authority: Authority {
            level: authority,
            issuer: None,
            scope: None,
        },
        ttl: Ttl::Never,
        provenance: Provenance {
            source: dent8_core::SourceId::new(source).map_err(|e| format!("source: {e}"))?,
            actor: ActorId::new("actor:cli").map_err(|e| format!("actor: {e}"))?,
            tool: Some("dent8-cli".to_string()),
            run_id: None,
            input_digest: None,
            recorded_at: now,
        },
        evidence: vec![Evidence {
            id: EvidenceId::new("evidence:cli").map_err(|e| format!("evidence id: {e}"))?,
            kind: EvidenceKind::UserStatement,
            locator: format!("cli:{source}"),
            digest: None,
            summary: None,
        }],
        observed_at: None,
        valid_from: None,
    })
}

/// A failed operation: `Invalid` is a malformed request (CLI exit 2 / MCP tool error),
/// `Rejected` is a well-formed request the firewall or store refused (CLI exit 1 / MCP
/// tool error). Carrying the distinction lets the CLI keep its exit codes while the MCP
/// server reports both as tool errors.
enum OpError {
    Invalid(String),
    Rejected(String),
    /// A retryable concurrent-writer conflict (Postgres optimistic-id race). Surfaced so
    /// [`with_write_retry`] can re-run the operation against a fresh snapshot; it never reaches
    /// the user unless retries are exhausted (then it is downgraded to `Rejected`).
    Conflict(String),
}

impl OpError {
    fn message(&self) -> &str {
        match self {
            Self::Invalid(message) | Self::Rejected(message) | Self::Conflict(message) => message,
        }
    }
}

/// Map a durable-append failure to an `OpError`, preserving the retryable conflict signal.
/// `Other` covers both an I/O failure and a durable firewall rejection (e.g. a same-subject
/// race the in-memory snapshot admitted but the transaction rejected), so the message says
/// "could not commit" rather than implying the write was admitted-then-lost.
fn write_error_to_op(error: WriteError) -> OpError {
    match error {
        WriteError::Conflict(message) => OpError::Conflict(message),
        WriteError::Other(message) => {
            OpError::Rejected(format!("could not commit the write: {message}"))
        }
    }
}

/// Run a write operation, retrying on a concurrent-writer conflict. Each attempt re-runs the
/// whole `op_*` (fresh snapshot → fresh `event:{n}` id → re-arbitrate → append), so a retry
/// mints a non-colliding id and commits. Between attempts it backs off with per-process jitter
/// to **de-synchronize a thundering herd** — immediate retries would re-collide on the same
/// next id, so the spread is what lets many concurrent writers converge. A success or any
/// non-conflict failure returns immediately. Without the `postgres` feature no conflict is ever
/// produced, so this runs `op` exactly once.
fn with_write_retry(mut op: impl FnMut() -> Result<String, OpError>) -> Result<String, OpError> {
    const MAX_ATTEMPTS: u32 = 16;
    let mut last = String::new();
    for attempt in 0..MAX_ATTEMPTS {
        match op() {
            Err(OpError::Conflict(message)) => {
                last = message;
                back_off(attempt);
            }
            settled => return settled,
        }
    }
    Err(OpError::Rejected(format!(
        "write conflict persisted after {MAX_ATTEMPTS} attempts (last: {last}); a concurrent \
         writer kept racing — try again, or move to DB-assigned ids for heavy write contention"
    )))
}

/// Capped exponential backoff with **decorrelated** per-process jitter for the write-conflict
/// retry. The jitter mixes the process id *and the attempt* through `SplitMix64` and takes an
/// **odd** modulus (`2·exp+1`) — not a power of two — so two processes whose ids happen to be
/// congruent mod a power of two are not phase-locked into the same delay every attempt (the bug
/// a plain `pid % (1<<n)` would have). No RNG dependency: the process id is the per-process
/// entropy, re-mixed each attempt.
fn back_off(attempt: u32) {
    let exp_ms = 1u64 << attempt.min(7); // 1, 2, 4, … capped at 128 ms
    let mut z = u64::from(std::process::id())
        .wrapping_add(u64::from(attempt).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    let jitter_ms = z % (2 * exp_ms + 1); // [0, 2·exp]; odd modulus → no power-of-two phase-lock
    std::thread::sleep(std::time::Duration::from_millis(exp_ms + jitter_ms));
}

/// Assert a fact through the firewall + registry and persist it. The shared core behind
/// both `dent8 assert` and the MCP `assert` tool — one firewall/persistence path.
fn op_assert(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    value: &str,
    authority: AuthorityLevel,
    source: &str,
) -> Result<String, OpError> {
    enforce_write_authority(&WriteAuth::new(
        "assert",
        subject_kind,
        subject_key,
        predicate,
        Some(value),
        authority,
        source,
    ))?;
    let mut store = load_store(path).map_err(OpError::Invalid)?;
    let now = now_millis();
    // A fresh claim per assertion (keyed by sequence); the registry's uniqueness governs
    // whether a second *fresh* claim for the same subject+predicate is admissible.
    let seq = next_seq(&store);
    let mut event = build_event(
        &format!("event:{seq}"),
        &format!("claim:{subject_kind}:{subject_key}:{predicate}:{seq}"),
        subject_kind,
        subject_key,
        predicate,
        ClaimEventKind::Asserted,
        Some(ClaimValue::Text(value.to_string())),
        source,
        authority,
        now,
    )
    .map_err(|error| OpError::Invalid(format!("invalid assertion: {error}")))?;
    let registry = PredicateRegistry::coding_agent();
    // Apply the predicate's default TTL up front so the event we *persist* is byte-identical
    // to the one `admit` arbitrates and hashes (otherwise the durable event would carry
    // `Ttl::Never` and a hash that disagrees with the receipt on reload).
    apply_policy_defaults(&registry, &mut event);
    let receipt = admit(&mut store, &registry, event.clone(), now)
        .map_err(|error| OpError::Rejected(format!("REJECTED: {error}")))?;
    append_events(path, &[&event]).map_err(write_error_to_op)?;
    Ok(format!(
        "ACCEPTED  {subject_kind}:{subject_key} {predicate} = \"{value}\"  (authority={authority:?})\n  \
         seq={}  hash={}",
        receipt.global_sequence,
        short(&receipt.event_hash)
    ))
}

fn cmd_assert(args: &ValueWriteArgs) -> i32 {
    present(with_write_retry(|| {
        op_assert(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            &args.value,
            args.authority.level(),
            &args.source,
        )
    }))
}

/// Assert a fact **derived from** another fact, recording the claim->claim dependency edge
/// (`EvidenceKind::DerivedFrom`, ADR 0010). The source is named by *subject* (kind/key/
/// predicate) and resolved to its currently-believed claim id(s), so no internal claim id need
/// be typed. If that source is later retracted/expired, `verify` flags this derivative as
/// tainted. Shared by `dent8 derive` and the MCP `derive` tool.
#[allow(clippy::too_many_arguments)]
fn op_derive(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    value: &str,
    authority: AuthorityLevel,
    source: &str,
    from_kind: &str,
    from_key: &str,
    from_predicate: &str,
) -> Result<String, OpError> {
    enforce_write_authority(
        &WriteAuth::new(
            "derive",
            subject_kind,
            subject_key,
            predicate,
            Some(value),
            authority,
            source,
        )
        .with_derived_from(from_kind, from_key, from_predicate),
    )?;
    let mut store = load_store(path).map_err(OpError::Invalid)?;
    let from_subject = EntityRef::new(from_kind, from_key)
        .map_err(|error| OpError::Invalid(format!("invalid source subject: {error}")))?;
    let from_predicate_parsed = Predicate::new(from_predicate)
        .map_err(|error| OpError::Invalid(format!("invalid source predicate: {error}")))?;
    let sources = store
        .believed_claim_ids(&from_subject, &from_predicate_parsed)
        .map_err(|error| OpError::Invalid(error.to_string()))?;
    if sources.is_empty() {
        return Err(OpError::Rejected(format!(
            "nothing to derive from: no believed {from_kind}:{from_key} {from_predicate}"
        )));
    }
    let now = now_millis();
    let seq = next_seq(&store);
    let mut event = build_event(
        &format!("event:{seq}"),
        &format!("claim:{subject_kind}:{subject_key}:{predicate}:{seq}"),
        subject_kind,
        subject_key,
        predicate,
        ClaimEventKind::Asserted,
        Some(ClaimValue::Text(value.to_string())),
        source,
        authority,
        now,
    )
    .map_err(|error| OpError::Invalid(format!("invalid derivation: {error}")))?;
    // Record a DerivedFrom evidence edge to each believed source claim.
    for (index, src) in sources.iter().enumerate() {
        event.evidence.push(Evidence {
            id: EvidenceId::new(format!("evidence:derived:{index}"))
                .map_err(|error| OpError::Invalid(format!("evidence id: {error}")))?,
            kind: EvidenceKind::DerivedFrom,
            locator: src.as_str().to_string(),
            digest: None,
            summary: None,
        });
    }
    let registry = PredicateRegistry::coding_agent();
    apply_policy_defaults(&registry, &mut event);
    let receipt = admit(&mut store, &registry, event.clone(), now)
        .map_err(|error| OpError::Rejected(format!("REJECTED: {error}")))?;
    append_events(path, &[&event]).map_err(write_error_to_op)?;
    Ok(format!(
        "ACCEPTED  {subject_kind}:{subject_key} {predicate} = \"{value}\"  (authority={authority:?}, \
         derived from {from_kind}:{from_key} {from_predicate})\n  seq={}  hash={}",
        receipt.global_sequence,
        short(&receipt.event_hash)
    ))
}

fn cmd_derive(args: &DeriveWriteArgs) -> i32 {
    let from_subject = match CliSubject::from_str(&args.from[0]) {
        Ok(subject) => subject,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    let from_predicate = match parse_predicate(&args.from[1]) {
        Ok(predicate) => predicate,
        Err(message) => {
            eprintln!("{message}");
            return 2;
        }
    };
    present(with_write_retry(|| {
        op_derive(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            &args.value,
            args.authority.level(),
            &args.source,
            &from_subject.kind,
            &from_subject.key,
            &from_predicate,
        )
    }))
}

/// Render an operation result for the CLI: success to stdout (exit 0), a malformed request
/// to stderr (exit 2), a refused one to stderr (exit 1).
fn present(outcome: Result<String, OpError>) -> i32 {
    match outcome {
        Ok(message) => {
            println!("{}", paint_status(&message, CliStream::Stdout));
            0
        }
        Err(OpError::Invalid(message)) => {
            eprintln!("{}", paint_status(&message, CliStream::Stderr));
            2
        }
        Err(OpError::Rejected(message) | OpError::Conflict(message)) => {
            eprintln!("{}", paint_status(&message, CliStream::Stderr));
            1
        }
    }
}

/// Build the events for a revision: one fresh replacement assertion (`event:{seq}`,
/// appended first so the supersessions can resolve it) followed by **one supersession per
/// believed incumbent** (`event:{seq+1+i}`), each pointing `by` at the replacement.
/// Superseding *every* believed incumbent — not just one — is what makes the end state
/// satisfy uniqueness, since the registry can leave a stale + fresh pair both believed.
/// Returns `(events, replacement_claim_id)` with `events[0]` the replacement.
#[allow(clippy::too_many_arguments)]
fn build_revision(
    seq: usize,
    incumbents: &[ClaimId],
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    new_value: &str,
    source: &str,
    authority: AuthorityLevel,
    now: TimestampMillis,
) -> Result<(Vec<ClaimEvent>, String), String> {
    let replacement_claim_id = format!("claim:{subject_kind}:{subject_key}:{predicate}:{seq}");
    let replacement = build_event(
        &format!("event:{seq}"),
        &replacement_claim_id,
        subject_kind,
        subject_key,
        predicate,
        ClaimEventKind::Asserted,
        Some(ClaimValue::Text(new_value.to_string())),
        source,
        authority,
        now,
    )?;
    let mut events = vec![replacement];
    for (index, incumbent) in incumbents.iter().enumerate() {
        let by = ClaimId::new(&replacement_claim_id).map_err(|e| format!("claim id: {e}"))?;
        events.push(build_event(
            &format!("event:{}", seq + 1 + index),
            incumbent.as_str(),
            subject_kind,
            subject_key,
            predicate,
            ClaimEventKind::Superseded {
                by,
                reason: SupersessionReason::UserCorrection,
            },
            None,
            source,
            authority,
            now,
        )?);
    }
    Ok((events, replacement_claim_id))
}

/// Revise the believed fact for a subject+predicate via the sanctioned supersession path:
/// assert a *replacement* claim and mark **every** believed incumbent superseded by it,
/// persisted as one best-effort single write on the file dev store, or a real transaction on
/// async backends. The base firewall's anti-laundering enforces that the replacement out-ranks each
/// incumbent, so a lower-authority revision is rejected. Uniqueness holds in the end state
/// because *all* believed incumbents become terminal — the replacement assertion goes
/// through the base firewall directly (not the uniqueness-checking `admit` path) because
/// the supersessions, not a pre-check, are what restore the invariant.
fn op_supersede(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    new_value: &str,
    authority: AuthorityLevel,
    source: &str,
) -> Result<String, OpError> {
    enforce_write_authority(&WriteAuth::new(
        "supersede",
        subject_kind,
        subject_key,
        predicate,
        Some(new_value),
        authority,
        source,
    ))?;
    let mut store = load_store(path).map_err(OpError::Invalid)?;
    let subject = EntityRef::new(subject_kind, subject_key)
        .map_err(|error| OpError::Invalid(format!("invalid subject: {error}")))?;
    let predicate_parsed = Predicate::new(predicate)
        .map_err(|error| OpError::Invalid(format!("invalid predicate: {error}")))?;
    let now = now_millis();

    // Every believed incumbent must be superseded so the end state is unique.
    let incumbents = match store
        .believed_claim_ids(&subject, &predicate_parsed)
        .map_err(|error| OpError::Invalid(error.to_string()))?
    {
        ids if !ids.is_empty() => ids,
        _ => {
            return Err(OpError::Rejected(format!(
                "nothing to supersede: no believed {subject_kind}:{subject_key} {predicate}"
            )));
        }
    };
    let previous = store
        .explain_subject(&subject, &predicate_parsed, now)
        .ok()
        .flatten()
        .map_or_else(|| "?".to_string(), |receipt| display_value(&receipt.value));

    // Defensive floor check: the replacement must still clear the predicate's floor even if
    // the floor was raised after the incumbent was admitted. (Anti-laundering already
    // requires replacement >= incumbent, but the incumbent could predate a raised floor.)
    let registry = PredicateRegistry::coding_agent();
    if let Some(policy) = registry.policy_for(&subject, &predicate_parsed)
        && authority < policy.authority_floor
    {
        return Err(OpError::Rejected(format!(
            "REJECTED: {subject_kind}.{predicate} requires authority {:?}, got {authority:?}",
            policy.authority_floor
        )));
    }

    let (mut events, replacement_claim_id) = build_revision(
        next_seq(&store),
        &incumbents,
        subject_kind,
        subject_key,
        predicate,
        new_value,
        source,
        authority,
        now,
    )
    .map_err(|error| OpError::Invalid(format!("invalid supersession: {error}")))?;
    // The replacement is a fresh assertion of this predicate, so it inherits the same
    // default freshness as `assert` (e.g. a revised `branch.status` still goes stale).
    apply_policy_defaults(&registry, &mut events[0]);

    // Apply all in memory first (replacement, then each supersession); persist only if
    // every one is admitted, so a rejected revision leaves no orphan in the durable log.
    for event in &events {
        store
            .append(event.clone())
            .map_err(|error| OpError::Rejected(format!("REJECTED: {error}")))?;
    }
    let refs: Vec<&ClaimEvent> = events.iter().collect();
    append_events(path, &refs).map_err(write_error_to_op)?;

    let count = incumbents.len();
    let claims = if count == 1 { "claim" } else { "claims" };
    Ok(format!(
        "ACCEPTED  superseded {count} believed {claims} of {subject_kind}:{subject_key} \
         {predicate}: {previous} -> \"{new_value}\"  (authority={authority:?})\n  \
         new believed claim {replacement_claim_id}"
    ))
}

/// Revise the believed fact for a subject+predicate via the sanctioned supersession path:
/// assert a *replacement* claim and mark **every** believed incumbent superseded by it.
/// The base firewall's anti-laundering enforces that the replacement out-ranks each
/// incumbent, so a lower-authority revision is rejected; uniqueness holds in the end state
/// because all believed incumbents become terminal. Shared by `dent8 supersede` and the
/// MCP `supersede` tool.
fn cmd_supersede(args: &ValueWriteArgs) -> i32 {
    present(with_write_retry(|| {
        op_supersede(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            &args.value,
            args.authority.level(),
            &args.source,
        )
    }))
}

/// Build one `Retracted` event per believed incumbent. Each retraction is authority-gated
/// in the core fold (it may not under-rank its incumbent — [ADR 0008]), so a low-authority
/// retraction of a high-authority fact is rejected.
#[allow(clippy::too_many_arguments)]
fn build_retractions(
    seq: usize,
    incumbents: &[ClaimId],
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    source: &str,
    authority: AuthorityLevel,
    now: TimestampMillis,
) -> Result<Vec<ClaimEvent>, String> {
    incumbents
        .iter()
        .enumerate()
        .map(|(index, incumbent)| {
            build_event(
                &format!("event:{}", seq + index),
                incumbent.as_str(),
                subject_kind,
                subject_key,
                predicate,
                ClaimEventKind::Retracted {
                    reason: RetractionReason::UserDeleted,
                },
                None,
                source,
                authority,
                now,
            )
        })
        .collect()
}

fn op_retract(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: AuthorityLevel,
    source: &str,
) -> Result<String, OpError> {
    enforce_write_authority(&WriteAuth::new(
        "retract",
        subject_kind,
        subject_key,
        predicate,
        None,
        authority,
        source,
    ))?;
    let mut store = load_store(path).map_err(OpError::Invalid)?;
    let subject = EntityRef::new(subject_kind, subject_key)
        .map_err(|error| OpError::Invalid(format!("invalid subject: {error}")))?;
    let predicate_parsed = Predicate::new(predicate)
        .map_err(|error| OpError::Invalid(format!("invalid predicate: {error}")))?;
    let incumbents = match store
        .believed_claim_ids(&subject, &predicate_parsed)
        .map_err(|error| OpError::Invalid(error.to_string()))?
    {
        ids if !ids.is_empty() => ids,
        _ => {
            return Err(OpError::Rejected(format!(
                "nothing to retract: no believed {subject_kind}:{subject_key} {predicate}"
            )));
        }
    };
    let events = build_retractions(
        next_seq(&store),
        &incumbents,
        subject_kind,
        subject_key,
        predicate,
        source,
        authority,
        now_millis(),
    )
    .map_err(|error| OpError::Invalid(format!("invalid retraction: {error}")))?;
    // Apply all in memory first (each authority-gated); persist only if all are admitted.
    for event in &events {
        store
            .append(event.clone())
            .map_err(|error| OpError::Rejected(format!("REJECTED: {error}")))?;
    }
    let refs: Vec<&ClaimEvent> = events.iter().collect();
    append_events(path, &refs).map_err(write_error_to_op)?;
    let count = incumbents.len();
    let claims = if count == 1 { "claim" } else { "claims" };
    Ok(format!(
        "ACCEPTED  retracted {count} believed {claims} of {subject_kind}:{subject_key} \
         {predicate}  (authority={authority:?})"
    ))
}

/// Terminally remove the believed fact(s) for a subject+predicate. Unlike `supersede`
/// there is no replacement; unlike a contradiction (dissent) it is authority-gated — the
/// core fold rejects a retraction that under-ranks its incumbent, so a low-authority actor
/// cannot delete a trusted fact. Shared by `dent8 retract` and the MCP `retract` tool.
fn cmd_retract(args: &FactWriteArgs) -> i32 {
    present(with_write_retry(|| {
        op_retract(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            args.authority.level(),
            &args.source,
        )
    }))
}

/// Corroborate the believed fact(s): append a `Reinforced` event per believed claim. The
/// fold raises earned entrenchment (a distinct source/authority backing the same value) and
/// counts the evidence; the value is left unset so it is pure corroboration (no restatement,
/// no value-mismatch). Shared by `dent8 reinforce` and the MCP `reinforce` tool.
fn op_reinforce(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: AuthorityLevel,
    source: &str,
) -> Result<String, OpError> {
    let events = build_per_incumbent(
        path,
        subject_kind,
        subject_key,
        predicate,
        authority,
        source,
        "reinforce",
        |incumbent| ClaimEventKind::Reinforced {
            by: incumbent.clone(),
        },
    )?;
    let count = events.len();
    Ok(format!(
        "ACCEPTED  reinforced {count} believed claim(s) of {subject_kind}:{subject_key} \
         {predicate}  (authority={authority:?})"
    ))
}

/// Mark the believed fact(s) expired: append an `Expired` event per believed claim, moving it
/// to the terminal `Expired` lifecycle. This is an explicit lifecycle close and is
/// authority-gated by the core fold; TTL staleness remains read-time and non-mutating.
/// Shared by `dent8 expire` and the MCP `expire` tool.
fn op_expire(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: AuthorityLevel,
    source: &str,
) -> Result<String, OpError> {
    let events = build_per_incumbent(
        path,
        subject_kind,
        subject_key,
        predicate,
        authority,
        source,
        "expire",
        |_incumbent| ClaimEventKind::Expired {
            reason: dent8_core::ExpirationReason::PolicyRetention,
        },
    )?;
    let count = events.len();
    Ok(format!(
        "ACCEPTED  expired {count} believed claim(s) of {subject_kind}:{subject_key} {predicate}"
    ))
}

/// Shared body for the single-event-per-believed-claim writes (`reinforce`, `expire`): find
/// the believed incumbents, build one event per incumbent (its kind chosen by `kind_for`),
/// admit each through the firewall, then persist all-or-nothing.
#[allow(clippy::too_many_arguments)]
fn build_per_incumbent(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: AuthorityLevel,
    source: &str,
    verb: &str,
    kind_for: impl Fn(&ClaimId) -> ClaimEventKind,
) -> Result<Vec<ClaimEvent>, OpError> {
    enforce_write_authority(&WriteAuth::new(
        verb,
        subject_kind,
        subject_key,
        predicate,
        None,
        authority,
        source,
    ))?;
    let mut store = load_store(path).map_err(OpError::Invalid)?;
    let subject = EntityRef::new(subject_kind, subject_key)
        .map_err(|error| OpError::Invalid(format!("invalid subject: {error}")))?;
    let predicate_parsed = Predicate::new(predicate)
        .map_err(|error| OpError::Invalid(format!("invalid predicate: {error}")))?;
    let incumbents = store
        .believed_claim_ids(&subject, &predicate_parsed)
        .map_err(|error| OpError::Invalid(error.to_string()))?;
    if incumbents.is_empty() {
        return Err(OpError::Rejected(format!(
            "nothing to {verb}: no believed {subject_kind}:{subject_key} {predicate}"
        )));
    }
    let now = now_millis();
    let seq = next_seq(&store);
    let mut events = Vec::with_capacity(incumbents.len());
    for (index, incumbent) in incumbents.iter().enumerate() {
        let event = build_event(
            &format!("event:{}", seq + index),
            incumbent.as_str(),
            subject_kind,
            subject_key,
            predicate,
            kind_for(incumbent),
            None,
            source,
            authority,
            now,
        )
        .map_err(|error| OpError::Invalid(format!("invalid {verb}: {error}")))?;
        events.push(event);
    }
    for event in &events {
        store
            .append(event.clone())
            .map_err(|error| OpError::Rejected(format!("REJECTED: {error}")))?;
    }
    let refs: Vec<&ClaimEvent> = events.iter().collect();
    append_events(path, &refs).map_err(write_error_to_op)?;
    Ok(events)
}

fn cmd_reinforce(args: &FactWriteArgs) -> i32 {
    present(with_write_retry(|| {
        op_reinforce(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            args.authority.level(),
            &args.source,
        )
    }))
}

fn cmd_expire(args: &FactWriteArgs) -> i32 {
    present(with_write_retry(|| {
        op_expire(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            args.authority.level(),
            &args.source,
        )
    }))
}

/// Build the `(events, opposing_claim_id)` for a `contradict`: a fresh opposing assertion
/// (`event:{seq}`, appended first) carrying the rival value, plus a `Contradicted` event on
/// the incumbent pointing `by` at it. Both end up believed — the paraconsistent surfaced
/// conflict ([ADR 0009](../../docs/decisions/0009-uniqueness-and-contestation.md)).
#[allow(clippy::too_many_arguments)]
fn build_contradiction(
    seq: usize,
    incumbent_claim_id: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    opposing_value: &str,
    source: &str,
    authority: AuthorityLevel,
    now: TimestampMillis,
) -> Result<(Vec<ClaimEvent>, String), String> {
    let opposing_claim_id = format!("claim:{subject_kind}:{subject_key}:{predicate}:{seq}");
    let opposing = build_event(
        &format!("event:{seq}"),
        &opposing_claim_id,
        subject_kind,
        subject_key,
        predicate,
        ClaimEventKind::Asserted,
        Some(ClaimValue::Text(opposing_value.to_string())),
        source,
        authority,
        now,
    )?;
    let by = ClaimId::new(&opposing_claim_id).map_err(|e| format!("claim id: {e}"))?;
    let contradiction = build_event(
        &format!("event:{}", seq + 1),
        incumbent_claim_id,
        subject_kind,
        subject_key,
        predicate,
        ClaimEventKind::Contradicted {
            by,
            basis: ContradictionBasis::SamePredicateDifferentValue,
        },
        None,
        source,
        authority,
        now,
    )?;
    Ok((vec![opposing, contradiction], opposing_claim_id))
}

fn op_contradict(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    opposing_value: &str,
    authority: AuthorityLevel,
    source: &str,
) -> Result<String, OpError> {
    enforce_write_authority(&WriteAuth::new(
        "contradict",
        subject_kind,
        subject_key,
        predicate,
        Some(opposing_value),
        authority,
        source,
    ))?;
    let mut store = load_store(path).map_err(OpError::Invalid)?;
    let subject = EntityRef::new(subject_kind, subject_key)
        .map_err(|error| OpError::Invalid(format!("invalid subject: {error}")))?;
    let predicate_parsed = Predicate::new(predicate)
        .map_err(|error| OpError::Invalid(format!("invalid predicate: {error}")))?;
    let now = now_millis();
    // Contradiction targets the *single* believed incumbent (explain_subject prefers the
    // contested/fresh one) — unlike supersede/retract, which act on every believed claim.
    // Flagging one fact as disputed is the intent (ADR 0009); the surfaced conflict can
    // then be resolved with supersede/retract.
    let Some(incumbent) = store
        .explain_subject(&subject, &predicate_parsed, now)
        .ok()
        .flatten()
    else {
        return Err(OpError::Rejected(format!(
            "nothing to contradict: no believed {subject_kind}:{subject_key} {predicate}"
        )));
    };
    let (mut events, opposing_claim_id) = build_contradiction(
        next_seq(&store),
        incumbent.claim_id.as_str(),
        subject_kind,
        subject_key,
        predicate,
        opposing_value,
        source,
        authority,
        now,
    )
    .map_err(|error| OpError::Invalid(format!("invalid contradiction: {error}")))?;
    // The opposing claim is a fresh assertion of this predicate (default TTL like `assert`).
    let registry = PredicateRegistry::coding_agent();
    apply_policy_defaults(&registry, &mut events[0]);

    // Apply both in memory first; persist only if both admit (a Canonical incumbent makes
    // the contradiction hard-alarm, rejecting the whole operation with nothing persisted).
    for event in &events {
        store
            .append(event.clone())
            .map_err(|error| OpError::Rejected(format!("REJECTED: {error}")))?;
    }
    let refs: Vec<&ClaimEvent> = events.iter().collect();
    append_events(path, &refs).map_err(write_error_to_op)?;
    Ok(format!(
        "CONTESTED  {subject_kind}:{subject_key} {predicate}: {} (incumbent) vs \"{opposing_value}\"  \
         (authority={authority:?})\n  both are now believed; resolve with `supersede` (install a \
         winner) or `retract`. new claim {opposing_claim_id}",
        display_value(&incumbent.value)
    ))
}

/// Flag a conflict: assert an opposing claim and move the believed incumbent to
/// `Contested`, keeping **both** (paraconsistency — localize, don't drop). Unlike
/// `supersede`/`retract` this is **dissent**: it is *not* authority-gated, so a
/// low-authority source can flag a wrong fact without overriding it — the one exception
/// being a `Canonical` incumbent, which hard-alarms. Shared by `dent8 contradict` and the
/// MCP `contradict` tool.
fn cmd_contradict(args: &ValueWriteArgs) -> i32 {
    present(with_write_retry(|| {
        op_contradict(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            &args.value,
            args.authority.level(),
            &args.source,
        )
    }))
}

/// One line of a fact's event history for `replay`: what happened, with provenance.
fn format_history_line(event: &ClaimEvent) -> String {
    let what = match &event.kind {
        ClaimEventKind::Asserted => {
            let value = event
                .value
                .as_ref()
                .map_or_else(|| "-".to_string(), display_value);
            format!("asserted     = {value}")
        }
        ClaimEventKind::Superseded { by, .. } => format!("superseded   by {by}"),
        ClaimEventKind::Contradicted { by, .. } => format!("contradicted by {by}"),
        ClaimEventKind::Retracted { reason } => format!("retracted    ({reason:?})"),
        ClaimEventKind::Expired { .. } => "expired".to_string(),
        ClaimEventKind::Reinforced { .. } => "reinforced".to_string(),
        ClaimEventKind::Retrieved { .. } => "retrieved".to_string(),
        ClaimEventKind::UsedInDecision { .. } => "used-in-decision".to_string(),
    };
    format!(
        "  {:<9} {:<34} {what}  ({:?}, {})",
        event.event_id.as_str(),
        event.claim_id.as_str(),
        event.authority.level,
        event.provenance.source
    )
}

/// Replay the full ordered event history for a subject+predicate — every assertion,
/// supersession, retraction, and contradiction, with its authority and source — then the
/// current believed (or terminal) state. dent8's "replay *why* a fact is believed". Shared
/// by `dent8 replay` and the MCP `replay` tool.
fn op_replay(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
) -> Result<String, OpError> {
    use std::fmt::Write;
    let store = load_store(path).map_err(OpError::Invalid)?;
    let subject = EntityRef::new(subject_kind, subject_key)
        .map_err(|error| OpError::Invalid(format!("invalid subject: {error}")))?;
    let predicate_parsed = Predicate::new(predicate)
        .map_err(|error| OpError::Invalid(format!("invalid predicate: {error}")))?;
    let filter = EventFilter {
        subject: Some(subject.clone()),
        predicate: Some(predicate_parsed.clone()),
        ..EventFilter::default()
    };
    let events = store
        .scan_events(&filter)
        .map_err(|error| OpError::Rejected(format!("replay failed: {error}")))?;
    if events.is_empty() {
        return Err(OpError::Rejected(format!(
            "no events for {subject_kind}:{subject_key} {predicate}"
        )));
    }
    let mut out = format!(
        "replay {subject_kind}:{subject_key} {predicate}  ({} events)",
        events.len()
    );
    for event in &events {
        out.push('\n');
        out.push_str(&format_history_line(event));
    }
    if let Ok(Some(receipt)) = store.explain_latest(&subject, &predicate_parsed, now_millis()) {
        // Freshness is folded into the non-terminal cases so the audit summary never
        // understates staleness (a contested *and* stale claim says so).
        let stale = if receipt.fresh { "" } else { " (stale)" };
        let status = if receipt.lifecycle.is_terminal() {
            format!("{:?}", receipt.lifecycle)
        } else if receipt.lifecycle == ClaimLifecycle::Contested {
            format!("contested by {}{stale}", receipt.contradicted_by.len())
        } else {
            format!("believed{stale}")
        };
        let _ = write!(
            out,
            "\n  => current: {} [{status}]",
            display_value(&receipt.value)
        );
    }
    Ok(out)
}

fn cmd_replay(args: &ReadFactArgs) -> i32 {
    present(op_replay(
        &log_path(),
        &args.subject.kind,
        &args.subject.key,
        &args.predicate,
    ))
}

/// Explain the believed (or terminal) fact + its integrity receipt. Shared by
/// `dent8 explain` and the MCP `explain` tool.
fn op_explain(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
) -> Result<String, OpError> {
    let receipt = op_explain_receipt(path, subject_kind, subject_key, predicate)?;
    let annotation = read_annotation(receipt.lifecycle, receipt.fresh);
    Ok(format!(
        "explain {subject_kind}:{subject_key} {predicate}{annotation}\n{}",
        format_receipt(&receipt)
    ))
}

/// Resolve the believed (or terminal) fact as a typed receipt. The CLI renders this as text;
/// MCP uses the same receipt as `structuredContent` so agents do not need to parse prose.
fn op_explain_receipt(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
) -> Result<IntegrityReceipt, OpError> {
    let store = load_store(path).map_err(OpError::Invalid)?;
    let subject = EntityRef::new(subject_kind, subject_key)
        .map_err(|error| OpError::Invalid(format!("invalid subject: {error}")))?;
    let predicate_parsed = Predicate::new(predicate)
        .map_err(|error| OpError::Invalid(format!("invalid predicate: {error}")))?;
    match store.explain_latest(&subject, &predicate_parsed, now_millis()) {
        Ok(Some(receipt)) => Ok(receipt),
        Ok(None) => Err(OpError::Rejected(format!(
            "no claim for {subject_kind}:{subject_key} {predicate}"
        ))),
        Err(error) => Err(OpError::Rejected(format!("explain failed: {error}"))),
    }
}

fn cmd_explain(args: &ReadFactArgs) -> i32 {
    present(op_explain(
        &log_path(),
        &args.subject.kind,
        &args.subject.key,
        &args.predicate,
    ))
}

/// The distinct `(kind, key, predicate)` fact streams in the log, in append order — the
/// enumeration behind the MCP `resources/list` surface.
fn op_list_subjects(path: &str) -> Result<Vec<(String, String, String)>, OpError> {
    let store = load_store(path).map_err(OpError::Invalid)?;
    Ok(store
        .subjects()
        .into_iter()
        .map(|(subject, predicate)| {
            (
                subject.kind().to_string(),
                subject.key().to_string(),
                predicate.as_str().to_string(),
            )
        })
        .collect())
}

/// List every contested fact (a fact in dispute — `Contested` lifecycle) across all
/// entities. Read-only; backend-aware via `load_store`. Wires `EntityProjection::contested`
/// to a runnable surface (gap-register #8).
fn op_conflicts(path: &str) -> Result<String, OpError> {
    let store = load_store(path).map_err(OpError::Invalid)?;
    let mut lines = Vec::new();
    for (subject, predicate) in store.subjects() {
        let filter = EventFilter {
            subject: Some(subject.clone()),
            predicate: Some(predicate.clone()),
            ..EventFilter::default()
        };
        let events = store
            .scan_events(&filter)
            .map_err(|error| OpError::Invalid(error.to_string()))?;
        let Ok(projection) = replay_entity(&events) else {
            continue;
        };
        // An entity is in dispute when one of its believed claims is `Contested`. Show *all*
        // its believed claims so both sides of the dispute are visible, not just one.
        let believed: Vec<&dent8_core::ClaimState> = projection.believed().collect();
        if believed
            .iter()
            .any(|state| state.lifecycle == ClaimLifecycle::Contested)
        {
            let rivals: Vec<String> = believed
                .iter()
                .map(|state| {
                    format!(
                        "{:?} (authority={:?}, {:?})",
                        state.value, state.authority.level, state.lifecycle
                    )
                })
                .collect();
            lines.push(format!(
                "{}:{} {}: {}",
                subject.kind(),
                subject.key(),
                predicate.as_str(),
                rivals.join("  vs  ")
            ));
        }
    }
    if lines.is_empty() {
        Ok("no contested facts — nothing in dispute".to_string())
    } else {
        Ok(format!(
            "{} contested fact(s) (resolve with `supersede`):\n  {}",
            lines.len(),
            lines.join("\n  ")
        ))
    }
}

fn cmd_conflicts() -> i32 {
    present(op_conflicts(&log_path()))
}

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
            actor: ActorId::new("actor:demo").expect("actor"),
            tool: Some("dent8-demo".to_string()),
            run_id: None,
            input_digest: None,
            recorded_at: TimestampMillis::from_unix_millis(1),
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
            Err(OpError::Rejected(_))
        ));
        // An unregistered source has an Unknown ceiling: anything above Unknown is rejected.
        assert!(matches!(
            check("source:web-scrape", AuthorityLevel::Low),
            Err(OpError::Rejected(_))
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
        let (revision, _replacement) = build_revision(
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
