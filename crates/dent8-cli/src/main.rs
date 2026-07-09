use std::{
    io::IsTerminal,
    str::FromStr,
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use clap::builder::styling::{AnsiColor, Styles};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
#[cfg(test)]
use dent8_core::{
    ActorId, Authority, Confidence, Evidence, EvidenceId, EvidenceKind, FactEventId, FactEventKind,
    Provenance, Ttl,
};
use dent8_core::{
    AuthorityLevel, FactEvent, FactId, FactLifecycle, FactValue, Predicate, SourceId, Subject,
    TimestampMillis, content_check,
};
#[cfg(test)]
use dent8_store::StoreError;
use dent8_store::{
    EventFilter, EventStore, InMemoryEventStore, IntegrityReceipt, LineageIssue, PredicateRegistry,
    UnearnedSupersession, replay_subject, tainted_facts,
};
use dent8_store_postgres::{EVENT_LOG_SCHEMA_SQL, MATERIALIZATION_SCHEMA_SQL};

mod capture;
mod context;
mod daemon;
mod doctor;
mod hook;
mod identity;
mod mcp;
/// The daemon write client (ADR 0018 PR 5): a synchronous Unix socket that proves identity via
/// the session challenge, so it needs `identity` signing and a Unix target.
#[cfg(all(unix, feature = "async-store"))]
mod mcp_client;
mod mcp_config;
mod memory;
mod native;
mod ops;
mod setup;
mod snapshot;
mod status;
mod witness;

use status::Status;

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
    if let Some(command) = cli.command.as_ref()
        && cli.output == CliOutput::Json
        && !command.supports_json_output()
    {
        eprintln!(
            "`dent8 {}` has no `--output json` result — it is a streaming/hook command; \
             every other command supports `--output json`.",
            command.cli_name()
        );
        return 2;
    }
    match cli.command {
        None => {
            if cli.output == CliOutput::Json {
                eprintln!("`dent8 --output json` requires a command");
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
        Some(CliCommand::Snapshot(args)) => snapshot::cmd_snapshot(&args, cli.output),
        Some(CliCommand::Conflicts) => ops::cmd_conflicts(cli.output),
        Some(CliCommand::Eval) => cmd_eval(cli.output),
        Some(CliCommand::Init(args)) => setup::cmd_init(&args, cli.output),
        Some(CliCommand::Agent(args)) => match args.command {
            AgentCommand::Add(args) => setup::cmd_agent_add(&args, cli.output),
        },
        Some(CliCommand::Doctor(args)) => doctor::cmd_doctor(&args, cli.output),
        Some(CliCommand::Daemon(args)) => match args.command {
            DaemonCommand::Status(args) => daemon::cmd_daemon_status(&args, cli.output),
            DaemonCommand::Serve(args) => daemon::cmd_daemon_serve(&args),
        },
        Some(CliCommand::Completions(args)) => cmd_completions(args.shell, cli.output),
        Some(CliCommand::Export(args)) => {
            if let Some(target) = args.target.as_deref() {
                // The native-memory export is stock (like `context`), so it works under
                // `--no-default-features`; only the Parquet path is feature-gated.
                memory::cmd_export_native(target, cli.output)
            } else {
                #[cfg(feature = "export")]
                {
                    cmd_export(&args.out, cli.output)
                }
                #[cfg(not(feature = "export"))]
                {
                    cmd_export_unavailable(&args.out, cli.output)
                }
            }
        }
        Some(CliCommand::Import(args)) => memory::cmd_import(&args, cli.output),
        Some(CliCommand::Assert(args)) => ops::cmd_assert(&args, cli.output),
        Some(CliCommand::Derive(args)) => ops::cmd_derive(&args, cli.output),
        Some(CliCommand::Supersede(args)) => ops::cmd_supersede(&args, cli.output),
        Some(CliCommand::Retract(args)) => ops::cmd_retract(&args, cli.output),
        Some(CliCommand::Reinforce(args)) => ops::cmd_reinforce(&args, cli.output),
        Some(CliCommand::Expire(args)) => ops::cmd_expire(&args, cli.output),
        Some(CliCommand::Contradict(args)) => ops::cmd_contradict(&args, cli.output),
        Some(CliCommand::Explain(args)) => ops::cmd_explain(&args, cli.output),
        Some(CliCommand::Replay(args)) => ops::cmd_replay(&args, cli.output),
        Some(CliCommand::Context(args)) => context::cmd_context(&args, cli.output),
        Some(CliCommand::Capture(args)) => capture::cmd_capture(&args, cli.output),
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
            AuthorityCommand::Remove(args) => {
                cmd_authority_remove(&args.source, args.force, cli.output)
            }
            AuthorityCommand::Defaults => cmd_authority_defaults(cli.output),
        },
        Some(CliCommand::Identity(args)) => run_identity(&args.command, cli.output),
        Some(CliCommand::Hook(args)) => match args.command {
            HookCommand::NativeMemoryGuard => hook::cmd_hook_native_memory_guard(),
        },
        Some(CliCommand::Native(args)) => match args.command {
            NativeCommand::Scan(args) => native::cmd_native_scan(&args, cli.output),
            NativeCommand::Reconcile(args) => native::cmd_native_reconcile(&args, cli.output),
        },
        Some(CliCommand::Mcp(args)) => match args.command {
            McpCommand::Serve(args) => mcp::serve_command(args.daemon, args.socket.as_deref()),
            McpCommand::Proxy(args) => mcp::proxy_command(args.socket.as_deref()),
            McpCommand::Install(args) => setup::cmd_mcp_install(&args, cli.output),
        },
        Some(CliCommand::Schema(args)) => match args.command {
            SchemaCommand::Postgres => cmd_schema_postgres(cli.output),
        },
        Some(CliCommand::Witness(args)) => run_witness(&args.command, cli.output),
    }
}

const CLI_AFTER_HELP: &str = "\
Subject is written as <kind>:<key>, e.g. person:alice or repo:dent8.
Example: dent8 assert person:alice favorite_drink tea

Storage: a JSON-lines dev log by default (DENT8_LOG, default ./dent8-log.jsonl), or an
async backend selected by DENT8_STORE_URL, dispatched by scheme (postgres:// needs
--features postgres). authority is one of: low | medium | high | canonical. Write commands
accept --source/--authority explicitly, or default them from DENT8_GRANT when signed identity
is configured.
Authority ceiling: a source may assert at most its registered max. Enforced once a registry
exists (DENT8_AUTHORITY, default ./dent8-authority.json) — then deny-by-default: an unlisted
source is blocked from writing. Without a registry the CLI is permissive (dev mode), unless
DENT8_REQUIRE_AUTHORITY=1 is set. The registry is host-local config, independent of the event
backend. A grant's scope restricts write subjects (\"*\" or exact <kind>:<key>), and a grant
issued by another registered source is capped by that issuer's own grant — an issuer cannot
delegate authority or scope it does not hold. See docs/STATUS.md.";

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
    #[arg(long, short = 'o', global = true, value_enum, default_value_t = CliOutput::Text)]
    output: CliOutput,
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    /// Assert a fact through the firewall, persisted to the log.
    #[command(
        override_usage = "dent8 assert <SUBJECT> <PREDICATE> <VALUE> [--authority <AUTHORITY>] [--source <SOURCE>]"
    )]
    Assert(ValueWriteArgs),
    /// Revise the believed fact, rejected if it cannot out-rank the incumbent.
    #[command(
        override_usage = "dent8 supersede <SUBJECT> <PREDICATE> <NEW_VALUE> [--authority <AUTHORITY>] [--source <SOURCE>]"
    )]
    Supersede(ValueWriteArgs),
    /// Remove the believed fact, rejected if it cannot out-rank the incumbent.
    #[command(
        override_usage = "dent8 retract <SUBJECT> <PREDICATE> [--authority <AUTHORITY>] [--source <SOURCE>]"
    )]
    Retract(FactWriteArgs),
    /// Flag a conflict (dissent): contest the fact, keep both.
    #[command(
        override_usage = "dent8 contradict <SUBJECT> <PREDICATE> <OPPOSING_VALUE> [--authority <AUTHORITY>] [--source <SOURCE>]"
    )]
    Contradict(ValueWriteArgs),
    /// Assert a fact derived from another fact, recording a dependency edge.
    #[command(
        override_usage = "dent8 derive <SUBJECT> <PREDICATE> <VALUE> --basis <BASIS_SUBJECT> <BASIS_PREDICATE> [--authority <AUTHORITY>] [--source <SOURCE>]"
    )]
    Derive(DeriveWriteArgs),
    /// Corroborate the believed fact without restating its value.
    #[command(
        override_usage = "dent8 reinforce <SUBJECT> <PREDICATE> [--authority <AUTHORITY>] [--source <SOURCE>]"
    )]
    Reinforce(FactWriteArgs),
    /// Terminally expire the believed fact.
    #[command(
        override_usage = "dent8 expire <SUBJECT> <PREDICATE> [--authority <AUTHORITY>] [--source <SOURCE>]"
    )]
    Expire(FactWriteArgs),
    /// Explain the believed fact, with an integrity receipt.
    Explain(ReadFactArgs),
    /// Replay the full event history for a fact.
    Replay(ReadFactArgs),
    /// Emit the currently-believed facts as an agent context pack (markdown by default).
    Context(ContextArgs),
    /// Capture structured fact proposals (JSON lines) through the firewall.
    #[command(
        override_usage = "dent8 capture [FILE] [--consume [--keep-failed]] [--authority <AUTHORITY>] [--source <SOURCE>]"
    )]
    Capture(CaptureArgs),
    /// Browse fact streams known to dent8.
    Facts(FactsArgs),
    /// Check log integrity.
    Verify,
    /// Emit a debugger/control-plane snapshot of the current dent8 state.
    Snapshot(SnapshotArgs),
    /// List contested facts.
    Conflicts,
    /// Run the adversarial corpus and Mem0/Zep integrity comparison.
    Eval,
    /// Bootstrap a local dent8 project configuration.
    Init(InitArgs),
    /// Add an agent profile to an existing shared dent8 bundle.
    Agent(AgentArgs),
    /// Diagnose the current dent8 setup.
    Doctor(DoctorArgs),
    /// Inspect or run the local Unix-socket daemon.
    Daemon(DaemonArgs),
    /// Generate shell completion scripts.
    #[command(visible_aliases = ["completion", "autocomplete"])]
    Completions(CompletionsArgs),
    /// Export the log to Parquet, or (with `--target`) into a native memory/rules file.
    Export(ExportArgs),
    /// Import durable facts from a native memory/rules file through the firewall.
    Import(ImportArgs),
    /// Manage the source -> authority ceiling.
    Authority(AuthorityArgs),
    /// Manage signed source identity keys and grants.
    Identity(IdentityArgs),
    /// Provider hook helpers.
    Hook(HookArgs),
    /// Audit agent-native memory/rules files.
    Native(NativeArgs),
    /// Emit/verify Ed25519 signed tree heads.
    Witness(WitnessArgs),
    /// Print schemas.
    Schema(SchemaArgs),
    /// Serve dent8 over MCP.
    Mcp(McpArgs),
}

impl CliCommand {
    /// Whether this command emits a `--output json` result. Everything does, except commands
    /// that have no single JSON result to emit: `mcp serve`, `mcp proxy`, and `daemon serve`
    /// stream JSON-RPC frames, and `hook` is a git-hook stdin/stdout filter. A deny-list, not an
    /// allow-list, so a newly added command is machine-readable by default.
    fn supports_json_output(&self) -> bool {
        !matches!(
            self,
            Self::Hook(_)
                | Self::Daemon(DaemonArgs {
                    command: DaemonCommand::Serve(_),
                })
                | Self::Mcp(McpArgs {
                    command: McpCommand::Serve(_) | McpCommand::Proxy(_),
                })
        )
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
            Self::Context(_) => "context",
            Self::Capture(_) => "capture",
            Self::Facts(_) => "facts",
            Self::Verify => "verify",
            Self::Snapshot(_) => "snapshot",
            Self::Conflicts => "conflicts",
            Self::Eval => "eval",
            Self::Init(_) => "init",
            Self::Agent(_) => "agent",
            Self::Doctor(_) => "doctor",
            Self::Daemon(_) => "daemon",
            Self::Completions(_) => "completions",
            Self::Export(_) => "export",
            Self::Import(_) => "import",
            Self::Authority(_) => "authority",
            Self::Identity(_) => "identity",
            Self::Hook(_) => "hook",
            Self::Native(_) => "native",
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
    /// Authority level. Defaults to the active signed grant's max authority when `DENT8_GRANT` is set.
    #[arg(long, short = 'a', value_enum)]
    authority: Option<CliAuthority>,
    /// Provenance source for this write. Defaults to the active signed grant's source when `DENT8_GRANT` is set.
    #[arg(long, short = 's', value_parser = parse_source)]
    source: Option<String>,
    /// Valid-time lower bound (unix millis): when the fact starts to hold. Also anchors
    /// TTL freshness. Applies to the assertion this write creates.
    #[arg(long = "valid-from", value_name = "MILLIS")]
    valid_from: Option<i64>,
    /// Valid-time upper bound (unix millis): when the fact stops holding (ADR 0016).
    /// Past it the fact reads as stale, like an elapsed TTL.
    #[arg(long = "valid-to", value_name = "MILLIS")]
    valid_to: Option<i64>,
    /// Retention TTL as a human duration (e.g. 90d, 12h, 30m, 45s). The fact reads as stale
    /// once its freshness window elapses. A value beyond the predicate's retention ceiling is
    /// rejected. Omitted leaves the predicate default (or non-expiring when there is none).
    #[arg(long = "ttl", value_name = "DURATION", value_parser = parse_duration_ms)]
    ttl: Option<u64>,
}

#[derive(Args, Debug)]
struct FactWriteArgs {
    /// Fact subject, written as <kind>:<key> (for example person:alice).
    subject: CliSubject,
    /// Predicate within the subject's fact stream.
    #[arg(value_parser = parse_predicate)]
    predicate: String,
    /// Authority level. Defaults to the active signed grant's max authority when `DENT8_GRANT` is set.
    #[arg(long, short = 'a', value_enum)]
    authority: Option<CliAuthority>,
    /// Provenance source for this write. Defaults to the active signed grant's source when `DENT8_GRANT` is set.
    #[arg(long, short = 's', value_parser = parse_source)]
    source: Option<String>,
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
    /// Basis fact this derivative depends on: <basis-subject> <basis-predicate>.
    #[arg(long, required = true, num_args = 2, value_names = ["BASIS_SUBJECT", "BASIS_PREDICATE"])]
    basis: Vec<String>,
    /// Authority level. Defaults to the active signed grant's max authority when `DENT8_GRANT` is set.
    #[arg(long, short = 'a', value_enum)]
    authority: Option<CliAuthority>,
    /// Provenance source for this write. Defaults to the active signed grant's source when `DENT8_GRANT` is set.
    #[arg(long, short = 's', value_parser = parse_source)]
    source: Option<String>,
    /// Valid-time lower bound (unix millis) for the derived assertion (ADR 0016).
    #[arg(long = "valid-from", value_name = "MILLIS")]
    valid_from: Option<i64>,
    /// Valid-time upper bound (unix millis) for the derived assertion (ADR 0016).
    #[arg(long = "valid-to", value_name = "MILLIS")]
    valid_to: Option<i64>,
    /// Retention TTL as a human duration (e.g. 90d, 12h). Rejected if beyond the predicate's
    /// retention ceiling. Omitted leaves the predicate default (or non-expiring).
    #[arg(long = "ttl", value_name = "DURATION", value_parser = parse_duration_ms)]
    ttl: Option<u64>,
}

#[derive(Args, Debug)]
struct ReadFactArgs {
    /// Fact subject, written as <kind>:<key> (for example person:alice).
    subject: CliSubject,
    /// Predicate within the subject's fact stream.
    #[arg(value_parser = parse_predicate)]
    predicate: String,
    /// Read the log as it stood at this instant (unix millis): fold only events recorded
    /// at or before it (transaction-time travel, ADR 0016).
    #[arg(long = "as-of", value_name = "MILLIS")]
    as_of: Option<i64>,
    /// Evaluate freshness/validity at this instant (unix millis) instead of now.
    #[arg(long = "valid-at", value_name = "MILLIS")]
    valid_at: Option<i64>,
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

#[derive(Args, Debug, Default)]
pub(crate) struct ContextArgs {
    /// Only include facts with this subject kind.
    #[arg(long, value_name = "KIND", value_parser = parse_non_empty_filter)]
    kind: Option<String>,
    /// Only include facts with this subject key.
    #[arg(long, value_name = "KEY", value_parser = parse_non_empty_filter)]
    key: Option<String>,
    /// Only include facts with this predicate.
    #[arg(long, value_name = "PREDICATE", value_parser = parse_predicate)]
    predicate: Option<String>,
    /// Include believed-but-stale (and not-yet-valid) facts, annotated as such.
    #[arg(long)]
    include_stale: bool,
    /// Include dent8 internal diagnostic streams, such as doctor write-check facts.
    #[arg(long)]
    include_diagnostics: bool,
    /// Record a `fact.retrieved` audit event for every fact the pack emits (the read half
    /// of the read-audit loop). Recorded as the active signed grant's source when
    /// configured, else the agent tier (`source:agent` at `low`), through the normal
    /// write boundary.
    #[arg(long)]
    record_retrieval: bool,
    /// Purpose stamped on recorded retrieval events.
    #[arg(
        long,
        value_name = "TEXT",
        default_value = "context-pack",
        requires = "record_retrieval"
    )]
    purpose: String,
}

#[derive(Args, Debug)]
pub(crate) struct CaptureArgs {
    /// Proposals file (JSON lines). Reads stdin when omitted.
    #[arg(value_name = "FILE")]
    file: Option<String>,
    /// Truncate the proposals file after processing, so a session-end hook can flush a
    /// queue without replaying it on the next firing.
    #[arg(long, requires = "file")]
    consume: bool,
    /// With --consume, keep rejected and malformed proposal lines in the file (accepted
    /// lines are still removed) so they can be inspected or retried instead of surviving
    /// only in hook logs.
    #[arg(long, requires = "consume")]
    keep_failed: bool,
    /// Default authority for proposals that do not state one.
    #[arg(long, short = 'a', value_enum)]
    authority: Option<CliAuthority>,
    /// Default provenance source for proposals that do not state one.
    #[arg(long, short = 's', value_parser = parse_source)]
    source: Option<String>,
}

#[derive(Args, Debug)]
struct SnapshotArgs {
    /// Include dent8 internal diagnostic streams in the nested facts list.
    #[arg(long)]
    include_diagnostics: bool,
}

#[derive(Args, Debug)]
struct ExportArgs {
    /// Parquet output path (used when `--target` is not given).
    #[arg(default_value = "dent8-events.parquet", value_name = "OUT")]
    out: String,
    /// Write the currently-believed facts into a native memory/rules file (`CLAUDE.md`,
    /// `AGENTS.md`, …) as a receipt-bearing dent8-managed block, spliced in idempotently. This
    /// path is always available (it is not gated behind `--features export`).
    #[arg(long, value_name = "FILE")]
    target: Option<std::path::PathBuf>,
}

#[derive(Args, Debug)]
struct ImportArgs {
    /// Native memory/rules file (`CLAUDE.md`, `AGENTS.md`, markdown, …) to import durable
    /// facts from. Only dent8 managed blocks, inline `dent8://` receipt markers, and fenced
    /// `dent8` proposal blocks are read; free prose is skipped and reported.
    #[arg(value_name = "FILE")]
    file: std::path::PathBuf,
    /// Parse and report the proposals that would be made, writing nothing to the store.
    #[arg(long)]
    dry_run: bool,
    /// Default authority for imported proposals that do not carry one (a marker's or proposal's
    /// own authority still takes precedence; the firewall makes the final call).
    #[arg(long, short = 'a', value_enum)]
    authority: Option<CliAuthority>,
    /// Default provenance source for imported proposals that do not carry one.
    #[arg(long, short = 's', value_parser = parse_source)]
    source: Option<String>,
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
    /// Install the MCP client config to connect through `dent8 mcp proxy` instead of
    /// launching a store-backed stdio server directly.
    #[arg(long, requires = "install_mcp")]
    mcp_use_daemon: bool,
    /// Socket path written into the installed `dent8 mcp proxy --socket PATH` command.
    /// Implies daemon-proxy mode.
    #[arg(long, value_name = "PATH", requires = "install_mcp")]
    mcp_daemon_socket: Option<String>,
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
    /// Patch the agent config to connect through `dent8 mcp proxy` instead of launching a
    /// store-backed stdio server directly.
    #[arg(long, visible_alias = "use-daemon")]
    mcp_use_daemon: bool,
    /// Socket path written into the installed `dent8 mcp proxy --socket PATH` command.
    /// Implies daemon-proxy mode.
    #[arg(long, visible_alias = "daemon-socket", value_name = "PATH")]
    mcp_daemon_socket: Option<String>,
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
    const ALL: [Self; 7] = [
        Self::Codex,
        Self::ClaudeCode,
        Self::Cursor,
        Self::GrokBuild,
        Self::Gemini,
        Self::Cascade,
        Self::Hecate,
    ];

    fn all() -> &'static [Self] {
        &Self::ALL
    }

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
#[allow(clippy::struct_excessive_bools)]
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
    /// Diagnose every installed known agent profile from its generated .dent8 bundle.
    #[arg(
        long,
        conflicts_with_all = [
            "source",
            "agent",
            "mcp_config",
            "mcp_command",
            "mcp_local_bin",
            "repair"
        ]
    )]
    all_agents: bool,
    /// Directory for dent8's local project config when --agent or --all-agents is set.
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
struct DaemonArgs {
    #[command(subcommand)]
    command: DaemonCommand,
}

#[derive(Subcommand, Debug)]
enum DaemonCommand {
    /// Check whether the local daemon socket is reachable and whether this shell can authenticate.
    Status(DaemonStatusArgs),
    /// Run the local Unix-socket daemon in the foreground.
    Serve(DaemonServeArgs),
}

#[derive(Args, Debug)]
struct DaemonStatusArgs {
    /// Socket path to check. Defaults to `DENT8_DAEMON_SOCKET`, then the per-user daemon path.
    #[arg(long, value_name = "PATH")]
    socket: Option<String>,
}

#[derive(Args, Debug)]
struct DaemonServeArgs {
    /// Socket path to bind. Defaults to the per-user daemon path.
    #[arg(long, value_name = "PATH")]
    socket: Option<String>,
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
    /// Seed the default trust profile: human > CI > agent.
    Defaults,
}

#[derive(Args, Debug)]
struct AuthorityAddArgs {
    #[arg(value_parser = parse_source)]
    source: String,
    #[arg(value_enum)]
    max: CliAuthority,
    /// Who granted this ceiling. Naming another registered source caps this grant by that
    /// issuer's own grant (no self-escalation); any other name is an operator-level root.
    issuer: Option<String>,
    /// Subject scope: "*" (the default when omitted) or an exact <kind>:<key> subject the
    /// source may write about.
    scope: Option<String>,
}

#[derive(Args, Debug)]
struct AuthorityRemoveArgs {
    #[arg(value_parser = parse_source)]
    source: String,
    /// Also revoke every grant whose issuer chain passes through this source. Without it,
    /// removing a grant that other grants chain their authority through is refused.
    #[arg(long)]
    force: bool,
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
    /// Maximum authority this source key may assert.
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
    /// Maximum authority this source key may assert.
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
struct NativeArgs {
    #[command(subcommand)]
    command: NativeCommand,
}

#[derive(Subcommand, Debug)]
enum NativeCommand {
    /// Read-only audit of provider-native memory/rules files.
    Scan(NativeScanArgs),
    /// Verify dent8 receipt references found in provider-native memory/rules files.
    Reconcile(NativeReconcileArgs),
}

#[derive(Args, Debug)]
pub(crate) struct NativeScanArgs {
    /// Agent profile whose native memory/rules posture should be audited.
    #[arg(long, value_enum)]
    agent: InitAgent,
    /// Directory for dent8's local project config. Used to infer the project root.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// Project root to scan. Defaults to the parent of --dir when --dir is .dent8, else cwd.
    #[arg(long, value_name = "ROOT")]
    root: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct NativeReconcileArgs {
    /// Agent profile whose native memory/rules posture should be audited.
    #[arg(long, value_enum)]
    agent: InitAgent,
    /// Directory for dent8's local project config. Used to infer the project root.
    #[arg(long, default_value = ".dent8", value_name = "DIR")]
    dir: String,
    /// Project root to scan. Defaults to the parent of --dir when --dir is .dent8, else cwd.
    #[arg(long, value_name = "ROOT")]
    root: Option<String>,
    /// Replay the dent8 store as-of this Unix millisecond timestamp.
    #[arg(long, value_name = "MILLIS")]
    as_of: Option<i64>,
    /// Evaluate fact freshness/validity at this Unix millisecond timestamp.
    #[arg(long, value_name = "MILLIS")]
    valid_at: Option<i64>,
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
    /// Expose the belief surface over JSON-RPC — stdio by default, or a local Unix socket
    /// with `--daemon` (ADR 0018).
    Serve(McpServeArgs),
    /// Bridge stdio MCP to a running local daemon.
    Proxy(McpProxyArgs),
    /// Patch an agent MCP config with dent8 and show the resulting file.
    Install(McpInstallArgs),
}

#[derive(Args, Debug)]
struct McpServeArgs {
    /// Serve on a local Unix-domain socket instead of stdio: a per-user daemon many processes
    /// share over one transport. Authenticated connections can write; unauthenticated
    /// connections are read-only.
    #[arg(long)]
    daemon: bool,
    /// Socket path for `--daemon`. Defaults to `$XDG_RUNTIME_DIR/dent8/dent8.sock` (a per-user
    /// fallback under the temp dir is used when `$XDG_RUNTIME_DIR` is unset, e.g. macOS).
    #[arg(long, value_name = "PATH", requires = "daemon")]
    socket: Option<String>,
}

#[derive(Args, Debug)]
struct McpProxyArgs {
    /// Socket path for the running daemon. Defaults to `DENT8_DAEMON_SOCKET`, then the same
    /// per-user path as `mcp serve --daemon`.
    #[arg(long, value_name = "PATH")]
    socket: Option<String>,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
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
    /// Patch the agent config to connect through `dent8 mcp proxy` instead of launching a
    /// store-backed stdio server directly.
    #[arg(long)]
    use_daemon: bool,
    /// Socket path written into the installed `dent8 mcp proxy --socket PATH` command.
    /// Implies daemon-proxy mode.
    #[arg(long, value_name = "PATH")]
    daemon_socket: Option<String>,
    /// Render the resulting file without writing it.
    #[arg(long, conflicts_with = "check")]
    dry_run: bool,
    /// Exit 0 only when the existing config already matches the generated dent8 entry.
    #[arg(long)]
    check: bool,
}

#[derive(Args, Debug)]
struct WitnessArgs {
    #[command(subcommand)]
    command: WitnessCommand,
}

/// Transparency-log (witness) operations. Real subcommands so `witness` shares the same clap
/// parsing, `--output json`, and help as every other command (ADR 0011/0014).
#[derive(Subcommand, Debug)]
enum WitnessCommand {
    /// Generate a witness signing keypair.
    Keygen,
    /// Sign the current event-log head into the signed-head log.
    Sign,
    /// Verify the local signed-head log against the event log.
    Verify,
    /// Verify a published heads file, optionally cross-checking a published grants file.
    VerifyPublished {
        /// Published signed heads (JSON-lines).
        published_heads: String,
        /// Published grants (JSON-lines) to cross-check.
        #[arg(long)]
        grants: Option<String>,
    },
    /// Print the current event-log head.
    Head,
    /// Publish the current head, and optionally the grant history, to a file.
    Publish {
        /// Destination path for the published signed heads (JSON-lines).
        published_heads: String,
        /// Also publish the grant history to this path (JSON-lines).
        #[arg(long)]
        grants: Option<String>,
    },
    /// Long-running signer: sign the head as the log grows (streams NDJSON to stderr).
    Serve {
        /// Seconds between growth checks (floored at 1; default 5).
        interval_seconds: Option<u64>,
        /// Stop after signing this many heads.
        max_heads: Option<u64>,
    },
    /// Diagnose the witness setup for a role.
    Doctor {
        /// Which side to check: the writer, the signer, or both.
        #[arg(value_enum)]
        role: WitnessRole,
    },
}

/// The side of the witness split to diagnose (`witness doctor`).
#[derive(Copy, Clone, Debug, ValueEnum)]
enum WitnessRole {
    /// The writing side (formerly also spelled `verifier`).
    #[value(alias = "verifier")]
    Writer,
    /// The signing side.
    Signer,
    /// Both sides on one host (formerly also spelled `local`).
    #[value(alias = "local")]
    Both,
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
        Subject::new(kind, key)
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
    SourceId::new(raw).map_err(|error| format!("invalid source '{raw}': {error}"))?;
    Ok(raw.to_string())
}

/// Parse a human retention duration (`--ttl`) into milliseconds. Accepts a whole number with a
/// unit suffix — `ms`, `s`, `m`, `h`, or `d` (e.g. `90d`, `12h`, `30m`, `45s`). A missing or
/// unknown unit is rejected so an ambiguous bare number never silently means milliseconds.
fn parse_duration_ms(raw: &str) -> Result<u64, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("duration must not be empty (e.g. 90d, 12h, 30m, 45s)".to_string());
    }
    let split = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    if number.is_empty() {
        return Err(format!(
            "invalid duration '{raw}': expected a whole number with a unit (e.g. 90d, 12h)"
        ));
    }
    let amount: u64 = number
        .parse()
        .map_err(|_| format!("invalid duration '{raw}': '{number}' is not a whole number"))?;
    let unit_ms: u64 = match unit.trim() {
        "ms" => 1,
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        "" => {
            return Err(format!(
                "duration '{raw}' needs a unit suffix: ms, s, m, h, or d (e.g. 90d)"
            ));
        }
        other => {
            return Err(format!(
                "unknown duration unit '{other}' in '{raw}': use ms, s, m, h, or d"
            ));
        }
    };
    amount
        .checked_mul(unit_ms)
        .ok_or_else(|| format!("duration '{raw}' is too large"))
}

fn run_identity(command: &IdentityCommand, output: CliOutput) -> i32 {
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

/// Dispatch `dent8 witness <sub>` (the transparency-log surface, ADR 0011/0014).
fn run_witness(command: &WitnessCommand, output: CliOutput) -> i32 {
    match command {
        WitnessCommand::Keygen => witness::keygen(output),
        WitnessCommand::Sign => witness::sign(output),
        WitnessCommand::Verify => witness::verify(output),
        WitnessCommand::VerifyPublished {
            published_heads,
            grants,
        } => witness::verify_published(published_heads, grants.as_deref(), output),
        WitnessCommand::Head => witness::head(output),
        WitnessCommand::Publish {
            published_heads,
            grants,
        } => witness::publish(published_heads, grants.as_deref(), output),
        WitnessCommand::Serve {
            interval_seconds,
            max_heads,
        } => witness::serve(*interval_seconds, *max_heads, output),
        WitnessCommand::Doctor { role } => witness::doctor(*role, output),
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

fn display_value(value: &FactValue) -> String {
    match value {
        FactValue::Text(text) => format!("\"{text}\""),
        FactValue::Json(json) => format!("json:{}", json.as_str()),
        FactValue::Redacted => "<redacted>".to_string(),
    }
}

/// The read-time headline verdict for an explained fact: a terminal fact is no longer
/// believed; a fact whose asserted `valid_from` is still in the future is **not yet valid**;
/// a fact past its TTL or `valid_to` is **stale** (threat-model T4) — an agent must not act
/// on either as current. Fresh `Active` facts get no annotation. The receipt body (value,
/// `valid_from`, `expires_at`) is always shown for the audit trail.
fn read_annotation(lifecycle: FactLifecycle, fresh: bool, not_yet_valid: bool) -> String {
    if lifecycle.is_terminal() {
        format!("  [no longer believed — {lifecycle:?}]")
    } else if not_yet_valid {
        "  [not yet valid — valid_from is in the future]".to_string()
    } else if !fresh {
        "  [stale — no longer valid]".to_string()
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
    let valid_from = r.valid_from.map_or_else(
        || "-".to_string(),
        |at| {
            let suffix = if r.not_yet_valid {
                " (not yet valid)"
            } else {
                ""
            };
            format!("{}{suffix}", at.as_unix_millis())
        },
    );
    format!(
        "    value         : {value}\n    \
         lifecycle     : {:?}\n    \
         authority     : {:?}\n    \
         fresh         : {}\n    \
         valid_from    : {valid_from}\n    \
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

fn fact_value_json(value: &FactValue) -> serde_json::Value {
    match value {
        FactValue::Text(text) => serde_json::json!({
            "kind": "text",
            "text": text,
            "display": display_value(value),
        }),
        FactValue::Json(json) => serde_json::json!({
            "kind": "json",
            "json": json.as_str(),
            "display": display_value(value),
        }),
        FactValue::Redacted => serde_json::json!({
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
        "fact_id": receipt.fact_id.as_str(),
        "value": fact_value_json(&receipt.value),
        "lifecycle": format!("{:?}", receipt.lifecycle),
        "authority": receipt.authority.name(),
        "fresh": receipt.fresh,
        "not_yet_valid": receipt.not_yet_valid,
        "valid_from": receipt.valid_from.map(TimestampMillis::as_unix_millis),
        "expires_at": receipt.expires_at.map(TimestampMillis::as_unix_millis),
        "evidence_count": receipt.evidence_count,
        "corroboration": receipt.corroboration,
        "survived_challenges": receipt.survived_challenges,
        "superseded_by": receipt.superseded_by.as_ref().map(FactId::as_str),
        "contradicted_by": receipt
            .contradicted_by
            .iter()
            .map(FactId::as_str)
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
    // Mirror MCP: a contested fact reads `contested`, not `ok`.
    let status = if receipt.lifecycle == FactLifecycle::Contested {
        Status::Contested
    } else {
        Status::Ok
    };
    object.insert("status".to_string(), serde_json::json!(status.as_str()));
    object.insert("tool".to_string(), serde_json::json!(tool));
    value
}

fn short(hash: &str) -> String {
    format!("{}…", &hash[..hash.len().min(12)])
}

// ---- Persistent file-backed commands -------------------------------------------------
//
// `dent8 assert …` and `dent8 explain …` persist to a JSON-lines event log (one
// serialized `FactEvent` per line) so commands compose across separate invocations.
// Each invocation rehydrates the store via the trusted-reload path, runs the firewall +
// registry on a new write, and appends the admitted event. This is a *local* dev store;
// operational, transactional backends are selected by DENT8_STORE_URL.

const DEFAULT_LOG: &str = "dent8-log.jsonl";
const DEFAULT_AUTHORITY: &str = "dent8-authority.json";
/// The per-project store directory `dent8 init` creates.
const STORE_DIR: &str = ".dent8";

/// Discover the project store directory, **confined to the enclosing git repository** so a
/// `.dent8/` planted in an unrelated ancestor (e.g. `/tmp/.dent8` for a process running under
/// `/tmp`) is never silently adopted as an attacker-controlled store *and* authority registry.
///
/// Discovery rules:
/// - Find the enclosing repo root: the nearest ancestor of the cwd that holds a `.git` entry
///   (file or dir), searching upward but stopping at (and never above) `$HOME` and the
///   filesystem root.
/// - Inside that repo, scan from the cwd up to and including the repo root; the first `.dent8/`
///   found wins. This still lets a command run from any sub-directory of an initialized project
///   resolve the project's store instead of creating a parallel one in the cwd.
/// - When the cwd is **not** inside a git repo (no `.git` within bounds), only `./.dent8/` in
///   the cwd itself is considered — discovery does *not* walk upward.
///
/// `None` when nothing is found, so the caller falls back to the legacy cwd default (keeping a
/// fresh `dent8 init` working). Explicit `DENT8_LOG` / `DENT8_STORE_URL` / `DENT8_AUTHORITY`
/// overrides bypass discovery entirely (see the resolution helpers), so a store outside any repo
/// stays reachable via those env vars.
fn discover_dent8_dir() -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let Some(repo_root) = enclosing_repo_root(&cwd) else {
        // Not in a repo: only the cwd's own `.dent8/`, no upward walk.
        let candidate = cwd.join(STORE_DIR);
        return candidate.is_dir().then_some(candidate);
    };
    // Inside a repo: scan cwd..=repo_root; first `.dent8/` wins, never above the repo root.
    for dir in cwd.ancestors() {
        let candidate = dir.join(STORE_DIR);
        if candidate.is_dir() {
            return Some(candidate);
        }
        if dir == repo_root {
            break;
        }
    }
    None
}

/// The nearest ancestor of `start` (inclusive) that contains a `.git` entry — the enclosing git
/// repository root — searching upward but never above `$HOME` or the filesystem root. `None`
/// when `start` is not inside a repo within those bounds. This is the security boundary that
/// confines store discovery to the repo you are actually working in.
fn enclosing_repo_root(start: &std::path::Path) -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    for dir in start.ancestors() {
        if dir.join(".git").exists() {
            return Some(dir.to_path_buf());
        }
        // `$HOME` is checked (above) but never crossed; the filesystem root, where `ancestors()`
        // terminates, is the other bound.
        if home.as_deref() == Some(dir) {
            break;
        }
    }
    None
}

/// Undo the single-quote shell quoting [`shell_quote`] applies to a value in `.dent8/env`. A
/// value without surrounding quotes is returned trimmed and unchanged.
fn shell_unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('\'') && trimmed.ends_with('\'') {
        trimmed[1..trimmed.len() - 1].replace("'\\''", "'")
    } else {
        trimmed.to_string()
    }
}

/// A discovered project store: the `.dent8/` directory plus the assignments parsed from its
/// `env` file. The `env` file is parsed as **safe `KEY=value`** (single-quote-unquoted), never
/// shell-sourced, so a discovered store only supplies configuration values and can never execute
/// code. Callers layer this under the process environment (which always wins).
struct DiscoveredStore {
    dir: std::path::PathBuf,
    env: std::collections::BTreeMap<String, String>,
}

impl DiscoveredStore {
    /// The value a sourced `.dent8/env` would export for `key`, when present and non-empty.
    fn env_value(&self, key: &str) -> Option<String> {
        self.env
            .get(key)
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }
}

/// Discover the enclosing-repo project store (see [`discover_dent8_dir`]) and parse its
/// `.dent8/env`. Centralizes discovery so log / authority / store-URL resolution all agree on
/// one store and one parsed env per invocation.
fn discover_store() -> Option<DiscoveredStore> {
    let dir = discover_dent8_dir()?;
    let env = parse_dent8_env(&dir);
    Some(DiscoveredStore { dir, env })
}

/// Parse a discovered `.dent8/env` as safe `KEY=value` assignments (single-quote-unquoted),
/// tolerating comments (`#…`) and blank lines. **Not** shell-sourced — values never run as
/// code. A missing/unreadable env file yields an empty map so discovery degrades to store-dir
/// defaults.
fn parse_dent8_env(store_dir: &std::path::Path) -> std::collections::BTreeMap<String, String> {
    let mut env = std::collections::BTreeMap::new();
    let Ok(contents) = std::fs::read_to_string(store_dir.join("env")) else {
        return env;
    };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            env.insert(key.trim().to_string(), shell_unquote(value));
        }
    }
    env
}

fn log_path() -> String {
    // An explicit `DENT8_LOG` override always wins — the escape hatch for a store outside any
    // git repo, and backward compatible with a sourced `.dent8/env`.
    if let Ok(explicit) = std::env::var("DENT8_LOG") {
        return explicit;
    }
    // Otherwise resolve against the discovered enclosing-repo store: honor a `DENT8_LOG` set in
    // its `.dent8/env`, else the store's own `memory.jsonl`, so a subdir run with unsourced env
    // reads/writes the real store rather than a parallel `./dent8-log.jsonl`.
    if let Some(store) = discover_store() {
        if let Some(log) = store.env_value("DENT8_LOG") {
            return log;
        }
        return store
            .dir
            .join("memory.jsonl")
            .to_string_lossy()
            .into_owned();
    }
    // No project store within bounds: fall back to the legacy cwd default so a fresh `init`
    // (and ad-hoc dev use) still works.
    DEFAULT_LOG.to_string()
}

// ---- Source authority registry (authz: cap what a source may *fact*) ----------------
//
// dent8 otherwise trusts the requested/defaulted `authority` value. The registry maps a
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
    /// Who granted this ceiling. When it names another **registered source**, the write gate
    /// also enforces that issuer's own grant (ceiling and scope), transitively — an issuer
    /// cannot delegate authority it does not hold, and a cyclic/self-issued chain authorizes
    /// nothing. An unregistered issuer is an operator-level root recorded for audit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issuer: Option<String>,
    /// Subject scope: `"*"` (or absent) covers every subject; any other value covers exactly
    /// the literal `<kind>:<key>` subject it names (see [`scope_covers`]).
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
    // An explicit `DENT8_AUTHORITY` override always wins — backward compatible with sourced env.
    if let Ok(explicit) = std::env::var("DENT8_AUTHORITY") {
        return explicit;
    }
    // Otherwise resolve against the discovered enclosing-repo store: honor a `DENT8_AUTHORITY`
    // set in its `.dent8/env`, else the store's own `authority.json`, so `init` and the
    // `authority` subcommands agree on one registry per store even when the env file was never
    // sourced (no more divergent `./dent8-authority.json`).
    if let Some(store) = discover_store() {
        if let Some(authority) = store.env_value("DENT8_AUTHORITY") {
            return authority;
        }
        return store
            .dir
            .join("authority.json")
            .to_string_lossy()
            .into_owned();
    }
    DEFAULT_AUTHORITY.to_string()
}

/// What the write-boundary auth gate needs to know about a write: the subject (for grant
/// scope checks), the stated authority (for ceiling checks), and the source. The full write
/// *content* is no longer carried here — the persisted per-event attestation (ADR 0013) signs
/// the whole event at the append boundary, which covers strictly more than any summary could.
#[derive(Clone, Copy, Debug)]
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

/// The authz gate, run before the firewall on every write: reject a write above its
/// `source`'s registered ceiling, outside its grant's scope, or beyond what the grant's
/// issuer chain can delegate. A no-op only when no registry is configured and
/// `DENT8_REQUIRE_AUTHORITY` is not enabled.
fn enforce_registry_grant(auth: &WriteAuth<'_>) -> Result<(), ops::OpError> {
    let registry = load_authority_registry().map_err(ops::OpError::Invalid)?;
    registry_grant_check(registry.as_ref(), auth)
}

/// Which source identity a write is authorized and attested under, threaded from the request
/// origin down to the two identity wrappers (ADR 0018). This is the single seam between *where
/// the identity comes from* and *how the write is signed*, and it encodes the fail-closed
/// invariant in the type: a daemon connection that has not proven an identity carries
/// [`WriteIdentity::Unauthenticated`], so a write that somehow reaches the seam without a proven
/// identity errors rather than silently borrowing the daemon's *own* env identity.
#[derive(Clone)]
pub(crate) enum WriteIdentity {
    /// The CLI and the stdio MCP server: resolve identity from process env, exactly as before
    /// ADR 0018 (`IdentityContext::from_env` when the `identity` feature is on; the configured
    /// check otherwise).
    Env,
    /// A local-daemon connection that has not completed the session-challenge handshake: it may
    /// only read, and a write reaching the identity seam fails closed. Only the daemon transport
    /// constructs this, so a build without it (no `async-store`) never does.
    #[cfg_attr(not(feature = "async-store"), allow(dead_code))]
    Unauthenticated,
    /// A local-daemon connection's proven per-connection identity (ADR 0018): the source it
    /// proved possession of at `dent8/hello` + `dent8/prove`. Its writes are authorized and
    /// Ed25519-attested as that source — the same-user key the daemon holds — never borrowing an
    /// ambient env identity. Constructed only by the Unix-socket daemon handshake.
    #[cfg(all(unix, feature = "async-store"))]
    Connection(std::sync::Arc<identity::IdentityContext>),
}

/// The write-boundary auth gate: source→authority ceiling first (authz), then optional
/// signed source identity (authn) when a trust root is configured.
fn enforce_write_authority(
    auth: &WriteAuth<'_>,
    identity: &WriteIdentity,
) -> Result<(), ops::OpError> {
    enforce_registry_grant(auth)?;
    enforce_source_identity(auth, identity).map_err(ops::OpError::Invalid)
}

/// The error a write that reaches the identity seam without a proven connection identity fails
/// closed with — a daemon-plumbing backstop that must never sign with the daemon's own grant.
const UNAUTHENTICATED_WRITE_ERROR: &str =
    "write reached the identity seam without a proven connection identity";

fn enforce_source_identity(auth: &WriteAuth<'_>, identity: &WriteIdentity) -> Result<(), String> {
    match identity {
        WriteIdentity::Env => {
            let ctx = identity::IdentityContext::from_env()?;
            identity::enforce_write(&ctx, auth, now_millis())
        }
        #[cfg(all(unix, feature = "async-store"))]
        WriteIdentity::Connection(ctx) => identity::enforce_write(ctx, auth, now_millis()),
        WriteIdentity::Unauthenticated => Err(UNAUTHENTICATED_WRITE_ERROR.to_string()),
    }
}

/// Whether a grant's `scope` covers a write subject. Scope is a **subject scope** — the same
/// grammar as signed identity grants: `None` and `"*"` cover every subject; any other value
/// covers exactly the literal `<kind>:<key>` subject it names. Conservative by construction:
/// a malformed scope covers *nothing* (fail closed), never everything, and scope does not
/// restrict predicates — it restricts which subjects a source may write about.
fn scope_covers(scope: Option<&str>, subject: &str) -> bool {
    match scope {
        None => true,
        Some(scope) => scope == "*" || scope == subject,
    }
}

/// The literal subject `source`'s registry grant chain is scoped to, if any: the first
/// non-`"*"` scope found walking the source's grant and its registered issuer chain.
/// `None` means the chain leaves the subject unconstrained (or the source is unregistered).
/// Used by the doctor write-check to pick a probe subject a correctly-scoped source is
/// actually allowed to write about; a hand-edited chain with conflicting literal scopes
/// authorizes nothing anywhere, and returning the first scope simply lets the write gate
/// report that rejection.
fn scoped_probe_subject<'a>(registry: &'a SourceRegistry, source: &str) -> Option<&'a str> {
    let mut visited: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut link = source;
    while visited.insert(link) {
        let grant = registry.sources.get(link)?;
        if let Some(scope) = grant.scope.as_deref()
            && scope != "*"
        {
            return Some(scope);
        }
        link = grant.issuer.as_deref()?;
    }
    None
}

/// The ceiling a **listed** source is granted, or `None` when the source is not in the
/// registry. Unlike [`SourceRegistry::ceiling`] (which returns `Unknown` for both an unlisted
/// source and a source explicitly granted `Unknown`), this distinguishes "not listed" so the
/// write-check can fall back to a signed identity's ceiling before defaulting to `High`.
fn source_registry_ceiling(registry: &SourceRegistry, source: &str) -> Option<AuthorityLevel> {
    registry
        .sources
        .get(source)
        .map(|grant| grant.max_authority)
}

/// The pure decision: reject a write above the source's ceiling, outside its grant's scope,
/// or beyond what the grant's **issuer chain** can delegate. `None` registry is permissive
/// (dev mode); production can disable that path with `DENT8_REQUIRE_AUTHORITY`. Rejection —
/// not silent capping — keeps a laundering attempt visible. An active registry is
/// deny-by-default — an unlisted source's ceiling is `Unknown`, below the lowest requestable
/// level (`Low`), so it is blocked from writing entirely.
///
/// Enforcement semantics (where the domain model was silent, the conservative reading):
///
/// - **Scope** ([`scope_covers`]): a grant scoped to a subject authorizes writes about that
///   subject only; the write's *subject* is checked against every registered link of the
///   issuer chain, so an issuer scoped to X cannot delegate writes outside X.
/// - **Issuer / no self-escalation**: when a grant's `issuer` names another *registered
///   source*, the write must also satisfy that issuer's own grant (ceiling and scope),
///   transitively — an issuer cannot delegate authority it does not hold. An issuer that is
///   not a registered source is an operator-level root recorded for audit; the registry has
///   nothing to rank it against, so the chain grounds out there (the registry file itself is
///   operator-managed config).
/// - **Cycles fail closed**: a self-issued grant or an issuer cycle never grounds out in an
///   operator root, so it authorizes nothing — a grant cannot be the source of its own
///   authority.
fn registry_grant_check(
    registry: Option<&SourceRegistry>,
    auth: &WriteAuth<'_>,
) -> Result<(), ops::OpError> {
    let Some(registry) = registry else {
        return Ok(());
    };
    let source = auth.source;
    let requested = auth.authority;
    // The direct ceiling first, preserving the deny-by-default Unknown for unlisted sources.
    let ceiling = registry.ceiling(source);
    if requested > ceiling {
        return Err(ops::OpError::Rejected(format!(
            "authority ceiling: source {source:?} may assert at most {ceiling}, but requested \
             {requested} (grant it with `dent8 authority add {source} <max>`)"
        )));
    }
    // Then walk the grant and its issuer chain: every registered link must cover the write's
    // subject and hold a ceiling at or above the request.
    let subject = auth.subject();
    let mut visited: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut link: &str = source;
    loop {
        if !visited.insert(link) {
            return Err(ops::OpError::Rejected(format!(
                "authority grant: the issuer chain for source {source:?} cycles at {link:?} — \
                 a grant cannot ground its own authority (no self-escalation); re-issue it \
                 from an operator with `dent8 authority add`"
            )));
        }
        let Some(grant) = registry.sources.get(link) else {
            // An issuer that is not a registered source is an operator-level root recorded
            // for audit — the chain grounds out here. (For the first link this is the
            // unlisted-source case, already rejected above unless requested <= Unknown.)
            return Ok(());
        };
        if !scope_covers(grant.scope.as_deref(), &subject) {
            let via = if link == source {
                String::new()
            } else {
                format!(" (issuing {source:?}'s grant)")
            };
            return Err(ops::OpError::Rejected(format!(
                "authority scope: source {link:?}{via} is scoped to {:?}, which does not \
                 cover write subject {subject:?}",
                grant.scope.as_deref().unwrap_or("*"),
            )));
        }
        // Only reachable on issuer links (the direct ceiling was checked above): an issuer
        // cannot delegate authority above its own ceiling.
        if requested > grant.max_authority {
            return Err(ops::OpError::Rejected(format!(
                "authority ceiling: source {source:?} was granted by issuer {link:?}, whose \
                 own ceiling is {}, but requested {requested} — an issuer cannot delegate \
                 authority it does not hold",
                grant.max_authority
            )));
        }
        let Some(issuer) = grant.issuer.as_deref() else {
            return Ok(());
        };
        link = issuer;
    }
}

// ---- Content-check hook (pluggable external scanner; docs/content-check.md) ----------
//
// The write boundary's *content* gate, mirroring the authority gate above: arbitration
// never reads a fact's `value` text, so a deployment that must catch content-embedded
// attacks (injected imperatives, exfil instructions — eval classes A/F/G/H) composes an
// external scanner in here. dent8 ships no classifier of its own; the configured command
// (LLM Guard, Rebuff, a Lakera/Azure Prompt Shields bridge, …) owns the judgment. See
// `dent8_core::content_check` for the verdict protocol and `docs/content-check.md`.

/// Build the content-check config from the environment, or `None` when no scanner is
/// configured (exact pass-through). Malformed configuration is a loud error, not a silent
/// disable — the operator tried to set a security control.
fn content_check_config() -> Result<Option<content_check::ContentCheckConfig>, String> {
    let raw = match std::env::var("DENT8_CONTENT_CHECK") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("DENT8_CONTENT_CHECK must be valid UTF-8".to_string());
        }
    };
    if raw.trim().is_empty() {
        return Ok(None);
    }
    // Whitespace-split program + args; anything needing quoting belongs in a wrapper script.
    let command: Vec<String> = raw.split_whitespace().map(ToString::to_string).collect();
    let mut config = content_check::ContentCheckConfig::new(command)?;
    if let Ok(millis) = std::env::var("DENT8_CONTENT_CHECK_TIMEOUT_MS") {
        let millis: u64 = millis.trim().parse().map_err(|_| {
            format!("DENT8_CONTENT_CHECK_TIMEOUT_MS must be a millisecond count, got {millis:?}")
        })?;
        config.timeout = Duration::from_millis(millis);
    }
    // DEFAULT fail-closed: a configured scanner going dark must not silently readmit
    // unchecked content. Fail-open is an explicit opt-in (and still flags the admit).
    if env_flag("DENT8_CONTENT_CHECK_FAIL_OPEN")? {
        config.failure_policy = content_check::FailurePolicy::FailOpen;
    }
    Ok(Some(config))
}

/// The write-boundary content gate, run on every batch of candidate events **after**
/// authority enforcement and **before** they are arbitrated, attested, or persisted —
/// the same placement discipline as [`enforce_write_authority`]: every `op_*` write path
/// (CLI commands, `dent8 capture`, the MCP tools, daemon connections) passes its built
/// events through here, so there is no write entry point that skips the scanner. A no-op
/// when no scanner is configured.
fn enforce_content_check(events: &mut [FactEvent]) -> Result<(), ops::OpError> {
    let Some(config) = content_check_config().map_err(ops::OpError::Invalid)? else {
        return Ok(());
    };
    content_check::enforce(&config, events)
        .map_err(|refusal| ops::OpError::Rejected(format!("REJECTED: {refusal}")))
}

/// Content flags on still-believed facts, for `verify` — the same detect-only surfacing as
/// retraction taint: a `taint` verdict (or a fail-open admit) marked the event at write
/// time ([`content_check::content_flag`]); here every non-terminal fact carrying such a
/// mark is listed so the flag is never silently absorbed.
fn content_flag_findings(events: &[FactEvent]) -> Vec<String> {
    let mut streams: std::collections::BTreeMap<FactId, Vec<FactEvent>> =
        std::collections::BTreeMap::new();
    for event in events {
        streams
            .entry(event.fact_id.clone())
            .or_default()
            .push(event.clone());
    }
    let mut findings = Vec::new();
    for (fact, stream) in &streams {
        let Ok(Some(state)) = dent8_store::replay_fact(stream) else {
            continue;
        };
        // Terminal facts are no longer believed; their old flags are history, not findings.
        if state.lifecycle.is_terminal() {
            continue;
        }
        for event in stream {
            if let Some(flag) = content_check::content_flag(event) {
                findings.push(format!(
                    "CONTENT-FLAGGED: {} — {} (scanner: {})",
                    fact.as_str(),
                    flag.reason,
                    flag.scanner
                ));
            }
        }
    }
    findings
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
                    "  (issuer/scope enforced)"
                } else {
                    ""
                };
                format!("{source}  max={}{issuer}{scope}{note}", grant.max_authority)
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
                    "issuer_enforced": true,
                    "scope_enforced": true,
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
                print_json_stdout_with_code(&authority_error_json("authority list", &error), 2)
            }
        },
    }
}

/// Validate an `authority add` up front, so the registry never records a grant the write
/// gate would treat as self-escalation or nonsense. Write-time [`registry_grant_check`]
/// remains the security boundary (the file can be hand-edited); this is the operator UX.
fn validate_authority_grant(
    registry: &SourceRegistry,
    source: &str,
    max_authority: AuthorityLevel,
    issuer: Option<&str>,
    scope: Option<&str>,
) -> Result<(), String> {
    if let Some(scope) = scope
        && scope != "*"
        && CliSubject::from_str(scope).is_err()
    {
        return Err(format!(
            "invalid scope {scope:?}: expected \"*\" or an exact subject <kind>:<key> \
             (e.g. repo:dent8)"
        ));
    }
    let Some(issuer) = issuer else {
        return Ok(());
    };
    if issuer == source {
        return Err(format!(
            "a grant for {source:?} cannot name itself as issuer — a grant cannot ground \
             its own authority (no self-escalation)"
        ));
    }
    // An issuer that is not a registered source is an operator-level root recorded for
    // audit; the registry has nothing to rank it against.
    let mut link = issuer;
    let mut visited: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    loop {
        // The cycle check runs before the registry lookup so the refusal is
        // order-independent: a chain that reaches the grant being added completes a cycle
        // whether or not that grant is already registered — `add a <max> b` then
        // `add b <max> a` must be refused like the reverse order. (The write gate rejects
        // the cycle either way; add-time is where the operator can still fix it.)
        if link == source || !visited.insert(link) {
            return Err(format!(
                "issuer {issuer:?} would create an issuer cycle through {link:?} — a grant \
                 cannot ground its own authority (no self-escalation)"
            ));
        }
        let Some(grant) = registry.sources.get(link) else {
            break;
        };
        if max_authority > grant.max_authority {
            return Err(format!(
                "issuer {link:?} may grant at most {}, but the new grant requests \
                 {max_authority} — an issuer cannot delegate authority it does not hold",
                grant.max_authority
            ));
        }
        if let Some(issuer_scope) = grant.scope.as_deref()
            && issuer_scope != "*"
            && scope != Some(issuer_scope)
        {
            return Err(format!(
                "issuer {link:?} is scoped to {issuer_scope:?}, so the new grant's scope \
                 must be exactly {issuer_scope:?} — an issuer cannot delegate scope it \
                 does not hold"
            ));
        }
        let Some(next) = grant.issuer.as_deref() else {
            break;
        };
        link = next;
    }
    Ok(())
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
                    print_json_stdout_with_code(&authority_error_json("authority add", &error), 2)
                }
            };
        }
    };
    if let Err(error) = validate_authority_grant(&registry, source, max_authority, issuer, scope) {
        return match output {
            CliOutput::Text => {
                eprintln!("{error}");
                2
            }
            CliOutput::Json => {
                print_json_stdout_with_code(&authority_error_json("authority add", &error), 2)
            }
        };
    }
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
            let message = format!("granted {source} a max authority of {max_authority}");
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
                    "issuer_enforced": true,
                    "scope_enforced": true,
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
                print_json_stdout_with_code(&authority_error_json("authority add", &error), 1)
            }
        },
    }
}

/// The registered sources whose issuer chain passes through `source` — the grants a
/// removal of `source` would orphan. Each grant's chain is walked through registered
/// links only, with a visited set, so a hand-edited cyclic registry cannot loop the check.
fn dependent_grants(registry: &SourceRegistry, source: &str) -> Vec<String> {
    registry
        .sources
        .iter()
        .filter(|(name, grant)| {
            name.as_str() != source && issuer_chain_reaches(registry, grant, source)
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// Whether `grant`'s issuer chain reaches `target` through registered links.
fn issuer_chain_reaches(registry: &SourceRegistry, grant: &SourceGrant, target: &str) -> bool {
    let mut visited: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut link = grant.issuer.as_deref();
    while let Some(name) = link {
        if name == target {
            return true;
        }
        if !visited.insert(name) {
            return false;
        }
        link = registry
            .sources
            .get(name)
            .and_then(|grant| grant.issuer.as_deref());
    }
    false
}

/// Emit an authority-command failure on the selected output surface and return `code`.
fn authority_failure(tool: &str, message: &str, code: i32, output: CliOutput) -> i32 {
    match output {
        CliOutput::Text => {
            eprintln!("{message}");
            code
        }
        CliOutput::Json => print_json_stdout_with_code(&authority_error_json(tool, message), code),
    }
}

/// Revoke a grant. Removing a grant that other grants chain their authority through is
/// **refused** without `--force`: the deleted issuer would become an *unregistered* name,
/// which the write gate treats as an operator-level root — so revoking an issuer would
/// silently *loosen* its delegates. With `--force`, revocation cascades down the delegation
/// chain: the dependent grants are removed too, so orphaned delegates authorize nothing
/// (an unlisted source is deny-by-default) until an operator re-parents them with
/// `dent8 authority add`.
fn cmd_authority_remove(source: &str, force: bool, output: CliOutput) -> i32 {
    let mut registry = match load_authority_registry_for_edit() {
        Ok(Some(registry)) => registry,
        Ok(None) => {
            return authority_failure(
                "authority remove",
                "no authority registry to remove from",
                1,
                output,
            );
        }
        Err(error) => return authority_failure("authority remove", &error, 2, output),
    };
    if !registry.sources.contains_key(source) {
        let message = format!("{source} is not in the authority registry");
        return authority_failure("authority remove", &message, 1, output);
    }
    let dependents = dependent_grants(&registry, source);
    if !dependents.is_empty() && !force {
        let message = format!(
            "cannot remove {source}: {} dependent grant(s) chain their authority through it \
             ({}) — deleting the issuer would loosen them to an operator-level root; pass \
             --force to revoke the dependent grant(s) too, then re-parent them with \
             `dent8 authority add <source> <max> [issuer]`",
            dependents.len(),
            dependents.join(", "),
        );
        return authority_failure("authority remove", &message, 2, output);
    }
    registry.sources.remove(source);
    for dependent in &dependents {
        registry.sources.remove(dependent);
    }
    match save_authority_registry(&registry) {
        Ok(()) => {
            let message = if dependents.is_empty() {
                format!("revoked {source}")
            } else {
                format!(
                    "revoked {source} and {} dependent grant(s): {} — re-parent them with \
                     `dent8 authority add`",
                    dependents.len(),
                    dependents.join(", "),
                )
            };
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
                    "also_revoked": dependents,
                    "message": message,
                })),
            }
        }
        Err(error) => authority_failure("authority remove", &error, 1, output),
    }
}

/// The default authority profile shipped out of the box: the natural trust ordering for a
/// repository shared by a human, CI, and coding agents — **human > CI > agent** — so
/// arbitration works without inventing a trust taxonomy first. `canonical` stays reserved
/// for explicit policy (`dent8 authority add`), because contradicting a canonical fact
/// hard-alarms. `dent8 capture` uses the agent tier as its unattributed fallback.
const DEFAULT_AUTHORITY_PROFILE: [(&str, AuthorityLevel); 3] = [
    ("source:human", AuthorityLevel::High),
    ("source:ci", AuthorityLevel::Medium),
    ("source:agent", AuthorityLevel::Low),
];

/// Merge [`DEFAULT_AUTHORITY_PROFILE`] into `registry`. Merge-only: an existing grant for one
/// of the profile sources is **kept**, never downgraded or overwritten — an operator's explicit
/// taxonomy (or a prior `init`) out-ranks the shipped default (`dent8 authority add` still
/// replaces). Returns, per source, whether it was `added` or `kept` and the resulting ceiling.
/// Shared by `dent8 init` (which seeds the profile at bootstrap) and `dent8 authority defaults`.
fn seed_default_authority_profile(
    registry: &mut SourceRegistry,
) -> Vec<(&'static str, &'static str, AuthorityLevel)> {
    let mut entries = Vec::new();
    for (source, max_authority) in DEFAULT_AUTHORITY_PROFILE {
        let action = match registry.sources.entry(source.to_string()) {
            std::collections::btree_map::Entry::Occupied(existing) => {
                ("kept", existing.get().max_authority)
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(SourceGrant {
                    max_authority,
                    issuer: None,
                    scope: None,
                });
                ("added", max_authority)
            }
        };
        entries.push((source, action.0, action.1));
    }
    entries
}

/// `dent8 authority defaults`: seed the shipped profile into the registry via
/// [`seed_default_authority_profile`] (merge-only) and report what was added or kept.
fn cmd_authority_defaults(output: CliOutput) -> i32 {
    let mut registry = match load_authority_registry_for_edit() {
        Ok(registry) => registry.unwrap_or_default(),
        Err(error) => {
            return match output {
                CliOutput::Text => {
                    eprintln!("{error}");
                    2
                }
                CliOutput::Json => print_json_stdout_with_code(
                    &authority_error_json("authority defaults", &error),
                    2,
                ),
            };
        }
    };
    let entries = seed_default_authority_profile(&mut registry);
    match save_authority_registry(&registry) {
        Ok(()) => {
            let lines = entries
                .iter()
                .map(|(source, action, max)| format!("  {action} {source}  max={max}"))
                .collect::<Vec<_>>()
                .join("\n");
            let message = format!(
                "seeded the default authority profile (human > CI > agent) in {}:\n{lines}\n\
                 the registry is now deny-by-default: unlisted sources are blocked until \
                 granted with `dent8 authority add`.",
                authority_registry_path()
            );
            match output {
                CliOutput::Text => {
                    println!("{message}");
                    0
                }
                CliOutput::Json => print_json_stdout(&serde_json::json!({
                    "status": "ok",
                    "tool": "authority defaults",
                    "path": authority_registry_path(),
                    "profile": entries
                        .iter()
                        .map(|(source, action, max)| {
                            serde_json::json!({
                                "source": source,
                                "max_authority": max.name(),
                                "action": action,
                            })
                        })
                        .collect::<Vec<_>>(),
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
                print_json_stdout_with_code(&authority_error_json("authority defaults", &error), 1)
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
/// invariant the writer is supposed to maintain — at most one fresh believed fact per
/// unique predicate — so a torn write or external edit that orphaned a believed fact is
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
        let event: FactEvent = serde_json::from_str(line)
            .map_err(|error| format!("{path}:{}: corrupt event: {error}", line_no + 1))?;
        events.push(event);
    }
    let store = InMemoryEventStore::from_trusted_events(events)
        .map_err(|error| format!("cannot load {path}: {error}"))?;
    validate_unique_log(&store, now_millis()).map_err(|error| format!("{path}: {error}"))?;
    Ok(store)
}

/// The event log as a raw, ordered `Vec<FactEvent>` — the same global append order
/// [`load_store`] reads, but **without** the trusted-reload integrity gate
/// (`validate_unique_log`). The witness must be the *authoritative* tamper oracle: it has to
/// render its own `TAMPER`/`ROLLBACK` verdict even on a log the integrity gate would reject,
/// rather than be preempted by that gate's error. A genuinely unparseable line is still a hard
/// error (nothing to witness).
fn load_raw_events(path: &str) -> Result<Vec<FactEvent>, String> {
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
        let event: FactEvent = serde_json::from_str(line)
            .map_err(|error| format!("{path}:{}: corrupt event: {error}", line_no + 1))?;
        events.push(event);
    }
    Ok(events)
}

/// Raw ordered backend log for the witness: connect + self-migrate + scan, with **no**
/// integrity gate (see [`load_raw_events`]). Backend-agnostic via [`connect_backend`].
#[cfg(feature = "async-store")]
fn backend_scan_raw(url: &str) -> Result<Vec<FactEvent>, String> {
    use dent8_store::EventFilter;
    store_runtime()?.block_on(async {
        let store = connect_backend(url).await?;
        store
            .scan_events(&EventFilter::default())
            .await
            .map_err(|error| error.to_string())
    })
}

/// On-demand integrity check: re-verify the hash chain and the per-subject lineage.
/// Backend-aware. For **Postgres** it re-verifies the *stored* global chain (real
/// tamper-evidence — a mutated stored event is caught); for the **file dev store** it
/// re-folds and checks structural integrity (tamper-*resistance* over the file log is the
/// witness's job, not this).
/// The result of re-checking persisted write attestations (ADR 0013) during `verify`.
struct AttestationSummary {
    /// Events carrying an attestation.
    attested: usize,
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
    /// attestations verify (with entitlement counts when a grant log is present).
    fn ok_clause(&self) -> String {
        if self.attested == 0 {
            String::new()
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
fn check_attestations(events: &[FactEvent]) -> AttestationSummary {
    let mut summary = AttestationSummary {
        attested: 0,
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
/// let the caller report them as present-but-unverified rather than silently reporting "OK".
/// Unearned-supersession **advisories** (ADR 0007/0015/0017), grouped from a flat event set
/// by fact stream. Unlike lineage breaks, retraction taint, or a broken attestation, these
/// are **not** integrity failures — the base firewall admitted the supersession (the
/// earned-supersession gate is opt-in and off by default). They surface a replacement that
/// did not out-*entrench* what it displaced (a downgraded authority, or weaker earned
/// entrenchment = corroboration + survived challenges at equal authority), so `verify` reports
/// them as advisories and stays `OK`. Turn on `DENT8_ENTRENCHMENT_GATE` to reject them at
/// write time instead.
fn unearned_supersession_advisories(events: &[FactEvent]) -> Vec<String> {
    use std::collections::BTreeMap;
    let mut streams: BTreeMap<(String, String, String), Vec<FactEvent>> = BTreeMap::new();
    for event in events {
        streams
            .entry((
                event.subject.kind().to_string(),
                event.subject.key().to_string(),
                event.predicate.as_str().to_string(),
            ))
            .or_default()
            .push(event.clone());
    }
    let mut out = Vec::new();
    for ((kind, key, predicate), stream) in streams {
        let Ok(projection) = replay_subject(&stream) else {
            continue;
        };
        for unearned in projection.unearned_supersessions() {
            let detail = match unearned {
                UnearnedSupersession::AuthorityDowngrade {
                    superseded,
                    by,
                    incumbent,
                    challenger,
                } => format!(
                    "{superseded} replaced by {by} at lower authority ({incumbent} -> {challenger})",
                ),
                UnearnedSupersession::WeakerEntrenchment {
                    superseded,
                    by,
                    incumbent_entrenchment,
                    challenger_entrenchment,
                } => format!(
                    "{superseded} replaced by {by} with weaker earned entrenchment \
                     ({challenger_entrenchment} < {incumbent_entrenchment})",
                ),
            };
            out.push(format!(
                "ADVISORY: {kind}:{key} {predicate} — unearned supersession: {detail}"
            ));
        }
    }
    out
}

/// Append an unearned-supersession advisory block to an OK `verify` report, if any. Kept
/// out of the failure path: advisories never flip `verify` to non-zero.
fn append_advisories(report: String, advisories: &[String]) -> String {
    if advisories.is_empty() {
        return report;
    }
    format!(
        "{report}\n{} unearned-supersession advisory(ies) (admitted; enable \
         DENT8_ENTRENCHMENT_GATE to reject at write time):\n  {}",
        advisories.len(),
        advisories.join("\n  ")
    )
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
        if let Ok(projection) = replay_subject(&events) {
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
    // Retraction taint (ADR 0010): a still-believed fact deriving from a retracted/expired
    // source is surviving poison — flag it across all subjects.
    let all_events = store
        .scan_events(&EventFilter::default())
        .map_err(|error| error.to_string())?;
    for taint in tainted_facts(&all_events).map_err(|error| error.to_string())? {
        issues.push(format!(
            "TAINTED: {} derives from {} (now {:?})",
            taint.fact.as_str(),
            taint.root.as_str(),
            taint.root_lifecycle
        ));
    }
    // Content-check flags: a still-believed fact the configured scanner admitted-but-marked
    // (`taint` verdict, or a fail-open admit) is surfaced like retraction taint.
    issues.extend(content_flag_findings(&all_events));
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
    let report = format!(
        "OK: {} event(s) across {} subject(s) — STRUCTURAL integrity holds (uniqueness + \
         lineage intact, no retraction taint or content-check flags, all events \
         canonicalize){}. This does NOT \
         detect a content edit to *unattested* events: the file dev store keeps no stored \
         hash to compare against — use `dent8 witness verify` (or the Postgres backend) for \
         tamper-detection.",
        store.len(),
        subjects.len(),
        attestations.ok_clause()
    );
    Ok(append_advisories(
        report,
        &unearned_supersession_advisories(&all_events),
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
        // Retraction taint (ADR 0010): surviving poison — a believed fact deriving from a
        // retracted/expired source.
        let tainted = tainted_facts(&events).map_err(|error| error.to_string())?;
        let mut lines: Vec<String> = tainted
            .iter()
            .map(|taint| {
                format!(
                    "TAINTED: {} derives from {} (now {:?})",
                    taint.fact.as_str(),
                    taint.root.as_str(),
                    taint.root_lifecycle
                )
            })
            .collect();
        // Content-check flags: surfaced like retraction taint (see `content_flag_findings`).
        lines.extend(content_flag_findings(&events));
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
        let report = format!(
            "OK: {} event(s) — the stored global hash chain re-verifies, no retraction taint \
             or content-check flags{}. \
             (Tamper-resistance needs an external operated witness.)",
            events.len(),
            attestations.ok_clause()
        );
        Ok(append_advisories(
            report,
            &unearned_supersession_advisories(&events),
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
    // Unearned-supersession advisories ride the OK report (they never fail verify); surface
    // them as a structured array so a monitor need not parse prose.
    let advisories = report
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("ADVISORY: "))
        .map(str::to_string)
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": if ok { Status::Ok.as_str() } else { Status::IntegrityIssues.as_str() },
        "tool": "verify",
        "ok": ok,
        "summary": first_line(report),
        "report": report,
        "findings": findings,
        "advisories": advisories,
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

/// Run the adversarial corpus and the external integrity-axis comparison (modeled
/// Mem0 / Zep-Graphiti resolution). Exits non-zero if a demonstrative scenario regresses
/// or the comparison frozen tally drifts.
fn cmd_eval(output: CliOutput) -> i32 {
    let results = dent8_evals::run_corpus();
    let demonstrated = results
        .iter()
        .filter(|result| result.demonstrates_defense())
        .count();
    let comparison = dent8_evals::run_comparison();
    let comparison_ok = dent8_evals::comparison_tally_ok(&comparison);
    let exit_code = i32::from(demonstrated != results.len() || !comparison_ok);
    match output {
        CliOutput::Text => {
            println!(
                "dent8 adversarial corpus — {demonstrated}/{} scenarios demonstrate the firewall's \
                 defense:\nthe firewall blocks every attack in this demonstrative corpus that a \
                 recency-only baseline (newest-write-wins, no authority/dependency) falls to.\n",
                results.len()
            );
            print!("{}", dent8_evals::summary_table());
            println!(
                "\nExternal integrity comparison (modeled peer semantics — not live APIs):\n\
                 dent8 vs Zep/Graphiti-style recency vs Mem0-style mutate-in-place on the same \
                 integrity axes.\n"
            );
            print!(
                "{}",
                dent8_evals::comparison_summary_table_from(&comparison)
            );
            if !comparison_ok {
                eprintln!(
                    "comparison tally regressed (expected dent8 holds all axes; peers fall on \
                     attack axes; all three admit legitimate supersession)"
                );
            }
            exit_code
        }
        CliOutput::Json => {
            print_json_stdout_with_code(&eval_json(&results, demonstrated, &comparison), exit_code)
        }
    }
}

fn eval_json(
    results: &[dent8_evals::AttackResult],
    demonstrated: usize,
    comparison: &[dent8_evals::ComparisonRow],
) -> serde_json::Value {
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
    let axes = comparison
        .iter()
        .map(|row| {
            serde_json::json!({
                "axis": row.axis,
                "family": row.family,
                "property": row.property,
                "dent8_holds": row.dent8_holds,
                "zep_holds": row.zep_holds,
                "mem0_holds": row.mem0_holds,
                "differentiates": row.differentiates(),
            })
        })
        .collect::<Vec<_>>();
    let comparison_ok = dent8_evals::comparison_tally_ok(comparison);
    let status = if demonstrated == results.len() && comparison_ok {
        "ok"
    } else {
        "failed"
    };
    serde_json::json!({
        "status": status,
        "tool": "eval",
        "scenario_count": results.len(),
        "demonstrated_count": demonstrated,
        "scenarios": scenarios,
        "comparison": {
            "ok": comparison_ok,
            "axis_count": comparison.len(),
            "dent8_hold_count": comparison.iter().filter(|r| r.dent8_holds).count(),
            "axes": axes,
        },
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
                CliOutput::Json => print_json_stdout_with_code(&export_error_json(out, &error), 2),
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
                CliOutput::Json => {
                    print_json_stdout_with_code(&export_error_json(out, &message), 1)
                }
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
                CliOutput::Json => {
                    print_json_stdout_with_code(&export_error_json(out, &message), 1)
                }
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
                CliOutput::Json => {
                    print_json_stdout_with_code(&export_error_json(out, &message), 1)
                }
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
        CliOutput::Json => print_json_stdout_with_code(&export_error_json(out, message), 2),
    }
}

#[cfg(feature = "export")]
fn export_message(out: &str, event_count: usize) -> String {
    format!(
        "exported {event_count} event(s) to {out}\n  query it with DuckDB, e.g.:\n    \
         duckdb -c \"SELECT source, count(*) AS writes FROM '{out}' GROUP BY 1 ORDER BY 2 DESC\"\n    \
         duckdb -c \"SELECT fact_id, UNNEST(derived_from) AS source_fact FROM '{out}' WHERE derived_from IS NOT NULL\"",
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

/// The next event/fact sequence: one past the **highest** `event:{n}` id actually
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

/// Reserve the first numeric suffix for `count` new `event:{n}` ids. File-backed dev logs derive
/// it from the trusted snapshot; async backends reserve it from the database so concurrent
/// writers do not sign the same event id. Reserved async ids are unique, not gap-free.
pub(crate) fn reserve_event_seq(store: &InMemoryEventStore, count: usize) -> Result<usize, String> {
    if count == 0 {
        return Err("cannot reserve zero event ids".to_string());
    }
    #[cfg(feature = "async-store")]
    if let Some(url) = store_url() {
        return backend_reserve_event_ids(&url, count).and_then(|seq| {
            usize::try_from(seq).map_err(|_| format!("reserved event id {seq} exceeds usize"))
        });
    }
    #[cfg(not(feature = "async-store"))]
    if store_url().is_some() {
        return Err(
            "DENT8_STORE_URL is set but this build has no async backend — \
             rebuild with `--features postgres` (or another backend)"
                .to_string(),
        );
    }
    Ok(next_seq(store))
}

/// Reject a log that already violates per-predicate uniqueness (more than one *fresh*
/// believed fact for a `unique` predicate). A legitimate stale + fresh pair is allowed
/// (only one is fresh); two fresh believed facts signal corruption (a torn write or an
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
        let subject = replay_subject(&store.scan_events(&filter).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        // A supersession whose replacement is *missing* (dangling) or *cyclic* silently
        // drops the fact — the symmetric corruption to a duplicated belief, which the
        // >1-fresh check below never catches (0 fresh). Flag only those. NOT
        // `SupersededByInvalidated`: a successor that was legitimately retracted or expired
        // (e.g. assert -> supersede -> retract) is a valid history, not corruption.
        if let Some(issue) = subject.lineage_issues().into_iter().find(|issue| {
            matches!(
                issue,
                LineageIssue::DanglingSupersession { .. } | LineageIssue::SupersessionCycle { .. }
            )
        }) {
            return Err(format!(
                "corrupt log: {} subject has a broken supersession lineage ({issue:?}) \
                 (possible external edit)",
                event.subject.kind()
            ));
        }
        let fresh: Vec<_> = subject
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
            // A *surfaced* conflict (ADR 0009) is exactly the `Contested` facts plus the
            // contradictors they name; everything in that set is audited. Any *other*
            // believed fact is silent duplication — corruption a single contradiction must
            // not launder. So account for the contested facts + their contradictors, and
            // reject if any believed fact is left unaccounted-for.
            let mut accounted: Vec<&FactId> = Vec::new();
            for s in &group {
                if s.lifecycle == FactLifecycle::Contested {
                    accounted.push(&s.fact_id);
                    accounted.extend(s.contradicted_by.iter());
                }
            }
            let unaccounted = group
                .iter()
                .filter(|s| !accounted.contains(&&s.fact_id))
                .count();
            if unaccounted > 0 {
                return Err(format!(
                    "corrupt log: {}.{} has {unaccounted} fresh believed fact(s) not \
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

/// The outcome of a durable append. `Conflict` is **retryable** write contention (a duplicate
/// event id from a direct/legacy writer, or a backend lock held past timeout) that a
/// fresh-snapshot retry may resolve; every other failure is terminal. The file dev store is
/// single-writer and never conflicts.
enum WriteError {
    #[cfg_attr(not(feature = "async-store"), allow(dead_code))]
    Conflict(String),
    Other(String),
}

/// Append admitted events to the durable log as JSON lines in a **single write** so a
/// multi-event operation (e.g. a supersession's replacement + supersession events) lands
/// all-or-nothing at the file boundary. This is best-effort file atomicity for the dev
/// store; true transactional atomicity belongs to the async backends.
fn append_events(
    path: &str,
    events: &mut [FactEvent],
    identity: &WriteIdentity,
) -> Result<(), WriteError> {
    use std::io::Write;
    // Sign the write attestations (ADR 0013) at this choke point — after every op-level
    // mutation, immediately before persistence — so each signature covers exactly the stored
    // content and the append's hash chain covers the attestation.
    attest_events(events, identity).map_err(WriteError::Other)?;
    // An async backend commits the whole operation (assert / supersede / retract / contradict)
    // as one transaction via `append_many`; the file store just appends the lines. (A build
    // with no async backend that reaches here with a store URL set already errored in
    // `load_store`.)
    #[cfg(feature = "async-store")]
    if let Some(url) = store_url() {
        let refs: Vec<&FactEvent> = events.iter().collect();
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
fn attest_events(events: &mut [FactEvent], identity: &WriteIdentity) -> Result<(), String> {
    match identity {
        WriteIdentity::Env => {
            let ctx = identity::IdentityContext::from_env()?;
            identity::attest_events(&ctx, events).map(|_| ())
        }
        #[cfg(all(unix, feature = "async-store"))]
        WriteIdentity::Connection(ctx) => identity::attest_events(ctx, events).map(|_| ()),
        WriteIdentity::Unauthenticated => Err(UNAUTHENTICATED_WRITE_ERROR.to_string()),
    }
}

/// Without the `identity` feature there is no signer. `enforce_source_identity` has already
/// failed closed if identity is *configured* in this build (or the write is from an
/// unauthenticated daemon connection), so reaching here means dev mode — events are simply
/// written unattested.
/// The async-backend URL (dispatched by scheme). `None` selects the file dev store. Always
/// available (just env reads plus discovery), so the file-only build can still detect "a store
/// URL is set but no backend is compiled in."
///
/// Resolution: the process-env `DENT8_STORE_URL` wins (the escape hatch); otherwise a
/// `DENT8_STORE_URL` from the discovered enclosing-repo `.dent8/env` is honored, so an unsourced
/// run in a repo with a SQLite/Postgres backend uses that backend instead of forking a parallel
/// `memory.jsonl` inside `.dent8/`. A set-but-empty (or whitespace-only) value counts as
/// **unset** at each layer; the value is trimmed so a quoted/padded entry still dispatches.
fn store_url() -> Option<String> {
    if let Some(url) = std::env::var("DENT8_STORE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        return Some(url);
    }
    // Explicit `DENT8_LOG` selects the file-dev log for this process. Do not fall through to a
    // discovered `.dent8/env` `DENT8_STORE_URL` (e.g. dogfood SQLite), or hooks/tests that set
    // only `DENT8_LOG` silently verify the wrong store.
    if std::env::var("DENT8_LOG")
        .ok()
        .is_some_and(|value| !value.trim().is_empty())
    {
        return None;
    }
    discover_store().and_then(|store| store.env_value("DENT8_STORE_URL"))
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
/// `BEGIN IMMEDIATE` + `busy_timeout`), so concurrent writers wait rather than corrupt. CLI/MCP
/// event ids are reserved from the backend before signing, so duplicate-id conflicts should only
/// come from direct/legacy writers; lock contention can still be retryable.
#[cfg(feature = "async-store")]
fn backend_append(url: &str, events: &[&FactEvent]) -> Result<(), WriteError> {
    use dent8_store::StoreError;
    let owned: Vec<FactEvent> = events.iter().map(|&event| event.clone()).collect();
    store_runtime().map_err(WriteError::Other)?.block_on(async {
        let store = connect_backend(url).await.map_err(WriteError::Other)?;
        store
            .append_many(owned)
            .await
            .map_err(|error| match error {
                // A duplicate id or long-held write lock can be retried by re-running the op
                // against a fresh snapshot and reserving a fresh id range.
                StoreError::Conflict(message) => WriteError::Conflict(message),
                other => WriteError::Other(other.to_string()),
            })?;
        Ok(())
    })
}

#[cfg(feature = "async-store")]
fn backend_reserve_event_ids(url: &str, count: usize) -> Result<u64, String> {
    let count = u32::try_from(count)
        .map_err(|_| format!("cannot reserve {count} event ids in one operation"))?;
    store_runtime()?.block_on(async {
        let store = connect_backend(url).await?;
        store
            .reserve_event_ids(count)
            .await
            .map_err(|error| error.to_string())
    })
}

/// The version of dent8's JSON output shape, stamped on every `--output json` object and every
/// MCP `structuredContent`, so a consumer can branch when the (pre-1.0, still-evolving) shape
/// changes. One shared constant across both surfaces.
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Stamp `schema_version` onto a top-level JSON object; a non-object value passes through
/// unchanged. Applied at the CLI JSON choke points so every `--output json` payload carries it.
pub(crate) fn stamp_schema_version(value: &serde_json::Value) -> serde_json::Value {
    let mut value = value.clone();
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "schema_version".to_string(),
            serde_json::json!(SCHEMA_VERSION),
        );
    }
    value
}

fn print_json_stdout(value: &serde_json::Value) -> i32 {
    print_json_stdout_with_code(value, 0)
}

/// Print a JSON payload to **stdout** with the given process exit code. Every `--output json`
/// result — success *and* error — goes here, so a machine consumer reads one stream and branches
/// on the payload's `status` (and the exit code), rather than having to merge stdout and stderr.
/// Text-mode errors still go to stderr via `present`/`eprintln!`.
fn print_json_stdout_with_code(value: &serde_json::Value, code: i32) -> i32 {
    println!(
        "{}",
        serde_json::to_string_pretty(&stamp_schema_version(value))
            .expect("CLI JSON output should serialize")
    );
    code
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn assert_event(
    event_id: &str,
    fact_id: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    value: &str,
    source: &str,
    authority: AuthorityLevel,
) -> FactEvent {
    let mut event = base(
        event_id,
        fact_id,
        subject_kind,
        subject_key,
        predicate,
        source,
        authority,
    );
    event.kind = FactEventKind::Asserted;
    event.value = Some(FactValue::Text(value.to_string()));
    event
}

#[cfg(test)]
fn base(
    event_id: &str,
    fact_id: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    source: &str,
    authority: AuthorityLevel,
) -> FactEvent {
    FactEvent {
        event_id: FactEventId::new(event_id).expect("event id"),
        fact_id: FactId::new(fact_id).expect("fact id"),
        kind: FactEventKind::Asserted,
        subject: Subject::new(subject_kind, subject_key).expect("subject"),
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
        valid_to: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_ms_accepts_unit_suffixes() {
        assert_eq!(parse_duration_ms("45s"), Ok(45_000));
        assert_eq!(parse_duration_ms("30m"), Ok(1_800_000));
        assert_eq!(parse_duration_ms("12h"), Ok(43_200_000));
        assert_eq!(parse_duration_ms("90d"), Ok(90 * 86_400_000));
        assert_eq!(parse_duration_ms("500ms"), Ok(500));
        // Surrounding whitespace is tolerated.
        assert_eq!(parse_duration_ms(" 1d "), Ok(86_400_000));
    }

    #[test]
    fn parse_duration_ms_rejects_bad_input() {
        // A bare number has no unit and must not silently mean milliseconds.
        assert!(parse_duration_ms("90").is_err());
        assert!(parse_duration_ms("").is_err());
        assert!(parse_duration_ms("d").is_err());
        assert!(parse_duration_ms("10y").is_err());
        assert!(parse_duration_ms("abc").is_err());
    }

    #[test]
    fn parse_duration_ms_matches_the_retention_ceiling() {
        // `90d` is exactly the 90-day default retention ceiling, so a fact written at that TTL
        // sits at the ceiling and one past it is rejected on write.
        assert_eq!(
            parse_duration_ms("90d"),
            Ok(dent8_store::registry::DEFAULT_MAX_TTL_MS)
        );
    }

    fn grant(
        max_authority: AuthorityLevel,
        issuer: Option<&str>,
        scope: Option<&str>,
    ) -> SourceGrant {
        SourceGrant {
            max_authority,
            issuer: issuer.map(str::to_string),
            scope: scope.map(str::to_string),
        }
    }

    fn registry_of(entries: &[(&str, SourceGrant)]) -> SourceRegistry {
        let mut registry = SourceRegistry::default();
        for (source, grant) in entries {
            registry
                .sources
                .insert((*source).to_string(), grant.clone());
        }
        registry
    }

    fn write(source: &'static str, level: AuthorityLevel) -> WriteAuth<'static> {
        WriteAuth::new("repo", "app", level, source)
    }

    #[test]
    fn the_authority_ceiling_rejects_writes_above_a_source_grant() {
        let registry = registry_of(&[("source:owner", grant(AuthorityLevel::High, None, None))]);
        let check = |source, level| registry_grant_check(Some(&registry), &write(source, level));

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
        assert!(
            registry_grant_check(None, &write("source:web-scrape", AuthorityLevel::Canonical))
                .is_ok()
        );
    }

    #[test]
    fn a_scoped_grant_rejects_writes_outside_its_subject() {
        let registry = registry_of(&[
            (
                "source:scoped",
                grant(AuthorityLevel::High, None, Some("repo:app")),
            ),
            ("source:star", grant(AuthorityLevel::High, None, Some("*"))),
            (
                "source:malformed",
                grant(AuthorityLevel::High, None, Some("not a subject")),
            ),
        ]);
        let check = |source: &'static str, kind, key| {
            registry_grant_check(
                Some(&registry),
                &WriteAuth::new(kind, key, AuthorityLevel::High, source),
            )
        };

        // The scoped subject is admitted; any other subject is rejected.
        assert!(check("source:scoped", "repo", "app").is_ok());
        let outside = check("source:scoped", "repo", "other")
            .expect_err("a write outside the grant scope must be rejected");
        assert!(
            outside.message().contains("authority scope"),
            "{}",
            outside.message()
        );
        assert!(matches!(
            check("source:scoped", "person", "alice"),
            Err(ops::OpError::Rejected(_))
        ));
        // "*" covers everything, like an absent scope.
        assert!(check("source:star", "person", "alice").is_ok());
        // A malformed scope covers nothing (fail closed), never everything.
        assert!(matches!(
            check("source:malformed", "repo", "app"),
            Err(ops::OpError::Rejected(_))
        ));
    }

    #[test]
    fn an_issuer_chain_caps_delegated_authority_and_scope() {
        let registry = registry_of(&[
            (
                "source:lead",
                grant(AuthorityLevel::Medium, None, Some("repo:app")),
            ),
            (
                "source:bot",
                grant(AuthorityLevel::High, Some("source:lead"), None),
            ),
            (
                "source:rooted",
                grant(AuthorityLevel::High, Some("operator"), None),
            ),
        ]);
        let check = |auth: &WriteAuth<'_>| registry_grant_check(Some(&registry), auth);

        // Within the issuer's own ceiling and scope the delegated grant works.
        assert!(check(&write("source:bot", AuthorityLevel::Medium)).is_ok());
        assert!(check(&write("source:bot", AuthorityLevel::Low)).is_ok());
        // Above the issuer's own ceiling is rejected even though the grant says High:
        // an issuer cannot delegate authority it does not hold.
        let escalated = check(&write("source:bot", AuthorityLevel::High))
            .expect_err("delegation above the issuer's ceiling must be rejected");
        assert!(
            escalated.message().contains("source:lead"),
            "{}",
            escalated.message()
        );
        // The issuer's scope constrains the delegate too.
        let outside = check(&WriteAuth::new(
            "repo",
            "other",
            AuthorityLevel::Low,
            "source:bot",
        ))
        .expect_err("delegation outside the issuer's scope must be rejected");
        assert!(
            outside.message().contains("authority scope"),
            "{}",
            outside.message()
        );
        // An issuer that is not a registered source is an operator-level root: the chain
        // grounds out there and the grant's own ceiling governs.
        assert!(check(&write("source:rooted", AuthorityLevel::High)).is_ok());
    }

    #[test]
    fn issuer_cycles_and_self_issuance_fail_closed() {
        let registry = registry_of(&[
            (
                "source:self",
                grant(AuthorityLevel::High, Some("source:self"), None),
            ),
            (
                "source:a",
                grant(AuthorityLevel::High, Some("source:b"), None),
            ),
            (
                "source:b",
                grant(AuthorityLevel::High, Some("source:a"), None),
            ),
        ]);
        for source in ["source:self", "source:a", "source:b"] {
            let error = registry_grant_check(
                Some(&registry),
                &WriteAuth::new("repo", "app", AuthorityLevel::Low, source),
            )
            .expect_err("a cyclic issuer chain must authorize nothing");
            assert!(
                error.message().contains("no self-escalation"),
                "{}",
                error.message()
            );
        }
    }

    #[test]
    fn authority_add_rejects_self_escalating_grants_up_front() {
        let registry = registry_of(&[(
            "source:lead",
            grant(AuthorityLevel::Medium, None, Some("repo:app")),
        )]);

        // A grant above its registered issuer's ceiling is refused.
        let error = validate_authority_grant(
            &registry,
            "source:bot",
            AuthorityLevel::High,
            Some("source:lead"),
            None,
        )
        .expect_err("delegating above the issuer ceiling must be rejected");
        assert!(error.contains("cannot delegate"), "{error}");
        // A grant broader than its registered issuer's scope is refused.
        let error = validate_authority_grant(
            &registry,
            "source:bot",
            AuthorityLevel::Low,
            Some("source:lead"),
            Some("*"),
        )
        .expect_err("delegating outside the issuer scope must be rejected");
        assert!(error.contains("scoped to"), "{error}");
        // Self-issuance is refused.
        let error = validate_authority_grant(
            &registry,
            "source:bot",
            AuthorityLevel::Low,
            Some("source:bot"),
            None,
        )
        .expect_err("self-issuance must be rejected");
        assert!(error.contains("no self-escalation"), "{error}");
        // A malformed scope is refused (it would cover nothing at write time).
        let error =
            validate_authority_grant(&registry, "source:bot", AuthorityLevel::Low, None, Some(""))
                .expect_err("a malformed scope must be rejected");
        assert!(error.contains("invalid scope"), "{error}");
        // The valid shape passes: within the issuer's ceiling, matching its scope.
        assert!(
            validate_authority_grant(
                &registry,
                "source:bot",
                AuthorityLevel::Low,
                Some("source:lead"),
                Some("repo:app"),
            )
            .is_ok()
        );
        // An unregistered issuer is an operator root: no delegation constraint applies.
        assert!(
            validate_authority_grant(
                &registry,
                "source:bot",
                AuthorityLevel::Canonical,
                Some("operator"),
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn authority_add_refuses_an_issuer_cycle_in_both_insertion_orders() {
        // a already names b as issuer; adding b issued by a completes the cycle...
        let registry = registry_of(&[(
            "source:a",
            grant(AuthorityLevel::High, Some("source:b"), None),
        )]);
        let error = validate_authority_grant(
            &registry,
            "source:b",
            AuthorityLevel::High,
            Some("source:a"),
            None,
        )
        .expect_err("completing an a<->b cycle must be refused");
        assert!(error.contains("issuer cycle"), "{error}");

        // ...and the reverse insertion order is refused the same way.
        let registry = registry_of(&[(
            "source:b",
            grant(AuthorityLevel::High, Some("source:a"), None),
        )]);
        let error = validate_authority_grant(
            &registry,
            "source:a",
            AuthorityLevel::High,
            Some("source:b"),
            None,
        )
        .expect_err("completing a b<->a cycle must be refused");
        assert!(error.contains("issuer cycle"), "{error}");
    }

    #[test]
    fn dependent_grants_walks_issuer_chains_transitively() {
        let registry = registry_of(&[
            ("source:lead", grant(AuthorityLevel::High, None, None)),
            (
                "source:bot",
                grant(AuthorityLevel::Medium, Some("source:lead"), None),
            ),
            (
                "source:sub",
                grant(AuthorityLevel::Low, Some("source:bot"), None),
            ),
            ("source:other", grant(AuthorityLevel::High, None, None)),
        ]);
        // Direct and transitive delegates both depend on the lead...
        assert_eq!(
            dependent_grants(&registry, "source:lead"),
            vec!["source:bot".to_string(), "source:sub".to_string()]
        );
        // ...an unrelated grant depends on nothing, and a leaf has no dependents.
        assert!(dependent_grants(&registry, "source:other").is_empty());
        assert!(dependent_grants(&registry, "source:sub").is_empty());
        // A hand-edited cyclic chain must not loop the check.
        let cyclic = registry_of(&[
            (
                "source:a",
                grant(AuthorityLevel::High, Some("source:b"), None),
            ),
            (
                "source:b",
                grant(AuthorityLevel::High, Some("source:a"), None),
            ),
        ]);
        assert!(dependent_grants(&cyclic, "source:other").is_empty());
        assert_eq!(
            dependent_grants(&cyclic, "source:a"),
            vec!["source:b".to_string()]
        );
    }

    #[test]
    fn scoped_probe_subject_finds_the_grant_chains_literal_scope() {
        let registry = registry_of(&[
            (
                "source:lead",
                grant(AuthorityLevel::High, None, Some("repo:app")),
            ),
            (
                "source:bot",
                grant(AuthorityLevel::Medium, Some("source:lead"), None),
            ),
            ("source:star", grant(AuthorityLevel::High, None, Some("*"))),
            ("source:open", grant(AuthorityLevel::High, None, None)),
            (
                "source:cyclic",
                grant(AuthorityLevel::High, Some("source:cyclic"), Some("*")),
            ),
        ]);
        // A directly scoped grant pins the probe subject...
        assert_eq!(
            scoped_probe_subject(&registry, "source:lead"),
            Some("repo:app")
        );
        // ...and so does a scope inherited through the issuer chain.
        assert_eq!(
            scoped_probe_subject(&registry, "source:bot"),
            Some("repo:app")
        );
        // Wildcard, absent scope, unregistered sources, and cycles leave it unconstrained.
        assert_eq!(scoped_probe_subject(&registry, "source:star"), None);
        assert_eq!(scoped_probe_subject(&registry, "source:open"), None);
        assert_eq!(scoped_probe_subject(&registry, "source:unknown"), None);
        assert_eq!(scoped_probe_subject(&registry, "source:cyclic"), None);
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
        assert!(read_annotation(FactLifecycle::Active, true, false).is_empty());
        // An Active fact past its TTL is flagged stale (the T4 read-surface verdict).
        assert!(read_annotation(FactLifecycle::Active, false, false).contains("stale"));
        assert!(read_annotation(FactLifecycle::Active, false, true).contains("not yet valid"));
        // A terminal fact is flagged no-longer-believed...
        assert!(
            read_annotation(FactLifecycle::Superseded, true, false).contains("no longer believed")
        );
        // ...and that verdict wins even if it is also stale.
        assert!(
            read_annotation(FactLifecycle::Retracted, false, false).contains("no longer believed")
        );
    }

    /// A durable log with a hole at `event:2` — a line lost to a torn write or to manual /
    /// tool log surgery. The highest id present (`3`) and the line-count (`3`) coincide,
    /// which is exactly the case the old `seq = store.len()` got wrong.
    fn gapped_log() -> Vec<FactEvent> {
        vec![
            assert_event(
                "event:0",
                "fact:repo:a:database:0",
                "repo",
                "a",
                "database",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ),
            assert_event(
                "event:1",
                "fact:repo:b:lang:1",
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
                "fact:repo:c:ci:3",
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
            &format!("fact:repo:a:database:{seq}"),
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
            &format!("fact:repo:a:database:{buggy_seq}"),
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
        let incumbents = vec![FactId::new("fact:repo:a:database:0").expect("fact id")];
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
