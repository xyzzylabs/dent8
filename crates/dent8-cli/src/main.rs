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

mod mcp;
#[cfg(feature = "witness")]
mod witness;

fn main() {
    let code = run(std::env::args().skip(1));
    std::process::exit(code);
}

#[allow(clippy::too_many_lines)] // a flat command-dispatch table; splitting it would obscure it
fn run(args: impl IntoIterator<Item = String>) -> i32 {
    let args = args.into_iter().collect::<Vec<_>>();
    match args.as_slice() {
        [] => {
            print_help();
            0
        }
        [arg] if arg == "--help" || arg == "-h" => {
            print_help();
            0
        }
        [command] if command == "--version" || command == "-V" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            0
        }
        [command, backend] if command == "schema" && backend == "postgres" => {
            // Print exactly the schema `migrate()` deploys (the event-log table + the
            // materialized projection/edges), so an operator who pre-creates it gets the tables
            // the runtime actually uses — not migration 001's per-column design sketch.
            print!("{EVENT_LOG_SCHEMA_SQL}{MATERIALIZATION_SCHEMA_SQL}");
            0
        }
        [command] if command == "demo" => {
            demo();
            0
        }
        [command] if command == "verify" => cmd_verify(),
        [command] if command == "conflicts" => cmd_conflicts(),
        [command] if command == "eval" => cmd_eval(),
        #[cfg(feature = "export")]
        [command, out] if command == "export" => cmd_export(out),
        #[cfg(feature = "export")]
        [command] if command == "export" => cmd_export("dent8-events.parquet"),
        #[cfg(feature = "export")]
        [command, ..] if command == "export" => {
            // Wrong arity on an export-enabled build: a targeted usage, not the generic help.
            eprintln!("usage: dent8 export [out.parquet]");
            2
        }
        #[cfg(not(feature = "export"))]
        [command, ..] if command == "export" => {
            eprintln!(
                "`dent8 export` (Parquet for DuckDB) requires a build with `--features export`"
            );
            2
        }
        [command, kind, key, predicate, value, authority, source] if command == "assert" => {
            cmd_assert(kind, key, predicate, value, authority, source)
        }
        [
            command,
            kind,
            key,
            predicate,
            value,
            authority,
            source,
            fk,
            fkey,
            fpred,
        ] if command == "derive" => cmd_derive(
            kind, key, predicate, value, authority, source, fk, fkey, fpred,
        ),
        [command, kind, key, predicate, value, authority, source] if command == "supersede" => {
            cmd_supersede(kind, key, predicate, value, authority, source)
        }
        [command, kind, key, predicate, authority, source] if command == "retract" => {
            cmd_retract(kind, key, predicate, authority, source)
        }
        [command, kind, key, predicate, authority, source] if command == "reinforce" => {
            cmd_reinforce(kind, key, predicate, authority, source)
        }
        [command, kind, key, predicate, authority, source] if command == "expire" => {
            cmd_expire(kind, key, predicate, authority, source)
        }
        [command, kind, key, predicate, value, authority, source] if command == "contradict" => {
            cmd_contradict(kind, key, predicate, value, authority, source)
        }
        [command, kind, key, predicate] if command == "explain" => {
            cmd_explain(kind, key, predicate)
        }
        [command, kind, key, predicate] if command == "replay" => cmd_replay(kind, key, predicate),
        [command, sub] if command == "authority" && sub == "list" => cmd_authority_list(),
        [command, sub, source, max] if command == "authority" && sub == "add" => {
            cmd_authority_add(source, max, None, None)
        }
        [command, sub, source, max, issuer] if command == "authority" && sub == "add" => {
            cmd_authority_add(source, max, Some(issuer), None)
        }
        [command, sub, source, max, issuer, scope] if command == "authority" && sub == "add" => {
            cmd_authority_add(source, max, Some(issuer), Some(scope))
        }
        [command, sub, source] if command == "authority" && sub == "remove" => {
            cmd_authority_remove(source)
        }
        [command] if command == "authority" => {
            eprintln!(
                "usage: dent8 authority <list | add <source> <max> [issuer] [scope] | \
                 remove <source>>"
            );
            2
        }
        [command, subcommand] if command == "mcp" && subcommand == "serve" => mcp::serve(),
        [command, rest @ ..] if command == "witness" => run_witness(rest),
        [command] => usage_error(command),
        _ => {
            print_help();
            2
        }
    }
}

/// A known verb invoked with the wrong arity prints its specific usage (exit 2); anything else
/// falls back to the general help. Keeps the per-verb usage text out of the dispatch match.
fn usage_error(command: &str) -> i32 {
    let usage = match command {
        "assert" => {
            "dent8 assert <subject-kind> <subject-key> <predicate> <value> <authority> <source>\
             \n  e.g.  dent8 assert repo myproj database postgres high owner"
        }
        "supersede" => {
            "dent8 supersede <subject-kind> <subject-key> <predicate> <new-value> <authority> \
             <source>\n  e.g.  dent8 supersede repo myproj database mysql high owner"
        }
        "retract" => {
            "dent8 retract <subject-kind> <subject-key> <predicate> <authority> <source>\
             \n  e.g.  dent8 retract repo myproj database high owner"
        }
        "derive" => {
            "dent8 derive <kind> <key> <predicate> <value> <authority> <source> <from-kind> \
             <from-key> <from-predicate>\n  e.g.  dent8 derive repo myproj deploy_target pg high \
             agent repo myproj database"
        }
        "reinforce" => {
            "dent8 reinforce <subject-kind> <subject-key> <predicate> <authority> <source>\
             \n  e.g.  dent8 reinforce repo myproj database high ci-system"
        }
        "expire" => {
            "dent8 expire <subject-kind> <subject-key> <predicate> <authority> <source>\
             \n  e.g.  dent8 expire repo myproj branch.status high owner"
        }
        "contradict" => {
            "dent8 contradict <subject-kind> <subject-key> <predicate> <opposing-value> \
             <authority> <source>\n  e.g.  dent8 contradict repo myproj database mysql low scanner"
        }
        "explain" => "dent8 explain <subject-kind> <subject-key> <predicate>",
        "replay" => "dent8 replay <subject-kind> <subject-key> <predicate>",
        _ => {
            print_help();
            return 2;
        }
    };
    eprintln!("usage: {usage}");
    2
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

fn print_help() {
    println!(
        "\
dent8 - a memory firewall for coding agents

Usage:
  dent8 demo              run the firewall + replay/explain loop (in-memory)
  dent8 assert <kind> <key> <predicate> <value> <authority> <source>
                          assert a fact through the firewall, persisted to the log
  dent8 supersede <kind> <key> <predicate> <new-value> <authority> <source>
                          revise the believed fact (rejected if it can't out-rank it)
  dent8 retract <kind> <key> <predicate> <authority> <source>
                          remove the believed fact (rejected if it can't out-rank it)
  dent8 contradict <kind> <key> <predicate> <opposing-value> <authority> <source>
                          flag a conflict (dissent): contest the fact, keep both
  dent8 derive <kind> <key> <predicate> <value> <authority> <source> <from-kind> <from-key> <from-predicate>
                          assert a fact derived from another fact (records a dependency
                          edge; retract the source → `verify` flags this as tainted)
  dent8 reinforce <kind> <key> <predicate> <authority> <source>
                          corroborate the believed fact (raise earned entrenchment)
  dent8 expire <kind> <key> <predicate> <authority> <source>
                          terminally expire the believed fact (authority-gated)
  dent8 explain <kind> <key> <predicate>
                          explain the believed fact, with an integrity receipt
  dent8 replay <kind> <key> <predicate>
                          replay the full event history (why the fact is what it is)
  dent8 verify            check log integrity (structural on the file store; a real
                          stored-hash-chain re-verification on Postgres)
  dent8 conflicts         list contested facts (in dispute), across all entities
  dent8 eval              run the adversarial corpus (firewall vs recency-only baseline)
  dent8 export [out]      export the log to Parquet for DuckDB analysis (out defaults to
                          ./dent8-events.parquet; needs --features export)
  dent8 authority list | add <source> <max> [issuer] [scope] | remove <source>
                          manage the source -> authority ceiling (authz)
  dent8 witness keygen | sign | verify | head | serve [interval] [max-heads]
                          emit/verify Ed25519 signed tree heads to detect a history
                          rewrite or rollback; `serve` is the cadence signer, `head`
                          prints the latest head to publish (needs --features witness)
  dent8 schema postgres   print the Postgres schema
  dent8 mcp serve         expose the full belief surface to agents over MCP (stdio JSON-RPC)

Storage: a JSON-lines dev log by default (DENT8_LOG, default ./dent8-log.jsonl), or the
operational transactional Postgres backend when DENT8_DATABASE_URL is set (requires a build
with --features postgres). authority is one of: low | medium | high | canonical.
Authority ceiling: a source may assert at most its registered max. Enforced once a registry
exists (DENT8_AUTHORITY, default ./dent8-authority.json) — then deny-by-default: an unlisted
source is blocked from writing. Without a registry the CLI is permissive (dev mode), unless
DENT8_REQUIRE_AUTHORITY=1 is set. The registry is host-local config, independent of the event
backend. issuer/scope are recorded but NOT enforced in v0. See docs/STATUS.md."
    );
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
// the operational, transactional backend is Postgres (M2b).

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
    let json =
        serde_json::to_string_pretty(registry).map_err(|error| format!("serialize: {error}"))?;
    // Atomic write: a torn save would corrupt the registry, and a corrupt registry fails
    // *closed* (every write is then blocked). Stage a sibling temp file, then rename it over
    // the target — rename is atomic within a filesystem. Concurrent writers remain
    // last-write-wins, which is acceptable for a human-managed config file.
    let tmp = format!("{path}.tmp.{}", std::process::id());
    std::fs::write(&tmp, format!("{json}\n"))
        .map_err(|error| format!("cannot write {tmp}: {error}"))?;
    std::fs::rename(&tmp, &path).map_err(|error| format!("cannot install {path}: {error}"))
}

/// The authz gate, run before the firewall on every write: reject a stated `authority` above
/// its `source`'s registered ceiling. A no-op only when no registry is configured and
/// `DENT8_REQUIRE_AUTHORITY` is not enabled.
fn enforce_source_ceiling(source: &str, requested: AuthorityLevel) -> Result<(), OpError> {
    let registry = load_authority_registry().map_err(OpError::Invalid)?;
    ceiling_check(registry.as_ref(), source, requested)
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

fn cmd_authority_add(source: &str, max: &str, issuer: Option<&str>, scope: Option<&str>) -> i32 {
    let Some(max_authority) = parse_authority(max) else {
        eprintln!("unknown authority '{max}' (expected: low | medium | high | canonical)");
        return 2;
    };
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

fn now_millis() -> TimestampMillis {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |delta| delta.as_millis());
    TimestampMillis::from_unix_millis(i64::try_from(ms).unwrap_or(i64::MAX))
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

/// Rehydrate the durable log via the trusted-reload path (no re-arbitration of
/// already-admitted events). A missing file is an empty log.
///
/// Because the trusted path performs no policy checks, this *also* re-validates the
/// invariant the writer is supposed to maintain — at most one fresh believed claim per
/// unique predicate — so a torn write or external edit that orphaned a believed claim is
/// rejected loudly rather than silently masked by `explain`.
fn load_store(path: &str) -> Result<InMemoryEventStore, String> {
    // Backend selection lives here (and in `append_events`) so every `op_*` is backend-aware
    // with no changes of its own. With `DENT8_DATABASE_URL` set (and the `postgres` feature),
    // reads/writes go to the operational Postgres store; otherwise to the file dev store.
    #[cfg(feature = "postgres")]
    if let Ok(url) = std::env::var("DENT8_DATABASE_URL") {
        return pg_load(&url);
    }
    #[cfg(not(feature = "postgres"))]
    if std::env::var_os("DENT8_DATABASE_URL").is_some() {
        return Err(
            "DENT8_DATABASE_URL is set but this build lacks Postgres support — \
                    rebuild with `--features postgres`"
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
    #[cfg(feature = "postgres")]
    if let Ok(url) = std::env::var("DENT8_DATABASE_URL") {
        return pg_scan_raw(&url);
    }
    #[cfg(not(feature = "postgres"))]
    if std::env::var_os("DENT8_DATABASE_URL").is_some() {
        return Err(
            "DENT8_DATABASE_URL is set but this build lacks Postgres support — \
                    rebuild with `--features postgres`"
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

/// Raw ordered Postgres log for the witness: connect + self-migrate + scan, with **no**
/// integrity gate (see [`load_raw_events`]).
#[cfg(all(feature = "witness", feature = "postgres"))]
fn pg_scan_raw(url: &str) -> Result<Vec<ClaimEvent>, String> {
    use dent8_store_postgres::PostgresEventStore;
    pg_runtime()?.block_on(async {
        let store = PostgresEventStore::connect(url)
            .await
            .map_err(|error| error.to_string())?;
        store.migrate().await.map_err(|error| error.to_string())?;
        store
            .scan_events(&dent8_store::EventFilter::default())
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
    #[cfg(feature = "postgres")]
    if let Ok(url) = std::env::var("DENT8_DATABASE_URL") {
        return pg_verify(&url);
    }
    #[cfg(not(feature = "postgres"))]
    if std::env::var_os("DENT8_DATABASE_URL").is_some() {
        return Err(
            "DENT8_DATABASE_URL is set but this build lacks Postgres support — \
                    rebuild with `--features postgres`"
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

/// Postgres integrity check: re-verify the stored global hash chain (real tamper-evidence).
#[cfg(feature = "postgres")]
fn pg_verify(url: &str) -> Result<String, String> {
    use dent8_store_postgres::PostgresEventStore;
    pg_runtime()?.block_on(async {
        let store = PostgresEventStore::connect(url)
            .await
            .map_err(|error| error.to_string())?;
        store.migrate().await.map_err(|error| error.to_string())?;
        if !store
            .verify_chain()
            .await
            .map_err(|error| error.to_string())?
        {
            return Err(
                "INTEGRITY FAILURE: the Postgres global hash chain does not re-verify \
                        (a stored event was altered)"
                    .to_string(),
            );
        }
        let events = store
            .scan_events(&dent8_store::EventFilter::default())
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
            "OK: {} event(s) — the Postgres global hash chain re-verifies, no retraction taint. \
             (Tamper-resistance needs an external operated witness.)",
            events.len()
        ))
    })
}

fn cmd_verify() -> i32 {
    match verify_log(&log_path()) {
        Ok(report) => {
            println!("{report}");
            0
        }
        Err(message) => {
            eprintln!("{message}");
            1
        }
    }
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
/// store; true transactional atomicity is the Postgres backend (M2b).
fn append_events(path: &str, events: &[&ClaimEvent]) -> Result<(), WriteError> {
    use std::io::Write;
    // Postgres commits the whole operation (assert / supersede / retract / contradict) as one
    // transaction via `append_many`; the file store just appends the lines. (A `not(postgres)`
    // build that reaches here with the env var set already errored in `load_store`.)
    #[cfg(feature = "postgres")]
    if let Ok(url) = std::env::var("DENT8_DATABASE_URL") {
        return pg_append(&url, events);
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

/// A throwaway current-thread runtime to bridge the sync CLI to the async adapter. One per
/// storage call is fine for a single-operation CLI process.
#[cfg(feature = "postgres")]
fn pg_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("tokio runtime: {error}"))
}

/// Load the whole Postgres log into an in-memory working store (the decide snapshot the
/// `op_*` functions read), connecting + self-migrating on the way.
#[cfg(feature = "postgres")]
fn pg_load(url: &str) -> Result<InMemoryEventStore, String> {
    use dent8_store_postgres::PostgresEventStore;
    pg_runtime()?.block_on(async {
        let store = PostgresEventStore::connect(url)
            .await
            .map_err(|error| error.to_string())?;
        store.migrate().await.map_err(|error| error.to_string())?;
        let events = store
            .scan_events(&dent8_store::EventFilter::default())
            .await
            .map_err(|error| error.to_string())?;
        let working = InMemoryEventStore::from_trusted_events(events)
            .map_err(|error| format!("cannot load Postgres log: {error}"))?;
        // Re-run the same integrity gate the file path enforces, so the operational backend is
        // at least as defensive: a torn/forged state (e.g. a direct SQL edit) is rejected, not
        // silently believed.
        validate_unique_log(&working, now_millis())?;
        Ok(working)
    })
}

/// Persist an accepted operation to Postgres as **one transaction** (`append_many`), so a
/// multi-event supersede/retract/contradict commits atomically and is re-arbitrated by the
/// durable firewall.
///
/// v0 concurrency: commits are serialized by the adapter's advisory lock and any racing write
/// is safely rejected (the `event_id` UNIQUE constraint + in-transaction re-arbitration), so
/// there is no corruption — but event/claim ids are minted optimistically from a snapshot, so
/// two writers racing the same DB can collide and one gets a **retryable** write conflict.
/// Treat the v0 Postgres path as effectively single-writer until DB-assigned ids land.
#[cfg(feature = "postgres")]
fn pg_append(url: &str, events: &[&ClaimEvent]) -> Result<(), WriteError> {
    use dent8_store::StoreError;
    use dent8_store_postgres::PostgresEventStore;
    let owned: Vec<ClaimEvent> = events.iter().map(|&event| event.clone()).collect();
    pg_runtime().map_err(WriteError::Other)?.block_on(async {
        let store = PostgresEventStore::connect(url)
            .await
            .map_err(|error| WriteError::Other(error.to_string()))?;
        store
            .migrate()
            .await
            .map_err(|error| WriteError::Other(error.to_string()))?;
        store
            .append_many(owned)
            .await
            .map_err(|error| match error {
                // A duplicate id under the optimistic scheme is a race, not corruption: signal it as
                // retryable so the caller re-snapshots and re-mints a non-colliding id.
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
    enforce_source_ceiling(source, authority)?;
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

fn cmd_assert(
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    value: &str,
    authority: &str,
    source: &str,
) -> i32 {
    let Some(authority_level) = parse_authority(authority) else {
        eprintln!("unknown authority '{authority}' (expected: low | medium | high | canonical)");
        return 2;
    };
    present(with_write_retry(|| {
        op_assert(
            &log_path(),
            subject_kind,
            subject_key,
            predicate,
            value,
            authority_level,
            source,
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
    enforce_source_ceiling(source, authority)?;
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

#[allow(clippy::too_many_arguments)]
fn cmd_derive(
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    value: &str,
    authority: &str,
    source: &str,
    from_kind: &str,
    from_key: &str,
    from_predicate: &str,
) -> i32 {
    let Some(authority_level) = parse_authority(authority) else {
        eprintln!("unknown authority '{authority}' (expected: low | medium | high | canonical)");
        return 2;
    };
    present(with_write_retry(|| {
        op_derive(
            &log_path(),
            subject_kind,
            subject_key,
            predicate,
            value,
            authority_level,
            source,
            from_kind,
            from_key,
            from_predicate,
        )
    }))
}

/// Render an operation result for the CLI: success to stdout (exit 0), a malformed request
/// to stderr (exit 2), a refused one to stderr (exit 1).
fn present(outcome: Result<String, OpError>) -> i32 {
    match outcome {
        Ok(message) => {
            println!("{message}");
            0
        }
        Err(OpError::Invalid(message)) => {
            eprintln!("{message}");
            2
        }
        Err(OpError::Rejected(message) | OpError::Conflict(message)) => {
            eprintln!("{message}");
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
/// persisted as one best-effort single write (true transactional atomicity is Postgres,
/// M2b). The base firewall's anti-laundering enforces that the replacement out-ranks each
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
    enforce_source_ceiling(source, authority)?;
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
fn cmd_supersede(
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    new_value: &str,
    authority: &str,
    source: &str,
) -> i32 {
    let Some(authority_level) = parse_authority(authority) else {
        eprintln!("unknown authority '{authority}' (expected: low | medium | high | canonical)");
        return 2;
    };
    present(with_write_retry(|| {
        op_supersede(
            &log_path(),
            subject_kind,
            subject_key,
            predicate,
            new_value,
            authority_level,
            source,
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
    enforce_source_ceiling(source, authority)?;
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
fn cmd_retract(
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: &str,
    source: &str,
) -> i32 {
    let Some(authority_level) = parse_authority(authority) else {
        eprintln!("unknown authority '{authority}' (expected: low | medium | high | canonical)");
        return 2;
    };
    present(with_write_retry(|| {
        op_retract(
            &log_path(),
            subject_kind,
            subject_key,
            predicate,
            authority_level,
            source,
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
    enforce_source_ceiling(source, authority)?;
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

fn cmd_reinforce(
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: &str,
    source: &str,
) -> i32 {
    let Some(authority_level) = parse_authority(authority) else {
        eprintln!("unknown authority '{authority}' (expected: low | medium | high | canonical)");
        return 2;
    };
    present(with_write_retry(|| {
        op_reinforce(
            &log_path(),
            subject_kind,
            subject_key,
            predicate,
            authority_level,
            source,
        )
    }))
}

fn cmd_expire(
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: &str,
    source: &str,
) -> i32 {
    let Some(authority_level) = parse_authority(authority) else {
        eprintln!("unknown authority '{authority}' (expected: low | medium | high | canonical)");
        return 2;
    };
    present(with_write_retry(|| {
        op_expire(
            &log_path(),
            subject_kind,
            subject_key,
            predicate,
            authority_level,
            source,
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
    enforce_source_ceiling(source, authority)?;
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
fn cmd_contradict(
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    opposing_value: &str,
    authority: &str,
    source: &str,
) -> i32 {
    let Some(authority_level) = parse_authority(authority) else {
        eprintln!("unknown authority '{authority}' (expected: low | medium | high | canonical)");
        return 2;
    };
    present(with_write_retry(|| {
        op_contradict(
            &log_path(),
            subject_kind,
            subject_key,
            predicate,
            opposing_value,
            authority_level,
            source,
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

fn cmd_replay(subject_kind: &str, subject_key: &str, predicate: &str) -> i32 {
    present(op_replay(&log_path(), subject_kind, subject_key, predicate))
}

/// Explain the believed (or terminal) fact + its integrity receipt. Shared by
/// `dent8 explain` and the MCP `explain` tool.
fn op_explain(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
) -> Result<String, OpError> {
    let store = load_store(path).map_err(OpError::Invalid)?;
    let subject = EntityRef::new(subject_kind, subject_key)
        .map_err(|error| OpError::Invalid(format!("invalid subject: {error}")))?;
    let predicate_parsed = Predicate::new(predicate)
        .map_err(|error| OpError::Invalid(format!("invalid predicate: {error}")))?;
    match store.explain_latest(&subject, &predicate_parsed, now_millis()) {
        Ok(Some(receipt)) => {
            let annotation = read_annotation(receipt.lifecycle, receipt.fresh);
            Ok(format!(
                "explain {subject_kind}:{subject_key} {predicate}{annotation}\n{}",
                format_receipt(&receipt)
            ))
        }
        Ok(None) => Err(OpError::Rejected(format!(
            "no claim for {subject_kind}:{subject_key} {predicate}"
        ))),
        Err(error) => Err(OpError::Rejected(format!("explain failed: {error}"))),
    }
}

fn cmd_explain(subject_kind: &str, subject_key: &str, predicate: &str) -> i32 {
    present(op_explain(
        &log_path(),
        subject_kind,
        subject_key,
        predicate,
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
