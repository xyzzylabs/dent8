//! The **witness** primitive: emit and verify Ed25519 *signed tree heads* (STHs) over the
//! event log across time, so a history rewrite or rollback that an internal chain re-verify
//! *cannot* catch (the threat model's T6 residual — a re-hashed-forward rewrite is internally
//! self-consistent) becomes detectable by anyone holding the witness's **public** key.
//!
//! How it works. A [`SignedTreeHead`] signs `(event_count, head)` — and because the chain is
//! a linked hash chain, `head` at count `N` commits to the entire prefix `events[0..N]`. So a
//! past STH issued at count `N` still verifies against a *grown* log by checking it against
//! that log's **prefix** of length `N` (`verify_signed_head(&events[..N], sth, key)`). A
//! witness is therefore just an append-only sequence of STHs; verification re-checks each one
//! against the current log's matching prefix and that the counts never decrease. A rewritten
//! prefix fails its signature (TAMPER); a log shorter than a witnessed count, or a witness log
//! whose counts go backwards, is a ROLLBACK.
//!
//! **This is the mechanism, not a deployment.** Tamper-*resistance* (not just evidence) holds
//! only if the signing key lives **off** the log-writer's machine — a writer who also holds
//! the key can re-sign a rewrite. `keygen` prints that warning. `serve` is the **cadence
//! signer** (sign on growth), `publish` idempotently appends the latest head to an external
//! JSONL sequence, and `head` still prints a JSON line for custom publication channels. What
//! remains *operational* is running `serve` on a host separate from the writer, rotating its
//! key, and publishing/monitoring heads outside the writer's control. See the threat model's
//! T6 residuals.
//!
//! Residual — the witness log itself is plain appended JSONL. Every head is independently
//! signature-verified (none can be *forged* without the key), but an attacker with write
//! access can *drop* the latest head to shrink coverage — undetectable from the log alone.
//! That is the same "missing/rewound anchor" residual the operated service closes by
//! **publishing** heads externally; `verify` prints how many heads it checked so an operator
//! who knows how many were issued can spot a shortfall.

use std::io::Write;

use crate::{CliOutput, print_json_stdout, print_json_stdout_with_code};
use dent8_core::{FactEvent, SignedTreeHead, sign_head, verify_signed_head};
use ed25519_dalek::{SigningKey, VerifyingKey};

const DEFAULT_KEY: &str = "dent8-witness.key";
const DEFAULT_LOG: &str = "dent8-witness.jsonl";

/// `serve` bails after this many consecutive failed ticks (a deleted key, a full disk).
const MAX_CONSECUTIVE_ERRORS: u32 = 10;

const KEYGEN_TOOL: &str = "witness keygen";
const SIGN_TOOL: &str = "witness sign";
const SERVE_TOOL: &str = "witness serve";
const HEAD_TOOL: &str = "witness head";
const PUBLISH_TOOL: &str = "witness publish";
const VERIFY_TOOL: &str = "witness verify";
const VERIFY_PUBLISHED_TOOL: &str = "witness verify-published";
const DOCTOR_TOOL: &str = "witness doctor";

fn key_path() -> String {
    std::env::var("DENT8_WITNESS_KEY").unwrap_or_else(|_| DEFAULT_KEY.to_string())
}

fn witness_log_path() -> String {
    std::env::var("DENT8_WITNESS_LOG").unwrap_or_else(|_| DEFAULT_LOG.to_string())
}

fn verifying_key_path() -> String {
    std::env::var("DENT8_WITNESS_PUBKEY").unwrap_or_else(|_| public_key_path(&key_path()))
}

fn public_key_path(key: &str) -> String {
    format!("{key}.pub")
}

fn witness_error_with_paths_json(
    tool: &str,
    message: &str,
    key_path: Option<&str>,
    public_key_path: Option<&str>,
    witness_log_path: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": tool,
        "key_path": key_path,
        "public_key_path": public_key_path,
        "witness_log_path": witness_log_path,
        "message": message,
    })
}

/// A setup/config failure (unreadable key, missing file, …): `status: "failed"`.
fn print_witness_error(output: CliOutput, tool: &str, message: &str, code: i32) -> i32 {
    print_witness_fault(output, tool, "failed", message, code)
}

/// A witness outcome with a machine-readable verdict. `status` distinguishes the security
/// verdicts (`tamper` / `rollback` / `conflict`), an inconclusive check (`cannot_verify`),
/// and a plain setup failure (`failed`) — a monitor must not have to parse the prose
/// `message` to tell an alarm from a typo'd path.
fn print_witness_fault(
    output: CliOutput,
    tool: &str,
    status: &str,
    message: &str,
    code: i32,
) -> i32 {
    match output {
        CliOutput::Text => {
            eprintln!("{message}");
            code
        }
        CliOutput::Json => print_json_stdout_with_code(
            &serde_json::json!({
                "status": status,
                "tool": tool,
                "message": message,
            }),
            code,
        ),
    }
}

fn print_witness_usage(output: CliOutput, tool: &str, usage: &str) -> i32 {
    match output {
        CliOutput::Text => {
            eprintln!("usage: {usage}");
            2
        }
        CliOutput::Json => print_json_stdout_with_code(
            &serde_json::json!({
                "status": "invalid",
                "tool": tool,
                "usage": usage,
                "message": "invalid witness command arguments",
            }),
            2,
        ),
    }
}

fn signed_head_json(sth: &SignedTreeHead) -> serde_json::Value {
    serde_json::to_value(sth).expect("signed tree head should serialize")
}

fn signed_head_json_line(sth: &SignedTreeHead) -> Result<String, String> {
    serde_json::to_string(sth).map_err(|error| format!("could not serialize the head: {error}"))
}

fn unwitnessed_events(witnessed: u64, current: u64) -> u64 {
    current.saturating_sub(witnessed)
}

fn coverage_level(witnessed: u64, current: u64) -> &'static str {
    if witnessed == current { "ok" } else { "warn" }
}

fn coverage_status(witnessed: u64, current: u64) -> &'static str {
    if witnessed == current {
        "complete"
    } else {
        "trailing"
    }
}

/// The current event log in global append order — the chain `sign_head`/`verify_signed_head`
/// commit to. Backend-aware (file dev store or Postgres). Loaded **raw**, without the
/// trusted-reload integrity gate, so the witness renders its own tamper verdict on a log that
/// gate would reject rather than being preempted by it.
fn load_events() -> Result<Vec<FactEvent>, String> {
    crate::load_raw_events(&crate::log_path())
}

/// Generate an Ed25519 witness keypair: the private signing key (hex, `0600`) at
/// `DENT8_WITNESS_KEY`, the public verifying key (hex) alongside as `<key>.pub`. Refuses to
/// clobber an existing key.
pub fn keygen(output: CliOutput) -> i32 {
    let key = key_path();
    if std::path::Path::new(&key).exists() {
        let message = format!("{key} already exists — refusing to overwrite a witness signing key");
        return match output {
            CliOutput::Text => {
                eprintln!("{message}");
                1
            }
            CliOutput::Json => print_json_stdout_with_code(
                &witness_error_with_paths_json(
                    KEYGEN_TOOL,
                    &message,
                    Some(&key),
                    Some(&public_key_path(&key)),
                    None,
                ),
                1,
            ),
        };
    }
    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::getrandom(&mut seed) {
        let message = format!("could not gather randomness for the key: {error}");
        return print_witness_error(output, KEYGEN_TOOL, &message, 1);
    }
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    if let Err(error) = write_secret(&key, &hex::encode(signing.to_bytes())) {
        return print_witness_error(output, KEYGEN_TOOL, &error, 1);
    }
    let public = public_key_path(&key);
    if let Err(error) = std::fs::write(&public, format!("{}\n", hex::encode(verifying.to_bytes())))
    {
        // Don't strand a private key with no public counterpart — a later `keygen` would refuse
        // to overwrite it. Best-effort remove the half-written pair.
        let _ = std::fs::remove_file(&key);
        let message = format!("cannot write {public}: {error} (removed the partial key {key})");
        return match output {
            CliOutput::Text => {
                eprintln!("{message}");
                1
            }
            CliOutput::Json => print_json_stdout_with_code(
                &witness_error_with_paths_json(
                    KEYGEN_TOOL,
                    &message,
                    Some(&key),
                    Some(&public),
                    None,
                ),
                1,
            ),
        };
    }
    let message = format!(
        "wrote witness signing key to {key} (keep it OFF the log-writer's machine — that \
         separation is what gives tamper-resistance)\nwrote public verifying key to {public}"
    );
    let permission_warning = {
        #[cfg(unix)]
        {
            None::<String>
        }
        #[cfg(not(unix))]
        {
            Some(format!(
                "note: this is a non-Unix platform — {key} was NOT restricted to owner-only file \
                 permissions; protect it yourself"
            ))
        }
    };
    match output {
        CliOutput::Text => {
            println!("{message}");
            if let Some(warning) = &permission_warning {
                println!("{warning}");
            }
            0
        }
        CliOutput::Json => print_json_stdout(&serde_json::json!({
            "status": "ok",
            "tool": KEYGEN_TOOL,
            "key_path": key,
            "public_key_path": public,
            "operated_role": "signer",
            "writer_must_not_inherit_key": true,
            "permission_warning": permission_warning,
            "message": message,
        })),
    }
}

/// Sign a tree head over the current log and append it to the witness log.
pub fn sign(output: CliOutput) -> i32 {
    let events = match load_events() {
        Ok(events) => events,
        Err(error) => {
            return print_witness_error(output, SIGN_TOOL, &error, 1);
        }
    };
    let signing = match load_signing_key() {
        Ok(key) => key,
        Err(error) => {
            return print_witness_error(output, SIGN_TOOL, &error, 1);
        }
    };
    let sth = match sign_head(&events, &signing) {
        Ok(sth) => sth,
        Err(error) => {
            let message = format!("could not sign the tree head: {error}");
            return print_witness_error(output, SIGN_TOOL, &message, 1);
        }
    };
    let path = witness_log_path();
    if let Err(error) = append_head(&path, &sth) {
        return print_witness_error(output, SIGN_TOOL, &error, 1);
    }
    // Grant-log lane (ADR 0014 follow-up): when a grant log is discoverable, witness its
    // head too, so a truncated revocation is detectable.
    let grant_lane = match sign_grant_log_head(&signing) {
        Ok(line) => line,
        Err(error) => {
            let message = format!("could not sign the grant-log head: {error}");
            return print_witness_error(output, SIGN_TOOL, &message, 1);
        }
    };
    let mut message = format!(
        "signed tree head: count={} head={} -> appended to {path}",
        sth.event_count,
        sth.head.as_deref().unwrap_or("(empty log)"),
    );
    if let Some(lane) = &grant_lane {
        message.push('\n');
        message.push_str(&lane.message());
    }
    match output {
        CliOutput::Text => {
            println!("{message}");
            0
        }
        CliOutput::Json => print_json_stdout(&serde_json::json!({
            "status": "ok",
            "tool": SIGN_TOOL,
            "witness_log_path": path,
            "current_event_count": events.len(),
            "signed_head": signed_head_json(&sth),
            "grant_log_head": grant_lane.as_ref().map(|lane| grant_log_head_json(&lane.head)),
            "message": message,
        })),
    }
}

/// Run as a **cadence signer** — the *operated* witness loop. Every `interval` seconds, sign
/// the head **if the log has grown** (an append-only log's head changes only when its count
/// does) and append it to the witness log; when a grant log is discoverable (ADR 0014), sign
/// its head on change the same way. Run this on a host **separate** from the writer, holding
/// the key, so the accumulated signatures are evidence the writer cannot forge. The optional
/// second argument bounds the number of *event* heads signed (for a finite run); without it,
/// it runs until interrupted. A later in-place rewrite is still caught by an *earlier* signed
/// head failing `verify`, so signing only on growth loses no resistance.
///
/// With `--output json` the loop streams **NDJSON**: signed heads as one compact JSON line
/// each on stdout (`event: "head_signed"`, `lane: "events" | "grants"`), lifecycle and
/// diagnostics (`started` / `warning` / `error` / `stopped`) on stderr — so a collector
/// tailing stdout sees exactly the signed-head record stream.
#[allow(clippy::too_many_lines)] // one linear loop, two lanes, two output modes
pub fn serve(args: &[String], output: CliOutput) -> i32 {
    // Floor the interval at 1s: a 0s interval whose head target is never reached on a static log
    // would busy-spin the CPU (and hammer the DB on the Postgres backend).
    let interval = args
        .first()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5)
        .max(1);
    let max_heads = args.get(1).and_then(|value| value.parse::<u64>().ok());
    let serve_error = |message: &str| match output {
        CliOutput::Text => eprintln!("{message}"),
        CliOutput::Json => eprintln!(
            "{}",
            serde_json::json!({"event": "error", "tool": SERVE_TOOL, "message": message})
        ),
    };
    let signing = match load_signing_key() {
        Ok(key) => key,
        Err(error) => {
            serve_error(&error);
            return 1;
        }
    };
    let verifying = signing.verifying_key();
    let path = witness_log_path();
    match output {
        CliOutput::Text => eprintln!(
            "witness: signing the head on growth every {interval}s -> {path}{} (interrupt to stop)",
            max_heads.map_or_else(String::new, |max| format!(", up to {max} head(s)"))
        ),
        CliOutput::Json => eprintln!(
            "{}",
            serde_json::json!({
                "event": "started",
                "tool": SERVE_TOOL,
                "interval_seconds": interval,
                "witness_log_path": path,
                "max_heads": max_heads,
            })
        ),
    }
    // Seed from any heads already on disk so growth is measured from the last witnessed point,
    // and a pre-existing head can flag a rewrite on the first growth tick.
    let mut last_signed: Option<SignedTreeHead> =
        load_witness_log().ok().and_then(|mut heads| heads.pop());
    // The grant-log lane (ADR 0014), same shape: seed from the grants-witness log's tail and
    // sign only when the grant log's (count, head) changes, so a 5s cadence does not bloat
    // the lane with identical heads.
    let mut last_grant_state: Option<(u64, Option<String>)> =
        load_grant_log_heads(&grants_witness_log_path(), "grants-witness log", true)
            .ok()
            .and_then(|mut heads| heads.pop())
            .map(|head| (head.record_count, head.head));
    let mut signed: u64 = 0;
    // Bail out after a run of consecutive failures (a deleted key, a full disk) rather than
    // logging forever in a tight loop.
    let mut errors = 0u32;
    loop {
        let mut had_error = false;
        match load_events() {
            Ok(events) => {
                let count = events.len() as u64;
                if last_signed.as_ref().map(|sth| sth.event_count) != Some(count) {
                    if let Some(warning) =
                        prior_head_warning(last_signed.as_ref(), &events, &verifying)
                    {
                        match output {
                            CliOutput::Text => eprintln!("{warning}"),
                            CliOutput::Json => eprintln!(
                                "{}",
                                serde_json::json!({
                                    "event": "warning",
                                    "tool": SERVE_TOOL,
                                    "message": warning,
                                })
                            ),
                        }
                    }
                    match sign_head(&events, &signing)
                        .map_err(|error| error.to_string())
                        .and_then(|sth| append_head(&path, &sth).map(|()| sth))
                    {
                        Ok(sth) => {
                            signed += 1;
                            match output {
                                CliOutput::Text => println!(
                                    "signed head: count={} head={}",
                                    sth.event_count,
                                    sth.head.as_deref().unwrap_or("(empty log)")
                                ),
                                CliOutput::Json => println!(
                                    "{}",
                                    serde_json::json!({
                                        "event": "head_signed",
                                        "tool": SERVE_TOOL,
                                        "lane": "events",
                                        "head": signed_head_json(&sth),
                                        "signed_total": signed,
                                    })
                                ),
                            }
                            last_signed = Some(sth);
                        }
                        Err(error) => {
                            serve_error(&format!("witness: {error}"));
                            had_error = true;
                        }
                    }
                }
            }
            Err(error) => {
                serve_error(&format!("witness: could not load the log: {error}"));
                had_error = true;
            }
        }
        match sign_grant_log_head_if_changed(&signing, &mut last_grant_state) {
            Ok(Some(lane)) => match output {
                CliOutput::Text => println!("{}", lane.message()),
                CliOutput::Json => println!(
                    "{}",
                    serde_json::json!({
                        "event": "head_signed",
                        "tool": SERVE_TOOL,
                        "lane": "grants",
                        "head": grant_log_head_json(&lane.head),
                    })
                ),
            },
            Ok(None) => {}
            Err(error) => {
                serve_error(&format!("witness: {error}"));
                had_error = true;
            }
        }
        errors = if had_error { errors + 1 } else { 0 };
        if errors >= MAX_CONSECUTIVE_ERRORS {
            match output {
                CliOutput::Text => {
                    eprintln!("witness: giving up after {errors} consecutive errors");
                }
                CliOutput::Json => eprintln!(
                    "{}",
                    serde_json::json!({
                        "event": "stopped",
                        "tool": SERVE_TOOL,
                        "reason": "consecutive_errors",
                        "message": format!("giving up after {errors} consecutive errors"),
                    })
                ),
            }
            return 1;
        }
        if max_heads.is_some_and(|max| signed >= max) {
            if output == CliOutput::Json {
                eprintln!(
                    "{}",
                    serde_json::json!({
                        "event": "stopped",
                        "tool": SERVE_TOOL,
                        "reason": "max_heads_reached",
                        "signed_heads": signed,
                    })
                );
            }
            return 0;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}

/// Warn (loudly, non-fatally) if the most recent witnessed head no longer matches the current
/// log's prefix — history was rewritten or rolled back under the witness. The witness still
/// signs the new growth; the stale head remains the evidence at `verify` time.
fn prior_head_warning(
    previous: Option<&SignedTreeHead>,
    events: &[FactEvent],
    verifying: &VerifyingKey,
) -> Option<String> {
    let previous = previous?;
    let Ok(count) = usize::try_from(previous.event_count) else {
        return None;
    };
    if count > events.len() {
        return Some(format!(
            "witness: WARNING — the log shrank below a previously witnessed count {} (ROLLBACK); \
             signing the new head anyway, the earlier head is the evidence",
            previous.event_count
        ));
    }
    match verify_signed_head(&events[..count], previous, verifying) {
        Ok(true) => None,
        Ok(false) => Some(format!(
            "witness: WARNING — the log no longer matches the head witnessed at count {} (history \
             was REWRITTEN); signing the new head anyway, the earlier head is the evidence",
            previous.event_count
        )),
        Err(error) => Some(format!("witness: could not check the prior head: {error}")),
    }
}

/// Print the latest signed tree head (as one JSON line) for an operator to **publish** —
/// recording it externally is what lets a third party detect a later rollback.
pub fn head(output: CliOutput) -> i32 {
    match load_witness_log() {
        Ok(heads) => match heads.last() {
            None => {
                let message = format!(
                    "no signed tree heads in {} yet (run `dent8 witness sign` or `serve`)",
                    witness_log_path()
                );
                match output {
                    CliOutput::Text => {
                        println!("{message}");
                        0
                    }
                    CliOutput::Json => print_json_stdout(&serde_json::json!({
                        "status": "ok",
                        "level": "warn",
                        "tool": HEAD_TOOL,
                        "witness_log_path": witness_log_path(),
                        "signed_head_count": 0,
                        "latest_head": null,
                        "jsonl": null,
                        "message": message,
                    })),
                }
            }
            Some(sth) => match signed_head_json_line(sth) {
                Ok(json) => match output {
                    CliOutput::Text => {
                        println!("{json}");
                        0
                    }
                    CliOutput::Json => print_json_stdout(&serde_json::json!({
                        "status": "ok",
                        "level": "ok",
                        "tool": HEAD_TOOL,
                        "witness_log_path": witness_log_path(),
                        "signed_head_count": heads.len(),
                        "latest_head": signed_head_json(sth),
                        "jsonl": json,
                    })),
                },
                Err(error) => print_witness_error(output, HEAD_TOOL, &error, 1),
            },
        },
        Err(error) => print_witness_error(output, HEAD_TOOL, &error, 1),
    }
}

/// Publish the latest local witness head to an external JSONL sequence.
///
/// This is a safer wrapper around `dent8 witness head >> published-heads.jsonl`: it refuses to
/// append a local head behind the already-published sequence, treats an identical latest head
/// as idempotent, and verifies the resulting published sequence against the current log before
/// writing.
pub fn publish(args: &[String], output: CliOutput) -> i32 {
    let (path, grants_path) = match args {
        [path] => (path, None),
        [path, flag, grants] if flag == "--grants" => (path, Some(grants)),
        _ => {
            return print_witness_usage(
                output,
                PUBLISH_TOOL,
                "dent8 witness publish <published-heads.jsonl> [--grants <published-grants.jsonl>]",
            );
        }
    };
    let outcome = match publish_outcome(path) {
        Ok(outcome) => outcome,
        Err((status, message, code)) => {
            return print_witness_fault(output, PUBLISH_TOOL, status, &message, code);
        }
    };
    let grants = match grants_path {
        Some(grants_path) => match publish_grants_outcome(grants_path) {
            Ok(grants_outcome) => Some((grants_path.as_str(), grants_outcome)),
            Err((status, message, code)) => {
                return print_witness_fault(output, PUBLISH_TOOL, status, &message, code);
            }
        },
        None => None,
    };
    // Publishing only the event lane while a grants-witness log exists locally would leave
    // grant history truncatable — say so instead of silently half-covering.
    let unpublished_grants_log = (grants.is_none()
        && std::path::Path::new(&grants_witness_log_path()).exists())
    .then(grants_witness_log_path);
    let mut level = coverage_level(outcome.latest.event_count, outcome.current_count);
    if let Some((_, grants_outcome)) = &grants
        && coverage_level(
            grants_outcome.latest.record_count,
            grants_outcome.current_record_count,
        ) == "warn"
    {
        level = "warn";
    }
    match output {
        CliOutput::Text => {
            println!("{}", outcome.message);
            warn_if_published_head_trails(outcome.latest.event_count, outcome.current_count);
            if let Some((_, grants_outcome)) = &grants {
                println!("{}", grants_outcome.message);
                warn_if_published_grants_trail(
                    grants_outcome.latest.record_count,
                    grants_outcome.current_record_count,
                );
            }
            if let Some(local) = &unpublished_grants_log {
                println!(
                    "note: a grants-witness log exists at {local} but is not being published — \
                     pass --grants <published-grants.jsonl> to retain grant history off-host"
                );
            }
            0
        }
        CliOutput::Json => {
            let mut value = serde_json::json!({
                "status": "ok",
                "level": level,
                "tool": PUBLISH_TOOL,
                "action": outcome.action,
                "published_heads_path": path,
                "local_witness_log_path": witness_log_path(),
                "local_signed_head_count": outcome.local_head_count,
                "published_signed_head_count": outcome.published_head_count,
                "latest_published_count": outcome.latest.event_count,
                "current_event_count": outcome.current_count,
                "unwitnessed_events": unwitnessed_events(outcome.latest.event_count, outcome.current_count),
                "coverage": coverage_status(outcome.latest.event_count, outcome.current_count),
                "latest_head": signed_head_json(&outcome.latest),
                "message": outcome.message,
            });
            if let Some((grants_path, grants_outcome)) = &grants {
                value["grants"] = grants_publish_json(grants_path, grants_outcome);
            }
            if let Some(local) = &unpublished_grants_log {
                value["unpublished_grants_witness_log"] = serde_json::json!(local);
            }
            print_json_stdout(&value)
        }
    }
}

struct PublishOutcome {
    action: &'static str,
    message: String,
    latest: SignedTreeHead,
    local_head_count: usize,
    published_head_count: usize,
    current_count: u64,
}

fn publish_outcome(path: &str) -> Result<PublishOutcome, WitnessFailure> {
    let events = load_events().map_err(|error| ("failed", error, 1))?;
    let verifying = load_verifying_key().map_err(|error| ("failed", error, 1))?;
    let local_heads = load_witness_log().map_err(|error| ("failed", error, 1))?;
    let latest = local_heads
        .last()
        .cloned()
        .ok_or_else(|| ("failed", empty_witness_log_message(), 1))?;
    verify_heads_for_publish(&events, &local_heads, &verifying, "local witness log")?;

    let mut published =
        load_signed_heads(path, "published heads", true).map_err(|error| ("failed", error, 1))?;
    let already_published = publication_state(path, &published, &latest)?;
    if !already_published {
        published.push(latest.clone());
    }
    verify_heads_for_publish(&events, &published, &verifying, "published-head")?;

    let (action, message) = if already_published {
        (
            "already_published",
            format!(
                "OK: latest witness head at count {} is already published in {path}",
                latest.event_count
            ),
        )
    } else {
        append_head(path, &latest).map_err(|error| ("failed", error, 1))?;
        (
            "appended",
            format!(
                "published witness head: count={} head={} -> appended to {path}",
                latest.event_count,
                latest.head.as_deref().unwrap_or("(empty log)")
            ),
        )
    };

    Ok(PublishOutcome {
        action,
        message,
        latest,
        local_head_count: local_heads.len(),
        published_head_count: published.len(),
        current_count: events.len() as u64,
    })
}

fn empty_witness_log_message() -> String {
    format!(
        "no signed tree heads in {} yet (run `dent8 witness sign` or `serve`)",
        witness_log_path()
    )
}

fn verify_heads_for_publish(
    events: &[FactEvent],
    heads: &[SignedTreeHead],
    verifying: &VerifyingKey,
    label: &str,
) -> Result<(), WitnessFailure> {
    match verify_heads(events, heads, verifying) {
        Ok(()) => Ok(()),
        Err(WitnessFault::CannotVerify(message)) => Err((
            "cannot_verify",
            format!("{label} verification could not be performed: {message}"),
            2,
        )),
        Err(WitnessFault::Detected(verdict, message)) => Err((verdict.status(), message, 1)),
    }
}

/// A failed witness outcome as `(status, message, exit_code)` — the `status` is the
/// machine-readable verdict fed to [`print_witness_fault`].
type WitnessFailure = (&'static str, String, i32);

fn publication_state(
    path: &str,
    published: &[SignedTreeHead],
    latest: &SignedTreeHead,
) -> Result<bool, WitnessFailure> {
    match published.last() {
        Some(previous) if previous.event_count > latest.event_count => Err((
            "rollback",
            format!(
                "ROLLBACK: published heads in {path} are already at count {}, ahead of the \
                 local witness log's latest count {}",
                previous.event_count, latest.event_count
            ),
            1,
        )),
        Some(previous) if previous.event_count == latest.event_count && previous != latest => {
            Err((
                "conflict",
                format!(
                    "CONFLICT: published head at count {} does not match the local witness head",
                    latest.event_count
                ),
                1,
            ))
        }
        Some(previous) if previous.event_count == latest.event_count => Ok(true),
        Some(_) | None => Ok(false),
    }
}

/// Verify the witness log against the current event log and public key.
#[allow(clippy::too_many_lines)] // two lanes (event log + grant log) in one linear pass
pub fn verify(output: CliOutput) -> i32 {
    let events = match load_events() {
        Ok(events) => events,
        Err(error) => {
            return print_witness_error(output, VERIFY_TOOL, &error, 1);
        }
    };
    let verifying = match load_verifying_key() {
        Ok(key) => key,
        Err(error) => {
            return print_witness_error(output, VERIFY_TOOL, &error, 1);
        }
    };
    let heads = match load_witness_log() {
        Ok(heads) => heads,
        Err(error) => {
            return print_witness_error(output, VERIFY_TOOL, &error, 1);
        }
    };
    if heads.is_empty() {
        let message = format!(
            "no signed tree heads in {} — nothing to verify (run `dent8 witness sign`)",
            witness_log_path()
        );
        return match output {
            CliOutput::Text => {
                println!("{message}");
                0
            }
            CliOutput::Json => print_json_stdout(&serde_json::json!({
                "status": "ok",
                "level": "warn",
                "tool": VERIFY_TOOL,
                "witness_log_path": witness_log_path(),
                "public_key_path": verifying_key_path(),
                "signed_head_count": 0,
                "latest_witnessed_count": 0,
                "current_event_count": events.len(),
                "unwitnessed_events": events.len(),
                "coverage": "none",
                "message": message,
            })),
        };
    }
    match verify_heads(&events, &heads, &verifying) {
        Ok(()) => {
            // Grant-log lane (ADR 0014 follow-up): a fault here is a fault, full stop.
            let grant_lane = match verify_grant_log_heads(&verifying) {
                Ok(lane) => lane,
                Err(WitnessFault::CannotVerify(message)) => {
                    let message =
                        format!("grant-log verification could not be performed: {message}");
                    return print_witness_fault(output, VERIFY_TOOL, "cannot_verify", &message, 2);
                }
                Err(WitnessFault::Detected(verdict, message)) => {
                    return print_witness_fault(output, VERIFY_TOOL, verdict.status(), &message, 1);
                }
            };
            let head_count = heads.last().map_or(0, |sth| sth.event_count);
            let current_count = events.len() as u64;
            let mut message = format!(
                "OK: {} signed tree head(s) verify — the log is append-only consistent with the \
                 witness (latest witnessed count {head_count}, current log {current_count} events)",
                heads.len()
            );
            if let Some(grant_heads) = grant_lane {
                use std::fmt::Write as _;
                let _ = write!(
                    message,
                    "; {grant_heads} grant-log head(s) verify (grant history is append-only)"
                );
            }
            match output {
                CliOutput::Text => {
                    println!("{message}");
                    0
                }
                CliOutput::Json => print_json_stdout(&serde_json::json!({
                    "status": "ok",
                    "level": coverage_level(head_count, current_count),
                    "tool": VERIFY_TOOL,
                    "witness_log_path": witness_log_path(),
                    "public_key_path": verifying_key_path(),
                    "signed_head_count": heads.len(),
                    "latest_witnessed_count": head_count,
                    "current_event_count": current_count,
                    "unwitnessed_events": unwitnessed_events(head_count, current_count),
                    "coverage": coverage_status(head_count, current_count),
                    "latest_head": heads.last().map(signed_head_json),
                    "message": message,
                })),
            }
        }
        Err(WitnessFault::CannotVerify(message)) => {
            let message = format!("verification could not be performed: {message}");
            print_witness_fault(output, VERIFY_TOOL, "cannot_verify", &message, 2)
        }
        Err(WitnessFault::Detected(verdict, message)) => {
            print_witness_fault(output, VERIFY_TOOL, verdict.status(), &message, 1)
        }
    }
}

/// Verify externally published signed heads against the current event log and public key.
///
/// This is the monitor-side check for the residual that local `witness verify` cannot close:
/// the witness log itself can be rolled back by someone who controls the writer's storage. A
/// published-heads file is expected to live somewhere outside that control boundary (CI
/// artifact, Git history, object storage, another host) and contain JSON lines printed by
/// `dent8 witness head`.
#[allow(clippy::too_many_lines)] // two lanes (event heads + grant-log heads) in one linear pass
pub fn verify_published(args: &[String], output: CliOutput) -> i32 {
    let (path, grants_path) = match args {
        [path] => (path, None),
        [path, flag, grants] if flag == "--grants" => (path, Some(grants)),
        _ => {
            return print_witness_usage(
                output,
                VERIFY_PUBLISHED_TOOL,
                "dent8 witness verify-published <published-heads.jsonl> [--grants <published-grants.jsonl>]",
            );
        }
    };
    let events = match load_events() {
        Ok(events) => events,
        Err(error) => {
            return print_witness_error(output, VERIFY_PUBLISHED_TOOL, &error, 1);
        }
    };
    let verifying = match load_verifying_key() {
        Ok(key) => key,
        Err(error) => {
            return print_witness_error(output, VERIFY_PUBLISHED_TOOL, &error, 1);
        }
    };
    let heads = match load_signed_heads(path, "published heads", false) {
        Ok(heads) => heads,
        Err(error) => {
            return print_witness_error(output, VERIFY_PUBLISHED_TOOL, &error, 1);
        }
    };
    if heads.is_empty() {
        let message = format!(
            "no published signed tree heads in {path} — cannot prove external witness coverage"
        );
        return print_witness_error(output, VERIFY_PUBLISHED_TOOL, &message, 1);
    }
    match verify_heads(&events, &heads, &verifying) {
        Ok(()) => {
            let grants = match grants_path {
                Some(grants_path) => match verify_published_grants(grants_path, &verifying) {
                    Ok(summary) => Some(summary),
                    Err((status, message, code)) => {
                        return print_witness_fault(
                            output,
                            VERIFY_PUBLISHED_TOOL,
                            status,
                            &message,
                            code,
                        );
                    }
                },
                None => None,
            };
            let head_count = heads.last().map_or(0, |sth| sth.event_count);
            let current = events.len() as u64;
            let mut level = coverage_level(head_count, current);
            if let Some(summary) = &grants
                && coverage_level(summary.latest_record_count, summary.current_record_count)
                    == "warn"
            {
                level = "warn";
            }
            let event_body = if head_count == current {
                format!(
                    "{} published signed tree head(s) verify from {path} — latest published \
                     count {head_count}, current log {current} events",
                    heads.len()
                )
            } else {
                let published_heads = heads.len();
                let unwitnessed = current.saturating_sub(head_count);
                format!(
                    "{published_heads} published signed tree head(s) verify from {path}, but latest \
                     published count {head_count} trails current log {current} by {unwitnessed} \
                     unwitnessed event(s)"
                )
            };
            let grants_body = grants.as_ref().map_or_else(String::new, |summary| {
                if summary.latest_record_count == summary.current_record_count {
                    format!(
                        "; {} published grant-log head(s) verify from {} (latest record count \
                         {}, current grant log {})",
                        summary.head_count,
                        summary.path,
                        summary.latest_record_count,
                        summary.current_record_count
                    )
                } else {
                    format!(
                        "; {} published grant-log head(s) verify from {}, but latest published \
                         record count {} trails current grant log {} by {} record(s)",
                        summary.head_count,
                        summary.path,
                        summary.latest_record_count,
                        summary.current_record_count,
                        summary
                            .current_record_count
                            .saturating_sub(summary.latest_record_count)
                    )
                }
            });
            let prefix = if level == "warn" { "WARN" } else { "OK" };
            let message = format!("{prefix}: {event_body}{grants_body}");
            match output {
                CliOutput::Text => {
                    println!("{message}");
                    0
                }
                CliOutput::Json => {
                    let mut value = serde_json::json!({
                        "status": "ok",
                        "level": level,
                        "tool": VERIFY_PUBLISHED_TOOL,
                        "published_heads_path": path,
                        "public_key_path": verifying_key_path(),
                        "published_signed_head_count": heads.len(),
                        "latest_published_count": head_count,
                        "current_event_count": current,
                        "unwitnessed_events": unwitnessed_events(head_count, current),
                        "coverage": coverage_status(head_count, current),
                        "latest_head": heads.last().map(signed_head_json),
                        "message": message,
                    });
                    if let Some(summary) = &grants {
                        value["grants"] = published_grants_json(summary);
                    }
                    print_json_stdout(&value)
                }
            }
        }
        Err(WitnessFault::CannotVerify(message)) => {
            let message = format!("published-head verification could not be performed: {message}");
            print_witness_fault(output, VERIFY_PUBLISHED_TOOL, "cannot_verify", &message, 2)
        }
        Err(WitnessFault::Detected(verdict, message)) => {
            print_witness_fault(output, VERIFY_PUBLISHED_TOOL, verdict.status(), &message, 1)
        }
    }
}

/// The verified state of an external published-grants sequence, for output shaping.
struct PublishedGrantsSummary {
    path: String,
    head_count: usize,
    latest_record_count: u64,
    current_record_count: u64,
    latest: GrantLogHead,
}

fn verify_published_grants(
    path: &str,
    verifying: &VerifyingKey,
) -> Result<PublishedGrantsSummary, WitnessFailure> {
    let current = current_grant_log_hashes().map_err(|error| ("failed", error, 1))?;
    let heads = load_grant_log_heads(path, "published grant-log heads", false)
        .map_err(|error| ("failed", error, 1))?;
    if heads.is_empty() {
        return Err((
            "failed",
            format!(
                "no published grant-log heads in {path} — cannot prove external coverage of \
                 grant history"
            ),
            1,
        ));
    }
    match verify_grant_heads(&heads, &current, verifying) {
        Ok(head_count) => {
            let latest = heads.last().cloned().expect("checked non-empty above");
            Ok(PublishedGrantsSummary {
                path: path.to_string(),
                head_count,
                latest_record_count: latest.record_count,
                current_record_count: current.len() as u64,
                latest,
            })
        }
        Err(WitnessFault::CannotVerify(message)) => Err((
            "cannot_verify",
            format!("published grant-log head verification could not be performed: {message}"),
            2,
        )),
        Err(WitnessFault::Detected(verdict, message)) => Err((verdict.status(), message, 1)),
    }
}

fn published_grants_json(summary: &PublishedGrantsSummary) -> serde_json::Value {
    serde_json::json!({
        "published_grants_path": summary.path,
        "published_signed_head_count": summary.head_count,
        "latest_published_record_count": summary.latest_record_count,
        "current_grant_record_count": summary.current_record_count,
        "unwitnessed_records":
            summary.current_record_count.saturating_sub(summary.latest_record_count),
        "coverage": coverage_status(summary.latest_record_count, summary.current_record_count),
        "latest_head": grant_log_head_json(&summary.latest),
    })
}

fn warn_if_published_head_trails(published_count: u64, current_count: u64) {
    if published_count < current_count {
        println!(
            "WARN: published count {published_count} trails current log {current_count} by {} \
             unwitnessed event(s)",
            current_count - published_count
        );
    }
}

fn warn_if_published_grants_trail(published_count: u64, current_count: u64) {
    if published_count < current_count {
        println!(
            "WARN: published grant-log count {published_count} trails current grant log \
             {current_count} by {} record(s)",
            current_count - published_count
        );
    }
}

/// Check witness operator readiness for one side of the deployment boundary.
pub fn doctor(args: &[String], output: CliOutput) -> i32 {
    let role = match args {
        [role] if role == "writer" || role == "verifier" => WitnessDoctorRole::Writer,
        [role] if role == "signer" => WitnessDoctorRole::Signer,
        [role] if role == "both" || role == "local" => WitnessDoctorRole::Both,
        _ => {
            return print_witness_usage(
                output,
                DOCTOR_TOOL,
                "dent8 witness doctor <writer|signer|both>",
            );
        }
    };

    let lines = role.doctor_lines();
    let ok = lines.iter().all(|line| line.ok);
    match output {
        CliOutput::Text => {
            for line in lines {
                println!("{}  {}", line.level, line.message);
            }
        }
        CliOutput::Json => {
            print_json_stdout(&witness_doctor_json(role.name(), ok, &lines));
        }
    }
    i32::from(!ok)
}

fn witness_doctor_json(role: &str, ok: bool, lines: &[DoctorLine]) -> serde_json::Value {
    let mut ok_lines = Vec::new();
    let mut warn_lines = Vec::new();
    let mut fail_lines = Vec::new();
    for line in lines {
        match line.level {
            "OK" => ok_lines.push(doctor_line_json(line)),
            "WARN" => warn_lines.push(doctor_line_json(line)),
            "FAIL" => fail_lines.push(doctor_line_json(line)),
            _ => {}
        }
    }
    serde_json::json!({
        "status": if ok { "ok" } else { "failed" },
        "tool": DOCTOR_TOOL,
        "role": role,
        "ok": ok,
        "summary": {
            "ok": ok_lines.len(),
            "warn": warn_lines.len(),
            "fail": fail_lines.len(),
        },
        "sections": {
            "ok": ok_lines,
            "warn": warn_lines,
            "fail": fail_lines,
        },
        "checks": lines.iter().map(doctor_line_json).collect::<Vec<_>>(),
    })
}

fn doctor_line_json(line: &DoctorLine) -> serde_json::Value {
    serde_json::json!({
        "status": line.level.to_ascii_lowercase(),
        "level": line.level,
        "ok": line.ok,
        "message": line.message,
    })
}

pub(crate) struct DoctorLine {
    pub(crate) level: &'static str,
    pub(crate) message: String,
    pub(crate) ok: bool,
}

impl DoctorLine {
    fn ok(message: impl Into<String>) -> Self {
        Self {
            level: "OK",
            message: message.into(),
            ok: true,
        }
    }

    fn warn(message: impl Into<String>) -> Self {
        Self {
            level: "WARN",
            message: message.into(),
            ok: true,
        }
    }

    fn fail(message: impl Into<String>) -> Self {
        Self {
            level: "FAIL",
            message: message.into(),
            ok: false,
        }
    }
}

enum WitnessDoctorRole {
    Writer,
    Signer,
    Both,
}

impl WitnessDoctorRole {
    fn name(&self) -> &'static str {
        match self {
            Self::Writer => "writer",
            Self::Signer => "signer",
            Self::Both => "both",
        }
    }

    fn doctor_lines(&self) -> Vec<DoctorLine> {
        match self {
            Self::Writer => writer_doctor_lines(false),
            Self::Signer => signer_doctor_lines(),
            Self::Both => {
                let mut lines = vec![DoctorLine::warn(
                    "witness local mode: writer and signer checks are running in one process; use this only for local demos",
                )];
                lines.extend(writer_doctor_lines(true));
                lines.extend(signer_doctor_lines());
                lines
            }
        }
    }
}

fn writer_doctor_lines(allow_signing_key: bool) -> Vec<DoctorLine> {
    let mut lines = vec![DoctorLine::ok(
        "witness writer env: checking verifier-side configuration",
    )];
    match env_value("DENT8_WITNESS_LOG") {
        Some(path) => lines.push(witness_log_line("witness writer env", &path)),
        None => lines.push(DoctorLine::fail(
            "witness writer env: set DENT8_WITNESS_LOG to the signed-head log path",
        )),
    }
    match env_value("DENT8_WITNESS_PUBKEY") {
        Some(path) => match load_verifying_key_from(&path) {
            Ok(_) => lines.push(DoctorLine::ok(format!(
                "witness writer env: public key {path} decodes"
            ))),
            Err(error) => lines.push(DoctorLine::fail(format!("witness writer env: {error}"))),
        },
        None => lines.push(DoctorLine::fail(
            "witness writer env: set DENT8_WITNESS_PUBKEY to the witness public key",
        )),
    }
    match env_value("DENT8_WITNESS_KEY") {
        Some(_) if allow_signing_key => lines.push(DoctorLine::warn(
            "witness writer env: DENT8_WITNESS_KEY is set; acceptable only for local demos",
        )),
        Some(_) => lines.push(DoctorLine::fail(
            "witness writer env: DENT8_WITNESS_KEY is set; remove the private signing key from writer/agent/MCP environment",
        )),
        None => lines.push(DoctorLine::ok(
            "witness writer env: DENT8_WITNESS_KEY is not set",
        )),
    }
    lines
}

fn signer_doctor_lines() -> Vec<DoctorLine> {
    let mut lines = vec![DoctorLine::ok(
        "witness signer env: checking signing-side configuration",
    )];
    match env_value("DENT8_WITNESS_LOG") {
        Some(path) => lines.push(witness_log_line("witness signer env", &path)),
        None => lines.push(DoctorLine::fail(
            "witness signer env: set DENT8_WITNESS_LOG to the signed-head log path",
        )),
    }
    let Some(key_path) = env_value("DENT8_WITNESS_KEY") else {
        lines.push(DoctorLine::fail(
            "witness signer env: set DENT8_WITNESS_KEY to the private witness signing key",
        ));
        return lines;
    };

    let signing = match load_signing_key_from(&key_path) {
        Ok(signing) => {
            lines.push(DoctorLine::ok(format!(
                "witness signer env: signing key {key_path} decodes"
            )));
            Some(signing)
        }
        Err(error) => {
            lines.push(DoctorLine::fail(format!("witness signer env: {error}")));
            None
        }
    };
    lines.push(secret_permissions_line("witness signer env", &key_path));

    let pubkey_path =
        env_value("DENT8_WITNESS_PUBKEY").unwrap_or_else(|| public_key_path(&key_path));
    match (signing.as_ref(), load_verifying_key_from(&pubkey_path)) {
        (Some(signing), Ok(verifying))
            if verifying.to_bytes() == signing.verifying_key().to_bytes() =>
        {
            lines.push(DoctorLine::ok(format!(
                "witness signer env: public key {pubkey_path} matches the signing key"
            )));
        }
        (Some(_), Ok(_)) => lines.push(DoctorLine::fail(format!(
            "witness signer env: public key {pubkey_path} does not match the signing key"
        ))),
        (None, Ok(_)) => {}
        (_, Err(error)) => lines.push(DoctorLine::fail(format!("witness signer env: {error}"))),
    }
    lines
}

fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn witness_log_line(prefix: &str, path: &str) -> DoctorLine {
    let path_ref = std::path::Path::new(path);
    match std::fs::metadata(path_ref) {
        Ok(metadata) if metadata.is_file() => {
            DoctorLine::ok(format!("{prefix}: witness log {path} exists"))
        }
        Ok(_) => DoctorLine::fail(format!("{prefix}: witness log {path} is not a file")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent_ready = path_ref
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .is_none_or(std::path::Path::exists);
            if parent_ready {
                DoctorLine::warn(format!(
                    "{prefix}: witness log {path} does not exist yet; it will be created on first signature"
                ))
            } else {
                DoctorLine::fail(format!(
                    "{prefix}: parent directory for witness log {path} does not exist"
                ))
            }
        }
        Err(error) => {
            DoctorLine::fail(format!("{prefix}: cannot stat witness log {path}: {error}"))
        }
    }
}

fn secret_permissions_line(prefix: &str, path: &str) -> DoctorLine {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::metadata(path) {
            Ok(metadata) => {
                let mode = metadata.permissions().mode() & 0o777;
                let group_or_other = mode & 0o077;
                if group_or_other == 0 {
                    DoctorLine::ok(format!("{prefix}: signing key permissions are owner-only"))
                } else {
                    DoctorLine::fail(format!(
                        "{prefix}: signing key {path} has permissions {mode:o}; expected 600 or stricter"
                    ))
                }
            }
            Err(error) => {
                DoctorLine::fail(format!("{prefix}: cannot stat signing key {path}: {error}"))
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        DoctorLine::warn(format!(
            "{prefix}: signing key permissions were not checked on this platform"
        ))
    }
}

pub(crate) fn doctor_status() -> Vec<DoctorLine> {
    if !witness_configured() {
        return vec![DoctorLine::warn(
            "witness: not configured (optional; set DENT8_WITNESS_LOG + DENT8_WITNESS_PUBKEY for signed tree heads)",
        )];
    }

    let log_path = witness_log_path();
    let pubkey_path = verifying_key_path();
    let mut lines = vec![DoctorLine::ok(format!(
        "witness: log {log_path}; public key {pubkey_path}"
    ))];

    if std::env::var("DENT8_WITNESS_KEY").is_ok_and(|value| !value.trim().is_empty()) {
        lines.push(DoctorLine::warn(
            "witness: DENT8_WITNESS_KEY is present in this process; fine for dev, but an operated witness keeps the signing key off the writer",
        ));
    }

    let events = match load_events() {
        Ok(events) => events,
        Err(error) => {
            lines.push(DoctorLine::fail(format!(
                "witness: cannot load event log: {error}"
            )));
            return lines;
        }
    };
    let heads = match load_witness_log() {
        Ok(heads) => heads,
        Err(error) => {
            lines.push(DoctorLine::fail(format!("witness: {error}")));
            return lines;
        }
    };
    if heads.is_empty() {
        let pubkey_note = if std::path::Path::new(&pubkey_path).exists() {
            format!("public key {pubkey_path} is present")
        } else {
            format!("public key {pubkey_path} is missing")
        };
        lines.push(DoctorLine::warn(format!(
            "witness verify: no signed tree heads in {log_path}; {pubkey_note}; run `dent8 witness sign` or `serve`"
        )));
        return lines;
    }

    let verifying = match load_verifying_key() {
        Ok(key) => key,
        Err(error) => {
            lines.push(DoctorLine::fail(format!("witness: {error}")));
            return lines;
        }
    };
    match verify_heads(&events, &heads, &verifying) {
        Ok(()) => {
            let latest = heads.last().map_or(0, |head| head.event_count);
            let current = events.len() as u64;
            if latest == current {
                lines.push(DoctorLine::ok(format!(
                    "witness verify: {} signed tree head(s) verify; latest witnessed count {latest}, current log {current}",
                    heads.len()
                )));
            } else {
                let unwitnessed = current.saturating_sub(latest);
                lines.push(DoctorLine::warn(format!(
                    "witness verify: {} signed tree head(s) verify, but latest witnessed count {latest} trails current log {current} by {unwitnessed} unwitnessed event(s)",
                    heads.len()
                )));
            }
        }
        Err(WitnessFault::CannotVerify(message)) => {
            lines.push(DoctorLine::fail(format!(
                "witness verify: could not verify signed heads: {message}"
            )));
        }
        Err(WitnessFault::Detected(_, message)) => {
            lines.push(DoctorLine::fail(format!("witness verify: {message}")));
        }
    }
    lines
}

fn witness_configured() -> bool {
    std::env::var("DENT8_WITNESS_LOG").is_ok_and(|value| !value.trim().is_empty())
        || std::env::var("DENT8_WITNESS_PUBKEY").is_ok_and(|value| !value.trim().is_empty())
        || std::env::var("DENT8_WITNESS_KEY").is_ok_and(|value| !value.trim().is_empty())
        || std::path::Path::new(&witness_log_path()).exists()
}

/// What a detected witness inconsistency *is*, as a machine-readable verdict: a monitor
/// alerting on `dent8 --output json witness verify` must be able to distinguish "history was
/// rewritten" from "the log was truncated/reordered" without parsing prose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WitnessVerdict {
    /// An already-witnessed prefix no longer verifies — history was rewritten (or the wrong
    /// public key is configured).
    Tamper,
    /// The log (or the witness log itself) went backwards below a witnessed count.
    Rollback,
}

impl WitnessVerdict {
    fn status(self) -> &'static str {
        match self {
            Self::Tamper => "tamper",
            Self::Rollback => "rollback",
        }
    }
}

/// A witness-verification outcome other than success: a detected inconsistency (typed by
/// [`WitnessVerdict`]) versus an inability to even perform the check.
enum WitnessFault {
    Detected(WitnessVerdict, String),
    CannotVerify(String),
}

/// The pure verification core: every signed tree head must (a) have a non-decreasing count
/// (the witness log is append-only), (b) not exceed the current log length (no truncation
/// below a witnessed count), and (c) verify against the log's prefix of that length (no
/// rewrite of already-witnessed history, under the witness's public key). Returns the first
/// fault, or `Ok(())` if all heads are consistent.
fn verify_heads(
    events: &[FactEvent],
    heads: &[SignedTreeHead],
    verifying: &VerifyingKey,
) -> Result<(), WitnessFault> {
    let mut previous_count = 0u64;
    for (index, sth) in heads.iter().enumerate() {
        if sth.event_count < previous_count {
            return Err(WitnessFault::Detected(
                WitnessVerdict::Rollback,
                format!(
                    "ROLLBACK: witness head #{index} commits to count {} but an earlier head \
                     committed to {previous_count} — the witness log went backwards (reordered \
                     or rolled back)",
                    sth.event_count
                ),
            ));
        }
        previous_count = sth.event_count;
        let count = usize::try_from(sth.event_count).map_err(|_| {
            WitnessFault::CannotVerify("witnessed count overflows usize".to_string())
        })?;
        if count > events.len() {
            return Err(WitnessFault::Detected(
                WitnessVerdict::Rollback,
                format!(
                    "ROLLBACK: a tree head was witnessed at count {} but the current log has \
                     only {} events — the log was truncated below a witnessed point",
                    sth.event_count,
                    events.len()
                ),
            ));
        }
        match verify_signed_head(&events[..count], sth, verifying) {
            Ok(true) => {}
            Ok(false) => {
                return Err(WitnessFault::Detected(
                    WitnessVerdict::Tamper,
                    format!(
                        "TAMPER: the head witnessed at count {} does not verify against the \
                         current log's prefix — history at or before that point was rewritten \
                         (or this is the wrong public key)",
                        sth.event_count
                    ),
                ));
            }
            Err(error) => {
                return Err(WitnessFault::CannotVerify(format!(
                    "at count {}: {error}",
                    sth.event_count
                )));
            }
        }
    }
    Ok(())
}

// ---- key + witness-log persistence ---------------------------------------------------

fn load_signing_key() -> Result<SigningKey, String> {
    let path = key_path();
    load_signing_key_from(&path)
}

fn load_signing_key_from(path: &str) -> Result<SigningKey, String> {
    let raw = std::fs::read_to_string(path).map_err(|error| {
        format!("cannot read witness key {path}: {error} (run `dent8 witness keygen`)")
    })?;
    let bytes = decode_key_bytes(raw.trim(), path)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn load_verifying_key() -> Result<VerifyingKey, String> {
    let path = verifying_key_path();
    load_verifying_key_from(&path)
}

fn load_verifying_key_from(path: &str) -> Result<VerifyingKey, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read witness public key {path}: {error}"))?;
    let bytes = decode_key_bytes(raw.trim(), path)?;
    VerifyingKey::from_bytes(&bytes).map_err(|error| format!("{path}: invalid public key: {error}"))
}

/// Decode a 32-byte key from a hex string, with clear errors.
fn decode_key_bytes(raw: &str, path: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(raw).map_err(|error| format!("{path}: not valid hex: {error}"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("{path}: expected a 32-byte (64-hex) key"))
}

fn load_witness_log() -> Result<Vec<SignedTreeHead>, String> {
    let path = witness_log_path();
    load_signed_heads(&path, "witness log", true)
}

fn load_signed_heads(
    path: &str,
    label: &str,
    missing_is_empty: bool,
) -> Result<Vec<SignedTreeHead>, String> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if missing_is_empty && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(format!("cannot read {label} {path}: {error}")),
    };
    contents
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(number, line)| {
            serde_json::from_str(line).map_err(|error| {
                format!("{path}:{}: corrupt signed tree head: {error}", number + 1)
            })
        })
        .collect()
}

fn append_line(path: &str, line: &str) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open {path}: {error}"))?;
    writeln!(file, "{line}").map_err(|error| format!("cannot append to {path}: {error}"))
}

/// Serialize a signed tree head to one JSON line and append it to the witness log.
fn append_head(path: &str, sth: &SignedTreeHead) -> Result<(), String> {
    let line = serde_json::to_string(sth)
        .map_err(|error| format!("could not serialize the tree head: {error}"))?;
    append_line(path, &line)
}

/// Write a secret to `path`, owner-read/write only where the platform supports it.
fn write_secret(path: &str, contents: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot create {path}: {error}"))?;
    writeln!(file, "{contents}").map_err(|error| format!("cannot write {path}: {error}"))
}

// ---- grant-log witness lane (ADR 0014 follow-up) --------------------------------------
//
// The grant log is issuer-signed and hash-chained, but its TAIL can be truncated (hiding a
// fresh revocation) undetectably from the file alone — the same residual the event log has.
// Same remedy: the witness signs `(record_count, head)` over the grant log into its own
// appended sequence, and `witness verify` re-checks every signed head against the current
// grant log's prefix. Requires both the witness key (this module) and the identity feature
// (the grant log lives there); builds without `identity` skip the lane.

/// One signed grant-log head: `(record_count, hash of the last record line)` under the
/// witness key. Strict deserialization — a security artifact. The head *machinery* is
/// feature-independent (publishing and re-checking an external sequence needs no identity
/// bundle); only reading the local grant log itself requires the `identity` feature.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantLogHead {
    record_count: u64,
    /// Lowercase-hex SHA-256 of the last grant-record line, or `None` for an empty log.
    head: Option<String>,
    /// Lowercase-hex Ed25519 over the framed `(record_count, head)` message.
    signature: String,
}

#[derive(serde::Serialize)]
struct GrantLogHeadPayload<'a> {
    record_count: u64,
    head: Option<&'a str>,
}

const GRANT_LOG_HEAD_DOMAIN: &[u8] = b"dent8.grant-log-head.v1\0";
const DEFAULT_GRANTS_WITNESS_LOG: &str = "dent8-witness-grants.jsonl";

fn grants_witness_log_path() -> String {
    std::env::var("DENT8_WITNESS_GRANTS_LOG")
        .unwrap_or_else(|_| DEFAULT_GRANTS_WITNESS_LOG.to_string())
}

fn grant_log_head_json(head: &GrantLogHead) -> serde_json::Value {
    serde_json::to_value(head).expect("grant-log head should serialize")
}

fn load_grant_log_heads(
    path: &str,
    label: &str,
    missing_is_empty: bool,
) -> Result<Vec<GrantLogHead>, String> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if missing_is_empty && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(format!("cannot read {label} {path}: {error}")),
    };
    contents
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(number, line)| {
            serde_json::from_str(line)
                .map_err(|error| format!("{path}:{}: corrupt grant-log head: {error}", number + 1))
        })
        .collect()
}

/// The line hashes of the *current* grant log — the ground truth every signed grant-log head
/// is re-checked against. Explicit-lane callers (`--grants`) go through this: a build without
/// the identity feature cannot see grant logs, and an explicit request must fail closed
/// rather than silently verify nothing.
#[cfg(feature = "identity")]
fn current_grant_log_hashes() -> Result<Vec<String>, String> {
    Ok(crate::identity::grant_log_line_hashes()?
        .map(|(_, hashes)| hashes)
        .unwrap_or_default())
}

#[cfg(not(feature = "identity"))]
fn current_grant_log_hashes() -> Result<Vec<String>, String> {
    Err(
        "the grant-log lane needs the identity feature — this build was compiled without it"
            .to_string(),
    )
}

fn grant_log_head_message(record_count: u64, head: Option<&str>) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(&GrantLogHeadPayload { record_count, head })
        .map_err(|error| format!("canonicalize grant-log head: {error}"))?;
    let mut message = Vec::with_capacity(GRANT_LOG_HEAD_DOMAIN.len() + 8 + body.len());
    message.extend_from_slice(GRANT_LOG_HEAD_DOMAIN);
    message.extend_from_slice(&(body.len() as u64).to_be_bytes());
    message.extend_from_slice(&body);
    Ok(message)
}

/// One grant-log head signing, structured for output shaping: the head itself plus the
/// paths involved (for the human line and the JSON fields).
struct GrantLaneSigned {
    head: GrantLogHead,
    grant_log: std::path::PathBuf,
    lane_path: String,
}

impl GrantLaneSigned {
    fn message(&self) -> String {
        format!(
            "signed grant-log head: count={} ({}) -> appended to {}",
            self.head.record_count,
            self.grant_log.display(),
            self.lane_path
        )
    }
}

/// Sign the current grant-log head, if a grant log is discoverable. Returns `None` when
/// there is no grant log (not an error — witness-only setups are legitimate).
#[cfg(feature = "identity")]
fn sign_grant_log_head(signing: &SigningKey) -> Result<Option<GrantLaneSigned>, String> {
    use ed25519_dalek::Signer as _;
    let Some((grant_log, hashes)) = crate::identity::grant_log_line_hashes()? else {
        return Ok(None);
    };
    let record_count = hashes.len() as u64;
    let head = hashes.last().cloned();
    let message = grant_log_head_message(record_count, head.as_deref())?;
    let signed = GrantLogHead {
        record_count,
        head,
        signature: hex::encode(signing.sign(&message).to_bytes()),
    };
    let path = grants_witness_log_path();
    let line = serde_json::to_string(&signed)
        .map_err(|error| format!("serialize grant-log head: {error}"))?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|error| format!("cannot open {path}: {error}"))?;
    file.write_all(format!("{line}\n").as_bytes())
        .map_err(|error| format!("cannot append to {path}: {error}"))?;
    Ok(Some(GrantLaneSigned {
        head: signed,
        grant_log,
        lane_path: path,
    }))
}

// The wrap is load-bearing: the signature must match the cfg(identity) twin above, whose
// errors are real.
#[cfg(not(feature = "identity"))]
#[allow(clippy::unnecessary_wraps)]
fn sign_grant_log_head(_signing: &SigningKey) -> Result<Option<GrantLaneSigned>, String> {
    Ok(None)
}

/// `serve`'s growth-triggered wrapper for the grant-log lane: sign a new head only when the
/// grant log's `(record_count, last-line hash)` differs from the last state this process
/// signed (or was seeded with). A count that goes *down* still gets signed — the regressed
/// head in the lane's own sequence is exactly the ROLLBACK evidence `verify` renders.
#[cfg(feature = "identity")]
fn sign_grant_log_head_if_changed(
    signing: &SigningKey,
    last: &mut Option<(u64, Option<String>)>,
) -> Result<Option<GrantLaneSigned>, String> {
    let Some((_, hashes)) = crate::identity::grant_log_line_hashes()? else {
        return Ok(None);
    };
    let state = (hashes.len() as u64, hashes.last().cloned());
    if last.as_ref() == Some(&state) {
        return Ok(None);
    }
    let lane = sign_grant_log_head(signing)?;
    *last = Some(state);
    Ok(lane)
}

// The wrap is load-bearing: the signature must match the cfg(identity) twin above, whose
// errors are real.
#[cfg(not(feature = "identity"))]
#[allow(clippy::unnecessary_wraps)]
fn sign_grant_log_head_if_changed(
    _signing: &SigningKey,
    _last: &mut Option<(u64, Option<String>)>,
) -> Result<Option<GrantLaneSigned>, String> {
    Ok(None)
}

/// Verify a sequence of signed grant-log heads against the current grant log's line hashes:
/// signatures under the witness public key, non-decreasing counts, and each witnessed prefix
/// hash still matching. Returns the number of verified heads. Shared by the implicit lane in
/// `verify` and the explicit published-sequence lane (`publish`/`verify-published --grants`).
fn verify_grant_heads(
    heads: &[GrantLogHead],
    current: &[String],
    verifying: &VerifyingKey,
) -> Result<usize, WitnessFault> {
    use ed25519_dalek::Verifier as _;
    let mut previous_count = 0u64;
    for (index, head) in heads.iter().enumerate() {
        let message = grant_log_head_message(head.record_count, head.head.as_deref())
            .map_err(WitnessFault::CannotVerify)?;
        let signature = ed25519_dalek::Signature::from_slice(
            &hex::decode(&head.signature).map_err(|error| {
                WitnessFault::CannotVerify(format!(
                    "grant-log head #{}: signature hex: {error}",
                    index + 1
                ))
            })?,
        )
        .map_err(|error| {
            WitnessFault::CannotVerify(format!("grant-log head #{}: signature: {error}", index + 1))
        })?;
        verifying.verify(&message, &signature).map_err(|_| {
            WitnessFault::Detected(
                WitnessVerdict::Tamper,
                format!(
                    "TAMPER: grant-log head #{} does not verify under the witness key",
                    index + 1
                ),
            )
        })?;
        if head.record_count < previous_count {
            return Err(WitnessFault::Detected(
                WitnessVerdict::Rollback,
                format!(
                    "ROLLBACK: grant-log witness went backwards at head #{} ({} after {})",
                    index + 1,
                    head.record_count,
                    previous_count
                ),
            ));
        }
        previous_count = head.record_count;
        let count = usize::try_from(head.record_count).map_err(|_| {
            WitnessFault::CannotVerify("grant-log head count overflows usize".to_string())
        })?;
        if count > current.len() {
            return Err(WitnessFault::Detected(
                WitnessVerdict::Rollback,
                format!(
                    "ROLLBACK: a grant-log head was witnessed at {count} record(s) but the \
                     current grant log has only {} — a revocation may have been truncated away",
                    current.len()
                ),
            ));
        }
        if count > 0 && head.head.as_deref() != Some(current[count - 1].as_str()) {
            return Err(WitnessFault::Detected(
                WitnessVerdict::Tamper,
                format!(
                    "TAMPER: the grant log's first {count} record(s) no longer match the head \
                     witnessed at that count — grant history was rewritten"
                ),
            ));
        }
    }
    Ok(heads.len())
}

/// Verify every signed grant-log head against the CURRENT grant log: signatures under the
/// witness public key, non-decreasing counts, and each witnessed prefix hash still matching.
/// Returns `Ok(None)` when the lane is unused, `Ok(Some(count))` with the number of verified
/// heads, or the same fault taxonomy as the event lane.
#[cfg(feature = "identity")]
fn verify_grant_log_heads(verifying: &VerifyingKey) -> Result<Option<usize>, WitnessFault> {
    let path = grants_witness_log_path();
    let heads = load_grant_log_heads(&path, "grants-witness log", true)
        .map_err(WitnessFault::CannotVerify)?;
    if heads.is_empty() {
        return Ok(None);
    }
    let current = current_grant_log_hashes().map_err(WitnessFault::CannotVerify)?;
    verify_grant_heads(&heads, &current, verifying).map(Some)
}

// The wrap is load-bearing: the signature must match the cfg(identity) twin above, whose
// faults are real.
#[cfg(not(feature = "identity"))]
#[allow(clippy::unnecessary_wraps)]
fn verify_grant_log_heads(_verifying: &VerifyingKey) -> Result<Option<usize>, WitnessFault> {
    Ok(None)
}

struct GrantsPublishOutcome {
    action: &'static str,
    message: String,
    latest: GrantLogHead,
    local_head_count: usize,
    published_head_count: usize,
    current_record_count: u64,
}

fn empty_grants_witness_log_message() -> String {
    format!(
        "no signed grant-log heads in {} yet (run `dent8 witness sign` or `serve` with a grant \
         log configured)",
        grants_witness_log_path()
    )
}

fn verify_grant_heads_for_publish(
    heads: &[GrantLogHead],
    current: &[String],
    verifying: &VerifyingKey,
    label: &str,
) -> Result<(), WitnessFailure> {
    match verify_grant_heads(heads, current, verifying) {
        Ok(_) => Ok(()),
        Err(WitnessFault::CannotVerify(message)) => Err((
            "cannot_verify",
            format!("{label} verification could not be performed: {message}"),
            2,
        )),
        Err(WitnessFault::Detected(verdict, message)) => Err((verdict.status(), message, 1)),
    }
}

fn grants_publication_state(
    path: &str,
    published: &[GrantLogHead],
    latest: &GrantLogHead,
) -> Result<bool, WitnessFailure> {
    match published.last() {
        Some(previous) if previous.record_count > latest.record_count => Err((
            "rollback",
            format!(
                "ROLLBACK: published grant-log heads in {path} are already at count {}, ahead \
                 of the local grants-witness log's latest count {}",
                previous.record_count, latest.record_count
            ),
            1,
        )),
        Some(previous) if previous.record_count == latest.record_count && previous != latest => {
            Err((
                "conflict",
                format!(
                    "CONFLICT: published grant-log head at count {} does not match the local \
                     grants-witness head",
                    latest.record_count
                ),
                1,
            ))
        }
        Some(previous) if previous.record_count == latest.record_count => Ok(true),
        Some(_) | None => Ok(false),
    }
}

/// Idempotently publish the latest signed grant-log head to an external sequence — the same
/// off-host retention that closes the event lane's "drop the newest head" residual, applied
/// to grant history (ADR 0014): a writer who truncates a revocation *and* the local
/// grants-witness file still cannot shrink the published sequence.
fn publish_grants_outcome(path: &str) -> Result<GrantsPublishOutcome, WitnessFailure> {
    let current = current_grant_log_hashes().map_err(|error| ("failed", error, 1))?;
    let verifying = load_verifying_key().map_err(|error| ("failed", error, 1))?;
    let local_path = grants_witness_log_path();
    let local_heads = load_grant_log_heads(&local_path, "grants-witness log", true)
        .map_err(|error| ("failed", error, 1))?;
    let latest = local_heads
        .last()
        .cloned()
        .ok_or_else(|| ("failed", empty_grants_witness_log_message(), 1))?;
    verify_grant_heads_for_publish(
        &local_heads,
        &current,
        &verifying,
        "local grants-witness log",
    )?;

    let mut published = load_grant_log_heads(path, "published grant-log heads", true)
        .map_err(|error| ("failed", error, 1))?;
    let already_published = grants_publication_state(path, &published, &latest)?;
    if !already_published {
        published.push(latest.clone());
    }
    verify_grant_heads_for_publish(&published, &current, &verifying, "published grant-log head")?;

    let (action, message) = if already_published {
        (
            "already_published",
            format!(
                "OK: latest grant-log head at count {} is already published in {path}",
                latest.record_count
            ),
        )
    } else {
        let line = serde_json::to_string(&latest)
            .map_err(|error| ("failed", format!("serialize grant-log head: {error}"), 1))?;
        append_line(path, &line).map_err(|error| ("failed", error, 1))?;
        (
            "appended",
            format!(
                "published grant-log head: count={} -> appended to {path}",
                latest.record_count
            ),
        )
    };

    Ok(GrantsPublishOutcome {
        action,
        message,
        latest,
        local_head_count: local_heads.len(),
        published_head_count: published.len(),
        current_record_count: current.len() as u64,
    })
}

fn grants_publish_json(path: &str, outcome: &GrantsPublishOutcome) -> serde_json::Value {
    serde_json::json!({
        "action": outcome.action,
        "published_grants_path": path,
        "local_grants_witness_log_path": grants_witness_log_path(),
        "local_signed_head_count": outcome.local_head_count,
        "published_signed_head_count": outcome.published_head_count,
        "latest_published_record_count": outcome.latest.record_count,
        "current_grant_record_count": outcome.current_record_count,
        "unwitnessed_records":
            outcome.current_record_count.saturating_sub(outcome.latest.record_count),
        "coverage": coverage_status(outcome.latest.record_count, outcome.current_record_count),
        "latest_head": grant_log_head_json(&outcome.latest),
        "message": outcome.message,
    })
}

#[cfg(test)]
mod tests {
    use super::{WitnessFault, WitnessVerdict, verify_heads};
    use dent8_core::{
        AuthorityLevel, FactEvent, FactEventKind, FactValue, SignedTreeHead, TimestampMillis,
        sign_head,
    };
    use ed25519_dalek::SigningKey;

    fn event(event_id: &str, fact_id: &str, value: &str) -> FactEvent {
        crate::ops::build_event(
            event_id,
            fact_id,
            "repo",
            "myproj",
            "database",
            FactEventKind::Asserted,
            Some(FactValue::Text(value.to_string())),
            "source:owner",
            AuthorityLevel::High,
            TimestampMillis::from_unix_millis(1),
        )
        .expect("event")
    }

    fn signed(events: &[FactEvent], key: &SigningKey) -> SignedTreeHead {
        sign_head(events, key).expect("sign")
    }

    #[test]
    fn a_witnessed_append_only_log_verifies_and_a_rewrite_or_rollback_is_caught() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = key.verifying_key();
        let log = vec![
            event("event:0", "fact:a", "postgres"),
            event("event:1", "fact:b", "redis"),
            event("event:2", "fact:c", "kafka"),
        ];

        // A witness signs at count 1, then again at count 3 (the log grew, append-only).
        let sth1 = signed(&log[..1], &key);
        let sth3 = signed(&log[..3], &key);
        let heads = vec![sth1.clone(), sth3.clone()];

        // Past + present heads both verify against the grown log's matching prefixes.
        assert!(verify_heads(&log, &heads, &verifying).is_ok());

        // TAMPER: rewrite an already-witnessed event (event:1 redis -> mysql). The prefix at
        // count 3 no longer matches sth3's signature.
        let mut rewritten = log.clone();
        rewritten[1] = event("event:1", "fact:b", "mysql");
        assert!(matches!(
            verify_heads(&rewritten, &heads, &verifying),
            Err(WitnessFault::Detected(WitnessVerdict::Tamper, message)) if message.contains("TAMPER")
        ));

        // ROLLBACK: the log was truncated below a witnessed count (only 2 events, but sth3
        // committed to 3).
        assert!(matches!(
            verify_heads(&log[..2], &heads, &verifying),
            Err(WitnessFault::Detected(WitnessVerdict::Rollback, message)) if message.contains("ROLLBACK")
        ));

        // ROLLBACK: a witness log whose counts go backwards (3 then 1) is itself suspect.
        let reordered = vec![sth3, sth1];
        assert!(matches!(
            verify_heads(&log, &reordered, &verifying),
            Err(WitnessFault::Detected(WitnessVerdict::Rollback, message)) if message.contains("ROLLBACK")
        ));

        // Wrong public key: an attacker's key does not verify the witness's heads.
        let attacker = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(matches!(
            verify_heads(&log, &heads, &attacker),
            Err(WitnessFault::Detected(WitnessVerdict::Tamper, message)) if message.contains("TAMPER")
        ));
    }
}
