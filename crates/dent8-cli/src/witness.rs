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

use crate::{CliOutput, print_json_stderr, print_json_stdout};
use dent8_core::{ClaimEvent, SignedTreeHead, sign_head, verify_signed_head};
use ed25519_dalek::{SigningKey, VerifyingKey};

const DEFAULT_KEY: &str = "dent8-witness.key";
const DEFAULT_LOG: &str = "dent8-witness.jsonl";

/// `serve` bails after this many consecutive failed ticks (a deleted key, a full disk).
const MAX_CONSECUTIVE_ERRORS: u32 = 10;

const KEYGEN_TOOL: &str = "witness keygen";
const SIGN_TOOL: &str = "witness sign";
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

fn witness_error_json(tool: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": tool,
        "message": message,
    })
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

fn print_witness_error(output: CliOutput, tool: &str, message: &str, code: i32) -> i32 {
    match output {
        CliOutput::Text => {
            eprintln!("{message}");
            code
        }
        CliOutput::Json => print_json_stderr(&witness_error_json(tool, message), code),
    }
}

fn print_witness_usage(output: CliOutput, tool: &str, usage: &str) -> i32 {
    match output {
        CliOutput::Text => {
            eprintln!("usage: {usage}");
            2
        }
        CliOutput::Json => print_json_stderr(
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
fn load_events() -> Result<Vec<ClaimEvent>, String> {
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
            CliOutput::Json => print_json_stderr(
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
            CliOutput::Json => print_json_stderr(
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
    let message = format!(
        "signed tree head: count={} head={} -> appended to {path}",
        sth.event_count,
        sth.head.as_deref().unwrap_or("(empty log)"),
    );
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
            "message": message,
        })),
    }
}

/// Run as a **cadence signer** — the *operated* witness loop. Every `interval` seconds, sign
/// the head **if the log has grown** (an append-only log's head changes only when its count
/// does) and append it to the witness log. Run this on a host **separate** from the writer,
/// holding the key, so the accumulated signatures are evidence the writer cannot forge. The
/// optional second argument bounds the number of heads signed (for a finite run); without it,
/// it runs until interrupted. A later in-place rewrite is still caught by an *earlier* signed
/// head failing `verify`, so signing only on growth loses no resistance.
pub fn serve(args: &[String]) -> i32 {
    // Floor the interval at 1s: a 0s interval whose head target is never reached on a static log
    // would busy-spin the CPU (and hammer the DB on the Postgres backend).
    let interval = args
        .first()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(5)
        .max(1);
    let max_heads = args.get(1).and_then(|value| value.parse::<u64>().ok());
    let signing = match load_signing_key() {
        Ok(key) => key,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let verifying = signing.verifying_key();
    let path = witness_log_path();
    eprintln!(
        "witness: signing the head on growth every {interval}s -> {path}{} (interrupt to stop)",
        max_heads.map_or_else(String::new, |max| format!(", up to {max} head(s)"))
    );
    // Seed from any heads already on disk so growth is measured from the last witnessed point,
    // and a pre-existing head can flag a rewrite on the first growth tick.
    let mut last_signed: Option<SignedTreeHead> =
        load_witness_log().ok().and_then(|mut heads| heads.pop());
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
                    warn_if_prior_head_broken(last_signed.as_ref(), &events, &verifying);
                    match sign_head(&events, &signing)
                        .map_err(|error| error.to_string())
                        .and_then(|sth| append_head(&path, &sth).map(|()| sth))
                    {
                        Ok(sth) => {
                            signed += 1;
                            println!(
                                "signed head: count={} head={}",
                                sth.event_count,
                                sth.head.as_deref().unwrap_or("(empty log)")
                            );
                            last_signed = Some(sth);
                        }
                        Err(error) => {
                            eprintln!("witness: {error}");
                            had_error = true;
                        }
                    }
                }
            }
            Err(error) => {
                eprintln!("witness: could not load the log: {error}");
                had_error = true;
            }
        }
        errors = if had_error { errors + 1 } else { 0 };
        if errors >= MAX_CONSECUTIVE_ERRORS {
            eprintln!("witness: giving up after {errors} consecutive errors");
            return 1;
        }
        if max_heads.is_some_and(|max| signed >= max) {
            return 0;
        }
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}

/// Warn (loudly, non-fatally) if the most recent witnessed head no longer matches the current
/// log's prefix — history was rewritten or rolled back under the witness. The witness still
/// signs the new growth; the stale head remains the evidence at `verify` time.
fn warn_if_prior_head_broken(
    previous: Option<&SignedTreeHead>,
    events: &[ClaimEvent],
    verifying: &VerifyingKey,
) {
    let Some(previous) = previous else { return };
    let Ok(count) = usize::try_from(previous.event_count) else {
        return;
    };
    if count > events.len() {
        eprintln!(
            "witness: WARNING — the log shrank below a previously witnessed count {} (ROLLBACK); \
             signing the new head anyway, the earlier head is the evidence",
            previous.event_count
        );
        return;
    }
    match verify_signed_head(&events[..count], previous, verifying) {
        Ok(true) => {}
        Ok(false) => eprintln!(
            "witness: WARNING — the log no longer matches the head witnessed at count {} (history \
             was REWRITTEN); signing the new head anyway, the earlier head is the evidence",
            previous.event_count
        ),
        Err(error) => eprintln!("witness: could not check the prior head: {error}"),
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
    let [path] = args else {
        return print_witness_usage(
            output,
            PUBLISH_TOOL,
            "dent8 witness publish <published-heads.jsonl>",
        );
    };
    let outcome = match publish_outcome(path) {
        Ok(outcome) => outcome,
        Err((message, code)) => return print_witness_error(output, PUBLISH_TOOL, &message, code),
    };
    match output {
        CliOutput::Text => {
            println!("{}", outcome.message);
            warn_if_published_head_trails(outcome.latest.event_count, outcome.current_count);
            0
        }
        CliOutput::Json => print_json_stdout(&serde_json::json!({
            "status": "ok",
            "level": coverage_level(outcome.latest.event_count, outcome.current_count),
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
        })),
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

fn publish_outcome(path: &str) -> Result<PublishOutcome, (String, i32)> {
    let events = load_events().map_err(|error| (error, 1))?;
    let verifying = load_verifying_key().map_err(|error| (error, 1))?;
    let local_heads = load_witness_log().map_err(|error| (error, 1))?;
    let latest = local_heads
        .last()
        .cloned()
        .ok_or_else(|| (empty_witness_log_message(), 1))?;
    verify_heads_for_publish(&events, &local_heads, &verifying, "local witness log")?;

    let mut published =
        load_signed_heads(path, "published heads", true).map_err(|error| (error, 1))?;
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
        append_head(path, &latest).map_err(|error| (error, 1))?;
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
    events: &[ClaimEvent],
    heads: &[SignedTreeHead],
    verifying: &VerifyingKey,
    label: &str,
) -> Result<(), (String, i32)> {
    match verify_heads(events, heads, verifying) {
        Ok(()) => Ok(()),
        Err(WitnessFault::CannotVerify(message)) => Err((
            format!("{label} verification could not be performed: {message}"),
            2,
        )),
        Err(WitnessFault::Detected(message)) => Err((message, 1)),
    }
}

fn publication_state(
    path: &str,
    published: &[SignedTreeHead],
    latest: &SignedTreeHead,
) -> Result<bool, (String, i32)> {
    match published.last() {
        Some(previous) if previous.event_count > latest.event_count => Err((
            format!(
                "ROLLBACK: published heads in {path} are already at count {}, ahead of the \
                 local witness log's latest count {}",
                previous.event_count, latest.event_count
            ),
            1,
        )),
        Some(previous) if previous.event_count == latest.event_count && previous != latest => {
            Err((
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
            let head_count = heads.last().map_or(0, |sth| sth.event_count);
            let current_count = events.len() as u64;
            let message = format!(
                "OK: {} signed tree head(s) verify — the log is append-only consistent with the \
                 witness (latest witnessed count {head_count}, current log {current_count} events)",
                heads.len()
            );
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
            print_witness_error(output, VERIFY_TOOL, &message, 2)
        }
        Err(WitnessFault::Detected(message)) => {
            print_witness_error(output, VERIFY_TOOL, &message, 1)
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
pub fn verify_published(args: &[String], output: CliOutput) -> i32 {
    let [path] = args else {
        return print_witness_usage(
            output,
            VERIFY_PUBLISHED_TOOL,
            "dent8 witness verify-published <published-heads.jsonl>",
        );
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
            let head_count = heads.last().map_or(0, |sth| sth.event_count);
            let current = events.len() as u64;
            let level = coverage_level(head_count, current);
            let message = if head_count == current {
                format!(
                    "OK: {} published signed tree head(s) verify from {path} — latest published \
                     count {head_count}, current log {current} events",
                    heads.len()
                )
            } else {
                let published_heads = heads.len();
                let unwitnessed = current.saturating_sub(head_count);
                format!(
                    "WARN: {published_heads} published signed tree head(s) verify from {path}, but latest \
                     published count {head_count} trails current log {current} by {unwitnessed} \
                     unwitnessed event(s)"
                )
            };
            match output {
                CliOutput::Text => {
                    println!("{message}");
                    0
                }
                CliOutput::Json => print_json_stdout(&serde_json::json!({
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
                })),
            }
        }
        Err(WitnessFault::CannotVerify(message)) => {
            let message = format!("published-head verification could not be performed: {message}");
            print_witness_error(output, VERIFY_PUBLISHED_TOOL, &message, 2)
        }
        Err(WitnessFault::Detected(message)) => {
            print_witness_error(output, VERIFY_PUBLISHED_TOOL, &message, 1)
        }
    }
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
        Err(WitnessFault::Detected(message)) => {
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

/// A witness-verification outcome other than success: a detected inconsistency (the log was
/// rewritten/rolled back, or the key is wrong) versus an inability to even perform the check.
enum WitnessFault {
    Detected(String),
    CannotVerify(String),
}

/// The pure verification core: every signed tree head must (a) have a non-decreasing count
/// (the witness log is append-only), (b) not exceed the current log length (no truncation
/// below a witnessed count), and (c) verify against the log's prefix of that length (no
/// rewrite of already-witnessed history, under the witness's public key). Returns the first
/// fault, or `Ok(())` if all heads are consistent.
fn verify_heads(
    events: &[ClaimEvent],
    heads: &[SignedTreeHead],
    verifying: &VerifyingKey,
) -> Result<(), WitnessFault> {
    let mut previous_count = 0u64;
    for (index, sth) in heads.iter().enumerate() {
        if sth.event_count < previous_count {
            return Err(WitnessFault::Detected(format!(
                "ROLLBACK: witness head #{index} commits to count {} but an earlier head \
                 committed to {previous_count} — the witness log went backwards (reordered or \
                 rolled back)",
                sth.event_count
            )));
        }
        previous_count = sth.event_count;
        let count = usize::try_from(sth.event_count).map_err(|_| {
            WitnessFault::CannotVerify("witnessed count overflows usize".to_string())
        })?;
        if count > events.len() {
            return Err(WitnessFault::Detected(format!(
                "ROLLBACK: a tree head was witnessed at count {} but the current log has only {} \
                 events — the log was truncated below a witnessed point",
                sth.event_count,
                events.len()
            )));
        }
        match verify_signed_head(&events[..count], sth, verifying) {
            Ok(true) => {}
            Ok(false) => {
                return Err(WitnessFault::Detected(format!(
                    "TAMPER: the head witnessed at count {} does not verify against the current \
                     log's prefix — history at or before that point was rewritten (or this is \
                     the wrong public key)",
                    sth.event_count
                )));
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

#[cfg(test)]
mod tests {
    use super::{WitnessFault, verify_heads};
    use dent8_core::{
        AuthorityLevel, ClaimEvent, ClaimEventKind, ClaimValue, SignedTreeHead, TimestampMillis,
        sign_head,
    };
    use ed25519_dalek::SigningKey;

    fn event(event_id: &str, claim_id: &str, value: &str) -> ClaimEvent {
        crate::build_event(
            event_id,
            claim_id,
            "repo",
            "myproj",
            "database",
            ClaimEventKind::Asserted,
            Some(ClaimValue::Text(value.to_string())),
            "source:owner",
            AuthorityLevel::High,
            TimestampMillis::from_unix_millis(1),
        )
        .expect("event")
    }

    fn signed(events: &[ClaimEvent], key: &SigningKey) -> SignedTreeHead {
        sign_head(events, key).expect("sign")
    }

    #[test]
    fn a_witnessed_append_only_log_verifies_and_a_rewrite_or_rollback_is_caught() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying = key.verifying_key();
        let log = vec![
            event("event:0", "claim:a", "postgres"),
            event("event:1", "claim:b", "redis"),
            event("event:2", "claim:c", "kafka"),
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
        rewritten[1] = event("event:1", "claim:b", "mysql");
        assert!(matches!(
            verify_heads(&rewritten, &heads, &verifying),
            Err(WitnessFault::Detected(message)) if message.contains("TAMPER")
        ));

        // ROLLBACK: the log was truncated below a witnessed count (only 2 events, but sth3
        // committed to 3).
        assert!(matches!(
            verify_heads(&log[..2], &heads, &verifying),
            Err(WitnessFault::Detected(message)) if message.contains("ROLLBACK")
        ));

        // ROLLBACK: a witness log whose counts go backwards (3 then 1) is itself suspect.
        let reordered = vec![sth3, sth1];
        assert!(matches!(
            verify_heads(&log, &reordered, &verifying),
            Err(WitnessFault::Detected(message)) if message.contains("ROLLBACK")
        ));

        // Wrong public key: an attacker's key does not verify the witness's heads.
        let attacker = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(matches!(
            verify_heads(&log, &heads, &attacker),
            Err(WitnessFault::Detected(message)) if message.contains("TAMPER")
        ));
    }
}
