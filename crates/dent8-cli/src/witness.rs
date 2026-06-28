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
//! **This is the primitive, not a deployment.** Tamper-*resistance* (not just evidence) holds
//! only if the signing key lives **off** the log-writer's machine — a writer who also holds
//! the key can re-sign a rewrite. `keygen` prints that warning; the operational witness
//! service (a separate signer on a cadence, key rotation) is the layer above this. See the
//! threat model's T6 residuals.

use std::io::Write;

use dent8_core::{ClaimEvent, SignedTreeHead, sign_head, verify_signed_head};
use dent8_store::{EventFilter, EventStore};
use ed25519_dalek::{SigningKey, VerifyingKey};

const DEFAULT_KEY: &str = "dent8-witness.key";
const DEFAULT_LOG: &str = "dent8-witness.jsonl";

fn key_path() -> String {
    std::env::var("DENT8_WITNESS_KEY").unwrap_or_else(|_| DEFAULT_KEY.to_string())
}

fn witness_log_path() -> String {
    std::env::var("DENT8_WITNESS_LOG").unwrap_or_else(|_| DEFAULT_LOG.to_string())
}

fn public_key_path(key: &str) -> String {
    format!("{key}.pub")
}

/// The current event log in global append order — the chain `sign_head`/`verify_signed_head`
/// commit to. Backend-aware (file dev store or Postgres), reusing the same loader the rest of
/// the CLI uses.
fn load_events() -> Result<Vec<ClaimEvent>, String> {
    let store = crate::load_store(&crate::log_path())?;
    store
        .scan_events(&EventFilter::default())
        .map_err(|error| error.to_string())
}

/// Generate an Ed25519 witness keypair: the private signing key (hex, `0600`) at
/// `DENT8_WITNESS_KEY`, the public verifying key (hex) alongside as `<key>.pub`. Refuses to
/// clobber an existing key.
pub fn keygen() -> i32 {
    let key = key_path();
    if std::path::Path::new(&key).exists() {
        eprintln!("{key} already exists — refusing to overwrite a witness signing key");
        return 1;
    }
    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::getrandom(&mut seed) {
        eprintln!("could not gather randomness for the key: {error}");
        return 1;
    }
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key();
    if let Err(error) = write_secret(&key, &hex::encode(signing.to_bytes())) {
        eprintln!("{error}");
        return 1;
    }
    let public = public_key_path(&key);
    if let Err(error) = std::fs::write(&public, format!("{}\n", hex::encode(verifying.to_bytes())))
    {
        eprintln!("cannot write {public}: {error}");
        return 1;
    }
    println!(
        "wrote witness signing key to {key} (keep it OFF the log-writer's machine — that \
         separation is what gives tamper-resistance)\nwrote public verifying key to {public}"
    );
    0
}

/// Sign a tree head over the current log and append it to the witness log.
pub fn sign() -> i32 {
    let events = match load_events() {
        Ok(events) => events,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let signing = match load_signing_key() {
        Ok(key) => key,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let sth = match sign_head(&events, &signing) {
        Ok(sth) => sth,
        Err(error) => {
            eprintln!("could not sign the tree head: {error}");
            return 1;
        }
    };
    let line = match serde_json::to_string(&sth) {
        Ok(line) => line,
        Err(error) => {
            eprintln!("could not serialize the tree head: {error}");
            return 1;
        }
    };
    let path = witness_log_path();
    if let Err(error) = append_line(&path, &line) {
        eprintln!("{error}");
        return 1;
    }
    println!(
        "signed tree head: count={} head={} -> appended to {path}",
        sth.event_count,
        sth.head.as_deref().unwrap_or("(empty log)"),
    );
    0
}

/// Verify the witness log against the current event log and public key.
pub fn verify() -> i32 {
    let events = match load_events() {
        Ok(events) => events,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let verifying = match load_verifying_key() {
        Ok(key) => key,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let heads = match load_witness_log() {
        Ok(heads) => heads,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    if heads.is_empty() {
        println!(
            "no signed tree heads in {} — nothing to verify (run `dent8 witness sign`)",
            witness_log_path()
        );
        return 0;
    }
    match verify_heads(&events, &heads, &verifying) {
        Ok(()) => {
            let head_count = heads.last().map_or(0, |sth| sth.event_count);
            println!(
                "OK: {} signed tree head(s) verify — the log is append-only consistent with the \
                 witness (latest witnessed count {head_count}, current log {} events)",
                heads.len(),
                events.len()
            );
            0
        }
        Err(WitnessFault::CannotVerify(message)) => {
            eprintln!("verification could not be performed: {message}");
            2
        }
        Err(WitnessFault::Detected(message)) => {
            eprintln!("{message}");
            1
        }
    }
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
    let raw = std::fs::read_to_string(&path).map_err(|error| {
        format!("cannot read witness key {path}: {error} (run `dent8 witness keygen`)")
    })?;
    let bytes = decode_key_bytes(raw.trim(), &path)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn load_verifying_key() -> Result<VerifyingKey, String> {
    let path =
        std::env::var("DENT8_WITNESS_PUBKEY").unwrap_or_else(|_| public_key_path(&key_path()));
    let raw = std::fs::read_to_string(&path)
        .map_err(|error| format!("cannot read witness public key {path}: {error}"))?;
    let bytes = decode_key_bytes(raw.trim(), &path)?;
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
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read witness log {path}: {error}")),
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
