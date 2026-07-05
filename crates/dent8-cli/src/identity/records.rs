//! The **grant log** (ADR 0014): the append-only, issuer-signed, hash-chained history of
//! grant issuances and revocations that lets `verify` decide *entitlement at write time*
//! for attested events, and lets the witness lane detect a truncated revocation. The
//! bundle-facing lifecycle commands live in the parent module; this module owns the record
//! format, its integrity rules, and the entitlement resolution.

use std::path::{Path, PathBuf};

use dent8_core::AuthorityLevel;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use serde::{Deserialize, Serialize};

use super::{
    SignedSourceGrant, TrustedIssuers, framed, load_trust_at, nonempty_env, signature_from_hex,
    trust_path, verifying_key_from_hex,
};
use std::io::Write as _;

/// One line of the append-only grant log (ADR 0014): the issuer-signed history that lets
/// `verify` decide *entitlement at write time* for attested events. `record_signature` is the
/// issuer's Ed25519 over the domain-framed payload (everything except the signature and the
/// chain link); `previous_record_hash` chains the log so deletion/reordering is
/// tamper-evident. Strict deserialization: this is a security artifact.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantRecord {
    pub(super) action: GrantAction,
    /// The `SignedSourceGrant.signature` this record is about — the grant's stable id.
    pub(super) grant_signature: String,
    source: String,
    public_key: String,
    max_authority: AuthorityLevel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<i64>,
    at_ms: i64,
    issuer: String,
    record_signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_record_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum GrantAction {
    #[serde(rename = "issued")]
    Issued,
    #[serde(rename = "revoked")]
    Revoked,
}

/// The exact bytes a grant record's issuer signature covers: the record minus the signature
/// and chain link, domain-framed like every other dent8 signing context.
#[derive(Serialize)]
struct GrantRecordPayload<'a> {
    pub(super) action: GrantAction,
    grant_signature: &'a str,
    source: &'a str,
    public_key: &'a str,
    max_authority: AuthorityLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<i64>,
    at_ms: i64,
    issuer: &'a str,
}

const GRANT_LOG_FILE: &str = "grant-log.jsonl";
const GRANT_RECORD_DOMAIN: &[u8] = b"dent8.grant-record.v1\0";

fn grant_record_payload(record: &GrantRecord) -> GrantRecordPayload<'_> {
    GrantRecordPayload {
        action: record.action,
        grant_signature: &record.grant_signature,
        source: &record.source,
        public_key: &record.public_key,
        max_authority: record.max_authority,
        scope: record.scope.as_deref(),
        expires_at_ms: record.expires_at_ms,
        at_ms: record.at_ms,
        issuer: &record.issuer,
    }
}

fn grant_record_line_hash(line: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(line.as_bytes()))
}

pub(super) fn grant_log_path_in(dir: &Path) -> PathBuf {
    dir.join(GRANT_LOG_FILE)
}

/// The grant log a verifier should consult: `DENT8_GRANT_LOG`, or the sibling of the trust
/// registry when one exists (the same discovery shape as the active-grant registry).
fn grant_log_path_for_verify() -> Option<PathBuf> {
    if let Some(path) = nonempty_env("DENT8_GRANT_LOG") {
        return Some(PathBuf::from(path));
    }
    let candidate = Path::new(&trust_path()).parent().map_or_else(
        || PathBuf::from(GRANT_LOG_FILE),
        |parent| parent.join(GRANT_LOG_FILE),
    );
    candidate.exists().then_some(candidate)
}

/// Load the grant log, verifying line-to-line chain continuity. Signature verification
/// against the trust registry is [`verify_grant_records`] (a verifier may hold the log
/// before it holds trust).
pub(super) fn load_grant_records(path: &Path) -> Result<Vec<GrantRecord>, String> {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    let mut records = Vec::new();
    let mut previous_hash: Option<String> = None;
    for (index, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: GrantRecord = serde_json::from_str(line).map_err(|error| {
            format!(
                "{}:{}: corrupt grant record: {error}",
                path.display(),
                index + 1
            )
        })?;
        if record.previous_record_hash != previous_hash {
            return Err(format!(
                "{}:{}: grant log chain break (a record was removed, reordered, or edited)",
                path.display(),
                index + 1
            ));
        }
        previous_hash = Some(grant_record_line_hash(line));
        records.push(record);
    }
    Ok(records)
}

/// Verify every record's issuer signature against the trust registry.
fn verify_grant_records(records: &[GrantRecord], trust: &TrustedIssuers) -> Result<(), String> {
    for record in records {
        let issuer = trust
            .issuers
            .get(&record.issuer)
            .ok_or_else(|| format!("grant log: untrusted record issuer {}", record.issuer))?;
        let key = verifying_key_from_hex(&issuer.public_key)?;
        let signature = signature_from_hex(&record.record_signature)?;
        key.verify(
            &framed(GRANT_RECORD_DOMAIN, &grant_record_payload(record))?,
            &signature,
        )
        .map_err(|error| {
            format!(
                "grant log: record for {} ({:?} at {}) does not verify: {error}",
                record.source, record.action, record.at_ms
            )
        })?;
    }
    Ok(())
}

/// Append issuer-signed lifecycle records as **one write** (a rotation's revoked+issued pair
/// must land together or not at all). Chain-checks the existing log first, so a tampered log
/// refuses further appends rather than papering over the break.
pub(super) fn append_grant_records(
    path: &Path,
    issuer: &str,
    issuer_key: &SigningKey,
    entries: &[(GrantAction, &SignedSourceGrant)],
    at_ms: i64,
) -> Result<(), String> {
    load_grant_records(path)?;
    let mut previous_record_hash = match std::fs::read_to_string(path) {
        Ok(contents) => contents
            .lines()
            .rfind(|line| !line.trim().is_empty())
            .map(grant_record_line_hash),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    let mut buffer = String::new();
    for (action, grant) in entries {
        let mut record = GrantRecord {
            action: *action,
            grant_signature: grant.signature.clone(),
            source: grant.grant.source.clone(),
            public_key: grant.grant.public_key.clone(),
            max_authority: grant.grant.max_authority,
            scope: grant.grant.scope.clone(),
            expires_at_ms: grant.grant.expires_at_ms,
            at_ms,
            issuer: issuer.to_string(),
            record_signature: String::new(),
            previous_record_hash: previous_record_hash.take(),
        };
        let signature = issuer_key.sign(&framed(
            GRANT_RECORD_DOMAIN,
            &grant_record_payload(&record),
        )?);
        record.record_signature = hex::encode(signature.to_bytes());
        let line = serde_json::to_string(&record)
            .map_err(|error| format!("serialize grant record: {error}"))?;
        previous_record_hash = Some(grant_record_line_hash(&line));
        buffer.push_str(&line);
        buffer.push('\n');
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    file.write_all(buffer.as_bytes())
        .map_err(|error| format!("cannot append to {}: {error}", path.display()))
}

/// Whether the log already has an `issued` record for this exact grant (used to keep reuse
/// paths like `agent add` idempotent).
pub(super) fn has_issued_record(path: &Path, grant_signature: &str) -> Result<bool, String> {
    Ok(load_grant_records(path)?.iter().any(|record| {
        record.action == GrantAction::Issued && record.grant_signature == grant_signature
    }))
}

/// The verifier-side verdict for one attested event (ADR 0014).
pub(crate) enum Entitlement {
    Entitled,
    Unentitled(String),
    /// No history for this (source, key) — pre-history writes or a foreign bundle. Reported
    /// honestly, never failed: absence of history is not evidence of a violation.
    Unknown,
}

/// Resolve entitlement of (`source`, `public_key`) for a write at `at_ms` against the grant
/// history: the latest issuance at or before the write must not be revoked before it, not
/// expired at it, and must cover the facted authority and subject scope.
pub(crate) fn entitlement_at(
    records: &[GrantRecord],
    source: &str,
    public_key: &str,
    authority: AuthorityLevel,
    subject: &str,
    at_ms: i64,
) -> Entitlement {
    let mut active: Option<&GrantRecord> = None;
    let mut revoked_before = false;
    for record in records {
        if record.source != source || record.public_key != public_key || record.at_ms > at_ms {
            continue;
        }
        match record.action {
            GrantAction::Issued => {
                active = Some(record);
                revoked_before = false;
            }
            GrantAction::Revoked => {
                if active.is_some_and(|current| current.grant_signature == record.grant_signature) {
                    active = None;
                    revoked_before = true;
                }
            }
        }
    }
    let Some(grant) = active else {
        // Only an issuance that was explicitly ENDED before the write positively excludes it.
        // "No issuance at or before T" is indistinguishable from "history started later"
        // (e.g. a backfilled log), so it stays honest Unknown — never a fabricated violation.
        if revoked_before {
            return Entitlement::Unentitled(format!(
                "the grant for {source} had been revoked before {at_ms}"
            ));
        }
        return Entitlement::Unknown;
    };
    if let Some(expires_at) = grant.expires_at_ms
        && at_ms > expires_at
    {
        return Entitlement::Unentitled(format!(
            "the grant active for {source} had expired at {expires_at}"
        ));
    }
    if authority > grant.max_authority {
        return Entitlement::Unentitled(format!(
            "the write asserts {authority:?} but the active grant for {source} caps at {:?}",
            grant.max_authority
        ));
    }
    if let Some(scope) = grant.scope.as_deref()
        && scope != "*"
        && scope != subject
    {
        return Entitlement::Unentitled(format!(
            "the active grant for {source} is scoped to {scope:?}, not {subject}"
        ));
    }
    Entitlement::Entitled
}

/// The grant log as (path, per-record line hashes), for witness coverage (ADR 0014
/// follow-up): a signed head commits to `(record_count, hash_of_last_line)`, and a verifier
/// re-checks each witnessed count against the hash at that prefix. `Ok(None)` = no grant log
/// configured/present. The records themselves are chain-validated on load. Only the witness
/// lane consumes this, so it is gated on that feature to stay dead-code-free in stock builds.
#[cfg(feature = "witness")]
pub(crate) fn grant_log_line_hashes() -> Result<Option<(PathBuf, Vec<String>)>, String> {
    let Some(path) = grant_log_path_for_verify() else {
        return Ok(None);
    };
    let contents = match std::fs::read_to_string(&path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    // Chain-validate before vouching for line hashes.
    load_grant_records(&path)?;
    let hashes = contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(grant_record_line_hash)
        .collect();
    Ok(Some((path, hashes)))
}

/// Everything `verify` needs from the grant history, loaded and integrity-checked (chain +
/// issuer signatures). `Ok(None)` = no grant log configured/present or an empty one.
pub(crate) fn load_grant_history_for_verify() -> Result<Option<Vec<GrantRecord>>, String> {
    let Some(path) = grant_log_path_for_verify() else {
        return Ok(None);
    };
    let records = load_grant_records(&path)?;
    if records.is_empty() {
        return Ok(None);
    }
    let Some(trust) = load_trust_at(&trust_path(), false)? else {
        return Err(format!(
            "grant log {} is present but there is no trust registry to verify its records",
            path.display()
        ));
    };
    verify_grant_records(&records, &trust)?;
    Ok(Some(records))
}
