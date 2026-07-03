//! Read-only identity diagnostics: the `identity status` renderer and the `doctor` role
//! checks — trust registry, grant and active-grant registry consistency, source/issuer key
//! material, expiry warnings, and the ADR 0014 grant-log consistency line. Rendering and
//! verdicts only: every mutation lives in the parent module or `bundle`.

use std::path::Path;

use dent8_core::TimestampMillis;

use super::bundle::{
    bootstrap_issuer_key_path, default_issuer_key_path, identity_bundle_paths,
    load_issuer_key_matching_trust, path_string,
};
use super::records::{GrantAction, grant_log_path_in, load_grant_records};
use super::{
    DAY_MILLIS, DoctorLine, SignedSourceGrant, SourceGrantPayload, TrustedIssuers,
    active_grants_path, grant_path, identity_key_path, identity_required, load_active_grants_at,
    load_grant, load_signing_key, load_trust_at, nonempty_env_is_set, trust_path,
    verify_active_grant, verify_grant, verify_source_key_matches_grant, verifying_key_from_hex,
};
use crate::now_millis;

pub(super) fn print_status_lines(lines: &[DoctorLine]) -> bool {
    let ok = status_lines_ok(lines);
    for line in lines {
        println!("  {}  {}", line.level, line.message);
    }
    ok
}

pub(super) fn status_lines_ok(lines: &[DoctorLine]) -> bool {
    lines.iter().all(|line| line.ok)
}

pub(super) fn identity_status_json(
    dir: &str,
    source: Option<&str>,
    issuer_key: Option<&str>,
    expires_warning_days: u64,
    lines: &[DoctorLine],
) -> serde_json::Value {
    let ok = status_lines_ok(lines);
    serde_json::json!({
        "status": if ok { "ok" } else { "failed" },
        "tool": "identity status",
        "ok": ok,
        "dir": dir,
        "source": source,
        "issuer_key": issuer_key,
        "expires_warning_days": expires_warning_days,
        "checks": lines
            .iter()
            .map(|line| {
                serde_json::json!({
                    "level": line.level,
                    "ok": line.ok,
                    "message": line.message,
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(super) fn identity_status(
    dir: &str,
    expected_source: Option<&str>,
    issuer_key: Option<&str>,
    expires_warning_days: u64,
) -> Result<Vec<DoctorLine>, String> {
    let paths = identity_bundle_paths(dir, expected_source)?;
    let mut lines = vec![DoctorLine::ok(format!("bundle: {}", paths.dir.display()))];

    let trust = match doctor_trust(&path_string(&paths.trust_file)) {
        Ok(trust) => {
            lines.push(DoctorLine::ok(format!(
                "trust: {} ({} issuer(s))",
                paths.trust_file.display(),
                trust.issuers.len()
            )));
            trust
        }
        Err(line) => {
            lines.push(line);
            return Ok(lines);
        }
    };

    let grant = match load_grant(&path_string(&paths.grant_file)) {
        Ok(grant) => grant,
        Err(error) => {
            lines.push(DoctorLine::fail(format!("grant: {error}")));
            return Ok(lines);
        }
    };
    if let Some(source) = expected_source
        && grant.grant.source != source
    {
        lines.push(DoctorLine::fail(format!(
            "source: active grant is {}, expected {source}",
            grant.grant.source
        )));
    }

    match verify_grant(&grant, &trust, now_millis()) {
        Ok(()) => lines.push(DoctorLine::ok(format!(
            "grant: {} (source={} max={:?} issuer={} scope={} expires_at_ms={})",
            paths.grant_file.display(),
            grant.grant.source,
            grant.grant.max_authority,
            grant.grant.issuer,
            grant.grant.scope.as_deref().unwrap_or("*"),
            grant
                .grant
                .expires_at_ms
                .map_or_else(|| "never".to_string(), |expires| expires.to_string())
        ))),
        Err(error) => lines.push(DoctorLine::fail(format!("grant: {error}"))),
    }
    lines.extend(active_grant_status(&paths.active_grants_file, &grant));
    lines.extend(grant_log_status(&paths.dir, &grant));
    lines.extend(expiration_lines(&grant.grant, expires_warning_days));
    lines.extend(identity_key_status(&paths.source_key_path, &grant));
    lines.extend(issuer_key_status(
        issuer_key,
        &paths.dir,
        &grant.grant.issuer,
        &trust,
    ));
    Ok(lines)
}

fn active_grant_status(path: &Path, grant: &SignedSourceGrant) -> Vec<DoctorLine> {
    let mut lines = Vec::new();
    let active = match load_active_grants_at(path, true) {
        Ok(Some(active)) => active,
        Ok(None) => {
            lines.push(DoctorLine::fail(format!(
                "active grant: {} is missing",
                path.display()
            )));
            return lines;
        }
        Err(error) => {
            lines.push(DoctorLine::fail(format!("active grant: {error}")));
            return lines;
        }
    };
    match verify_active_grant(grant, &active) {
        Ok(()) => lines.push(DoctorLine::ok(format!(
            "active grant: {} (current for {})",
            path.display(),
            grant.grant.source
        ))),
        Err(error) => lines.push(DoctorLine::fail(format!("active grant: {error}"))),
    }
    lines
}

pub(super) fn verify_active_grant_if_configured(
    grant: &SignedSourceGrant,
    trust_path: &str,
) -> Result<(), String> {
    let Some(path) = active_grants_path(trust_path) else {
        return Ok(());
    };
    let Some(active) = load_active_grants_at(&path, true)? else {
        return Ok(());
    };
    verify_active_grant(grant, &active)
}

fn expiration_lines(grant: &SourceGrantPayload, warning_days: u64) -> Vec<DoctorLine> {
    let Some(expires_at) = grant.expires_at_ms else {
        return vec![DoctorLine::ok("grant expiry: never")];
    };
    let now = now_millis().as_unix_millis();
    if now > expires_at {
        return vec![DoctorLine::fail(format!(
            "grant expiry: expired at {expires_at}"
        ))];
    }
    let remaining = expires_at.saturating_sub(now);
    let warning_ms = i64::try_from(warning_days)
        .unwrap_or(i64::MAX / DAY_MILLIS)
        .saturating_mul(DAY_MILLIS);
    let message = format!(
        "grant expiry: expires at {expires_at} (in {} day(s))",
        remaining / DAY_MILLIS
    );
    if remaining <= warning_ms {
        vec![DoctorLine::warn(message)]
    } else {
        vec![DoctorLine::ok(message)]
    }
}

fn identity_key_status(key_path: &Path, grant: &SignedSourceGrant) -> Vec<DoctorLine> {
    let mut lines = Vec::new();
    match verify_source_key_matches_grant(key_path, grant) {
        Ok(()) => lines.push(DoctorLine::ok(format!(
            "source key: {} (matches grant public key)",
            key_path.display()
        ))),
        Err(error) => lines.push(DoctorLine::fail(format!("source key: {error}"))),
    }
    lines
}

fn issuer_key_status(
    raw_issuer_key: Option<&str>,
    bundle_dir: &Path,
    issuer_name: &str,
    trust: &TrustedIssuers,
) -> Vec<DoctorLine> {
    let mut lines = Vec::new();
    let issuer_key_path = match raw_issuer_key {
        Some(path) => match bootstrap_issuer_key_path(Some(path), bundle_dir) {
            Ok(path) => Some(path),
            Err(error) => {
                lines.push(DoctorLine::fail(format!("issuer key: {error}")));
                return lines;
            }
        },
        None => default_issuer_key_path().ok(),
    };
    let Some(path) = issuer_key_path else {
        lines.push(DoctorLine::warn(
            "issuer key: not checked (pass --issuer-key to check the operator signing key)",
        ));
        return lines;
    };
    if path.starts_with(bundle_dir) {
        lines.push(DoctorLine::fail(format!(
            "issuer key: {} is inside {}; keep issuer keys outside the agent/project bundle",
            path.display(),
            bundle_dir.display()
        )));
        return lines;
    }
    if !path.exists() {
        lines.push(DoctorLine::warn(format!(
            "issuer key: {} not present on this machine",
            path.display()
        )));
        return lines;
    }
    match load_issuer_key_matching_trust(&path, issuer_name, trust) {
        Ok(()) => lines.push(DoctorLine::ok(format!(
            "issuer key: {} (matches trusted issuer {issuer_name})",
            path.display()
        ))),
        Err(error) => lines.push(DoctorLine::fail(format!("issuer key: {error}"))),
    }
    lines
}

pub(crate) fn doctor_status(source: &str, now: TimestampMillis) -> Vec<DoctorLine> {
    let required = match identity_required() {
        Ok(required) => required,
        Err(error) => return vec![DoctorLine::fail(format!("identity: {error}"))],
    };
    let path = trust_path();
    if !identity_is_configured(required, &path) {
        return vec![DoctorLine::warn(
            "identity: not configured (optional; run `dent8 identity bootstrap` to create a signed source grant)",
        )];
    }

    let trust = match doctor_trust(&path) {
        Ok(trust) => trust,
        Err(line) => return vec![line],
    };

    let mut lines = vec![DoctorLine::ok(format!(
        "identity trust: {path} ({} issuer(s))",
        trust.issuers.len()
    ))];

    let Some(grant) = doctor_grant(&mut lines, &trust, now) else {
        return lines;
    };
    doctor_active_grant(&mut lines, &grant, &path);
    doctor_source(&mut lines, source, &grant);
    doctor_key(&mut lines, &grant);
    lines
}

fn identity_is_configured(required: bool, path: &str) -> bool {
    required
        || nonempty_env_is_set("DENT8_TRUST")
        || nonempty_env_is_set("DENT8_GRANT")
        || nonempty_env_is_set("DENT8_IDENTITY_KEY")
        || Path::new(path).exists()
}

fn doctor_trust(path: &str) -> Result<TrustedIssuers, DoctorLine> {
    let trust = match load_trust_at(path, true) {
        Ok(Some(trust)) => trust,
        Ok(None) => {
            return Err(DoctorLine::fail(format!(
                "identity: no trust registry at {path}"
            )));
        }
        Err(error) => return Err(DoctorLine::fail(format!("identity: {error}"))),
    };
    if trust.issuers.is_empty() {
        Err(DoctorLine::fail(
            "identity: trust registry is empty; no issuer can verify grants",
        ))
    } else {
        Ok(trust)
    }
}

fn doctor_grant(
    lines: &mut Vec<DoctorLine>,
    trust: &TrustedIssuers,
    now: TimestampMillis,
) -> Option<SignedSourceGrant> {
    let grant_file = match grant_path() {
        Ok(path) => path,
        Err(error) => {
            lines.push(DoctorLine::fail(format!("identity grant: {error}")));
            return None;
        }
    };
    let grant = match load_grant(&grant_file) {
        Ok(grant) => grant,
        Err(error) => {
            lines.push(DoctorLine::fail(format!("identity grant: {error}")));
            return None;
        }
    };
    match verify_grant(&grant, trust, now) {
        Ok(()) => lines.push(DoctorLine::ok(format!(
            "identity grant: {grant_file} (source={} max={:?} issuer={} scope={})",
            grant.grant.source,
            grant.grant.max_authority,
            grant.grant.issuer,
            grant.grant.scope.as_deref().unwrap_or("*"),
        ))),
        Err(error) => {
            lines.push(DoctorLine::fail(format!("identity grant: {error}")));
            return None;
        }
    }
    Some(grant)
}

fn doctor_source(lines: &mut Vec<DoctorLine>, source: &str, grant: &SignedSourceGrant) {
    if grant.grant.source == source {
        lines.push(DoctorLine::ok(format!(
            "identity source: grant source matches doctor source {source}"
        )));
    } else {
        lines.push(DoctorLine::fail(format!(
            "identity source: grant source {} does not match doctor source {}; pass `--source {}` or use the matching grant",
            grant.grant.source, source, grant.grant.source
        )));
    }
}

fn doctor_active_grant(lines: &mut Vec<DoctorLine>, grant: &SignedSourceGrant, trust_path: &str) {
    let Some(path) = active_grants_path(trust_path) else {
        return;
    };
    let active = match load_active_grants_at(&path, true) {
        Ok(Some(active)) => active,
        Ok(None) => return,
        Err(error) => {
            lines.push(DoctorLine::fail(format!("identity active grant: {error}")));
            return;
        }
    };
    match verify_active_grant(grant, &active) {
        Ok(()) => lines.push(DoctorLine::ok(format!(
            "identity active grant: {} (current for {})",
            path.display(),
            grant.grant.source
        ))),
        Err(error) => lines.push(DoctorLine::fail(format!("identity active grant: {error}"))),
    }
}

fn doctor_key(lines: &mut Vec<DoctorLine>, grant: &SignedSourceGrant) {
    let key_file = match identity_key_path() {
        Ok(path) => path,
        Err(error) => {
            lines.push(DoctorLine::fail(format!("identity key: {error}")));
            return;
        }
    };
    let signing = match load_signing_key(&key_file) {
        Ok(signing) => signing,
        Err(error) => {
            lines.push(DoctorLine::fail(format!("identity key: {error}")));
            return;
        }
    };
    let grant_key = match verifying_key_from_hex(&grant.grant.public_key) {
        Ok(key) => key,
        Err(error) => {
            lines.push(DoctorLine::fail(format!("identity grant: {error}")));
            return;
        }
    };
    if signing.verifying_key().to_bytes() == grant_key.to_bytes() {
        lines.push(DoctorLine::ok(format!(
            "identity key: {key_file} (matches grant public key)"
        )));
    } else {
        lines.push(DoctorLine::fail(format!(
            "identity key: {key_file} does not match grant public key"
        )));
    }
}

/// ADR 0014 consistency line for `identity status`/`doctor`: is there a grant log, and does
/// it cover the *current* grant with an unrevoked issuance?
fn grant_log_status(dir: &Path, grant: &SignedSourceGrant) -> Vec<DoctorLine> {
    let path = grant_log_path_in(dir);
    if !path.exists() {
        return vec![DoctorLine::warn(format!(
            "grant log: none at {} — entitlement-at-write-time is unverifiable; run `dent8 \
             identity backfill-grant-log`",
            path.display()
        ))];
    }
    match load_grant_records(&path) {
        Err(message) => vec![DoctorLine::fail(format!("grant log: {message}"))],
        Ok(records) => {
            let mut active_issued = false;
            for record in &records {
                if record.grant_signature == grant.signature {
                    match record.action {
                        GrantAction::Issued => active_issued = true,
                        GrantAction::Revoked => active_issued = false,
                    }
                }
            }
            if active_issued {
                vec![DoctorLine::ok(format!(
                    "grant log: {} ({} record(s); current grant issued and not revoked)",
                    path.display(),
                    records.len()
                ))]
            } else {
                vec![DoctorLine::fail(format!(
                    "grant log: {} has no unrevoked issuance for the current grant — run \
                     `dent8 identity backfill-grant-log` (or the grant was revoked; rotate \
                     before writing)",
                    path.display()
                ))]
            }
        }
    }
}
