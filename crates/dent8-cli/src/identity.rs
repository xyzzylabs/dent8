//! Signed source identity for the CLI/MCP write boundary.
//!
//! The authority registry answers "what may this source claim?" Signed identity answers
//! "is this caller actually holding the key for that source?" The model is deliberately
//! small: a trusted issuer public key verifies a signed grant binding a source id to a
//! source public key and authority ceiling; the write boundary checks the caller holds the
//! matching source private key, and every persisted event carries a **signed write
//! attestation** (ADR 0013) — an Ed25519 signature by that key over the event's canonical
//! content — so provenance is offline-re-verifiable long after the write.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use dent8_core::{AuthorityLevel, ClaimEvent, TimestampMillis};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{CliAuthority, CliOutput, WriteAuth, env_flag, now_millis, parse_source, write_atomic};

const DEFAULT_TRUST: &str = "dent8-trust.json";
const ACTIVE_GRANTS_FILE: &str = "active-grants.json";
const GRANT_DOMAIN: &[u8] = b"dent8.source-grant.v1\0";
const DAY_MILLIS: i64 = 86_400_000;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedIssuers {
    issuers: BTreeMap<String, TrustedIssuer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedIssuer {
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedSourceGrant {
    grant: SourceGrantPayload,
    signature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveSourceGrants {
    sources: BTreeMap<String, ActiveSourceGrant>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveSourceGrant {
    grant_signature: String,
    public_key: String,
}

mod records;
#[cfg(feature = "witness")]
pub(crate) use records::grant_log_line_hashes;
pub(crate) use records::{Entitlement, entitlement_at, load_grant_history_for_verify};
use records::{GrantAction, append_grant_records, grant_log_path_in, has_issued_record};

mod bundle;
use bundle::{
    absolute_existing_dir, bootstrap_issuer_key_path, identity_bundle_paths, keygen_outcome,
    load_issuer_signing_key_matching_trust, path_string, repair_env_bundle_outcome,
    rotate_source_bundle, verify_grant_signature, write_json_path,
};
pub(crate) use bundle::{
    add_source_to_bundle, bootstrap_bundle, identity_env_path_for_source,
    preflight_bootstrap_bundle, repair_env_bundle,
};

mod status;
pub(crate) use status::doctor_status;
use status::{
    identity_status, identity_status_json, print_status_lines, status_lines_ok,
    verify_active_grant_if_configured,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceGrantPayload {
    version: u8,
    source: String,
    public_key: String,
    max_authority: AuthorityLevel,
    issuer: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<i64>,
}

#[derive(Clone, Debug)]
pub(crate) struct BootstrapOutput {
    pub(crate) issuer: String,
    pub(crate) source: String,
    pub(crate) max_authority: AuthorityLevel,
    pub(crate) scope: String,
    pub(crate) issuer_key_path: PathBuf,
    pub(crate) trust_file: PathBuf,
    pub(crate) active_grants_file: PathBuf,
    pub(crate) grant_file: PathBuf,
    pub(crate) source_key_path: PathBuf,
    pub(crate) env_file: PathBuf,
    bundle_dir: PathBuf,
}

impl BootstrapOutput {
    pub(crate) fn message(&self) -> String {
        format!(
            "bootstrapped signed identity in {}\n  issuer: {} ({})\n  source: {} max={:?} scope={}\n  trust: {}\n  active grants: {}\n  grant: {}\n  source key: {}\n  env: {}\n\nNext:\n  set -a\n  . {}\n  set +a\n  dent8 doctor --source {} --write-check",
            self.bundle_dir.display(),
            self.issuer,
            self.issuer_key_path.display(),
            self.source,
            self.max_authority,
            self.scope,
            self.trust_file.display(),
            self.active_grants_file.display(),
            self.grant_file.display(),
            self.source_key_path.display(),
            self.env_file.display(),
            shell_quote(&path_string(&self.env_file)),
            self.source,
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SourceIdentityOutput {
    pub(crate) source: String,
    pub(crate) issuer: String,
    pub(crate) max_authority: AuthorityLevel,
    pub(crate) scope: String,
    pub(crate) active_grants_file: PathBuf,
    pub(crate) grant_file: PathBuf,
    pub(crate) source_key_path: PathBuf,
    pub(crate) env_file: PathBuf,
    pub(crate) reused: bool,
}

#[derive(Clone, Debug)]
struct RepairEnvOutput {
    source: String,
    dir: PathBuf,
    active_grants_file: PathBuf,
    env_file: PathBuf,
    repaired_active: bool,
}

impl RepairEnvOutput {
    fn message(&self) -> String {
        let mut lines = vec![
            format!("repaired signed identity env for {}", self.source),
            format!("  env: {}", self.env_file.display()),
            format!("  active grants: {}", self.active_grants_file.display()),
        ];
        if self.repaired_active {
            lines.push(
                "  active grants: restored current grant entry from signed grant".to_string(),
            );
        }
        lines.push(String::new());
        lines.push(format!(
            "Next:\n  dent8 identity status --dir {} --source {}\n  dent8 doctor --source {} --write-check",
            shell_quote(&path_string(&self.dir)),
            self.source,
            self.source
        ));
        lines.join("\n")
    }
}

#[derive(Clone, Debug)]
struct RotateSourceOutput {
    source: String,
    dir: PathBuf,
    source_key_path: PathBuf,
    grant_file: PathBuf,
    active_grants_file: PathBuf,
    env_file: PathBuf,
    old_grant_backup: PathBuf,
    old_env_backup: PathBuf,
    old_active_grant_backup: Option<PathBuf>,
    old_public_key_backup: Option<PathBuf>,
}

impl RotateSourceOutput {
    fn message(&self) -> String {
        let mut lines = vec![
            format!(
                "rotated source identity for {} in {}",
                self.source,
                self.dir.display()
            ),
            format!("  source key: {}", self.source_key_path.display()),
            format!("  grant: {}", self.grant_file.display()),
            format!("  active grants: {}", self.active_grants_file.display()),
            format!("  env: {}", self.env_file.display()),
            "  old source key backup: removed after successful rotation".to_string(),
            format!("  old grant backup: {}", self.old_grant_backup.display()),
            format!("  old env backup: {}", self.old_env_backup.display()),
        ];
        if let Some(active_backup) = &self.old_active_grant_backup {
            lines.push(format!(
                "  old active grant backup: {}",
                active_backup.display()
            ));
        }
        if let Some(public_backup) = &self.old_public_key_backup {
            lines.push(format!(
                "  old public key backup: {}",
                public_backup.display()
            ));
        }
        lines.push(String::new());
        lines.push(format!(
            "Next:\n  dent8 identity status --dir {} --source {}\n  dent8 doctor --source {} --write-check",
            shell_quote(&path_string(&self.dir)),
            self.source,
            self.source,
        ));
        lines.join("\n")
    }
}

#[derive(Clone, Debug)]
struct KeygenOutput {
    label: String,
    private_key_path: PathBuf,
    public_key_path: PathBuf,
}

impl KeygenOutput {
    fn message(&self) -> String {
        format!(
            "wrote {} signing key to {}\nwrote public key to {}",
            self.label,
            self.private_key_path.display(),
            self.public_key_path.display()
        )
    }
}

#[derive(Clone, Debug)]
struct TrustAddOutput {
    path: String,
    issuer: String,
    public_key: String,
}

impl TrustAddOutput {
    fn message(&self) -> String {
        format!("trusted issuer {} at {}", self.issuer, self.path)
    }
}

#[derive(Clone, Debug)]
struct TrustListOutput {
    path: String,
    trust: Option<TrustedIssuers>,
}

impl TrustListOutput {
    fn message(&self) -> String {
        match &self.trust {
            None => format!("no identity trust registry at {}", self.path),
            Some(trust) if trust.issuers.is_empty() => {
                "identity trust registry is empty".to_string()
            }
            Some(trust) => trust
                .issuers
                .iter()
                .map(|(issuer, trusted)| format!("{issuer}  public_key={}", trusted.public_key))
                .collect::<Vec<_>>()
                .join("\n"),
        }
    }
}

#[derive(Clone, Debug)]
struct GrantIssueOutput {
    out: String,
    grant: SourceGrantPayload,
}

impl GrantIssueOutput {
    fn message(&self) -> String {
        format!(
            "issued signed grant for {} -> {}",
            self.grant.source, self.out
        )
    }
}

#[derive(Clone, Debug)]
struct GrantVerifyOutput {
    path: String,
    grant: SourceGrantPayload,
}

impl GrantVerifyOutput {
    fn message(&self) -> String {
        format!(
            "OK: grant for {} max={:?} issuer={}",
            self.grant.source, self.grant.max_authority, self.grant.issuer
        )
    }
}

#[derive(Clone, Debug)]
struct BootstrapPlan {
    dir: PathBuf,
    identities_dir: PathBuf,
    grants_dir: PathBuf,
    issuer_key_path: PathBuf,
    source_key_path: PathBuf,
    source_public_path: PathBuf,
    trust_file: PathBuf,
    active_grants_file: PathBuf,
    grant_file: PathBuf,
    env_file: PathBuf,
}

impl BootstrapPlan {
    fn identity_outputs(&self) -> [&Path; 6] {
        [
            self.source_key_path.as_path(),
            self.source_public_path.as_path(),
            self.trust_file.as_path(),
            self.active_grants_file.as_path(),
            self.grant_file.as_path(),
            self.env_file.as_path(),
        ]
    }
}

#[derive(Clone, Debug)]
struct IdentityBundlePaths {
    dir: PathBuf,
    trust_file: PathBuf,
    active_grants_file: PathBuf,
    grant_file: PathBuf,
    source_key_path: PathBuf,
    env_file: PathBuf,
}

#[derive(Clone, Debug)]
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

pub(crate) fn trust_path() -> String {
    std::env::var("DENT8_TRUST").unwrap_or_else(|_| DEFAULT_TRUST.to_string())
}

fn identity_required() -> Result<bool, String> {
    env_flag("DENT8_REQUIRE_IDENTITY")
}

fn grant_path() -> Result<String, String> {
    env_string("DENT8_GRANT")
}

fn identity_key_path() -> Result<String, String> {
    env_string("DENT8_IDENTITY_KEY")
}

fn active_grants_path(trust_path: &str) -> Option<PathBuf> {
    if let Some(path) = nonempty_env("DENT8_ACTIVE_GRANTS") {
        return Some(PathBuf::from(path));
    }
    let candidate = Path::new(trust_path).parent().map_or_else(
        || PathBuf::from(ACTIVE_GRANTS_FILE),
        |parent| parent.join(ACTIVE_GRANTS_FILE),
    );
    candidate.exists().then_some(candidate)
}

fn missing_identity_path(name: &str) -> String {
    format!("{name} must point to a signed source identity file")
}

fn env_string(name: &str) -> Result<String, String> {
    std::env::var(name)
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| missing_identity_path(name))
}

/// The on-disk identity inputs a write is authorized and attested against (ADR 0018).
///
/// This is the single seam between *where the identity comes from* and *how it is checked*.
/// The CLI builds one from process env via [`IdentityContext::from_env`] — byte-identical to
/// the pre-0018 direct env reads — for every command. A per-connection local daemon (the rest
/// of ADR 0018) builds ONE PER CONNECTION from the source it proved possession of, so each
/// request is authorized and Ed25519-attested as its own source without the process-global env.
/// [`enforce_write`] and [`attest_events`] read *only* from this struct, never from env.
pub(crate) struct IdentityContext {
    /// Trust-registry path (`DENT8_TRUST`, else [`DEFAULT_TRUST`]). Always resolved.
    trust_path: String,
    /// Whether `DENT8_TRUST` was explicitly set to a non-empty value. Kept distinct from the
    /// resolved default because it is one of the "identity is configured" signals — a bare
    /// default trust path that happens not to exist must not flip the write into fail-closed.
    trust_explicit: bool,
    /// Signed-grant path (`DENT8_GRANT`), if set to a non-empty value.
    grant_path: Option<String>,
    /// Source signing-key path (`DENT8_IDENTITY_KEY`), if set to a non-empty value.
    identity_key_path: Option<String>,
    /// Explicit active-grants path (`DENT8_ACTIVE_GRANTS`); when unset it is derived as the
    /// sibling of the trust registry (see [`IdentityContext::active_grants_path`]).
    active_grants_override: Option<String>,
    /// `DENT8_REQUIRE_IDENTITY`: fail closed even when nothing else is configured.
    required: bool,
}

impl IdentityContext {
    /// Resolve the identity inputs from process env. Byte-identical to the direct env reads
    /// these functions used before ADR 0018 — the CLI's only constructor.
    pub(crate) fn from_env() -> Result<Self, String> {
        Ok(Self {
            trust_path: trust_path(),
            trust_explicit: nonempty_env_is_set("DENT8_TRUST"),
            grant_path: nonempty_env("DENT8_GRANT"),
            identity_key_path: nonempty_env("DENT8_IDENTITY_KEY"),
            active_grants_override: nonempty_env("DENT8_ACTIVE_GRANTS"),
            required: identity_required()?,
        })
    }

    /// Whether signed identity is *configured*: a missing or invalid grant is then a hard
    /// error rather than unconfigured dev mode (in which writes pass unattested).
    pub(crate) fn configured(&self) -> bool {
        self.required
            || self.trust_explicit
            || self.grant_path.is_some()
            || self.identity_key_path.is_some()
            || Path::new(&self.trust_path).exists()
    }

    /// The grant path, or the same `must point to a signed source identity file` error the
    /// direct env read produced.
    fn require_grant_path(&self) -> Result<&str, String> {
        self.grant_path
            .as_deref()
            .ok_or_else(|| missing_identity_path("DENT8_GRANT"))
    }

    /// The signing-key path, with the same missing-path error as the grant path.
    fn require_identity_key_path(&self) -> Result<&str, String> {
        self.identity_key_path
            .as_deref()
            .ok_or_else(|| missing_identity_path("DENT8_IDENTITY_KEY"))
    }

    /// The active-grants file to check a grant against, if one exists: the explicit override,
    /// else the `active-grants.json` sibling of the trust registry when present.
    fn active_grants_path(&self) -> Option<PathBuf> {
        if let Some(path) = self.active_grants_override.as_deref() {
            return Some(PathBuf::from(path));
        }
        let candidate = Path::new(&self.trust_path).parent().map_or_else(
            || PathBuf::from(ACTIVE_GRANTS_FILE),
            |parent| parent.join(ACTIVE_GRANTS_FILE),
        );
        candidate.exists().then_some(candidate)
    }
}

pub(crate) fn enforce_write(
    ctx: &IdentityContext,
    auth: &WriteAuth<'_>,
    now: TimestampMillis,
) -> Result<(), String> {
    let Some(trust) = load_trust_at(&ctx.trust_path, ctx.configured())? else {
        return Ok(());
    };
    if trust.issuers.is_empty() {
        return Err("identity trust registry is empty; no issuer can verify grants".to_string());
    }

    let grant = load_grant(ctx.require_grant_path()?)?;
    verify_grant(&grant, &trust, now)?;
    verify_grant_matches_write(&grant.grant, auth, now)?;
    verify_active_grant_if_configured(&grant, ctx.active_grants_path().as_deref())?;

    let signing = load_signing_key(ctx.require_identity_key_path()?)?;
    let source_key = signing.verifying_key();
    let grant_key = verifying_key_from_hex(&grant.grant.public_key)?;
    if source_key.to_bytes() != grant_key.to_bytes() {
        return Err(format!(
            "identity key does not match the grant for {}",
            grant.grant.source
        ));
    }
    // Possession is proven for real by the persisted per-event attestation ([`attest_events`],
    // ADR 0013), signed at the append boundary over the final event content.
    Ok(())
}

/// Attach a signed write attestation (ADR 0013) to each event when signed identity is
/// configured; a no-op (`Ok(false)`) in unconfigured dev mode. Runs at the append boundary,
/// **after** every event mutation, so the signature covers exactly the persisted content.
/// [`enforce_write`] has already validated the grant against the trust registry and the
/// write's source/authority/scope; this signs [`dent8_core::attestation_message`] with the
/// source key and embeds the public key + signature in `provenance.attestation`.
pub(crate) fn attest_events(
    ctx: &IdentityContext,
    events: &mut [ClaimEvent],
) -> Result<bool, String> {
    if !ctx.configured() {
        return Ok(false);
    }
    let grant = load_grant(ctx.require_grant_path()?)?;
    let signing = load_signing_key(ctx.require_identity_key_path()?)?;
    if signing.verifying_key().to_bytes()
        != verifying_key_from_hex(&grant.grant.public_key)?.to_bytes()
    {
        return Err(format!(
            "identity key does not match the grant for {}",
            grant.grant.source
        ));
    }
    for event in events.iter_mut() {
        // Never sign over a stale/foreign attestation: the message strips the field, and the
        // stored value is replaced wholesale below.
        event.provenance.attestation = None;
        let message = dent8_core::attestation_message(event)
            .map_err(|error| format!("attestation canonicalization: {error}"))?;
        let signature = signing.sign(&message);
        event.provenance.attestation = Some(dent8_core::WriteAttestation {
            algorithm: dent8_core::AttestationAlgorithm::Ed25519,
            public_key: grant.grant.public_key.clone(),
            signature: hex::encode(signature.to_bytes()),
        });
    }
    Ok(true)
}

/// Re-verify one event's persisted attestation (ADR 0013): recompute the attestation message
/// from the stored event and check the embedded signature against the embedded public key.
/// `Ok(false)` = the event carries no attestation (a pre-attestation or dev-mode write).
///
/// This proves the event content is exactly what the holder of `public_key` signed. Whether
/// that key was *entitled* to the claimed source/authority at write time is a trust question
/// (grant history) deliberately out of scope here — see ADR 0013.
pub(crate) fn verify_event_attestation(event: &ClaimEvent) -> Result<bool, String> {
    let Some(attestation) = event.provenance.attestation.as_ref() else {
        return Ok(false);
    };
    let dent8_core::AttestationAlgorithm::Ed25519 = attestation.algorithm;
    let key = verifying_key_from_hex(&attestation.public_key).map_err(|error| {
        format!(
            "{}: attestation public key: {error}",
            event.event_id.as_str()
        )
    })?;
    let signature = signature_from_hex(&attestation.signature)?;
    let message = dent8_core::attestation_message(event)
        .map_err(|error| format!("attestation canonicalization: {error}"))?;
    key.verify(&message, &signature).map_err(|error| {
        format!(
            "{}: attestation does not verify (content altered or signature forged): {error}",
            event.event_id.as_str()
        )
    })?;
    Ok(true)
}

fn nonempty_env_is_set(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn bootstrap(
    dir: &str,
    source: &str,
    issuer: &str,
    issuer_key: Option<&str>,
    max_authority: CliAuthority,
    scope: &str,
    expires_at_ms: Option<i64>,
    output: CliOutput,
) -> i32 {
    match bootstrap_bundle(
        dir,
        source,
        issuer,
        issuer_key,
        max_authority,
        scope,
        expires_at_ms,
    ) {
        Ok(result) => match output {
            CliOutput::Text => {
                println!("{}", result.message());
                0
            }
            CliOutput::Json => print_json_stdout(&identity_bootstrap_json(
                dir,
                source,
                issuer,
                issuer_key,
                max_authority,
                scope,
                expires_at_ms,
                &result,
            )),
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stderr(
                &identity_bootstrap_error_json(
                    dir,
                    source,
                    issuer,
                    issuer_key,
                    max_authority,
                    scope,
                    expires_at_ms,
                    &error,
                ),
                1,
            ),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn identity_bootstrap_json(
    dir: &str,
    source: &str,
    issuer: &str,
    issuer_key: Option<&str>,
    max_authority: CliAuthority,
    scope: &str,
    expires_at_ms: Option<i64>,
    output: &BootstrapOutput,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": "identity bootstrap",
        "dir": path_string(&output.bundle_dir),
        "source": output.source.as_str(),
        "issuer": output.issuer.as_str(),
        "max_authority": output.max_authority.name(),
        "scope": output.scope.as_str(),
        "issuer_key_path": path_string(&output.issuer_key_path),
        "trust_file": path_string(&output.trust_file),
        "active_grants_file": path_string(&output.active_grants_file),
        "grant_file": path_string(&output.grant_file),
        "source_key_path": path_string(&output.source_key_path),
        "env_file": path_string(&output.env_file),
        "next": {
            "load_command": format!("set -a; . {}; set +a", shell_quote(&path_string(&output.env_file))),
            "doctor_command": format!("dent8 doctor --source {} --write-check", output.source),
        },
        "message": output.message(),
        "requested": {
            "dir": dir,
            "source": source,
            "issuer": issuer,
            "issuer_key": issuer_key,
            "max_authority": max_authority.level().name(),
            "scope": scope,
            "expires_at_ms": expires_at_ms,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn identity_bootstrap_error_json(
    dir: &str,
    source: &str,
    issuer: &str,
    issuer_key: Option<&str>,
    max_authority: CliAuthority,
    scope: &str,
    expires_at_ms: Option<i64>,
    message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "identity bootstrap",
        "dir": dir,
        "source": source,
        "issuer": issuer,
        "issuer_key": issuer_key,
        "max_authority": max_authority.level().name(),
        "scope": scope,
        "expires_at_ms": expires_at_ms,
        "message": message,
    })
}

pub(crate) fn issuer_keygen(out: &str, output: CliOutput) -> i32 {
    match keygen_outcome(out, "issuer") {
        Ok(result) => match output {
            CliOutput::Text => {
                println!("{}", result.message());
                0
            }
            CliOutput::Json => print_json_stdout(&identity_keygen_json(
                "identity issuer-keygen",
                None,
                out,
                &result,
            )),
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stderr(
                &identity_keygen_error_json("identity issuer-keygen", None, out, &error),
                1,
            ),
        },
    }
}

pub(crate) fn agent_keygen(source: &str, out: &str, output: CliOutput) -> i32 {
    if let Err(error) = parse_source(source) {
        return match output {
            CliOutput::Text => {
                eprintln!("{error}");
                2
            }
            CliOutput::Json => print_json_stderr(
                &identity_keygen_error_json("identity agent-keygen", Some(source), out, &error),
                2,
            ),
        };
    }
    match keygen_outcome(out, source) {
        Ok(result) => match output {
            CliOutput::Text => {
                println!("{}", result.message());
                0
            }
            CliOutput::Json => print_json_stdout(&identity_keygen_json(
                "identity agent-keygen",
                Some(source),
                out,
                &result,
            )),
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stderr(
                &identity_keygen_error_json("identity agent-keygen", Some(source), out, &error),
                1,
            ),
        },
    }
}

fn identity_keygen_json(
    tool: &'static str,
    source: Option<&str>,
    out: &str,
    output: &KeygenOutput,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": tool,
        "source": source,
        "private_key_path": path_string(&output.private_key_path),
        "public_key_path": path_string(&output.public_key_path),
        "message": output.message(),
        "requested": {
            "out": out,
            "source": source,
        },
    })
}

fn identity_keygen_error_json(
    tool: &'static str,
    source: Option<&str>,
    out: &str,
    message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": tool,
        "source": source,
        "out": out,
        "message": message,
    })
}

pub(crate) fn trust_add(issuer: &str, public_key_path: &str, output: CliOutput) -> i32 {
    let public_key = match read_public_key_hex(public_key_path) {
        Ok(public_key) => public_key,
        Err(error) => {
            return identity_trust_add_error(issuer, public_key_path, &error, 2, output);
        }
    };
    let path = trust_path();
    let mut trust = match load_trust_at(&path, false) {
        Ok(Some(trust)) => trust,
        Ok(None) => TrustedIssuers::default(),
        Err(error) => {
            return identity_trust_add_error(issuer, public_key_path, &error, 2, output);
        }
    };
    trust.issuers.insert(
        issuer.to_string(),
        TrustedIssuer {
            public_key: public_key.clone(),
        },
    );
    match save_trust_at(&path, &trust) {
        Ok(()) => {
            let result = TrustAddOutput {
                path,
                issuer: issuer.to_string(),
                public_key,
            };
            match output {
                CliOutput::Text => {
                    println!("{}", result.message());
                    0
                }
                CliOutput::Json => {
                    print_json_stdout(&identity_trust_add_json(public_key_path, &result))
                }
            }
        }
        Err(error) => identity_trust_add_error(issuer, public_key_path, &error, 1, output),
    }
}

fn identity_trust_add_error(
    issuer: &str,
    public_key_path: &str,
    message: &str,
    code: i32,
    output: CliOutput,
) -> i32 {
    match output {
        CliOutput::Text => {
            eprintln!("{message}");
            code
        }
        CliOutput::Json => print_json_stderr(
            &identity_trust_add_error_json(issuer, public_key_path, message),
            code,
        ),
    }
}

fn identity_trust_add_json(public_key_path: &str, output: &TrustAddOutput) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": "identity trust-add",
        "path": output.path.as_str(),
        "issuer": output.issuer.as_str(),
        "public_key": output.public_key.as_str(),
        "message": output.message(),
        "requested": {
            "issuer": output.issuer.as_str(),
            "public_key_path": public_key_path,
        },
    })
}

fn identity_trust_add_error_json(
    issuer: &str,
    public_key_path: &str,
    message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "identity trust-add",
        "issuer": issuer,
        "public_key_path": public_key_path,
        "message": message,
    })
}

pub(crate) fn trust_list(output: CliOutput) -> i32 {
    let path = trust_path();
    match load_trust_at(&path, false) {
        Ok(trust) => {
            let result = TrustListOutput { path, trust };
            match output {
                CliOutput::Text => {
                    println!("{}", result.message());
                    0
                }
                CliOutput::Json => print_json_stdout(&identity_trust_list_json(&result)),
            }
        }
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                2
            }
            CliOutput::Json => print_json_stderr(&identity_trust_list_error_json(&path, &error), 2),
        },
    }
}

fn identity_trust_list_json(output: &TrustListOutput) -> serde_json::Value {
    let issuers = output.trust.as_ref().map_or_else(Vec::new, |trust| {
        trust
            .issuers
            .iter()
            .map(|(issuer, trusted)| {
                serde_json::json!({
                    "issuer": issuer,
                    "public_key": trusted.public_key.as_str(),
                })
            })
            .collect()
    });
    serde_json::json!({
        "status": "ok",
        "tool": "identity trust-list",
        "path": output.path.as_str(),
        "registry_present": output.trust.is_some(),
        "count": issuers.len(),
        "issuers": issuers,
        "message": output.message(),
    })
}

fn identity_trust_list_error_json(path: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "identity trust-list",
        "path": path,
        "message": message,
    })
}

pub(crate) fn status(
    dir: &str,
    source: Option<&str>,
    issuer_key: Option<&str>,
    expires_warning_days: u64,
    output: CliOutput,
) -> i32 {
    match identity_status(dir, source, issuer_key, expires_warning_days) {
        Ok(lines) => match output {
            CliOutput::Text => {
                println!("identity status");
                let ok = print_status_lines(&lines);
                i32::from(!ok)
            }
            CliOutput::Json => {
                let ok = status_lines_ok(&lines);
                print_json_stdout(&identity_status_json(
                    dir,
                    source,
                    issuer_key,
                    expires_warning_days,
                    &lines,
                ));
                i32::from(!ok)
            }
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stderr(
                &serde_json::json!({
                    "status": "failed",
                    "tool": "identity status",
                    "dir": dir,
                    "source": source,
                    "issuer_key": issuer_key,
                    "expires_warning_days": expires_warning_days,
                    "message": error,
                }),
                1,
            ),
        },
    }
}

pub(crate) fn repair_env(dir: &str, source: &str, output: CliOutput) -> i32 {
    match repair_env_bundle_outcome(dir, source) {
        Ok(result) => match output {
            CliOutput::Text => {
                println!("{}", result.message());
                0
            }
            CliOutput::Json => print_json_stdout(&identity_repair_env_json(dir, source, &result)),
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => {
                print_json_stderr(&identity_repair_env_error_json(dir, source, &error), 1)
            }
        },
    }
}

fn identity_repair_env_json(
    dir: &str,
    source: &str,
    output: &RepairEnvOutput,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": "identity repair-env",
        "dir": path_string(&output.dir),
        "source": output.source.as_str(),
        "active_grants_file": path_string(&output.active_grants_file),
        "env_file": path_string(&output.env_file),
        "repaired_active_grant": output.repaired_active,
        "next": {
            "status_command": format!(
                "dent8 identity status --dir {} --source {}",
                shell_quote(&path_string(&output.dir)),
                output.source
            ),
            "doctor_command": format!("dent8 doctor --source {} --write-check", output.source),
        },
        "message": output.message(),
        "requested": {
            "dir": dir,
            "source": source,
        },
    })
}

fn identity_repair_env_error_json(dir: &str, source: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "identity repair-env",
        "dir": dir,
        "source": source,
        "message": message,
    })
}

#[allow(clippy::too_many_lines)]
pub(crate) fn rotate_source(
    dir: &str,
    source: &str,
    issuer_key: Option<&str>,
    max_authority: Option<CliAuthority>,
    scope: Option<&str>,
    expires_at_ms: Option<i64>,
    output: CliOutput,
) -> i32 {
    match rotate_source_bundle(dir, source, issuer_key, max_authority, scope, expires_at_ms) {
        Ok(result) => match output {
            CliOutput::Text => {
                println!("{}", result.message());
                0
            }
            CliOutput::Json => print_json_stdout(&identity_rotate_source_json(
                dir,
                source,
                issuer_key,
                max_authority,
                scope,
                expires_at_ms,
                &result,
            )),
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stderr(
                &identity_rotate_source_error_json(
                    dir,
                    source,
                    issuer_key,
                    max_authority,
                    scope,
                    expires_at_ms,
                    &error,
                ),
                1,
            ),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn identity_rotate_source_json(
    dir: &str,
    source: &str,
    issuer_key: Option<&str>,
    max_authority: Option<CliAuthority>,
    scope: Option<&str>,
    expires_at_ms: Option<i64>,
    output: &RotateSourceOutput,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": "identity rotate-source",
        "dir": path_string(&output.dir),
        "source": output.source.as_str(),
        "source_key_path": path_string(&output.source_key_path),
        "grant_file": path_string(&output.grant_file),
        "active_grants_file": path_string(&output.active_grants_file),
        "env_file": path_string(&output.env_file),
        "old_source_key_backup_removed": true,
        "old_grant_backup": path_string(&output.old_grant_backup),
        "old_env_backup": path_string(&output.old_env_backup),
        "old_active_grant_backup": output
            .old_active_grant_backup
            .as_ref()
            .map(|path| path_string(path)),
        "old_public_key_backup": output
            .old_public_key_backup
            .as_ref()
            .map(|path| path_string(path)),
        "next": {
            "load_command": format!("set -a; . {}; set +a", shell_quote(&path_string(&output.env_file))),
            "status_command": format!(
                "dent8 identity status --dir {} --source {}",
                shell_quote(&path_string(&output.dir)),
                output.source
            ),
            "doctor_command": format!("dent8 doctor --source {} --write-check", output.source),
        },
        "message": output.message(),
        "requested": {
            "dir": dir,
            "source": source,
            "issuer_key": issuer_key,
            "max_authority": max_authority.map(|authority| authority.level().name()),
            "scope": scope,
            "expires_at_ms": expires_at_ms,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn identity_rotate_source_error_json(
    dir: &str,
    source: &str,
    issuer_key: Option<&str>,
    max_authority: Option<CliAuthority>,
    scope: Option<&str>,
    expires_at_ms: Option<i64>,
    message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "identity rotate-source",
        "dir": dir,
        "source": source,
        "issuer_key": issuer_key,
        "max_authority": max_authority.map(|authority| authority.level().name()),
        "scope": scope,
        "expires_at_ms": expires_at_ms,
        "message": message,
    })
}

fn verify_active_grant(
    grant: &SignedSourceGrant,
    active: &ActiveSourceGrants,
) -> Result<(), String> {
    let entry = active
        .sources
        .get(&grant.grant.source)
        .ok_or_else(|| format!("no active grant is registered for {}", grant.grant.source))?;
    signature_from_hex(&entry.grant_signature)
        .map_err(|error| format!("active grant signature is invalid: {error}"))?;
    verifying_key_from_hex(&entry.public_key)
        .map_err(|error| format!("active grant public key is invalid: {error}"))?;
    if !entry.grant_signature.eq_ignore_ascii_case(&grant.signature) {
        return Err(format!(
            "grant for {} is not active; use the current grant from the identity bundle",
            grant.grant.source
        ));
    }
    if !entry
        .public_key
        .eq_ignore_ascii_case(&grant.grant.public_key)
    {
        return Err(format!(
            "grant for {} has an active signature but a different public key",
            grant.grant.source
        ));
    }
    Ok(())
}

fn active_entry_matches_grant(entry: &ActiveSourceGrant, grant: &SignedSourceGrant) -> bool {
    entry.grant_signature.eq_ignore_ascii_case(&grant.signature)
        && entry
            .public_key
            .eq_ignore_ascii_case(&grant.grant.public_key)
}

fn active_source_grant_for(grant: &SignedSourceGrant) -> ActiveSourceGrant {
    ActiveSourceGrant {
        grant_signature: grant.signature.clone(),
        public_key: grant.grant.public_key.clone(),
    }
}

fn verify_source_key_matches_grant(
    key_path: &Path,
    grant: &SignedSourceGrant,
) -> Result<(), String> {
    let signing = load_signing_key(&path_string(key_path))?;
    let grant_key = verifying_key_from_hex(&grant.grant.public_key)
        .map_err(|error| format!("grant public key: {error}"))?;
    if signing.verifying_key().to_bytes() != grant_key.to_bytes() {
        return Err(format!(
            "{} does not match grant public key",
            key_path.display()
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // linear arg validation + one grant-log branch
pub(crate) fn grant_issue(
    source: &str,
    public_key_path: &str,
    max_authority: CliAuthority,
    issuer: &str,
    issuer_key_path: &str,
    out: &str,
    scope: Option<&str>,
    expires_at_ms: Option<i64>,
    output: CliOutput,
) -> i32 {
    if let Err(error) = parse_source(source) {
        return identity_grant_issue_error(
            source,
            public_key_path,
            issuer,
            issuer_key_path,
            out,
            &error,
            2,
            output,
        );
    }
    let public_key = match read_public_key_hex(public_key_path) {
        Ok(public_key) => public_key,
        Err(error) => {
            return identity_grant_issue_error(
                source,
                public_key_path,
                issuer,
                issuer_key_path,
                out,
                &error,
                2,
                output,
            );
        }
    };
    let issuer_key = match load_signing_key(issuer_key_path) {
        Ok(key) => key,
        Err(error) => {
            return identity_grant_issue_error(
                source,
                public_key_path,
                issuer,
                issuer_key_path,
                out,
                &error,
                2,
                output,
            );
        }
    };
    let grant = SourceGrantPayload {
        version: 1,
        source: source.to_string(),
        public_key,
        max_authority: max_authority.level(),
        issuer: issuer.to_string(),
        scope: scope.map(str::to_string),
        expires_at_ms,
    };
    let message = match framed(GRANT_DOMAIN, &grant) {
        Ok(message) => message,
        Err(error) => {
            return identity_grant_issue_error(
                source,
                public_key_path,
                issuer,
                issuer_key_path,
                out,
                &error,
                2,
                output,
            );
        }
    };
    let signed = SignedSourceGrant {
        signature: hex::encode(issuer_key.sign(&message).to_bytes()),
        grant,
    };
    // Grant history (ADR 0014): this low-level command runs outside a bundle, so it records
    // history only when a log is explicitly configured — and says so when it is not, rather
    // than leaving a silent gap.
    match nonempty_env("DENT8_GRANT_LOG") {
        Some(log_path) => {
            if let Err(error) = append_grant_records(
                Path::new(&log_path),
                issuer,
                &issuer_key,
                &[(GrantAction::Issued, &signed)],
                now_millis().as_unix_millis(),
            ) {
                return identity_grant_issue_error(
                    source,
                    public_key_path,
                    issuer,
                    issuer_key_path,
                    out,
                    &format!("grant log append failed: {error}"),
                    1,
                    output,
                );
            }
        }
        None if output == CliOutput::Text => {
            eprintln!(
                "note: no DENT8_GRANT_LOG configured — this issuance is not recorded in grant \
                 history (run `dent8 identity backfill-grant-log` on the target bundle, or set \
                 DENT8_GRANT_LOG)"
            );
        }
        None => {}
    }
    match write_json(out, &signed) {
        Ok(()) => {
            let result = GrantIssueOutput {
                out: out.to_string(),
                grant: signed.grant,
            };
            match output {
                CliOutput::Text => {
                    println!("{}", result.message());
                    0
                }
                CliOutput::Json => print_json_stdout(&identity_grant_issue_json(
                    public_key_path,
                    issuer_key_path,
                    &result,
                )),
            }
        }
        Err(error) => identity_grant_issue_error(
            source,
            public_key_path,
            issuer,
            issuer_key_path,
            out,
            &error,
            1,
            output,
        ),
    }
}

pub(crate) fn grant_verify(path: &str, output: CliOutput) -> i32 {
    let trust = match load_trust_at(&trust_path(), true) {
        Ok(Some(trust)) => trust,
        Ok(None) => {
            return identity_grant_verify_error(
                path,
                "identity trust registry required but not found",
                2,
                output,
            );
        }
        Err(error) => {
            return identity_grant_verify_error(path, &error, 2, output);
        }
    };
    let grant = match load_grant(path) {
        Ok(grant) => grant,
        Err(error) => {
            return identity_grant_verify_error(path, &error, 2, output);
        }
    };
    match verify_grant(&grant, &trust, now_millis()) {
        Ok(()) => {
            let result = GrantVerifyOutput {
                path: path.to_string(),
                grant: grant.grant,
            };
            match output {
                CliOutput::Text => {
                    println!("{}", result.message());
                    0
                }
                CliOutput::Json => print_json_stdout(&identity_grant_verify_json(&result)),
            }
        }
        Err(error) => identity_grant_verify_error(path, &error, 1, output),
    }
}

#[allow(clippy::too_many_arguments)]
fn identity_grant_issue_error(
    source: &str,
    public_key_path: &str,
    issuer: &str,
    issuer_key_path: &str,
    out: &str,
    message: &str,
    code: i32,
    output: CliOutput,
) -> i32 {
    match output {
        CliOutput::Text => {
            eprintln!("{message}");
            code
        }
        CliOutput::Json => print_json_stderr(
            &identity_grant_issue_error_json(
                source,
                public_key_path,
                issuer,
                issuer_key_path,
                out,
                message,
            ),
            code,
        ),
    }
}

fn identity_grant_issue_json(
    public_key_path: &str,
    issuer_key_path: &str,
    output: &GrantIssueOutput,
) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": "identity grant-issue",
        "out": output.out.as_str(),
        "source": output.grant.source.as_str(),
        "issuer": output.grant.issuer.as_str(),
        "max_authority": output.grant.max_authority.name(),
        "scope": output.grant.scope.as_deref(),
        "expires_at_ms": output.grant.expires_at_ms,
        "public_key": output.grant.public_key.as_str(),
        "message": output.message(),
        "requested": {
            "source": output.grant.source.as_str(),
            "public_key_path": public_key_path,
            "issuer": output.grant.issuer.as_str(),
            "issuer_key": issuer_key_path,
            "out": output.out.as_str(),
            "max_authority": output.grant.max_authority.name(),
            "scope": output.grant.scope.as_deref(),
            "expires_at_ms": output.grant.expires_at_ms,
        },
    })
}

fn identity_grant_issue_error_json(
    source: &str,
    public_key_path: &str,
    issuer: &str,
    issuer_key_path: &str,
    out: &str,
    message: &str,
) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "identity grant-issue",
        "source": source,
        "public_key_path": public_key_path,
        "issuer": issuer,
        "issuer_key": issuer_key_path,
        "out": out,
        "message": message,
    })
}

fn identity_grant_verify_error(path: &str, message: &str, code: i32, output: CliOutput) -> i32 {
    match output {
        CliOutput::Text => {
            eprintln!("{message}");
            code
        }
        CliOutput::Json => {
            print_json_stderr(&identity_grant_verify_error_json(path, message), code)
        }
    }
}

fn identity_grant_verify_json(output: &GrantVerifyOutput) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": "identity grant-verify",
        "path": output.path.as_str(),
        "source": output.grant.source.as_str(),
        "issuer": output.grant.issuer.as_str(),
        "max_authority": output.grant.max_authority.name(),
        "scope": output.grant.scope.as_deref(),
        "expires_at_ms": output.grant.expires_at_ms,
        "public_key": output.grant.public_key.as_str(),
        "message": output.message(),
    })
}

fn identity_grant_verify_error_json(path: &str, message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "failed",
        "tool": "identity grant-verify",
        "path": path,
        "message": message,
    })
}

fn print_json_stdout(value: &serde_json::Value) -> i32 {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("identity JSON output should serialize")
    );
    0
}

fn print_json_stderr(value: &serde_json::Value, code: i32) -> i32 {
    eprintln!(
        "{}",
        serde_json::to_string_pretty(value).expect("identity JSON error output should serialize")
    );
    code
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn source_slug(source: &str) -> String {
    path_slug(source)
}

fn path_slug(value: &str) -> String {
    value
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

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn load_trust_at(path: &str, required: bool) -> Result<Option<TrustedIssuers>, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents)
            .map(Some)
            .map_err(|error| format!("{path}: corrupt identity trust registry: {error}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && required => Err(format!(
            "identity trust registry is required, but {path} does not exist; create it with \
             `dent8 identity trust-add <issuer> <issuer.pub>` or unset identity enforcement env vars"
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {path}: {error}")),
    }
}

fn save_trust_at(path: &str, trust: &TrustedIssuers) -> Result<(), String> {
    write_json(path, trust)
}

fn load_grant(path: &str) -> Result<SignedSourceGrant, String> {
    let contents =
        std::fs::read_to_string(path).map_err(|error| format!("cannot read {path}: {error}"))?;
    serde_json::from_str(&contents)
        .map_err(|error| format!("{path}: corrupt source grant: {error}"))
}

fn load_active_grants_at(
    path: &Path,
    required: bool,
) -> Result<Option<ActiveSourceGrants>, String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents)
            .map(Some)
            .map_err(|error| format!("{}: corrupt active grant registry: {error}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && required => Err(format!(
            "active grant registry is required, but {} does not exist",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("cannot read {}: {error}", path.display())),
    }
}

fn write_active_grants_path(path: &Path, active: &ActiveSourceGrants) -> Result<(), String> {
    write_json_path(path, active)
}

fn verify_grant(
    grant: &SignedSourceGrant,
    trust: &TrustedIssuers,
    now: TimestampMillis,
) -> Result<(), String> {
    if grant.grant.version != 1 {
        return Err(format!("unsupported grant version {}", grant.grant.version));
    }
    if let Err(error) = parse_source(&grant.grant.source) {
        return Err(format!("grant source is invalid: {error}"));
    }
    verifying_key_from_hex(&grant.grant.public_key)?;
    if let Some(expires_at) = grant.grant.expires_at_ms
        && now.as_unix_millis() > expires_at
    {
        return Err(format!(
            "grant for {} expired at {expires_at}",
            grant.grant.source
        ));
    }
    let issuer = trust
        .issuers
        .get(&grant.grant.issuer)
        .ok_or_else(|| format!("untrusted grant issuer {}", grant.grant.issuer))?;
    let issuer_key = verifying_key_from_hex(&issuer.public_key)?;
    let signature = signature_from_hex(&grant.signature)?;
    issuer_key
        .verify(&framed(GRANT_DOMAIN, &grant.grant)?, &signature)
        .map_err(|error| format!("grant signature does not verify: {error}"))
}

fn verify_grant_matches_write(
    grant: &SourceGrantPayload,
    auth: &WriteAuth<'_>,
    now: TimestampMillis,
) -> Result<(), String> {
    if grant.source != auth.source {
        return Err(format!(
            "grant source {:?} does not match write source {:?}",
            grant.source, auth.source
        ));
    }
    if auth.authority > grant.max_authority {
        return Err(format!(
            "identity grant: source {:?} may assert at most {:?}, but requested {:?}",
            grant.source, grant.max_authority, auth.authority
        ));
    }
    if let Some(expires_at) = grant.expires_at_ms
        && now.as_unix_millis() > expires_at
    {
        return Err(format!(
            "grant for {} expired at {expires_at}",
            grant.source
        ));
    }
    if let Some(scope) = grant.scope.as_deref()
        && scope != "*"
        && scope != auth.subject()
    {
        return Err(format!(
            "identity grant scope {scope:?} does not cover write subject {}",
            auth.subject()
        ));
    }
    Ok(())
}

fn framed<T: Serialize>(domain: &[u8], value: &T) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(value)
        .map_err(|error| format!("canonicalize identity message: {error}"))?;
    let mut framed = Vec::with_capacity(domain.len() + 8 + body.len());
    framed.extend_from_slice(domain);
    framed.extend_from_slice(&(body.len() as u64).to_be_bytes());
    framed.extend_from_slice(&body);
    Ok(framed)
}

/// Domain-separation tag for the local daemon's session-challenge signature (ADR 0018),
/// following the `dent8.<purpose>.v1\0` convention ([`GRANT_DOMAIN`]). Distinct from the grant
/// and event-attestation domains, so a challenge signature can never verify as a grant or an
/// attestation, and vice versa.
///
/// The whole session-challenge surface is gated on `all(unix, async-store)`: its only consumer
/// is the local Unix-socket daemon, which needs the tokio bridge (`async-store`) and a Unix
/// socket. A non-daemon build never compiles it.
#[cfg(all(unix, feature = "async-store"))]
const SESSION_CHALLENGE_DOMAIN: &[u8] = b"dent8.session-challenge.v1\0";

/// The exact structure a daemon connection signs to prove possession of its source key: the
/// issued nonce bound to the source and the *exact* grant it presented (public key + grant
/// signature). Binding all four defeats cross-nonce replay, cross-source confusion, key
/// substitution, and rotated-grant reuse in one signature. Field/declaration order is
/// load-bearing (serde emits in declaration order) — pinned by a sign-here/verify-there test.
#[cfg(all(unix, feature = "async-store"))]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SessionChallenge<'a> {
    nonce: &'a str,
    source: &'a str,
    public_key: &'a str,
    grant_signature: &'a str,
}

/// The verified facts captured at `dent8/hello`, held per-connection until `dent8/prove`. The
/// daemon rebuilds the [`SessionChallenge`] to verify from *these stored fields*, never from
/// anything the prove message re-supplies.
#[cfg(all(unix, feature = "async-store"))]
pub(crate) struct VerifiedHello {
    pub(crate) source: String,
    public_key: String,
    grant_signature: String,
}

/// A fresh 32-byte session nonce from the OS CSPRNG, hex-encoded (64 chars). A `getrandom`
/// failure fails the handshake closed (no nonce issued) — never a zero/constant/counter/time
/// fallback.
#[cfg(all(unix, feature = "async-store"))]
pub(crate) fn session_nonce() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| format!("session nonce: {error}"))?;
    Ok(hex::encode(bytes))
}

/// Verify a daemon connection's `dent8/hello` (ADR 0018): the client-presented grant must be a
/// valid, active grant whose key the daemon *holds* (the same-user identity in `ctx`), so the
/// daemon can Ed25519-attest that source's writes. Returns the facts to challenge against.
///
/// `ctx` is the daemon's own [`IdentityContext::from_env`]. The `verify_source_key_matches_grant`
/// check ties a connection to the daemon's single configured source: a grant for any other key
/// is rejected here (multi-source over one daemon is future work). The caller maps any error to
/// a coarse client response and logs the detail, so the wire never reveals which check failed.
#[cfg(all(unix, feature = "async-store"))]
pub(crate) fn verify_session_hello(
    ctx: &IdentityContext,
    grant_json: &serde_json::Value,
    claimed_source: &str,
    now: TimestampMillis,
) -> Result<VerifiedHello, String> {
    let grant: SignedSourceGrant = serde_json::from_value(grant_json.clone())
        .map_err(|error| format!("invalid grant in hello: {error}"))?;
    if grant.grant.source != claimed_source {
        return Err(format!(
            "hello source {claimed_source:?} does not match the presented grant's source {:?}",
            grant.grant.source
        ));
    }
    let trust = load_trust_at(&ctx.trust_path, true)?
        .ok_or_else(|| "daemon has no trust registry configured".to_string())?;
    verify_grant(&grant, &trust, now)?;
    verify_active_grant_if_configured(&grant, ctx.active_grants_path().as_deref())?;
    let key_path = ctx.require_identity_key_path()?;
    verify_source_key_matches_grant(Path::new(key_path), &grant)?;
    Ok(VerifiedHello {
        source: grant.grant.source,
        public_key: grant.grant.public_key,
        grant_signature: grant.signature,
    })
}

/// Verify a `dent8/prove` signature against the stored [`VerifiedHello`] and the issued nonce:
/// the connection proves it holds the source private key by signing
/// `framed(SESSION_CHALLENGE_DOMAIN, &challenge)`. The challenge is reconstructed from stored
/// fields, so a signature is bound to exactly this nonce, source, key, and grant.
#[cfg(all(unix, feature = "async-store"))]
pub(crate) fn verify_session_prove(
    hello: &VerifiedHello,
    nonce: &str,
    signature_hex: &str,
) -> Result<(), String> {
    let challenge = SessionChallenge {
        nonce,
        source: &hello.source,
        public_key: &hello.public_key,
        grant_signature: &hello.grant_signature,
    };
    let message = framed(SESSION_CHALLENGE_DOMAIN, &challenge)?;
    let key = verifying_key_from_hex(&hello.public_key)?;
    let signature = signature_from_hex(signature_hex)?;
    key.verify(&message, &signature)
        .map_err(|error| format!("session challenge signature does not verify: {error}"))
}

fn write_json<T: Serialize>(path: &str, value: &T) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(value).map_err(|error| format!("serialize: {error}"))?;
    write_atomic(path, &format!("{json}\n"))
}

fn read_public_key_hex(path: &str) -> Result<String, String> {
    let text = read_hex_file(path)?;
    verifying_key_from_hex(&text)?;
    Ok(text)
}

fn load_signing_key(path: &str) -> Result<SigningKey, String> {
    check_secret_permissions(path)?;
    let text = read_hex_file(path)?;
    let bytes = decode_fixed::<32>(&text, "signing key")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn verifying_key_from_hex(value: &str) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(&decode_fixed::<32>(value, "public key")?)
        .map_err(|error| format!("invalid public key: {error}"))
}

fn signature_from_hex(value: &str) -> Result<Signature, String> {
    Ok(Signature::from_bytes(&decode_fixed::<64>(
        value,
        "signature",
    )?))
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let bytes =
        hex::decode(value.trim()).map_err(|error| format!("invalid hex {label}: {error}"))?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(|_| format!("{label} must be {N} bytes of hex"))
}

fn read_hex_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map(|value| value.trim().to_ascii_lowercase())
        .map_err(|error| format!("cannot read {path}: {error}"))
}

fn write_secret(path: &str, hex_secret: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| format!("cannot write {path}: {error}"))?;
        writeln!(file, "{hex_secret}").map_err(|error| format!("cannot write {path}: {error}"))
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .and_then(|mut file| writeln!(file, "{hex_secret}"))
            .map_err(|error| format!("cannot write {path}: {error}"))
    }
}

fn check_secret_permissions(path: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|error| format!("cannot stat {path}: {error}"))?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{path} has permissions {mode:o}; identity signing keys must be owner-only (0600)"
            ));
        }
    }
    Ok(())
}

// ---- grant revocation + history backfill (ADR 0014) ----------------------------------

pub(crate) struct RevokeOutput {
    source: String,
    grant_log: PathBuf,
    active_grants_file: PathBuf,
}

impl RevokeOutput {
    fn message(&self) -> String {
        format!(
            "revoked signed identity for {}\n  grant log: {}\n  active grants: {} (entry removed — writes as {} now fail closed)\n\nThe revoked key material stays on disk as evidence; issue a replacement with\n`dent8 identity rotate-source` or `dent8 agent add` when the source should write again.",
            self.source,
            self.grant_log.display(),
            self.active_grants_file.display(),
            self.source,
        )
    }
}

/// `dent8 identity revoke`: end trust in a source's current grant **without** issuing a
/// replacement — the compromise response rotation cannot express. Appends an issuer-signed
/// `revoked` record and removes the source from the active-grant registry (the write path
/// then fails closed for that source).
pub(crate) fn revoke(
    dir: &str,
    source: &str,
    raw_issuer_key: Option<&str>,
    output: CliOutput,
) -> i32 {
    match revoke_bundle(dir, source, raw_issuer_key) {
        Ok(result) => match output {
            CliOutput::Text => {
                println!("{}", result.message());
                0
            }
            CliOutput::Json => print_json_stdout(&serde_json::json!({
                "status": "ok",
                "tool": "identity revoke",
                "source": result.source,
                "grant_log": path_string(&result.grant_log),
                "active_grants_file": path_string(&result.active_grants_file),
                "message": result.message(),
            })),
        },
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stderr(
                &serde_json::json!({
                    "status": "failed",
                    "tool": "identity revoke",
                    "source": source,
                    "message": error,
                }),
                1,
            ),
        },
    }
}

fn revoke_bundle(
    dir: &str,
    source: &str,
    raw_issuer_key: Option<&str>,
) -> Result<RevokeOutput, String> {
    parse_source(source)?;
    let paths = identity_bundle_paths(dir, Some(source))?;
    let trust = load_trust_at(&path_string(&paths.trust_file), true)?.ok_or_else(|| {
        format!(
            "identity trust registry required at {}",
            paths.trust_file.display()
        )
    })?;
    let grant = load_grant(&path_string(&paths.grant_file))?;
    verify_grant_signature(&grant, &trust)?;
    if grant.grant.source != source {
        return Err(format!(
            "active grant is for {}, not {source}",
            grant.grant.source
        ));
    }
    let issuer_key_path = bootstrap_issuer_key_path(raw_issuer_key, &paths.dir)?;
    if !issuer_key_path.exists() {
        return Err(format!(
            "identity issuer key {} does not exist; pass --issuer-key for the trusted issuer",
            issuer_key_path.display()
        ));
    }
    let issuer_key =
        load_issuer_signing_key_matching_trust(&issuer_key_path, &grant.grant.issuer, &trust)?;

    let grant_log = grant_log_path_in(&paths.dir);
    append_grant_records(
        &grant_log,
        &grant.grant.issuer,
        &issuer_key,
        &[(GrantAction::Revoked, &grant)],
        now_millis().as_unix_millis(),
    )?;
    let mut active = load_active_grants_at(&paths.active_grants_file, false)?.unwrap_or_default();
    active.sources.remove(source);
    write_active_grants_path(&paths.active_grants_file, &active)?;
    Ok(RevokeOutput {
        source: source.to_string(),
        grant_log,
        active_grants_file: paths.active_grants_file,
    })
}

/// `dent8 identity backfill-grant-log`: seed `issued` records (at **now**) for the bundle's
/// current grants that predate the grant log. Deliberately does not invent history —
/// entitlement before the backfill stays *unknown* (ADR 0014).
pub(crate) fn backfill_grant_log(
    dir: &str,
    raw_issuer_key: Option<&str>,
    output: CliOutput,
) -> i32 {
    match backfill_grant_log_inner(dir, raw_issuer_key) {
        Ok((appended, skipped, grant_log)) => {
            let message = format!(
                "grant log {}: backfilled {appended} grant(s), {skipped} already recorded\n\
                 Entitlement before this backfill remains UNKNOWN by design — records are\n\
                 stamped now, not backdated.",
                grant_log.display()
            );
            match output {
                CliOutput::Text => {
                    println!("{message}");
                    0
                }
                CliOutput::Json => print_json_stdout(&serde_json::json!({
                    "status": "ok",
                    "tool": "identity backfill-grant-log",
                    "grant_log": path_string(&grant_log),
                    "appended": appended,
                    "already_recorded": skipped,
                    "message": message,
                })),
            }
        }
        Err(error) => match output {
            CliOutput::Text => {
                eprintln!("{error}");
                1
            }
            CliOutput::Json => print_json_stderr(
                &serde_json::json!({
                    "status": "failed",
                    "tool": "identity backfill-grant-log",
                    "message": error,
                }),
                1,
            ),
        },
    }
}

fn backfill_grant_log_inner(
    dir: &str,
    raw_issuer_key: Option<&str>,
) -> Result<(usize, usize, PathBuf), String> {
    let bundle = absolute_existing_dir(&PathBuf::from(dir))?;
    let trust_file = bundle.join("trust.json");
    let trust = load_trust_at(&path_string(&trust_file), true)?.ok_or_else(|| {
        format!(
            "identity trust registry required at {}",
            trust_file.display()
        )
    })?;
    let grants_dir = bundle.join("grants");
    let mut entries: Vec<SignedSourceGrant> = Vec::new();
    let read_dir = std::fs::read_dir(&grants_dir)
        .map_err(|error| format!("cannot read {}: {error}", grants_dir.display()))?;
    for entry in read_dir {
        let entry = entry.map_err(|error| format!("cannot read grants dir: {error}"))?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let grant = load_grant(&path_string(&path))?;
            verify_grant_signature(&grant, &trust)?;
            entries.push(grant);
        }
    }
    if entries.is_empty() {
        return Err(format!("no grants found under {}", grants_dir.display()));
    }
    let issuer_key_path = bootstrap_issuer_key_path(raw_issuer_key, &bundle)?;
    if !issuer_key_path.exists() {
        return Err(format!(
            "identity issuer key {} does not exist; pass --issuer-key for the trusted issuer",
            issuer_key_path.display()
        ));
    }
    let grant_log = grant_log_path_in(&bundle);
    let mut appended = 0usize;
    let mut skipped = 0usize;
    for grant in &entries {
        if has_issued_record(&grant_log, &grant.signature)? {
            skipped += 1;
            continue;
        }
        let issuer_key =
            load_issuer_signing_key_matching_trust(&issuer_key_path, &grant.grant.issuer, &trust)?;
        append_grant_records(
            &grant_log,
            &grant.grant.issuer,
            &issuer_key,
            &[(GrantAction::Issued, grant)],
            now_millis().as_unix_millis(),
        )?;
        appended += 1;
    }
    Ok((appended, skipped, grant_log))
}

#[cfg(all(test, unix, feature = "async-store"))]
mod session_challenge_tests {
    use super::{
        SESSION_CHALLENGE_DOMAIN, SessionChallenge, SigningKey, VerifiedHello, framed,
        session_nonce, verify_session_prove,
    };
    use ed25519_dalek::Signer;

    /// A source signing key + the `VerifiedHello` the daemon would have stored for it, plus a
    /// nonce. The `grant_signature` is arbitrary here — `verify_session_prove` only needs it to
    /// be the *same bytes* the client signed over (binding is what matters, not validity).
    fn fixture(seed: u8) -> (SigningKey, VerifiedHello, String) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let public_key = hex::encode(key.verifying_key().to_bytes());
        let hello = VerifiedHello {
            source: "source:owner".to_string(),
            public_key,
            grant_signature: "abcd1234".to_string(),
        };
        (key, hello, session_nonce().expect("nonce"))
    }

    /// The exact bytes a client signs, mirroring `verify_session_prove`'s reconstruction.
    fn sign(key: &SigningKey, hello: &VerifiedHello, nonce: &str) -> String {
        let challenge = SessionChallenge {
            nonce,
            source: &hello.source,
            public_key: &hello.public_key,
            grant_signature: &hello.grant_signature,
        };
        let message = framed(SESSION_CHALLENGE_DOMAIN, &challenge).expect("framed");
        hex::encode(key.sign(&message).to_bytes())
    }

    #[test]
    fn a_valid_signature_over_the_challenge_verifies() {
        let (key, hello, nonce) = fixture(1);
        let signature = sign(&key, &hello, &nonce);
        assert!(verify_session_prove(&hello, &nonce, &signature).is_ok());
    }

    #[test]
    fn a_signature_for_a_different_nonce_is_rejected() {
        let (key, hello, nonce) = fixture(2);
        let signature = sign(&key, &hello, &nonce);
        let other_nonce = session_nonce().expect("nonce");
        assert_ne!(nonce, other_nonce);
        // A captured signature cannot be lifted onto a fresh challenge.
        assert!(verify_session_prove(&hello, &other_nonce, &signature).is_err());
    }

    #[test]
    fn a_signature_from_a_different_key_is_rejected() {
        let (attacker, hello, nonce) = fixture(3);
        // `hello` advertises key 3's public key, but a fresh victim key signs. Since the hello
        // used the attacker's key, re-point it at a *different* public key to model substitution.
        let victim = SigningKey::from_bytes(&[9u8; 32]);
        let victim_hello = VerifiedHello {
            source: hello.source.clone(),
            public_key: hex::encode(victim.verifying_key().to_bytes()),
            grant_signature: hello.grant_signature.clone(),
        };
        // The attacker signs the victim's challenge; it must not verify under the victim's key.
        let forged = sign(&attacker, &victim_hello, &nonce);
        assert!(verify_session_prove(&victim_hello, &nonce, &forged).is_err());
    }

    #[test]
    fn a_signature_over_a_tampered_grant_is_rejected() {
        let (key, hello, nonce) = fixture(4);
        let signature = sign(&key, &hello, &nonce);
        // Same nonce + key, but a different presented grant signature: the binding breaks.
        let rotated = VerifiedHello {
            source: hello.source.clone(),
            public_key: hello.public_key.clone(),
            grant_signature: "ffff0000".to_string(),
        };
        assert!(verify_session_prove(&rotated, &nonce, &signature).is_err());
    }

    #[test]
    fn the_challenge_serializes_in_a_pinned_field_order() {
        // The client and daemon must produce byte-identical `framed` input; field order is part
        // of the wire contract. Pin it so a struct reordering is caught here, not in the field.
        let challenge = SessionChallenge {
            nonce: "NONCE",
            source: "source:owner",
            public_key: "PUBKEY",
            grant_signature: "SIG",
        };
        let json = serde_json::to_string(&challenge).expect("serialize");
        assert_eq!(
            json,
            r#"{"nonce":"NONCE","source":"source:owner","public_key":"PUBKEY","grant_signature":"SIG"}"#
        );
    }

    #[test]
    fn a_nonce_is_64_hex_chars_and_fresh_each_call() {
        let a = session_nonce().expect("nonce");
        let b = session_nonce().expect("nonce");
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "32 bytes of CSPRNG must not repeat");
    }
}
