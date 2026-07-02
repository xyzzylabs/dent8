//! Signed source identity for the CLI/MCP write boundary.
//!
//! The authority registry answers "what may this source claim?" Signed identity answers
//! "is this caller actually holding the key for that source?" The model is deliberately
//! small: a trusted issuer public key verifies a signed grant binding a source id to a
//! source public key and authority ceiling; the dent8 process signs each write request with
//! the source private key and verifies that signature before the write reaches the firewall.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use dent8_core::{AuthorityLevel, TimestampMillis};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{CliAuthority, WriteAuth, env_flag, now_millis, parse_source, write_atomic};

const DEFAULT_TRUST: &str = "dent8-trust.json";
const ACTIVE_GRANTS_FILE: &str = "active-grants.json";
const GRANT_DOMAIN: &[u8] = b"dent8.source-grant.v1\0";
const WRITE_DOMAIN: &[u8] = b"dent8.source-write.v1\0";
const DAY_MILLIS: i64 = 86_400_000;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct TrustedIssuers {
    issuers: BTreeMap<String, TrustedIssuer>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrustedIssuer {
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SignedSourceGrant {
    grant: SourceGrantPayload,
    signature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ActiveSourceGrants {
    sources: BTreeMap<String, ActiveSourceGrant>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveSourceGrant {
    grant_signature: String,
    public_key: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize)]
struct WriteSignaturePayload<'a> {
    version: u8,
    operation: &'a str,
    source: &'a str,
    authority: AuthorityLevel,
    subject_kind: &'a str,
    subject_key: &'a str,
    predicate: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derived_from: Option<WriteSignatureSource<'a>>,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct WriteSignatureSource<'a> {
    subject_kind: &'a str,
    subject_key: &'a str,
    predicate: &'a str,
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

fn env_string(name: &str) -> Result<String, String> {
    std::env::var(name)
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} must point to a signed source identity file"))
}

pub(crate) fn enforce_write(auth: &WriteAuth<'_>, now: TimestampMillis) -> Result<(), String> {
    let required = identity_required()?;
    let path = trust_path();
    let configured = required
        || nonempty_env_is_set("DENT8_TRUST")
        || nonempty_env_is_set("DENT8_GRANT")
        || nonempty_env_is_set("DENT8_IDENTITY_KEY")
        || std::path::Path::new(&path).exists();
    let Some(trust) = load_trust_at(&path, configured)? else {
        return Ok(());
    };
    if trust.issuers.is_empty() {
        return Err("identity trust registry is empty; no issuer can verify grants".to_string());
    }

    let grant = load_grant(&grant_path()?)?;
    verify_grant(&grant, &trust, now)?;
    verify_grant_matches_write(&grant.grant, auth, now)?;
    verify_active_grant_if_configured(&grant, &path)?;

    let signing = load_signing_key(&identity_key_path()?)?;
    let source_key = signing.verifying_key();
    let grant_key = verifying_key_from_hex(&grant.grant.public_key)?;
    if source_key.to_bytes() != grant_key.to_bytes() {
        return Err(format!(
            "identity key does not match the grant for {}",
            grant.grant.source
        ));
    }

    let payload = write_payload(auth);
    let signature = signing.sign(&framed(WRITE_DOMAIN, &payload)?);
    source_key
        .verify(&framed(WRITE_DOMAIN, &payload)?, &signature)
        .map_err(|error| format!("could not verify write signature: {error}"))?;
    Ok(())
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
        Ok(output) => {
            println!("{}", output.message());
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

pub(crate) fn issuer_keygen(out: &str) -> i32 {
    keygen(out, "issuer")
}

pub(crate) fn agent_keygen(source: &str, out: &str) -> i32 {
    if let Err(error) = parse_source(source) {
        eprintln!("{error}");
        return 2;
    }
    keygen(out, source)
}

pub(crate) fn trust_add(issuer: &str, public_key_path: &str) -> i32 {
    let public_key = match read_public_key_hex(public_key_path) {
        Ok(public_key) => public_key,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    let path = trust_path();
    let mut trust = match load_trust_at(&path, false) {
        Ok(Some(trust)) => trust,
        Ok(None) => TrustedIssuers::default(),
        Err(error) => {
            eprintln!("{error}");
            return 2;
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
            println!("trusted issuer {issuer} at {path}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

pub(crate) fn trust_list() -> i32 {
    match load_trust_at(&trust_path(), false) {
        Ok(None) => {
            println!("no identity trust registry at {}", trust_path());
            0
        }
        Ok(Some(trust)) if trust.issuers.is_empty() => {
            println!("identity trust registry is empty");
            0
        }
        Ok(Some(trust)) => {
            for (issuer, trusted) in trust.issuers {
                println!("{issuer}  public_key={}", trusted.public_key);
            }
            0
        }
        Err(error) => {
            eprintln!("{error}");
            2
        }
    }
}

pub(crate) fn status(
    dir: &str,
    source: Option<&str>,
    issuer_key: Option<&str>,
    expires_warning_days: u64,
) -> i32 {
    match identity_status(dir, source, issuer_key, expires_warning_days) {
        Ok(lines) => {
            println!("identity status");
            let ok = print_status_lines(&lines);
            i32::from(!ok)
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

pub(crate) fn repair_env(dir: &str, source: &str) -> i32 {
    match repair_env_bundle(dir, source) {
        Ok(message) => {
            println!("{message}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

#[allow(clippy::too_many_lines)]
pub(crate) fn rotate_source(
    dir: &str,
    source: &str,
    issuer_key: Option<&str>,
    max_authority: Option<CliAuthority>,
    scope: Option<&str>,
    expires_at_ms: Option<i64>,
) -> i32 {
    match rotate_source_bundle(dir, source, issuer_key, max_authority, scope, expires_at_ms) {
        Ok(output) => {
            println!("{output}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn print_status_lines(lines: &[DoctorLine]) -> bool {
    let mut ok = true;
    for line in lines {
        if !line.ok {
            ok = false;
        }
        println!("  {}  {}", line.level, line.message);
    }
    ok
}

fn identity_status(
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

fn verify_active_grant_if_configured(
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

pub(crate) fn repair_env_bundle(dir: &str, source: &str) -> Result<String, String> {
    parse_source(source)?;
    let paths = identity_bundle_paths(dir, Some(source))?;
    let trust = load_trust_at(&path_string(&paths.trust_file), true)?.ok_or_else(|| {
        format!(
            "identity trust registry required at {}",
            paths.trust_file.display()
        )
    })?;
    let grant = load_grant(&path_string(&paths.grant_file))?;
    verify_grant(&grant, &trust, now_millis())?;
    if grant.grant.source != source {
        return Err(format!(
            "grant source is {}, expected {source}",
            grant.grant.source
        ));
    }
    verify_source_key_matches_grant(&paths.source_key_path, &grant)?;

    let mut active = load_active_grants_at(&paths.active_grants_file, false)?.unwrap_or_default();
    let repaired_active = match active.sources.get(source) {
        Some(entry) if active_entry_matches_grant(entry, &grant) => false,
        Some(_) => {
            return Err(format!(
                "active grant registry {} already has a different current grant for {source}; \
                 refusing to overwrite it",
                paths.active_grants_file.display()
            ));
        }
        None => {
            active
                .sources
                .insert(source.to_string(), active_source_grant_for(&grant));
            write_active_grants_path(&paths.active_grants_file, &active)?;
            true
        }
    };
    write_identity_env(&paths)?;

    let mut lines = vec![
        format!("repaired signed identity env for {source}"),
        format!("  env: {}", paths.env_file.display()),
        format!("  active grants: {}", paths.active_grants_file.display()),
    ];
    if repaired_active {
        lines.push("  active grants: restored current grant entry from signed grant".to_string());
    }
    lines.push(String::new());
    lines.push(format!(
        "Next:\n  dent8 identity status --dir {} --source {source}\n  dent8 doctor --source {source} --write-check",
        shell_quote(&path_string(&paths.dir))
    ));
    Ok(lines.join("\n"))
}

#[allow(clippy::too_many_lines)]
fn rotate_source_bundle(
    dir: &str,
    source: &str,
    raw_issuer_key: Option<&str>,
    max_authority: Option<CliAuthority>,
    scope: Option<&str>,
    expires_at_ms: Option<i64>,
) -> Result<String, String> {
    parse_source(source)?;
    let paths = identity_bundle_paths(dir, Some(source))?;
    let trust = load_trust_at(&path_string(&paths.trust_file), true)?.ok_or_else(|| {
        format!(
            "identity trust registry required at {}",
            paths.trust_file.display()
        )
    })?;
    let old_grant = load_grant(&path_string(&paths.grant_file))?;
    verify_grant_signature(&old_grant, &trust)?;
    if old_grant.grant.source != source {
        return Err(format!(
            "active grant is for {}, not {source}",
            old_grant.grant.source
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
        load_issuer_signing_key_matching_trust(&issuer_key_path, &old_grant.grant.issuer, &trust)?;

    let replacement_scope = match scope {
        Some(scope) if scope.trim().is_empty() => {
            return Err(
                "identity grant scope must not be empty; use `*` for all subjects".to_string(),
            );
        }
        Some(scope) => Some(scope.to_string()),
        None => old_grant.grant.scope.clone(),
    };
    let replacement = generate_signing_key()?;
    let grant = SourceGrantPayload {
        version: 1,
        source: source.to_string(),
        public_key: hex::encode(replacement.verifying_key().to_bytes()),
        max_authority: max_authority.map_or(old_grant.grant.max_authority, CliAuthority::level),
        issuer: old_grant.grant.issuer.clone(),
        scope: replacement_scope,
        expires_at_ms: expires_at_ms.or(old_grant.grant.expires_at_ms),
    };
    let signed = SignedSourceGrant {
        signature: hex::encode(issuer_key.sign(&framed(GRANT_DOMAIN, &grant)?).to_bytes()),
        grant,
    };
    let mut active = load_active_grants_at(&paths.active_grants_file, false)?.unwrap_or_default();
    if active.sources.contains_key(source) {
        verify_active_grant(&old_grant, &active)?;
    }

    let stamp = now_millis().as_unix_millis();
    let mut rollback = RotationRollback::default();
    let key_backup = rollback.backup_required(&paths.source_key_path, stamp)?;
    let public_key_path = public_key_path(&paths.source_key_path);
    let public_backup = rollback.backup_optional(&public_key_path, stamp)?;
    let grant_backup = rollback.backup_required(&paths.grant_file, stamp)?;
    let active_backup = rollback.backup_optional(&paths.active_grants_file, stamp)?;
    let env_backup = rollback.backup_required(&paths.env_file, stamp)?;

    write_key_pair(&paths.source_key_path, &replacement)?;
    rollback.record_key_pair(&paths.source_key_path);
    write_json_path(&paths.grant_file, &signed)?;
    rollback.record_file(&paths.grant_file);
    active
        .sources
        .insert(source.to_string(), active_source_grant_for(&signed));
    write_active_grants_path(&paths.active_grants_file, &active)?;
    rollback.record_file(&paths.active_grants_file);
    write_identity_env(&paths)?;
    rollback.record_file(&paths.env_file);
    remove_rotated_private_key_backup(&key_backup)?;
    rollback.commit();

    let mut lines = vec![
        format!(
            "rotated source identity for {source} in {}",
            paths.dir.display()
        ),
        format!("  source key: {}", paths.source_key_path.display()),
        format!("  grant: {}", paths.grant_file.display()),
        format!("  active grants: {}", paths.active_grants_file.display()),
        format!("  env: {}", paths.env_file.display()),
        "  old source key backup: removed after successful rotation".to_string(),
        format!("  old grant backup: {}", grant_backup.display()),
        format!("  old env backup: {}", env_backup.display()),
    ];
    if let Some(active_backup) = active_backup {
        lines.push(format!(
            "  old active grant backup: {}",
            active_backup.display()
        ));
    }
    if let Some(public_backup) = public_backup {
        lines.push(format!(
            "  old public key backup: {}",
            public_backup.display()
        ));
    }
    lines.push(String::new());
    lines.push(format!(
        "Next:\n  dent8 identity status --dir {} --source {source}\n  dent8 doctor --source {source} --write-check",
        shell_quote(&path_string(&paths.dir))
    ));
    Ok(lines.join("\n"))
}

pub(crate) fn identity_env_path_for_source(dir: &Path, source: &str) -> Result<PathBuf, String> {
    parse_source(source)?;
    let suffix = source
        .strip_prefix("source:")
        .ok_or_else(|| format!("source id must start with source:, got {source}"))?;
    Ok(dir.join(format!("identity-{}.env", path_slug(suffix))))
}

fn identity_bundle_paths(
    dir: &str,
    expected_source: Option<&str>,
) -> Result<IdentityBundlePaths, String> {
    let dir = absolute_existing_dir(&PathBuf::from(dir))?;
    let trust_file = dir.join("trust.json");
    let active_grants_file = dir.join(ACTIVE_GRANTS_FILE);
    if let Some(source) = expected_source {
        parse_source(source)?;
        let slug = source_slug(source);
        return Ok(IdentityBundlePaths {
            trust_file,
            active_grants_file,
            grant_file: dir.join("grants").join(format!("{slug}.grant.json")),
            source_key_path: dir.join("identities").join(format!("{slug}.key")),
            env_file: identity_env_path_for_source(&dir, source)?,
            dir,
        });
    }

    let legacy_env = dir.join("identity.env");
    if legacy_env.exists() {
        let env = read_identity_env_file(&legacy_env)?;
        let grant_file = env
            .get("DENT8_GRANT")
            .ok_or_else(|| format!("{} is missing DENT8_GRANT", legacy_env.display()))
            .map(|path| env_path_value(path, &dir))?;
        let source_key_path = env
            .get("DENT8_IDENTITY_KEY")
            .ok_or_else(|| format!("{} is missing DENT8_IDENTITY_KEY", legacy_env.display()))
            .map(|path| env_path_value(path, &dir))?;
        let trust_file = env
            .get("DENT8_TRUST")
            .map_or(trust_file, |path| env_path_value(path, &dir));
        let active_grants_file = env
            .get("DENT8_ACTIVE_GRANTS")
            .map_or(active_grants_file, |path| env_path_value(path, &dir));
        return Ok(IdentityBundlePaths {
            dir,
            trust_file,
            active_grants_file,
            grant_file,
            source_key_path,
            env_file: legacy_env,
        });
    }

    if active_grants_file.exists() {
        let active = load_active_grants_at(&active_grants_file, true)?
            .ok_or_else(|| format!("{} is empty", active_grants_file.display()))?;
        return match active.sources.len() {
            0 => Err(format!(
                "{} has no active source grants; pass --source or run `dent8 identity repair-env`",
                active_grants_file.display()
            )),
            1 => {
                let source = active
                    .sources
                    .keys()
                    .next()
                    .expect("checked len above")
                    .clone();
                identity_bundle_paths(&path_string(&dir), Some(&source))
            }
            _ => Err(
                "multiple active source grants in this bundle; pass --source to select one"
                    .to_string(),
            ),
        };
    }

    Err(format!(
        "cannot read {}; run `dent8 identity repair-env --dir {} --source <source>`",
        legacy_env.display(),
        shell_quote(&path_string(&dir))
    ))
}

fn env_path_value(raw: &str, bundle_dir: &Path) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        bundle_dir.join(path)
    }
}

fn read_identity_env_file(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut env = BTreeMap::new();
    for (line_no, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!(
                "{}:{} is not a KEY=VALUE line",
                path.display(),
                line_no + 1
            ));
        };
        env.insert(key.trim().to_string(), shell_unquote(value.trim()));
    }
    Ok(env)
}

fn shell_unquote(value: &str) -> String {
    if value.len() >= 2 && value.starts_with('\'') && value.ends_with('\'') {
        value[1..value.len() - 1].replace("'\\''", "'")
    } else {
        value.to_string()
    }
}

fn write_identity_env(paths: &IdentityBundlePaths) -> Result<(), String> {
    let env_contents = format!(
        "# dent8 signed source identity environment\n\
         # Load with: set -a; . {}; set +a\n\
         DENT8_TRUST={}\n\
         DENT8_ACTIVE_GRANTS={}\n\
         DENT8_REQUIRE_IDENTITY=1\n\
         DENT8_GRANT={}\n\
         DENT8_IDENTITY_KEY={}\n",
        shell_quote(&path_string(&paths.env_file)),
        shell_quote(&path_string(&paths.trust_file)),
        shell_quote(&path_string(&paths.active_grants_file)),
        shell_quote(&path_string(&paths.grant_file)),
        shell_quote(&path_string(&paths.source_key_path)),
    );
    write_text_path(&paths.env_file, &env_contents)
}

fn verify_grant_signature(grant: &SignedSourceGrant, trust: &TrustedIssuers) -> Result<(), String> {
    if grant.grant.version != 1 {
        return Err(format!("unsupported grant version {}", grant.grant.version));
    }
    if let Err(error) = parse_source(&grant.grant.source) {
        return Err(format!("grant source is invalid: {error}"));
    }
    verifying_key_from_hex(&grant.grant.public_key)?;
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

fn load_issuer_key_matching_trust(
    path: &Path,
    issuer_name: &str,
    trust: &TrustedIssuers,
) -> Result<(), String> {
    load_issuer_signing_key_matching_trust(path, issuer_name, trust).map(|_| ())
}

fn load_issuer_signing_key_matching_trust(
    path: &Path,
    issuer_name: &str,
    trust: &TrustedIssuers,
) -> Result<SigningKey, String> {
    let signing = load_signing_key(&path_string(path))?;
    let trusted = trust
        .issuers
        .get(issuer_name)
        .ok_or_else(|| format!("untrusted grant issuer {issuer_name}"))?;
    let trusted_key = verifying_key_from_hex(&trusted.public_key)?;
    if signing.verifying_key().to_bytes() != trusted_key.to_bytes() {
        return Err(format!(
            "{} does not match trusted issuer {issuer_name}",
            path.display()
        ));
    }
    Ok(signing)
}

#[derive(Default)]
struct RotationRollback {
    backups: Vec<(PathBuf, PathBuf)>,
    created_files: Vec<PathBuf>,
    committed: bool,
}

impl RotationRollback {
    fn backup_required(&mut self, path: &Path, stamp: i64) -> Result<PathBuf, String> {
        if !path.exists() {
            return Err(format!(
                "{} does not exist; cannot rotate it",
                path.display()
            ));
        }
        self.backup_existing(path, stamp)
    }

    fn backup_optional(&mut self, path: &Path, stamp: i64) -> Result<Option<PathBuf>, String> {
        if path.exists() {
            self.backup_existing(path, stamp).map(Some)
        } else {
            Ok(None)
        }
    }

    fn backup_existing(&mut self, path: &Path, stamp: i64) -> Result<PathBuf, String> {
        let backup = available_backup_path(path, stamp);
        std::fs::rename(path, &backup).map_err(|error| {
            format!(
                "cannot move {} to backup {}: {error}",
                path.display(),
                backup.display()
            )
        })?;
        self.backups.push((path.to_path_buf(), backup.clone()));
        Ok(backup)
    }

    fn record_file(&mut self, path: &Path) {
        self.created_files.push(path.to_path_buf());
    }

    fn record_key_pair(&mut self, private_path: &Path) {
        self.record_file(private_path);
        self.record_file(&public_key_path(private_path));
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for RotationRollback {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for path in self.created_files.iter().rev() {
            let _ = std::fs::remove_file(path);
        }
        for (original, backup) in self.backups.iter().rev() {
            let _ = std::fs::rename(backup, original);
        }
    }
}

fn available_backup_path(path: &Path, stamp: i64) -> PathBuf {
    for attempt in 0u32.. {
        let candidate = backup_path(path, stamp, attempt);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!("unbounded backup path search should always return");
}

fn backup_path(path: &Path, stamp: i64, attempt: u32) -> PathBuf {
    let suffix = if attempt == 0 {
        format!(".old.{stamp}")
    } else {
        format!(".old.{stamp}.{attempt}")
    };
    PathBuf::from(format!("{}{suffix}", path.to_string_lossy()))
}

fn remove_rotated_private_key_backup(path: &Path) -> Result<(), String> {
    std::fs::remove_file(path).map_err(|error| {
        format!(
            "cannot remove old source private-key backup {}: {error}",
            path.display()
        )
    })
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn grant_issue(
    source: &str,
    public_key_path: &str,
    max_authority: CliAuthority,
    issuer: &str,
    issuer_key_path: &str,
    out: &str,
    scope: Option<&str>,
    expires_at_ms: Option<i64>,
) -> i32 {
    if let Err(error) = parse_source(source) {
        eprintln!("{error}");
        return 2;
    }
    let public_key = match read_public_key_hex(public_key_path) {
        Ok(public_key) => public_key,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    let issuer_key = match load_signing_key(issuer_key_path) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("{error}");
            return 2;
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
            eprintln!("{error}");
            return 2;
        }
    };
    let signed = SignedSourceGrant {
        signature: hex::encode(issuer_key.sign(&message).to_bytes()),
        grant,
    };
    match write_json(out, &signed) {
        Ok(()) => {
            println!("issued signed grant for {source} -> {out}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

pub(crate) fn grant_verify(path: &str) -> i32 {
    let trust = match load_trust_at(&trust_path(), true) {
        Ok(Some(trust)) => trust,
        Ok(None) => {
            eprintln!("identity trust registry required but not found");
            return 2;
        }
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    let grant = match load_grant(path) {
        Ok(grant) => grant,
        Err(error) => {
            eprintln!("{error}");
            return 2;
        }
    };
    match verify_grant(&grant, &trust, now_millis()) {
        Ok(()) => {
            println!(
                "OK: grant for {} max={:?} issuer={}",
                grant.grant.source, grant.grant.max_authority, grant.grant.issuer
            );
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

pub(crate) fn bootstrap_bundle(
    dir: &str,
    source: &str,
    issuer: &str,
    issuer_key: Option<&str>,
    max_authority: CliAuthority,
    scope: &str,
    expires_at_ms: Option<i64>,
) -> Result<BootstrapOutput, String> {
    let plan = bootstrap_plan(dir, source, issuer, issuer_key, scope)?;
    preflight_bootstrap_plan(&plan)?;

    let mut rollback = BootstrapRollback::default();
    ensure_dir(&plan.dir, &mut rollback)?;
    ensure_dir(&plan.identities_dir, &mut rollback)?;
    ensure_dir(&plan.grants_dir, &mut rollback)?;

    let issuer_key = load_or_create_issuer_key(&plan.issuer_key_path, &mut rollback)?;
    let source_key = generate_signing_key()?;
    write_key_pair(&plan.source_key_path, &source_key)?;
    rollback.record_key_pair(&plan.source_key_path);

    let mut trust = TrustedIssuers::default();
    trust.issuers.insert(
        issuer.to_string(),
        TrustedIssuer {
            public_key: hex::encode(issuer_key.verifying_key().to_bytes()),
        },
    );
    write_json_path(&plan.trust_file, &trust)?;
    rollback.record_file(&plan.trust_file);

    let grant = SourceGrantPayload {
        version: 1,
        source: source.to_string(),
        public_key: hex::encode(source_key.verifying_key().to_bytes()),
        max_authority: max_authority.level(),
        issuer: issuer.to_string(),
        scope: Some(scope.to_string()),
        expires_at_ms,
    };
    let signature = hex::encode(issuer_key.sign(&framed(GRANT_DOMAIN, &grant)?).to_bytes());
    let signed_grant = SignedSourceGrant { grant, signature };
    write_json_path(&plan.grant_file, &signed_grant)?;
    rollback.record_file(&plan.grant_file);

    let mut active = ActiveSourceGrants::default();
    active
        .sources
        .insert(source.to_string(), active_source_grant_for(&signed_grant));
    write_active_grants_path(&plan.active_grants_file, &active)?;
    rollback.record_file(&plan.active_grants_file);

    let env_contents = format!(
        "# dent8 signed source identity environment\n\
         # Load with: set -a; . {}; set +a\n\
         DENT8_TRUST={}\n\
         DENT8_ACTIVE_GRANTS={}\n\
         DENT8_REQUIRE_IDENTITY=1\n\
         DENT8_GRANT={}\n\
         DENT8_IDENTITY_KEY={}\n",
        shell_quote(&path_string(&plan.env_file)),
        shell_quote(&path_string(&plan.trust_file)),
        shell_quote(&path_string(&plan.active_grants_file)),
        shell_quote(&path_string(&plan.grant_file)),
        shell_quote(&path_string(&plan.source_key_path)),
    );
    write_text_path(&plan.env_file, &env_contents)?;
    rollback.record_file(&plan.env_file);
    rollback.commit();

    Ok(BootstrapOutput {
        issuer: issuer.to_string(),
        source: source.to_string(),
        max_authority: max_authority.level(),
        scope: scope.to_string(),
        issuer_key_path: plan.issuer_key_path,
        trust_file: plan.trust_file,
        active_grants_file: plan.active_grants_file,
        grant_file: plan.grant_file,
        source_key_path: plan.source_key_path,
        env_file: plan.env_file,
        bundle_dir: plan.dir,
    })
}

pub(crate) fn preflight_bootstrap_bundle(
    dir: &str,
    source: &str,
    issuer: &str,
    issuer_key: Option<&str>,
    scope: &str,
) -> Result<(), String> {
    let plan = bootstrap_plan(dir, source, issuer, issuer_key, scope)?;
    preflight_bootstrap_plan(&plan)
}

fn bootstrap_plan(
    dir: &str,
    source: &str,
    issuer: &str,
    issuer_key: Option<&str>,
    scope: &str,
) -> Result<BootstrapPlan, String> {
    parse_source(source)?;
    if issuer.trim().is_empty() {
        return Err("identity issuer must not be empty".to_string());
    }
    if scope.trim().is_empty() {
        return Err("identity grant scope must not be empty; use `*` for all subjects".to_string());
    }

    let dir = absolute_dir_for_new(&PathBuf::from(dir))?;
    let identities_dir = dir.join("identities");
    let grants_dir = dir.join("grants");

    let slug = source_slug(source);
    let issuer_key_path = bootstrap_issuer_key_path(issuer_key, &dir)?;
    let source_key_path = identities_dir.join(format!("{slug}.key"));
    let source_public_path = public_key_path(&source_key_path);
    let trust_file = dir.join("trust.json");
    let active_grants_file = dir.join(ACTIVE_GRANTS_FILE);
    let grant_file = grants_dir.join(format!("{slug}.grant.json"));
    let env_file = identity_env_path_for_source(&dir, source)?;

    Ok(BootstrapPlan {
        dir,
        identities_dir,
        grants_dir,
        issuer_key_path,
        source_key_path,
        source_public_path,
        trust_file,
        active_grants_file,
        grant_file,
        env_file,
    })
}

fn preflight_bootstrap_plan(plan: &BootstrapPlan) -> Result<(), String> {
    for path in [
        plan.dir.as_path(),
        plan.identities_dir.as_path(),
        plan.grants_dir.as_path(),
    ] {
        ensure_dir_available(path)?;
    }
    for path in plan.identity_outputs() {
        ensure_absent(path)?;
    }
    preflight_issuer_key(&plan.issuer_key_path)
}

fn keygen(out: &str, label: &str) -> i32 {
    let out = Path::new(out);
    if out.exists() {
        eprintln!(
            "{} already exists; refusing to overwrite a signing key",
            out.display()
        );
        return 1;
    }
    let public = public_key_path(out);
    if public.exists() {
        eprintln!(
            "{} already exists; refusing to overwrite a public key",
            public.display()
        );
        return 1;
    }
    let signing = match generate_signing_key() {
        Ok(signing) => signing,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    if let Err(error) = write_key_pair(out, &signing) {
        eprintln!("{error}");
        return 1;
    }
    println!(
        "wrote {label} signing key to {}\nwrote public key to {}",
        out.display(),
        public.display()
    );
    0
}

fn generate_signing_key() -> Result<SigningKey, String> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|error| format!("could not gather randomness for the key: {error}"))?;
    Ok(SigningKey::from_bytes(&seed))
}

#[derive(Default)]
struct BootstrapRollback {
    files: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
    committed: bool,
}

impl BootstrapRollback {
    fn record_file(&mut self, path: &Path) {
        self.files.push(path.to_path_buf());
    }

    fn record_key_pair(&mut self, private_path: &Path) {
        self.record_file(private_path);
        self.record_file(&public_key_path(private_path));
    }

    fn record_dir(&mut self, path: &Path) {
        self.dirs.push(path.to_path_buf());
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for BootstrapRollback {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for path in self.files.iter().rev() {
            let _ = std::fs::remove_file(path);
        }
        for path in self.dirs.iter().rev() {
            let _ = std::fs::remove_dir(path);
        }
    }
}

fn bootstrap_issuer_key_path(raw: Option<&str>, bundle_dir: &Path) -> Result<PathBuf, String> {
    let key = match raw {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        Some(_) => return Err("identity issuer key path must not be empty".to_string()),
        None => default_issuer_key_path()?,
    };
    let key = absolute_path_for_new(&key)?;
    if key.starts_with(bundle_dir) {
        return Err(format!(
            "identity issuer key {} is inside {}; keep issuer keys outside the agent/project bundle",
            key.display(),
            bundle_dir.display()
        ));
    }
    Ok(key)
}

fn default_issuer_key_path() -> Result<PathBuf, String> {
    if let Some(path) = nonempty_env("DENT8_ISSUER_KEY") {
        return Ok(PathBuf::from(path));
    }
    if let Some(path) = nonempty_env("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(path).join("dent8/issuer.key"));
    }
    if let Some(home) = nonempty_env("HOME") {
        return Ok(PathBuf::from(home).join(".config/dent8/issuer.key"));
    }
    Err(
        "identity bootstrap needs --issuer-key because neither XDG_CONFIG_HOME nor HOME is set"
            .to_string(),
    )
}

fn absolute_dir_for_new(path: &Path) -> Result<PathBuf, String> {
    let candidate = absolute_candidate(path)?;
    if candidate.exists() {
        return candidate
            .canonicalize()
            .map_err(|error| format!("cannot resolve {}: {error}", candidate.display()));
    }
    canonicalize_parent_for_new(&candidate)
}

fn absolute_existing_dir(path: &Path) -> Result<PathBuf, String> {
    let candidate = absolute_candidate(path)?;
    let resolved = candidate
        .canonicalize()
        .map_err(|error| format!("cannot resolve {}: {error}", candidate.display()))?;
    if !resolved.is_dir() {
        return Err(format!(
            "{} is not an identity bundle directory",
            resolved.display()
        ));
    }
    Ok(resolved)
}

fn absolute_path_for_new(path: &Path) -> Result<PathBuf, String> {
    canonicalize_parent_for_new(&absolute_candidate(path)?)
}

fn absolute_candidate(path: &Path) -> Result<PathBuf, String> {
    let candidate = if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("cannot resolve {}: {error}", path.display()))
    }?;
    Ok(candidate)
}

fn canonicalize_parent_for_new(candidate: &Path) -> Result<PathBuf, String> {
    if let (Some(parent), Some(file_name)) = (candidate.parent(), candidate.file_name()) {
        return canonicalize_existing_prefix(parent)
            .map(|parent| parent.join(file_name))
            .map_err(|error| format!("cannot resolve {}: {error}", candidate.display()));
    }
    Ok(candidate.to_path_buf())
}

fn canonicalize_existing_prefix(path: &Path) -> Result<PathBuf, std::io::Error> {
    if path.exists() {
        return path.canonicalize();
    }
    if let (Some(parent), Some(file_name)) = (path.parent(), path.file_name()) {
        return canonicalize_existing_prefix(parent).map(|parent| parent.join(file_name));
    }
    Ok(path.to_path_buf())
}

fn load_or_create_issuer_key(
    path: &Path,
    rollback: &mut BootstrapRollback,
) -> Result<SigningKey, String> {
    if path.exists() {
        let signing = load_signing_key(&path_string(path))?;
        ensure_public_key_for_key(path, &signing, rollback)?;
        return Ok(signing);
    }

    let public = public_key_path(path);
    if public.exists() {
        return Err(format!(
            "{} exists but {} does not; refusing to pair a public key with a newly generated issuer key",
            public.display(),
            path.display()
        ));
    }
    if let Some(parent) = parent_dir(path) {
        ensure_dir(parent, rollback)?;
    }
    let signing = generate_signing_key()?;
    write_key_pair(path, &signing)?;
    rollback.record_key_pair(path);
    Ok(signing)
}

fn preflight_issuer_key(path: &Path) -> Result<(), String> {
    if path.exists() {
        let signing = load_signing_key(&path_string(path))?;
        let public_path = public_key_path(path);
        if public_path.exists() {
            let actual = read_hex_file(&path_string(&public_path))?;
            let expected = hex::encode(signing.verifying_key().to_bytes());
            if actual != expected {
                return Err(format!(
                    "{} does not match issuer key {}",
                    public_path.display(),
                    path.display()
                ));
            }
        }
        return Ok(());
    }

    let public_path = public_key_path(path);
    if public_path.exists() {
        return Err(format!(
            "{} exists but {} does not; refusing to pair a public key with a newly generated issuer key",
            public_path.display(),
            path.display()
        ));
    }
    ensure_parent_available(path)
}

fn ensure_public_key_for_key(
    private_path: &Path,
    signing: &SigningKey,
    rollback: &mut BootstrapRollback,
) -> Result<(), String> {
    let public_path = public_key_path(private_path);
    let expected = hex::encode(signing.verifying_key().to_bytes());
    if public_path.exists() {
        let actual = read_hex_file(&path_string(&public_path))?;
        if actual == expected {
            return Ok(());
        }
        return Err(format!(
            "{} does not match issuer key {}",
            public_path.display(),
            private_path.display()
        ));
    }
    write_public_key_file(&public_path, &expected)?;
    rollback.record_file(&public_path);
    Ok(())
}

fn write_key_pair(private_path: &Path, signing: &SigningKey) -> Result<(), String> {
    let private = path_string(private_path);
    write_secret(&private, &hex::encode(signing.to_bytes()))?;
    let public_path = public_key_path(private_path);
    let public_key = hex::encode(signing.verifying_key().to_bytes());
    if let Err(error) = write_public_key_file(&public_path, &public_key) {
        let _ = std::fs::remove_file(private_path);
        return Err(format!(
            "cannot write {}: {error} (removed partial key {})",
            public_path.display(),
            private_path.display()
        ));
    }
    Ok(())
}

fn write_public_key_file(path: &Path, public_key: &str) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut file| writeln!(file, "{public_key}"))
        .map_err(|error| error.to_string())
}

fn public_key_path(private_path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", private_path.to_string_lossy()))
}

fn ensure_dir(path: &Path, rollback: &mut BootstrapRollback) -> Result<(), String> {
    if path.exists() {
        if path.is_dir() {
            return Ok(());
        }
        return Err(format!("{} exists but is not a directory", path.display()));
    }
    std::fs::create_dir_all(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    rollback.record_dir(path);
    Ok(())
}

fn ensure_dir_available(path: &Path) -> Result<(), String> {
    if path.exists() && !path.is_dir() {
        return Err(format!("{} exists but is not a directory", path.display()));
    }
    Ok(())
}

fn ensure_parent_available(path: &Path) -> Result<(), String> {
    let Some(mut cursor) = parent_dir(path) else {
        return Ok(());
    };
    loop {
        if cursor.exists() {
            return ensure_dir_available(cursor);
        }
        let Some(parent) = parent_dir(cursor) else {
            return Ok(());
        };
        if parent == cursor {
            return Ok(());
        }
        cursor = parent;
    }
}

fn parent_dir(path: &Path) -> Option<&Path> {
    let parent = path.parent()?;
    if parent.as_os_str().is_empty() {
        None
    } else {
        Some(parent)
    }
}

fn ensure_absent(path: &Path) -> Result<(), String> {
    if path.exists() {
        Err(format!(
            "{} already exists; refusing to overwrite identity bootstrap output",
            path.display()
        ))
    } else {
        Ok(())
    }
}

fn write_json_path<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    write_json(&path_string(path), value)
}

fn write_text_path(path: &Path, contents: &str) -> Result<(), String> {
    write_atomic(&path_string(path), contents)
}

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
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

fn write_payload<'a>(auth: &WriteAuth<'a>) -> WriteSignaturePayload<'a> {
    WriteSignaturePayload {
        version: 1,
        operation: auth.operation,
        source: auth.source,
        authority: auth.authority,
        subject_kind: auth.subject_kind,
        subject_key: auth.subject_key,
        predicate: auth.predicate,
        value: auth.value,
        derived_from: auth.derived_from.map(|source| WriteSignatureSource {
            subject_kind: source.subject_kind,
            subject_key: source.subject_key,
            predicate: source.predicate,
        }),
    }
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
