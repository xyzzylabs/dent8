//! Identity-bundle lifecycle internals: the filesystem side of `bootstrap`, `agent add`,
//! `rotate-source`, and `repair-env` — key generation and issuer-key management, the bundle
//! path layout and per-source env files, grant issuance/rotation against the active-grant
//! registry (with the ADR 0014 grant-log appends), and the rollback guards that keep a
//! failed ceremony from leaving a half-written bundle behind. The command surfaces (arg
//! handling, output shaping, JSON) stay in the parent module.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
use serde::Serialize;

use super::records::{GrantAction, append_grant_records, grant_log_path_in};
use super::{
    ACTIVE_GRANTS_FILE, ActiveSourceGrants, BootstrapOutput, BootstrapPlan, GRANT_DOMAIN,
    IdentityBundlePaths, KeygenOutput, RepairEnvOutput, RotateSourceOutput, SignedSourceGrant,
    SourceGrantPayload, SourceIdentityOutput, TrustedIssuer, TrustedIssuers,
    active_entry_matches_grant, active_source_grant_for, framed, load_active_grants_at, load_grant,
    load_signing_key, load_trust_at, nonempty_env, path_slug, read_hex_file, shell_quote,
    signature_from_hex, source_slug, verify_active_grant, verify_grant,
    verify_source_key_matches_grant, verifying_key_from_hex, write_active_grants_path, write_json,
    write_secret,
};
use crate::{CliAuthority, now_millis, parse_source, write_atomic};

pub(crate) fn repair_env_bundle(dir: &str, source: &str) -> Result<String, String> {
    repair_env_bundle_outcome(dir, source).map(|outcome| outcome.message())
}

pub(super) fn repair_env_bundle_outcome(
    dir: &str,
    source: &str,
) -> Result<RepairEnvOutput, String> {
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

    Ok(RepairEnvOutput {
        source: source.to_string(),
        dir: paths.dir,
        active_grants_file: paths.active_grants_file,
        env_file: paths.env_file,
        repaired_active,
    })
}

pub(crate) fn add_source_to_bundle(
    dir: &str,
    source: &str,
    requested_issuer: Option<&str>,
    issuer_key: Option<&str>,
    max_authority: CliAuthority,
    scope: &str,
    expires_at_ms: Option<i64>,
) -> Result<SourceIdentityOutput, String> {
    parse_source(source)?;
    if scope.trim().is_empty() {
        return Err("identity grant scope must not be empty; use `*` for all subjects".to_string());
    }
    let paths = identity_bundle_paths(dir, Some(source))?;
    if let Some(existing) = reuse_or_reject_existing_source_identity(dir, source, &paths)? {
        return Ok(existing);
    }

    issue_source_identity(
        paths,
        source,
        requested_issuer,
        issuer_key,
        max_authority,
        scope,
        expires_at_ms,
    )
}

fn reuse_or_reject_existing_source_identity(
    dir: &str,
    source: &str,
    paths: &IdentityBundlePaths,
) -> Result<Option<SourceIdentityOutput>, String> {
    let source_public_path = public_key_path(&paths.source_key_path);
    let grant_exists = paths.grant_file.exists();
    let source_key_exists = paths.source_key_path.exists();
    let source_public_exists = source_public_path.exists();
    let env_exists = paths.env_file.exists();

    if grant_exists && source_key_exists {
        repair_env_bundle(dir, source)?;
        let grant = load_grant(&path_string(&paths.grant_file))?;
        return Ok(Some(SourceIdentityOutput {
            source: grant.grant.source,
            issuer: grant.grant.issuer,
            max_authority: grant.grant.max_authority,
            scope: grant.grant.scope.unwrap_or_else(|| "*".to_string()),
            active_grants_file: paths.active_grants_file.clone(),
            grant_file: paths.grant_file.clone(),
            source_key_path: paths.source_key_path.clone(),
            env_file: paths.env_file.clone(),
            reused: true,
        }));
    }

    if grant_exists || source_key_exists || source_public_exists || env_exists {
        return Err(format!(
            "partial signed identity material already exists for {source} in {}; refusing to \
             guess or rotate. Expected either both {} and {}, or none of {}, {}, {}, {}.",
            paths.dir.display(),
            paths.grant_file.display(),
            paths.source_key_path.display(),
            paths.grant_file.display(),
            paths.source_key_path.display(),
            source_public_path.display(),
            paths.env_file.display()
        ));
    }

    Ok(None)
}

fn issue_source_identity(
    paths: IdentityBundlePaths,
    source: &str,
    requested_issuer: Option<&str>,
    issuer_key: Option<&str>,
    max_authority: CliAuthority,
    scope: &str,
    expires_at_ms: Option<i64>,
) -> Result<SourceIdentityOutput, String> {
    let trust = load_trust_at(&path_string(&paths.trust_file), true)?.ok_or_else(|| {
        format!(
            "identity trust registry required at {}; run `dent8 init --agent <profile> \
             --store sqlite` first",
            paths.trust_file.display()
        )
    })?;
    let issuer = select_issuer(requested_issuer, &trust)?;
    let issuer_key_path = bootstrap_issuer_key_path(issuer_key, &paths.dir)?;
    let issuer_signing = load_issuer_signing_key_matching_trust(&issuer_key_path, &issuer, &trust)?;
    let mut active = load_active_grants_at(&paths.active_grants_file, false)?.unwrap_or_default();
    if active.sources.contains_key(source) {
        return Err(format!(
            "{} already has an active grant entry for {source}, but the grant/key files are \
             missing; refusing to create a mismatched replacement",
            paths.active_grants_file.display()
        ));
    }

    let mut rollback = BootstrapRollback::default();
    if let Some(parent) = parent_dir(&paths.source_key_path) {
        ensure_dir(parent, &mut rollback)?;
    }
    if let Some(parent) = parent_dir(&paths.grant_file) {
        ensure_dir(parent, &mut rollback)?;
    }

    let source_key = generate_signing_key()?;
    write_key_pair(&paths.source_key_path, &source_key)?;
    rollback.record_key_pair(&paths.source_key_path);

    let grant = SourceGrantPayload {
        version: 1,
        source: source.to_string(),
        public_key: hex::encode(source_key.verifying_key().to_bytes()),
        max_authority: max_authority.level(),
        issuer: issuer.clone(),
        scope: Some(scope.to_string()),
        expires_at_ms,
    };
    let signature = hex::encode(
        issuer_signing
            .sign(&framed(GRANT_DOMAIN, &grant)?)
            .to_bytes(),
    );
    let signed_grant = SignedSourceGrant { grant, signature };
    write_json_path(&paths.grant_file, &signed_grant)?;
    rollback.record_file(&paths.grant_file);
    write_identity_env(&paths)?;
    rollback.record_file(&paths.env_file);

    let active_created = !paths.active_grants_file.exists();
    active
        .sources
        .insert(source.to_string(), active_source_grant_for(&signed_grant));
    write_active_grants_path(&paths.active_grants_file, &active)?;
    if active_created {
        rollback.record_file(&paths.active_grants_file);
    }
    // Grant history (ADR 0014): record the issuance.
    let grant_log = grant_log_path_in(&paths.dir);
    let grant_log_created = !grant_log.exists();
    append_grant_records(
        &grant_log,
        &signed_grant.grant.issuer,
        &issuer_signing,
        &[(GrantAction::Issued, &signed_grant)],
        now_millis().as_unix_millis(),
    )?;
    if grant_log_created {
        rollback.record_file(&grant_log);
    }
    rollback.commit();

    Ok(SourceIdentityOutput {
        source: signed_grant.grant.source,
        issuer: signed_grant.grant.issuer,
        max_authority: signed_grant.grant.max_authority,
        scope: signed_grant.grant.scope.unwrap_or_else(|| "*".to_string()),
        active_grants_file: paths.active_grants_file,
        grant_file: paths.grant_file,
        source_key_path: paths.source_key_path,
        env_file: paths.env_file,
        reused: false,
    })
}

fn select_issuer(requested: Option<&str>, trust: &TrustedIssuers) -> Result<String, String> {
    if let Some(issuer) = requested {
        let issuer = issuer.trim();
        if issuer.is_empty() {
            return Err("identity issuer must not be empty".to_string());
        }
        if !trust.issuers.contains_key(issuer) {
            return Err(format!("untrusted grant issuer {issuer}"));
        }
        return Ok(issuer.to_string());
    }

    match trust.issuers.len() {
        0 => Err("identity trust registry has no trusted issuers".to_string()),
        1 => Ok(trust
            .issuers
            .keys()
            .next()
            .expect("checked trusted issuer count")
            .clone()),
        _ => Err(
            "identity trust registry has multiple trusted issuers; pass --issuer explicitly"
                .to_string(),
        ),
    }
}

#[allow(clippy::too_many_lines)]
pub(super) fn rotate_source_bundle(
    dir: &str,
    source: &str,
    raw_issuer_key: Option<&str>,
    max_authority: Option<CliAuthority>,
    scope: Option<&str>,
    expires_at_ms: Option<i64>,
) -> Result<RotateSourceOutput, String> {
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
    // Grant history (ADR 0014): a rotation is a revocation of the old grant plus an issuance
    // of the replacement, landed as one write. A failed append fails the rotation.
    append_grant_records(
        &grant_log_path_in(&paths.dir),
        &old_grant.grant.issuer,
        &issuer_key,
        &[
            (GrantAction::Revoked, &old_grant),
            (GrantAction::Issued, &signed),
        ],
        now_millis().as_unix_millis(),
    )?;
    remove_rotated_private_key_backup(&key_backup)?;
    rollback.commit();

    Ok(RotateSourceOutput {
        source: source.to_string(),
        dir: paths.dir,
        source_key_path: paths.source_key_path,
        grant_file: paths.grant_file,
        active_grants_file: paths.active_grants_file,
        env_file: paths.env_file,
        old_grant_backup: grant_backup,
        old_env_backup: env_backup,
        old_active_grant_backup: active_backup,
        old_public_key_backup: public_backup,
    })
}

pub(crate) fn identity_env_path_for_source(dir: &Path, source: &str) -> Result<PathBuf, String> {
    parse_source(source)?;
    let suffix = source
        .strip_prefix("source:")
        .ok_or_else(|| format!("source id must start with source:, got {source}"))?;
    Ok(dir.join(format!("identity-{}.env", path_slug(suffix))))
}

pub(super) fn identity_bundle_paths(
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
        "cannot infer identity source from {}; pass --source or run \
         `dent8 identity repair-env --dir {} --source <source>`",
        active_grants_file.display(),
        shell_quote(&path_string(&dir))
    ))
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

pub(super) fn verify_grant_signature(
    grant: &SignedSourceGrant,
    trust: &TrustedIssuers,
) -> Result<(), String> {
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

pub(super) fn load_issuer_key_matching_trust(
    path: &Path,
    issuer_name: &str,
    trust: &TrustedIssuers,
) -> Result<(), String> {
    load_issuer_signing_key_matching_trust(path, issuer_name, trust).map(|_| ())
}

pub(super) fn load_issuer_signing_key_matching_trust(
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
    // Grant history (ADR 0014): record the issuance.
    let grant_log = grant_log_path_in(&plan.dir);
    let grant_log_created = !grant_log.exists();
    append_grant_records(
        &grant_log,
        issuer,
        &issuer_key,
        &[(GrantAction::Issued, &signed_grant)],
        now_millis().as_unix_millis(),
    )?;
    if grant_log_created {
        rollback.record_file(&grant_log);
    }

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

pub(super) fn keygen_outcome(out: &str, label: &str) -> Result<KeygenOutput, String> {
    // `--out keychain:<account>`: the private key goes into the OS keychain (no file, no
    // `.pub` sibling — the public key is reported and derivable from the private item).
    if let Some(account) = super::keychain_account(out) {
        let signing = generate_signing_key()?;
        super::keychain_write_new(account, &hex::encode(signing.to_bytes()))?;
        return Ok(KeygenOutput {
            label: label.to_string(),
            private_key_path: PathBuf::from(format!("keychain:{account}")),
            public_key_path: None,
            public_key_hex: hex::encode(signing.verifying_key().to_bytes()),
        });
    }
    let out = Path::new(out);
    if out.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite a signing key",
            out.display()
        ));
    }
    let public = public_key_path(out);
    if public.exists() {
        return Err(format!(
            "{} already exists; refusing to overwrite a public key",
            public.display()
        ));
    }
    let signing = generate_signing_key()?;
    write_key_pair(out, &signing)?;
    Ok(KeygenOutput {
        label: label.to_string(),
        private_key_path: out.to_path_buf(),
        public_key_path: Some(public),
        public_key_hex: hex::encode(signing.verifying_key().to_bytes()),
    })
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

pub(super) fn bootstrap_issuer_key_path(
    raw: Option<&str>,
    bundle_dir: &Path,
) -> Result<PathBuf, String> {
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

pub(super) fn default_issuer_key_path() -> Result<PathBuf, String> {
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

pub(super) fn absolute_existing_dir(path: &Path) -> Result<PathBuf, String> {
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
    // Bundle flows (bootstrap / rotate) lay out key *files* in a directory; a keychain ref
    // reaching here would silently create a literal `keychain:…` file instead.
    if super::keychain_account(&private).is_some() {
        return Err(
            "bootstrap/rotate write key files into the bundle directory and do not support \
             keychain: references yet; `identity agent-keygen`/`issuer-keygen` accept \
             --out keychain:<account>"
                .to_string(),
        );
    }
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

pub(super) fn write_json_path<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    write_json(&path_string(path), value)
}

fn write_text_path(path: &Path, contents: &str) -> Result<(), String> {
    write_atomic(&path_string(path), contents)
}

pub(super) fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
