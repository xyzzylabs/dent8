//! Signed source identity for the CLI/MCP write boundary.
//!
//! The authority registry answers "what may this source claim?" Signed identity answers
//! "is this caller actually holding the key for that source?" The model is deliberately
//! small: a trusted issuer public key verifies a signed grant binding a source id to a
//! source public key and authority ceiling; the dent8 process signs each write request with
//! the source private key and verifies that signature before the write reaches the firewall.

use std::collections::BTreeMap;
use std::io::Write;

use dent8_core::{AuthorityLevel, TimestampMillis};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::{CliAuthority, WriteAuth, env_flag, now_millis, parse_source, write_atomic};

const DEFAULT_TRUST: &str = "dent8-trust.json";
const GRANT_DOMAIN: &[u8] = b"dent8.source-grant.v1\0";
const WRITE_DOMAIN: &[u8] = b"dent8.source-write.v1\0";

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

fn keygen(out: &str, label: &str) -> i32 {
    if std::path::Path::new(out).exists() {
        eprintln!("{out} already exists; refusing to overwrite a signing key");
        return 1;
    }
    let mut seed = [0u8; 32];
    if let Err(error) = getrandom::getrandom(&mut seed) {
        eprintln!("could not gather randomness for the key: {error}");
        return 1;
    }
    let signing = SigningKey::from_bytes(&seed);
    let public = format!("{out}.pub");
    if std::path::Path::new(&public).exists() {
        eprintln!("{public} already exists; refusing to overwrite a public key");
        return 1;
    }
    if let Err(error) = write_secret(out, &hex::encode(signing.to_bytes())) {
        eprintln!("{error}");
        return 1;
    }
    if let Err(error) = std::fs::write(
        &public,
        format!("{}\n", hex::encode(signing.verifying_key().to_bytes())),
    ) {
        let _ = std::fs::remove_file(out);
        eprintln!("cannot write {public}: {error} (removed partial key {out})");
        return 1;
    }
    println!("wrote {label} signing key to {out}\nwrote public key to {public}");
    0
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
