//! The **op layer**: every CLI/MCP belief operation (`assert` / `supersede` / `retract` /
//! `contradict` / `reinforce` / `expire` / `derive` and the read side `explain` / `replay` /
//! `facts list` / `conflicts`), sharing one firewall/persistence path. Each `op_*` is the
//! transport-agnostic core (used by both `cmd_*` here and the MCP tools); each `cmd_*` adds
//! the CLI presentation (text or `--output json`) on top. Storage plumbing (`load_store`,
//! `append_events`, attestation) and the write-boundary auth gate stay in the crate root.

use dent8_core::{
    ActorId, Authority, AuthorityLevel, ChallengeKind, ChallengeRejection, ClaimEvent,
    ClaimEventId, ClaimEventKind, ClaimId, ClaimLifecycle, ClaimValue, Confidence,
    ContradictionBasis, EntityRef, Evidence, EvidenceId, EvidenceKind, Predicate, Provenance,
    RetractionReason, SupersessionReason, TimestampMillis, Ttl,
};
use dent8_store::{
    AppendReceipt, EventFilter, EventStore, InMemoryEventStore, IntegrityReceipt,
    PredicateRegistry, StoreError, apply_policy_defaults, enforce_policy, replay_claim,
    replay_entity,
};

use std::str::FromStr;

use crate::{
    CliOutput, CliStream, CliSubject, DeriveWriteArgs, FactWriteArgs, FactsListArgs, ReadFactArgs,
    ValueWriteArgs, WriteAuth, WriteError, WriteIdentity, append_events, attest_events,
    claim_value_json, display_value, enforce_write_authority, format_receipt, load_store, log_path,
    next_seq, now_millis, paint_status, parse_predicate, print_json_stderr, print_json_stdout,
    read_annotation, receipt_fields_json, receipt_json, short,
};

/// Build a validated `ClaimEvent` from CLI strings, returning a friendly error rather than
/// panicking on malformed input. The `kind` and `value` distinguish an assertion from a
/// supersession; `claim_id` is the *subject* claim of the event (the new claim for an
/// assertion, the incumbent for a supersession).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_event(
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
            tool: Some("dent8".to_string()),
            run_id: None,
            input_digest: None,
            recorded_at: now,
            attestation: None,
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
        valid_to: None,
    })
}

/// A failed operation: `Invalid` is a malformed request (CLI exit 2 / MCP tool error),
/// `Rejected` is a well-formed request the firewall or store refused (CLI exit 1 / MCP
/// tool error). Carrying the distinction lets the CLI keep its exit codes while the MCP
/// server reports both as tool errors.
pub(crate) enum OpError {
    Invalid(String),
    Rejected(String),
    /// A retryable concurrent-writer conflict (Postgres optimistic-id race). Surfaced so
    /// [`with_write_retry`] can re-run the operation against a fresh snapshot; it never reaches
    /// the user unless retries are exhausted (then it is downgraded to `Rejected`).
    Conflict(String),
}

impl OpError {
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Invalid(message) | Self::Rejected(message) | Self::Conflict(message) => message,
        }
    }
}

/// Map a durable-append failure to an `OpError`, preserving the retryable conflict signal.
/// `Other` covers both an I/O failure and a durable firewall rejection (e.g. a same-subject
/// race the in-memory snapshot admitted but the transaction rejected), so the message says
/// "could not commit" rather than implying the write was admitted-then-lost.
pub(crate) fn write_error_to_op(error: WriteError) -> OpError {
    match error {
        WriteError::Conflict(message) => OpError::Conflict(message),
        WriteError::Other(message) => {
            OpError::Rejected(format!("could not commit the write: {message}"))
        }
    }
}

/// The valid-time interval for a written assertion (ADR 0016), unix millis. `from` is
/// also the TTL freshness anchor; `to` is the asserted end of validity (past it the fact
/// reads as stale). Defaults to an open interval (unset).
#[derive(Clone, Copy, Default)]
pub(crate) struct Validity {
    pub(crate) from: Option<i64>,
    pub(crate) to: Option<i64>,
}

impl Validity {
    fn stamp(self, event: &mut ClaimEvent) {
        event.valid_from = self.from.map(TimestampMillis::from_unix_millis);
        event.valid_to = self.to.map(TimestampMillis::from_unix_millis);
    }
}

/// The temporal frame for a read (ADR 0016): `as_of` folds only events recorded at or
/// before that instant (transaction-time travel); `valid_at` sets the instant freshness
/// and validity are evaluated at. Defaults read the full log at wall-clock now.
#[derive(Clone, Copy, Default)]
pub(crate) struct ReadClock {
    pub(crate) as_of: Option<i64>,
    pub(crate) valid_at: Option<i64>,
}

impl ReadClock {
    /// The instant freshness/validity is judged at.
    fn now(self) -> TimestampMillis {
        self.valid_at
            .map_or_else(now_millis, TimestampMillis::from_unix_millis)
    }

    /// The store as this clock sees it. With `as_of`, the fold is restricted to events
    /// recorded at or before that instant — trusting appender-supplied `recorded_at`
    /// exactly as freshness always has. The filtered prefix skips the trusted-reload
    /// uniqueness gate: it re-reads a historical state that was admitted event-by-event
    /// when written, judged by the clock of *that* time.
    fn store(self, path: &str) -> Result<InMemoryEventStore, String> {
        let store = load_store(path)?;
        let Some(as_of) = self.as_of else {
            return Ok(store);
        };
        let at = TimestampMillis::from_unix_millis(as_of);
        let events: Vec<ClaimEvent> = store
            .scan_events(&EventFilter::default())
            .map_err(|error| error.to_string())?
            .into_iter()
            .filter(|event| event.provenance.recorded_at <= at)
            .collect();
        InMemoryEventStore::from_trusted_events(events)
            .map_err(|error| format!("as-of load: {error}"))
    }
}

/// Apply registry defaults and predicate policy before the event reaches the store firewall.
/// The file-backed CLI uses this against a fresh snapshot, then persists the same event bytes
/// so the durable log agrees with the receipt hash.
pub(crate) fn admit(
    store: &mut InMemoryEventStore,
    registry: &PredicateRegistry,
    mut event: ClaimEvent,
    now: TimestampMillis,
) -> Result<AppendReceipt, StoreError> {
    apply_policy_defaults(registry, &mut event);
    enforce_policy(registry, store, &event, now)?;
    store.append(event)
}

/// ADR 0015: survived-challenge recording is on unless `DENT8_RECORD_CHALLENGES` is
/// explicitly falsy. A malformed value keeps recording — the safe direction is more
/// evidence, and a typo must not silently erase the attack audit.
fn challenge_recording_enabled() -> bool {
    match std::env::var("DENT8_RECORD_CHALLENGES") {
        Err(_) => true,
        Ok(value) if value.trim().is_empty() => true,
        Ok(_) => crate::env_flag("DENT8_RECORD_CHALLENGES").unwrap_or(true),
    }
}

/// ADR 0015: the earned-supersession gate is opt-in (`DENT8_ENTRENCHMENT_GATE=1`). A
/// malformed value fails toward enforcement — the project convention for security flags:
/// a typo must not silently disable a gate the operator tried to set.
fn entrenchment_gate_enabled() -> bool {
    match std::env::var("DENT8_ENTRENCHMENT_GATE") {
        Err(_) => false,
        Ok(value) if value.trim().is_empty() => false,
        Ok(_) => crate::env_flag("DENT8_ENTRENCHMENT_GATE").unwrap_or(true),
    }
}

/// Classify a firewall rejection as a survivable challenge (ADR 0015): only a real contest
/// lost **on strength** counts — insufficient stated authority, a laundered supersession,
/// or the canonical hard-alarm. Malformed writes, duplicates, and terminal-state mutations
/// are never recorded. Returns the challenge shape and the challenger's *effective*
/// authority (for a laundered supersession, the backing claim's actual level — "survived a
/// High challenge" must mean the challenge was actually High).
fn classify_challenge(
    candidate: &ClaimEvent,
    error: &StoreError,
) -> Option<(
    ChallengeKind,
    Option<ClaimId>,
    ChallengeRejection,
    AuthorityLevel,
)> {
    use dent8_core::TransitionError as T;
    let stated = candidate.authority.level;
    match (&candidate.kind, error) {
        (
            ClaimEventKind::Superseded { by, .. },
            StoreError::Rejected(T::InsufficientAuthority { .. }),
        ) => Some((
            ChallengeKind::Supersession,
            Some(by.clone()),
            ChallengeRejection::InsufficientAuthority,
            stated,
        )),
        (
            ClaimEventKind::Superseded { by, .. },
            StoreError::LaunderedAuthority { challenger, .. },
        ) => Some((
            ChallengeKind::Supersession,
            Some(by.clone()),
            ChallengeRejection::LaunderedAuthority,
            *challenger,
        )),
        (
            ClaimEventKind::Contradicted { by, .. },
            StoreError::Rejected(T::CanonicalContradiction),
        ) => Some((
            ChallengeKind::Contradiction,
            Some(by.clone()),
            ChallengeRejection::CanonicalContradiction,
            stated,
        )),
        (
            ClaimEventKind::Retracted { .. },
            StoreError::Rejected(T::InsufficientAuthority { .. }),
        ) => Some((
            ChallengeKind::Retraction,
            None,
            ChallengeRejection::InsufficientAuthority,
            stated,
        )),
        (ClaimEventKind::Expired { .. }, StoreError::Rejected(T::InsufficientAuthority { .. })) => {
            Some((
                ChallengeKind::Expiration,
                None,
                ChallengeRejection::InsufficientAuthority,
                stated,
            ))
        }
        _ => None,
    }
}

/// ADR 0015 — persist one `ChallengeRejected` bookkeeping event on the incumbent's stream.
/// Arbitrated and appended against a **fresh** snapshot: the caller's in-memory store may
/// hold admitted-but-never-persisted siblings of the rejected write (e.g. a supersession's
/// replacement assertion), and the record must take the next *durable* event id.
#[allow(clippy::too_many_arguments)]
fn persist_challenge_record(
    path: &str,
    incumbent: &ClaimId,
    subject: &EntityRef,
    predicate: &Predicate,
    challenge: ChallengeKind,
    by: Option<ClaimId>,
    rejection: ChallengeRejection,
    source: &str,
    effective: AuthorityLevel,
    identity: &WriteIdentity,
) -> bool {
    let Ok(mut store) = load_store(path) else {
        return false;
    };
    let Ok(record) = build_event(
        &format!("event:{}", next_seq(&store)),
        incumbent.as_str(),
        subject.kind(),
        subject.key(),
        predicate.as_str(),
        ClaimEventKind::ChallengeRejected {
            challenge,
            by,
            rejection,
        },
        None,
        source,
        effective,
        now_millis(),
    ) else {
        return false;
    };
    if store.append(record.clone()).is_err() {
        return false;
    }
    let mut batch = [record];
    append_events(path, &mut batch, identity).is_ok()
}

/// The note appended to a rejection message when the survived challenge was recorded.
const CHALLENGE_RECORDED_NOTE: &str =
    "\n  the incumbent recorded the survived challenge (claim.challenge_rejected)";

/// ADR 0015 — when a rejected write was a real challenge lost on strength, record the
/// survival on the incumbent's stream with the **challenger's** provenance (so identity
/// attestation binds the attempt to the challenger's key). Best-effort: a recording
/// failure never masks the original rejection; the returned note is appended to the
/// caller's error message when a record was persisted.
fn record_survived_challenge(
    path: &str,
    candidate: &ClaimEvent,
    error: &StoreError,
    identity: &WriteIdentity,
) -> &'static str {
    if !challenge_recording_enabled() {
        return "";
    }
    let Some((challenge, by, rejection, effective)) = classify_challenge(candidate, error) else {
        return "";
    };
    if persist_challenge_record(
        path,
        &candidate.claim_id,
        &candidate.subject,
        &candidate.predicate,
        challenge,
        by,
        rejection,
        candidate.provenance.source.as_str(),
        effective,
        identity,
    ) {
        CHALLENGE_RECORDED_NOTE
    } else {
        ""
    }
}

/// Run a write operation, retrying on a concurrent-writer conflict. Each attempt re-runs the
/// whole `op_*` (fresh snapshot → fresh `event:{n}` id → re-arbitrate → append), so a retry
/// mints a non-colliding id and commits. Between attempts it backs off with per-process jitter
/// to **de-synchronize a thundering herd** — immediate retries would re-collide on the same
/// next id, so the spread is what lets many concurrent writers converge. A success or any
/// non-conflict failure returns immediately. Without the `postgres` feature no conflict is ever
/// produced, so this runs `op` exactly once.
pub(crate) fn with_write_retry(
    mut op: impl FnMut() -> Result<String, OpError>,
) -> Result<String, OpError> {
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
pub(crate) fn back_off(attempt: u32) {
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
#[allow(clippy::too_many_arguments)]
pub(crate) fn op_assert(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    value: &str,
    authority: AuthorityLevel,
    source: &str,
    validity: Validity,
    identity: &WriteIdentity,
) -> Result<String, OpError> {
    enforce_write_authority(
        &WriteAuth::new(subject_kind, subject_key, authority, source),
        identity,
    )?;
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
    validity.stamp(&mut event);
    let registry = PredicateRegistry::coding_agent();
    // Apply the predicate's default TTL up front so the event we *persist* is byte-identical
    // to the one `admit` arbitrates and hashes (otherwise the durable event would carry
    // `Ttl::Never` and a hash that disagrees with the receipt on reload).
    apply_policy_defaults(&registry, &mut event);
    // Attest before `admit` so the receipt hash is computed over the exact (attested) bytes
    // that will be persisted; the deterministic re-sign inside `append_events` is a no-op.
    attest_events(std::slice::from_mut(&mut event), identity).map_err(OpError::Invalid)?;
    let receipt = admit(&mut store, &registry, event.clone(), now)
        .map_err(|error| OpError::Rejected(format!("REJECTED: {error}")))?;
    append_events(path, std::slice::from_mut(&mut event), identity).map_err(write_error_to_op)?;
    Ok(format!(
        "ACCEPTED  {subject_kind}:{subject_key} {predicate} = \"{value}\"  (authority={authority:?})\n  \
         seq={}  hash={}",
        receipt.global_sequence,
        short(&receipt.event_hash)
    ))
}

pub(crate) fn cmd_assert(args: &ValueWriteArgs, output: CliOutput) -> i32 {
    let view = value_write_json_view("assert", args);
    let outcome = with_write_retry(|| {
        op_assert(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            &args.value,
            args.authority.level(),
            &args.source,
            Validity {
                from: args.valid_from,
                to: args.valid_to,
            },
            &WriteIdentity::Env,
        )
    });
    present_write(outcome, output, &view)
}

/// Assert a fact **derived from** another fact, recording the claim->claim dependency edge
/// (`EvidenceKind::DerivedFrom`, ADR 0010). The source is named by *subject* (kind/key/
/// predicate) and resolved to its currently-believed claim id(s), so no internal claim id need
/// be typed. If that source is later retracted/expired, `verify` flags this derivative as
/// tainted. Shared by `dent8 derive` and the MCP `derive` tool.
#[allow(clippy::too_many_arguments)]
pub(crate) fn op_derive(
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
    validity: Validity,
    identity: &WriteIdentity,
) -> Result<String, OpError> {
    enforce_write_authority(
        &WriteAuth::new(subject_kind, subject_key, authority, source),
        identity,
    )?;
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
    validity.stamp(&mut event);
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
    // Attest before `admit` so the receipt hash is computed over the exact (attested) bytes
    // that will be persisted; the deterministic re-sign inside `append_events` is a no-op.
    attest_events(std::slice::from_mut(&mut event), identity).map_err(OpError::Invalid)?;
    let receipt = admit(&mut store, &registry, event.clone(), now)
        .map_err(|error| OpError::Rejected(format!("REJECTED: {error}")))?;
    append_events(path, std::slice::from_mut(&mut event), identity).map_err(write_error_to_op)?;
    Ok(format!(
        "ACCEPTED  {subject_kind}:{subject_key} {predicate} = \"{value}\"  (authority={authority:?}, \
         derived from {from_kind}:{from_key} {from_predicate})\n  seq={}  hash={}",
        receipt.global_sequence,
        short(&receipt.event_hash)
    ))
}

pub(crate) fn cmd_derive(args: &DeriveWriteArgs, output: CliOutput) -> i32 {
    let from_subject = match CliSubject::from_str(&args.from[0]) {
        Ok(subject) => subject,
        Err(message) => {
            return present_write(
                Err(OpError::Invalid(message)),
                output,
                &WriteJsonView::derive_without_source(args),
            );
        }
    };
    let from_predicate = match parse_predicate(&args.from[1]) {
        Ok(predicate) => predicate,
        Err(message) => {
            return present_write(
                Err(OpError::Invalid(message)),
                output,
                &WriteJsonView::derive_without_source(args),
            );
        }
    };
    let view = WriteJsonView {
        tool: "derive",
        subject_kind: &args.subject.kind,
        subject_key: &args.subject.key,
        predicate: &args.predicate,
        value: Some(&args.value),
        authority: args.authority.level(),
        source: &args.source,
        derived_from: Some(DerivedFromJson {
            subject_kind: &from_subject.kind,
            subject_key: &from_subject.key,
            predicate: &from_predicate,
        }),
    };
    let outcome = with_write_retry(|| {
        op_derive(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            &args.value,
            args.authority.level(),
            &args.source,
            &from_subject.kind,
            &from_subject.key,
            &from_predicate,
            Validity {
                from: args.valid_from,
                to: args.valid_to,
            },
            &WriteIdentity::Env,
        )
    });
    present_write(outcome, output, &view)
}

/// Render an operation result for the CLI: success to stdout (exit 0), a malformed request
/// to stderr (exit 2), a refused one to stderr (exit 1).
pub(crate) fn present(outcome: Result<String, OpError>) -> i32 {
    match outcome {
        Ok(message) => {
            println!("{}", paint_status(&message, CliStream::Stdout));
            0
        }
        Err(OpError::Invalid(message)) => {
            eprintln!("{}", paint_status(&message, CliStream::Stderr));
            2
        }
        Err(OpError::Rejected(message) | OpError::Conflict(message)) => {
            eprintln!("{}", paint_status(&message, CliStream::Stderr));
            1
        }
    }
}

pub(crate) fn op_error_json(error: &OpError) -> serde_json::Value {
    match error {
        OpError::Invalid(message) => serde_json::json!({
            "status": "invalid",
            "message": message,
        }),
        OpError::Rejected(message) | OpError::Conflict(message) => serde_json::json!({
            "status": "rejected",
            "message": message,
        }),
    }
}

pub(crate) struct DerivedFromJson<'a> {
    subject_kind: &'a str,
    subject_key: &'a str,
    predicate: &'a str,
}

pub(crate) struct WriteJsonView<'a> {
    tool: &'static str,
    subject_kind: &'a str,
    subject_key: &'a str,
    predicate: &'a str,
    value: Option<&'a str>,
    authority: AuthorityLevel,
    source: &'a str,
    derived_from: Option<DerivedFromJson<'a>>,
}

impl<'a> WriteJsonView<'a> {
    fn derive_without_source(args: &'a DeriveWriteArgs) -> Self {
        Self {
            tool: "derive",
            subject_kind: &args.subject.kind,
            subject_key: &args.subject.key,
            predicate: &args.predicate,
            value: Some(&args.value),
            authority: args.authority.level(),
            source: &args.source,
            derived_from: None,
        }
    }
}

pub(crate) fn value_write_json_view<'a>(
    tool: &'static str,
    args: &'a ValueWriteArgs,
) -> WriteJsonView<'a> {
    WriteJsonView {
        tool,
        subject_kind: &args.subject.kind,
        subject_key: &args.subject.key,
        predicate: &args.predicate,
        value: Some(&args.value),
        authority: args.authority.level(),
        source: &args.source,
        derived_from: None,
    }
}

pub(crate) fn fact_write_json_view<'a>(
    tool: &'static str,
    args: &'a FactWriteArgs,
) -> WriteJsonView<'a> {
    WriteJsonView {
        tool,
        subject_kind: &args.subject.kind,
        subject_key: &args.subject.key,
        predicate: &args.predicate,
        value: None,
        authority: args.authority.level(),
        source: &args.source,
        derived_from: None,
    }
}

pub(crate) fn write_value_json(value: Option<&str>) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, |text| {
        claim_value_json(&ClaimValue::Text(text.to_string()))
    })
}

pub(crate) fn derived_from_write_json(value: Option<&DerivedFromJson<'_>>) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, |from| {
        serde_json::json!({
            "subject": {
                "kind": from.subject_kind,
                "key": from.subject_key,
            },
            "predicate": from.predicate,
        })
    })
}

pub(crate) fn write_success_json(view: &WriteJsonView<'_>, message: &str) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": view.tool,
        "accepted": true,
        "subject": {
            "kind": view.subject_kind,
            "key": view.subject_key,
        },
        "predicate": view.predicate,
        "value": write_value_json(view.value),
        "authority": view.authority.name(),
        "source": view.source,
        "derived_from": derived_from_write_json(view.derived_from.as_ref()),
        "message": message,
    })
}

pub(crate) fn write_error_json(view: &WriteJsonView<'_>, error: &OpError) -> serde_json::Value {
    let mut value = op_error_json(error);
    let object = value
        .as_object_mut()
        .expect("operation error should serialize as an object");
    object.insert("tool".to_string(), serde_json::json!(view.tool));
    object.insert("accepted".to_string(), serde_json::json!(false));
    object.insert(
        "subject".to_string(),
        serde_json::json!({
            "kind": view.subject_kind,
            "key": view.subject_key,
        }),
    );
    object.insert("predicate".to_string(), serde_json::json!(view.predicate));
    object.insert("value".to_string(), write_value_json(view.value));
    object.insert(
        "authority".to_string(),
        serde_json::json!(view.authority.name()),
    );
    object.insert("source".to_string(), serde_json::json!(view.source));
    object.insert(
        "derived_from".to_string(),
        derived_from_write_json(view.derived_from.as_ref()),
    );
    value
}

pub(crate) fn op_error_exit_code(error: &OpError) -> i32 {
    match error {
        OpError::Invalid(_) => 2,
        OpError::Rejected(_) | OpError::Conflict(_) => 1,
    }
}

pub(crate) fn present_write(
    outcome: Result<String, OpError>,
    output: CliOutput,
    view: &WriteJsonView<'_>,
) -> i32 {
    match output {
        CliOutput::Text => present(outcome),
        CliOutput::Json => match outcome {
            Ok(message) => print_json_stdout(&write_success_json(view, &message)),
            Err(error) => {
                print_json_stderr(&write_error_json(view, &error), op_error_exit_code(&error))
            }
        },
    }
}

/// Build the events for a revision: one fresh replacement assertion (`event:{seq}`,
/// appended first so the supersessions can resolve it) followed by **one supersession per
/// believed incumbent** (`event:{seq+1+i}`), each pointing `by` at the replacement.
/// Superseding *every* believed incumbent — not just one — is what makes the end state
/// satisfy uniqueness, since the registry can leave a stale + fresh pair both believed.
/// Returns `(events, replacement_claim_id)` with `events[0]` the replacement.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_revision(
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
/// persisted as one best-effort single write on the file dev store, or a real transaction on
/// async backends. The base firewall's anti-laundering enforces that the replacement out-ranks each
/// incumbent, so a lower-authority revision is rejected. Uniqueness holds in the end state
/// because *all* believed incumbents become terminal — the replacement assertion goes
/// through the base firewall directly (not the uniqueness-checking `admit` path) because
/// the supersessions, not a pre-check, are what restore the invariant.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)] // one linear flow: preflight -> entrenchment gate -> apply -> persist
pub(crate) fn op_supersede(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    new_value: &str,
    authority: AuthorityLevel,
    source: &str,
    validity: Validity,
    identity: &WriteIdentity,
) -> Result<String, OpError> {
    enforce_write_authority(
        &WriteAuth::new(subject_kind, subject_key, authority, source),
        identity,
    )?;
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
    validity.stamp(&mut events[0]);
    apply_policy_defaults(&registry, &mut events[0]);

    // ADR 0015 (opt-in): the earned-supersession gate. At *equal* authority, a replacement
    // may not displace an incumbent with strictly stronger authority-weighted corroboration
    // — and a fresh replacement's corroboration is exactly 1 (its asserter). The lost
    // challenge is recorded like any other. Authority downgrades need no gate here: the
    // anti-laundering check already rejects them at write time.
    if entrenchment_gate_enabled() {
        for incumbent in &incumbents {
            let state = store
                .load_claim_events(incumbent)
                .ok()
                .and_then(|stream| replay_claim(&stream).ok().flatten());
            let Some(state) = state else { continue };
            // Earned entrenchment (ADR 0017) = corroboration + survived challenges, at the
            // incumbent's authority. A fresh replacement's earned entrenchment is exactly 1
            // (its asserter, no survived challenges), so `> 1` is "incumbent out-entrenches
            // the challenger" — and surviving even one equal-authority challenge (raising
            // entrenchment to 2) is now enough to resist a fresh equal-authority replacement.
            let level = state.authority.level;
            let entrenchment = state.earned_entrenchment_at_or_above(level);
            if level == authority && entrenchment > 1 {
                let backing = state.corroboration_at_or_above(level);
                let survived = state.survived_challenges_at_or_above(level);
                let note = if challenge_recording_enabled()
                    && persist_challenge_record(
                        path,
                        incumbent,
                        &subject,
                        &predicate_parsed,
                        ChallengeKind::Supersession,
                        Some(events[0].claim_id.clone()),
                        ChallengeRejection::WeakerEntrenchment,
                        source,
                        authority,
                        identity,
                    ) {
                    CHALLENGE_RECORDED_NOTE
                } else {
                    ""
                };
                return Err(OpError::Rejected(format!(
                    "REJECTED: unearned supersession: incumbent {incumbent} has earned \
                     entrenchment {entrenchment} at {level:?} ({backing} corroborating \
                     source(s) + {survived} survived challenge(s)), and a fresh single-source \
                     replacement may not displace it (earned-supersession gate, \
                     DENT8_ENTRENCHMENT_GATE){note}"
                )));
            }
        }
    }

    // Apply all in memory first (replacement, then each supersession); persist only if
    // every one is admitted, so a rejected revision leaves no orphan in the durable log.
    for event in &events {
        if let Err(error) = store.append(event.clone()) {
            let note = record_survived_challenge(path, event, &error, identity);
            return Err(OpError::Rejected(format!("REJECTED: {error}{note}")));
        }
    }
    append_events(path, &mut events, identity).map_err(write_error_to_op)?;

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
pub(crate) fn cmd_supersede(args: &ValueWriteArgs, output: CliOutput) -> i32 {
    let view = value_write_json_view("supersede", args);
    let outcome = with_write_retry(|| {
        op_supersede(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            &args.value,
            args.authority.level(),
            &args.source,
            Validity {
                from: args.valid_from,
                to: args.valid_to,
            },
            &WriteIdentity::Env,
        )
    });
    present_write(outcome, output, &view)
}

/// Build one `Retracted` event per believed incumbent. Each retraction is authority-gated
/// in the core fold (it may not under-rank its incumbent — [ADR 0008]), so a low-authority
/// retraction of a high-authority fact is rejected.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_retractions(
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

pub(crate) fn op_retract(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: AuthorityLevel,
    source: &str,
    identity: &WriteIdentity,
) -> Result<String, OpError> {
    enforce_write_authority(
        &WriteAuth::new(subject_kind, subject_key, authority, source),
        identity,
    )?;
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
    let mut events = build_retractions(
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
        if let Err(error) = store.append(event.clone()) {
            let note = record_survived_challenge(path, event, &error, identity);
            return Err(OpError::Rejected(format!("REJECTED: {error}{note}")));
        }
    }
    append_events(path, &mut events, identity).map_err(write_error_to_op)?;
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
pub(crate) fn cmd_retract(args: &FactWriteArgs, output: CliOutput) -> i32 {
    let view = fact_write_json_view("retract", args);
    let outcome = with_write_retry(|| {
        op_retract(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            args.authority.level(),
            &args.source,
            &WriteIdentity::Env,
        )
    });
    present_write(outcome, output, &view)
}

/// Corroborate the believed fact(s): append a `Reinforced` event per believed claim. The
/// fold raises earned entrenchment (a distinct source/authority backing the same value) and
/// counts the evidence; the value is left unset so it is pure corroboration (no restatement,
/// no value-mismatch). Shared by `dent8 reinforce` and the MCP `reinforce` tool.
pub(crate) fn op_reinforce(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: AuthorityLevel,
    source: &str,
    identity: &WriteIdentity,
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
        identity,
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
pub(crate) fn op_expire(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: AuthorityLevel,
    source: &str,
    identity: &WriteIdentity,
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
        identity,
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
pub(crate) fn build_per_incumbent(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    authority: AuthorityLevel,
    source: &str,
    verb: &str,
    kind_for: impl Fn(&ClaimId) -> ClaimEventKind,
    identity: &WriteIdentity,
) -> Result<Vec<ClaimEvent>, OpError> {
    enforce_write_authority(
        &WriteAuth::new(subject_kind, subject_key, authority, source),
        identity,
    )?;
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
        if let Err(error) = store.append(event.clone()) {
            let note = record_survived_challenge(path, event, &error, identity);
            return Err(OpError::Rejected(format!("REJECTED: {error}{note}")));
        }
    }
    append_events(path, &mut events, identity).map_err(write_error_to_op)?;
    Ok(events)
}

pub(crate) fn cmd_reinforce(args: &FactWriteArgs, output: CliOutput) -> i32 {
    let view = fact_write_json_view("reinforce", args);
    let outcome = with_write_retry(|| {
        op_reinforce(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            args.authority.level(),
            &args.source,
            &WriteIdentity::Env,
        )
    });
    present_write(outcome, output, &view)
}

pub(crate) fn cmd_expire(args: &FactWriteArgs, output: CliOutput) -> i32 {
    let view = fact_write_json_view("expire", args);
    let outcome = with_write_retry(|| {
        op_expire(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            args.authority.level(),
            &args.source,
            &WriteIdentity::Env,
        )
    });
    present_write(outcome, output, &view)
}

/// Build the `(events, opposing_claim_id)` for a `contradict`: a fresh opposing assertion
/// (`event:{seq}`, appended first) carrying the rival value, plus a `Contradicted` event on
/// the incumbent pointing `by` at it. Both end up believed — the paraconsistent surfaced
/// conflict ([ADR 0009](../../docs/decisions/0009-uniqueness-and-contestation.md)).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_contradiction(
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn op_contradict(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    opposing_value: &str,
    authority: AuthorityLevel,
    source: &str,
    validity: Validity,
    identity: &WriteIdentity,
) -> Result<String, OpError> {
    enforce_write_authority(
        &WriteAuth::new(subject_kind, subject_key, authority, source),
        identity,
    )?;
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
    validity.stamp(&mut events[0]);
    let registry = PredicateRegistry::coding_agent();
    apply_policy_defaults(&registry, &mut events[0]);

    // Apply both in memory first; persist only if both admit (a Canonical incumbent makes
    // the contradiction hard-alarm, rejecting the whole operation with nothing persisted).
    for event in &events {
        if let Err(error) = store.append(event.clone()) {
            let note = record_survived_challenge(path, event, &error, identity);
            return Err(OpError::Rejected(format!("REJECTED: {error}{note}")));
        }
    }
    append_events(path, &mut events, identity).map_err(write_error_to_op)?;
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
pub(crate) fn cmd_contradict(args: &ValueWriteArgs, output: CliOutput) -> i32 {
    let view = value_write_json_view("contradict", args);
    let outcome = with_write_retry(|| {
        op_contradict(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            &args.value,
            args.authority.level(),
            &args.source,
            Validity {
                from: args.valid_from,
                to: args.valid_to,
            },
            &WriteIdentity::Env,
        )
    });
    present_write(outcome, output, &view)
}

/// One line of a fact's event history for `replay`: what happened, with provenance.
pub(crate) fn format_history_line(event: &ClaimEvent) -> String {
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
        ClaimEventKind::ChallengeRejected {
            challenge,
            by,
            rejection,
        } => {
            let who = by
                .as_ref()
                .map_or_else(String::new, |claim| format!(" by {claim}"));
            format!("survived     {challenge:?} challenge{who} ({rejection:?})")
        }
    };
    format!(
        "  {:<9} {:<34} {what}  ({:?}, {})",
        event.event_id.as_str(),
        event.claim_id.as_str(),
        event.authority.level,
        event.provenance.source
    )
}

pub(crate) struct ReplayOutcome {
    subject_kind: String,
    subject_key: String,
    predicate: String,
    events: Vec<ClaimEvent>,
    current: Option<IntegrityReceipt>,
}

/// Replay the full ordered event history for a subject+predicate — every assertion,
/// supersession, retraction, and contradiction, with its authority and source — then the
/// current believed (or terminal) state: dent8's "replay *why* a fact is believed".
pub(crate) fn replay_outcome(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    clock: ReadClock,
) -> Result<ReplayOutcome, OpError> {
    let store = clock.store(path).map_err(OpError::Invalid)?;
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
    let current = store
        .explain_latest(&subject, &predicate_parsed, clock.now())
        .ok()
        .flatten();
    Ok(ReplayOutcome {
        subject_kind: subject_kind.to_string(),
        subject_key: subject_key.to_string(),
        predicate: predicate.to_string(),
        events,
        current,
    })
}

pub(crate) fn format_replay(outcome: &ReplayOutcome) -> String {
    use std::fmt::Write;

    let mut out = format!(
        "replay {}:{} {}  ({} events)",
        outcome.subject_kind,
        outcome.subject_key,
        outcome.predicate,
        outcome.events.len()
    );
    for event in &outcome.events {
        out.push('\n');
        out.push_str(&format_history_line(event));
    }
    if let Some(receipt) = &outcome.current {
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
    out
}

pub(crate) fn op_replay(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    clock: ReadClock,
) -> Result<String, OpError> {
    replay_outcome(path, subject_kind, subject_key, predicate, clock)
        .map(|outcome| format_replay(&outcome))
}

pub(crate) fn enum_name_json<T: serde::Serialize>(value: T) -> serde_json::Value {
    serde_json::to_value(value).expect("enum name should serialize")
}

pub(crate) fn event_kind_details_json(kind: &ClaimEventKind) -> serde_json::Value {
    match kind {
        ClaimEventKind::Asserted => serde_json::json!({}),
        ClaimEventKind::Reinforced { by } => serde_json::json!({
            "by": by.as_str(),
        }),
        ClaimEventKind::Contradicted { by, basis } => serde_json::json!({
            "by": by.as_str(),
            "basis": enum_name_json(basis),
        }),
        ClaimEventKind::Superseded { by, reason } => serde_json::json!({
            "by": by.as_str(),
            "reason": enum_name_json(reason),
        }),
        ClaimEventKind::Expired { reason } => serde_json::json!({
            "reason": enum_name_json(reason),
        }),
        ClaimEventKind::Retracted { reason } => serde_json::json!({
            "reason": enum_name_json(reason),
        }),
        ClaimEventKind::Retrieved { purpose } => serde_json::json!({
            "purpose": purpose,
        }),
        ClaimEventKind::UsedInDecision { decision_id } => serde_json::json!({
            "decision_id": decision_id,
        }),
        ClaimEventKind::ChallengeRejected {
            challenge,
            by,
            rejection,
        } => serde_json::json!({
            "challenge": enum_name_json(challenge),
            "by": by.as_ref().map(dent8_core::ClaimId::as_str),
            "rejection": enum_name_json(rejection),
        }),
    }
}

pub(crate) fn claim_event_json(event: &ClaimEvent) -> serde_json::Value {
    serde_json::json!({
        "event_id": event.event_id.as_str(),
        "claim_id": event.claim_id.as_str(),
        "kind": event.kind.name(),
        "details": event_kind_details_json(&event.kind),
        "subject": {
            "kind": event.subject.kind(),
            "key": event.subject.key(),
        },
        "predicate": event.predicate.as_str(),
        "value": event.value.as_ref().map(claim_value_json),
        "authority": event.authority.level.name(),
        "source": event.provenance.source.as_str(),
        "actor": event.provenance.actor.as_str(),
        "tool": event.provenance.tool.as_deref(),
        "run_id": event.provenance.run_id.as_deref(),
        "recorded_at": event.provenance.recorded_at.as_unix_millis(),
        "observed_at": event.observed_at.map(TimestampMillis::as_unix_millis),
        "valid_from": event.valid_from.map(TimestampMillis::as_unix_millis),
        "evidence_count": event.evidence.len(),
        "derived_from": event
            .dependency_edges()
            .into_iter()
            .map(|claim_id| claim_id.as_str().to_string())
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn replay_json(outcome: &ReplayOutcome) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": "replay",
        "subject": {
            "kind": outcome.subject_kind.as_str(),
            "key": outcome.subject_key.as_str(),
        },
        "predicate": outcome.predicate.as_str(),
        "event_count": outcome.events.len(),
        "events": outcome
            .events
            .iter()
            .map(claim_event_json)
            .collect::<Vec<_>>(),
        "current": outcome.current.as_ref().map(receipt_fields_json),
    })
}

pub(crate) fn cmd_replay(args: &ReadFactArgs, output: CliOutput) -> i32 {
    match (
        replay_outcome(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            ReadClock {
                as_of: args.as_of,
                valid_at: args.valid_at,
            },
        ),
        output,
    ) {
        (Ok(outcome), CliOutput::Text) => {
            println!(
                "{}",
                paint_status(&format_replay(&outcome), CliStream::Stdout)
            );
            0
        }
        (Ok(outcome), CliOutput::Json) => print_json_stdout(&replay_json(&outcome)),
        (Err(error), CliOutput::Text) => present(Err(error)),
        (Err(error), CliOutput::Json) => {
            let code = match error {
                OpError::Invalid(_) => 2,
                OpError::Rejected(_) | OpError::Conflict(_) => 1,
            };
            print_json_stderr(&op_error_json(&error), code)
        }
    }
}

/// Explain the believed (or terminal) fact + its integrity receipt. Shared by
/// `dent8 explain` and the MCP `explain` tool.
pub(crate) fn op_explain(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    clock: ReadClock,
) -> Result<String, OpError> {
    let receipt = op_explain_receipt(path, subject_kind, subject_key, predicate, clock)?;
    let annotation = read_annotation(receipt.lifecycle, receipt.fresh, receipt.not_yet_valid);
    Ok(format!(
        "explain {subject_kind}:{subject_key} {predicate}{annotation}\n{}",
        format_receipt(&receipt)
    ))
}

/// Resolve the believed (or terminal) fact as a typed receipt. The CLI renders this as text;
/// MCP uses the same receipt as `structuredContent` so agents do not need to parse prose.
pub(crate) fn op_explain_receipt(
    path: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    clock: ReadClock,
) -> Result<IntegrityReceipt, OpError> {
    let store = clock.store(path).map_err(OpError::Invalid)?;
    let subject = EntityRef::new(subject_kind, subject_key)
        .map_err(|error| OpError::Invalid(format!("invalid subject: {error}")))?;
    let predicate_parsed = Predicate::new(predicate)
        .map_err(|error| OpError::Invalid(format!("invalid predicate: {error}")))?;
    match store.explain_latest(&subject, &predicate_parsed, clock.now()) {
        Ok(Some(receipt)) => Ok(receipt),
        Ok(None) => Err(OpError::Rejected(format!(
            "no claim for {subject_kind}:{subject_key} {predicate}"
        ))),
        Err(error) => Err(OpError::Rejected(format!("explain failed: {error}"))),
    }
}

pub(crate) fn cmd_explain(args: &ReadFactArgs, output: CliOutput) -> i32 {
    match output {
        CliOutput::Text => present(op_explain(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            ReadClock {
                as_of: args.as_of,
                valid_at: args.valid_at,
            },
        )),
        CliOutput::Json => match op_explain_receipt(
            &log_path(),
            &args.subject.kind,
            &args.subject.key,
            &args.predicate,
            ReadClock {
                as_of: args.as_of,
                valid_at: args.valid_at,
            },
        ) {
            Ok(receipt) => print_json_stdout(&receipt_json("explain", &receipt)),
            Err(error) => {
                let code = match error {
                    OpError::Invalid(_) => 2,
                    OpError::Rejected(_) | OpError::Conflict(_) => 1,
                };
                print_json_stderr(&op_error_json(&error), code)
            }
        },
    }
}

/// The read-time freshness of a listed fact stream (threat-model T4), so the enumeration
/// surfaces (`facts list`, MCP `list_facts` / `resources/list`) flag a stale or not-yet-valid
/// fact without the caller reading each one. Computed from the believed (or terminal) receipt
/// at wall-clock now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FactFreshness {
    Fresh,
    Stale,
    NotYetValid,
    NoLongerBelieved,
}

impl FactFreshness {
    fn from_receipt(receipt: &IntegrityReceipt) -> Self {
        if receipt.lifecycle.is_terminal() {
            Self::NoLongerBelieved
        } else if receipt.not_yet_valid {
            Self::NotYetValid
        } else if !receipt.fresh {
            Self::Stale
        } else {
            Self::Fresh
        }
    }

    /// Stable machine name for JSON.
    pub(crate) fn json_name(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::NotYetValid => "not_yet_valid",
            Self::NoLongerBelieved => "no_longer_believed",
        }
    }

    /// A compact human marker; empty for a fresh fact so the common case stays quiet.
    pub(crate) fn text_marker(self) -> &'static str {
        match self {
            Self::Fresh => "",
            Self::Stale => "  [stale]",
            Self::NotYetValid => "  [not yet valid]",
            Self::NoLongerBelieved => "  [no longer believed]",
        }
    }
}

/// Distinct fact streams **with each one's current freshness** (T4), resolved from a single
/// store load. `facts list` and the MCP list surfaces use this so a stale/not-yet-valid fact
/// is visible in the summary, not only on an individual `explain`/`resources/read`.
pub(crate) fn op_list_subjects_with_freshness(
    path: &str,
    include_diagnostics: bool,
) -> Result<Vec<(String, String, String, FactFreshness)>, OpError> {
    let store = load_store(path).map_err(OpError::Invalid)?;
    let now = now_millis();
    let mut out = Vec::new();
    for (subject, predicate) in store.subjects() {
        let kind = subject.kind().to_string();
        let key = subject.key().to_string();
        let pred = predicate.as_str().to_string();
        if !include_diagnostics && is_diagnostic_fact_stream(&kind, &key, &pred) {
            continue;
        }
        // Freshness only needs the claim's replayed state, so use the chain-check-free
        // resolver — listing N streams must not re-hash the whole log N times.
        let freshness = store
            .latest_freshness(&subject, &predicate, now)
            .ok()
            .flatten()
            .map_or(FactFreshness::Fresh, |receipt| {
                FactFreshness::from_receipt(&receipt)
            });
        out.push((kind, key, pred, freshness));
    }
    Ok(out)
}

pub(crate) fn is_diagnostic_fact_stream(kind: &str, key: &str, predicate: &str) -> bool {
    (kind == "diagnostic" && predicate.starts_with("dent8."))
        || (kind == "person" && key.starts_with("alice-doctor-") && predicate == "favorite_drink")
}

pub(crate) fn fact_stream_matches(
    kind: &str,
    key: &str,
    predicate: &str,
    filters: &FactsListArgs,
) -> bool {
    filters.kind.as_deref().is_none_or(|want| kind == want)
        && filters.key.as_deref().is_none_or(|want| key == want)
        && filters
            .predicate
            .as_deref()
            .is_none_or(|want| predicate == want)
}

pub(crate) fn filters_are_empty(filters: &FactsListArgs) -> bool {
    filters.kind.is_none() && filters.key.is_none() && filters.predicate.is_none()
}

pub(crate) struct FactsListOutcome {
    facts: Vec<(String, String, String, FactFreshness)>,
    include_diagnostics: bool,
    hidden_diagnostics_count: usize,
    filters_applied: bool,
    kind_filter: Option<String>,
    key_filter: Option<String>,
    predicate_filter: Option<String>,
}

pub(crate) struct ConflictRival {
    claim_id: ClaimId,
    value: ClaimValue,
    authority: AuthorityLevel,
    lifecycle: ClaimLifecycle,
}

pub(crate) struct ConflictFact {
    subject_kind: String,
    subject_key: String,
    predicate: String,
    rivals: Vec<ConflictRival>,
}

/// List distinct fact streams in the durable store. This is the human CLI counterpart to
/// MCP `list_facts`, with the same default hiding of internal doctor/write-check diagnostics.
pub(crate) fn facts_list_outcome(
    path: &str,
    filters: &FactsListArgs,
) -> Result<FactsListOutcome, OpError> {
    let all_subjects = op_list_subjects_with_freshness(path, true)?;
    let mut visible = Vec::new();
    let mut hidden_diagnostics_count = 0usize;
    for (kind, key, predicate, freshness) in all_subjects {
        if !fact_stream_matches(&kind, &key, &predicate, filters) {
            continue;
        }
        if !filters.include_diagnostics && is_diagnostic_fact_stream(&kind, &key, &predicate) {
            hidden_diagnostics_count += 1;
            continue;
        }
        visible.push((kind, key, predicate, freshness));
    }

    Ok(FactsListOutcome {
        facts: visible,
        include_diagnostics: filters.include_diagnostics,
        hidden_diagnostics_count,
        filters_applied: !filters_are_empty(filters),
        kind_filter: filters.kind.clone(),
        key_filter: filters.key.clone(),
        predicate_filter: filters.predicate.clone(),
    })
}

pub(crate) fn format_facts_list(outcome: &FactsListOutcome) -> String {
    let hidden_note = if outcome.hidden_diagnostics_count == 0 {
        String::new()
    } else {
        format!(
            " ({} diagnostic stream(s) hidden; pass --include-diagnostics to show)",
            outcome.hidden_diagnostics_count
        )
    };

    if outcome.facts.is_empty() {
        let empty = if outcome.filters_applied {
            "no dent8 facts matched filters"
        } else {
            "no dent8 facts recorded yet"
        };
        return format!("{empty}{hidden_note}");
    }

    let lines = outcome
        .facts
        .iter()
        .map(|(kind, key, predicate, freshness)| {
            format!(
                "- {}  ({}:{} {}){}",
                crate::mcp::resource_uri(kind, key, predicate),
                kind,
                key,
                predicate,
                freshness.text_marker(),
            )
        })
        .collect::<Vec<_>>();
    format!(
        "{} dent8 fact stream(s){}:\n{}",
        outcome.facts.len(),
        hidden_note,
        lines.join("\n")
    )
}

pub(crate) fn facts_list_json(outcome: &FactsListOutcome) -> serde_json::Value {
    let facts = outcome
        .facts
        .iter()
        .map(|(kind, key, predicate, freshness)| {
            serde_json::json!({
                "uri": crate::mcp::resource_uri(kind, key, predicate),
                "subject": {
                    "kind": kind,
                    "key": key,
                },
                "predicate": predicate,
                "freshness": freshness.json_name(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "status": "ok",
        "tool": "facts list",
        "count": facts.len(),
        "facts": facts,
        "filters": {
            "kind": outcome.kind_filter,
            "key": outcome.key_filter,
            "predicate": outcome.predicate_filter,
        },
        "include_diagnostics": outcome.include_diagnostics,
        "hidden_diagnostics_count": outcome.hidden_diagnostics_count,
    })
}

pub(crate) fn cmd_facts_list(args: &FactsListArgs, output: CliOutput) -> i32 {
    match facts_list_outcome(&log_path(), args) {
        Ok(outcome) => match output {
            CliOutput::Text => {
                println!("{}", format_facts_list(&outcome));
                0
            }
            CliOutput::Json => print_json_stdout(&facts_list_json(&outcome)),
        },
        Err(error) => match output {
            CliOutput::Text => present(Err(error)),
            CliOutput::Json => {
                let code = match error {
                    OpError::Invalid(_) => 2,
                    OpError::Rejected(_) | OpError::Conflict(_) => 1,
                };
                print_json_stderr(&op_error_json(&error), code)
            }
        },
    }
}

/// List every contested fact (a fact in dispute — `Contested` lifecycle) across all
/// entities. Read-only; backend-aware via `load_store`. Wires `EntityProjection::contested`
/// to a runnable surface (gap-register #8).
pub(crate) fn conflicts_outcome(path: &str) -> Result<Vec<ConflictFact>, OpError> {
    let store = load_store(path).map_err(OpError::Invalid)?;
    let mut conflicts = Vec::new();
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
            let rivals = believed
                .iter()
                .map(|state| ConflictRival {
                    claim_id: state.claim_id.clone(),
                    value: state.value.clone(),
                    authority: state.authority.level,
                    lifecycle: state.lifecycle,
                })
                .collect::<Vec<_>>();
            conflicts.push(ConflictFact {
                subject_kind: subject.kind().to_string(),
                subject_key: subject.key().to_string(),
                predicate: predicate.as_str().to_string(),
                rivals,
            });
        }
    }
    Ok(conflicts)
}

pub(crate) fn format_conflicts(conflicts: &[ConflictFact]) -> String {
    if conflicts.is_empty() {
        "no contested facts — nothing in dispute".to_string()
    } else {
        let lines = conflicts
            .iter()
            .map(|conflict| {
                let rivals = conflict
                    .rivals
                    .iter()
                    .map(|state| {
                        format!(
                            "{:?} (authority={:?}, {:?})",
                            state.value, state.authority, state.lifecycle
                        )
                    })
                    .collect::<Vec<_>>();
                format!(
                    "{}:{} {}: {}",
                    conflict.subject_kind.as_str(),
                    conflict.subject_key.as_str(),
                    conflict.predicate.as_str(),
                    rivals.join("  vs  ")
                )
            })
            .collect::<Vec<_>>();
        format!(
            "{} contested fact(s) (resolve with `supersede`):\n  {}",
            conflicts.len(),
            lines.join("\n  ")
        )
    }
}

pub(crate) fn op_conflicts(path: &str) -> Result<String, OpError> {
    conflicts_outcome(path).map(|conflicts| format_conflicts(&conflicts))
}

pub(crate) fn conflicts_json(conflicts: &[ConflictFact]) -> serde_json::Value {
    serde_json::json!({
        "status": "ok",
        "tool": "conflicts",
        "count": conflicts.len(),
        "conflicts": conflicts
            .iter()
            .map(|conflict| {
                serde_json::json!({
                    "subject": {
                        "kind": conflict.subject_kind.as_str(),
                        "key": conflict.subject_key.as_str(),
                    },
                    "predicate": conflict.predicate.as_str(),
                    "rivals": conflict
                        .rivals
                        .iter()
                        .map(|rival| {
                            serde_json::json!({
                                "claim_id": rival.claim_id.as_str(),
                                "value": claim_value_json(&rival.value),
                                "authority": rival.authority.name(),
                                "lifecycle": enum_name_json(rival.lifecycle),
                            })
                        })
                        .collect::<Vec<_>>(),
                })
            })
            .collect::<Vec<_>>(),
    })
}

pub(crate) fn cmd_conflicts(output: CliOutput) -> i32 {
    match (conflicts_outcome(&log_path()), output) {
        (Ok(conflicts), CliOutput::Text) => {
            println!(
                "{}",
                paint_status(&format_conflicts(&conflicts), CliStream::Stdout)
            );
            0
        }
        (Ok(conflicts), CliOutput::Json) => print_json_stdout(&conflicts_json(&conflicts)),
        (Err(error), CliOutput::Text) => present(Err(error)),
        (Err(error), CliOutput::Json) => {
            let code = match error {
                OpError::Invalid(_) => 2,
                OpError::Rejected(_) | OpError::Conflict(_) => 1,
            };
            print_json_stderr(&op_error_json(&error), code)
        }
    }
}
