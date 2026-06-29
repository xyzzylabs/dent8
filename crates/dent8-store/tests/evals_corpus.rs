//! Scenario-family golden corpus (`evals/`): named, often **multi-claim** event streams whose
//! whole-stream **firewall outcome** is frozen to disk — which writes the firewall admits vs
//! rejects, the final believed state per claim, read-time freshness, and evidence-edge
//! **retraction taint**. A regression in authority arbitration, the canonical hard-alarm,
//! freshness, or the taint analysis is then caught as a snapshot mismatch.
//!
//! This is the file-based corpus [docs/evals.md](../../../docs/evals.md) calls for ("Fixtures
//! should live under `evals/fixtures` and `evals/replay`"). It complements, not duplicates:
//!   - `dent8-core/tests/golden_replay.rs` freezes the *single-claim* encoding + fold (every
//!     event must apply); this harness runs the *store-level firewall* over whole scenario
//!     streams that may include writes the firewall is **expected to reject**.
//!   - `dent8-evals` is the firewall-vs-recency *benchmark* (booleans, `dent8 eval`); this is
//!     the frozen *fixture* form, regression-guarded byte-for-byte.
//!
//! Each scenario owns two files:
//!   - `evals/fixtures/<name>.events.jsonl` — the authored stream (one `ClaimEvent` per line,
//!     the `DENT8_LOG` format), including any write the firewall rejects, and
//!   - `evals/replay/<name>.expected.json` — the frozen outcome.
//!
//! Regenerate after an intentional change with
//! `UPDATE_GOLDEN=1 cargo test -p dent8-store --test evals_corpus`.

use std::fs;
use std::path::{Path, PathBuf};

use dent8_core::{
    ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
    ClaimValue, Confidence, ContradictionBasis, EntityRef, Evidence, EvidenceId, EvidenceKind,
    Predicate, Provenance, RetractionReason, SourceId, SupersessionReason, TimestampMillis,
    TransitionError, Ttl, hash_chain,
};
use dent8_store::{
    EventFilter, EventStore, InMemoryEventStore, StoreError, replay_entity, tainted_claims,
};
use serde::{Deserialize, Serialize};

/// One claim's frozen end-state. `believed` is non-terminal lifecycle (Active/Contested);
/// `fresh` is read-time TTL freshness at the scenario's `now`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ClaimOutcome {
    claim_id: String,
    lifecycle: String,
    value: String,
    authority: String,
    believed: bool,
    fresh: bool,
}

/// A write the firewall refused, with a **stable category** (variant name, no volatile ids).
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct RejectionOutcome {
    event_id: String,
    reason: String,
}

/// A still-believed claim that transitively derives from an invalidated source.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TaintOutcome {
    claim: String,
    root: String,
    root_lifecycle: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Expected {
    /// Lowercase-hex head of the hash chain over the **admitted** events.
    chain_head: String,
    claims: Vec<ClaimOutcome>,
    rejected: Vec<RejectionOutcome>,
    tainted: Vec<TaintOutcome>,
}

struct Scenario {
    name: &'static str,
    description: &'static str,
    /// Read-time clock for freshness (`unix_millis`).
    now_ms: i64,
    events: Vec<ClaimEvent>,
    /// The **independent, hand-declared** headline of the outcome, asserted against the freshly
    /// computed result (not just frozen to disk). This is the guard against a bad regeneration:
    /// if a code regression changes an outcome and someone runs `UPDATE_GOLDEN=1`, the frozen
    /// file matches the (wrong) computed result, but the wrong result no longer matches this
    /// hand-written expectation — so the test still fails.
    expect: Headline,
}

/// The load-bearing facts of a scenario's outcome, declared by the author. Each list is the
/// **sorted** set of claim/event ids; the harness derives the same four sets from the computed
/// [`Expected`] and asserts equality.
struct Headline {
    /// Claim ids expected to be believed (non-terminal lifecycle), sorted.
    believed: &'static [&'static str],
    /// Event ids the firewall is expected to reject, sorted.
    rejected: &'static [&'static str],
    /// Claim ids expected to be flagged as retraction-tainted, sorted.
    tainted: &'static [&'static str],
    /// Believed claim ids expected to be read-time stale (`fresh == false`), sorted.
    stale: &'static [&'static str],
}

/// Compact event builder: one event on `claim`/`subject`/`predicate`, stamped at `seq`
/// (which is also its `recorded_at`). `Ttl::Never`, one `UserStatement` evidence — callers
/// mutate the result for the TTL and `DerivedFrom` cases.
#[allow(clippy::too_many_arguments)]
fn ev(
    seq: i64,
    claim: &str,
    subject_kind: &str,
    subject_key: &str,
    predicate: &str,
    kind: ClaimEventKind,
    value: Option<&str>,
    authority: AuthorityLevel,
    source: &str,
) -> ClaimEvent {
    ClaimEvent {
        event_id: ClaimEventId::new(format!("event:{seq}")).expect("event id"),
        claim_id: ClaimId::new(claim).expect("claim id"),
        kind,
        subject: EntityRef::new(subject_kind, subject_key).expect("entity"),
        predicate: Predicate::new(predicate).expect("predicate"),
        value: value.map(|v| ClaimValue::Text(v.to_string())),
        confidence: Confidence::from_millis(900).expect("confidence"),
        authority: Authority {
            level: authority,
            issuer: None,
            scope: None,
        },
        ttl: Ttl::Never,
        provenance: Provenance {
            source: SourceId::new(source).expect("source"),
            actor: ActorId::new("actor:agent").expect("actor"),
            tool: None,
            run_id: None,
            input_digest: None,
            recorded_at: TimestampMillis::from_unix_millis(seq),
        },
        evidence: vec![Evidence {
            id: EvidenceId::new(format!("evidence:{seq}")).expect("evidence id"),
            kind: EvidenceKind::UserStatement,
            locator: "spec".to_string(),
            digest: None,
            summary: None,
        }],
        observed_at: None,
        valid_from: None,
    }
}

fn assert_kind() -> ClaimEventKind {
    ClaimEventKind::Asserted
}

fn superseded_by(by: &str) -> ClaimEventKind {
    ClaimEventKind::Superseded {
        by: ClaimId::new(by).expect("claim id"),
        reason: SupersessionReason::UserCorrection,
    }
}

fn contradicted_by(by: &str) -> ClaimEventKind {
    ClaimEventKind::Contradicted {
        by: ClaimId::new(by).expect("claim id"),
        basis: ContradictionBasis::SamePredicateDifferentValue,
    }
}

fn retracted_kind() -> ClaimEventKind {
    ClaimEventKind::Retracted {
        reason: RetractionReason::UserDeleted,
    }
}

/// Add a `DerivedFrom` evidence edge to `source_claim`, recording a claim->claim dependency.
fn derived_from(mut event: ClaimEvent, source_claim: &str) -> ClaimEvent {
    event.evidence.push(Evidence {
        id: EvidenceId::new("evidence:derived").expect("evidence id"),
        kind: EvidenceKind::DerivedFrom,
        locator: source_claim.to_string(),
        digest: None,
        summary: None,
    });
    event
}

fn with_ttl(mut event: ClaimEvent, ttl: Ttl) -> ClaimEvent {
    event.ttl = ttl;
    event
}

#[allow(clippy::too_many_lines)] // a flat scenario data table; splitting it would obscure it
fn scenarios() -> Vec<Scenario> {
    vec![
        // The canonical dent8 supersession arc: a project fact corrected over time. Both the
        // replacement assertion and the supersession are admitted (the corrector out-ranks);
        // the old fact goes terminal, the new one is the single believed value.
        Scenario {
            name: "beginner_to_senior",
            description: "A project fact (developer_level) is corrected from 'beginner' to \
                          'senior' via an authority-sufficient supersession.",
            now_ms: 2_000_000_000,
            events: vec![
                ev(
                    0,
                    "claim:jan",
                    "person",
                    "alex",
                    "developer_level",
                    assert_kind(),
                    Some("beginner"),
                    AuthorityLevel::High,
                    "source:owner",
                ),
                ev(
                    1,
                    "claim:nov",
                    "person",
                    "alex",
                    "developer_level",
                    assert_kind(),
                    Some("senior"),
                    AuthorityLevel::High,
                    "source:owner",
                ),
                ev(
                    2,
                    "claim:jan",
                    "person",
                    "alex",
                    "developer_level",
                    superseded_by("claim:nov"),
                    None,
                    AuthorityLevel::High,
                    "source:owner",
                ),
            ],
            expect: Headline {
                believed: &["claim:nov"],
                rejected: &[],
                tainted: &[],
                stale: &[],
            },
        },
        // Read-time freshness: a finite-TTL fact with NO `Expired` event is still lifecycle
        // Active, but reads at a later clock see it as not fresh (the T4 stale-read axis).
        Scenario {
            name: "ttl_expiry",
            description: "A fact with a 1s TTL and no explicit Expired event is Active but \
                          read-time stale once the clock passes its TTL.",
            now_ms: 10_000,
            events: vec![with_ttl(
                ev(
                    0,
                    "claim:flag",
                    "repo",
                    "dent8",
                    "feature_flag",
                    assert_kind(),
                    Some("beta-x"),
                    AuthorityLevel::Medium,
                    "source:agent",
                ),
                Ttl::DurationMillis(1000),
            )],
            expect: Headline {
                believed: &["claim:flag"],
                rejected: &[],
                tainted: &[],
                stale: &["claim:flag"],
            },
        },
        // The differentiator (ADR 0010): a summary derived from a source fact is poisoned when
        // the source is retracted. The summary stays believed but is flagged TAINTED — poison
        // does not silently survive in derivatives.
        Scenario {
            name: "summary_drift",
            description: "A derived summary outlives the retraction of the source it was \
                          derived from, and is flagged as tainted.",
            now_ms: 2_000_000_000,
            events: vec![
                ev(
                    0,
                    "claim:source",
                    "repo",
                    "dent8",
                    "database",
                    assert_kind(),
                    Some("postgres"),
                    AuthorityLevel::High,
                    "source:owner",
                ),
                derived_from(
                    ev(
                        1,
                        "claim:summary",
                        "doc",
                        "readme",
                        "stack_summary",
                        assert_kind(),
                        Some("the project uses postgres"),
                        AuthorityLevel::Medium,
                        "source:agent",
                    ),
                    "claim:source",
                ),
                ev(
                    2,
                    "claim:source",
                    "repo",
                    "dent8",
                    "database",
                    retracted_kind(),
                    None,
                    AuthorityLevel::High,
                    "source:owner",
                ),
            ],
            expect: Headline {
                believed: &["claim:summary"],
                rejected: &[],
                tainted: &["claim:summary"],
                stale: &[],
            },
        },
        // The LFI hard-alarm: a contradiction against a Canonical fact is REJECTED outright
        // (not softened to Contested), so the canonical fact stays Active and untouched.
        Scenario {
            name: "consistency_required",
            description: "A low-authority contradiction of a Canonical fact hard-alarms — the \
                          firewall rejects it; the canonical fact is untouched.",
            now_ms: 2_000_000_000,
            events: vec![
                ev(
                    0,
                    "claim:canon",
                    "repo",
                    "dent8",
                    "license",
                    assert_kind(),
                    Some("MIT"),
                    AuthorityLevel::Canonical,
                    "source:owner",
                ),
                ev(
                    1,
                    "claim:canon",
                    "repo",
                    "dent8",
                    "license",
                    contradicted_by("claim:rumor"),
                    None,
                    AuthorityLevel::Low,
                    "source:user",
                ),
            ],
            expect: Headline {
                believed: &["claim:canon"],
                rejected: &["event:1"],
                tainted: &[],
                stale: &[],
            },
        },
        // MINJA: a low-authority source tries to supersede a high-authority fact. The firewall
        // rejects the supersession (the challenger cannot out-rank the incumbent), so the
        // trusted fact stands; the low-authority claim lingers but never overrode it.
        Scenario {
            name: "low_authority_injection",
            description: "A low-authority supersession of a high-authority fact is rejected; \
                          the trusted fact stays believed.",
            now_ms: 2_000_000_000,
            events: vec![
                ev(
                    0,
                    "claim:trusted",
                    "repo",
                    "dent8",
                    "database",
                    assert_kind(),
                    Some("postgres"),
                    AuthorityLevel::High,
                    "source:owner",
                ),
                ev(
                    1,
                    "claim:attacker",
                    "repo",
                    "dent8",
                    "database",
                    assert_kind(),
                    Some("mysql"),
                    AuthorityLevel::Low,
                    "source:web-scrape",
                ),
                ev(
                    2,
                    "claim:trusted",
                    "repo",
                    "dent8",
                    "database",
                    superseded_by("claim:attacker"),
                    None,
                    AuthorityLevel::Low,
                    "source:web-scrape",
                ),
            ],
            expect: Headline {
                believed: &["claim:attacker", "claim:trusted"],
                rejected: &["event:2"],
                tainted: &[],
                stale: &[],
            },
        },
    ]
}

fn render_value(value: &ClaimValue) -> String {
    match value {
        ClaimValue::Text(text) => format!("text:{text}"),
        ClaimValue::Json(json) => format!("json:{}", json.as_str()),
        ClaimValue::Redacted => "<redacted>".to_string(),
    }
}

/// Stable category for a firewall rejection: the `StoreError`/`TransitionError` variant name.
/// A **typed, exhaustive** match (not parsing `Debug` output, whose format Rust does not
/// guarantee) — so adding a variant is a compile error here, forcing a conscious category
/// choice rather than a silently-changed snapshot key.
fn rejection_category(error: &StoreError) -> String {
    match error {
        StoreError::Conflict(_) => "Conflict".to_string(),
        StoreError::Unavailable(_) => "Unavailable".to_string(),
        StoreError::CorruptEvent(_) => "CorruptEvent".to_string(),
        StoreError::Canonicalization(_) => "Canonicalization".to_string(),
        StoreError::Rejected(transition) => {
            format!("Rejected::{}", transition_category(transition))
        }
        StoreError::LaunderedAuthority { .. } => "LaunderedAuthority".to_string(),
        StoreError::UnbackedSupersession(_) => "UnbackedSupersession".to_string(),
        StoreError::BelowAuthorityFloor { .. } => "BelowAuthorityFloor".to_string(),
        StoreError::UniquenessViolation { .. } => "UniquenessViolation".to_string(),
        StoreError::Replay(_) => "Replay".to_string(),
    }
}

fn transition_category(error: &TransitionError) -> &'static str {
    match error {
        TransitionError::InvalidEvent(_) => "InvalidEvent",
        TransitionError::MissingInitialAssertion => "MissingInitialAssertion",
        TransitionError::DuplicateAssertion => "DuplicateAssertion",
        TransitionError::ClaimIdMismatch => "ClaimIdMismatch",
        TransitionError::ClaimShapeMismatch => "ClaimShapeMismatch",
        TransitionError::ReinforcementValueMismatch => "ReinforcementValueMismatch",
        TransitionError::TerminalStateMutation(_) => "TerminalStateMutation",
        TransitionError::InsufficientAuthority { .. } => "InsufficientAuthority",
        TransitionError::CanonicalContradiction => "CanonicalContradiction",
    }
}

/// Replay a whole authored stream through the **store firewall**, capturing rejections, then
/// summarize the admitted log: chain head, per-claim end-state, and retraction taint.
fn replay(events: &[ClaimEvent], now: TimestampMillis) -> Expected {
    let mut store = InMemoryEventStore::new();
    let mut rejected = Vec::new();
    for event in events {
        if let Err(error) = store.append(event.clone()) {
            rejected.push(RejectionOutcome {
                event_id: event.event_id.as_str().to_string(),
                reason: rejection_category(&error),
            });
        }
    }
    rejected.sort_by(|a, b| a.event_id.cmp(&b.event_id));

    let admitted = store
        .scan_events(&EventFilter::default())
        .expect("scan admitted");
    let chain_head = hash_chain(&admitted)
        .expect("hash chain")
        .last()
        .cloned()
        .unwrap_or_default();

    let mut claims = Vec::new();
    for (subject, predicate) in store.subjects() {
        let filter = EventFilter {
            subject: Some(subject),
            predicate: Some(predicate),
            ..EventFilter::default()
        };
        let stream = store.scan_events(&filter).expect("scan entity");
        let projection = replay_entity(&stream).expect("replay entity");
        for (claim_id, state) in &projection.claims {
            claims.push(ClaimOutcome {
                claim_id: claim_id.as_str().to_string(),
                lifecycle: format!("{:?}", state.lifecycle),
                value: render_value(&state.value),
                authority: format!("{:?}", state.authority.level),
                believed: !state.lifecycle.is_terminal(),
                fresh: !state.is_expired_at(now),
            });
        }
    }
    claims.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));

    let mut tainted: Vec<TaintOutcome> = tainted_claims(&admitted)
        .expect("taint analysis")
        .into_iter()
        .map(|t| TaintOutcome {
            claim: t.claim.as_str().to_string(),
            root: t.root.as_str().to_string(),
            root_lifecycle: format!("{:?}", t.root_lifecycle),
        })
        .collect();
    tainted.sort_by(|a, b| a.claim.cmp(&b.claim));

    Expected {
        chain_head,
        claims,
        rejected,
        tainted,
    }
}

fn corpus_dir() -> PathBuf {
    // crates/dent8-store -> workspace root -> evals/
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../evals")
}

fn serialize_events(events: &[ClaimEvent]) -> String {
    let mut out = String::new();
    for event in events {
        out.push_str(&serde_json::to_string(event).expect("serialize event"));
        out.push('\n');
    }
    out
}

#[test]
fn evals_corpus_outcomes_are_stable() {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    // Regeneration must never run in CI: it would rewrite the snapshots from the current code
    // and pass unconditionally, masking a regression.
    assert!(
        !(update && std::env::var_os("CI").is_some()),
        "UPDATE_GOLDEN must not be set in CI (it would mask a regression)"
    );
    let fixtures = corpus_dir().join("fixtures");
    let replays = corpus_dir().join("replay");
    if update {
        fs::create_dir_all(&fixtures).expect("create fixtures dir");
        fs::create_dir_all(&replays).expect("create replay dir");
    }

    for scenario in scenarios() {
        let now = TimestampMillis::from_unix_millis(scenario.now_ms);
        let events_path = fixtures.join(format!("{}.events.jsonl", scenario.name));
        let expected_path = replays.join(format!("{}.expected.json", scenario.name));
        let serialized = serialize_events(&scenario.events);

        if update {
            fs::write(&events_path, &serialized).expect("write events");
            let expected = replay(&scenario.events, now);
            let json = serde_json::to_string_pretty(&expected).expect("serialize expected");
            fs::write(&expected_path, format!("{json}\n")).expect("write expected");
        }

        // The authored stream must re-serialize to the exact on-disk bytes (encoding stability).
        assert_eq!(
            serialized,
            fs::read_to_string(&events_path).unwrap_or_else(|error| panic!(
                "read {}: {error} (run with UPDATE_GOLDEN=1 to generate)",
                events_path.display()
            )),
            "on-disk event encoding drifted for `{}`",
            scenario.name
        );

        // Replay the ON-DISK stream through the firewall and compare to the frozen outcome.
        let from_disk: Vec<ClaimEvent> = fs::read_to_string(&events_path)
            .expect("read events")
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("deserialize event"))
            .collect();
        let computed = replay(&from_disk, now);
        let frozen: Expected =
            serde_json::from_str(&fs::read_to_string(&expected_path).expect("read expected"))
                .expect("parse expected");
        assert_eq!(
            computed, frozen,
            "firewall outcome drifted for `{}` ({})",
            scenario.name, scenario.description
        );

        // Independent guard against a bad regeneration: the freshly-computed outcome must
        // match the hand-declared headline, regardless of what is frozen on disk. (The
        // `computed == frozen` check above compares two code-derived values; this one
        // compares against author intent.) Each list is sorted, matching `Headline`'s order.
        let believed: Vec<&str> = computed
            .claims
            .iter()
            .filter(|claim| claim.believed)
            .map(|claim| claim.claim_id.as_str())
            .collect();
        assert_eq!(
            believed.as_slice(),
            scenario.expect.believed,
            "believed claims for `{}`",
            scenario.name
        );
        let rejected: Vec<&str> = computed
            .rejected
            .iter()
            .map(|rejection| rejection.event_id.as_str())
            .collect();
        assert_eq!(
            rejected.as_slice(),
            scenario.expect.rejected,
            "rejected events for `{}`",
            scenario.name
        );
        let tainted: Vec<&str> = computed
            .tainted
            .iter()
            .map(|taint| taint.claim.as_str())
            .collect();
        assert_eq!(
            tainted.as_slice(),
            scenario.expect.tainted,
            "tainted claims for `{}`",
            scenario.name
        );
        let stale: Vec<&str> = computed
            .claims
            .iter()
            .filter(|claim| claim.believed && !claim.fresh)
            .map(|claim| claim.claim_id.as_str())
            .collect();
        assert_eq!(
            stale.as_slice(),
            scenario.expect.stale,
            "stale believed claims for `{}`",
            scenario.name
        );
    }
}
