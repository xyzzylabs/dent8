//! Golden replay fixtures: named, human-readable event streams whose canonical on-disk
//! encoding **and** replayed outcome are frozen to disk, so an accidental change to the
//! event encoding, the hash chain, or the `apply_event` fold is caught as a snapshot
//! mismatch.
//!
//! Each scenario owns two files under `tests/golden/replay/`:
//!   - `<name>.events.jsonl` — the canonical event stream (one `ClaimEvent` per line, the
//!     same format the CLI's `DENT8_LOG` uses), and
//!   - `<name>.expected.json` — the frozen `chain_head` plus the replayed-state summary.
//!
//! The test reads the **on-disk** events (so an encoding change that breaks deserialization
//! fails), replays them through the real `apply_event`/`hash_chain`, and asserts the result
//! reproduces the frozen expectation. It also asserts the Rust-defined scenario re-serializes
//! to the exact on-disk bytes. Regenerate after an intentional change with
//! `UPDATE_GOLDEN=1 cargo test -p dent8-core --test golden_replay`.

use std::fs;
use std::path::{Path, PathBuf};

use dent8_core::{
    ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
    ClaimState, ClaimValue, Confidence, ContradictionBasis, EntityRef, Evidence, EvidenceId,
    EvidenceKind, ExpirationReason, Predicate, Provenance, SourceId, SupersessionReason,
    TimestampMillis, Ttl, apply_event, hash_chain,
};
use serde::{Deserialize, Serialize};

/// The frozen expectation for a replayed stream: the chain head plus the observable
/// projection. `Debug`-rendered enums/values keep the snapshot stable and readable.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Expected {
    /// Lowercase-hex head of the event hash chain.
    chain_head: String,
    lifecycle: String,
    value: String,
    authority: String,
    superseded_by: Option<String>,
    contradicted_by: Vec<String>,
    /// Distinct sources backing this exact value (earned-entrenchment degree).
    corroboration: usize,
}

struct Scenario {
    name: &'static str,
    description: &'static str,
    events: Vec<ClaimEvent>,
    /// Independent (code-free) assertion of the headline outcome, so a wrong regeneration
    /// cannot silently bless a wrong lifecycle.
    expect_lifecycle: &'static str,
}

/// Compact builder for one event on a shared claim, stamped at `seq`.
struct Stream {
    claim: ClaimId,
    subject: EntityRef,
    predicate: Predicate,
}

impl Stream {
    fn new() -> Self {
        Self {
            claim: ClaimId::new("claim:repo:dent8:database").expect("claim id"),
            subject: EntityRef::new("repo", "dent8").expect("entity"),
            predicate: Predicate::new("database").expect("predicate"),
        }
    }

    fn event(
        &self,
        seq: usize,
        kind: ClaimEventKind,
        value: Option<ClaimValue>,
        authority: AuthorityLevel,
        source: &str,
        ttl: Ttl,
    ) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(format!("event:{seq}")).expect("event id"),
            claim_id: self.claim.clone(),
            kind,
            subject: self.subject.clone(),
            predicate: self.predicate.clone(),
            value,
            confidence: Confidence::from_millis(900).expect("confidence"),
            authority: Authority {
                level: authority,
                issuer: None,
                scope: None,
            },
            ttl,
            provenance: Provenance {
                source: SourceId::new(source).expect("source"),
                actor: ActorId::new("actor:agent").expect("actor"),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(i64::try_from(seq).expect("seq")),
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
}

fn text(value: &str) -> ClaimValue {
    ClaimValue::Text(value.to_string())
}

#[allow(clippy::too_many_lines)] // a flat scenario data table; splitting it would obscure it
fn scenarios() -> Vec<Scenario> {
    let s = Stream::new();
    let other = ClaimId::new("claim:replacement").expect("claim id");
    vec![
        Scenario {
            name: "asserted_then_reinforced",
            description: "A fact asserted by the owner, then corroborated by a second source.",
            events: vec![
                s.event(
                    0,
                    ClaimEventKind::Asserted,
                    Some(text("postgres")),
                    AuthorityLevel::High,
                    "source:owner",
                    Ttl::Never,
                ),
                s.event(
                    1,
                    ClaimEventKind::Reinforced {
                        by: s.claim.clone(),
                    },
                    Some(text("postgres")),
                    AuthorityLevel::Medium,
                    "source:scanner",
                    Ttl::Never,
                ),
            ],
            expect_lifecycle: "Active",
        },
        Scenario {
            name: "superseded_by_equal_authority",
            description: "An incumbent fact revised by an equal-authority replacement.",
            events: vec![
                s.event(
                    0,
                    ClaimEventKind::Asserted,
                    Some(text("postgres")),
                    AuthorityLevel::High,
                    "source:owner",
                    Ttl::Never,
                ),
                s.event(
                    1,
                    ClaimEventKind::Superseded {
                        by: other.clone(),
                        reason: SupersessionReason::UserCorrection,
                    },
                    None,
                    AuthorityLevel::High,
                    "source:owner",
                    Ttl::Never,
                ),
            ],
            expect_lifecycle: "Superseded",
        },
        Scenario {
            name: "contested_then_unresolved",
            description: "A low-authority source contests a non-canonical fact; both remain believed.",
            events: vec![
                s.event(
                    0,
                    ClaimEventKind::Asserted,
                    Some(text("postgres")),
                    AuthorityLevel::Medium,
                    "source:owner",
                    Ttl::Never,
                ),
                s.event(
                    1,
                    ClaimEventKind::Contradicted {
                        by: other.clone(),
                        basis: ContradictionBasis::SamePredicateDifferentValue,
                    },
                    None,
                    AuthorityLevel::Low,
                    "source:scanner",
                    Ttl::Never,
                ),
            ],
            expect_lifecycle: "Contested",
        },
        Scenario {
            name: "retracted_by_owner",
            description: "An owner terminally removes a previously-asserted fact.",
            events: vec![
                s.event(
                    0,
                    ClaimEventKind::Asserted,
                    Some(text("postgres")),
                    AuthorityLevel::High,
                    "source:owner",
                    Ttl::Never,
                ),
                s.event(
                    1,
                    ClaimEventKind::Retracted {
                        reason: dent8_core::RetractionReason::UserDeleted,
                    },
                    None,
                    AuthorityLevel::High,
                    "source:owner",
                    Ttl::Never,
                ),
            ],
            expect_lifecycle: "Retracted",
        },
        Scenario {
            name: "expired_after_ttl",
            description: "A fact with a finite TTL is explicitly expired.",
            events: vec![
                s.event(
                    0,
                    ClaimEventKind::Asserted,
                    Some(text("feature-x")),
                    AuthorityLevel::Medium,
                    "source:agent",
                    Ttl::DurationMillis(1000),
                ),
                s.event(
                    1,
                    ClaimEventKind::Expired {
                        reason: ExpirationReason::TtlElapsed,
                    },
                    None,
                    AuthorityLevel::Medium,
                    "source:agent",
                    Ttl::Never,
                ),
            ],
            expect_lifecycle: "Expired",
        },
        Scenario {
            name: "corroborated_by_three_sources",
            description: "Earned entrenchment: three distinct sources back the same value.",
            events: vec![
                s.event(
                    0,
                    ClaimEventKind::Asserted,
                    Some(text("postgres")),
                    AuthorityLevel::Medium,
                    "source:a",
                    Ttl::Never,
                ),
                s.event(
                    1,
                    ClaimEventKind::Reinforced {
                        by: s.claim.clone(),
                    },
                    Some(text("postgres")),
                    AuthorityLevel::High,
                    "source:b",
                    Ttl::Never,
                ),
                s.event(
                    2,
                    ClaimEventKind::Reinforced {
                        by: s.claim.clone(),
                    },
                    // Restates the value, so it is a genuine same-value corroborator.
                    Some(text("postgres")),
                    AuthorityLevel::Canonical,
                    "source:c",
                    Ttl::Never,
                ),
            ],
            expect_lifecycle: "Active",
        },
        Scenario {
            name: "retrieved_after_terminal",
            description: "A retracted fact still admits audit reads: a Retrieved event is \
                          accepted after the claim is terminal, leaving the lifecycle frozen.",
            events: vec![
                s.event(
                    0,
                    ClaimEventKind::Asserted,
                    Some(text("postgres")),
                    AuthorityLevel::High,
                    "source:owner",
                    Ttl::Never,
                ),
                s.event(
                    1,
                    ClaimEventKind::Retracted {
                        reason: dent8_core::RetractionReason::UserDeleted,
                    },
                    None,
                    AuthorityLevel::High,
                    "source:owner",
                    Ttl::Never,
                ),
                s.event(
                    2,
                    ClaimEventKind::Retrieved {
                        purpose: "audit".to_string(),
                    },
                    None,
                    AuthorityLevel::Low,
                    "source:auditor",
                    Ttl::Never,
                ),
            ],
            expect_lifecycle: "Retracted",
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

/// Replay an event stream and summarize the head + projected state. Every event in a golden
/// fixture must be accepted (a persisted log only contains admitted events).
fn replay(events: &[ClaimEvent]) -> Expected {
    let chain = hash_chain(events).expect("hash chain");
    let mut state: Option<ClaimState> = None;
    for event in events {
        state = Some(apply_event(state.clone(), event).expect("every fixture event must apply"));
    }
    let state = state.expect("a fixture must contain at least one event");
    Expected {
        chain_head: chain.last().expect("non-empty chain").clone(),
        lifecycle: format!("{:?}", state.lifecycle),
        value: render_value(&state.value),
        authority: format!("{:?}", state.authority.level),
        superseded_by: state.superseded_by.as_ref().map(|c| c.as_str().to_string()),
        contradicted_by: state
            .contradicted_by
            .iter()
            .map(|c| c.as_str().to_string())
            .collect(),
        corroboration: state.corroboration(),
    }
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden/replay")
}

fn serialize_events(events: &[ClaimEvent]) -> String {
    let mut out = String::new();
    for event in events {
        out.push_str(&serde_json::to_string(event).expect("serialize event"));
        out.push('\n');
    }
    out
}

fn read_events(path: &Path) -> Vec<ClaimEvent> {
    let contents = fs::read_to_string(path).unwrap_or_else(|error| {
        panic!(
            "read {}: {error} (run with UPDATE_GOLDEN=1 to generate)",
            path.display()
        )
    });
    contents
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("deserialize event"))
        .collect()
}

#[test]
fn golden_replay_fixtures_are_stable() {
    let update = std::env::var_os("UPDATE_GOLDEN").is_some();
    // Regeneration must never run in CI: it would rewrite the snapshots from the current
    // code and pass unconditionally, silently re-blessing any regression.
    assert!(
        !(update && std::env::var_os("CI").is_some()),
        "UPDATE_GOLDEN must not be set in CI (it would mask a regression)"
    );
    let dir = golden_dir();
    if update {
        fs::create_dir_all(&dir).expect("create golden dir");
    }

    for scenario in scenarios() {
        let events_path = dir.join(format!("{}.events.jsonl", scenario.name));
        let expected_path = dir.join(format!("{}.expected.json", scenario.name));
        let serialized = serialize_events(&scenario.events);

        if update {
            fs::write(&events_path, &serialized).expect("write events");
            let expected = replay(&scenario.events);
            let json = serde_json::to_string_pretty(&expected).expect("serialize expected");
            fs::write(&expected_path, format!("{json}\n")).expect("write expected");
        }

        // The Rust-defined scenario must re-serialize to the exact on-disk bytes (encoding
        // stability), independent of replay.
        assert_eq!(
            serialized,
            fs::read_to_string(&events_path).unwrap_or_else(|error| panic!(
                "read {}: {error} (run with UPDATE_GOLDEN=1 to generate)",
                events_path.display()
            )),
            "on-disk event encoding drifted for `{}`",
            scenario.name
        );

        // Replay the ON-DISK events and compare to the frozen expectation.
        let from_disk = read_events(&events_path);
        let computed = replay(&from_disk);
        let frozen: Expected =
            serde_json::from_str(&fs::read_to_string(&expected_path).expect("read expected"))
                .expect("parse expected");
        assert_eq!(
            computed, frozen,
            "replayed outcome drifted for `{}` ({})",
            scenario.name, scenario.description
        );

        // Independent, code-free check of the headline lifecycle.
        assert_eq!(
            computed.lifecycle, scenario.expect_lifecycle,
            "lifecycle for `{}` is not the documented outcome",
            scenario.name
        );
    }
}
