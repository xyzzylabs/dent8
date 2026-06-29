//! Adversarial evaluation corpus for the dent8 memory firewall.
//!
//! Each scenario is a concrete attack — a sequence of `ClaimEvent`s a poisoning adversary
//! might submit — run two ways:
//!
//! - through the **real firewall** (`dent8_store::InMemoryEventStore::append`, i.e.
//!   `arbitrate` + the core fold), and
//! - through a **recency-only baseline** that resolves conflicts by "newest write wins"
//!   with no authority arbitration — the resolution strategy dent8 argues against (e.g.
//!   Graphiti's "consistently prioritizes new information").
//!
//! The eval asserts the firewall **blocks** each attack while the baseline is
//! **compromised** — the measurable evidence behind the [threat model](../../docs/threat-model.md)
//! claims (T1 MINJA, T5 canonical contradiction, authority laundering, Sybil corroboration).
//! This is the empirical complement to the `#[cfg(kani)]` proofs and the exhaustive
//! authority-lattice tests in `dent8-core`.

use dent8_core::{
    ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
    ClaimLifecycle, ClaimState, ClaimValue, Confidence, ContradictionBasis, EntityRef, Evidence,
    EvidenceId, EvidenceKind, Predicate, Provenance, RetractionReason, SourceId,
    SupersessionReason, TimestampMillis, Ttl,
};
use dent8_store::{EventFilter, EventStore, InMemoryEventStore, replay_claim, tainted_claims};

/// The outcome of running one attack scenario through both resolution strategies.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttackResult {
    pub name: &'static str,
    pub family: &'static str,
    /// The real firewall prevented the attack (the protected fact stood).
    pub firewall_blocked: bool,
    /// A recency-only store would have been poisoned by the same sequence.
    pub baseline_compromised: bool,
}

impl AttackResult {
    /// An attack is *demonstrative* only if the firewall blocks it **and** the baseline
    /// does not — i.e. the firewall earns its keep on this scenario.
    #[must_use]
    pub fn demonstrates_defense(&self) -> bool {
        self.firewall_blocked && self.baseline_compromised
    }
}

/// Run the full adversarial corpus.
#[must_use]
pub fn run_corpus() -> Vec<AttackResult> {
    vec![
        minja_low_authority_injection(),
        authority_laundering(),
        canonical_contradiction(),
        sybil_corroboration(),
        poisoned_source_retraction(),
    ]
}

/// A Markdown table of the corpus result — the firewall-vs-recency contrast, suitable for
/// the paper / README.
#[must_use]
pub fn summary_table() -> String {
    use std::fmt::Write;

    let mut out =
        String::from("| attack | family | firewall | recency-only baseline |\n|---|---|---|---|\n");
    for result in run_corpus() {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} |",
            result.name,
            result.family,
            if result.firewall_blocked {
                "blocked ✓"
            } else {
                "**compromised**"
            },
            if result.baseline_compromised {
                "**compromised**"
            } else {
                "blocked"
            },
        );
    }
    out
}

// ---- Attack families -----------------------------------------------------------------

/// T1 / MINJA: a low-privilege source tries to supersede a high-authority fact. The
/// firewall rejects the under-ranked supersession; recency-only would adopt it.
fn minja_low_authority_injection() -> AttackResult {
    let events = vec![
        asserted(
            "event:0",
            "claim:trusted",
            "postgres",
            "source:owner",
            AuthorityLevel::High,
            1,
        ),
        asserted(
            "event:1",
            "claim:attacker",
            "mysql",
            "source:user",
            AuthorityLevel::Low,
            2,
        ),
        superseded(
            "event:2",
            "claim:trusted",
            "claim:attacker",
            "source:user",
            AuthorityLevel::Low,
            3,
        ),
    ];
    AttackResult {
        name: "minja_low_authority_injection",
        family: "T1_memory_injection",
        // Firewall: the trusted claim is still Active (the supersession was rejected).
        firewall_blocked: firewall_state(&events, "claim:trusted")
            .is_some_and(|state| state.lifecycle == ClaimLifecycle::Active),
        // Baseline: newest write wins, so the trusted fact is overridden by "mysql".
        baseline_compromised: recency_head(&events) == Some("mysql".to_string()),
    }
}

/// Retraction taint (T2/T8 — poison does not survive in derivatives, ADR 0010): a claim is
/// **derived** (`EvidenceKind::DerivedFrom`) from a source, then the source is retracted as
/// poisoned. The firewall flags the still-believed derivative as **tainted** (it traces to a
/// retracted source); a recency-only store has no dependency graph at all, so the derivative
/// silently survives with no flag. This is the structural capability recency-only memory
/// cannot represent.
fn poisoned_source_retraction() -> AttackResult {
    let source = asserted(
        "event:0",
        "claim:source",
        "postgres",
        "source:owner",
        AuthorityLevel::High,
        1,
    );
    let derived = derived_from(
        "event:1",
        "claim:derived",
        "deploy-to-pg",
        "source:agent",
        AuthorityLevel::High,
        2,
        "claim:source",
    );
    let retract = retracted(
        "event:2",
        "claim:source",
        "source:owner",
        AuthorityLevel::High,
        3,
    );
    let admitted = firewall_admitted(&[source, derived.clone(), retract]);
    AttackResult {
        name: "poisoned_source_retraction",
        family: "T2_retraction_cascade",
        // Firewall: the still-believed derivative is flagged as tainted (its source retracted).
        firewall_blocked: tainted_claims(&admitted)
            .expect("taint")
            .iter()
            .any(|taint| taint.claim.as_str() == "claim:derived"),
        // Baseline: recency-only has no dependency graph, so the derivative's own stream is
        // never touched by the source's retraction — it silently survives, unflagged.
        baseline_compromised: recency_head(&[derived]).is_some(),
    }
}

/// Authority laundering: the attacker over-states the *supersession event's* authority as
/// High while it is backed by a Low claim. The firewall resolves the backing claim's real
/// authority and rejects; recency-only never looks at authority at all.
fn authority_laundering() -> AttackResult {
    let events = vec![
        asserted(
            "event:0",
            "claim:trusted",
            "postgres",
            "source:owner",
            AuthorityLevel::High,
            1,
        ),
        asserted(
            "event:1",
            "claim:attacker",
            "mysql",
            "source:user",
            AuthorityLevel::Low,
            2,
        ),
        // The supersession EVENT claims High, but claim:attacker is really Low.
        superseded(
            "event:2",
            "claim:trusted",
            "claim:attacker",
            "source:user",
            AuthorityLevel::High,
            3,
        ),
    ];
    AttackResult {
        name: "authority_laundering",
        family: "T1_memory_injection",
        firewall_blocked: firewall_state(&events, "claim:trusted")
            .is_some_and(|state| state.lifecycle == ClaimLifecycle::Active),
        baseline_compromised: recency_head(&events) == Some("mysql".to_string()),
    }
}

/// T5 / consistency-required: a low-authority source contradicts a `Canonical` fact. The
/// firewall raises a hard alarm (the canonical fact stays Active, untouched); recency-only
/// (and even ordinary contradiction) would soften it to Contested, casting doubt.
fn canonical_contradiction() -> AttackResult {
    let events = vec![
        asserted(
            "event:0",
            "claim:canon",
            "postgres",
            "source:owner",
            AuthorityLevel::Canonical,
            1,
        ),
        contradicted(
            "event:1",
            "claim:canon",
            "claim:rumor",
            "source:user",
            AuthorityLevel::Low,
            2,
        ),
    ];
    AttackResult {
        name: "canonical_contradiction",
        family: "T5_canonical_contradiction",
        // Firewall: the canonical fact is still Active — the contradiction hard-alarmed
        // (was rejected) rather than moving it to Contested.
        firewall_blocked: firewall_state(&events, "claim:canon")
            .is_some_and(|state| state.lifecycle == ClaimLifecycle::Active),
        // Baseline: an unguarded store accepts the contradiction and casts doubt.
        baseline_compromised: recency_contested(&events),
    }
}

/// Sybil corroboration: many distinct *low*-authority sources reinforce a claim to fake
/// entrenchment by volume. The firewall's authority-weighted corroboration is unmoved
/// (no high-authority backing); a naive count-based metric is fooled.
fn sybil_corroboration() -> AttackResult {
    let mut events = vec![asserted(
        "event:0",
        "claim:rumor",
        "mysql",
        "source:sybil:0",
        AuthorityLevel::Low,
        1,
    )];
    for n in 1i64..=9 {
        events.push(reinforced(
            &format!("event:{n}"),
            "claim:rumor",
            "mysql",
            &format!("source:sybil:{n}"),
            AuthorityLevel::Low,
            n + 1,
        ));
    }
    let state = firewall_state(&events, "claim:rumor");
    AttackResult {
        name: "sybil_corroboration",
        family: "earned_entrenchment",
        // Firewall: authority-weighted corroboration at High is zero — Sybil volume earns
        // no entrenchment a security-conscious reader would trust.
        firewall_blocked: state
            .as_ref()
            .is_some_and(|s| s.corroboration_at_or_above(AuthorityLevel::High) == 0),
        // Baseline: a naive count sees 10 corroborating sources and treats it as strong.
        baseline_compromised: state.is_some_and(|s| s.corroboration() >= 10),
    }
}

/// A *positive control*: a legitimate, equal-or-higher-authority supersession must be
/// **accepted** — the firewall is not a blanket "reject all change" gate. Not part of the
/// attack corpus; asserted directly in tests.
#[must_use]
pub fn legitimate_supersession_is_accepted() -> bool {
    let events = vec![
        asserted(
            "event:0",
            "claim:old",
            "postgres",
            "source:owner",
            AuthorityLevel::High,
            1,
        ),
        asserted(
            "event:1",
            "claim:new",
            "mysql",
            "source:owner",
            AuthorityLevel::High,
            2,
        ),
        superseded(
            "event:2",
            "claim:old",
            "claim:new",
            "source:owner",
            AuthorityLevel::High,
            3,
        ),
    ];
    firewall_state(&events, "claim:old")
        .is_some_and(|state| state.lifecycle == ClaimLifecycle::Superseded)
}

// ---- Resolution strategies -----------------------------------------------------------

/// Replay one claim's stream through the **real firewall** and return its projected state.
/// Events the firewall rejects simply never land, exactly as in the operational store.
fn firewall_state(events: &[ClaimEvent], claim_id: &str) -> Option<ClaimState> {
    let mut store = InMemoryEventStore::new();
    for event in events {
        // A rejected (inadmissible) write is dropped — that is the firewall doing its job.
        let _ = store.append(event.clone());
    }
    let id = ClaimId::new(claim_id).expect("claim id");
    let claim_events = store.load_claim_events(&id).expect("load");
    replay_claim(&claim_events).expect("replay")
}

/// The recency-only baseline's believed value: newest assertion wins, and a supersession
/// adopts its replacement's value — **with no authority arbitration**. `None` if retracted.
fn recency_head(events: &[ClaimEvent]) -> Option<String> {
    use std::collections::HashMap;
    let mut values: HashMap<&ClaimId, Option<String>> = HashMap::new();
    let mut head: Option<String> = None;
    for event in events {
        match &event.kind {
            ClaimEventKind::Asserted => {
                let value = text(event);
                values.insert(&event.claim_id, value.clone());
                head = value; // newest assertion wins
            }
            ClaimEventKind::Superseded { by, .. } => {
                // Recency: the supersession is applied unconditionally; adopt the
                // replacement's value.
                head = values.get(by).cloned().flatten();
            }
            ClaimEventKind::Retracted { .. } => head = None,
            _ => {}
        }
    }
    head
}

/// Whether the recency-only baseline would mark the fact contested (it accepts any
/// contradiction, with no canonical hard-alarm).
fn recency_contested(events: &[ClaimEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event.kind, ClaimEventKind::Contradicted { .. }))
}

fn text(event: &ClaimEvent) -> Option<String> {
    match &event.value {
        Some(ClaimValue::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

// ---- Event builders ------------------------------------------------------------------

fn asserted(
    event_id: &str,
    claim_id: &str,
    value: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> ClaimEvent {
    event(
        event_id,
        claim_id,
        ClaimEventKind::Asserted,
        Some(value),
        source,
        authority,
        at,
    )
}

fn reinforced(
    event_id: &str,
    claim_id: &str,
    value: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> ClaimEvent {
    event(
        event_id,
        claim_id,
        ClaimEventKind::Reinforced {
            by: ClaimId::new(claim_id).expect("claim id"),
        },
        Some(value),
        source,
        authority,
        at,
    )
}

fn superseded(
    event_id: &str,
    claim_id: &str,
    by: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> ClaimEvent {
    event(
        event_id,
        claim_id,
        ClaimEventKind::Superseded {
            by: ClaimId::new(by).expect("by"),
            reason: SupersessionReason::NewerObservation,
        },
        None,
        source,
        authority,
        at,
    )
}

fn contradicted(
    event_id: &str,
    claim_id: &str,
    by: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> ClaimEvent {
    event(
        event_id,
        claim_id,
        ClaimEventKind::Contradicted {
            by: ClaimId::new(by).expect("by"),
            basis: ContradictionBasis::SamePredicateDifferentValue,
        },
        None,
        source,
        authority,
        at,
    )
}

fn retracted(
    event_id: &str,
    claim_id: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> ClaimEvent {
    event(
        event_id,
        claim_id,
        ClaimEventKind::Retracted {
            reason: RetractionReason::PoisoningDetected,
        },
        None,
        source,
        authority,
        at,
    )
}

/// An `Asserted` claim on a *distinct* predicate (`deploy_target`, so it does not collide with
/// the source's `database` fact) carrying a `DerivedFrom` evidence edge to `from_claim` — the
/// claim->claim dependency the taint analysis walks (ADR 0010).
fn derived_from(
    event_id: &str,
    claim_id: &str,
    value: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
    from_claim: &str,
) -> ClaimEvent {
    let mut e = event(
        event_id,
        claim_id,
        ClaimEventKind::Asserted,
        Some(value),
        source,
        authority,
        at,
    );
    e.predicate = Predicate::new("deploy_target").expect("predicate");
    e.evidence.push(Evidence {
        id: EvidenceId::new(format!("evidence:dep:{event_id}")).expect("evidence id"),
        kind: EvidenceKind::DerivedFrom,
        locator: from_claim.to_string(),
        digest: None,
        summary: None,
    });
    e
}

/// The events the firewall actually admitted (rejected writes dropped), for an analysis that
/// should reflect the stored log rather than the raw candidate sequence.
fn firewall_admitted(events: &[ClaimEvent]) -> Vec<ClaimEvent> {
    let mut store = InMemoryEventStore::new();
    for event in events {
        let _ = store.append(event.clone());
    }
    store.scan_events(&EventFilter::default()).expect("scan")
}

fn event(
    event_id: &str,
    claim_id: &str,
    kind: ClaimEventKind,
    value: Option<&str>,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> ClaimEvent {
    ClaimEvent {
        event_id: ClaimEventId::new(event_id).expect("event id"),
        claim_id: ClaimId::new(claim_id).expect("claim id"),
        kind,
        subject: EntityRef::new("repo", "proj").expect("entity"),
        predicate: Predicate::new("database").expect("predicate"),
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
            actor: ActorId::new("actor:eval").expect("actor"),
            tool: None,
            run_id: None,
            input_digest: None,
            recorded_at: TimestampMillis::from_unix_millis(at),
        },
        evidence: vec![Evidence {
            id: EvidenceId::new(format!("evidence:{event_id}")).expect("evidence id"),
            kind: EvidenceKind::UserStatement,
            locator: "eval".to_string(),
            digest: None,
            summary: None,
        }],
        observed_at: None,
        valid_from: None,
    }
}

#[cfg(test)]
mod tests {
    use super::{legitimate_supersession_is_accepted, run_corpus};

    #[test]
    fn the_firewall_blocks_every_attack_the_baseline_falls_to() {
        let results = run_corpus();
        assert!(!results.is_empty());
        for result in &results {
            assert!(
                result.firewall_blocked,
                "firewall failed to block {}",
                result.name
            );
            assert!(
                result.baseline_compromised,
                "baseline unexpectedly survived {} — the scenario does not isolate a firewall defense",
                result.name
            );
            assert!(
                result.demonstrates_defense(),
                "{} is not demonstrative",
                result.name
            );
        }
    }

    #[test]
    fn attack_success_rate_is_zero_for_the_firewall_and_total_for_the_baseline() {
        let results = run_corpus();
        let n = results.len();
        let firewall_succeeded = results.iter().filter(|r| !r.firewall_blocked).count();
        let baseline_compromised = results.iter().filter(|r| r.baseline_compromised).count();
        assert_eq!(firewall_succeeded, 0, "firewall let an attack through");
        assert_eq!(
            baseline_compromised, n,
            "a recency-only baseline resisted an attack"
        );
    }

    #[test]
    fn the_firewall_admits_legitimate_revision() {
        assert!(
            legitimate_supersession_is_accepted(),
            "the firewall wrongly blocked a legitimate equal-authority supersession",
        );
    }

    /// Rigor check: each attack is rejected by the *intended* firewall mechanism, not by
    /// some incidental validation error — otherwise the corpus would prove nothing about
    /// authority arbitration.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn attacks_are_rejected_by_the_intended_mechanism() {
        use super::{asserted, contradicted, superseded};
        use dent8_core::{AuthorityLevel, TransitionError};
        use dent8_store::{EventStore, InMemoryEventStore, StoreError};

        // MINJA: an under-ranked supersession trips the authority gate.
        let mut store = InMemoryEventStore::new();
        store
            .append(asserted(
                "e0",
                "claim:trusted",
                "postgres",
                "src:owner",
                AuthorityLevel::High,
                1,
            ))
            .unwrap();
        store
            .append(asserted(
                "e1",
                "claim:attacker",
                "mysql",
                "src:user",
                AuthorityLevel::Low,
                2,
            ))
            .unwrap();
        let minja = store
            .append(superseded(
                "e2",
                "claim:trusted",
                "claim:attacker",
                "src:user",
                AuthorityLevel::Low,
                3,
            ))
            .unwrap_err();
        assert!(
            matches!(
                minja,
                StoreError::Rejected(TransitionError::InsufficientAuthority { .. })
            ),
            "MINJA rejected by the wrong mechanism: {minja:?}"
        );

        // Laundering: the supersession EVENT over-states High, but its backing claim is
        // Low — the anti-laundering branch (not apply_event) must catch it.
        let mut store = InMemoryEventStore::new();
        store
            .append(asserted(
                "e0",
                "claim:trusted",
                "postgres",
                "src:owner",
                AuthorityLevel::High,
                1,
            ))
            .unwrap();
        store
            .append(asserted(
                "e1",
                "claim:attacker",
                "mysql",
                "src:user",
                AuthorityLevel::Low,
                2,
            ))
            .unwrap();
        let laundering = store
            .append(superseded(
                "e2",
                "claim:trusted",
                "claim:attacker",
                "src:user",
                AuthorityLevel::High,
                3,
            ))
            .unwrap_err();
        assert!(
            matches!(laundering, StoreError::LaunderedAuthority { .. }),
            "laundering rejected by the wrong mechanism: {laundering:?}"
        );

        // Canonical contradiction: the LFI hard-alarm, not a soft contest.
        let mut store = InMemoryEventStore::new();
        store
            .append(asserted(
                "e0",
                "claim:canon",
                "postgres",
                "src:owner",
                AuthorityLevel::Canonical,
                1,
            ))
            .unwrap();
        let canonical = store
            .append(contradicted(
                "e1",
                "claim:canon",
                "claim:rumor",
                "src:user",
                AuthorityLevel::Low,
                2,
            ))
            .unwrap_err();
        assert!(
            matches!(
                canonical,
                StoreError::Rejected(TransitionError::CanonicalContradiction)
            ),
            "canonical contradiction rejected by the wrong mechanism: {canonical:?}"
        );
    }
}
