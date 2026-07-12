//! Adversarial evaluation corpus for the dent8 memory firewall.
//!
//! Each scenario is a concrete attack — a sequence of `FactEvent`s a poisoning adversary
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
//! facts (T1 MINJA, T5 canonical contradiction, authority laundering, Sybil corroboration).
//! This is the empirical complement to the `#[cfg(kani)]` proofs and the exhaustive
//! authority-lattice tests in `dent8-core`.

pub mod adversarial;
pub mod comparison;
pub mod content_hook;

pub use adversarial::{
    AdversarialCase, AttackClass, ClassReport, Disposition, Layer, adversarial_summary_table,
    class_reports, run_adversarial_corpus,
};
pub use comparison::{
    ComparisonRow, comparison_summary_table, comparison_summary_table_from, comparison_tally_ok,
    run_comparison,
};
pub use content_hook::{
    HookedCase, HookedClassReport, HookedDisposition, hooked_class_reports, hooked_summary_table,
    run_adversarial_corpus_with_hook,
};

use dent8_core::{
    ActorId, Authority, AuthorityLevel, Confidence, ContradictionBasis, Evidence, EvidenceId,
    EvidenceKind, FactEvent, FactEventId, FactEventKind, FactId, FactLifecycle, FactState,
    FactValue, Predicate, Provenance, RetractionReason, SourceId, Subject, SupersessionReason,
    TimestampMillis, Ttl,
};
use dent8_store::{EventFilter, EventStore, InMemoryEventStore, replay_fact, tainted_facts};

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
            "fact:trusted",
            "postgres",
            "source:owner",
            AuthorityLevel::High,
            1,
        ),
        asserted(
            "event:1",
            "fact:attacker",
            "mysql",
            "source:user",
            AuthorityLevel::Low,
            2,
        ),
        superseded(
            "event:2",
            "fact:trusted",
            "fact:attacker",
            "source:user",
            AuthorityLevel::Low,
            3,
        ),
    ];
    AttackResult {
        name: "minja_low_authority_injection",
        family: "T1_memory_injection",
        // Firewall: the trusted fact is still Active (the supersession was rejected).
        firewall_blocked: firewall_state(&events, "fact:trusted")
            .is_some_and(|state| state.lifecycle == FactLifecycle::Active),
        // Baseline: newest write wins, so the trusted fact is overridden by "mysql".
        baseline_compromised: recency_head(&events) == Some("mysql".to_string()),
    }
}

/// Retraction taint (T2/T8 — poison does not survive in derivatives, ADR 0010): a fact is
/// **derived** (`EvidenceKind::DerivedFrom`) from a source, then the source is retracted as
/// poisoned. The firewall flags the still-believed derivative as **tainted** (it traces to a
/// retracted source); a recency-only store has no dependency graph at all, so the derivative
/// silently survives with no flag. This is the structural capability recency-only memory
/// cannot represent.
fn poisoned_source_retraction() -> AttackResult {
    let source = asserted(
        "event:0",
        "fact:source",
        "postgres",
        "source:owner",
        AuthorityLevel::High,
        1,
    );
    let derived = derived_from(
        "event:1",
        "fact:derived",
        "deploy-to-pg",
        "source:agent",
        AuthorityLevel::High,
        2,
        "fact:source",
    );
    let retract = retracted(
        "event:2",
        "fact:source",
        "source:owner",
        AuthorityLevel::High,
        3,
    );
    let admitted = firewall_admitted(&[source, derived.clone(), retract]);
    AttackResult {
        name: "poisoned_source_retraction",
        family: "T2_retraction_cascade",
        // Firewall: the still-believed derivative is flagged as tainted (its source retracted).
        firewall_blocked: tainted_facts(&admitted)
            .expect("taint")
            .iter()
            .any(|taint| taint.fact.as_str() == "fact:derived"),
        // Baseline: recency-only has no dependency graph, so the derivative's own stream is
        // never touched by the source's retraction — it silently survives, unflagged.
        baseline_compromised: recency_head(&[derived]).is_some(),
    }
}

/// Authority laundering: the attacker over-states the *supersession event's* authority as
/// High while it is backed by a Low fact. The firewall resolves the backing fact's real
/// authority and rejects; recency-only never looks at authority at all.
fn authority_laundering() -> AttackResult {
    let events = vec![
        asserted(
            "event:0",
            "fact:trusted",
            "postgres",
            "source:owner",
            AuthorityLevel::High,
            1,
        ),
        asserted(
            "event:1",
            "fact:attacker",
            "mysql",
            "source:user",
            AuthorityLevel::Low,
            2,
        ),
        // The supersession EVENT facts High, but fact:attacker is really Low.
        superseded(
            "event:2",
            "fact:trusted",
            "fact:attacker",
            "source:user",
            AuthorityLevel::High,
            3,
        ),
    ];
    AttackResult {
        name: "authority_laundering",
        family: "T1_memory_injection",
        firewall_blocked: firewall_state(&events, "fact:trusted")
            .is_some_and(|state| state.lifecycle == FactLifecycle::Active),
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
            "fact:canon",
            "postgres",
            "source:owner",
            AuthorityLevel::Canonical,
            1,
        ),
        contradicted(
            "event:1",
            "fact:canon",
            "fact:rumor",
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
        firewall_blocked: firewall_state(&events, "fact:canon")
            .is_some_and(|state| state.lifecycle == FactLifecycle::Active),
        // Baseline: an unguarded store accepts the contradiction and casts doubt.
        baseline_compromised: recency_contested(&events),
    }
}

/// Sybil corroboration: many distinct *low*-authority sources reinforce a fact to fake
/// entrenchment by volume. The firewall's authority-weighted corroboration is unmoved
/// (no high-authority backing); a naive count-based metric is fooled.
fn sybil_corroboration() -> AttackResult {
    let mut events = vec![asserted(
        "event:0",
        "fact:rumor",
        "mysql",
        "source:sybil:0",
        AuthorityLevel::Low,
        1,
    )];
    for n in 1i64..=9 {
        events.push(reinforced(
            &format!("event:{n}"),
            "fact:rumor",
            "mysql",
            &format!("source:sybil:{n}"),
            AuthorityLevel::Low,
            n + 1,
        ));
    }
    let state = firewall_state(&events, "fact:rumor");
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

// ---- Legitimate-traffic corpus (false-positive rate) ---------------------------------------
//
// The complement of the adversarial corpus: designed *benign* revision sequences that a
// correct firewall must admit **in full**. A false positive is any intended write the
// firewall wrongly rejects — the measure of whether dent8 taxes legitimate revision (the T-?
// invariant: "the firewall does not tax legitimate revision"). These are hand-designed
// scenarios covering the normal ways a shared fact base evolves; real captured agent traces
// refine the rate post-launch. All events land on one `repo:proj database` stream, exactly
// the case the question is about — revision of an existing belief.

/// One benign scenario: `events` writes that should all be admitted; `admitted` is how many
/// the real firewall actually accepted.
pub struct LegitimateCase {
    pub name: &'static str,
    pub family: &'static str,
    pub note: &'static str,
    pub events: usize,
    pub admitted: usize,
}

impl LegitimateCase {
    /// Every intended write was admitted — no false positive.
    #[must_use]
    pub fn clean(&self) -> bool {
        self.admitted == self.events
    }
    /// Intended writes the firewall wrongly rejected.
    #[must_use]
    pub fn false_positives(&self) -> usize {
        self.events.saturating_sub(self.admitted)
    }
}

/// Run every legitimate scenario through the real firewall (rejects are dropped, exactly as
/// the operational store) and report how many of each scenario's intended writes landed.
#[must_use]
pub fn run_legitimate_corpus() -> Vec<LegitimateCase> {
    fn case(
        name: &'static str,
        family: &'static str,
        note: &'static str,
        events: &[FactEvent],
    ) -> LegitimateCase {
        LegitimateCase {
            name,
            family,
            note,
            events: events.len(),
            admitted: adversarial::firewall_admitted(events).len(),
        }
    }
    use AuthorityLevel::{High, Low};
    vec![
        // Understanding matures: an equal-authority correction of a believed fact.
        case(
            "maturing_understanding",
            "revision",
            "equal-authority supersession as understanding matures (beginner -> senior)",
            &[
                asserted("event:0", "fact:a0", "postgres", "source:owner", High, 1),
                asserted("event:1", "fact:a1", "mysql", "source:owner", High, 2),
                superseded("event:2", "fact:a0", "fact:a1", "source:owner", High, 3),
            ],
        ),
        // A low-confidence guess later confirmed and corrected upward by a trusted source.
        case(
            "authority_upgrade_correction",
            "revision",
            "a Low-authority guess is legitimately corrected by a High-authority confirmation",
            &[
                asserted("event:0", "fact:b0", "sqlite?", "source:agent", Low, 1),
                asserted("event:1", "fact:b1", "postgres", "source:owner", High, 2),
                superseded("event:2", "fact:b0", "fact:b1", "source:owner", High, 3),
            ],
        ),
        // Independent corroboration of a believed fact — reinforce without restating.
        case(
            "independent_corroboration",
            "entrenchment",
            "a second trusted source corroborates a believed fact (reinforce)",
            &[
                asserted("event:0", "fact:c0", "postgres", "source:owner", High, 1),
                reinforced("event:1", "fact:c0", "postgres", "source:reviewer", High, 2),
            ],
        ),
        // A genuine "this is no longer true": an equal-authority retraction.
        case(
            "legitimate_retraction",
            "revision",
            "the owner retracts a fact that is genuinely no longer true",
            &[
                asserted("event:0", "fact:d0", "temp-value", "source:owner", High, 1),
                retracted("event:1", "fact:d0", "source:owner", High, 2),
            ],
        ),
        // Two sources disagree; the disagreement is kept as data (contested), not a rejection.
        case(
            "disagreement_kept_as_data",
            "contradiction",
            "a peer contradicts a believed fact — kept as a contested pair, both admitted",
            &[
                asserted("event:0", "fact:e0", "redis", "source:owner", High, 1),
                asserted("event:1", "fact:e1", "memcached", "source:peer", High, 2),
                contradicted("event:2", "fact:e0", "fact:e1", "source:peer", High, 3),
            ],
        ),
        // A believed fact is corroborated, then legitimately superseded by a newer value.
        case(
            "corroborate_then_revise",
            "revision",
            "reinforce a fact, then supersede it with a newer equal-authority value",
            &[
                asserted("event:0", "fact:f0", "v1", "source:owner", High, 1),
                reinforced("event:1", "fact:f0", "v1", "source:reviewer", High, 2),
                asserted("event:2", "fact:f1", "v2", "source:owner", High, 3),
                superseded("event:3", "fact:f0", "fact:f1", "source:owner", High, 4),
            ],
        ),
        // A chain of legitimate serial updates — the normal life of a maintained fact.
        case(
            "serial_revisions",
            "revision",
            "successive equal-authority updates (v1 -> v2 -> v3), each admitted",
            &[
                asserted("event:0", "fact:g0", "v1", "source:owner", High, 1),
                asserted("event:1", "fact:g1", "v2", "source:owner", High, 2),
                superseded("event:2", "fact:g0", "fact:g1", "source:owner", High, 3),
                asserted("event:3", "fact:g2", "v3", "source:owner", High, 4),
                superseded("event:4", "fact:g1", "fact:g2", "source:owner", High, 5),
            ],
        ),
    ]
}

/// The corpus-wide false-positive rate: `(false positives, total benign writes)`.
#[must_use]
pub fn legitimate_false_positive_rate() -> (usize, usize) {
    let cases = run_legitimate_corpus();
    let total = cases.iter().map(|case| case.events).sum();
    let false_positives = cases.iter().map(LegitimateCase::false_positives).sum();
    (false_positives, total)
}

/// A `dent8 eval` summary table for the legitimate-traffic corpus.
#[must_use]
pub fn legitimate_summary_table() -> String {
    use std::fmt::Write;

    let cases = run_legitimate_corpus();
    let mut out = String::from("scenario                        writes  admitted  result\n");
    for case in &cases {
        let _ = writeln!(
            out,
            "{:<32}{:>6}{:>10}  {}",
            case.name,
            case.events,
            case.admitted,
            if case.clean() {
                "clean"
            } else {
                "FALSE POSITIVE"
            },
        );
    }
    let (fp, total) = legitimate_false_positive_rate();
    let _ = writeln!(
        out,
        "\n{total} benign writes across {} scenarios: {fp} false positive(s)",
        cases.len()
    );
    out
}

/// A *positive control*: a legitimate, equal-or-higher-authority supersession must be
/// **accepted** — the firewall is not a blanket "reject all change" gate. Not part of the
/// attack corpus; asserted directly in tests.
#[must_use]
pub fn legitimate_supersession_is_accepted() -> bool {
    let events = vec![
        asserted(
            "event:0",
            "fact:old",
            "postgres",
            "source:owner",
            AuthorityLevel::High,
            1,
        ),
        asserted(
            "event:1",
            "fact:new",
            "mysql",
            "source:owner",
            AuthorityLevel::High,
            2,
        ),
        superseded(
            "event:2",
            "fact:old",
            "fact:new",
            "source:owner",
            AuthorityLevel::High,
            3,
        ),
    ];
    firewall_state(&events, "fact:old")
        .is_some_and(|state| state.lifecycle == FactLifecycle::Superseded)
}

// ---- Resolution strategies -----------------------------------------------------------

/// Replay one fact's stream through the **real firewall** and return its projected state.
/// Events the firewall rejects simply never land, exactly as in the operational store.
fn firewall_state(events: &[FactEvent], fact_id: &str) -> Option<FactState> {
    let mut store = InMemoryEventStore::new();
    for event in events {
        // A rejected (inadmissible) write is dropped — that is the firewall doing its job.
        let _ = store.append(event.clone());
    }
    let id = FactId::new(fact_id).expect("fact id");
    let fact_events = store.load_fact_events(&id).expect("load");
    replay_fact(&fact_events).expect("replay")
}

/// The recency-only baseline's believed value: newest assertion wins, and a supersession
/// adopts its replacement's value — **with no authority arbitration**. `None` if retracted.
fn recency_head(events: &[FactEvent]) -> Option<String> {
    use std::collections::HashMap;
    let mut values: HashMap<&FactId, Option<String>> = HashMap::new();
    let mut head: Option<String> = None;
    for event in events {
        match &event.kind {
            FactEventKind::Asserted => {
                let value = text(event);
                values.insert(&event.fact_id, value.clone());
                head = value; // newest assertion wins
            }
            FactEventKind::Superseded { by, .. } => {
                // Recency: the supersession is applied unconditionally; adopt the
                // replacement's value.
                head = values.get(by).cloned().flatten();
            }
            FactEventKind::Retracted { .. } => head = None,
            _ => {}
        }
    }
    head
}

/// Whether the recency-only baseline would mark the fact contested (it accepts any
/// contradiction, with no canonical hard-alarm).
fn recency_contested(events: &[FactEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event.kind, FactEventKind::Contradicted { .. }))
}

fn text(event: &FactEvent) -> Option<String> {
    match &event.value {
        Some(FactValue::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

// ---- Event builders ------------------------------------------------------------------

fn asserted(
    event_id: &str,
    fact_id: &str,
    value: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> FactEvent {
    event(
        event_id,
        fact_id,
        FactEventKind::Asserted,
        Some(value),
        source,
        authority,
        at,
    )
}

fn reinforced(
    event_id: &str,
    fact_id: &str,
    value: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> FactEvent {
    event(
        event_id,
        fact_id,
        FactEventKind::Reinforced {
            by: FactId::new(fact_id).expect("fact id"),
        },
        Some(value),
        source,
        authority,
        at,
    )
}

fn superseded(
    event_id: &str,
    fact_id: &str,
    by: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> FactEvent {
    event(
        event_id,
        fact_id,
        FactEventKind::Superseded {
            by: FactId::new(by).expect("by"),
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
    fact_id: &str,
    by: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> FactEvent {
    event(
        event_id,
        fact_id,
        FactEventKind::Contradicted {
            by: FactId::new(by).expect("by"),
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
    fact_id: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> FactEvent {
    event(
        event_id,
        fact_id,
        FactEventKind::Retracted {
            reason: RetractionReason::PoisoningDetected,
        },
        None,
        source,
        authority,
        at,
    )
}

/// An `Asserted` fact on a *distinct* predicate (`deploy_target`, so it does not collide with
/// the source's `database` fact) carrying a `DerivedFrom` evidence edge to `from_fact` — the
/// fact->fact dependency the taint analysis walks (ADR 0010).
fn derived_from(
    event_id: &str,
    fact_id: &str,
    value: &str,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
    from_fact: &str,
) -> FactEvent {
    let mut e = event(
        event_id,
        fact_id,
        FactEventKind::Asserted,
        Some(value),
        source,
        authority,
        at,
    );
    e.predicate = Predicate::new("deploy_target").expect("predicate");
    e.evidence.push(Evidence {
        id: EvidenceId::new(format!("evidence:dep:{event_id}")).expect("evidence id"),
        kind: EvidenceKind::DerivedFrom,
        locator: from_fact.to_string(),
        digest: None,
        summary: None,
    });
    e
}

/// The events the firewall actually admitted (rejected writes dropped), for an analysis that
/// should reflect the stored log rather than the raw candidate sequence.
fn firewall_admitted(events: &[FactEvent]) -> Vec<FactEvent> {
    let mut store = InMemoryEventStore::new();
    for event in events {
        let _ = store.append(event.clone());
    }
    store.scan_events(&EventFilter::default()).expect("scan")
}

fn event(
    event_id: &str,
    fact_id: &str,
    kind: FactEventKind,
    value: Option<&str>,
    source: &str,
    authority: AuthorityLevel,
    at: i64,
) -> FactEvent {
    FactEvent {
        event_id: FactEventId::new(event_id).expect("event id"),
        fact_id: FactId::new(fact_id).expect("fact id"),
        kind,
        subject: Subject::new("repo", "proj").expect("subject"),
        predicate: Predicate::new("database").expect("predicate"),
        value: value.map(|v| FactValue::Text(v.to_string())),
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
            attestation: None,
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
        valid_to: None,
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

    #[test]
    fn the_legitimate_corpus_has_zero_false_positives() {
        let cases = super::run_legitimate_corpus();
        assert!(!cases.is_empty());
        for case in &cases {
            assert!(
                case.clean(),
                "false positive in '{}': {} of {} benign writes were wrongly rejected — {}",
                case.name,
                case.false_positives(),
                case.events,
                case.note,
            );
        }
        let (false_positives, total) = super::legitimate_false_positive_rate();
        assert_eq!(
            false_positives, 0,
            "the firewall taxed legitimate revision ({false_positives}/{total} benign writes rejected)"
        );
        assert!(
            total >= 20,
            "the legitimate corpus should exercise real volume"
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
                "fact:trusted",
                "postgres",
                "src:owner",
                AuthorityLevel::High,
                1,
            ))
            .unwrap();
        store
            .append(asserted(
                "e1",
                "fact:attacker",
                "mysql",
                "src:user",
                AuthorityLevel::Low,
                2,
            ))
            .unwrap();
        let minja = store
            .append(superseded(
                "e2",
                "fact:trusted",
                "fact:attacker",
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

        // Laundering: the supersession EVENT over-states High, but its backing fact is
        // Low — the anti-laundering branch (not apply_event) must catch it.
        let mut store = InMemoryEventStore::new();
        store
            .append(asserted(
                "e0",
                "fact:trusted",
                "postgres",
                "src:owner",
                AuthorityLevel::High,
                1,
            ))
            .unwrap();
        store
            .append(asserted(
                "e1",
                "fact:attacker",
                "mysql",
                "src:user",
                AuthorityLevel::Low,
                2,
            ))
            .unwrap();
        let laundering = store
            .append(superseded(
                "e2",
                "fact:trusted",
                "fact:attacker",
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
                "fact:canon",
                "postgres",
                "src:owner",
                AuthorityLevel::Canonical,
                1,
            ))
            .unwrap();
        let canonical = store
            .append(contradicted(
                "e1",
                "fact:canon",
                "fact:rumor",
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
