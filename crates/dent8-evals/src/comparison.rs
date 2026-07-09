//! Integrity-axis comparison against **modeled** peer memory systems.
//!
//! This is the external-eval lane for v0.4: the same attack sequences as the
//! demonstrative firewall-vs-recency corpus, judged against three resolution models:
//!
//! | model | what it stands for | semantics |
//! |---|---|---|
//! | **dent8** | this project | real `InMemoryEventStore::append` (authority arbitration + taint) |
//! | **zep_recency** | Zep / Graphiti | newest-write-wins edge invalidation; no authority weight [1] |
//! | **mem0_mutate** | Mem0 (base) | mutate-in-place by memory key; last UPDATE wins; no lineage [2] |
//!
//! These are **semantic models** of published resolution behaviour, not live API clients.
//! Calling production Mem0/Zep would couple the suite to network, accounts, and version
//! drift; the integrity claim is about *what their resolution policy admits*, which the
//! papers document. Patterns are adapted into dent8's event shape — not copied payloads.
//!
//! [1]: Zep/Graphiti "consistently prioritizes new information when determining edge
//!      invalidation" (arXiv:2501.13956).
//! [2]: Mem0 base path uses ADD/UPDATE/DELETE over similar memories with no append-only
//!      log, provenance, or supersession history (Mem0 paper / docs).
//!
//! # Honesty
//!
//! - A cell is **holds** only when the integrity property for that axis is preserved.
//! - A cell is **compromised** when the attacker's goal is met under that model.
//! - Fixture events share `subject=repo:proj` / `predicate=database` unless a case uses a
//!   distinct predicate (e.g. derived `deploy_target`). Mem0 keys on subject+predicate, so
//!   a second assert on the same S-P overwrites the slot before supersession — that is the
//!   intended "no authority filter on UPDATE" failure mode, not a supersession-only test.
//! - Mem0 has no corroboration or "contested" concept; the Sybil axis is scored as
//!   compromised when the model accepts a high volume of low-authority UPDATEs without an
//!   authority gate.
//! - Legitimate equal-authority revision is a **positive control**: all three models
//!   should accept it (dent8 is not a blanket reject gate).

#![allow(clippy::doc_markdown)]

use std::collections::HashMap;

use dent8_core::{AuthorityLevel, FactEvent, FactEventKind, FactId, FactLifecycle, FactValue};
use dent8_store::tainted_facts;

use crate::{
    asserted, contradicted, derived_from, firewall_admitted, firewall_state, recency_contested,
    recency_head, reinforced, retracted, superseded,
};

/// One integrity axis run against dent8 and the two peer models.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparisonRow {
    /// Stable axis id (matches the demonstrative corpus name where applicable).
    pub axis: &'static str,
    /// Threat-model / family tag.
    pub family: &'static str,
    /// Integrity property holds under the real dent8 firewall.
    pub dent8_holds: bool,
    /// Integrity property holds under Zep/Graphiti-style recency resolution.
    pub zep_holds: bool,
    /// Integrity property holds under Mem0-style mutate-in-place resolution.
    pub mem0_holds: bool,
    /// Short note for the report table (what "holds" means on this axis).
    pub property: &'static str,
}

impl ComparisonRow {
    /// dent8 preserves the property while **both** peer models fail it (the documented claim).
    #[must_use]
    pub fn differentiates(&self) -> bool {
        self.dent8_holds && !self.zep_holds && !self.mem0_holds
    }
}

/// Frozen tally predicate shared by unit tests and `dent8 eval`.
///
/// Attack axes: dent8 holds; both peers compromised. Positive control: all three hold.
#[must_use]
pub fn comparison_tally_ok(rows: &[ComparisonRow]) -> bool {
    rows.iter().all(|row| {
        if row.family == "positive_control" {
            row.dent8_holds && row.zep_holds && row.mem0_holds
        } else {
            row.dent8_holds && !row.zep_holds && !row.mem0_holds
        }
    })
}

/// Run every integrity axis. Order is stable for frozen-tally tests and docs tables.
#[must_use]
pub fn run_comparison() -> Vec<ComparisonRow> {
    vec![
        minja_low_authority_injection(),
        authority_laundering(),
        canonical_contradiction(),
        sybil_corroboration(),
        poisoned_source_retraction(),
        legitimate_supersession(),
    ]
}

/// Markdown table of the comparison — suitable for `dent8 eval` and docs.
#[must_use]
pub fn comparison_summary_table() -> String {
    comparison_summary_table_from(&run_comparison())
}

/// Markdown table from an already-computed comparison (avoids a second full run).
#[must_use]
pub fn comparison_summary_table_from(rows: &[ComparisonRow]) -> String {
    use std::fmt::Write;

    let mut out = String::from(
        "| axis | property | dent8 | zep/graphiti (recency) | mem0 (mutate-in-place) |\n\
         |---|---|---|---|---|\n",
    );
    for row in rows {
        let _ = writeln!(
            out,
            "| `{}` | {} | {} | {} | {} |",
            row.axis,
            row.property,
            cell(row.dent8_holds),
            cell(row.zep_holds),
            cell(row.mem0_holds),
        );
    }
    out
}

fn cell(holds: bool) -> &'static str {
    if holds {
        "holds ✓"
    } else {
        "**compromised**"
    }
}

// ---- Axes ---------------------------------------------------------------------------

fn minja_low_authority_injection() -> ComparisonRow {
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
    // Property: the trusted high-authority value is not displaced by a low-authority write.
    // Mem0: same S-P key means the attacker's Asserted already overwrites the slot (no
    // authority filter) — that is the intended failure mode for this fixture shape.
    let trusted_still_postgres = |value: Option<&str>| value == Some("postgres");
    ComparisonRow {
        axis: "minja_low_authority_injection",
        family: "T1_memory_injection",
        property: "low-authority write cannot displace trusted belief",
        dent8_holds: firewall_state(&events, "fact:trusted").is_some_and(|s| {
            s.lifecycle == FactLifecycle::Active && text_of(&s) == Some("postgres")
        }),
        zep_holds: trusted_still_postgres(recency_head(&events).as_deref()),
        mem0_holds: trusted_still_postgres(mem0_apply(&events).head().as_deref()),
    }
}

fn authority_laundering() -> ComparisonRow {
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
            AuthorityLevel::High,
            3,
        ),
    ];
    let trusted_still_postgres = |value: Option<&str>| value == Some("postgres");
    ComparisonRow {
        axis: "authority_laundering",
        family: "T1_memory_injection",
        property: "over-stated supersession authority cannot launder a low backing fact",
        dent8_holds: firewall_state(&events, "fact:trusted").is_some_and(|s| {
            s.lifecycle == FactLifecycle::Active && text_of(&s) == Some("postgres")
        }),
        zep_holds: trusted_still_postgres(recency_head(&events).as_deref()),
        mem0_holds: trusted_still_postgres(mem0_apply(&events).head().as_deref()),
    }
}

fn canonical_contradiction() -> ComparisonRow {
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
    let mem0 = mem0_apply(&events);
    ComparisonRow {
        axis: "canonical_contradiction",
        family: "T5_canonical_contradiction",
        property: "canonical fact is not softened by low-authority contradiction",
        dent8_holds: firewall_state(&events, "fact:canon")
            .is_some_and(|s| s.lifecycle == FactLifecycle::Active),
        // Recency model accepts the contradiction and casts doubt.
        zep_holds: !recency_contested(&events),
        // Mem0 has no contested state: a contradiction-shaped UPDATE overwrites the slot
        // (see mem0_apply).
        mem0_holds: mem0.head().as_deref() == Some("postgres")
            && !mem0.slots.values().any(|v| v == "__contested__"),
    }
}

fn sybil_corroboration() -> ComparisonRow {
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
    let mem0 = mem0_apply(&events);
    ComparisonRow {
        axis: "sybil_corroboration",
        family: "earned_entrenchment",
        property: "volume of low-authority sources earns no high-trust entrenchment",
        dent8_holds: state
            .as_ref()
            .is_some_and(|s| s.corroboration_at_or_above(AuthorityLevel::High) == 0),
        // Naive recency/count: 10 sources look strong.
        zep_holds: state.as_ref().is_none_or(|s| s.corroboration() < 10),
        // Model-scored: Mem0 accepted every Asserted/Reinforced write with no authority gate.
        mem0_holds: mem0.accepted_updates < 10,
    }
}

fn poisoned_source_retraction() -> ComparisonRow {
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
    let sequence = [source, derived.clone(), retract];
    let admitted = firewall_admitted(&sequence);
    let derived_key = mem0_key(&derived);
    let mem0 = mem0_apply(&sequence);
    // Integrity holds only if the derivative is gone or flagged. Peers never flag; they
    // hold only if the derived belief is removed by the source retract (cascade).
    ComparisonRow {
        axis: "poisoned_source_retraction",
        family: "T2_retraction_cascade",
        property: "derivative of a retracted source is flagged (or removed), not silent",
        dent8_holds: tainted_facts(&admitted)
            .is_ok_and(|taints| taints.iter().any(|t| t.fact.as_str() == "fact:derived")),
        // Recency has no dependency graph: retracting the source fact does not clear the
        // derived fact's value under a per-fact recency model.
        zep_holds: recency_fact_value(&sequence, "fact:derived").is_none(),
        // Mem0 DELETE of the source S-P key does not cascade to the derived deploy_target key.
        mem0_holds: mem0.get(&derived_key).is_none(),
    }
}

fn legitimate_supersession() -> ComparisonRow {
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
    ComparisonRow {
        axis: "legitimate_supersession",
        family: "positive_control",
        property: "equal-authority revision is admitted (not a blanket reject gate)",
        dent8_holds: firewall_state(&events, "fact:old")
            .is_some_and(|s| s.lifecycle == FactLifecycle::Superseded),
        zep_holds: recency_head(&events).as_deref() == Some("mysql"),
        mem0_holds: mem0_apply(&events).head().as_deref() == Some("mysql"),
    }
}

// ---- Peer models --------------------------------------------------------------------

/// Snapshot of the Mem0-style mutate-in-place store after applying a sequence.
struct Mem0State {
    slots: HashMap<String, String>,
    /// Count of Asserted / Reinforced / Superseded writes the model accepted.
    accepted_updates: usize,
    /// Most recently written key that still exists (for single-slot scenarios).
    last_key: Option<String>,
}

impl Mem0State {
    fn head(&self) -> Option<String> {
        self.last_key
            .as_ref()
            .and_then(|k| self.slots.get(k).cloned())
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.slots.get(key).map(String::as_str)
    }
}

/// Mem0-style mutate-in-place: one slot per memory key (`subject|predicate`), last write
/// wins, DELETE clears the slot, no lineage / authority / taint graph.
///
/// Mapping from dent8 events:
/// - `Asserted` → ADD/UPDATE the slot to the asserted value
/// - `Superseded` → UPDATE the superseded fact's key to the replacement's value
/// - `Retracted` → DELETE the slot
/// - `Contradicted` → UPDATE the slot to a contested marker (attacker casts doubt; no
///   authority gate). Modeled as overwriting with `"__contested__"` so the original
///   trusted value is no longer the sole believed content.
/// - `Reinforced` → UPDATE (touch) the same value; counts toward Sybil volume
fn mem0_apply(events: &[FactEvent]) -> Mem0State {
    let mut slots: HashMap<String, String> = HashMap::new();
    let mut values_by_fact: HashMap<FactId, String> = HashMap::new();
    let mut last_key: Option<String> = None;
    let mut accepted_updates = 0usize;

    for event in events {
        let key = mem0_key(event);
        match &event.kind {
            FactEventKind::Asserted => {
                if let Some(value) = event_text(event) {
                    values_by_fact.insert(event.fact_id.clone(), value.clone());
                    slots.insert(key.clone(), value);
                    last_key = Some(key);
                    accepted_updates += 1;
                }
            }
            FactEventKind::Superseded { by, .. } => {
                if let Some(value) = values_by_fact.get(by).cloned() {
                    slots.insert(key.clone(), value);
                    last_key = Some(key);
                    accepted_updates += 1;
                }
            }
            FactEventKind::Retracted { .. } => {
                slots.remove(&key);
                if last_key.as_ref() == Some(&key) {
                    // Prefer another surviving slot so multi-key scenarios stay queryable
                    // via head() when useful; cascade checks use get(key) directly.
                    last_key = slots.keys().next().cloned();
                }
            }
            FactEventKind::Contradicted { .. } => {
                slots.insert(key.clone(), "__contested__".to_string());
                last_key = Some(key);
                accepted_updates += 1;
            }
            FactEventKind::Reinforced { .. } => {
                if let Some(value) = event_text(event) {
                    slots.insert(key.clone(), value);
                    last_key = Some(key);
                    accepted_updates += 1;
                }
            }
            _ => {}
        }
    }

    Mem0State {
        slots,
        accepted_updates,
        last_key,
    }
}

/// Per-fact recency model: newest assert/reinforce wins per fact id; supersession adopts
/// the replacement value onto the superseded fact; retract clears that fact only.
fn recency_fact_value(events: &[FactEvent], fact_id: &str) -> Option<String> {
    let target = FactId::new(fact_id).expect("fact id");
    let mut values: HashMap<FactId, Option<String>> = HashMap::new();
    for event in events {
        match &event.kind {
            FactEventKind::Asserted | FactEventKind::Reinforced { .. } => {
                values.insert(event.fact_id.clone(), event_text(event));
            }
            FactEventKind::Superseded { by, .. } => {
                let replacement = values.get(by).cloned().flatten();
                values.insert(event.fact_id.clone(), replacement);
            }
            FactEventKind::Retracted { .. } => {
                values.insert(event.fact_id.clone(), None);
            }
            FactEventKind::Contradicted { .. } => {
                // Cast doubt but keep a believed value marker for "not clean".
                values.insert(event.fact_id.clone(), Some("__contested__".to_string()));
            }
            _ => {}
        }
    }
    values.get(&target).cloned().flatten()
}

fn mem0_key(event: &FactEvent) -> String {
    format!(
        "{}:{}|{}",
        event.subject.kind(),
        event.subject.key(),
        event.predicate.as_str()
    )
}

fn event_text(event: &FactEvent) -> Option<String> {
    match &event.value {
        Some(FactValue::Text(value)) => Some(value.clone()),
        _ => None,
    }
}

fn text_of(state: &dent8_core::FactState) -> Option<&str> {
    match &state.value {
        FactValue::Text(value) => Some(value.as_str()),
        FactValue::Json(_) | FactValue::Redacted => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{ComparisonRow, comparison_summary_table, comparison_tally_ok, run_comparison};

    /// Frozen honest tally: dent8 holds every integrity axis; both peer models fall on
    /// every attack axis; all three admit the legitimate-revision positive control.
    #[test]
    fn frozen_comparison_tally_matches_documented_results() {
        let rows = run_comparison();
        assert_eq!(rows.len(), 6);
        assert!(
            comparison_tally_ok(&rows),
            "frozen comparison tally drifted:\n{}",
            comparison_summary_table()
        );

        let by_axis: std::collections::BTreeMap<&str, &ComparisonRow> =
            rows.iter().map(|r| (r.axis, r)).collect();

        for axis in [
            "minja_low_authority_injection",
            "authority_laundering",
            "canonical_contradiction",
            "sybil_corroboration",
            "poisoned_source_retraction",
        ] {
            let row = by_axis[axis];
            assert!(
                row.differentiates(),
                "{axis}: should differentiate from both peers"
            );
        }

        let legit = by_axis["legitimate_supersession"];
        assert!(legit.dent8_holds && legit.zep_holds && legit.mem0_holds);
        assert!(!legit.differentiates());
    }

    #[test]
    fn comparison_summary_table_is_nonempty_markdown() {
        let table = comparison_summary_table();
        assert!(table.contains("| dent8 |"));
        assert!(table.contains("minja_low_authority_injection"));
        assert!(table.contains("legitimate_supersession"));
    }

    #[test]
    fn dent8_holds_count_is_six_and_attack_peers_are_zero() {
        let rows = run_comparison();
        let dent8 = rows.iter().filter(|r| r.dent8_holds).count();
        let zep_attacks = rows
            .iter()
            .filter(|r| r.family != "positive_control" && r.zep_holds)
            .count();
        let mem0_attacks = rows
            .iter()
            .filter(|r| r.family != "positive_control" && r.mem0_holds)
            .count();
        assert_eq!(dent8, 6);
        assert_eq!(zep_attacks, 0);
        assert_eq!(mem0_attacks, 0);
    }

    #[test]
    fn poisoned_source_peer_models_keep_derived_after_source_retract() {
        let rows = run_comparison();
        let row = rows
            .iter()
            .find(|r| r.axis == "poisoned_source_retraction")
            .expect("axis");
        // Peers compromised == integrity does not hold.
        assert!(!row.zep_holds);
        assert!(!row.mem0_holds);
        assert!(row.dent8_holds);
    }
}
