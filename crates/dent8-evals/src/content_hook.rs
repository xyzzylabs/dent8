//! Eval mode: the externally-grounded adversarial corpus with a **content-check hook**
//! attached (see `dent8_core::content_check` and `docs/content-check.md`).
//!
//! The plain corpus ([`crate::adversarial`]) reports honestly that `append`-arbitration
//! admits every content-embedded attack by design — it never reads `value` text. This
//! module re-runs the *same* 47 cases with a scanner composed into the write boundary,
//! exactly as the CLI/MCP hook does it: each value-carrying candidate is scanned before
//! it is offered to the firewall; a `reject` verdict drops it, a `taint` verdict admits
//! it marked, and the goal is then judged by the same predicate as the plain corpus.
//!
//! # Read the numbers honestly
//!
//! These results are reported **separately** from the core arbitration numbers — they
//! measure the *composition seam*, not dent8 itself, and they depend entirely on the
//! scanner you attach. The repo's reference scanner
//! (`examples/scanners/demo-content-check.sh`) is a handful of regexes written **with
//! knowledge of this corpus**: its hits demonstrate that the hook covers the write path,
//! and its deliberate misses (rot13, translated imperatives) demonstrate that regexes are
//! not a defense. Do not read its per-class rates as scanner efficacy.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use dent8_core::{
    FactId, TimestampMillis,
    content_check::{self, ContentCheckConfig, ContentCheckRefusal},
};
use dent8_store::tainted_facts;

use crate::adversarial::{
    AttackClass, Spec, firewall_admitted, goal_outcome, project, run_adversarial_corpus, specs,
};

/// The exclusive outcome of one corpus case with the hook attached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookedDisposition {
    /// Arbitration alone already blocks this case (the plain corpus's verdict), so the
    /// block is attributed to arbitration even when the scanner also fired.
    BlockedByArbitration,
    /// Newly blocked: prevented with the hook attached but admitted without it.
    BlockedByHook,
    /// Admitted but flagged — read-time freshness, retraction taint, or a content flag.
    DetectOnly,
    /// Admitted and unflagged: still out of reach even with this scanner attached.
    AdmittedUnflagged,
}

/// One corpus case's outcome with the hook attached.
#[derive(Clone, Debug)]
pub struct HookedCase {
    pub name: &'static str,
    pub class: AttackClass,
    pub disposition: HookedDisposition,
    /// The scanner rejected at least one candidate event of this case.
    pub hook_rejected_a_candidate: bool,
}

impl HookedCase {
    /// The attacker's goal was prevented — by arbitration or by the hook.
    #[must_use]
    pub fn blocked(&self) -> bool {
        matches!(
            self.disposition,
            HookedDisposition::BlockedByArbitration | HookedDisposition::BlockedByHook
        )
    }
}

/// One class's aggregate outcome with the hook attached. `blocked_by_arbitration` +
/// `blocked_by_hook` + `detect_only` + `admitted_unflagged` = `total`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HookedClassReport {
    pub class: AttackClass,
    pub total: usize,
    pub blocked_by_arbitration: usize,
    pub blocked_by_hook: usize,
    pub detect_only: usize,
    pub admitted_unflagged: usize,
}

/// Run the full corpus with `config`'s scanner composed into the write boundary. Errors
/// if the scanner itself fails (the eval judges verdicts, not scanner uptime — a broken
/// scanner is a broken eval run, so it fails loudly rather than skewing the numbers).
pub fn run_adversarial_corpus_with_hook(
    config: &ContentCheckConfig,
) -> Result<Vec<HookedCase>, String> {
    // Arbitration-only verdicts, for attribution: a case arbitration already blocks is
    // never credited to the scanner.
    let arbitration_blocked: BTreeMap<&'static str, bool> = run_adversarial_corpus()
        .into_iter()
        .map(|case| (case.name, case.firewall_blocked))
        .collect();
    specs()
        .iter()
        .map(|spec| evaluate_with_hook(spec, config, arbitration_blocked[spec.name]))
        .collect()
}

fn evaluate_with_hook(
    spec: &Spec,
    config: &ContentCheckConfig,
    blocked_by_arbitration_alone: bool,
) -> Result<HookedCase, String> {
    // The hook runs per candidate, before the firewall sees it — mirroring the `op_*`
    // write path: reject drops the candidate, taint marks it in place, allow passes it.
    let mut offered = Vec::with_capacity(spec.events.len());
    let mut hook_rejected_a_candidate = false;
    for event in &spec.events {
        let mut event = event.clone();
        match content_check::enforce(config, std::slice::from_mut(&mut event)) {
            Ok(()) => offered.push(event),
            Err(ContentCheckRefusal::Rejected { .. }) => hook_rejected_a_candidate = true,
            Err(refusal @ ContentCheckRefusal::ScannerUnavailable(_)) => {
                return Err(refusal.to_string());
            }
        }
    }

    let admitted = firewall_admitted(&offered);
    let states = project(&admitted);
    // Detect-only flags: retraction taint (as in the plain corpus) plus content flags
    // (a `taint` verdict marked the stored event).
    let mut flagged_facts: BTreeSet<FactId> = tainted_facts(&admitted)
        .map_err(|error| error.to_string())?
        .into_iter()
        .map(|t| t.fact)
        .collect();
    for event in &admitted {
        if content_check::content_flag(event).is_some() {
            flagged_facts.insert(event.fact_id.clone());
        }
    }
    let now = TimestampMillis::from_unix_millis(spec.now);
    let (goal_reached, flagged) = goal_outcome(spec.goal, &states, &flagged_facts, now);

    let disposition = if !goal_reached {
        if blocked_by_arbitration_alone {
            HookedDisposition::BlockedByArbitration
        } else {
            HookedDisposition::BlockedByHook
        }
    } else if flagged {
        HookedDisposition::DetectOnly
    } else {
        HookedDisposition::AdmittedUnflagged
    };
    Ok(HookedCase {
        name: spec.name,
        class: spec.class,
        disposition,
        hook_rejected_a_candidate,
    })
}

/// Aggregate the hooked corpus into per-class reports, in [`AttackClass::ALL`] order.
pub fn hooked_class_reports(config: &ContentCheckConfig) -> Result<Vec<HookedClassReport>, String> {
    let cases = run_adversarial_corpus_with_hook(config)?;
    Ok(AttackClass::ALL
        .iter()
        .map(|&class| {
            let mut report = HookedClassReport {
                class,
                total: 0,
                blocked_by_arbitration: 0,
                blocked_by_hook: 0,
                detect_only: 0,
                admitted_unflagged: 0,
            };
            for case in cases.iter().filter(|case| case.class == class) {
                report.total += 1;
                match case.disposition {
                    HookedDisposition::BlockedByArbitration => {
                        report.blocked_by_arbitration += 1;
                    }
                    HookedDisposition::BlockedByHook => report.blocked_by_hook += 1,
                    HookedDisposition::DetectOnly => report.detect_only += 1,
                    HookedDisposition::AdmittedUnflagged => report.admitted_unflagged += 1,
                }
            }
            report
        })
        .collect())
}

/// A Markdown table of the hooked per-class results, for the docs. Clearly labeled as the
/// hook + attached-scanner lane; the core arbitration numbers live in
/// [`crate::adversarial::adversarial_summary_table`] and are unchanged by this mode.
pub fn hooked_summary_table(config: &ContentCheckConfig) -> Result<String, String> {
    let reports = hooked_class_reports(config)?;
    let mut out = String::from(
        "| class | cases | blocked (arbitration) | + blocked (hook) | detect-only (flagged) | \
         admitted unflagged |\n|---|---|---|---|---|---|\n",
    );
    let mut totals = (0usize, 0usize, 0usize, 0usize, 0usize);
    for report in &reports {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} | {} |",
            report.class.label(),
            report.total,
            report.blocked_by_arbitration,
            report.blocked_by_hook,
            report.detect_only,
            report.admitted_unflagged,
        );
        totals.0 += report.total;
        totals.1 += report.blocked_by_arbitration;
        totals.2 += report.blocked_by_hook;
        totals.3 += report.detect_only;
        totals.4 += report.admitted_unflagged;
    }
    let _ = writeln!(
        out,
        "| **total** | **{}** | **{}** | **{}** | **{}** | **{}** |",
        totals.0, totals.1, totals.2, totals.3, totals.4,
    );
    Ok(out)
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use dent8_core::content_check::ContentCheckConfig;

    use super::{AttackClass, HookedClassReport, hooked_class_reports, hooked_summary_table};

    /// The repo's reference scanner, or `None` when the test runs outside the repo layout
    /// (e.g. from a packaged crate) — those runs skip rather than fail.
    fn demo_scanner() -> Option<ContentCheckConfig> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/scanners/demo-content-check.sh"
        );
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: reference scanner not found at {path}");
            return None;
        }
        Some(ContentCheckConfig::new(vec![path.to_string()]).expect("config"))
    }

    /// The frozen, HONEST per-class tally with the demo scanner attached:
    /// (class, total, blocked-by-arbitration, blocked-by-hook, detect-only, admitted-unflagged).
    /// Like the plain corpus's frozen tally, this encodes the truth — including the demo
    /// scanner's deliberate misses — never a "hook catches everything" fiction. If a rule
    /// or corpus case changes, update this map *and* the docs table in the same change.
    const EXPECTED: [(AttackClass, usize, usize, usize, usize, usize); 10] = [
        (AttackClass::InjectionInContent, 5, 0, 4, 1, 0),
        (AttackClass::AuthoritySpoofing, 5, 2, 0, 0, 3),
        (AttackClass::SupersedeOverrideAbuse, 6, 5, 0, 0, 1),
        (AttackClass::StalenessTemporal, 5, 2, 0, 2, 1),
        (AttackClass::CrossAgentContamination, 5, 2, 0, 1, 2),
        (AttackClass::DataExfiltration, 4, 0, 4, 0, 0),
        (AttackClass::ConditionalTimeBomb, 4, 0, 0, 4, 0),
        (AttackClass::Obfuscation, 5, 0, 1, 1, 3),
        (AttackClass::FalseFactCorruption, 4, 2, 0, 0, 2),
        (AttackClass::AntiFirewallBypass, 4, 3, 0, 0, 1),
    ];

    #[test]
    fn per_class_rates_with_the_demo_scanner_match_the_frozen_honest_tally() {
        let Some(config) = demo_scanner() else { return };
        let reports = hooked_class_reports(&config).expect("hooked corpus run");
        for (class, total, arbitration, hook, detect, unflagged) in EXPECTED {
            let report = reports
                .iter()
                .find(|r| r.class == class)
                .expect("class present");
            assert_eq!(
                *report,
                HookedClassReport {
                    class,
                    total,
                    blocked_by_arbitration: arbitration,
                    blocked_by_hook: hook,
                    detect_only: detect,
                    admitted_unflagged: unflagged,
                },
                "hooked per-class tally drifted for {}",
                class.label()
            );
        }
    }

    #[test]
    fn the_hook_never_shrinks_arbitration_and_the_demo_scanner_keeps_honest_misses() {
        let Some(config) = demo_scanner() else { return };
        let cases = super::run_adversarial_corpus_with_hook(&config).expect("hooked corpus run");
        // Every arbitration block from the plain corpus is still attributed to
        // arbitration — the hook adds a layer, never absorbs credit.
        let arbitration_blocks = super::run_adversarial_corpus()
            .into_iter()
            .filter(|case| case.firewall_blocked)
            .count();
        let attributed = cases
            .iter()
            .filter(|case| case.disposition == super::HookedDisposition::BlockedByArbitration)
            .count();
        assert_eq!(
            attributed, arbitration_blocks,
            "the hook run must attribute exactly the plain corpus's arbitration blocks"
        );
        // The demo scanner's deliberate misses stay missed: rot13 and translated
        // imperatives are admitted unflagged — the proof that regexes are not a defense.
        for miss in ["h_rot13_imperative", "h_translated_imperative"] {
            let case = cases
                .iter()
                .find(|case| case.name == miss)
                .expect("miss case present");
            assert_eq!(
                case.disposition,
                super::HookedDisposition::AdmittedUnflagged,
                "{miss} should sail past the demo regex scanner (it is not a defense)"
            );
        }
    }

    /// Not an assertion — prints the hooked per-class table when run with `--nocapture`,
    /// so the docs table can be regenerated from real behaviour.
    #[test]
    fn print_hooked_report() {
        let Some(config) = demo_scanner() else { return };
        println!(
            "\n(hook + demo scanner — the seam, not scanner efficacy)\n{}",
            hooked_summary_table(&config).expect("hooked corpus run")
        );
    }
}
