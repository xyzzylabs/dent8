//! Stateful property-based tests for the `apply_event` fold — the heart of the firewall.
//!
//! A random *coherent* event stream (all events on one fact) is folded through the real
//! `apply_event`, and every step is checked against an **independent reference model** that
//! re-implements the lifecycle algebra in a deliberately simpler shape. The model tracks
//! nearly the whole `FactState` — lifecycle, authority, value, `created_at`,
//! `corroborating_sources`, `contradicted_by`, `superseded_by`, `evidence_count` — so the
//! comparison is a near-complete state-machine equivalence, not just a lifecycle check.
//!
//! Beyond model agreement (accept/reject + reject *reason* + the full projected state), the
//! harness asserts the structural invariants that hold for ANY stream:
//!
//! - **Terminal absorption / non-resurrection** — once `Superseded`/`Expired`/`Retracted`,
//!   the lifecycle never returns to a live state (also pinned deterministically by a
//!   forced-terminal property).
//! - **Value immutability** — no event ever changes the asserted value.
//! - **`created_at` stability / `updated_at` tracking.**
//! - **Replay determinism** — folding the same events twice yields an identical state.
//! - **Fact isolation** — an event for a different fact id / subject / predicate is rejected.
//!
//! Two forced-prefix properties guarantee the rarer deep paths every case: resolution *out
//! of* `Contested`, and absorption of every op kind by a terminal state.

use std::collections::BTreeMap;

use dent8_core::{
    ActorId, Authority, AuthorityLevel, Confidence, ContradictionBasis, Evidence, EvidenceId,
    EvidenceKind, ExpirationReason, FactEvent, FactEventId, FactEventKind, FactId, FactLifecycle,
    FactState, FactValue, Predicate, Provenance, RetractionReason, SourceId, Subject,
    SupersessionReason, TimestampMillis, TransitionError, Ttl, apply_event,
};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;

/// A generated operation — an event kind plus only the data the lifecycle algebra reads.
/// `source` (small index) drives corroboration; `by` (small index) drives the contradiction
/// / supersession edges.
#[derive(Clone, Debug)]
enum Op {
    Assert {
        value: FactValue,
        authority: AuthorityLevel,
        source: u8,
    },
    Reinforce {
        value: Option<FactValue>,
        authority: AuthorityLevel,
        source: u8,
    },
    Contradict {
        authority: AuthorityLevel,
        by: u8,
    },
    Supersede {
        authority: AuthorityLevel,
        by: u8,
    },
    Expire {
        authority: AuthorityLevel,
    },
    Retract {
        authority: AuthorityLevel,
    },
    Retrieve,
    UseInDecision,
}

impl Op {
    /// The event authority. For kinds the algebra never gates on, the value is irrelevant.
    fn authority(&self) -> AuthorityLevel {
        match self {
            Op::Assert { authority, .. }
            | Op::Reinforce { authority, .. }
            | Op::Contradict { authority, .. }
            | Op::Supersede { authority, .. }
            | Op::Expire { authority }
            | Op::Retract { authority } => *authority,
            Op::Retrieve | Op::UseInDecision => AuthorityLevel::Medium,
        }
    }

    fn source(&self) -> u8 {
        match self {
            Op::Assert { source, .. } | Op::Reinforce { source, .. } => *source,
            _ => 0,
        }
    }

    fn by(&self) -> u8 {
        match self {
            Op::Contradict { by, .. } | Op::Supersede { by, .. } => *by,
            _ => 0,
        }
    }
}

fn source_id(index: u8) -> SourceId {
    SourceId::new(format!("source:{index}")).expect("source id")
}

fn by_fact(index: u8) -> FactId {
    FactId::new(format!("by:{index}")).expect("fact id")
}

/// The reason the model expects a step to be rejected. `Other` is never produced by the
/// model, so an unexpected real error (a stray `InvalidEvent`/`FactIdMismatch`) fails the
/// equality loudly.
#[derive(Clone, Debug, Eq, PartialEq)]
enum Reject {
    MissingInitialAssertion,
    DuplicateAssertion,
    TerminalMutation,
    InsufficientAuthority,
    CanonicalContradiction,
    ReinforcementValueMismatch,
    Other,
}

fn classify(error: &TransitionError) -> Reject {
    match error {
        TransitionError::MissingInitialAssertion => Reject::MissingInitialAssertion,
        TransitionError::DuplicateAssertion => Reject::DuplicateAssertion,
        TransitionError::TerminalStateMutation(_) => Reject::TerminalMutation,
        TransitionError::InsufficientAuthority { .. } => Reject::InsufficientAuthority,
        TransitionError::CanonicalContradiction => Reject::CanonicalContradiction,
        TransitionError::ReinforcementValueMismatch => Reject::ReinforcementValueMismatch,
        _ => Reject::Other,
    }
}

/// The independent reference model — nearly the whole projected `FactState`.
#[derive(Clone, Debug)]
struct Model {
    lifecycle: FactLifecycle,
    authority: AuthorityLevel,
    value: FactValue,
    created_at: TimestampMillis,
    corroborating: BTreeMap<SourceId, AuthorityLevel>,
    contradicted_by: Vec<FactId>,
    superseded_by: Option<FactId>,
    evidence_count: usize,
}

/// Predict the outcome of `op` (recorded at `at`) against the current model state, mirroring
/// the documented rules in a flatter shape than `apply_event`.
fn model_apply(state: Option<&Model>, op: &Op, at: TimestampMillis) -> Result<Model, Reject> {
    let Some(model) = state else {
        // No fact yet: only an assertion starts a stream.
        return match op {
            Op::Assert {
                value,
                authority,
                source,
            } => Ok(Model {
                lifecycle: FactLifecycle::Active,
                authority: *authority,
                value: value.clone(),
                created_at: at,
                corroborating: BTreeMap::from([(source_id(*source), *authority)]),
                contradicted_by: Vec::new(),
                superseded_by: None,
                evidence_count: 1,
            }),
            _ => Err(Reject::MissingInitialAssertion),
        };
    };

    let is_noop = matches!(op, Op::Retrieve | Op::UseInDecision);
    if model.lifecycle.is_terminal() && !is_noop {
        return Err(Reject::TerminalMutation);
    }

    let mut next = model.clone();
    match op {
        Op::Assert { .. } => return Err(Reject::DuplicateAssertion),
        Op::Reinforce {
            value,
            authority,
            source,
        } => {
            if let Some(value) = value
                && value != &model.value
            {
                return Err(Reject::ReinforcementValueMismatch);
            }
            next.corroborating
                .entry(source_id(*source))
                .and_modify(|level| *level = (*level).max(*authority))
                .or_insert(*authority);
            next.evidence_count += 1;
        }
        Op::Contradict { by, .. } => {
            if model.authority == AuthorityLevel::Canonical {
                return Err(Reject::CanonicalContradiction);
            }
            next.lifecycle = FactLifecycle::Contested;
            let by = by_fact(*by);
            if !next.contradicted_by.contains(&by) {
                next.contradicted_by.push(by);
            }
        }
        Op::Supersede { authority, by } => {
            if *authority < model.authority {
                return Err(Reject::InsufficientAuthority);
            }
            next.lifecycle = FactLifecycle::Superseded;
            next.superseded_by = Some(by_fact(*by));
        }
        Op::Expire { authority } => {
            if *authority < model.authority {
                return Err(Reject::InsufficientAuthority);
            }
            next.lifecycle = FactLifecycle::Expired;
        }
        Op::Retract { authority } => {
            if *authority < model.authority {
                return Err(Reject::InsufficientAuthority);
            }
            next.lifecycle = FactLifecycle::Retracted;
        }
        Op::Retrieve | Op::UseInDecision => {}
    }
    Ok(next)
}

struct Base {
    fact: FactId,
    subject: Subject,
    predicate: Predicate,
}

fn base() -> Base {
    Base {
        fact: FactId::new("fact:subject").expect("fact id"),
        subject: Subject::new("repo", "dent8").expect("subject"),
        predicate: Predicate::new("database").expect("predicate"),
    }
}

/// Build a structurally-valid `FactEvent` for `op` at position `index` on the shared fact.
fn build_event(base: &Base, index: usize, op: &Op) -> FactEvent {
    let (kind, value) = match op {
        Op::Assert { value, .. } => (FactEventKind::Asserted, Some(value.clone())),
        Op::Reinforce { value, .. } => {
            (FactEventKind::Reinforced { by: by_fact(0) }, value.clone())
        }
        Op::Contradict { .. } => (
            FactEventKind::Contradicted {
                by: by_fact(op.by()),
                basis: ContradictionBasis::SamePredicateDifferentValue,
            },
            None,
        ),
        Op::Supersede { .. } => (
            FactEventKind::Superseded {
                by: by_fact(op.by()),
                reason: SupersessionReason::NewerObservation,
            },
            None,
        ),
        Op::Expire { .. } => (
            FactEventKind::Expired {
                reason: ExpirationReason::TtlElapsed,
            },
            None,
        ),
        Op::Retract { .. } => (
            FactEventKind::Retracted {
                reason: RetractionReason::UserDeleted,
            },
            None,
        ),
        Op::Retrieve => (
            FactEventKind::Retrieved {
                purpose: "audit".to_string(),
            },
            None,
        ),
        Op::UseInDecision => (
            FactEventKind::UsedInDecision {
                decision_id: "decision".to_string(),
            },
            None,
        ),
    };
    FactEvent {
        event_id: FactEventId::new(format!("event:{index}")).expect("event id"),
        fact_id: base.fact.clone(),
        kind,
        subject: base.subject.clone(),
        predicate: base.predicate.clone(),
        value,
        confidence: Confidence::from_millis(900).expect("confidence"),
        authority: Authority {
            level: op.authority(),
            issuer: None,
            scope: None,
        },
        ttl: Ttl::Never,
        provenance: Provenance {
            source: source_id(op.source()),
            actor: ActorId::new("actor:test").expect("actor"),
            tool: None,
            run_id: None,
            input_digest: None,
            // Monotonic, so the applied event's stamp is `index`.
            recorded_at: TimestampMillis::from_unix_millis(i64::try_from(index).expect("index")),
            attestation: None,
        },
        evidence: vec![Evidence {
            id: EvidenceId::new("evidence:1").expect("evidence id"),
            kind: EvidenceKind::UserStatement,
            locator: "x".to_string(),
            digest: None,
            summary: None,
        }],
        observed_at: None,
        valid_from: None,
        valid_to: None,
    }
}

/// Fold an event stream through `apply_event`, advancing state only on accepted events.
fn fold(events: &[FactEvent]) -> Option<FactState> {
    let mut state: Option<FactState> = None;
    for event in events {
        if let Ok(next) = apply_event(state.clone(), event) {
            state = Some(next);
        }
    }
    state
}

/// Fold `ops` through the real `apply_event` and the reference model in lockstep, asserting
/// agreement and the structural invariants at every step. Shared by the random and the
/// forced-prefix properties.
fn check_stream(ops: &[Op]) -> Result<(), TestCaseError> {
    let base = base();
    let mut real: Option<FactState> = None;
    let mut model: Option<Model> = None;
    let mut was_terminal = false;

    for (index, op) in ops.iter().enumerate() {
        let event = build_event(&base, index, op);
        let at = event.provenance.recorded_at;
        let real_next = apply_event(real.clone(), &event);
        let model_next = model_apply(model.as_ref(), op, at);

        prop_assert_eq!(
            real_next.is_ok(),
            model_next.is_ok(),
            "accept/reject disagree on {:?}: real={:?} model={:?}",
            op,
            real_next,
            model_next
        );

        match (real_next, model_next) {
            (Ok(real_state), Ok(model_state)) => {
                prop_assert_eq!(real_state.lifecycle, model_state.lifecycle);
                prop_assert_eq!(&real_state.value, &model_state.value);
                prop_assert_eq!(real_state.authority.level, model_state.authority);
                prop_assert_eq!(real_state.created_at, model_state.created_at);
                prop_assert_eq!(real_state.updated_at, at);
                prop_assert_eq!(
                    &real_state.corroborating_sources,
                    &model_state.corroborating
                );
                prop_assert_eq!(&real_state.contradicted_by, &model_state.contradicted_by);
                prop_assert_eq!(&real_state.superseded_by, &model_state.superseded_by);
                prop_assert_eq!(real_state.evidence_count, model_state.evidence_count);
                // Non-resurrection: once terminal, the lifecycle stays terminal.
                if was_terminal {
                    prop_assert!(real_state.lifecycle.is_terminal());
                }
                was_terminal = real_state.lifecycle.is_terminal();
                real = Some(real_state);
                model = Some(model_state);
            }
            (Err(real_error), Err(model_reject)) => {
                prop_assert_eq!(classify(&real_error), model_reject);
                // A rejected event advances neither real nor model state.
            }
            (real_next, model_next) => {
                return Err(TestCaseError::fail(format!(
                    "outcome mismatch on {op:?}: real={real_next:?} model={model_next:?}"
                )));
            }
        }
    }
    Ok(())
}

fn arb_level() -> impl Strategy<Value = AuthorityLevel> {
    prop_oneof![
        Just(AuthorityLevel::Unknown),
        Just(AuthorityLevel::Low),
        Just(AuthorityLevel::Medium),
        Just(AuthorityLevel::High),
        Just(AuthorityLevel::Canonical),
    ]
}

/// A small set of distinct values, so reinforcement value-match vs mismatch both occur.
fn arb_small_value() -> impl Strategy<Value = FactValue> {
    prop_oneof![
        Just(FactValue::Text("alpha".to_string())),
        Just(FactValue::Text("beta".to_string())),
        Just(FactValue::Redacted),
    ]
}

/// Weighted toward the dissent/removal ops so `Contested` and the terminal states are
/// reached densely (the no-op and `Expire` arms are also covered deterministically by the
/// forced-prefix properties below).
fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => (arb_small_value(), arb_level(), 0u8..3)
            .prop_map(|(value, authority, source)| Op::Assert { value, authority, source }),
        2 => (proptest::option::of(arb_small_value()), arb_level(), 0u8..3)
            .prop_map(|(value, authority, source)| Op::Reinforce { value, authority, source }),
        3 => (arb_level(), 0u8..2).prop_map(|(authority, by)| Op::Contradict { authority, by }),
        2 => (arb_level(), 0u8..2).prop_map(|(authority, by)| Op::Supersede { authority, by }),
        1 => arb_level().prop_map(|authority| Op::Expire { authority }),
        2 => arb_level().prop_map(|authority| Op::Retract { authority }),
        1 => Just(Op::Retrieve),
        1 => Just(Op::UseInDecision),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(384))]

    /// The real fold and the independent model agree at every step on accept/reject, the
    /// reject reason, and the full projected state — and the structural invariants hold.
    #[test]
    fn the_fold_matches_an_independent_lifecycle_model(ops in prop::collection::vec(arb_op(), 1..18)) {
        check_stream(&ops)?;

        // Replay determinism: folding the same stream twice yields an identical state.
        let base = base();
        let events: Vec<FactEvent> = ops
            .iter()
            .enumerate()
            .map(|(index, op)| build_event(&base, index, op))
            .collect();
        prop_assert_eq!(fold(&events), fold(&events));
    }

    /// A `Contested` fact is reached every case (forced `Assert(High)` + `Contradict`
    /// prefix), then a random tail exercises resolution *out of* `Contested` against the
    /// full model.
    #[test]
    fn a_contested_fact_still_obeys_the_model(tail in prop::collection::vec(arb_op(), 0..14)) {
        let mut ops = vec![
            Op::Assert { value: FactValue::Text("alpha".to_string()), authority: AuthorityLevel::High, source: 0 },
            Op::Contradict { authority: AuthorityLevel::Low, by: 0 },
        ];
        ops.extend(tail);
        check_stream(&ops)?;
    }

    /// Terminal absorption, deterministically: after a forced `Assert` + equal-authority
    /// `Expire`, EVERY
    /// op kind is correctly handled — retrieval/decision no-ops are accepted with the
    /// lifecycle frozen, everything else is rejected with `TerminalStateMutation`.
    #[test]
    fn terminal_states_absorb_all_mutations(tail in prop::collection::vec(arb_op(), 0..14)) {
        let base = base();
        let asserted = build_event(
            &base, 0,
            &Op::Assert { value: FactValue::Text("alpha".to_string()), authority: AuthorityLevel::High, source: 0 },
        );
        let expired = build_event(&base, 1, &Op::Expire { authority: AuthorityLevel::High });
        let mut state = apply_event(None, &asserted).expect("assert");
        state = apply_event(Some(state), &expired).expect("expire");
        prop_assert!(state.lifecycle.is_terminal());
        let frozen = state.clone();

        for (offset, op) in tail.iter().enumerate() {
            let event = build_event(&base, offset + 2, op);
            let result = apply_event(Some(state.clone()), &event);
            if matches!(op, Op::Retrieve | Op::UseInDecision) {
                let next = result.expect("a no-op is accepted in a terminal state");
                prop_assert_eq!(next.lifecycle, frozen.lifecycle);
                prop_assert_eq!(&next.value, &frozen.value);
                prop_assert_eq!(&next.superseded_by, &frozen.superseded_by);
                state = next;
            } else {
                prop_assert!(
                    matches!(result, Err(TransitionError::TerminalStateMutation(_))),
                    "a non-no-op {:?} must be rejected in a terminal state, got {:?}",
                    op, result
                );
            }
        }
    }

    /// Fact isolation: once a fact is live, an event bearing a different fact id, subject,
    /// or predicate is rejected (it can never perturb this fact's state).
    #[test]
    fn a_foreign_fact_id_or_shape_is_rejected(first in arb_level(), which in 0u8..3) {
        let base = base();
        let asserted = build_event(
            &base, 0,
            &Op::Assert { value: FactValue::Text("alpha".to_string()), authority: first, source: 0 },
        );
        let state = apply_event(None, &asserted).expect("initial assertion");

        let mut foreign = build_event(
            &base, 1,
            &Op::Reinforce { value: Some(FactValue::Text("alpha".to_string())), authority: first, source: 0 },
        );
        match which {
            0 => foreign.fact_id = FactId::new("fact:foreign").expect("fact id"),
            1 => foreign.subject = Subject::new("repo", "other").expect("subject"),
            _ => foreign.predicate = Predicate::new("other_predicate").expect("predicate"),
        }
        let result = apply_event(Some(state), &foreign);
        prop_assert!(matches!(
            result,
            Err(TransitionError::FactIdMismatch | TransitionError::FactShapeMismatch)
        ));
    }
}
