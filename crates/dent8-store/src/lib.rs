use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use dent8_core::{
    AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId, ClaimLifecycle, ClaimState,
    ClaimValue, EntityRef, EpistemicPolicy, Predicate, TransitionError, apply_event,
};

pub mod firewall;
pub mod memory;
pub mod registry;

pub use firewall::{arbitrate, arbitrate_events};
pub use memory::{InMemoryEventStore, IntegrityReceipt};
pub use registry::{
    PredicatePolicy, PredicateRegistry, Volatility, apply_policy_defaults, enforce_policy,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendReceipt {
    pub global_sequence: u64,
    pub event_id: ClaimEventId,
    pub event_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct EventFilter {
    pub claim_id: Option<ClaimId>,
    pub subject: Option<EntityRef>,
    pub predicate: Option<Predicate>,
    pub after_sequence: Option<u64>,
    pub limit: Option<u32>,
}

pub trait EventStore {
    /// Append a candidate event **through the firewall**. Every implementation MUST
    /// arbitrate the candidate against current state — call [`arbitrate`] — and reject
    /// inadmissible writes (`StoreError::Rejected` / `LaunderedAuthority` /
    /// `UnbackedSupersession`) *before* persisting. There is deliberately no
    /// un-arbitrated write path: a lower-authority override must not reach the log.
    fn append(&mut self, event: ClaimEvent) -> Result<AppendReceipt, StoreError>;
    fn load_claim_events(&self, claim_id: &ClaimId) -> Result<Vec<ClaimEvent>, StoreError>;
    fn scan_events(&self, filter: &EventFilter) -> Result<Vec<ClaimEvent>, StoreError>;
}

/// Fold an ordered claim-event stream into its current projected state. Strict: a
/// stream that does not start with `claim.asserted` surfaces the transition error.
pub fn replay_claim(events: &[ClaimEvent]) -> Result<Option<ClaimState>, ReplayError> {
    replay_claim_with_policy(events, &EpistemicPolicy::identity())
}

/// Re-fold a claim-event stream under an [`EpistemicPolicy`]. Non-admitted events are
/// skipped as if they never occurred; if the *asserting* event is filtered out the
/// claim is absent (`Ok(None)`) under this policy.
///
/// Freshness is intentionally *not* applied here — it is a separate read-time axis
/// ([`ClaimState::is_expired_at`]) so valid-time staleness is never conflated with the
/// event-driven lifecycle.
///
/// With [`EpistemicPolicy::identity`] this is identical to [`replay_claim`], so it is
/// a strict superset: callers can compare a baseline replay against a counterfactual
/// one with [`diff_states`].
pub fn replay_claim_with_policy(
    events: &[ClaimEvent],
    policy: &EpistemicPolicy,
) -> Result<Option<ClaimState>, ReplayError> {
    let refs: Vec<&ClaimEvent> = events.iter().collect();
    fold_claim(&refs, policy)
}

/// Fold a single claim stream (events for one `claim_id`, in order) under a policy.
fn fold_claim(
    events: &[&ClaimEvent],
    policy: &EpistemicPolicy,
) -> Result<Option<ClaimState>, ReplayError> {
    // True only when an asserting event exists but the policy filters it out. This
    // distinguishes "the assertion was distrusted" (claim absent) from "the stream is
    // malformed and never had an assertion" (let the strict error surface, exactly as
    // plain replay would). Under the identity policy nothing is filtered, so this is
    // always false and behaviour is unchanged.
    let assertion_filtered = events
        .iter()
        .any(|event| matches!(event.kind, ClaimEventKind::Asserted) && !policy.admits(event));

    let mut state: Option<ClaimState> = None;
    for &event in events {
        if !policy.admits(event) {
            continue;
        }
        if state.is_none() && assertion_filtered && !matches!(event.kind, ClaimEventKind::Asserted)
        {
            return Ok(None);
        }
        state = Some(apply_event(state.take(), event).map_err(ReplayError::Transition)?);
    }

    Ok(state)
}

/// A projection of every claim stream for one entity, folded independently and keyed
/// by `claim_id`. Built by [`replay_entity`] (or [`replay_entity_with_policy`]) from
/// the entity's events in global order. Unlike per-claim replay, this view enables
/// cross-stream checks such as [`EntityProjection::lineage_issues`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EntityProjection {
    pub claims: BTreeMap<ClaimId, ClaimState>,
}

impl EntityProjection {
    #[must_use]
    pub fn get(&self, claim_id: &ClaimId) -> Option<&ClaimState> {
        self.claims.get(claim_id)
    }

    /// The claims currently believed (lifecycle `Active` or `Contested`). Freshness
    /// (TTL) is a separate read-time axis ([`ClaimState::is_expired_at`]) and is not
    /// applied here.
    pub fn believed(&self) -> impl Iterator<Item = &ClaimState> {
        self.claims
            .values()
            .filter(|state| !state.lifecycle.is_terminal())
    }

    /// The claims currently in conflict (lifecycle `Contested`).
    pub fn contested(&self) -> impl Iterator<Item = &ClaimState> {
        self.claims
            .values()
            .filter(|state| state.lifecycle == ClaimLifecycle::Contested)
    }

    /// Cross-stream supersession-lineage problems:
    ///
    /// - [`LineageIssue::DanglingSupersession`] — superseded by a claim absent from
    ///   the entity;
    /// - [`LineageIssue::SupersededByInvalidated`] — superseded by a claim that has
    ///   itself been retracted or closed by a `claim.expired` event (an intact
    ///   `A -> B -> C` chain where `B` is merely `Superseded` is *not* an issue);
    /// - [`LineageIssue::SupersessionCycle`] — the claim lies on a supersession cycle
    ///   (including self-supersession), so no terminal believed successor exists.
    ///
    /// Out of scope here: read-time TTL staleness of a successor is *not* flagged
    /// (freshness is a separate axis — combine with [`ClaimState::is_expired_at`]), and
    /// contradiction edges are not checked, because a contradictor may legitimately
    /// live in another entity.
    #[must_use]
    pub fn lineage_issues(&self) -> Vec<LineageIssue> {
        let on_cycle = self.supersession_cycle_members();
        let mut issues = Vec::new();
        for state in self.claims.values() {
            if on_cycle.contains(&state.claim_id) {
                issues.push(LineageIssue::SupersessionCycle {
                    claim: state.claim_id.clone(),
                });
                continue;
            }
            let Some(target) = &state.superseded_by else {
                continue;
            };
            match self.claims.get(target) {
                None => issues.push(LineageIssue::DanglingSupersession {
                    claim: state.claim_id.clone(),
                    target: target.clone(),
                }),
                Some(t)
                    if matches!(
                        t.lifecycle,
                        ClaimLifecycle::Retracted | ClaimLifecycle::Expired
                    ) =>
                {
                    issues.push(LineageIssue::SupersededByInvalidated {
                        claim: state.claim_id.clone(),
                        target: target.clone(),
                        target_lifecycle: t.lifecycle,
                    });
                }
                Some(_) => {}
            }
        }
        issues
    }

    /// Supersessions that did not *earn* their replacement, judged against the
    /// replacing claim's actual state (not just the supersession event's stated
    /// authority). This is the entity-level entrenchment audit — defense-in-depth over
    /// the per-stream authority gate in `apply_event`, which can only trust the
    /// supersession event's claimed authority. Two cases:
    ///
    /// - [`UnearnedSupersession::AuthorityDowngrade`] — the replacing claim is actually
    ///   *lower* authority than the one it replaced (the event must have overstated its
    ///   authority to pass the per-stream gate);
    /// - [`UnearnedSupersession::WeakerCorroboration`] — at equal authority, the
    ///   replacing claim has *less authority-weighted* corroboration than the incumbent
    ///   (measured by [`ClaimState::corroboration_at_or_above`] at their shared
    ///   authority level, so a Sybil flood of low-authority sources cannot mask it).
    ///
    /// Semantics: this is a **current-state advisory**, not a stable at-supersession
    /// verdict. The incumbent's corroboration is frozen (the terminal guard blocks
    /// reinforcing a superseded claim), but the replacement's keeps accruing, so a
    /// `WeakerCorroboration` flag clears if the replacement later earns enough backing.
    /// Read it as "the replacement *still* has weaker backing than what it displaced."
    ///
    /// Scope: only supersessions whose target is present *in this entity* are judged (a
    /// dangling target is a [`LineageIssue`]; a target in another entity is not seen).
    /// Cyclic supersessions are skipped (handled by [`EntityProjection::lineage_issues`]).
    #[must_use]
    pub fn unearned_supersessions(&self) -> Vec<UnearnedSupersession> {
        let on_cycle = self.supersession_cycle_members();
        let mut out = Vec::new();
        for state in self.claims.values() {
            if on_cycle.contains(&state.claim_id) {
                continue;
            }
            let Some(target) = &state.superseded_by else {
                continue;
            };
            let Some(by) = self.claims.get(target) else {
                continue;
            };
            if by.authority.level < state.authority.level {
                out.push(UnearnedSupersession::AuthorityDowngrade {
                    superseded: state.claim_id.clone(),
                    by: target.clone(),
                    incumbent: state.authority.level,
                    challenger: by.authority.level,
                });
            } else if by.authority.level == state.authority.level {
                let level = state.authority.level;
                let incumbent = state.corroboration_at_or_above(level);
                let challenger = by.corroboration_at_or_above(level);
                if challenger < incumbent {
                    out.push(UnearnedSupersession::WeakerCorroboration {
                        superseded: state.claim_id.clone(),
                        by: target.clone(),
                        incumbent_corroboration: incumbent,
                        challenger_corroboration: challenger,
                    });
                }
            }
        }
        out
    }

    /// The claims lying on a supersession cycle (including self-supersession), found by
    /// following `superseded_by` edges within the entity. Single traversal per start
    /// with a visited index, so cycles cannot loop.
    fn supersession_cycle_members(&self) -> BTreeSet<ClaimId> {
        let mut on_cycle = BTreeSet::new();
        for start in self.claims.keys() {
            if on_cycle.contains(start) {
                continue;
            }
            let mut index: BTreeMap<ClaimId, usize> = BTreeMap::new();
            let mut path: Vec<ClaimId> = Vec::new();
            let mut node = start.clone();
            loop {
                if let Some(&first) = index.get(&node) {
                    for member in &path[first..] {
                        on_cycle.insert(member.clone());
                    }
                    break;
                }
                if on_cycle.contains(&node) {
                    break;
                }
                index.insert(node.clone(), path.len());
                path.push(node.clone());
                match self
                    .claims
                    .get(&node)
                    .and_then(|s| s.superseded_by.as_ref())
                {
                    Some(next) if self.claims.contains_key(next) => node = next.clone(),
                    _ => break,
                }
            }
        }
        on_cycle
    }
}

/// A cross-stream supersession-lineage defect found by [`EntityProjection::lineage_issues`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineageIssue {
    /// `claim` is superseded by `target`, but no such claim exists in the entity.
    DanglingSupersession { claim: ClaimId, target: ClaimId },
    /// `claim` is superseded by `target`, but `target` has itself been invalidated by a
    /// retraction or a `claim.expired` event, orphaning the lineage.
    SupersededByInvalidated {
        claim: ClaimId,
        target: ClaimId,
        target_lifecycle: ClaimLifecycle,
    },
    /// `claim` lies on a supersession cycle (`A -> A`, `A -> B -> A`, …), so the
    /// lineage never resolves to a believed successor.
    SupersessionCycle { claim: ClaimId },
}

/// A supersession that did not earn its replacement, found by
/// [`EntityProjection::unearned_supersessions`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnearnedSupersession {
    /// `superseded` was replaced by `by`, but `by` is actually lower authority — the
    /// supersession event must have overstated its authority to pass the per-stream gate.
    AuthorityDowngrade {
        superseded: ClaimId,
        by: ClaimId,
        incumbent: AuthorityLevel,
        challenger: AuthorityLevel,
    },
    /// `superseded` was replaced by `by` at equal authority, but `by` has weaker
    /// authority-weighted corroboration (distinct backers at or above the shared
    /// authority level) than the claim it replaced.
    WeakerCorroboration {
        superseded: ClaimId,
        by: ClaimId,
        incumbent_corroboration: usize,
        challenger_corroboration: usize,
    },
}

/// Replay every claim stream for one entity (events in global order) into an
/// [`EntityProjection`]. Strict, like [`replay_claim`].
pub fn replay_entity(events: &[ClaimEvent]) -> Result<EntityProjection, ReplayError> {
    replay_entity_with_policy(events, &EpistemicPolicy::identity())
}

/// Entity-level [`replay_entity`] under an [`EpistemicPolicy`]: each stream is folded
/// under the policy, so a distrusted source can make whole claims absent from the
/// entity view — the multi-claim counterfactual surface.
pub fn replay_entity_with_policy(
    events: &[ClaimEvent],
    policy: &EpistemicPolicy,
) -> Result<EntityProjection, ReplayError> {
    let mut streams: BTreeMap<ClaimId, Vec<&ClaimEvent>> = BTreeMap::new();
    for event in events {
        streams
            .entry(event.claim_id.clone())
            .or_default()
            .push(event);
    }

    let mut claims = BTreeMap::new();
    for (claim_id, stream) in streams {
        if let Some(state) = fold_claim(&stream, policy)? {
            claims.insert(claim_id, state);
        }
    }

    Ok(EntityProjection { claims })
}

/// The structural difference between a baseline projection and a counterfactual one,
/// computed by [`diff_states`]. Powers "what changes if I distrust source X / raise
/// the authority or confidence floor" queries over the same log.
///
/// The comparison covers the belief-relevant fields that can vary between two folds of
/// the *same* claim stream: lifecycle, value, supersession target, contradiction
/// edges, and evidence count. Fields invariant within a stream (claim id, subject,
/// predicate, authority, ttl) are not compared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateDiff {
    /// Both projections are absent, or equal on every compared field.
    Unchanged,
    /// The claim is absent in the baseline but present in the counterfactual.
    Appeared,
    /// The claim is present in the baseline but absent in the counterfactual (e.g. its
    /// asserting source was distrusted).
    Disappeared,
    /// The claim is present in both but differs. Each field is `Some((base, cf))` only
    /// when it changed.
    Changed {
        lifecycle: Option<(ClaimLifecycle, ClaimLifecycle)>,
        value: Option<(ClaimValue, ClaimValue)>,
        superseded_by: Option<(Option<ClaimId>, Option<ClaimId>)>,
        contradicted_by: Option<(Vec<ClaimId>, Vec<ClaimId>)>,
        evidence_count: Option<(usize, usize)>,
    },
}

/// Compare a baseline projection against a counterfactual one (both folded from the
/// same log, under different policies). The arguments read base-then-counterfactual.
#[must_use]
pub fn diff_states(base: Option<&ClaimState>, counterfactual: Option<&ClaimState>) -> StateDiff {
    match (base, counterfactual) {
        (None, None) => StateDiff::Unchanged,
        (None, Some(_)) => StateDiff::Appeared,
        (Some(_), None) => StateDiff::Disappeared,
        (Some(base), Some(cf)) => {
            let lifecycle =
                (base.lifecycle != cf.lifecycle).then_some((base.lifecycle, cf.lifecycle));
            let value = (base.value != cf.value).then(|| (base.value.clone(), cf.value.clone()));
            let superseded_by = (base.superseded_by != cf.superseded_by)
                .then(|| (base.superseded_by.clone(), cf.superseded_by.clone()));
            let contradicted_by = (base.contradicted_by != cf.contradicted_by)
                .then(|| (base.contradicted_by.clone(), cf.contradicted_by.clone()));
            let evidence_count = (base.evidence_count != cf.evidence_count)
                .then_some((base.evidence_count, cf.evidence_count));

            if lifecycle.is_none()
                && value.is_none()
                && superseded_by.is_none()
                && contradicted_by.is_none()
                && evidence_count.is_none()
            {
                StateDiff::Unchanged
            } else {
                StateDiff::Changed {
                    lifecycle,
                    value,
                    superseded_by,
                    contradicted_by,
                    evidence_count,
                }
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreError {
    Conflict(String),
    Unavailable(String),
    CorruptEvent(String),
    Canonicalization(String),
    /// The firewall rejected the write: the per-claim transition was inadmissible
    /// (validation, insufficient *stated* authority, canonical contradiction, terminal
    /// mutation, duplicate assertion).
    Rejected(TransitionError),
    /// The firewall rejected a supersession because the *replacing claim's actual*
    /// authority is below the incumbent's — i.e. an over-stated-authority supersession
    /// (authority laundering).
    LaunderedAuthority {
        incumbent: AuthorityLevel,
        challenger: AuthorityLevel,
    },
    /// The firewall rejected a supersession whose replacing claim does not exist in the
    /// store, so its authority cannot be verified.
    UnbackedSupersession(ClaimId),
    /// A registered predicate's policy rejected the write: its authority is below the
    /// predicate's floor.
    BelowAuthorityFloor {
        predicate: String,
        floor: AuthorityLevel,
        actual: AuthorityLevel,
    },
    /// A registered predicate's uniqueness policy rejected the write: another claim about
    /// this subject+predicate is already believed (supersede it instead of asserting).
    UniquenessViolation {
        predicate: String,
    },
    /// Replaying the existing claim stream failed.
    Replay(ReplayError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict(message) => write!(f, "store conflict: {message}"),
            Self::Unavailable(message) => write!(f, "store unavailable: {message}"),
            Self::CorruptEvent(message) => write!(f, "corrupt event: {message}"),
            Self::Canonicalization(message) => write!(f, "canonicalization failed: {message}"),
            Self::Rejected(error) => write!(f, "firewall rejected the write: {error}"),
            Self::LaunderedAuthority {
                incumbent,
                challenger,
            } => write!(
                f,
                "firewall rejected the write: supersession by a weaker claim \
                 (challenger {challenger:?} is below incumbent {incumbent:?})"
            ),
            Self::UnbackedSupersession(claim) => write!(
                f,
                "firewall rejected the write: superseding claim {claim} does not exist"
            ),
            Self::BelowAuthorityFloor {
                predicate,
                floor,
                actual,
            } => write!(
                f,
                "policy rejected the write: {predicate} requires authority {floor:?}, got {actual:?}"
            ),
            Self::UniquenessViolation { predicate } => write!(
                f,
                "policy rejected the write: {predicate} already has a believed claim (supersede it)"
            ),
            Self::Replay(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for StoreError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayError {
    Transition(dent8_core::TransitionError),
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transition(error) => write!(f, "replay failed: {error}"),
        }
    }
}

impl std::error::Error for ReplayError {}

#[cfg(test)]
mod tests {
    use super::{
        LineageIssue, StateDiff, UnearnedSupersession, diff_states, replay_claim,
        replay_claim_with_policy, replay_entity, replay_entity_with_policy,
    };
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
        ClaimLifecycle, ClaimValue, Confidence, EntityRef, EpistemicPolicy, Evidence, EvidenceId,
        EvidenceKind, Predicate, Provenance, RetractionReason, SourceId, SupersessionReason,
        TimestampMillis, Ttl,
    };

    #[allow(clippy::too_many_arguments)]
    fn ev(
        event_id: &str,
        kind: ClaimEventKind,
        value: Option<ClaimValue>,
        source: &str,
        authority: AuthorityLevel,
        confidence_millis: u16,
        ttl: Ttl,
        valid_from: Option<TimestampMillis>,
    ) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).expect("event id"),
            claim_id: ClaimId::new("claim:1").expect("claim id"),
            kind,
            subject: EntityRef::new("repo", "dent8").expect("entity"),
            predicate: Predicate::new("uses_database").expect("predicate"),
            value,
            confidence: Confidence::from_millis(confidence_millis).expect("confidence"),
            authority: Authority {
                level: authority,
                issuer: None,
                scope: None,
            },
            ttl,
            provenance: Provenance {
                source: SourceId::new(source).expect("source"),
                actor: ActorId::new("actor:test").expect("actor"),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(1),
            },
            evidence: vec![Evidence {
                id: EvidenceId::new("evidence:1").expect("evidence id"),
                kind: EvidenceKind::UserStatement,
                locator: "x".to_string(),
                digest: None,
                summary: None,
            }],
            observed_at: None,
            valid_from,
        }
    }

    fn assert_from(event_id: &str, source: &str, authority: AuthorityLevel) -> ClaimEvent {
        ev(
            event_id,
            ClaimEventKind::Asserted,
            Some(ClaimValue::Text("postgres".to_string())),
            source,
            authority,
            900,
            Ttl::Never,
            None,
        )
    }

    fn supersede_from(event_id: &str, source: &str, authority: AuthorityLevel) -> ClaimEvent {
        ev(
            event_id,
            ClaimEventKind::Superseded {
                by: ClaimId::new("claim:2").expect("claim id"),
                reason: SupersessionReason::NewerObservation,
            },
            None,
            source,
            authority,
            900,
            Ttl::Never,
            None,
        )
    }

    fn contradict_from(event_id: &str, by: &str, source: &str) -> ClaimEvent {
        ev(
            event_id,
            ClaimEventKind::Contradicted {
                by: ClaimId::new(by).expect("claim id"),
                basis: dent8_core::ContradictionBasis::SamePredicateDifferentValue,
            },
            None,
            source,
            AuthorityLevel::High,
            900,
            Ttl::Never,
            None,
        )
    }

    fn distrust(source: &str) -> EpistemicPolicy {
        let mut policy = EpistemicPolicy::identity();
        policy
            .distrusted_sources
            .insert(SourceId::new(source).expect("source"));
        policy
    }

    #[test]
    fn identity_policy_matches_plain_replay() {
        let events = [
            assert_from("event:1", "source:owner", AuthorityLevel::High),
            supersede_from("event:2", "source:owner", AuthorityLevel::High),
        ];

        let plain = replay_claim(&events).expect("replay");
        let policied =
            replay_claim_with_policy(&events, &EpistemicPolicy::identity()).expect("replay");

        assert_eq!(plain, policied);
        assert_eq!(plain.expect("state").lifecycle, ClaimLifecycle::Superseded);
    }

    #[test]
    fn distrusting_the_superseding_source_keeps_the_claim_active() {
        let events = [
            assert_from("event:1", "source:owner", AuthorityLevel::High),
            supersede_from("event:2", "source:web-scrape", AuthorityLevel::High),
        ];

        let base = replay_claim(&events).expect("replay");
        let counterfactual = replay_claim_with_policy(&events, &distrust("source:web-scrape"))
            .expect("counterfactual replay");

        assert_eq!(
            base.as_ref().expect("base").lifecycle,
            ClaimLifecycle::Superseded
        );
        assert_eq!(
            counterfactual.as_ref().expect("cf").lifecycle,
            ClaimLifecycle::Active,
        );
        assert_eq!(
            diff_states(base.as_ref(), counterfactual.as_ref()),
            StateDiff::Changed {
                lifecycle: Some((ClaimLifecycle::Superseded, ClaimLifecycle::Active)),
                value: None,
                superseded_by: Some((Some(ClaimId::new("claim:2").unwrap()), None)),
                contradicted_by: None,
                evidence_count: None,
            }
        );
    }

    #[test]
    fn distrusting_the_asserting_source_makes_the_claim_disappear() {
        let events = [
            assert_from("event:1", "source:web-scrape", AuthorityLevel::High),
            supersede_from("event:2", "source:owner", AuthorityLevel::High),
        ];

        let base = replay_claim(&events).expect("replay");
        let counterfactual = replay_claim_with_policy(&events, &distrust("source:web-scrape"))
            .expect("counterfactual replay");

        assert!(base.is_some());
        assert!(counterfactual.is_none());
        assert_eq!(
            diff_states(base.as_ref(), counterfactual.as_ref()),
            StateDiff::Disappeared,
        );
    }

    #[test]
    fn raising_the_authority_floor_filters_a_low_authority_assertion() {
        let events = [assert_from("event:1", "source:owner", AuthorityLevel::Low)];

        let policy = EpistemicPolicy {
            authority_floor: AuthorityLevel::High,
            ..EpistemicPolicy::identity()
        };

        assert!(replay_claim(&events).expect("replay").is_some());
        assert!(
            replay_claim_with_policy(&events, &policy)
                .expect("policied replay")
                .is_none()
        );
    }

    #[test]
    fn raising_the_confidence_floor_filters_a_low_confidence_assertion() {
        let events = [ev(
            "event:1",
            ClaimEventKind::Asserted,
            Some(ClaimValue::Text("postgres".to_string())),
            "source:owner",
            AuthorityLevel::High,
            100,
            Ttl::Never,
            None,
        )];

        let policy = EpistemicPolicy {
            confidence_floor: Confidence::from_millis(500).expect("confidence"),
            ..EpistemicPolicy::identity()
        };

        assert!(replay_claim(&events).expect("replay").is_some());
        assert!(
            replay_claim_with_policy(&events, &policy)
                .expect("policied replay")
                .is_none()
        );
    }

    #[test]
    fn freshness_is_a_read_time_predicate_separate_from_lifecycle() {
        let events = [ev(
            "event:1",
            ClaimEventKind::Asserted,
            Some(ClaimValue::Text("postgres".to_string())),
            "source:owner",
            AuthorityLevel::High,
            900,
            Ttl::ExpiresAt(TimestampMillis::from_unix_millis(100)),
            Some(TimestampMillis::from_unix_millis(10)),
        )];

        let state = replay_claim(&events).expect("replay").expect("state");

        // Lifecycle is untouched by freshness — it stays Active (event-driven only).
        assert_eq!(state.lifecycle, ClaimLifecycle::Active);
        // Freshness is a separate read-time verdict against a valid-time clock.
        assert!(!state.is_expired_at(TimestampMillis::from_unix_millis(50)));
        assert!(state.is_expired_at(TimestampMillis::from_unix_millis(200)));
    }

    #[test]
    fn distrusting_a_contradictor_drops_the_contradiction_edge() {
        let events = [
            assert_from("event:1", "source:owner", AuthorityLevel::High),
            contradict_from("event:2", "claim:2", "source:rumor"),
            contradict_from("event:3", "claim:3", "source:owner"),
        ];

        let base = replay_claim(&events).expect("replay");
        let counterfactual =
            replay_claim_with_policy(&events, &distrust("source:rumor")).expect("counterfactual");

        // Both stay Contested, so only the contradiction-edge delta distinguishes them
        // — the diff must surface it (regression guard for diff completeness).
        assert_eq!(
            diff_states(base.as_ref(), counterfactual.as_ref()),
            StateDiff::Changed {
                lifecycle: None,
                value: None,
                superseded_by: None,
                contradicted_by: Some((
                    vec![
                        ClaimId::new("claim:2").unwrap(),
                        ClaimId::new("claim:3").unwrap()
                    ],
                    vec![ClaimId::new("claim:3").unwrap()],
                )),
                evidence_count: None,
            }
        );
    }

    #[test]
    fn diff_of_identical_projections_is_unchanged() {
        let events = [assert_from("event:1", "source:owner", AuthorityLevel::High)];
        let a = replay_claim(&events).expect("replay");
        let b = replay_claim_with_policy(&events, &EpistemicPolicy::identity()).expect("replay");
        assert_eq!(diff_states(a.as_ref(), b.as_ref()), StateDiff::Unchanged);
    }

    // ---- entity-level replay & cross-stream lineage ----

    fn with_claim(mut event: ClaimEvent, claim_id: &str) -> ClaimEvent {
        event.claim_id = ClaimId::new(claim_id).expect("claim id");
        event
    }

    fn assert_in(event_id: &str, claim_id: &str, source: &str) -> ClaimEvent {
        with_claim(
            assert_from(event_id, source, AuthorityLevel::High),
            claim_id,
        )
    }

    fn supersede_in(event_id: &str, claim_id: &str, by: &str, source: &str) -> ClaimEvent {
        with_claim(
            ev(
                event_id,
                ClaimEventKind::Superseded {
                    by: ClaimId::new(by).expect("claim id"),
                    reason: SupersessionReason::NewerObservation,
                },
                None,
                source,
                AuthorityLevel::High,
                900,
                Ttl::Never,
                None,
            ),
            claim_id,
        )
    }

    fn retract_in(event_id: &str, claim_id: &str) -> ClaimEvent {
        with_claim(
            ev(
                event_id,
                ClaimEventKind::Retracted {
                    reason: RetractionReason::SourceInvalidated,
                },
                None,
                "source:owner",
                AuthorityLevel::High,
                900,
                Ttl::Never,
                None,
            ),
            claim_id,
        )
    }

    fn claim(id: &str) -> ClaimId {
        ClaimId::new(id).expect("claim id")
    }

    fn assert_in_auth(
        event_id: &str,
        claim_id: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        with_claim(assert_from(event_id, source, authority), claim_id)
    }

    fn reinforce_in(event_id: &str, claim_id: &str, source: &str) -> ClaimEvent {
        reinforce_in_auth(event_id, claim_id, source, AuthorityLevel::High)
    }

    fn reinforce_in_auth(
        event_id: &str,
        claim_id: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        with_claim(
            ev(
                event_id,
                ClaimEventKind::Reinforced {
                    by: ClaimId::new("claim:evidence").expect("claim id"),
                },
                None,
                source,
                authority,
                900,
                Ttl::Never,
                None,
            ),
            claim_id,
        )
    }

    #[test]
    fn replay_entity_folds_each_stream_independently() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            assert_in("event:2", "claim:B", "source:owner"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert_eq!(entity.claims.len(), 2);
        assert_eq!(
            entity.get(&claim("claim:A")).unwrap().lifecycle,
            ClaimLifecycle::Active
        );
        assert_eq!(entity.believed().count(), 2);
        assert!(entity.lineage_issues().is_empty());
    }

    #[test]
    fn intact_supersession_lineage_has_no_issues() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            assert_in("event:2", "claim:B", "source:owner"),
            supersede_in("event:3", "claim:A", "claim:B", "source:owner"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert_eq!(
            entity.get(&claim("claim:A")).unwrap().lifecycle,
            ClaimLifecycle::Superseded
        );
        assert_eq!(
            entity.get(&claim("claim:B")).unwrap().lifecycle,
            ClaimLifecycle::Active
        );
        assert!(entity.lineage_issues().is_empty());
    }

    #[test]
    fn supersession_to_a_missing_claim_is_dangling() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            supersede_in("event:2", "claim:A", "claim:ghost", "source:owner"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert_eq!(
            entity.lineage_issues(),
            vec![LineageIssue::DanglingSupersession {
                claim: claim("claim:A"),
                target: claim("claim:ghost"),
            }]
        );
    }

    #[test]
    fn supersession_by_a_retracted_claim_orphans_the_lineage() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            assert_in("event:2", "claim:B", "source:owner"),
            supersede_in("event:3", "claim:A", "claim:B", "source:owner"),
            retract_in("event:4", "claim:B"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert_eq!(
            entity.lineage_issues(),
            vec![LineageIssue::SupersededByInvalidated {
                claim: claim("claim:A"),
                target: claim("claim:B"),
                target_lifecycle: ClaimLifecycle::Retracted,
            }]
        );
    }

    #[test]
    fn entity_level_distrust_drops_a_whole_stream() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            assert_in("event:2", "claim:B", "source:web-scrape"),
        ];

        let entity = replay_entity_with_policy(&events, &distrust("source:web-scrape"))
            .expect("entity replay");

        assert_eq!(entity.claims.len(), 1);
        assert!(entity.get(&claim("claim:A")).is_some());
        assert!(entity.get(&claim("claim:B")).is_none());
    }

    #[test]
    fn self_supersession_is_flagged_as_a_cycle() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            supersede_in("event:2", "claim:A", "claim:A", "source:owner"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert_eq!(
            entity.lineage_issues(),
            vec![LineageIssue::SupersessionCycle {
                claim: claim("claim:A"),
            }]
        );
    }

    #[test]
    fn a_two_claim_supersession_cycle_is_flagged() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            assert_in("event:2", "claim:B", "source:owner"),
            supersede_in("event:3", "claim:A", "claim:B", "source:owner"),
            supersede_in("event:4", "claim:B", "claim:A", "source:owner"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert_eq!(
            entity.lineage_issues(),
            vec![
                LineageIssue::SupersessionCycle {
                    claim: claim("claim:A"),
                },
                LineageIssue::SupersessionCycle {
                    claim: claim("claim:B"),
                },
            ]
        );
    }

    #[test]
    fn an_intact_three_claim_chain_has_no_issues() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            assert_in("event:2", "claim:B", "source:owner"),
            assert_in("event:3", "claim:C", "source:owner"),
            supersede_in("event:4", "claim:A", "claim:B", "source:owner"),
            supersede_in("event:5", "claim:B", "claim:C", "source:owner"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert!(entity.lineage_issues().is_empty());
        assert_eq!(entity.believed().count(), 1); // only C
        assert_eq!(
            entity.get(&claim("claim:C")).unwrap().lifecycle,
            ClaimLifecycle::Active
        );
    }

    // ---- earned entrenchment (rank 3) ----

    #[test]
    fn corroboration_counts_distinct_backing_sources() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            reinforce_in("event:2", "claim:A", "source:peer"),
            reinforce_in("event:3", "claim:A", "source:owner"), // same source: no new corroboration
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert_eq!(entity.get(&claim("claim:A")).unwrap().corroboration(), 2);
    }

    #[test]
    fn a_weaker_corroborated_supersession_is_unearned() {
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            reinforce_in("event:2", "claim:A", "source:peer"), // A corroboration = 2
            assert_in("event:3", "claim:B", "source:rumor"),   // B corroboration = 1
            supersede_in("event:4", "claim:A", "claim:B", "source:rumor"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        // Lineage is intact (B exists, active); the weakness is only visible to the
        // entrenchment audit.
        assert!(entity.lineage_issues().is_empty());
        assert_eq!(
            entity.unearned_supersessions(),
            vec![UnearnedSupersession::WeakerCorroboration {
                superseded: claim("claim:A"),
                by: claim("claim:B"),
                incumbent_corroboration: 2,
                challenger_corroboration: 1,
            }]
        );
    }

    #[test]
    fn an_authority_downgrade_supersession_is_unearned() {
        // The supersession event overstates its authority (High) to clear the
        // per-stream gate, but the replacing claim B is actually Low authority.
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            assert_in_auth("event:2", "claim:B", "source:rumor", AuthorityLevel::Low),
            supersede_in("event:3", "claim:A", "claim:B", "source:rumor"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert_eq!(
            entity.unearned_supersessions(),
            vec![UnearnedSupersession::AuthorityDowngrade {
                superseded: claim("claim:A"),
                by: claim("claim:B"),
                incumbent: AuthorityLevel::High,
                challenger: AuthorityLevel::Low,
            }]
        );
    }

    #[test]
    fn a_sybil_flood_of_low_authority_sources_does_not_earn_a_supersession() {
        // A is backed by two High-authority sources; the attacker's B has one High
        // asserter plus three Low-authority "sources" (a Sybil flood). B's *raw*
        // corroboration (4) exceeds A's (2), but at the shared High authority level B
        // has only 1 qualified backer vs A's 2 — so the supersession is still unearned.
        let events = [
            assert_in("event:1", "claim:A", "source:owner"),
            reinforce_in("event:2", "claim:A", "source:peer"),
            assert_in("event:3", "claim:B", "source:attacker"),
            reinforce_in_auth("event:4", "claim:B", "source:sybil-1", AuthorityLevel::Low),
            reinforce_in_auth("event:5", "claim:B", "source:sybil-2", AuthorityLevel::Low),
            reinforce_in_auth("event:6", "claim:B", "source:sybil-3", AuthorityLevel::Low),
            supersede_in("event:7", "claim:A", "claim:B", "source:attacker"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert_eq!(entity.get(&claim("claim:B")).unwrap().corroboration(), 4); // raw, inflated
        assert_eq!(
            entity.unearned_supersessions(),
            vec![UnearnedSupersession::WeakerCorroboration {
                superseded: claim("claim:A"),
                by: claim("claim:B"),
                incumbent_corroboration: 2,  // High-authority backers of A
                challenger_corroboration: 1, // High-authority backers of B (Sybils don't count)
            }]
        );
    }

    #[test]
    fn a_higher_authority_supersession_is_earned() {
        let events = [
            assert_in_auth("event:1", "claim:A", "source:owner", AuthorityLevel::Medium),
            assert_in_auth(
                "event:2",
                "claim:B",
                "source:owner",
                AuthorityLevel::Canonical,
            ),
            supersede_in("event:3", "claim:A", "claim:B", "source:owner"),
        ];

        let entity = replay_entity(&events).expect("entity replay");

        assert!(entity.unearned_supersessions().is_empty());
    }
}
