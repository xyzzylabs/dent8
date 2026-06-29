use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ids::{ClaimEventId, ClaimId, SourceId, TimestampMillis};
use crate::model::{
    Authority, AuthorityLevel, ClaimEvent, ClaimEventKind, ClaimValue, EntityRef, Predicate, Ttl,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ClaimLifecycle {
    Active,
    Contested,
    Superseded,
    Expired,
    Retracted,
}

impl ClaimLifecycle {
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Superseded | Self::Expired | Self::Retracted)
    }
}

/// The current projected state of a claim — the fold of its event stream. Serializable so
/// a backend may **materialize** it (cache it as a derived row) or transmit it; it remains a
/// pure projection of the log, never an independent source of truth.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimState {
    pub claim_id: ClaimId,
    pub subject: EntityRef,
    pub predicate: Predicate,
    pub value: ClaimValue,
    /// Entrenchment of the incumbent claim, captured at assertion. Drives
    /// authority-weighted supersession arbitration; see `docs/belief-revision.md`.
    pub authority: Authority,
    /// TTL captured at assertion, used by [`ClaimState::is_expired_at`] for
    /// read-time freshness evaluation.
    pub ttl: Ttl,
    /// Valid-time anchor for TTL freshness: `valid_from`, else `observed_at`, else
    /// the assertion's `recorded_at`.
    pub freshness_anchor: TimestampMillis,
    pub lifecycle: ClaimLifecycle,
    pub created_at: TimestampMillis,
    pub updated_at: TimestampMillis,
    pub last_event_id: ClaimEventId,
    pub superseded_by: Option<ClaimId>,
    pub contradicted_by: Vec<ClaimId>,
    pub evidence_count: usize,
    /// The distinct provenance sources that have *asserted or reinforced this exact
    /// value*, each mapped to the highest authority it backed at. This measures
    /// same-value corroboration only — surviving a contradiction or a rejected
    /// supersession is deliberately *not* counted here (that would require recording
    /// rejected attempts; see `docs/research/novelty.md` rank 3). The asserter is the
    /// first entry.
    pub corroborating_sources: BTreeMap<SourceId, AuthorityLevel>,
}

impl ClaimState {
    /// Raw earned-entrenchment degree: the number of distinct sources backing this
    /// value. **Sybil-inflatable** on its own (an attacker minting many sources raises
    /// it), so security decisions should use [`ClaimState::corroboration_at_or_above`]
    /// to count only sufficiently-authoritative backers.
    #[must_use]
    pub fn corroboration(&self) -> usize {
        self.corroborating_sources.len()
    }

    /// Authority-weighted corroboration: the number of distinct backing sources whose
    /// authority is at least `min`. This is the Sybil-resistant entrenchment signal —
    /// minting low-authority sources cannot raise the count measured at a higher floor.
    #[must_use]
    pub fn corroboration_at_or_above(&self, min: AuthorityLevel) -> usize {
        self.corroborating_sources
            .values()
            .filter(|&&level| level >= min)
            .count()
    }

    /// When this claim's TTL elapses relative to its freshness anchor, if ever.
    #[must_use]
    pub fn expires_at(&self) -> Option<TimestampMillis> {
        self.ttl.expires_at(self.freshness_anchor)
    }

    /// Whether the claim's TTL has elapsed at `now`. A claim with `Ttl::Never` is
    /// never expired. This is the read-time freshness predicate; it does not consult
    /// lifecycle (a `superseded` claim can still be "unexpired" by TTL).
    #[must_use]
    pub fn is_expired_at(&self, now: TimestampMillis) -> bool {
        self.ttl.is_expired_at(self.freshness_anchor, now)
    }
}

pub fn apply_event(
    current: Option<ClaimState>,
    event: &ClaimEvent,
) -> Result<ClaimState, TransitionError> {
    event.validate().map_err(TransitionError::InvalidEvent)?;

    match current {
        None => apply_initial_event(event),
        Some(state) => apply_next_event(state, event),
    }
}

fn apply_initial_event(event: &ClaimEvent) -> Result<ClaimState, TransitionError> {
    if !matches!(event.kind, ClaimEventKind::Asserted) {
        return Err(TransitionError::MissingInitialAssertion);
    }

    let value = event
        .value
        .clone()
        .ok_or(TransitionError::MissingInitialAssertion)?;

    let freshness_anchor = event
        .valid_from
        .or(event.observed_at)
        .unwrap_or(event.provenance.recorded_at);

    Ok(ClaimState {
        claim_id: event.claim_id.clone(),
        subject: event.subject.clone(),
        predicate: event.predicate.clone(),
        value,
        authority: event.authority.clone(),
        ttl: event.ttl.clone(),
        freshness_anchor,
        lifecycle: ClaimLifecycle::Active,
        created_at: event.provenance.recorded_at,
        updated_at: event.provenance.recorded_at,
        last_event_id: event.event_id.clone(),
        superseded_by: None,
        contradicted_by: Vec::new(),
        evidence_count: event.evidence.len(),
        corroborating_sources: BTreeMap::from([(
            event.provenance.source.clone(),
            event.authority.level,
        )]),
    })
}

fn apply_next_event(
    mut state: ClaimState,
    event: &ClaimEvent,
) -> Result<ClaimState, TransitionError> {
    if state.claim_id != event.claim_id {
        return Err(TransitionError::ClaimIdMismatch);
    }

    if state.subject != event.subject || state.predicate != event.predicate {
        return Err(TransitionError::ClaimShapeMismatch);
    }

    if state.lifecycle.is_terminal()
        && !matches!(
            event.kind,
            ClaimEventKind::Retrieved { .. } | ClaimEventKind::UsedInDecision { .. }
        )
    {
        return Err(TransitionError::TerminalStateMutation(state.lifecycle));
    }

    match &event.kind {
        ClaimEventKind::Asserted => return Err(TransitionError::DuplicateAssertion),
        ClaimEventKind::Reinforced { .. } => {
            if let Some(value) = &event.value
                && value != &state.value
            {
                return Err(TransitionError::ReinforcementValueMismatch);
            }
            state.evidence_count += event.evidence.len();
            // A distinct reinforcing source raises earned entrenchment; keep the
            // highest authority a source has ever backed this value at.
            state
                .corroborating_sources
                .entry(event.provenance.source.clone())
                .and_modify(|level| *level = (*level).max(event.authority.level))
                .or_insert(event.authority.level);
        }
        ClaimEventKind::Contradicted { by, .. } => {
            // LFI "gentle explosion" tier: ordinary contradiction is tolerated and
            // localized (-> Contested), but a contradiction against a canonical claim
            // is a hard alarm, not a soft contest. A canonical fact that genuinely
            // changed must be superseded by an equal-authority claim, not contradicted.
            if state.authority.level == AuthorityLevel::Canonical {
                return Err(TransitionError::CanonicalContradiction);
            }
            state.lifecycle = ClaimLifecycle::Contested;
            if !state.contradicted_by.contains(by) {
                state.contradicted_by.push(by.clone());
            }
        }
        ClaimEventKind::Superseded { by, .. } => {
            // Authority-as-entrenchment arbitration: a strictly lower-authority claim
            // cannot supersede a higher-authority incumbent. This is the firewall's
            // mitigation for MINJA-style memory injection by a low-privilege actor.
            // Confidence is deliberately NOT consulted here (entrenchment != evidence).
            if event.authority.level < state.authority.level {
                return Err(TransitionError::InsufficientAuthority {
                    incumbent: state.authority.level,
                    challenger: event.authority.level,
                });
            }
            state.lifecycle = ClaimLifecycle::Superseded;
            state.superseded_by = Some(by.clone());
        }
        ClaimEventKind::Expired { .. } => {
            // Explicit expiration is a terminal close, so it is authority-gated like
            // retraction: a low-authority actor cannot make a trusted fact disappear by
            // calling it "stale." TTL freshness remains a separate read-time predicate.
            if event.authority.level < state.authority.level {
                return Err(TransitionError::InsufficientAuthority {
                    incumbent: state.authority.level,
                    challenger: event.authority.level,
                });
            }
            state.lifecycle = ClaimLifecycle::Expired;
        }
        ClaimEventKind::Retracted { .. } => {
            // Retraction terminally *removes* a belief, so — unlike a `Contradicted`
            // event, which is dissent and is deliberately not authority-gated — it is
            // gated exactly like supersession: a strictly lower-authority actor cannot
            // retract a higher-authority incumbent (ADR 0008). Retraction carries no
            // backing claim, so there is no laundering indirection (the `arbitrate`
            // anti-laundering check is supersession-only); this stated-authority gate is
            // the complete check.
            if event.authority.level < state.authority.level {
                return Err(TransitionError::InsufficientAuthority {
                    incumbent: state.authority.level,
                    challenger: event.authority.level,
                });
            }
            state.lifecycle = ClaimLifecycle::Retracted;
        }
        ClaimEventKind::Retrieved { .. } | ClaimEventKind::UsedInDecision { .. } => {}
    }

    state.updated_at = event.provenance.recorded_at;
    state.last_event_id = event.event_id.clone();
    Ok(state)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionError {
    InvalidEvent(crate::model::ValidationError),
    MissingInitialAssertion,
    DuplicateAssertion,
    ClaimIdMismatch,
    ClaimShapeMismatch,
    ReinforcementValueMismatch,
    TerminalStateMutation(ClaimLifecycle),
    /// A belief-changing event was rejected because its authority strictly under-ranks
    /// the incumbent's. Shared by **supersession** and **retraction** (ADR 0008): a
    /// replacement or a retraction must out-rank or tie the incumbent. (Supersession is
    /// additionally checked for laundering in `arbitrate`; retraction carries no backing
    /// claim, so this authority gate is its complete check. Contradiction is *not* gated
    /// — dissent is always admitted.)
    InsufficientAuthority {
        incumbent: AuthorityLevel,
        challenger: AuthorityLevel,
    },
    /// A `claim.contradicted` event targeted a canonical claim. Canonical facts are
    /// not softly contested; a genuine change must arrive as an equal-authority
    /// supersession. This is the LFI hard-alarm tier.
    CanonicalContradiction,
}

impl fmt::Display for TransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEvent(error) => write!(f, "invalid event: {error}"),
            Self::MissingInitialAssertion => {
                f.write_str("claim stream must start with claim.asserted")
            }
            Self::DuplicateAssertion => {
                f.write_str("claim stream cannot assert the same claim twice")
            }
            Self::ClaimIdMismatch => f.write_str("event claim_id does not match current state"),
            Self::ClaimShapeMismatch => {
                f.write_str("event subject or predicate does not match current state")
            }
            Self::ReinforcementValueMismatch => {
                f.write_str("claim.reinforced cannot change the claim value")
            }
            Self::TerminalStateMutation(state) => {
                write!(f, "cannot mutate terminal claim state {state:?}")
            }
            Self::InsufficientAuthority {
                incumbent,
                challenger,
            } => write!(
                f,
                "insufficient authority: {challenger:?} may not override or remove an incumbent of {incumbent:?}"
            ),
            Self::CanonicalContradiction => {
                f.write_str("a canonical claim cannot be contradicted; supersede it with equal authority instead")
            }
        }
    }
}

impl std::error::Error for TransitionError {}

#[cfg(test)]
mod tests {
    use crate::ids::{ActorId, ClaimEventId, ClaimId, EvidenceId, SourceId, TimestampMillis};
    use crate::model::{
        Authority, AuthorityLevel, ClaimEvent, ClaimEventKind, ClaimValue, Confidence,
        ContradictionBasis, EntityRef, Evidence, EvidenceKind, ExpirationReason, Predicate,
        Provenance, RetractionReason, SupersessionReason, Ttl,
    };

    use super::{ClaimLifecycle, TransitionError, apply_event};

    const ALL_LEVELS: [AuthorityLevel; 5] = [
        AuthorityLevel::Unknown,
        AuthorityLevel::Low,
        AuthorityLevel::Medium,
        AuthorityLevel::High,
        AuthorityLevel::Canonical,
    ];

    fn with_authority(mut event: ClaimEvent, level: AuthorityLevel) -> ClaimEvent {
        event.authority = Authority {
            level,
            issuer: None,
            scope: None,
        };
        event
    }

    fn asserted(level: AuthorityLevel) -> ClaimEvent {
        with_authority(
            base_event(
                ClaimEventKind::Asserted,
                "event:1",
                Some(ClaimValue::Text("postgres".to_string())),
            ),
            level,
        )
    }

    fn supersede(event_id: &str, level: AuthorityLevel) -> ClaimEvent {
        with_authority(
            base_event(
                ClaimEventKind::Superseded {
                    by: claim_id("claim:2"),
                    reason: SupersessionReason::NewerObservation,
                },
                event_id,
                None,
            ),
            level,
        )
    }

    fn retract(event_id: &str, level: AuthorityLevel) -> ClaimEvent {
        with_authority(
            base_event(
                ClaimEventKind::Retracted {
                    reason: RetractionReason::UserDeleted,
                },
                event_id,
                None,
            ),
            level,
        )
    }

    fn expire(event_id: &str, level: AuthorityLevel) -> ClaimEvent {
        with_authority(
            base_event(
                ClaimEventKind::Expired {
                    reason: ExpirationReason::PolicyRetention,
                },
                event_id,
                None,
            ),
            level,
        )
    }

    fn claim_id(value: &str) -> ClaimId {
        ClaimId::new(value).expect("valid claim id")
    }

    fn base_event(kind: ClaimEventKind, event_id: &str, value: Option<ClaimValue>) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).expect("valid event id"),
            claim_id: claim_id("claim:1"),
            kind,
            subject: EntityRef::new("repo", "dent8").expect("valid entity"),
            predicate: Predicate::new("uses_database").expect("valid predicate"),
            value,
            confidence: Confidence::from_millis(900).expect("valid confidence"),
            authority: Authority::unknown(),
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:test").expect("valid source"),
                actor: ActorId::new("actor:test").expect("valid actor"),
                tool: Some("unit-test".to_string()),
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(1),
            },
            evidence: vec![Evidence {
                id: EvidenceId::new("evidence:1").expect("valid evidence id"),
                kind: EvidenceKind::UserStatement,
                locator: "test".to_string(),
                digest: None,
                summary: Some("test evidence".to_string()),
            }],
            observed_at: None,
            valid_from: None,
        }
    }

    #[test]
    fn assertion_creates_active_state() {
        let event = base_event(
            ClaimEventKind::Asserted,
            "event:1",
            Some(ClaimValue::Text("postgres".to_string())),
        );

        let state = apply_event(None, &event).expect("assertion applies");

        assert_eq!(state.lifecycle, ClaimLifecycle::Active);
        assert_eq!(state.evidence_count, 1);
    }

    #[test]
    fn duplicate_assertion_is_rejected() {
        let event = base_event(
            ClaimEventKind::Asserted,
            "event:1",
            Some(ClaimValue::Text("postgres".to_string())),
        );
        let state = apply_event(None, &event).expect("assertion applies");

        let error = apply_event(Some(state), &event).expect_err("duplicate rejected");

        assert_eq!(error, TransitionError::DuplicateAssertion);
    }

    #[test]
    fn contradiction_marks_claim_contested() {
        let asserted = base_event(
            ClaimEventKind::Asserted,
            "event:1",
            Some(ClaimValue::Text("postgres".to_string())),
        );
        let state = apply_event(None, &asserted).expect("assertion applies");
        let contradicted = base_event(
            ClaimEventKind::Contradicted {
                by: claim_id("claim:2"),
                basis: ContradictionBasis::SamePredicateDifferentValue,
            },
            "event:2",
            None,
        );

        let state = apply_event(Some(state), &contradicted).expect("contradiction applies");

        assert_eq!(state.lifecycle, ClaimLifecycle::Contested);
        assert_eq!(state.contradicted_by, vec![claim_id("claim:2")]);
    }

    #[test]
    fn terminal_state_rejects_lifecycle_mutation() {
        let asserted = base_event(
            ClaimEventKind::Asserted,
            "event:1",
            Some(ClaimValue::Text("postgres".to_string())),
        );
        let state = apply_event(None, &asserted).expect("assertion applies");
        let superseded = base_event(
            ClaimEventKind::Superseded {
                by: claim_id("claim:2"),
                reason: SupersessionReason::NewerObservation,
            },
            "event:2",
            None,
        );
        let state = apply_event(Some(state), &superseded).expect("supersession applies");
        let reinforced = base_event(
            ClaimEventKind::Reinforced {
                by: claim_id("claim:3"),
            },
            "event:3",
            Some(ClaimValue::Text("postgres".to_string())),
        );

        let error = apply_event(Some(state), &reinforced).expect_err("terminal mutation rejected");

        assert_eq!(
            error,
            TransitionError::TerminalStateMutation(ClaimLifecycle::Superseded)
        );
    }

    #[test]
    fn retrieval_does_not_change_lifecycle() {
        let asserted = base_event(
            ClaimEventKind::Asserted,
            "event:1",
            Some(ClaimValue::Text("postgres".to_string())),
        );
        let state = apply_event(None, &asserted).expect("assertion applies");
        let retrieved = base_event(
            ClaimEventKind::Retrieved {
                purpose: "context".to_string(),
            },
            "event:2",
            None,
        );

        let state = apply_event(Some(state), &retrieved).expect("retrieval applies");

        assert_eq!(state.lifecycle, ClaimLifecycle::Active);
    }

    #[test]
    fn lower_authority_supersession_is_rejected() {
        let state = apply_event(None, &asserted(AuthorityLevel::High)).expect("assertion applies");

        let error = apply_event(Some(state), &supersede("event:2", AuthorityLevel::Low))
            .expect_err("low-authority supersession rejected");

        assert_eq!(
            error,
            TransitionError::InsufficientAuthority {
                incumbent: AuthorityLevel::High,
                challenger: AuthorityLevel::Low,
            }
        );
    }

    #[test]
    fn equal_authority_supersession_succeeds() {
        let state =
            apply_event(None, &asserted(AuthorityLevel::Medium)).expect("assertion applies");

        let state = apply_event(Some(state), &supersede("event:2", AuthorityLevel::Medium))
            .expect("equal-authority supersession applies");

        assert_eq!(state.lifecycle, ClaimLifecycle::Superseded);
    }

    #[test]
    fn higher_authority_supersession_succeeds() {
        let state = apply_event(None, &asserted(AuthorityLevel::Low)).expect("assertion applies");

        let state = apply_event(
            Some(state),
            &supersede("event:2", AuthorityLevel::Canonical),
        )
        .expect("higher-authority supersession applies");

        assert_eq!(state.lifecycle, ClaimLifecycle::Superseded);
    }

    #[test]
    fn contradicting_a_canonical_claim_hard_alarms() {
        let state =
            apply_event(None, &asserted(AuthorityLevel::Canonical)).expect("assertion applies");
        let contradicted = base_event(
            ClaimEventKind::Contradicted {
                by: claim_id("claim:2"),
                basis: ContradictionBasis::SamePredicateDifferentValue,
            },
            "event:2",
            None,
        );

        let error = apply_event(Some(state), &contradicted)
            .expect_err("canonical contradiction hard-alarms");

        assert_eq!(error, TransitionError::CanonicalContradiction);
    }

    #[test]
    fn contradicting_a_non_canonical_claim_still_contests() {
        let state = apply_event(None, &asserted(AuthorityLevel::High)).expect("assertion applies");
        let contradicted = base_event(
            ClaimEventKind::Contradicted {
                by: claim_id("claim:2"),
                basis: ContradictionBasis::SamePredicateDifferentValue,
            },
            "event:2",
            None,
        );

        let state =
            apply_event(Some(state), &contradicted).expect("non-canonical contradiction applies");

        assert_eq!(state.lifecycle, ClaimLifecycle::Contested);
    }

    /// Exhaustive bounded proof over the finite `AuthorityLevel` lattice: for every
    /// (incumbent, challenger) pair, a supersession is accepted iff the challenger does
    /// not under-rank the incumbent; and once accepted, the claim is terminal and
    /// cannot be resurrected by any later event — even a canonical one. This is the
    /// runnable form of the rank-1 "verified non-resurrection" invariant; the
    /// `#[cfg(kani)]` harness in `proofs` checks the same property symbolically.
    #[test]
    fn authority_monotone_supersession_and_non_resurrection() {
        for incumbent in ALL_LEVELS {
            for challenger in ALL_LEVELS {
                let state = apply_event(None, &asserted(incumbent)).expect("assertion applies");
                let result = apply_event(Some(state), &supersede("event:2", challenger));

                if challenger < incumbent {
                    assert_eq!(
                        result,
                        Err(TransitionError::InsufficientAuthority {
                            incumbent,
                            challenger,
                        }),
                        "challenger {challenger:?} should not supersede incumbent {incumbent:?}",
                    );
                    continue;
                }

                let superseded = result.expect("non-under-ranking supersession applies");
                assert!(
                    superseded.lifecycle.is_terminal(),
                    "supersession should make the claim terminal",
                );

                // Non-resurrection: no later event, even a canonical supersession,
                // returns a terminal claim to an active/believed state.
                let resurrect = supersede("event:3", AuthorityLevel::Canonical);
                let error = apply_event(Some(superseded), &resurrect)
                    .expect_err("terminal claim cannot be resurrected");
                assert_eq!(
                    error,
                    TransitionError::TerminalStateMutation(ClaimLifecycle::Superseded)
                );
            }
        }
    }

    /// The retraction counterpart of the supersession lattice (ADR 0008): a `Retracted`
    /// event is accepted iff the retractor does not under-rank the incumbent, and once
    /// accepted the claim is terminally `Retracted` and cannot be resurrected. Retraction
    /// removes a belief, so it is authority-gated like supersession — unlike a
    /// `Contradicted` event, which is dissent and is admitted at any authority.
    #[test]
    fn authority_monotone_retraction_and_non_resurrection() {
        for incumbent in ALL_LEVELS {
            for challenger in ALL_LEVELS {
                let state = apply_event(None, &asserted(incumbent)).expect("assertion applies");
                let result = apply_event(Some(state), &retract("event:2", challenger));

                if challenger < incumbent {
                    assert_eq!(
                        result,
                        Err(TransitionError::InsufficientAuthority {
                            incumbent,
                            challenger,
                        }),
                        "retractor {challenger:?} should not retract incumbent {incumbent:?}",
                    );
                    continue;
                }

                let retracted = result.expect("non-under-ranking retraction applies");
                assert_eq!(retracted.lifecycle, ClaimLifecycle::Retracted);
                assert!(retracted.lifecycle.is_terminal());

                let resurrect = supersede("event:3", AuthorityLevel::Canonical);
                let error = apply_event(Some(retracted), &resurrect)
                    .expect_err("terminal claim cannot be resurrected");
                assert_eq!(
                    error,
                    TransitionError::TerminalStateMutation(ClaimLifecycle::Retracted)
                );
            }
        }
    }

    /// Explicit expiration is also a terminal close. TTL staleness is read-time and needs no
    /// actor authority, but a `claim.expired` event changes the durable lifecycle, so it must
    /// not under-rank the incumbent.
    #[test]
    fn authority_monotone_expiration_and_non_resurrection() {
        for incumbent in ALL_LEVELS {
            for challenger in ALL_LEVELS {
                let state = apply_event(None, &asserted(incumbent)).expect("assertion applies");
                let result = apply_event(Some(state), &expire("event:2", challenger));

                if challenger < incumbent {
                    assert_eq!(
                        result,
                        Err(TransitionError::InsufficientAuthority {
                            incumbent,
                            challenger,
                        }),
                        "expirer {challenger:?} should not expire incumbent {incumbent:?}",
                    );
                    continue;
                }

                let expired = result.expect("non-under-ranking expiration applies");
                assert_eq!(expired.lifecycle, ClaimLifecycle::Expired);
                assert!(expired.lifecycle.is_terminal());

                let resurrect = supersede("event:3", AuthorityLevel::Canonical);
                let error = apply_event(Some(expired), &resurrect)
                    .expect_err("terminal claim cannot be resurrected");
                assert_eq!(
                    error,
                    TransitionError::TerminalStateMutation(ClaimLifecycle::Expired)
                );
            }
        }
    }
}

/// Rank-1 "verified non-resurrection" harness. Bounded model check of the
/// authority-weighted supersession gate with Kani (`cargo kani`). Excluded from
/// normal builds via `#[cfg(kani)]`; see `docs/formal-verification.md` and
/// `docs/research/novelty.md`. Authority levels are symbolic (`kani::any`),
/// everything else is fixed, keeping the proof tractable.
#[cfg(kani)]
mod proofs {
    use crate::ids::{ActorId, ClaimEventId, ClaimId, EvidenceId, SourceId, TimestampMillis};
    use crate::model::{
        Authority, AuthorityLevel, ClaimEvent, ClaimEventKind, ClaimValue, Confidence, EntityRef,
        Evidence, EvidenceKind, ExpirationReason, Predicate, Provenance, SupersessionReason, Ttl,
    };

    use super::apply_event;

    fn level_from(n: u8) -> AuthorityLevel {
        match n {
            0 => AuthorityLevel::Unknown,
            1 => AuthorityLevel::Low,
            2 => AuthorityLevel::Medium,
            3 => AuthorityLevel::High,
            _ => AuthorityLevel::Canonical,
        }
    }

    fn event(
        kind: ClaimEventKind,
        event_id: &str,
        value: Option<ClaimValue>,
        level: AuthorityLevel,
    ) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).unwrap(),
            claim_id: ClaimId::new("claim:1").unwrap(),
            kind,
            subject: EntityRef::new("repo", "dent8").unwrap(),
            predicate: Predicate::new("uses_database").unwrap(),
            value,
            confidence: Confidence::from_millis(900).unwrap(),
            authority: Authority {
                level,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:test").unwrap(),
                actor: ActorId::new("actor:test").unwrap(),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(1),
            },
            evidence: vec![Evidence {
                id: EvidenceId::new("evidence:1").unwrap(),
                kind: EvidenceKind::UserStatement,
                locator: "x".to_string(),
                digest: None,
                summary: None,
            }],
            observed_at: None,
            valid_from: None,
        }
    }

    #[kani::proof]
    fn supersession_is_authority_monotone_and_non_resurrecting() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        kani::assume(a < 5);
        kani::assume(b < 5);
        let incumbent = level_from(a);
        let challenger = level_from(b);

        let asserted = event(
            ClaimEventKind::Asserted,
            "event:1",
            Some(ClaimValue::Text("postgres".to_string())),
            incumbent,
        );
        let state = apply_event(None, &asserted).unwrap();

        let superseded = event(
            ClaimEventKind::Superseded {
                by: ClaimId::new("claim:2").unwrap(),
                reason: SupersessionReason::NewerObservation,
            },
            "event:2",
            None,
            challenger,
        );

        match apply_event(Some(state), &superseded) {
            Ok(next) => {
                // Accepted only when the challenger does not under-rank the incumbent,
                // and the result is terminal.
                assert!(challenger >= incumbent);
                assert!(next.lifecycle.is_terminal());

                // Non-resurrection: even a canonical event cannot re-activate it.
                let resurrect = event(
                    ClaimEventKind::Superseded {
                        by: ClaimId::new("claim:3").unwrap(),
                        reason: SupersessionReason::NewerObservation,
                    },
                    "event:3",
                    None,
                    AuthorityLevel::Canonical,
                );
                assert!(apply_event(Some(next), &resurrect).is_err());
            }
            Err(_) => {
                // Rejected only when the challenger strictly under-ranks the incumbent.
                assert!(challenger < incumbent);
            }
        }
    }

    #[kani::proof]
    fn retraction_is_authority_monotone_and_non_resurrecting() {
        use crate::model::RetractionReason;

        let a: u8 = kani::any();
        let b: u8 = kani::any();
        kani::assume(a < 5);
        kani::assume(b < 5);
        let incumbent = level_from(a);
        let challenger = level_from(b);

        let asserted = event(
            ClaimEventKind::Asserted,
            "event:1",
            Some(ClaimValue::Text("postgres".to_string())),
            incumbent,
        );
        let state = apply_event(None, &asserted).unwrap();

        let retracted = event(
            ClaimEventKind::Retracted {
                reason: RetractionReason::UserDeleted,
            },
            "event:2",
            None,
            challenger,
        );

        match apply_event(Some(state), &retracted) {
            Ok(next) => {
                assert!(challenger >= incumbent);
                assert!(next.lifecycle.is_terminal());

                let resurrect = event(
                    ClaimEventKind::Superseded {
                        by: ClaimId::new("claim:3").unwrap(),
                        reason: SupersessionReason::NewerObservation,
                    },
                    "event:3",
                    None,
                    AuthorityLevel::Canonical,
                );
                assert!(apply_event(Some(next), &resurrect).is_err());
            }
            Err(_) => {
                assert!(challenger < incumbent);
            }
        }
    }

    #[kani::proof]
    fn expiration_is_authority_monotone_and_non_resurrecting() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        kani::assume(a < 5);
        kani::assume(b < 5);
        let incumbent = level_from(a);
        let challenger = level_from(b);

        let asserted = event(
            ClaimEventKind::Asserted,
            "event:1",
            Some(ClaimValue::Text("postgres".to_string())),
            incumbent,
        );
        let state = apply_event(None, &asserted).unwrap();

        let expired = event(
            ClaimEventKind::Expired {
                reason: ExpirationReason::PolicyRetention,
            },
            "event:2",
            None,
            challenger,
        );

        match apply_event(Some(state), &expired) {
            Ok(next) => {
                assert!(challenger >= incumbent);
                assert!(next.lifecycle.is_terminal());

                let resurrect = event(
                    ClaimEventKind::Superseded {
                        by: ClaimId::new("claim:3").unwrap(),
                        reason: SupersessionReason::NewerObservation,
                    },
                    "event:3",
                    None,
                    AuthorityLevel::Canonical,
                );
                assert!(apply_event(Some(next), &resurrect).is_err());
            }
            Err(_) => {
                assert!(challenger < incumbent);
            }
        }
    }
}
