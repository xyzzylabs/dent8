//! The firewall: arbitrate a candidate event before it is persisted.
//!
//! [`arbitrate`] is the policy that every [`EventStore::append`] must run before writing.
//! It is *not* an optional wrapper — `append` itself calls it, so there is no
//! un-arbitrated write path. It enforces two layers:
//!
//! 1. **Per-claim** ([`apply_event`]): schema validation, the *stated* authority gate,
//!    the canonical-contradiction hard-alarm, terminal immutability, duplicate detection.
//! 2. **Entity-aware** (anti-laundering): a `Superseded` event names a *replacing claim*;
//!    the firewall resolves that claim's **actual** authority and rejects the write if it
//!    is below the incumbent's. This closes the over-stated-authority hole that the
//!    per-claim gate alone cannot see, because a supersession event can claim any
//!    authority while the claim behind it is weak.

use dent8_core::{ClaimEvent, ClaimEventKind, apply_event};

use crate::{EventStore, StoreError, replay_claim};

/// Arbitrate `candidate` against the store's current state. Returns `Ok(())` if the
/// write is admissible; otherwise a [`StoreError`] describing the rejection. Called by
/// every `EventStore::append` implementation before it persists. Thin I/O wrapper around
/// [`arbitrate_events`]: it loads the candidate's claim stream (and, for a supersession,
/// the replacing claim's stream) and delegates the decision.
pub fn arbitrate<S>(store: &S, candidate: &ClaimEvent) -> Result<(), StoreError>
where
    S: EventStore + ?Sized,
{
    let existing = store.load_claim_events(&candidate.claim_id)?;
    let replacing = match &candidate.kind {
        ClaimEventKind::Superseded { by, .. } => Some(store.load_claim_events(by)?),
        _ => None,
    };
    arbitrate_events(candidate, &existing, replacing.as_deref())
}

/// The **pure, I/O-free firewall decision** over already-loaded event streams — the single
/// security decision shared by every backend (the synchronous [`crate::InMemoryEventStore`]
/// and any async adapter), so they cannot diverge. `existing` is the candidate's own claim
/// stream in order; `replacing` is the stream of the claim a `Superseded` candidate names
/// (ignored for other kinds; `None` is treated as an absent claim).
///
/// Enforces both firewall layers: the per-claim stated-authority gate, terminal/shape
/// invariants and the canonical hard-alarm (via [`apply_event`]); and the entity-aware
/// anti-laundering check (a supersession must be backed by a *real* claim that out-ranks
/// the incumbent).
pub fn arbitrate_events(
    candidate: &ClaimEvent,
    existing: &[ClaimEvent],
    replacing: Option<&[ClaimEvent]>,
) -> Result<(), StoreError> {
    let current = replay_claim(existing).map_err(StoreError::Replay)?;
    let incumbent_authority = current.as_ref().map(|state| state.authority.level);

    // Per-claim arbitration (gates on the event's own stated authority).
    apply_event(current, candidate).map_err(StoreError::Rejected)?;

    // Entity-aware anti-laundering: a supersession must be backed by a *real* claim that
    // out-ranks the incumbent, not merely by an event that claims high authority.
    if let ClaimEventKind::Superseded { by, .. } = &candidate.kind {
        let incumbent = incumbent_authority.expect("a supersession has an incumbent");
        let target = match replacing {
            Some(events) => replay_claim(events).map_err(StoreError::Replay)?,
            None => None,
        };
        match target {
            None => return Err(StoreError::UnbackedSupersession(by.clone())),
            Some(state) if state.authority.level < incumbent => {
                return Err(StoreError::LaunderedAuthority {
                    incumbent,
                    challenger: state.authority.level,
                });
            }
            Some(_) => {}
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{EventStore, InMemoryEventStore, StoreError};
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
        ClaimLifecycle, ClaimValue, Confidence, EntityRef, Evidence, EvidenceId, EvidenceKind,
        Predicate, Provenance, SourceId, SupersessionReason, TimestampMillis, TransitionError, Ttl,
    };

    fn assert_event(
        event_id: &str,
        claim_id: &str,
        value: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        base(
            event_id,
            claim_id,
            ClaimEventKind::Asserted,
            Some(ClaimValue::Text(value.to_string())),
            source,
            authority,
        )
    }

    fn supersede_event(
        event_id: &str,
        claim_id: &str,
        by: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        base(
            event_id,
            claim_id,
            ClaimEventKind::Superseded {
                by: ClaimId::new(by).expect("claim id"),
                reason: SupersessionReason::NewerObservation,
            },
            None,
            source,
            authority,
        )
    }

    fn base(
        event_id: &str,
        claim_id: &str,
        kind: ClaimEventKind,
        value: Option<ClaimValue>,
        source: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).expect("event id"),
            claim_id: ClaimId::new(claim_id).expect("claim id"),
            kind,
            subject: EntityRef::new("repo", "myproj").expect("entity"),
            predicate: Predicate::new("database").expect("predicate"),
            value,
            confidence: Confidence::from_millis(900).expect("confidence"),
            authority: Authority {
                level: authority,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
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
            valid_from: None,
        }
    }

    #[test]
    fn append_is_the_firewall_a_high_authority_assertion_is_admitted() {
        let mut store = InMemoryEventStore::new();
        let receipt = store
            .append(assert_event(
                "e1",
                "claim:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        assert_eq!(receipt.global_sequence, 0);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_low_stated_authority_override_is_rejected() {
        let mut store = InMemoryEventStore::new();
        store
            .append(assert_event(
                "e1",
                "claim:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        // Claim B exists at Low so the supersession is "backed" — the rejection here is
        // purely the per-claim stated-authority gate.
        store
            .append(assert_event(
                "e2",
                "claim:B",
                "mysql",
                "source:web-scrape",
                AuthorityLevel::Low,
            ))
            .expect("low claim may exist");

        let rejected = store.append(supersede_event(
            "e3",
            "claim:A",
            "claim:B",
            "source:web-scrape",
            AuthorityLevel::Low,
        ));
        assert!(matches!(
            rejected,
            Err(StoreError::Rejected(
                TransitionError::InsufficientAuthority { .. }
            ))
        ));
        assert_eq!(store.len(), 2); // the override never persisted
    }

    #[test]
    fn an_over_stated_authority_supersession_is_rejected_as_laundering() {
        let mut store = InMemoryEventStore::new();
        store
            .append(assert_event(
                "e1",
                "claim:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        // The attacker's actual claim is Low authority...
        store
            .append(assert_event(
                "e2",
                "claim:B",
                "mysql",
                "source:web-scrape",
                AuthorityLevel::Low,
            ))
            .expect("low claim may exist");

        // ...but the supersession EVENT claims High authority. The per-claim gate would
        // pass; the entity-aware firewall must reject it.
        let rejected = store.append(supersede_event(
            "e3",
            "claim:A",
            "claim:B",
            "source:web-scrape",
            AuthorityLevel::High,
        ));
        assert!(matches!(
            rejected,
            Err(StoreError::LaunderedAuthority {
                incumbent: AuthorityLevel::High,
                challenger: AuthorityLevel::Low,
            })
        ));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn a_supersession_by_a_genuinely_stronger_claim_is_admitted() {
        let mut store = InMemoryEventStore::new();
        store
            .append(assert_event(
                "e1",
                "claim:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        store
            .append(assert_event(
                "e2",
                "claim:B",
                "mariadb",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        store
            .append(supersede_event(
                "e3",
                "claim:A",
                "claim:B",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("legitimate supersession admitted");

        let receipt = store
            .explain(
                &ClaimId::new("claim:A").unwrap(),
                TimestampMillis::from_unix_millis(100),
            )
            .expect("explain")
            .expect("present");
        assert_eq!(receipt.lifecycle, ClaimLifecycle::Superseded);
        assert!(receipt.chain_verified);
    }

    #[test]
    fn a_supersession_by_a_nonexistent_claim_is_rejected() {
        let mut store = InMemoryEventStore::new();
        store
            .append(assert_event(
                "e1",
                "claim:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        let rejected = store.append(supersede_event(
            "e2",
            "claim:A",
            "claim:ghost",
            "source:owner",
            AuthorityLevel::High,
        ));
        assert!(matches!(rejected, Err(StoreError::UnbackedSupersession(_))));
    }
}
