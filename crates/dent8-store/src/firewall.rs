//! The firewall: arbitrate a candidate event before it is persisted.
//!
//! [`arbitrate`] is the policy that every [`EventStore::append`] must run before writing.
//! It is *not* an optional wrapper — `append` itself calls it, so there is no
//! un-arbitrated write path. It enforces two layers:
//!
//! 1. **Per-fact** ([`apply_event`]): schema validation, the *stated* authority gate,
//!    the canonical-contradiction hard-alarm, terminal immutability, duplicate detection.
//! 2. **Subject-aware** (anti-laundering): a `Superseded` event names a *replacing fact*;
//!    the firewall resolves that fact's **actual** authority and rejects the write if it
//!    is below the incumbent's. This closes the over-stated-authority hole that the
//!    per-fact gate alone cannot see, because a supersession event can assert any
//!    authority while the fact behind it is weak.

use dent8_core::{FactEvent, FactEventKind, apply_event};

use crate::{EventStore, StoreError, replay_fact};

/// Arbitrate `candidate` against the store's current state. Returns `Ok(())` if the
/// write is admissible; otherwise a [`StoreError`] describing the rejection. Called by
/// every `EventStore::append` implementation before it persists. Thin I/O wrapper around
/// [`arbitrate_events`]: it loads the candidate's fact stream (and, for a supersession,
/// the replacing fact's stream) and delegates the decision.
pub fn arbitrate<S>(store: &S, candidate: &FactEvent) -> Result<(), StoreError>
where
    S: EventStore + ?Sized,
{
    let existing = store.load_fact_events(&candidate.fact_id)?;
    let replacing = match &candidate.kind {
        FactEventKind::Superseded { by, .. } => Some(store.load_fact_events(by)?),
        _ => None,
    };
    arbitrate_events(candidate, &existing, replacing.as_deref())
}

/// The **pure, I/O-free firewall decision** over already-loaded event streams — the single
/// security decision shared by every backend (the synchronous [`crate::InMemoryEventStore`]
/// and any async adapter), so they cannot diverge. `existing` is the candidate's own fact
/// stream in order; `replacing` is the stream of the fact a `Superseded` candidate names
/// (ignored for other kinds; `None` is treated as an absent fact).
///
/// Enforces both firewall layers: the per-fact stated-authority gate, terminal/shape
/// invariants and the canonical hard-alarm (via [`apply_event`]); and the subject-aware
/// anti-laundering check (a supersession must be backed by a *real* fact that out-ranks
/// the incumbent).
pub fn arbitrate_events(
    candidate: &FactEvent,
    existing: &[FactEvent],
    replacing: Option<&[FactEvent]>,
) -> Result<(), StoreError> {
    let current = replay_fact(existing).map_err(StoreError::Replay)?;
    let incumbent_authority = current.as_ref().map(|state| state.authority.level);

    // Per-fact arbitration (gates on the event's own stated authority).
    apply_event(current, candidate).map_err(StoreError::Rejected)?;

    // Subject-aware anti-laundering: a supersession must be backed by a *real* fact that
    // out-ranks the incumbent, not merely by an event that asserts high authority.
    if let FactEventKind::Superseded { by, .. } = &candidate.kind {
        let incumbent = incumbent_authority.expect("a supersession has an incumbent");
        let target = match replacing {
            Some(events) => replay_fact(events).map_err(StoreError::Replay)?,
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
        ActorId, Authority, AuthorityLevel, Confidence, Evidence, EvidenceId, EvidenceKind,
        FactEvent, FactEventId, FactEventKind, FactId, FactLifecycle, FactValue, Predicate,
        Provenance, SourceId, Subject, SupersessionReason, TimestampMillis, TransitionError, Ttl,
    };

    fn assert_event(
        event_id: &str,
        fact_id: &str,
        value: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> FactEvent {
        base(
            event_id,
            fact_id,
            FactEventKind::Asserted,
            Some(FactValue::Text(value.to_string())),
            source,
            authority,
        )
    }

    fn supersede_event(
        event_id: &str,
        fact_id: &str,
        by: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> FactEvent {
        base(
            event_id,
            fact_id,
            FactEventKind::Superseded {
                by: FactId::new(by).expect("fact id"),
                reason: SupersessionReason::NewerObservation,
            },
            None,
            source,
            authority,
        )
    }

    fn base(
        event_id: &str,
        fact_id: &str,
        kind: FactEventKind,
        value: Option<FactValue>,
        source: &str,
        authority: AuthorityLevel,
    ) -> FactEvent {
        FactEvent {
            event_id: FactEventId::new(event_id).expect("event id"),
            fact_id: FactId::new(fact_id).expect("fact id"),
            kind,
            subject: Subject::new("repo", "myproj").expect("subject"),
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

    #[test]
    fn append_is_the_firewall_a_high_authority_assertion_is_admitted() {
        let mut store = InMemoryEventStore::new();
        let receipt = store
            .append(assert_event(
                "e1",
                "fact:A",
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
                "fact:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        // Fact B exists at Low so the supersession is "backed" — the rejection here is
        // purely the per-fact stated-authority gate.
        store
            .append(assert_event(
                "e2",
                "fact:B",
                "mysql",
                "source:web-scrape",
                AuthorityLevel::Low,
            ))
            .expect("low fact may exist");

        let rejected = store.append(supersede_event(
            "e3",
            "fact:A",
            "fact:B",
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
                "fact:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        // The attacker's actual fact is Low authority...
        store
            .append(assert_event(
                "e2",
                "fact:B",
                "mysql",
                "source:web-scrape",
                AuthorityLevel::Low,
            ))
            .expect("low fact may exist");

        // ...but the supersession EVENT facts High authority. The per-fact gate would
        // pass; the subject-aware firewall must reject it.
        let rejected = store.append(supersede_event(
            "e3",
            "fact:A",
            "fact:B",
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
    fn a_supersession_by_a_genuinely_stronger_fact_is_admitted() {
        let mut store = InMemoryEventStore::new();
        store
            .append(assert_event(
                "e1",
                "fact:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        store
            .append(assert_event(
                "e2",
                "fact:B",
                "mariadb",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        store
            .append(supersede_event(
                "e3",
                "fact:A",
                "fact:B",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("legitimate supersession admitted");

        let receipt = store
            .explain(
                &FactId::new("fact:A").unwrap(),
                TimestampMillis::from_unix_millis(100),
            )
            .expect("explain")
            .expect("present");
        assert_eq!(receipt.lifecycle, FactLifecycle::Superseded);
        assert!(receipt.chain_verified);
    }

    #[test]
    fn a_supersession_by_a_nonexistent_fact_is_rejected() {
        let mut store = InMemoryEventStore::new();
        store
            .append(assert_event(
                "e1",
                "fact:A",
                "postgres",
                "source:owner",
                AuthorityLevel::High,
            ))
            .expect("admitted");
        let rejected = store.append(supersede_event(
            "e2",
            "fact:A",
            "fact:ghost",
            "source:owner",
            AuthorityLevel::High,
        ));
        assert!(matches!(rejected, Err(StoreError::UnbackedSupersession(_))));
    }
}
