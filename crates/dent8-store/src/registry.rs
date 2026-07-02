//! Coding-agent predicate/policy registry.
//!
//! A [`PredicateRegistry`] attaches a [`PredicatePolicy`] to each *kind* of project fact
//! a coding agent records — `repo.database`, `repo.test_command`, `dependency.version`,
//! `branch.status`, `user.preference`. The policy lets the firewall enforce
//! predicate-specific rules the generic core cannot know: a **minimum authority to
//! *assert* the fact**, a **default freshness** (TTL) so volatile facts expire on their
//! own, and **uniqueness** (at most one *fresh* believed claim per subject+predicate).
//!
//! ## Layering and scope
//!
//! The registry is an **application-level policy layer above the base firewall**
//! ([`crate::arbitrate`], which every [`EventStore::append`] runs and cannot be
//! bypassed). Apply it via [`apply_policy_defaults`] + [`enforce_policy`] *before*
//! `append`. The base firewall is the unbypassable security floor (no override, no
//! laundering, canonical hard-alarm); the registry adds per-predicate *configuration*.
//!
//! The authority floor gates **assertion only** — creating a new authoritative fact. It
//! deliberately does **not** gate contradiction or reinforcement: a low-authority agent
//! must always be able to *dissent* (file a contradiction), and that dissent must reach
//! the core firewall so a contradiction against a canonical claim still trips the
//! hard-alarm. Revising an existing fact goes through supersession, which the base
//! firewall already gates (the replacing claim must out-rank the incumbent).

use std::collections::BTreeMap;

use dent8_core::{
    AuthorityLevel, ClaimEvent, ClaimEventKind, EntityRef, Predicate, TimestampMillis, Ttl,
};

use crate::{EventFilter, EventStore, StoreError, replay_entity};

/// How often a fact is expected to change — advisory metadata that motivates the
/// default TTL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Volatility {
    Stable,
    Volatile,
}

/// The policy for one kind of project fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredicatePolicy {
    /// The minimum authority required to *assert* a new claim of this fact.
    pub authority_floor: AuthorityLevel,
    /// The freshness applied to an assertion that does not set its own TTL. **Note:**
    /// `Ttl::Never` on an assertion is treated as "unset" and is replaced by this default
    /// when it is non-`Never` — there is currently no way for a caller to opt out of a
    /// default TTL (a known limitation; an explicit "never" sentinel is future work).
    pub default_ttl: Ttl,
    /// Whether at most one *fresh* claim about a given subject+predicate may be believed.
    pub unique: bool,
    pub volatility: Volatility,
}

/// A registry of [`PredicatePolicy`] keyed by the structured `(subject kind, predicate)`
/// pair — e.g. `("repo", "database")`. Keying on the pair (rather than a flattened
/// `"repo.database"` string) avoids any delimiter ambiguity when a kind or predicate
/// itself contains a dot.
#[derive(Clone, Debug, Default)]
pub struct PredicateRegistry {
    policies: BTreeMap<(String, String), PredicatePolicy>,
}

impl PredicateRegistry {
    /// The default registry of coding-agent fact predicates.
    #[must_use]
    pub fn coding_agent() -> Self {
        use AuthorityLevel::{High, Low, Medium};
        use Volatility::{Stable, Volatile};

        const ONE_HOUR_MS: u64 = 3_600_000;

        let mut registry = Self::default();
        registry.register("repo", "database", High, Ttl::Never, true, Stable);
        registry.register("repo", "test_command", Medium, Ttl::Never, true, Stable);
        registry.register("dependency", "version", Medium, Ttl::Never, true, Volatile);
        registry.register(
            "branch",
            "status",
            Low,
            Ttl::DurationMillis(ONE_HOUR_MS),
            true,
            Volatile,
        );
        registry.register("user", "preference", Medium, Ttl::Never, true, Stable);
        registry
    }

    /// Register or override a policy for `(subject_kind, predicate)`.
    pub fn register(
        &mut self,
        subject_kind: impl Into<String>,
        predicate: impl Into<String>,
        authority_floor: AuthorityLevel,
        default_ttl: Ttl,
        unique: bool,
        volatility: Volatility,
    ) {
        self.policies.insert(
            (subject_kind.into(), predicate.into()),
            PredicatePolicy {
                authority_floor,
                default_ttl,
                unique,
                volatility,
            },
        );
    }

    /// The policy for a claim's `(subject.kind, predicate)`, if registered.
    #[must_use]
    pub fn policy_for(
        &self,
        subject: &EntityRef,
        predicate: &Predicate,
    ) -> Option<&PredicatePolicy> {
        self.policies
            .get(&(subject.kind().to_string(), predicate.as_str().to_string()))
    }
}

fn display_key(subject: &EntityRef, predicate: &Predicate) -> String {
    format!("{}.{}", subject.kind(), predicate.as_str())
}

/// Apply the registry's default freshness to an asserting event that left its TTL unset
/// (`Ttl::Never`). A no-op for unregistered predicates, non-assertions, or predicates
/// whose default is itself `Never`. See [`PredicatePolicy::default_ttl`] for the
/// `Never`-as-unset caveat.
pub fn apply_policy_defaults(registry: &PredicateRegistry, candidate: &mut ClaimEvent) {
    if let Some(policy) = registry.policy_for(&candidate.subject, &candidate.predicate)
        && matches!(candidate.kind, ClaimEventKind::Asserted)
        && candidate.ttl == Ttl::Never
    {
        candidate.ttl = policy.default_ttl.clone();
    }
}

/// Enforce the registry policy for `candidate` at time `now`:
///
/// - **Authority floor** — an *assertion* below the predicate's floor is rejected.
///   Contradiction and reinforcement are *not* gated (dissent must always be possible).
/// - **Uniqueness** — a new assertion may not create a second *fresh* believed claim for
///   the same subject+predicate; stale (TTL-expired at `now`) claims do not block it.
///
/// Unregistered predicates pass. Run *before* the base firewall (`EventStore::append`).
pub fn enforce_policy<S>(
    registry: &PredicateRegistry,
    store: &S,
    candidate: &ClaimEvent,
    now: TimestampMillis,
) -> Result<(), StoreError>
where
    S: EventStore + ?Sized,
{
    let Some(policy) = registry.policy_for(&candidate.subject, &candidate.predicate) else {
        return Ok(());
    };

    // The floor gates assertion of a new authoritative fact only — never dissent.
    if matches!(candidate.kind, ClaimEventKind::Asserted)
        && candidate.authority.level < policy.authority_floor
    {
        return Err(StoreError::BelowAuthorityFloor {
            predicate: display_key(&candidate.subject, &candidate.predicate),
            floor: policy.authority_floor,
            actual: candidate.authority.level,
        });
    }

    if policy.unique && matches!(candidate.kind, ClaimEventKind::Asserted) {
        let filter = EventFilter {
            subject: Some(candidate.subject.clone()),
            predicate: Some(candidate.predicate.clone()),
            ..EventFilter::default()
        };
        let entity = replay_entity(&store.scan_events(&filter)?).map_err(StoreError::Replay)?;
        let conflict = entity
            .believed()
            .filter(|state| !state.is_expired_at(now))
            .any(|state| state.claim_id != candidate.claim_id);
        if conflict {
            return Err(StoreError::UniquenessViolation {
                predicate: display_key(&candidate.subject, &candidate.predicate),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{PredicateRegistry, Volatility, apply_policy_defaults, enforce_policy};
    use crate::{EventStore, InMemoryEventStore, StoreError};
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
        ClaimValue, Confidence, ContradictionBasis, EntityRef, Evidence, EvidenceId, EvidenceKind,
        Predicate, Provenance, SourceId, TimestampMillis, TransitionError, Ttl,
    };

    const NOW: TimestampMillis = TimestampMillis::from_unix_millis(100);

    #[allow(clippy::too_many_arguments)]
    fn event(
        event_id: &str,
        claim_id: &str,
        subject_kind: &str,
        subject_key: &str,
        predicate: &str,
        kind: ClaimEventKind,
        value: Option<ClaimValue>,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).expect("event id"),
            claim_id: ClaimId::new(claim_id).expect("claim id"),
            kind,
            subject: EntityRef::new(subject_kind, subject_key).expect("entity"),
            predicate: Predicate::new(predicate).expect("predicate"),
            value,
            confidence: Confidence::from_millis(900).expect("confidence"),
            authority: Authority {
                level: authority,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:test").expect("source"),
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
        }
    }

    fn assertion(
        event_id: &str,
        claim_id: &str,
        subject_kind: &str,
        subject_key: &str,
        predicate: &str,
        value: &str,
        authority: AuthorityLevel,
    ) -> ClaimEvent {
        event(
            event_id,
            claim_id,
            subject_kind,
            subject_key,
            predicate,
            ClaimEventKind::Asserted,
            Some(ClaimValue::Text(value.to_string())),
            authority,
        )
    }

    fn admit(
        store: &mut InMemoryEventStore,
        registry: &PredicateRegistry,
        mut candidate: ClaimEvent,
        now: TimestampMillis,
    ) -> Result<(), StoreError> {
        apply_policy_defaults(registry, &mut candidate);
        enforce_policy(registry, store, &candidate, now)?;
        store.append(candidate).map(|_| ())
    }

    #[test]
    fn a_below_floor_assertion_is_rejected() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        let result = admit(
            &mut store,
            &registry,
            assertion(
                "e1",
                "claim:A",
                "repo",
                "myproj",
                "database",
                "mysql",
                AuthorityLevel::Low,
            ),
            NOW,
        );
        assert!(matches!(
            result,
            Err(StoreError::BelowAuthorityFloor {
                floor: AuthorityLevel::High,
                actual: AuthorityLevel::Low,
                ..
            })
        ));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn a_below_floor_contradiction_is_admitted_dissent_is_never_silenced() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            assertion(
                "e1",
                "claim:A",
                "repo",
                "myproj",
                "database",
                "postgres",
                AuthorityLevel::High,
            ),
            NOW,
        )
        .expect("high assertion admitted");

        // A Low-authority agent contradicts the High fact — the floor must NOT block it.
        let contradiction = event(
            "e2",
            "claim:A",
            "repo",
            "myproj",
            "database",
            ClaimEventKind::Contradicted {
                by: ClaimId::new("claim:rumor").expect("claim id"),
                basis: ContradictionBasis::SamePredicateDifferentValue,
            },
            None,
            AuthorityLevel::Low,
        );
        admit(&mut store, &registry, contradiction, NOW).expect("low-authority dissent admitted");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn a_canonical_contradiction_is_not_masked_by_the_floor() {
        let mut registry = PredicateRegistry::coding_agent();
        // Give repo.database a High floor and assert a Canonical incumbent.
        registry.register(
            "repo",
            "database",
            AuthorityLevel::High,
            Ttl::Never,
            true,
            Volatility::Stable,
        );
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            assertion(
                "e1",
                "claim:A",
                "repo",
                "myproj",
                "database",
                "postgres",
                AuthorityLevel::Canonical,
            ),
            NOW,
        )
        .expect("canonical assertion admitted");

        // A Low contradiction must reach the core firewall and trip the hard-alarm,
        // NOT be masked as a routine BelowAuthorityFloor policy denial.
        let contradiction = event(
            "e2",
            "claim:A",
            "repo",
            "myproj",
            "database",
            ClaimEventKind::Contradicted {
                by: ClaimId::new("claim:rumor").expect("claim id"),
                basis: ContradictionBasis::SamePredicateDifferentValue,
            },
            None,
            AuthorityLevel::Low,
        );
        let result = admit(&mut store, &registry, contradiction, NOW);
        assert!(matches!(
            result,
            Err(StoreError::Rejected(
                TransitionError::CanonicalContradiction
            ))
        ));
    }

    #[test]
    fn a_second_competing_assertion_violates_uniqueness() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            assertion(
                "e1",
                "claim:A",
                "repo",
                "myproj",
                "database",
                "postgres",
                AuthorityLevel::High,
            ),
            NOW,
        )
        .expect("first claim admitted");

        let result = admit(
            &mut store,
            &registry,
            assertion(
                "e2",
                "claim:B",
                "repo",
                "myproj",
                "database",
                "mariadb",
                AuthorityLevel::High,
            ),
            NOW,
        );
        assert!(matches!(
            result,
            Err(StoreError::UniquenessViolation { .. })
        ));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_stale_unique_claim_does_not_block_a_fresh_assertion() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        // branch.status carries a 1h default TTL; assert at recorded_at=1.
        admit(
            &mut store,
            &registry,
            assertion(
                "e1",
                "claim:A",
                "branch",
                "main",
                "status",
                "ci-green",
                AuthorityLevel::Low,
            ),
            TimestampMillis::from_unix_millis(2),
        )
        .expect("first status admitted");

        // Two hours later the first status is stale; a new status must be admittable.
        let two_hours = TimestampMillis::from_unix_millis(7_200_000);
        admit(
            &mut store,
            &registry,
            assertion(
                "e2",
                "claim:B",
                "branch",
                "main",
                "status",
                "ci-red",
                AuthorityLevel::Low,
            ),
            two_hours,
        )
        .expect("fresh status admitted despite a stale prior");
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn the_default_ttl_is_applied_to_a_ttl_less_assertion() {
        let registry = PredicateRegistry::coding_agent();
        let mut candidate = assertion(
            "e1",
            "claim:A",
            "branch",
            "main",
            "status",
            "ci-green",
            AuthorityLevel::Low,
        );
        assert_eq!(candidate.ttl, Ttl::Never);
        apply_policy_defaults(&registry, &mut candidate);
        assert_eq!(candidate.ttl, Ttl::DurationMillis(3_600_000));
    }

    #[test]
    fn an_unregistered_predicate_has_no_extra_policy() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            assertion(
                "e1",
                "claim:A",
                "repo",
                "myproj",
                "note",
                "anything",
                AuthorityLevel::Low,
            ),
            NOW,
        )
        .expect("unregistered predicate admitted");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn coding_agent_registry_has_the_five_predicates() {
        let registry = PredicateRegistry::coding_agent();
        for (kind, predicate) in [
            ("repo", "database"),
            ("repo", "test_command"),
            ("dependency", "version"),
            ("branch", "status"),
            ("user", "preference"),
        ] {
            let subject = EntityRef::new(kind, "x").unwrap();
            let pred = Predicate::new(predicate).unwrap();
            assert!(
                registry.policy_for(&subject, &pred).is_some(),
                "{kind}.{predicate} should be registered"
            );
        }
        assert_eq!(Volatility::Stable, Volatility::Stable);
    }
}
