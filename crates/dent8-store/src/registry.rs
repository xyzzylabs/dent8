//! Coding-agent predicate/policy registry.
//!
//! A [`PredicateRegistry`] attaches a [`PredicatePolicy`] to each *kind* of project fact
//! a coding agent records — `repo.database`, `repo.test_command`, `dependency.version`,
//! `branch.status`, `user.preference`. The policy lets the firewall enforce
//! predicate-specific rules the generic core cannot know: a **minimum authority to
//! *assert* the fact**, a **default freshness** (TTL), a **volatility** class that bounds
//! how long a caller may claim a fact stays fresh (a `Volatile` predicate caps at 7 days),
//! and **uniqueness** (at most one *fresh* believed fact per subject+predicate).
//!
//! ## Layering and scope
//!
//! The registry is an **application-level policy layer above the base firewall**
//! ([`crate::arbitrate`], which every [`EventStore::append`] runs and cannot be
//! bypassed). Apply defaults/floors via [`apply_policy_defaults`] + [`enforce_policy`]
//! *before* `append`; async transactional stores also use [`validate_unique_projection`]
//! before commit so stale concurrent writers cannot leave two silent fresh beliefs for a
//! `unique` predicate. The base firewall is the unbypassable security floor (no override,
//! no laundering, canonical hard-alarm); the registry adds per-predicate *configuration*.
//!
//! The authority floor gates **assertion only** — creating a new authoritative fact. It
//! deliberately does **not** gate contradiction or reinforcement: a low-authority agent
//! must always be able to *dissent* (file a contradiction), and that dissent must reach
//! the core firewall so a contradiction against a canonical fact still trips the
//! hard-alarm. Revising an existing fact goes through supersession, which the base
//! firewall already gates (the replacing fact must out-rank the incumbent).

use std::collections::{BTreeMap, BTreeSet};

use dent8_core::{
    AuthorityLevel, FactEvent, FactEventKind, FactLifecycle, Predicate, Subject, TimestampMillis,
    Ttl,
};

use crate::{EventFilter, EventStore, StoreError, replay_subject};

/// The default retention ceiling: **90 days** in milliseconds.
///
/// A coding-agent fact is a working belief about a codebase — a database choice, a test
/// command, a dependency pin. Such facts drift; a freshness window measured in months, not
/// years, keeps the store honest without churning the common case (every predicate default
/// TTL is far below this). The ceiling bounds how far a *caller-supplied finite* TTL may
/// reach: an assertion whose bounded TTL exceeds the effective ceiling is **rejected, not
/// clamped** (see [`enforce_policy`]). It is a policy default, not a security invariant, so
/// it is overridable — globally via [`PredicateRegistry::with_max_ttl`] /
/// [`PredicateRegistry::set_max_ttl`], or per predicate via [`PredicatePolicy::max_ttl`].
pub const DEFAULT_MAX_TTL_MS: u64 = 90 * 24 * 60 * 60 * 1000;

/// The retention ceiling a `Volatile` predicate imposes on caller-supplied freshness:
/// **7 days**. A volatile fact is a working belief that changes often (a branch status, a
/// dependency pin) — one no caller should be able to pin *fresh* for months. This bounds a
/// caller-supplied finite TTL for a volatile predicate the way the registry-wide
/// [`DEFAULT_MAX_TTL_MS`] bounds everything else, only tighter. It is overridable per
/// predicate via [`PredicatePolicy::max_ttl`] (an explicit override wins over volatility).
pub const VOLATILE_RETENTION_CEILING_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// How often a fact of a given predicate is expected to change. **Functional, not advisory:**
/// a [`Volatile`](Volatility::Volatile) predicate caps how long a caller may claim its facts
/// stay fresh (the [`retention_ceiling`](Volatility::retention_ceiling), enforced by
/// [`enforce_policy`]); a [`Stable`](Volatility::Stable) predicate uses the registry-wide
/// ceiling. The classification is the predicate's declared nature; the ceiling is what the
/// firewall does with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Volatility {
    Stable,
    Volatile,
}

impl Volatility {
    /// The retention ceiling this volatility class imposes on a caller-supplied finite TTL:
    /// `Some(7 days)` for [`Volatile`](Self::Volatile), `None` for [`Stable`](Self::Stable)
    /// (which defers to the registry-wide ceiling). A per-predicate
    /// [`PredicatePolicy::max_ttl`] override takes precedence over this.
    #[must_use]
    pub fn retention_ceiling(self) -> Option<Ttl> {
        match self {
            Self::Volatile => Some(Ttl::DurationMillis(VOLATILE_RETENTION_CEILING_MS)),
            Self::Stable => None,
        }
    }
}

/// The policy for one kind of project fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PredicatePolicy {
    /// The minimum authority required to *assert* a new fact of this fact.
    pub authority_floor: AuthorityLevel,
    /// The freshness applied to an assertion that does not set its own TTL. **Note:**
    /// `Ttl::Never` on an assertion is treated as "unset" and is replaced by this default
    /// when it is non-`Never` — there is currently no way for a caller to opt out of a
    /// default TTL (a known limitation; an explicit "never" sentinel is future work).
    pub default_ttl: Ttl,
    /// Whether at most one *fresh* fact about a given subject+predicate may be believed.
    pub unique: bool,
    /// How often facts of this predicate change. A [`Volatility::Volatile`] predicate caps a
    /// caller-supplied finite TTL at [`VOLATILE_RETENTION_CEILING_MS`] (unless `max_ttl`
    /// below overrides it); [`Volatility::Stable`] defers to the registry-wide ceiling. See
    /// [`enforce_policy`].
    pub volatility: Volatility,
    /// A per-predicate retention ceiling overriding the registry-wide default. `None` (the
    /// common case) falls back to [`PredicateRegistry`]'s global `max_ttl`. Set it to raise or
    /// tighten how far a caller-supplied finite TTL may reach for *this* predicate specifically
    /// — e.g. a volatile predicate might cap freshness at hours, a stable one relax it.
    pub max_ttl: Option<Ttl>,
}

/// A registry of [`PredicatePolicy`] keyed by the structured `(subject kind, predicate)`
/// pair — e.g. `("repo", "database")`. Keying on the pair (rather than a flattened
/// `"repo.database"` string) avoids any delimiter ambiguity when a kind or predicate
/// itself contains a dot.
#[derive(Clone, Debug)]
pub struct PredicateRegistry {
    policies: BTreeMap<(String, String), PredicatePolicy>,
    /// The registry-wide retention ceiling applied to predicates without their own
    /// [`PredicatePolicy::max_ttl`]. Defaults to `DurationMillis(DEFAULT_MAX_TTL_MS)`;
    /// overridable so an operator can widen or tighten the bounded-freshness window in one
    /// place. A `Ttl::Never` ceiling disables the finite-TTL cap entirely.
    max_ttl: Ttl,
}

impl Default for PredicateRegistry {
    fn default() -> Self {
        Self {
            policies: BTreeMap::new(),
            max_ttl: Ttl::DurationMillis(DEFAULT_MAX_TTL_MS),
        }
    }
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
                max_ttl: None,
            },
        );
    }

    /// The policy for a fact's `(subject.kind, predicate)`, if registered.
    #[must_use]
    pub fn policy_for(&self, subject: &Subject, predicate: &Predicate) -> Option<&PredicatePolicy> {
        self.policies
            .get(&(subject.kind().to_string(), predicate.as_str().to_string()))
    }

    /// The registry-wide retention ceiling. Consult [`PredicatePolicy::max_ttl`] first for a
    /// per-predicate override.
    #[must_use]
    pub fn max_ttl(&self) -> &Ttl {
        &self.max_ttl
    }

    /// Override the registry-wide retention ceiling (builder form). Pass `Ttl::Never` to
    /// disable the finite-TTL cap.
    #[must_use]
    pub fn with_max_ttl(mut self, max_ttl: Ttl) -> Self {
        self.max_ttl = max_ttl;
        self
    }

    /// Override the registry-wide retention ceiling in place.
    pub fn set_max_ttl(&mut self, max_ttl: Ttl) {
        self.max_ttl = max_ttl;
    }

    /// Set a per-predicate retention ceiling ([`PredicatePolicy::max_ttl`]) for an
    /// already-registered `(subject_kind, predicate)`. A no-op for an unregistered pair.
    pub fn set_predicate_max_ttl(
        &mut self,
        subject_kind: &str,
        predicate: &str,
        max_ttl: Option<Ttl>,
    ) {
        if let Some(policy) = self
            .policies
            .get_mut(&(subject_kind.to_string(), predicate.to_string()))
        {
            policy.max_ttl = max_ttl;
        }
    }
}

fn display_key(subject: &Subject, predicate: &Predicate) -> String {
    format!("{}.{}", subject.kind(), predicate.as_str())
}

/// The bounded (finite) freshness duration an assertion claims, in milliseconds, or `None`
/// when the TTL makes *no finite-freshness claim* (`Ttl::Never`) and is therefore out of
/// scope for the retention ceiling — the append-only event log keeps the fact regardless, so
/// a non-expiring belief is a separate concern from a far-reaching *finite* TTL. `ExpiresAt`
/// is anchored at the event's validity start (`valid_from`, else its recorded-at timestamp);
/// an instant at or before the anchor yields 0.
fn bounded_ttl_ms(candidate: &FactEvent) -> Option<u64> {
    match &candidate.ttl {
        Ttl::Never => None,
        Ttl::DurationMillis(duration) => Some(*duration),
        Ttl::ExpiresAt(at) => {
            let anchor = candidate
                .valid_from
                .unwrap_or(candidate.provenance.recorded_at);
            let delta = at.as_unix_millis().saturating_sub(anchor.as_unix_millis());
            Some(u64::try_from(delta).unwrap_or(0))
        }
    }
}

/// The finite cap a retention ceiling imposes, in milliseconds, or `None` for "no cap". A
/// ceiling is expressed as a duration (`DurationMillis`); `Ttl::Never` disables the cap, and
/// an absolute-instant ceiling (`ExpiresAt`) is not a meaningful reach bound and is treated
/// as no cap.
fn ceiling_ms(ceiling: &Ttl) -> Option<u64> {
    match ceiling {
        Ttl::DurationMillis(duration) => Some(*duration),
        Ttl::Never | Ttl::ExpiresAt(_) => None,
    }
}

/// Apply the registry's default freshness to an asserting event that left its TTL unset
/// (`Ttl::Never`). A no-op for unregistered predicates, non-assertions, or predicates
/// whose default is itself `Never`. See [`PredicatePolicy::default_ttl`] for the
/// `Never`-as-unset caveat.
pub fn apply_policy_defaults(registry: &PredicateRegistry, candidate: &mut FactEvent) {
    if let Some(policy) = registry.policy_for(&candidate.subject, &candidate.predicate)
        && matches!(candidate.kind, FactEventKind::Asserted)
        && candidate.ttl == Ttl::Never
    {
        candidate.ttl = policy.default_ttl.clone();
    }
}

/// Enforce the registry policy for `candidate` at time `now`:
///
/// - **Authority floor** — an *assertion* below the predicate's floor is rejected.
///   Contradiction and reinforcement are *not* gated (dissent must always be possible).
/// - **Retention ceiling** — an *assertion* whose caller-supplied *bounded* (finite) TTL
///   reaches further than the effective ceiling (per-predicate [`PredicatePolicy::max_ttl`]
///   else the registry global) is **rejected, not clamped**. `Ttl::Never` is out of scope.
/// - **Uniqueness** — a new assertion may not create a second *fresh* believed fact for
///   the same subject+predicate; stale (TTL-expired at `now`) facts do not block it.
///
/// The **retention ceiling applies to every predicate**, registered or not: an unregistered
/// predicate has no authority floor or uniqueness rule, but its caller-supplied finite TTL is
/// still bounded by the registry-wide global ceiling — closing the hole where an unknown
/// predicate could assert an arbitrarily far-future finite TTL. Run *before* the base firewall
/// (`EventStore::append`).
pub fn enforce_policy<S>(
    registry: &PredicateRegistry,
    store: &S,
    candidate: &FactEvent,
    now: TimestampMillis,
) -> Result<(), StoreError>
where
    S: EventStore + ?Sized,
{
    // May be `None` for an unregistered predicate: the floor and uniqueness rules below then
    // do not apply, but the global retention ceiling still does.
    let policy = registry.policy_for(&candidate.subject, &candidate.predicate);

    // The floor gates assertion of a new authoritative fact only — never dissent. Registered
    // predicates only (an unregistered predicate has no floor).
    if let Some(policy) = policy
        && matches!(candidate.kind, FactEventKind::Asserted)
        && candidate.authority.level < policy.authority_floor
    {
        return Err(StoreError::BelowAuthorityFloor {
            predicate: display_key(&candidate.subject, &candidate.predicate),
            floor: policy.authority_floor,
            actual: candidate.authority.level,
        });
    }

    // Retention ceiling: reject (never clamp) an assertion whose *bounded* TTL reaches
    // further than the effective ceiling. Precedence, most specific first:
    //   1. the predicate's explicit `max_ttl` override (an operator's deliberate choice),
    //   2. its **volatility** ceiling — a `Volatile` predicate caps at 7 days so a working
    //      belief cannot be claimed fresh for months (the classification made functional),
    //   3. the registry-wide global ceiling.
    // Registered predicates only reach (1)/(2); an unregistered predicate falls straight to
    // (3). Runs on assertions only; predicate-default TTLs are all below every ceiling, so
    // only a caller-supplied finite TTL can trip this. `Ttl::Never` is out of scope (see
    // `bounded_ttl_ms`), and a `Never` ceiling disables the cap at whichever level sets it.
    if matches!(candidate.kind, FactEventKind::Asserted) {
        let effective_ceiling = policy
            .and_then(|policy| policy.max_ttl.clone())
            .or_else(|| policy.and_then(|policy| policy.volatility.retention_ceiling()))
            .unwrap_or_else(|| registry.max_ttl.clone());
        if let (Some(ceiling_ms), Some(ttl_ms)) =
            (ceiling_ms(&effective_ceiling), bounded_ttl_ms(candidate))
            && ttl_ms > ceiling_ms
        {
            return Err(StoreError::TtlCeilingExceeded {
                predicate: display_key(&candidate.subject, &candidate.predicate),
                ttl_ms,
                ceiling_ms,
            });
        }
    }

    if let Some(policy) = policy
        && policy.unique
        && matches!(candidate.kind, FactEventKind::Asserted)
    {
        let filter = EventFilter {
            subject: Some(candidate.subject.clone()),
            predicate: Some(candidate.predicate.clone()),
            ..EventFilter::default()
        };
        let subject = replay_subject(&store.scan_events(&filter)?).map_err(StoreError::Replay)?;
        let conflict = subject
            .believed()
            .filter(|state| !state.is_expired_at(now))
            .any(|state| state.fact_id != candidate.fact_id);
        if conflict {
            return Err(StoreError::UniquenessViolation {
                predicate: display_key(&candidate.subject, &candidate.predicate),
            });
        }
    }

    Ok(())
}

/// Validate that an already-folded subject/predicate stream still satisfies registry
/// invariants. Async adapters use this *inside* the append transaction after applying a whole
/// multi-event batch: it rejects two silent fresh beliefs for a `unique` predicate, while still
/// allowing explicit contestation and atomic supersession batches whose final projection is
/// unique.
pub fn validate_unique_projection(
    registry: &PredicateRegistry,
    events: &[FactEvent],
    now: TimestampMillis,
) -> Result<(), StoreError> {
    let subject = replay_subject(events).map_err(StoreError::Replay)?;
    let fresh: Vec<_> = subject
        .believed()
        .filter(|state| !state.is_expired_at(now))
        .collect();
    let mut checked = BTreeSet::new();

    for state in &fresh {
        let key = (
            state.subject.kind().to_string(),
            state.subject.key().to_string(),
            state.predicate.as_str().to_string(),
        );
        if !checked.insert(key) {
            continue;
        }
        let Some(policy) = registry.policy_for(&state.subject, &state.predicate) else {
            continue;
        };
        if !policy.unique {
            continue;
        }
        let group: Vec<_> = fresh
            .iter()
            .copied()
            .filter(|other| other.subject == state.subject && other.predicate == state.predicate)
            .collect();
        if group.len() <= 1 {
            continue;
        }

        let mut accounted = Vec::new();
        for candidate in &group {
            if candidate.lifecycle == FactLifecycle::Contested {
                accounted.push(&candidate.fact_id);
                accounted.extend(candidate.contradicted_by.iter());
            }
        }
        if group
            .iter()
            .any(|candidate| !accounted.contains(&&candidate.fact_id))
        {
            return Err(StoreError::UniquenessViolation {
                predicate: display_key(&state.subject, &state.predicate),
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        PredicateRegistry, Volatility, apply_policy_defaults, enforce_policy,
        validate_unique_projection,
    };
    use crate::{EventStore, InMemoryEventStore, StoreError};
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, Confidence, ContradictionBasis, Evidence, EvidenceId,
        EvidenceKind, FactEvent, FactEventId, FactEventKind, FactId, FactValue, Predicate,
        Provenance, SourceId, Subject, TimestampMillis, TransitionError, Ttl,
    };

    const NOW: TimestampMillis = TimestampMillis::from_unix_millis(100);

    #[allow(clippy::too_many_arguments)]
    fn event(
        event_id: &str,
        fact_id: &str,
        subject_kind: &str,
        subject_key: &str,
        predicate: &str,
        kind: FactEventKind,
        value: Option<FactValue>,
        authority: AuthorityLevel,
    ) -> FactEvent {
        FactEvent {
            event_id: FactEventId::new(event_id).expect("event id"),
            fact_id: FactId::new(fact_id).expect("fact id"),
            kind,
            subject: Subject::new(subject_kind, subject_key).expect("subject"),
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
            valid_to: None,
        }
    }

    fn assertion(
        event_id: &str,
        fact_id: &str,
        subject_kind: &str,
        subject_key: &str,
        predicate: &str,
        value: &str,
        authority: AuthorityLevel,
    ) -> FactEvent {
        event(
            event_id,
            fact_id,
            subject_kind,
            subject_key,
            predicate,
            FactEventKind::Asserted,
            Some(FactValue::Text(value.to_string())),
            authority,
        )
    }

    #[test]
    fn final_unique_projection_rejects_silent_duplicate_beliefs() {
        let registry = PredicateRegistry::coding_agent();
        let events = vec![
            assertion(
                "e1",
                "fact:A",
                "repo",
                "myproj",
                "database",
                "postgres",
                AuthorityLevel::High,
            ),
            assertion(
                "e2",
                "fact:B",
                "repo",
                "myproj",
                "database",
                "mysql",
                AuthorityLevel::High,
            ),
        ];

        assert!(matches!(
            validate_unique_projection(&registry, &events, NOW),
            Err(StoreError::UniquenessViolation { .. })
        ));
    }

    #[test]
    fn final_unique_projection_allows_explicit_contestation() {
        let registry = PredicateRegistry::coding_agent();
        let events = vec![
            assertion(
                "e1",
                "fact:A",
                "repo",
                "myproj",
                "database",
                "postgres",
                AuthorityLevel::High,
            ),
            assertion(
                "e2",
                "fact:B",
                "repo",
                "myproj",
                "database",
                "mysql",
                AuthorityLevel::Low,
            ),
            event(
                "e3",
                "fact:A",
                "repo",
                "myproj",
                "database",
                FactEventKind::Contradicted {
                    by: FactId::new("fact:B").expect("fact id"),
                    basis: ContradictionBasis::SamePredicateDifferentValue,
                },
                None,
                AuthorityLevel::Low,
            ),
        ];

        validate_unique_projection(&registry, &events, NOW).expect("contestation is explicit");
    }

    fn admit(
        store: &mut InMemoryEventStore,
        registry: &PredicateRegistry,
        mut candidate: FactEvent,
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
                "fact:A",
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
                "fact:A",
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
            "fact:A",
            "repo",
            "myproj",
            "database",
            FactEventKind::Contradicted {
                by: FactId::new("fact:rumor").expect("fact id"),
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
                "fact:A",
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
            "fact:A",
            "repo",
            "myproj",
            "database",
            FactEventKind::Contradicted {
                by: FactId::new("fact:rumor").expect("fact id"),
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
                "fact:A",
                "repo",
                "myproj",
                "database",
                "postgres",
                AuthorityLevel::High,
            ),
            NOW,
        )
        .expect("first fact admitted");

        let result = admit(
            &mut store,
            &registry,
            assertion(
                "e2",
                "fact:B",
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
    fn a_stale_unique_fact_does_not_block_a_fresh_assertion() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        // branch.status carries a 1h default TTL; assert at recorded_at=1.
        admit(
            &mut store,
            &registry,
            assertion(
                "e1",
                "fact:A",
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
                "fact:B",
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
            "fact:A",
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
                "fact:A",
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
    fn an_unregistered_predicate_over_the_ceiling_is_rejected() {
        // Regression: an unregistered predicate used to short-circuit `enforce_policy` before
        // the retention ceiling, so a far-future *finite* TTL slipped through. It is now bound
        // by the registry-wide global ceiling like any other predicate.
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        let mut event = assertion(
            "e1",
            "fact:A",
            "fact",
            "mfa",
            "mfa_state",
            "disabled",
            AuthorityLevel::Low,
        );
        // One millisecond past the 90-day global ceiling.
        event.ttl = Ttl::DurationMillis(super::DEFAULT_MAX_TTL_MS + 1);
        let result = admit(&mut store, &registry, event, NOW);
        assert!(
            matches!(result, Err(StoreError::TtlCeilingExceeded { .. })),
            "an unregistered predicate past the global ceiling must be rejected, got {result:?}"
        );
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn an_unregistered_predicate_within_the_ceiling_is_admitted() {
        // The complement of the regression above: an unregistered predicate whose finite TTL
        // sits at/under the global ceiling is still admitted (no floor, no uniqueness rule).
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        let mut event = assertion(
            "e1",
            "fact:A",
            "fact",
            "mfa",
            "mfa_state",
            "disabled",
            AuthorityLevel::Low,
        );
        event.ttl = Ttl::DurationMillis(super::DEFAULT_MAX_TTL_MS);
        admit(&mut store, &registry, event, NOW)
            .expect("an unregistered predicate at the ceiling is admitted");
        assert_eq!(store.len(), 1);
    }

    fn timed_assertion(
        event_id: &str,
        fact_id: &str,
        ttl: Ttl,
        recorded_at: TimestampMillis,
    ) -> FactEvent {
        let mut event = assertion(
            event_id,
            fact_id,
            "repo",
            "myproj",
            "database",
            "postgres",
            AuthorityLevel::High,
        );
        event.ttl = ttl;
        event.provenance.recorded_at = recorded_at;
        event
    }

    #[test]
    fn a_bounded_ttl_over_the_ceiling_is_rejected() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        // One millisecond past the 90-day ceiling.
        let over = super::DEFAULT_MAX_TTL_MS + 1;
        let result = admit(
            &mut store,
            &registry,
            timed_assertion("e1", "fact:A", Ttl::DurationMillis(over), NOW),
            NOW,
        );
        assert!(
            matches!(result, Err(StoreError::TtlCeilingExceeded { .. })),
            "a duration past the ceiling must be rejected, got {result:?}"
        );
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn an_expires_at_over_the_ceiling_is_rejected() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        let anchor = TimestampMillis::from_unix_millis(1_000);
        // ExpiresAt reach = at - recorded_at; make it exceed the ceiling.
        let at = TimestampMillis::from_unix_millis(
            1_000 + i64::try_from(super::DEFAULT_MAX_TTL_MS).unwrap() + 1,
        );
        let result = admit(
            &mut store,
            &registry,
            timed_assertion("e1", "fact:A", Ttl::ExpiresAt(at), anchor),
            anchor,
        );
        assert!(
            matches!(result, Err(StoreError::TtlCeilingExceeded { .. })),
            "an ExpiresAt reaching past the ceiling must be rejected, got {result:?}"
        );
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn a_bounded_ttl_at_the_ceiling_is_admitted() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            timed_assertion(
                "e1",
                "fact:A",
                Ttl::DurationMillis(super::DEFAULT_MAX_TTL_MS),
                NOW,
            ),
            NOW,
        )
        .expect("a TTL exactly at the ceiling is admitted");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_never_ttl_is_never_capped() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            timed_assertion("e1", "fact:A", Ttl::Never, NOW),
            NOW,
        )
        .expect("Never makes no finite-freshness claim and is out of scope for the ceiling");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_predicate_default_ttl_passes_the_ceiling() {
        // branch.status carries a 1h default TTL applied by `apply_policy_defaults`, well
        // under the ceiling — the default path must never trip the cap.
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            assertion(
                "e1",
                "fact:A",
                "branch",
                "main",
                "status",
                "ci-green",
                AuthorityLevel::Low,
            ),
            NOW,
        )
        .expect("predicate-default TTL is under the ceiling");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_per_predicate_override_tightens_the_ceiling() {
        let mut registry = PredicateRegistry::coding_agent();
        // Tighten repo.database to a one-hour ceiling; a two-hour TTL must now be rejected
        // even though it is far below the 90-day global.
        registry.set_predicate_max_ttl("repo", "database", Some(Ttl::DurationMillis(3_600_000)));
        let mut store = InMemoryEventStore::new();
        let result = admit(
            &mut store,
            &registry,
            timed_assertion("e1", "fact:A", Ttl::DurationMillis(7_200_000), NOW),
            NOW,
        );
        assert!(
            matches!(result, Err(StoreError::TtlCeilingExceeded { .. })),
            "a per-predicate override must reject a TTL above it, got {result:?}"
        );

        // The same two-hour TTL is admitted for a predicate still on the 90-day global.
        let mut store = InMemoryEventStore::new();
        let mut event = assertion(
            "e2",
            "fact:B",
            "user",
            "me",
            "preference",
            "dark",
            AuthorityLevel::Medium,
        );
        event.ttl = Ttl::DurationMillis(7_200_000);
        admit(&mut store, &registry, event, NOW)
            .expect("a predicate on the global ceiling still admits the two-hour TTL");
    }

    #[test]
    fn a_global_override_can_relax_or_disable_the_ceiling() {
        // A `Never` global ceiling disables the finite-TTL cap.
        let registry = PredicateRegistry::coding_agent().with_max_ttl(Ttl::Never);
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            timed_assertion(
                "e1",
                "fact:A",
                Ttl::DurationMillis(super::DEFAULT_MAX_TTL_MS * 100),
                NOW,
            ),
            NOW,
        )
        .expect("a Never ceiling disables the cap");
        assert_eq!(store.len(), 1);
    }

    const THIRTY_DAYS_MS: u64 = 30 * 24 * 60 * 60 * 1000;

    fn volatile_assertion(ttl: Ttl) -> FactEvent {
        // dependency.version is Volatile (authority floor Medium) — assert at High to clear
        // the floor and isolate the volatility ceiling.
        let mut event = assertion(
            "e1",
            "fact:A",
            "dependency",
            "serde",
            "version",
            "1.0",
            AuthorityLevel::High,
        );
        event.ttl = ttl;
        event
    }

    #[test]
    fn a_volatile_predicate_caps_claimable_freshness_at_seven_days() {
        // A 30-day TTL exceeds the 7-day volatility ceiling (well under the 90-day global)
        // and is rejected, not clamped.
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        let error = admit(
            &mut store,
            &registry,
            volatile_assertion(Ttl::DurationMillis(THIRTY_DAYS_MS)),
            NOW,
        )
        .expect_err("a volatile predicate rejects a 30-day freshness claim");
        assert!(
            matches!(
                error,
                StoreError::TtlCeilingExceeded { ceiling_ms, .. }
                    if ceiling_ms == super::VOLATILE_RETENTION_CEILING_MS
            ),
            "expected the 7-day volatility ceiling, got {error:?}"
        );
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn a_volatile_predicate_admits_freshness_within_the_ceiling() {
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            volatile_assertion(Ttl::DurationMillis(
                super::VOLATILE_RETENTION_CEILING_MS / 2,
            )),
            NOW,
        )
        .expect("a claim within the 7-day volatility ceiling is admitted");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_stable_predicate_is_not_bound_by_the_volatile_ceiling() {
        // repo.database is Stable: a 30-day claim is fine (only the 90-day global applies).
        let registry = PredicateRegistry::coding_agent();
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            timed_assertion("e1", "fact:A", Ttl::DurationMillis(THIRTY_DAYS_MS), NOW),
            NOW,
        )
        .expect("a stable predicate is not capped at the volatile 7-day ceiling");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_per_predicate_max_ttl_overrides_the_volatile_ceiling() {
        // An explicit per-predicate override wins over volatility: relaxing
        // dependency.version to `Never` lets a 30-day claim through.
        let mut registry = PredicateRegistry::coding_agent();
        registry.set_predicate_max_ttl("dependency", "version", Some(Ttl::Never));
        let mut store = InMemoryEventStore::new();
        admit(
            &mut store,
            &registry,
            volatile_assertion(Ttl::DurationMillis(THIRTY_DAYS_MS)),
            NOW,
        )
        .expect("an explicit per-predicate max_ttl override beats the volatility ceiling");
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
            let subject = Subject::new(kind, "x").unwrap();
            let pred = Predicate::new(predicate).unwrap();
            assert!(
                registry.policy_for(&subject, &pred).is_some(),
                "{kind}.{predicate} should be registered"
            );
        }
        assert_eq!(Volatility::Stable, Volatility::Stable);
    }
}
