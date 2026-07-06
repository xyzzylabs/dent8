use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use dent8_core::{
    AuthorityLevel, EpistemicPolicy, FactEvent, FactEventId, FactEventKind, FactId, FactLifecycle,
    FactState, FactValue, Predicate, Subject, TransitionError, apply_event,
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
    pub event_id: FactEventId,
    pub event_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct EventFilter {
    pub fact_id: Option<FactId>,
    pub subject: Option<Subject>,
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
    fn append(&mut self, event: FactEvent) -> Result<AppendReceipt, StoreError>;
    fn load_fact_events(&self, fact_id: &FactId) -> Result<Vec<FactEvent>, StoreError>;
    fn scan_events(&self, filter: &EventFilter) -> Result<Vec<FactEvent>, StoreError>;
}

/// The **async** counterpart to [`EventStore`], for backends that do network or embedded-DB
/// I/O (Postgres, `SQLite` via `sqlx`, …). It carries the same firewall contract: every
/// implementation MUST arbitrate each candidate ([`arbitrate_events`]) **inside its
/// transaction** before persisting — there is no un-arbitrated write path.
///
/// [`append_many`](AsyncEventStore::append_many) is the integrity-critical primitive: a
/// multi-event operation (a supersession's replacement + its supersessions, a contradiction's
/// opposing fact + edge) must commit **atomically** — all events arbitrate and land, or none
/// do. The trait therefore *requires* it rather than deriving it from single `append`, so a
/// backend cannot accidentally offer a non-atomic batch path.
///
/// Construction is backend-specific (each parses its own URL and deploys its own schema), so
/// it is deliberately **not** on the trait — see the CLI's `connect_backend`. Sync backends
/// (the file/in-memory dev store) stay on [`EventStore`]; the two are bridged at the call edge
/// (`block_on`), not unified, because the file store is genuinely synchronous I/O.
///
/// The trait is `?Send` (`async_trait(?Send)`): the CLI/MCP drive it on a **current-thread**
/// `block_on`, which never moves the futures across threads, and dropping the `Send` bound
/// sidesteps `sqlx`'s "Executor is not general enough" higher-ranked-lifetime wall. A future
/// multi-threaded server would need a `Send` variant (or native `async fn` in traits).
#[cfg(feature = "async-store")]
#[async_trait::async_trait(?Send)]
pub trait AsyncEventStore {
    /// Deploy the schema this backend needs (idempotent).
    async fn migrate(&self) -> Result<(), StoreError>;
    /// Append one candidate through the firewall (a one-element [`append_many`](Self::append_many)).
    async fn append(&self, event: FactEvent) -> Result<AppendReceipt, StoreError>;
    /// Append a whole operation **atomically**: every event arbitrates and commits, or none do.
    async fn append_many(&self, events: Vec<FactEvent>) -> Result<Vec<AppendReceipt>, StoreError>;
    /// Ordered events for one fact stream.
    async fn load_fact_events(&self, fact_id: &FactId) -> Result<Vec<FactEvent>, StoreError>;
    /// Events matching a filter, in global order.
    async fn scan_events(&self, filter: &EventFilter) -> Result<Vec<FactEvent>, StoreError>;
    /// Re-verify the stored global hash chain — `false` if a stored event was altered.
    async fn verify_chain(&self) -> Result<bool, StoreError>;
}

/// Fold an ordered fact-event stream into its current projected state. Strict: a
/// stream that does not start with `fact.asserted` surfaces the transition error.
pub fn replay_fact(events: &[FactEvent]) -> Result<Option<FactState>, ReplayError> {
    replay_fact_with_policy(events, &EpistemicPolicy::identity())
}

/// Re-fold a fact-event stream under an [`EpistemicPolicy`]. Non-admitted events are
/// skipped as if they never occurred; if the *asserting* event is filtered out the
/// fact is absent (`Ok(None)`) under this policy.
///
/// Freshness is intentionally *not* applied here — it is a separate read-time axis
/// ([`FactState::is_expired_at`]) so valid-time staleness is never conflated with the
/// event-driven lifecycle.
///
/// With [`EpistemicPolicy::identity`] this is identical to [`replay_fact`], so it is
/// a strict superset: callers can compare a baseline replay against a counterfactual
/// one with [`diff_states`].
pub fn replay_fact_with_policy(
    events: &[FactEvent],
    policy: &EpistemicPolicy,
) -> Result<Option<FactState>, ReplayError> {
    let refs: Vec<&FactEvent> = events.iter().collect();
    fold_fact(&refs, policy)
}

/// Fold a single fact stream (events for one `fact_id`, in order) under a policy.
fn fold_fact(
    events: &[&FactEvent],
    policy: &EpistemicPolicy,
) -> Result<Option<FactState>, ReplayError> {
    // True only when an asserting event exists but the policy filters it out. This
    // distinguishes "the assertion was distrusted" (fact absent) from "the stream is
    // malformed and never had an assertion" (let the strict error surface, exactly as
    // plain replay would). Under the identity policy nothing is filtered, so this is
    // always false and behaviour is unchanged.
    let assertion_filtered = events
        .iter()
        .any(|event| matches!(event.kind, FactEventKind::Asserted) && !policy.admits(event));

    let mut state: Option<FactState> = None;
    for &event in events {
        if !policy.admits(event) {
            continue;
        }
        if state.is_none() && assertion_filtered && !matches!(event.kind, FactEventKind::Asserted) {
            return Ok(None);
        }
        state = Some(apply_event(state.take(), event).map_err(ReplayError::Transition)?);
    }

    Ok(state)
}

/// A projection of every fact stream for one subject, folded independently and keyed
/// by `fact_id`. Built by [`replay_subject`] (or [`replay_subject_with_policy`]) from
/// the subject's events in global order. Unlike per-fact replay, this view enables
/// cross-stream checks such as [`SubjectProjection::lineage_issues`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubjectProjection {
    pub facts: BTreeMap<FactId, FactState>,
}

impl SubjectProjection {
    #[must_use]
    pub fn get(&self, fact_id: &FactId) -> Option<&FactState> {
        self.facts.get(fact_id)
    }

    /// The facts currently believed (lifecycle `Active` or `Contested`). Freshness
    /// (TTL) is a separate read-time axis ([`FactState::is_expired_at`]) and is not
    /// applied here.
    pub fn believed(&self) -> impl Iterator<Item = &FactState> {
        self.facts
            .values()
            .filter(|state| !state.lifecycle.is_terminal())
    }

    /// The facts currently in conflict (lifecycle `Contested`).
    pub fn contested(&self) -> impl Iterator<Item = &FactState> {
        self.facts
            .values()
            .filter(|state| state.lifecycle == FactLifecycle::Contested)
    }

    /// Cross-stream supersession-lineage problems:
    ///
    /// - [`LineageIssue::DanglingSupersession`] — superseded by a fact absent from
    ///   the subject;
    /// - [`LineageIssue::SupersededByInvalidated`] — superseded by a fact that has
    ///   itself been retracted or closed by a `fact.expired` event (an intact
    ///   `A -> B -> C` chain where `B` is merely `Superseded` is *not* an issue);
    /// - [`LineageIssue::SupersessionCycle`] — the fact lies on a supersession cycle
    ///   (including self-supersession), so no terminal believed successor exists.
    ///
    /// Out of scope here: read-time TTL staleness of a successor is *not* flagged
    /// (freshness is a separate axis — combine with [`FactState::is_expired_at`]), and
    /// contradiction edges are not checked, because a contradictor may legitimately
    /// live in another subject.
    #[must_use]
    pub fn lineage_issues(&self) -> Vec<LineageIssue> {
        let on_cycle = self.supersession_cycle_members();
        let mut issues = Vec::new();
        for state in self.facts.values() {
            if on_cycle.contains(&state.fact_id) {
                issues.push(LineageIssue::SupersessionCycle {
                    fact: state.fact_id.clone(),
                });
                continue;
            }
            let Some(target) = &state.superseded_by else {
                continue;
            };
            match self.facts.get(target) {
                None => issues.push(LineageIssue::DanglingSupersession {
                    fact: state.fact_id.clone(),
                    target: target.clone(),
                }),
                Some(t)
                    if matches!(
                        t.lifecycle,
                        FactLifecycle::Retracted | FactLifecycle::Expired
                    ) =>
                {
                    issues.push(LineageIssue::SupersededByInvalidated {
                        fact: state.fact_id.clone(),
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
    /// replacing fact's actual state (not just the supersession event's stated
    /// authority). This is the subject-level entrenchment audit — defense-in-depth over
    /// the per-stream authority gate in `apply_event`, which can only trust the
    /// supersession event's facted authority. Two cases:
    ///
    /// - [`UnearnedSupersession::AuthorityDowngrade`] — the replacing fact is actually
    ///   *lower* authority than the one it replaced (the event must have overstated its
    ///   authority to pass the per-stream gate);
    /// - [`UnearnedSupersession::WeakerEntrenchment`] — at equal authority, the replacing
    ///   fact has *less authority-weighted earned entrenchment* — corroboration plus
    ///   survived challenges (ADR 0017) — than the incumbent (measured by
    ///   [`FactState::earned_entrenchment_at_or_above`] at their shared authority level, so
    ///   a Sybil flood of low-authority sources or challenges cannot mask it). This is the
    ///   same measure the opt-in write-time gate uses, so the audit and the gate agree.
    ///
    /// Semantics: this is a **current-state advisory**, not a stable at-supersession
    /// verdict. The incumbent's entrenchment is frozen (the terminal guard blocks
    /// reinforcing a superseded fact), but the replacement's keeps accruing, so a
    /// `WeakerEntrenchment` flag clears if the replacement later earns enough standing.
    /// Read it as "the replacement *still* has weaker entrenchment than what it displaced."
    ///
    /// Scope: only supersessions whose target is present *in this subject* are judged (a
    /// dangling target is a [`LineageIssue`]; a target in another subject is not seen).
    /// Cyclic supersessions are skipped (handled by [`SubjectProjection::lineage_issues`]).
    #[must_use]
    pub fn unearned_supersessions(&self) -> Vec<UnearnedSupersession> {
        let on_cycle = self.supersession_cycle_members();
        let mut out = Vec::new();
        for state in self.facts.values() {
            if on_cycle.contains(&state.fact_id) {
                continue;
            }
            let Some(target) = &state.superseded_by else {
                continue;
            };
            let Some(by) = self.facts.get(target) else {
                continue;
            };
            if by.authority.level < state.authority.level {
                out.push(UnearnedSupersession::AuthorityDowngrade {
                    superseded: state.fact_id.clone(),
                    by: target.clone(),
                    incumbent: state.authority.level,
                    challenger: by.authority.level,
                });
            } else if by.authority.level == state.authority.level {
                let level = state.authority.level;
                let incumbent = state.earned_entrenchment_at_or_above(level);
                let challenger = by.earned_entrenchment_at_or_above(level);
                if challenger < incumbent {
                    out.push(UnearnedSupersession::WeakerEntrenchment {
                        superseded: state.fact_id.clone(),
                        by: target.clone(),
                        incumbent_entrenchment: incumbent,
                        challenger_entrenchment: challenger,
                    });
                }
            }
        }
        out
    }

    /// The facts lying on a supersession cycle (including self-supersession), found by
    /// following `superseded_by` edges within the subject. Single traversal per start
    /// with a visited index, so cycles cannot loop.
    fn supersession_cycle_members(&self) -> BTreeSet<FactId> {
        let mut on_cycle = BTreeSet::new();
        for start in self.facts.keys() {
            if on_cycle.contains(start) {
                continue;
            }
            let mut index: BTreeMap<FactId, usize> = BTreeMap::new();
            let mut path: Vec<FactId> = Vec::new();
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
                match self.facts.get(&node).and_then(|s| s.superseded_by.as_ref()) {
                    Some(next) if self.facts.contains_key(next) => node = next.clone(),
                    _ => break,
                }
            }
        }
        on_cycle
    }
}

/// A cross-stream supersession-lineage defect found by [`SubjectProjection::lineage_issues`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LineageIssue {
    /// `fact` is superseded by `target`, but no such fact exists in the subject.
    DanglingSupersession { fact: FactId, target: FactId },
    /// `fact` is superseded by `target`, but `target` has itself been invalidated by a
    /// retraction or a `fact.expired` event, orphaning the lineage.
    SupersededByInvalidated {
        fact: FactId,
        target: FactId,
        target_lifecycle: FactLifecycle,
    },
    /// `fact` lies on a supersession cycle (`A -> A`, `A -> B -> A`, …), so the
    /// lineage never resolves to a believed successor.
    SupersessionCycle { fact: FactId },
}

/// A supersession that did not earn its replacement, found by
/// [`SubjectProjection::unearned_supersessions`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnearnedSupersession {
    /// `superseded` was replaced by `by`, but `by` is actually lower authority — the
    /// supersession event must have overstated its authority to pass the per-stream gate.
    AuthorityDowngrade {
        superseded: FactId,
        by: FactId,
        incumbent: AuthorityLevel,
        challenger: AuthorityLevel,
    },
    /// `superseded` was replaced by `by` at equal authority, but `by` has weaker
    /// authority-weighted **earned entrenchment** — corroboration plus survived challenges,
    /// at or above the shared authority level (ADR 0017) — than the fact it replaced.
    WeakerEntrenchment {
        superseded: FactId,
        by: FactId,
        incumbent_entrenchment: usize,
        challenger_entrenchment: usize,
    },
}

/// Replay every fact stream for one subject (events in global order) into an
/// [`SubjectProjection`]. Strict, like [`replay_fact`].
pub fn replay_subject(events: &[FactEvent]) -> Result<SubjectProjection, ReplayError> {
    replay_subject_with_policy(events, &EpistemicPolicy::identity())
}

/// A still-believed fact that transitively derives (`EvidenceKind::DerivedFrom`, ADR 0010)
/// from a fact now in a terminal *invalidated* lifecycle (`Retracted`/`Expired`) — i.e. poison
/// (or a removed source) that survived in a derivative. `root` is an invalidated source the
/// taint traces to.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaintedFact {
    pub fact: FactId,
    pub root: FactId,
    pub root_lifecycle: FactLifecycle,
}

/// Cross-subject retraction-taint analysis over the **whole** log: fold every fact stream to
/// its lifecycle and collect its `DerivedFrom` dependency edges, then report each
/// *still-believed* fact that transitively depends on an invalidated (`Retracted`/`Expired`)
/// source. This is the read-side "poison does not survive in derivatives" check (ADR 0010) —
/// computed on replay, never written, and cross-subject (a dependency may live in another
/// subject's stream).
pub fn tainted_facts(events: &[FactEvent]) -> Result<Vec<TaintedFact>, ReplayError> {
    // Group by fact id — independent of subject, since a dependency edge may cross subjects.
    let mut streams: BTreeMap<FactId, Vec<&FactEvent>> = BTreeMap::new();
    for event in events {
        streams
            .entry(event.fact_id.clone())
            .or_default()
            .push(event);
    }
    let mut lifecycle: BTreeMap<FactId, FactLifecycle> = BTreeMap::new();
    let mut deps: BTreeMap<FactId, Vec<FactId>> = BTreeMap::new();
    for (fact, stream) in &streams {
        let mut state: Option<FactState> = None;
        let mut edges = Vec::new();
        for &event in stream {
            edges.extend(event.dependency_edges());
            state = Some(apply_event(state.take(), event).map_err(ReplayError::Transition)?);
        }
        if let Some(state) = state {
            lifecycle.insert(fact.clone(), state.lifecycle);
        }
        deps.insert(fact.clone(), edges);
    }
    let invalidated = |fact: &FactId| {
        matches!(
            lifecycle.get(fact),
            Some(FactLifecycle::Retracted | FactLifecycle::Expired)
        )
    };
    let mut tainted = Vec::new();
    for (fact, life) in &lifecycle {
        // Only a *still-believed* derivative is surviving poison; a terminal one is fine.
        if life.is_terminal() {
            continue;
        }
        if let Some(root) = an_invalidated_root(fact, &deps, &invalidated) {
            let root_lifecycle = lifecycle[&root];
            tainted.push(TaintedFact {
                fact: fact.clone(),
                root,
                root_lifecycle,
            });
        }
    }
    Ok(tainted)
}

/// Depth-first search from `fact` over `DerivedFrom` edges for an invalidated source.
/// Cycle-safe (a `seen` set), so a dependency cycle terminates.
fn an_invalidated_root(
    fact: &FactId,
    deps: &BTreeMap<FactId, Vec<FactId>>,
    invalidated: &impl Fn(&FactId) -> bool,
) -> Option<FactId> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<FactId> = deps.get(fact).cloned().unwrap_or_default();
    while let Some(next) = stack.pop() {
        if !seen.insert(next.clone()) {
            continue;
        }
        if invalidated(&next) {
            return Some(next);
        }
        if let Some(further) = deps.get(&next) {
            stack.extend(further.iter().cloned());
        }
    }
    None
}

/// Subject-level [`replay_subject`] under an [`EpistemicPolicy`]: each stream is folded
/// under the policy, so a distrusted source can make whole facts absent from the
/// subject view — the multi-fact counterfactual surface.
pub fn replay_subject_with_policy(
    events: &[FactEvent],
    policy: &EpistemicPolicy,
) -> Result<SubjectProjection, ReplayError> {
    let mut streams: BTreeMap<FactId, Vec<&FactEvent>> = BTreeMap::new();
    for event in events {
        streams
            .entry(event.fact_id.clone())
            .or_default()
            .push(event);
    }

    let mut facts = BTreeMap::new();
    for (fact_id, stream) in streams {
        if let Some(state) = fold_fact(&stream, policy)? {
            facts.insert(fact_id, state);
        }
    }

    Ok(SubjectProjection { facts })
}

/// The structural difference between a baseline projection and a counterfactual one,
/// computed by [`diff_states`]. Powers "what changes if I distrust source X / raise
/// the authority or confidence floor" queries over the same log.
///
/// The comparison covers the belief-relevant fields that can vary between two folds of
/// the *same* fact stream: lifecycle, value, supersession target, contradiction
/// edges, and evidence count. Fields invariant within a stream (fact id, subject,
/// predicate, authority, ttl) are not compared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateDiff {
    /// Both projections are absent, or equal on every compared field.
    Unchanged,
    /// The fact is absent in the baseline but present in the counterfactual.
    Appeared,
    /// The fact is present in the baseline but absent in the counterfactual (e.g. its
    /// asserting source was distrusted).
    Disappeared,
    /// The fact is present in both but differs. Each field is `Some((base, cf))` only
    /// when it changed.
    Changed {
        lifecycle: Option<(FactLifecycle, FactLifecycle)>,
        value: Option<(FactValue, FactValue)>,
        superseded_by: Option<(Option<FactId>, Option<FactId>)>,
        contradicted_by: Option<(Vec<FactId>, Vec<FactId>)>,
        evidence_count: Option<(usize, usize)>,
    },
}

/// Compare a baseline projection against a counterfactual one (both folded from the
/// same log, under different policies). The arguments read base-then-counterfactual.
#[must_use]
pub fn diff_states(base: Option<&FactState>, counterfactual: Option<&FactState>) -> StateDiff {
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
    /// The firewall rejected the write: the per-fact transition was inadmissible
    /// (validation, insufficient *stated* authority, canonical contradiction, terminal
    /// mutation, duplicate assertion).
    Rejected(TransitionError),
    /// The firewall rejected a supersession because the *replacing fact's actual*
    /// authority is below the incumbent's — i.e. an over-stated-authority supersession
    /// (authority laundering).
    LaunderedAuthority {
        incumbent: AuthorityLevel,
        challenger: AuthorityLevel,
    },
    /// The firewall rejected a supersession whose replacing fact does not exist in the
    /// store, so its authority cannot be verified.
    UnbackedSupersession(FactId),
    /// A registered predicate's policy rejected the write: its authority is below the
    /// predicate's floor.
    BelowAuthorityFloor {
        predicate: String,
        floor: AuthorityLevel,
        actual: AuthorityLevel,
    },
    /// A registered predicate's uniqueness policy rejected the write: another fact about
    /// this subject+predicate is already believed (supersede it instead of asserting).
    UniquenessViolation {
        predicate: String,
    },
    /// Replaying the existing fact stream failed.
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
                "firewall rejected the write: supersession by a weaker fact \
                 (challenger {challenger:?} is below incumbent {incumbent:?})"
            ),
            Self::UnbackedSupersession(fact) => write!(
                f,
                "firewall rejected the write: superseding fact {fact} does not exist"
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
                "policy rejected the write: {predicate} already has a believed fact (supersede it)"
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
        LineageIssue, StateDiff, UnearnedSupersession, diff_states, replay_fact,
        replay_fact_with_policy, replay_subject, replay_subject_with_policy, tainted_facts,
    };
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, ChallengeKind, ChallengeRejection, Confidence,
        EpistemicPolicy, Evidence, EvidenceId, EvidenceKind, FactEvent, FactEventId, FactEventKind,
        FactId, FactLifecycle, FactValue, Predicate, Provenance, RetractionReason, SourceId,
        Subject, SupersessionReason, TimestampMillis, Ttl,
    };

    #[allow(clippy::too_many_arguments)]
    fn ev(
        event_id: &str,
        kind: FactEventKind,
        value: Option<FactValue>,
        source: &str,
        authority: AuthorityLevel,
        confidence_millis: u16,
        ttl: Ttl,
        valid_from: Option<TimestampMillis>,
    ) -> FactEvent {
        FactEvent {
            event_id: FactEventId::new(event_id).expect("event id"),
            fact_id: FactId::new("fact:1").expect("fact id"),
            kind,
            subject: Subject::new("repo", "dent8").expect("subject"),
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
            valid_from,
            valid_to: None,
        }
    }

    fn assert_from(event_id: &str, source: &str, authority: AuthorityLevel) -> FactEvent {
        ev(
            event_id,
            FactEventKind::Asserted,
            Some(FactValue::Text("postgres".to_string())),
            source,
            authority,
            900,
            Ttl::Never,
            None,
        )
    }

    /// An event on `fact_id` (its own subject `repo:{fact_id}`), carrying a `DerivedFrom`
    /// evidence item per id in `derived_from` (the dependency edges, ADR 0010).
    fn taint_ev(
        event_id: &str,
        fact_id: &str,
        kind: FactEventKind,
        derived_from: &[&str],
    ) -> FactEvent {
        let mut evidence = vec![Evidence {
            id: EvidenceId::new("evidence:base").expect("evidence id"),
            kind: EvidenceKind::UserStatement,
            locator: "x".to_string(),
            digest: None,
            summary: None,
        }];
        for (index, source) in derived_from.iter().enumerate() {
            evidence.push(Evidence {
                id: EvidenceId::new(format!("evidence:dep:{index}")).expect("evidence id"),
                kind: EvidenceKind::DerivedFrom,
                locator: (*source).to_string(),
                digest: None,
                summary: None,
            });
        }
        FactEvent {
            event_id: FactEventId::new(event_id).expect("event id"),
            fact_id: FactId::new(fact_id).expect("fact id"),
            kind,
            subject: Subject::new("repo", fact_id).expect("subject"),
            predicate: Predicate::new("fact").expect("predicate"),
            value: Some(FactValue::Text("v".to_string())),
            confidence: Confidence::from_millis(900).expect("confidence"),
            authority: Authority {
                level: AuthorityLevel::High,
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
            evidence,
            observed_at: None,
            valid_from: None,
            valid_to: None,
        }
    }

    #[test]
    fn retracting_a_poisoned_source_taints_its_derivative() {
        // fact:derived was derived from fact:source; retract the (poisoned) source.
        let source = taint_ev("event:1", "fact:source", FactEventKind::Asserted, &[]);
        let derived = taint_ev(
            "event:2",
            "fact:derived",
            FactEventKind::Asserted,
            &["fact:source"],
        );
        let retract = taint_ev(
            "event:3",
            "fact:source",
            FactEventKind::Retracted {
                reason: RetractionReason::PoisoningDetected,
            },
            &[],
        );

        // Before retraction: nothing tainted (the source is still believed).
        let clean = tainted_facts(&[source.clone(), derived.clone()]).expect("taint");
        assert!(clean.is_empty(), "no taint while the source stands");

        // After retraction: the still-believed derivative is flagged, tracing to the source.
        let log = [source, derived, retract];
        let tainted = tainted_facts(&log).expect("taint");
        assert_eq!(tainted.len(), 1, "the derivative is tainted");
        assert_eq!(tainted[0].fact.as_str(), "fact:derived");
        assert_eq!(tainted[0].root.as_str(), "fact:source");
        assert_eq!(tainted[0].root_lifecycle, FactLifecycle::Retracted);
    }

    #[test]
    fn taint_is_transitive_and_cycle_safe() {
        // c <- b <- a (a poisoned); c must be tainted transitively. Plus a self-edge to prove
        // the DFS terminates on a cycle.
        let a = taint_ev("event:1", "fact:a", FactEventKind::Asserted, &[]);
        let b = taint_ev("event:2", "fact:b", FactEventKind::Asserted, &["fact:a"]);
        let c = taint_ev(
            "event:3",
            "fact:c",
            FactEventKind::Asserted,
            &["fact:b", "fact:c"], // self-edge -> cycle guard
        );
        let retract_a = taint_ev(
            "event:4",
            "fact:a",
            FactEventKind::Retracted {
                reason: RetractionReason::SourceInvalidated,
            },
            &[],
        );
        let tainted = tainted_facts(&[a, b, c, retract_a]).expect("taint");
        let names: std::collections::BTreeSet<&str> =
            tainted.iter().map(|t| t.fact.as_str()).collect();
        assert!(names.contains("fact:b"), "direct derivative tainted");
        assert!(names.contains("fact:c"), "transitive derivative tainted");
    }

    fn supersede_from(event_id: &str, source: &str, authority: AuthorityLevel) -> FactEvent {
        ev(
            event_id,
            FactEventKind::Superseded {
                by: FactId::new("fact:2").expect("fact id"),
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

    fn contradict_from(event_id: &str, by: &str, source: &str) -> FactEvent {
        ev(
            event_id,
            FactEventKind::Contradicted {
                by: FactId::new(by).expect("fact id"),
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

        let plain = replay_fact(&events).expect("replay");
        let policied =
            replay_fact_with_policy(&events, &EpistemicPolicy::identity()).expect("replay");

        assert_eq!(plain, policied);
        assert_eq!(plain.expect("state").lifecycle, FactLifecycle::Superseded);
    }

    #[test]
    fn distrusting_the_superseding_source_keeps_the_fact_active() {
        let events = [
            assert_from("event:1", "source:owner", AuthorityLevel::High),
            supersede_from("event:2", "source:web-scrape", AuthorityLevel::High),
        ];

        let base = replay_fact(&events).expect("replay");
        let counterfactual = replay_fact_with_policy(&events, &distrust("source:web-scrape"))
            .expect("counterfactual replay");

        assert_eq!(
            base.as_ref().expect("base").lifecycle,
            FactLifecycle::Superseded
        );
        assert_eq!(
            counterfactual.as_ref().expect("cf").lifecycle,
            FactLifecycle::Active,
        );
        assert_eq!(
            diff_states(base.as_ref(), counterfactual.as_ref()),
            StateDiff::Changed {
                lifecycle: Some((FactLifecycle::Superseded, FactLifecycle::Active)),
                value: None,
                superseded_by: Some((Some(FactId::new("fact:2").unwrap()), None)),
                contradicted_by: None,
                evidence_count: None,
            }
        );
    }

    #[test]
    fn distrusting_the_asserting_source_makes_the_fact_disappear() {
        let events = [
            assert_from("event:1", "source:web-scrape", AuthorityLevel::High),
            supersede_from("event:2", "source:owner", AuthorityLevel::High),
        ];

        let base = replay_fact(&events).expect("replay");
        let counterfactual = replay_fact_with_policy(&events, &distrust("source:web-scrape"))
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

        assert!(replay_fact(&events).expect("replay").is_some());
        assert!(
            replay_fact_with_policy(&events, &policy)
                .expect("policied replay")
                .is_none()
        );
    }

    #[test]
    fn raising_the_confidence_floor_filters_a_low_confidence_assertion() {
        let events = [ev(
            "event:1",
            FactEventKind::Asserted,
            Some(FactValue::Text("postgres".to_string())),
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

        assert!(replay_fact(&events).expect("replay").is_some());
        assert!(
            replay_fact_with_policy(&events, &policy)
                .expect("policied replay")
                .is_none()
        );
    }

    #[test]
    fn freshness_is_a_read_time_predicate_separate_from_lifecycle() {
        let events = [ev(
            "event:1",
            FactEventKind::Asserted,
            Some(FactValue::Text("postgres".to_string())),
            "source:owner",
            AuthorityLevel::High,
            900,
            Ttl::ExpiresAt(TimestampMillis::from_unix_millis(100)),
            Some(TimestampMillis::from_unix_millis(10)),
        )];

        let state = replay_fact(&events).expect("replay").expect("state");

        // Lifecycle is untouched by freshness — it stays Active (event-driven only).
        assert_eq!(state.lifecycle, FactLifecycle::Active);
        // Freshness is a separate read-time verdict against a valid-time clock.
        assert!(!state.is_expired_at(TimestampMillis::from_unix_millis(50)));
        assert!(state.is_expired_at(TimestampMillis::from_unix_millis(200)));
    }

    #[test]
    fn distrusting_a_contradictor_drops_the_contradiction_edge() {
        let events = [
            assert_from("event:1", "source:owner", AuthorityLevel::High),
            contradict_from("event:2", "fact:2", "source:rumor"),
            contradict_from("event:3", "fact:3", "source:owner"),
        ];

        let base = replay_fact(&events).expect("replay");
        let counterfactual =
            replay_fact_with_policy(&events, &distrust("source:rumor")).expect("counterfactual");

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
                        FactId::new("fact:2").unwrap(),
                        FactId::new("fact:3").unwrap()
                    ],
                    vec![FactId::new("fact:3").unwrap()],
                )),
                evidence_count: None,
            }
        );
    }

    #[test]
    fn diff_of_identical_projections_is_unchanged() {
        let events = [assert_from("event:1", "source:owner", AuthorityLevel::High)];
        let a = replay_fact(&events).expect("replay");
        let b = replay_fact_with_policy(&events, &EpistemicPolicy::identity()).expect("replay");
        assert_eq!(diff_states(a.as_ref(), b.as_ref()), StateDiff::Unchanged);
    }

    // ---- subject-level replay & cross-stream lineage ----

    fn with_fact(mut event: FactEvent, fact_id: &str) -> FactEvent {
        event.fact_id = FactId::new(fact_id).expect("fact id");
        event
    }

    fn assert_in(event_id: &str, fact_id: &str, source: &str) -> FactEvent {
        with_fact(assert_from(event_id, source, AuthorityLevel::High), fact_id)
    }

    fn supersede_in(event_id: &str, fact_id: &str, by: &str, source: &str) -> FactEvent {
        with_fact(
            ev(
                event_id,
                FactEventKind::Superseded {
                    by: FactId::new(by).expect("fact id"),
                    reason: SupersessionReason::NewerObservation,
                },
                None,
                source,
                AuthorityLevel::High,
                900,
                Ttl::Never,
                None,
            ),
            fact_id,
        )
    }

    fn retract_in(event_id: &str, fact_id: &str) -> FactEvent {
        with_fact(
            ev(
                event_id,
                FactEventKind::Retracted {
                    reason: RetractionReason::SourceInvalidated,
                },
                None,
                "source:owner",
                AuthorityLevel::High,
                900,
                Ttl::Never,
                None,
            ),
            fact_id,
        )
    }

    fn challenge_rejected_in(
        event_id: &str,
        fact_id: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> FactEvent {
        with_fact(
            ev(
                event_id,
                FactEventKind::ChallengeRejected {
                    challenge: ChallengeKind::Supersession,
                    by: None,
                    rejection: ChallengeRejection::InsufficientAuthority,
                },
                None,
                source,
                authority,
                900,
                Ttl::Never,
                None,
            ),
            fact_id,
        )
    }

    fn fact(id: &str) -> FactId {
        FactId::new(id).expect("fact id")
    }

    fn assert_in_auth(
        event_id: &str,
        fact_id: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> FactEvent {
        with_fact(assert_from(event_id, source, authority), fact_id)
    }

    fn reinforce_in(event_id: &str, fact_id: &str, source: &str) -> FactEvent {
        reinforce_in_auth(event_id, fact_id, source, AuthorityLevel::High)
    }

    fn reinforce_in_auth(
        event_id: &str,
        fact_id: &str,
        source: &str,
        authority: AuthorityLevel,
    ) -> FactEvent {
        with_fact(
            ev(
                event_id,
                FactEventKind::Reinforced {
                    by: FactId::new("fact:evidence").expect("fact id"),
                },
                None,
                source,
                authority,
                900,
                Ttl::Never,
                None,
            ),
            fact_id,
        )
    }

    #[test]
    fn replay_subject_folds_each_stream_independently() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            assert_in("event:2", "fact:B", "source:owner"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(subject.facts.len(), 2);
        assert_eq!(
            subject.get(&fact("fact:A")).unwrap().lifecycle,
            FactLifecycle::Active
        );
        assert_eq!(subject.believed().count(), 2);
        assert!(subject.lineage_issues().is_empty());
    }

    #[test]
    fn intact_supersession_lineage_has_no_issues() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            assert_in("event:2", "fact:B", "source:owner"),
            supersede_in("event:3", "fact:A", "fact:B", "source:owner"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(
            subject.get(&fact("fact:A")).unwrap().lifecycle,
            FactLifecycle::Superseded
        );
        assert_eq!(
            subject.get(&fact("fact:B")).unwrap().lifecycle,
            FactLifecycle::Active
        );
        assert!(subject.lineage_issues().is_empty());
    }

    #[test]
    fn supersession_to_a_missing_fact_is_dangling() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            supersede_in("event:2", "fact:A", "fact:ghost", "source:owner"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(
            subject.lineage_issues(),
            vec![LineageIssue::DanglingSupersession {
                fact: fact("fact:A"),
                target: fact("fact:ghost"),
            }]
        );
    }

    #[test]
    fn supersession_by_a_retracted_fact_orphans_the_lineage() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            assert_in("event:2", "fact:B", "source:owner"),
            supersede_in("event:3", "fact:A", "fact:B", "source:owner"),
            retract_in("event:4", "fact:B"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(
            subject.lineage_issues(),
            vec![LineageIssue::SupersededByInvalidated {
                fact: fact("fact:A"),
                target: fact("fact:B"),
                target_lifecycle: FactLifecycle::Retracted,
            }]
        );
    }

    #[test]
    fn subject_level_distrust_drops_a_whole_stream() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            assert_in("event:2", "fact:B", "source:web-scrape"),
        ];

        let subject = replay_subject_with_policy(&events, &distrust("source:web-scrape"))
            .expect("subject replay");

        assert_eq!(subject.facts.len(), 1);
        assert!(subject.get(&fact("fact:A")).is_some());
        assert!(subject.get(&fact("fact:B")).is_none());
    }

    #[test]
    fn self_supersession_is_flagged_as_a_cycle() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            supersede_in("event:2", "fact:A", "fact:A", "source:owner"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(
            subject.lineage_issues(),
            vec![LineageIssue::SupersessionCycle {
                fact: fact("fact:A"),
            }]
        );
    }

    #[test]
    fn a_two_fact_supersession_cycle_is_flagged() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            assert_in("event:2", "fact:B", "source:owner"),
            supersede_in("event:3", "fact:A", "fact:B", "source:owner"),
            supersede_in("event:4", "fact:B", "fact:A", "source:owner"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(
            subject.lineage_issues(),
            vec![
                LineageIssue::SupersessionCycle {
                    fact: fact("fact:A"),
                },
                LineageIssue::SupersessionCycle {
                    fact: fact("fact:B"),
                },
            ]
        );
    }

    #[test]
    fn an_intact_three_fact_chain_has_no_issues() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            assert_in("event:2", "fact:B", "source:owner"),
            assert_in("event:3", "fact:C", "source:owner"),
            supersede_in("event:4", "fact:A", "fact:B", "source:owner"),
            supersede_in("event:5", "fact:B", "fact:C", "source:owner"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert!(subject.lineage_issues().is_empty());
        assert_eq!(subject.believed().count(), 1); // only C
        assert_eq!(
            subject.get(&fact("fact:C")).unwrap().lifecycle,
            FactLifecycle::Active
        );
    }

    // ---- earned entrenchment (rank 3) ----

    #[test]
    fn corroboration_counts_distinct_backing_sources() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            reinforce_in("event:2", "fact:A", "source:peer"),
            reinforce_in("event:3", "fact:A", "source:owner"), // same source: no new corroboration
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(subject.get(&fact("fact:A")).unwrap().corroboration(), 2);
    }

    #[test]
    fn a_weaker_corroborated_supersession_is_unearned() {
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            reinforce_in("event:2", "fact:A", "source:peer"), // A corroboration = 2
            assert_in("event:3", "fact:B", "source:rumor"),   // B corroboration = 1
            supersede_in("event:4", "fact:A", "fact:B", "source:rumor"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        // Lineage is intact (B exists, active); the weakness is only visible to the
        // entrenchment audit.
        assert!(subject.lineage_issues().is_empty());
        assert_eq!(
            subject.unearned_supersessions(),
            vec![UnearnedSupersession::WeakerEntrenchment {
                superseded: fact("fact:A"),
                by: fact("fact:B"),
                incumbent_entrenchment: 2,
                challenger_entrenchment: 1,
            }]
        );
    }

    #[test]
    fn an_authority_downgrade_supersession_is_unearned() {
        // The supersession event overstates its authority (High) to clear the
        // per-stream gate, but the replacing fact B is actually Low authority.
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            assert_in_auth("event:2", "fact:B", "source:rumor", AuthorityLevel::Low),
            supersede_in("event:3", "fact:A", "fact:B", "source:rumor"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(
            subject.unearned_supersessions(),
            vec![UnearnedSupersession::AuthorityDowngrade {
                superseded: fact("fact:A"),
                by: fact("fact:B"),
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
            assert_in("event:1", "fact:A", "source:owner"),
            reinforce_in("event:2", "fact:A", "source:peer"),
            assert_in("event:3", "fact:B", "source:attacker"),
            reinforce_in_auth("event:4", "fact:B", "source:sybil-1", AuthorityLevel::Low),
            reinforce_in_auth("event:5", "fact:B", "source:sybil-2", AuthorityLevel::Low),
            reinforce_in_auth("event:6", "fact:B", "source:sybil-3", AuthorityLevel::Low),
            supersede_in("event:7", "fact:A", "fact:B", "source:attacker"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(subject.get(&fact("fact:B")).unwrap().corroboration(), 4); // raw, inflated
        assert_eq!(
            subject.unearned_supersessions(),
            vec![UnearnedSupersession::WeakerEntrenchment {
                superseded: fact("fact:A"),
                by: fact("fact:B"),
                incumbent_entrenchment: 2,  // High-authority backers of A
                challenger_entrenchment: 1, // High-authority backers of B (Sybils don't count)
            }]
        );
    }

    #[test]
    fn a_survived_challenge_makes_an_equal_corroboration_supersession_unearned() {
        // A and B each have exactly one High-authority backer, so on corroboration alone the
        // supersession would look earned. But A survived a High challenge (earned entrenchment
        // 1 + 1 = 2) while B has survived nothing (entrenchment 1) — so, per ADR 0017, the
        // supersession is unearned: survived challenges now count in the audit.
        let events = [
            assert_in("event:1", "fact:A", "source:owner"),
            challenge_rejected_in("event:2", "fact:A", "source:attacker", AuthorityLevel::High),
            assert_in("event:3", "fact:B", "source:rumor"),
            supersede_in("event:4", "fact:A", "fact:B", "source:rumor"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert_eq!(subject.get(&fact("fact:A")).unwrap().corroboration(), 1);
        assert_eq!(
            subject
                .get(&fact("fact:A"))
                .unwrap()
                .survived_challenges_at_or_above(AuthorityLevel::High),
            1
        );
        assert_eq!(
            subject.unearned_supersessions(),
            vec![UnearnedSupersession::WeakerEntrenchment {
                superseded: fact("fact:A"),
                by: fact("fact:B"),
                incumbent_entrenchment: 2, // 1 backer + 1 survived challenge
                challenger_entrenchment: 1,
            }]
        );
    }

    #[test]
    fn a_higher_authority_supersession_is_earned() {
        let events = [
            assert_in_auth("event:1", "fact:A", "source:owner", AuthorityLevel::Medium),
            assert_in_auth(
                "event:2",
                "fact:B",
                "source:owner",
                AuthorityLevel::Canonical,
            ),
            supersede_in("event:3", "fact:A", "fact:B", "source:owner"),
        ];

        let subject = replay_subject(&events).expect("subject replay");

        assert!(subject.unearned_supersessions().is_empty());
    }
}
