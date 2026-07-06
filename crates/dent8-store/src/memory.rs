//! An in-memory [`EventStore`] for tests and the demo.
//!
//! This is **not** the operational store — Postgres remains the source of truth
//! (ADR 0001). It exists so the firewall / replay / explain loop is runnable without a
//! database, behind the same `EventStore` trait and the same global hash chain. A
//! Postgres adapter is a second backend, not a replacement for this one.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use dent8_core::{
    AuthorityLevel, ChainAnchor, FactEvent, FactId, FactLifecycle, FactValue, Predicate, Subject,
    TimestampMillis, anchor_head, hash_chain, verify_anchor,
};

use crate::{
    AppendReceipt, EventFilter, EventStore, ReplayError, StoreError, replay_fact, replay_subject,
};

#[derive(Clone, Debug)]
struct StoredEvent {
    global_sequence: u64,
    event: FactEvent,
    event_hash: String,
}

/// A non-persistent, single-process [`EventStore`]. Assigns a global sequence and a
/// chained `event_hash` to every appended event; replay and explain re-derive state and
/// reverify the chain.
#[derive(Clone, Debug, Default)]
pub struct InMemoryEventStore {
    log: Vec<StoredEvent>,
    by_fact: BTreeMap<FactId, Vec<usize>>,
    event_ids: BTreeSet<String>,
    last_hash: Option<String>,
}

impl InMemoryEventStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconstruct a store from an **already-admitted** event log, in append order,
    /// **without** re-running the firewall. This is the trusted-load path used when
    /// rehydrating from a durable backend (e.g. a file): the events were arbitrated when
    /// first written, so they are replayed as-is and the global hash chain is recomputed.
    ///
    /// It is the deliberate counterpart to [`EventStore::append`] (which is the *only*
    /// arbitrated write path): callers must not feed it un-arbitrated events. A duplicate
    /// `event_id` is still rejected ([`StoreError::Conflict`]).
    pub fn from_trusted_events(
        events: impl IntoIterator<Item = FactEvent>,
    ) -> Result<Self, StoreError> {
        let mut store = Self::new();
        for event in events {
            store.persist(event)?;
        }
        Ok(store)
    }

    /// Persist one event: dedup `event_id`, chain its `event_hash` to the global head,
    /// assign a `global_sequence`, and index it. Assumes the event has already cleared
    /// the firewall (or is a trusted reload) — it performs **no** arbitration.
    fn persist(&mut self, event: FactEvent) -> Result<AppendReceipt, StoreError> {
        if self.event_ids.contains(event.event_id.as_str()) {
            return Err(StoreError::Conflict(format!(
                "duplicate event_id {}",
                event.event_id
            )));
        }
        let event_hash = dent8_core::event_hash(&event, self.last_hash.as_deref())
            .map_err(|error| StoreError::Canonicalization(error.to_string()))?;

        let global_sequence = self.log.len() as u64;
        let index = self.log.len();
        self.by_fact
            .entry(event.fact_id.clone())
            .or_default()
            .push(index);
        self.event_ids.insert(event.event_id.to_string());
        let receipt = AppendReceipt {
            global_sequence,
            event_id: event.event_id.clone(),
            event_hash: event_hash.clone(),
        };
        self.log.push(StoredEvent {
            global_sequence,
            event,
            event_hash: event_hash.clone(),
        });
        self.last_hash = Some(event_hash);
        Ok(receipt)
    }

    /// The number of events in the log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.log.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    fn all_events(&self) -> Vec<FactEvent> {
        self.log.iter().map(|stored| stored.event.clone()).collect()
    }

    /// The distinct `(subject, predicate)` pairs that appear anywhere in the log, in
    /// first-seen (append) order. Each names one fact stream that [`Self::explain_subject`]
    /// / [`Self::explain_latest`] can read — used to enumerate facts for browsing.
    #[must_use]
    pub fn subjects(&self) -> Vec<(Subject, Predicate)> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for stored in &self.log {
            let pair = (stored.event.subject.clone(), stored.event.predicate.clone());
            if seen.insert(pair.clone()) {
                out.push(pair);
            }
        }
        out
    }

    /// Recompute the **global** hash chain (over all events in append order) and confirm
    /// it matches the stored hashes. This proves the stored chain is *internally
    /// consistent* — it catches an event mutated without its hash being recomputed. It is
    /// **not** tamper-proof against a writer with full store access, who could re-hash a
    /// mutated log; that needs an external anchor (a signed/published head), which is a
    /// later step. An empty log verifies trivially.
    #[must_use]
    pub fn verify_chain(&self) -> bool {
        match hash_chain(&self.all_events()) {
            Ok(recomputed) => {
                recomputed.len() == self.log.len()
                    && recomputed
                        .iter()
                        .zip(&self.log)
                        .all(|(hash, stored)| *hash == stored.event_hash)
            }
            Err(_) => false,
        }
    }

    /// Commit to this store's current chain head under `witness_key` — an **external**
    /// anchor (see [`anchor_head`]). Unlike [`Self::verify_chain`] (which only re-checks
    /// internal consistency), an anchor stored off the writer's machine detects a later
    /// history rewrite that re-hashes the whole log forward.
    pub fn anchor(&self, witness_key: &[u8]) -> Result<ChainAnchor, StoreError> {
        anchor_head(&self.all_events(), witness_key)
            .map_err(|error| StoreError::Canonicalization(error.to_string()))
    }

    /// Verify this store's current log against a previously-issued [`ChainAnchor`] under
    /// `witness_key`. `Ok(false)` means the log no longer matches the commitment — tamper
    /// (a rewrite or truncation) detected, even when the internal chain re-verifies.
    pub fn verify_against_anchor(
        &self,
        anchor: &ChainAnchor,
        witness_key: &[u8],
    ) -> Result<bool, StoreError> {
        verify_anchor(&self.all_events(), anchor, witness_key)
            .map_err(|error| StoreError::Canonicalization(error.to_string()))
    }

    /// Build an [`IntegrityReceipt`] for one fact, evaluated for freshness at `now`.
    /// Returns `None` if the fact has no events.
    pub fn explain(
        &self,
        fact_id: &FactId,
        now: TimestampMillis,
    ) -> Result<Option<IntegrityReceipt>, ReplayError> {
        self.explain_with(fact_id, now, true)
    }

    /// [`Self::explain`] with the whole-log chain re-verification optional. Enumeration
    /// surfaces that only need a fact's freshness/lifecycle (`latest_freshness`) pass
    /// `verify_chain = false` so listing N streams does not re-hash the entire log N times;
    /// `chain_verified` is then reported `false` (the caller was not asking).
    fn explain_with(
        &self,
        fact_id: &FactId,
        now: TimestampMillis,
        verify_chain: bool,
    ) -> Result<Option<IntegrityReceipt>, ReplayError> {
        let Some(indices) = self.by_fact.get(fact_id) else {
            return Ok(None);
        };
        let Some(&last_index) = indices.last() else {
            return Ok(None);
        };
        let events: Vec<FactEvent> = indices
            .iter()
            .map(|&index| self.log[index].event.clone())
            .collect();
        let Some(state) = replay_fact(&events)? else {
            return Ok(None);
        };
        let last = &self.log[last_index];

        Ok(Some(IntegrityReceipt {
            fact_id: state.fact_id.clone(),
            subject: state.subject.clone(),
            predicate: state.predicate.clone(),
            value: state.value.clone(),
            lifecycle: state.lifecycle,
            authority: state.authority.level,
            fresh: state.is_fresh_at(now),
            not_yet_valid: state.is_not_yet_valid_at(now),
            valid_from: state.valid_from,
            expires_at: state.expires_at(),
            evidence_count: state.evidence_count,
            corroboration: state.corroboration(),
            survived_challenges: state.survived_challenge_count(),
            superseded_by: state.superseded_by.clone(),
            contradicted_by: state.contradicted_by.clone(),
            replay_position: last.global_sequence,
            event_hash: last.event_hash.clone(),
            chain_verified: verify_chain && self.verify_chain(),
        }))
    }

    /// The fact id [`Self::explain_latest`] resolves to: the believed fact (a contested or
    /// fresh one preferred), else the most-recently-updated terminal fact, else `None`.
    /// Shared by `explain_latest` and `latest_freshness` so the two never disagree.
    fn latest_fact_id(
        &self,
        subject: &Subject,
        predicate: &Predicate,
        now: TimestampMillis,
    ) -> Result<Option<FactId>, StoreError> {
        let filter = EventFilter {
            subject: Some(subject.clone()),
            predicate: Some(predicate.clone()),
            ..EventFilter::default()
        };
        let subject = replay_subject(&self.scan_events(&filter)?).map_err(StoreError::Replay)?;
        if let Some(state) = subject
            .believed()
            .find(|state| state.lifecycle == FactLifecycle::Contested && !state.is_expired_at(now))
            .or_else(|| subject.believed().find(|state| !state.is_expired_at(now)))
            .or_else(|| subject.believed().next())
        {
            return Ok(Some(state.fact_id.clone()));
        }
        Ok(subject
            .facts
            .values()
            .max_by_key(|state| state.updated_at)
            .map(|state| state.fact_id.clone()))
    }

    /// The believed (or terminal) fact's receipt with freshness resolved **without** the
    /// whole-log chain re-verification — for enumeration surfaces (`facts list`, MCP
    /// `list_facts` / `resources/list`) that flag per-stream freshness at scale. Resolves the
    /// same fact as [`Self::explain_latest`]; `chain_verified` is `false` (not asked).
    pub fn latest_freshness(
        &self,
        subject: &Subject,
        predicate: &Predicate,
        now: TimestampMillis,
    ) -> Result<Option<IntegrityReceipt>, StoreError> {
        match self.latest_fact_id(subject, predicate, now)? {
            Some(id) => self
                .explain_with(&id, now, false)
                .map_err(StoreError::Replay),
            None => Ok(None),
        }
    }

    /// All currently-believed (lifecycle-non-terminal) fact ids for a subject+predicate,
    /// in fact-id order. `supersede` uses this to revise **every** believed fact, so the
    /// end state has at most one — the registry's freshness-aware uniqueness can otherwise
    /// leave a stale + fresh pair both believed, and superseding only one would leak.
    pub fn believed_fact_ids(
        &self,
        subject: &Subject,
        predicate: &Predicate,
    ) -> Result<Vec<FactId>, StoreError> {
        let filter = EventFilter {
            subject: Some(subject.clone()),
            predicate: Some(predicate.clone()),
            ..EventFilter::default()
        };
        let subject = replay_subject(&self.scan_events(&filter)?).map_err(StoreError::Replay)?;
        Ok(subject
            .believed()
            .map(|state| state.fact_id.clone())
            .collect())
    }

    /// Explain the subject+predicate's current state at `now`, falling back to the most
    /// recently updated **terminal** fact when nothing is believed — so a fact that was
    /// retracted or superseded reads as `lifecycle: Retracted`/`Superseded` rather than
    /// being indistinguishable from one that never existed. Returns `None` only when the
    /// subject+predicate has no events at all.
    pub fn explain_latest(
        &self,
        subject: &Subject,
        predicate: &Predicate,
        now: TimestampMillis,
    ) -> Result<Option<IntegrityReceipt>, StoreError> {
        match self.latest_fact_id(subject, predicate, now)? {
            Some(id) => self.explain(&id, now).map_err(StoreError::Replay),
            None => Ok(None),
        }
    }

    /// Explain the believed fact for a `subject` + `predicate` at time `now`. When the
    /// predicate is contested, a `Contested` fact is surfaced first so the conflict is
    /// always visible (independent of fact-id ordering); otherwise a fresh fact is
    /// preferred over a stale one. Returns `None` if nothing is believed. This is the read
    /// used to resolve the *current* fact (e.g. by `supersede`/`contradict`).
    pub fn explain_subject(
        &self,
        subject: &Subject,
        predicate: &Predicate,
        now: TimestampMillis,
    ) -> Result<Option<IntegrityReceipt>, StoreError> {
        let filter = EventFilter {
            subject: Some(subject.clone()),
            predicate: Some(predicate.clone()),
            ..EventFilter::default()
        };
        let subject = replay_subject(&self.scan_events(&filter)?).map_err(StoreError::Replay)?;
        let fact_id = subject
            .believed()
            .find(|state| state.lifecycle == FactLifecycle::Contested && !state.is_expired_at(now))
            .or_else(|| subject.believed().find(|state| !state.is_expired_at(now)))
            .or_else(|| subject.believed().next())
            .map(|state| state.fact_id.clone());
        match fact_id {
            Some(id) => self.explain(&id, now).map_err(StoreError::Replay),
            None => Ok(None),
        }
    }
}

impl EventStore for InMemoryEventStore {
    fn append(&mut self, event: FactEvent) -> Result<AppendReceipt, StoreError> {
        // The firewall: arbitrate against current state and reject inadmissible writes
        // (insufficient or laundered authority, canonical contradiction, ...) before any
        // event is persisted. There is no un-arbitrated write path on this store.
        crate::arbitrate(self, &event)?;
        self.persist(event)
    }

    fn load_fact_events(&self, fact_id: &FactId) -> Result<Vec<FactEvent>, StoreError> {
        Ok(self
            .by_fact
            .get(fact_id)
            .map(|indices| indices.iter().map(|&i| self.log[i].event.clone()).collect())
            .unwrap_or_default())
    }

    fn scan_events(&self, filter: &EventFilter) -> Result<Vec<FactEvent>, StoreError> {
        let matches = self
            .log
            .iter()
            .filter(|stored| {
                filter
                    .fact_id
                    .as_ref()
                    .is_none_or(|c| c == &stored.event.fact_id)
                    && filter
                        .subject
                        .as_ref()
                        .is_none_or(|s| s == &stored.event.subject)
                    && filter
                        .predicate
                        .as_ref()
                        .is_none_or(|p| p == &stored.event.predicate)
                    && filter
                        .after_sequence
                        .is_none_or(|seq| stored.global_sequence > seq)
            })
            .map(|stored| stored.event.clone())
            .take(filter.limit.map_or(usize::MAX, |l| l as usize))
            .collect();
        Ok(matches)
    }
}

/// A read-time integrity receipt for one fact: its current believed state plus the
/// metadata that makes that state auditable. Returned by [`InMemoryEventStore::explain`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityReceipt {
    pub fact_id: FactId,
    pub subject: Subject,
    pub predicate: Predicate,
    pub value: FactValue,
    pub lifecycle: FactLifecycle,
    pub authority: AuthorityLevel,
    /// Whether the fact is fresh at the query time: within its validity window — at or
    /// after `valid_from` and before its TTL / `valid_to` upper bound (ADR 0016).
    pub fresh: bool,
    /// Whether the fact is **not yet valid** at the query time (its asserted `valid_from`
    /// is in the future) — a distinct reason for `fresh == false` from having expired.
    pub not_yet_valid: bool,
    /// The asserted valid-time lower bound, or `None`. Pairs with `expires_at` to bound the
    /// validity window and, with `not_yet_valid`, to explain a not-yet-in-effect read.
    pub valid_from: Option<TimestampMillis>,
    /// The instant the fact stops being fresh — the earliest of its TTL bound and asserted
    /// `valid_to`, or `None` if it never expires. Pairs with `fresh` to explain *why* a read
    /// is stale and *when* it lapsed.
    pub expires_at: Option<TimestampMillis>,
    pub evidence_count: usize,
    pub corroboration: usize,
    /// Distinct sources whose challenge against this fact the firewall rejected
    /// (ADR 0015) — the "attacked and stood" half of earned entrenchment.
    pub survived_challenges: usize,
    pub superseded_by: Option<FactId>,
    pub contradicted_by: Vec<FactId>,
    /// Global sequence of the fact's most recent event of *any* kind (including audit
    /// events like `retrieved`), not necessarily the state-determining one.
    pub replay_position: u64,
    /// Hash of the fact's most recent event (its link in the global hash chain).
    pub event_hash: String,
    /// Whether the whole log's hash chain is internally consistent (see
    /// [`InMemoryEventStore::verify_chain`] for what this does and does not prove).
    pub chain_verified: bool,
}

#[cfg(test)]
mod tests {
    use super::InMemoryEventStore;
    use crate::EventStore;
    use dent8_core::{
        ActorId, Authority, AuthorityLevel, Confidence, ContradictionBasis, Evidence, EvidenceId,
        EvidenceKind, FactEvent, FactEventId, FactEventKind, FactId, FactLifecycle, FactValue,
        Predicate, Provenance, SourceId, Subject, SupersessionReason, TimestampMillis, Ttl,
    };

    fn assertion(event_id: &str, fact_id: &str, value: &str) -> FactEvent {
        FactEvent {
            event_id: FactEventId::new(event_id).expect("event id"),
            fact_id: FactId::new(fact_id).expect("fact id"),
            kind: FactEventKind::Asserted,
            subject: Subject::new("repo", "myproj").expect("subject"),
            predicate: Predicate::new("database").expect("predicate"),
            value: Some(FactValue::Text(value.to_string())),
            confidence: Confidence::from_millis(900).expect("confidence"),
            authority: Authority {
                level: AuthorityLevel::High,
                issuer: None,
                scope: None,
            },
            ttl: Ttl::Never,
            provenance: Provenance {
                source: SourceId::new("source:owner").expect("source"),
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
    fn the_receipt_reports_freshness_and_expiry_at_the_query_time() {
        let mut store = InMemoryEventStore::new();
        let mut event = assertion("event:1", "fact:A", "postgres");
        event.ttl = Ttl::DurationMillis(100); // anchored at recorded_at = 1 -> expires at 101
        store.append(event).expect("append");
        let subject = Subject::new("repo", "myproj").unwrap();
        let predicate = Predicate::new("database").unwrap();

        // Before expiry: fresh, with the expiry instant surfaced.
        let fresh = store
            .explain_subject(&subject, &predicate, TimestampMillis::from_unix_millis(50))
            .unwrap()
            .expect("receipt");
        assert!(fresh.fresh);
        assert_eq!(
            fresh.expires_at,
            Some(TimestampMillis::from_unix_millis(101))
        );

        // After expiry: still returned (auditable) but not fresh; lifecycle is untouched
        // (freshness is a read-time axis, not an event-driven lifecycle change).
        let stale = store
            .explain_subject(&subject, &predicate, TimestampMillis::from_unix_millis(200))
            .unwrap()
            .expect("receipt");
        assert!(!stale.fresh);
        assert_eq!(
            stale.expires_at,
            Some(TimestampMillis::from_unix_millis(101))
        );
        assert_eq!(stale.lifecycle, FactLifecycle::Active);
    }

    #[test]
    fn a_serialized_log_reloads_through_the_trusted_path_with_an_identical_chain() {
        let now = TimestampMillis::from_unix_millis(100);
        let mut original = InMemoryEventStore::new();
        // Two distinct facts so the chain has more than one link.
        original
            .append(assertion("event:1", "fact:A", "postgres"))
            .expect("append 1");
        original
            .append(assertion("event:2", "fact:B", "redis"))
            .expect("append 2");
        assert!(original.verify_chain());

        // Round-trip every event through serde (what the file backend writes/reads) and
        // reconstruct via the trusted-load path.
        let wire: Vec<String> = original
            .all_events()
            .iter()
            .map(|event| serde_json::to_string(event).expect("serialize"))
            .collect();
        let reloaded_events = wire
            .iter()
            .map(|line| serde_json::from_str::<FactEvent>(line).expect("deserialize"));
        let reloaded = InMemoryEventStore::from_trusted_events(reloaded_events).expect("reload");

        assert_eq!(reloaded.len(), original.len());
        assert!(reloaded.verify_chain());
        // The reloaded store explains each fact identically (same hash, same chain).
        for fact in ["fact:A", "fact:B"] {
            let id = FactId::new(fact).unwrap();
            assert_eq!(
                reloaded.explain(&id, now).unwrap(),
                original.explain(&id, now).unwrap(),
            );
        }
    }

    #[test]
    fn an_external_anchor_detects_a_rehashed_forward_rewrite() {
        const KEY: &[u8] = b"witness-key-held-off-the-writer";
        let mut original = InMemoryEventStore::new();
        original
            .append(assertion("event:0", "fact:A", "postgres"))
            .unwrap();
        original
            .append(assertion("event:1", "fact:B", "redis"))
            .unwrap();
        let anchor = original.anchor(KEY).expect("anchor");
        assert!(
            original
                .verify_against_anchor(&anchor, KEY)
                .expect("verify")
        );

        // An operator edits the persisted log and the reload re-hashes the whole chain
        // forward (from_trusted_events) — the result is internally self-consistent.
        let tampered = InMemoryEventStore::from_trusted_events([
            assertion("event:0", "fact:A", "postgres"),
            assertion("event:1", "fact:B", "mysql"), // the quiet edit
        ])
        .expect("reload");

        // Internal re-verify PASSES (the rewritten chain is self-consistent) — this is the
        // exact gap an external anchor closes...
        assert!(tampered.verify_chain());
        // ...and the anchor CATCHES the rewrite (the witness MAC cannot be forged).
        assert!(
            !tampered
                .verify_against_anchor(&anchor, KEY)
                .expect("verify")
        );
    }

    #[test]
    fn the_trusted_path_still_rejects_a_duplicate_event_id() {
        let dup = || assertion("event:1", "fact:A", "postgres");
        let result = InMemoryEventStore::from_trusted_events([dup(), dup()]);
        assert!(matches!(result, Err(crate::StoreError::Conflict(_))));
    }

    fn supersession(event_id: &str, fact_id: &str, by: &str) -> FactEvent {
        let mut event = assertion(event_id, fact_id, "ignored");
        event.kind = FactEventKind::Superseded {
            by: FactId::new(by).expect("by"),
            reason: SupersessionReason::UserCorrection,
        };
        event.value = None;
        event
    }

    fn contradiction(event_id: &str, fact_id: &str, by: &str) -> FactEvent {
        let mut event = assertion(event_id, fact_id, "ignored");
        event.kind = FactEventKind::Contradicted {
            by: FactId::new(by).expect("by"),
            basis: ContradictionBasis::SamePredicateDifferentValue,
        };
        event.value = None;
        event
    }

    #[test]
    fn a_contradiction_contests_the_incumbent_and_keeps_both_believed() {
        // Paraconsistency: a contradiction localizes the conflict (incumbent -> Contested)
        // and *keeps* both facts, rather than dropping one (ADR 0009).
        let mut store = InMemoryEventStore::from_trusted_events([
            assertion("event:0", "fact:A", "postgres"),
            assertion("event:1", "fact:B", "mysql"),
        ])
        .expect("load");
        store
            .append(contradiction("event:2", "fact:A", "fact:B"))
            .expect("contradiction admitted");

        let subject = Subject::new("repo", "myproj").unwrap();
        let predicate = Predicate::new("database").unwrap();
        assert_eq!(
            store.believed_fact_ids(&subject, &predicate).unwrap().len(),
            2,
            "both the contested incumbent and its contradictor remain believed"
        );
        let now = TimestampMillis::from_unix_millis(100);
        let incumbent = store
            .explain(&FactId::new("fact:A").unwrap(), now)
            .unwrap()
            .unwrap();
        assert_eq!(incumbent.lifecycle, FactLifecycle::Contested);
        assert_eq!(incumbent.contradicted_by.len(), 1);
    }

    #[test]
    fn explain_surfaces_a_contested_fact_regardless_of_fact_id_order() {
        // "fact:10" sorts BEFORE "fact:9" lexicographically, so a naive first-believed
        // pick would return the Active contradictor and hide the contest. explain must
        // prefer the Contested incumbent.
        let mut store = InMemoryEventStore::from_trusted_events([
            assertion("event:0", "fact:9", "postgres"),
            assertion("event:1", "fact:10", "mysql"),
        ])
        .expect("load");
        store
            .append(contradiction("event:2", "fact:9", "fact:10"))
            .expect("contradiction admitted");

        let receipt = store
            .explain_subject(
                &Subject::new("repo", "myproj").unwrap(),
                &Predicate::new("database").unwrap(),
                TimestampMillis::from_unix_millis(100),
            )
            .unwrap()
            .unwrap();
        assert_eq!(receipt.lifecycle, FactLifecycle::Contested);
        assert_eq!(receipt.value, FactValue::Text("postgres".to_string()));
    }

    #[test]
    fn superseding_every_believed_incumbent_leaves_exactly_one() {
        // Two believed facts coexist for one subject+predicate — the base store enforces
        // no uniqueness (that is the registry's job, and freshness can leave a stale+fresh
        // pair both believed). `supersede` must revise *both*, not just one.
        let mut store = InMemoryEventStore::from_trusted_events([
            assertion("event:0", "fact:A", "postgres"),
            assertion("event:1", "fact:B", "mysql"),
        ])
        .expect("load");
        let subject = Subject::new("repo", "myproj").unwrap();
        let predicate = Predicate::new("database").unwrap();
        assert_eq!(
            store.believed_fact_ids(&subject, &predicate).unwrap().len(),
            2
        );

        // One replacement, a supersession for EACH incumbent, all pointing at it.
        store
            .append(assertion("event:2", "fact:C", "sqlite"))
            .expect("replacement");
        store
            .append(supersession("event:3", "fact:A", "fact:C"))
            .expect("supersede A");
        store
            .append(supersession("event:4", "fact:B", "fact:C"))
            .expect("supersede B");

        assert_eq!(
            store.believed_fact_ids(&subject, &predicate).unwrap(),
            vec![FactId::new("fact:C").unwrap()],
        );
    }
}
