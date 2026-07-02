//! An in-memory [`EventStore`] for tests and the demo.
//!
//! This is **not** the operational store — Postgres remains the source of truth
//! (ADR 0001). It exists so the firewall / replay / explain loop is runnable without a
//! database, behind the same `EventStore` trait and the same global hash chain. A
//! Postgres adapter is a second backend, not a replacement for this one.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use dent8_core::{
    AuthorityLevel, ChainAnchor, ClaimEvent, ClaimId, ClaimLifecycle, ClaimValue, EntityRef,
    Predicate, TimestampMillis, anchor_head, hash_chain, verify_anchor,
};

use crate::{
    AppendReceipt, EventFilter, EventStore, ReplayError, StoreError, replay_claim, replay_entity,
};

#[derive(Clone, Debug)]
struct StoredEvent {
    global_sequence: u64,
    event: ClaimEvent,
    event_hash: String,
}

/// A non-persistent, single-process [`EventStore`]. Assigns a global sequence and a
/// chained `event_hash` to every appended event; replay and explain re-derive state and
/// reverify the chain.
#[derive(Clone, Debug, Default)]
pub struct InMemoryEventStore {
    log: Vec<StoredEvent>,
    by_claim: BTreeMap<ClaimId, Vec<usize>>,
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
        events: impl IntoIterator<Item = ClaimEvent>,
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
    fn persist(&mut self, event: ClaimEvent) -> Result<AppendReceipt, StoreError> {
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
        self.by_claim
            .entry(event.claim_id.clone())
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

    fn all_events(&self) -> Vec<ClaimEvent> {
        self.log.iter().map(|stored| stored.event.clone()).collect()
    }

    /// The distinct `(subject, predicate)` pairs that appear anywhere in the log, in
    /// first-seen (append) order. Each names one fact stream that [`Self::explain_subject`]
    /// / [`Self::explain_latest`] can read — used to enumerate facts for browsing.
    #[must_use]
    pub fn subjects(&self) -> Vec<(EntityRef, Predicate)> {
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

    /// Build an [`IntegrityReceipt`] for one claim, evaluated for freshness at `now`.
    /// Returns `None` if the claim has no events.
    pub fn explain(
        &self,
        claim_id: &ClaimId,
        now: TimestampMillis,
    ) -> Result<Option<IntegrityReceipt>, ReplayError> {
        let Some(indices) = self.by_claim.get(claim_id) else {
            return Ok(None);
        };
        let Some(&last_index) = indices.last() else {
            return Ok(None);
        };
        let events: Vec<ClaimEvent> = indices
            .iter()
            .map(|&index| self.log[index].event.clone())
            .collect();
        let Some(state) = replay_claim(&events)? else {
            return Ok(None);
        };
        let last = &self.log[last_index];

        Ok(Some(IntegrityReceipt {
            claim_id: state.claim_id.clone(),
            subject: state.subject.clone(),
            predicate: state.predicate.clone(),
            value: state.value.clone(),
            lifecycle: state.lifecycle,
            authority: state.authority.level,
            fresh: !state.is_expired_at(now),
            expires_at: state.expires_at(),
            evidence_count: state.evidence_count,
            corroboration: state.corroboration(),
            superseded_by: state.superseded_by.clone(),
            contradicted_by: state.contradicted_by.clone(),
            replay_position: last.global_sequence,
            event_hash: last.event_hash.clone(),
            chain_verified: self.verify_chain(),
        }))
    }

    /// All currently-believed (lifecycle-non-terminal) claim ids for a subject+predicate,
    /// in claim-id order. `supersede` uses this to revise **every** believed claim, so the
    /// end state has at most one — the registry's freshness-aware uniqueness can otherwise
    /// leave a stale + fresh pair both believed, and superseding only one would leak.
    pub fn believed_claim_ids(
        &self,
        subject: &EntityRef,
        predicate: &Predicate,
    ) -> Result<Vec<ClaimId>, StoreError> {
        let filter = EventFilter {
            subject: Some(subject.clone()),
            predicate: Some(predicate.clone()),
            ..EventFilter::default()
        };
        let entity = replay_entity(&self.scan_events(&filter)?).map_err(StoreError::Replay)?;
        Ok(entity
            .believed()
            .map(|state| state.claim_id.clone())
            .collect())
    }

    /// Explain the subject+predicate's current state at `now`, falling back to the most
    /// recently updated **terminal** claim when nothing is believed — so a fact that was
    /// retracted or superseded reads as `lifecycle: Retracted`/`Superseded` rather than
    /// being indistinguishable from one that never existed. Returns `None` only when the
    /// subject+predicate has no events at all.
    pub fn explain_latest(
        &self,
        subject: &EntityRef,
        predicate: &Predicate,
        now: TimestampMillis,
    ) -> Result<Option<IntegrityReceipt>, StoreError> {
        if let Some(receipt) = self.explain_subject(subject, predicate, now)? {
            return Ok(Some(receipt));
        }
        let filter = EventFilter {
            subject: Some(subject.clone()),
            predicate: Some(predicate.clone()),
            ..EventFilter::default()
        };
        let entity = replay_entity(&self.scan_events(&filter)?).map_err(StoreError::Replay)?;
        let latest = entity
            .claims
            .values()
            .max_by_key(|state| state.updated_at)
            .map(|state| state.claim_id.clone());
        match latest {
            Some(id) => self.explain(&id, now).map_err(StoreError::Replay),
            None => Ok(None),
        }
    }

    /// Explain the believed claim for a `subject` + `predicate` at time `now`. When the
    /// predicate is contested, a `Contested` claim is surfaced first so the conflict is
    /// always visible (independent of claim-id ordering); otherwise a fresh claim is
    /// preferred over a stale one. Returns `None` if nothing is believed. This is the read
    /// used to resolve the *current* fact (e.g. by `supersede`/`contradict`).
    pub fn explain_subject(
        &self,
        subject: &EntityRef,
        predicate: &Predicate,
        now: TimestampMillis,
    ) -> Result<Option<IntegrityReceipt>, StoreError> {
        let filter = EventFilter {
            subject: Some(subject.clone()),
            predicate: Some(predicate.clone()),
            ..EventFilter::default()
        };
        let entity = replay_entity(&self.scan_events(&filter)?).map_err(StoreError::Replay)?;
        let claim_id = entity
            .believed()
            .find(|state| state.lifecycle == ClaimLifecycle::Contested && !state.is_expired_at(now))
            .or_else(|| entity.believed().find(|state| !state.is_expired_at(now)))
            .or_else(|| entity.believed().next())
            .map(|state| state.claim_id.clone());
        match claim_id {
            Some(id) => self.explain(&id, now).map_err(StoreError::Replay),
            None => Ok(None),
        }
    }
}

impl EventStore for InMemoryEventStore {
    fn append(&mut self, event: ClaimEvent) -> Result<AppendReceipt, StoreError> {
        // The firewall: arbitrate against current state and reject inadmissible writes
        // (insufficient or laundered authority, canonical contradiction, ...) before any
        // event is persisted. There is no un-arbitrated write path on this store.
        crate::arbitrate(self, &event)?;
        self.persist(event)
    }

    fn load_claim_events(&self, claim_id: &ClaimId) -> Result<Vec<ClaimEvent>, StoreError> {
        Ok(self
            .by_claim
            .get(claim_id)
            .map(|indices| indices.iter().map(|&i| self.log[i].event.clone()).collect())
            .unwrap_or_default())
    }

    fn scan_events(&self, filter: &EventFilter) -> Result<Vec<ClaimEvent>, StoreError> {
        let matches = self
            .log
            .iter()
            .filter(|stored| {
                filter
                    .claim_id
                    .as_ref()
                    .is_none_or(|c| c == &stored.event.claim_id)
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

/// A read-time integrity receipt for one claim: its current believed state plus the
/// metadata that makes that state auditable. Returned by [`InMemoryEventStore::explain`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityReceipt {
    pub claim_id: ClaimId,
    pub subject: EntityRef,
    pub predicate: Predicate,
    pub value: ClaimValue,
    pub lifecycle: ClaimLifecycle,
    pub authority: AuthorityLevel,
    /// Whether the claim is fresh at the query time (its TTL has not elapsed).
    pub fresh: bool,
    /// The instant the claim's TTL elapses (its freshness anchor + TTL), or `None` for a
    /// non-expiring (`Ttl::Never`) claim. Pairs with `fresh` to explain *why* a read is
    /// stale and *when* it lapsed.
    pub expires_at: Option<TimestampMillis>,
    pub evidence_count: usize,
    pub corroboration: usize,
    pub superseded_by: Option<ClaimId>,
    pub contradicted_by: Vec<ClaimId>,
    /// Global sequence of the claim's most recent event of *any* kind (including audit
    /// events like `retrieved`), not necessarily the state-determining one.
    pub replay_position: u64,
    /// Hash of the claim's most recent event (its link in the global hash chain).
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
        ActorId, Authority, AuthorityLevel, ClaimEvent, ClaimEventId, ClaimEventKind, ClaimId,
        ClaimLifecycle, ClaimValue, Confidence, ContradictionBasis, EntityRef, Evidence,
        EvidenceId, EvidenceKind, Predicate, Provenance, SourceId, SupersessionReason,
        TimestampMillis, Ttl,
    };

    fn assertion(event_id: &str, claim_id: &str, value: &str) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).expect("event id"),
            claim_id: ClaimId::new(claim_id).expect("claim id"),
            kind: ClaimEventKind::Asserted,
            subject: EntityRef::new("repo", "myproj").expect("entity"),
            predicate: Predicate::new("database").expect("predicate"),
            value: Some(ClaimValue::Text(value.to_string())),
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
        }
    }

    #[test]
    fn the_receipt_reports_freshness_and_expiry_at_the_query_time() {
        let mut store = InMemoryEventStore::new();
        let mut event = assertion("event:1", "claim:A", "postgres");
        event.ttl = Ttl::DurationMillis(100); // anchored at recorded_at = 1 -> expires at 101
        store.append(event).expect("append");
        let subject = EntityRef::new("repo", "myproj").unwrap();
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
        assert_eq!(stale.lifecycle, ClaimLifecycle::Active);
    }

    #[test]
    fn a_serialized_log_reloads_through_the_trusted_path_with_an_identical_chain() {
        let now = TimestampMillis::from_unix_millis(100);
        let mut original = InMemoryEventStore::new();
        // Two distinct claims so the chain has more than one link.
        original
            .append(assertion("event:1", "claim:A", "postgres"))
            .expect("append 1");
        original
            .append(assertion("event:2", "claim:B", "redis"))
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
            .map(|line| serde_json::from_str::<ClaimEvent>(line).expect("deserialize"));
        let reloaded = InMemoryEventStore::from_trusted_events(reloaded_events).expect("reload");

        assert_eq!(reloaded.len(), original.len());
        assert!(reloaded.verify_chain());
        // The reloaded store explains each claim identically (same hash, same chain).
        for claim in ["claim:A", "claim:B"] {
            let id = ClaimId::new(claim).unwrap();
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
            .append(assertion("event:0", "claim:A", "postgres"))
            .unwrap();
        original
            .append(assertion("event:1", "claim:B", "redis"))
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
            assertion("event:0", "claim:A", "postgres"),
            assertion("event:1", "claim:B", "mysql"), // the quiet edit
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
        let dup = || assertion("event:1", "claim:A", "postgres");
        let result = InMemoryEventStore::from_trusted_events([dup(), dup()]);
        assert!(matches!(result, Err(crate::StoreError::Conflict(_))));
    }

    fn supersession(event_id: &str, claim_id: &str, by: &str) -> ClaimEvent {
        let mut event = assertion(event_id, claim_id, "ignored");
        event.kind = ClaimEventKind::Superseded {
            by: ClaimId::new(by).expect("by"),
            reason: SupersessionReason::UserCorrection,
        };
        event.value = None;
        event
    }

    fn contradiction(event_id: &str, claim_id: &str, by: &str) -> ClaimEvent {
        let mut event = assertion(event_id, claim_id, "ignored");
        event.kind = ClaimEventKind::Contradicted {
            by: ClaimId::new(by).expect("by"),
            basis: ContradictionBasis::SamePredicateDifferentValue,
        };
        event.value = None;
        event
    }

    #[test]
    fn a_contradiction_contests_the_incumbent_and_keeps_both_believed() {
        // Paraconsistency: a contradiction localizes the conflict (incumbent -> Contested)
        // and *keeps* both claims, rather than dropping one (ADR 0009).
        let mut store = InMemoryEventStore::from_trusted_events([
            assertion("event:0", "claim:A", "postgres"),
            assertion("event:1", "claim:B", "mysql"),
        ])
        .expect("load");
        store
            .append(contradiction("event:2", "claim:A", "claim:B"))
            .expect("contradiction admitted");

        let subject = EntityRef::new("repo", "myproj").unwrap();
        let predicate = Predicate::new("database").unwrap();
        assert_eq!(
            store
                .believed_claim_ids(&subject, &predicate)
                .unwrap()
                .len(),
            2,
            "both the contested incumbent and its contradictor remain believed"
        );
        let now = TimestampMillis::from_unix_millis(100);
        let incumbent = store
            .explain(&ClaimId::new("claim:A").unwrap(), now)
            .unwrap()
            .unwrap();
        assert_eq!(incumbent.lifecycle, ClaimLifecycle::Contested);
        assert_eq!(incumbent.contradicted_by.len(), 1);
    }

    #[test]
    fn explain_surfaces_a_contested_claim_regardless_of_claim_id_order() {
        // "claim:10" sorts BEFORE "claim:9" lexicographically, so a naive first-believed
        // pick would return the Active contradictor and hide the contest. explain must
        // prefer the Contested incumbent.
        let mut store = InMemoryEventStore::from_trusted_events([
            assertion("event:0", "claim:9", "postgres"),
            assertion("event:1", "claim:10", "mysql"),
        ])
        .expect("load");
        store
            .append(contradiction("event:2", "claim:9", "claim:10"))
            .expect("contradiction admitted");

        let receipt = store
            .explain_subject(
                &EntityRef::new("repo", "myproj").unwrap(),
                &Predicate::new("database").unwrap(),
                TimestampMillis::from_unix_millis(100),
            )
            .unwrap()
            .unwrap();
        assert_eq!(receipt.lifecycle, ClaimLifecycle::Contested);
        assert_eq!(receipt.value, ClaimValue::Text("postgres".to_string()));
    }

    #[test]
    fn superseding_every_believed_incumbent_leaves_exactly_one() {
        // Two believed claims coexist for one subject+predicate — the base store enforces
        // no uniqueness (that is the registry's job, and freshness can leave a stale+fresh
        // pair both believed). `supersede` must revise *both*, not just one.
        let mut store = InMemoryEventStore::from_trusted_events([
            assertion("event:0", "claim:A", "postgres"),
            assertion("event:1", "claim:B", "mysql"),
        ])
        .expect("load");
        let subject = EntityRef::new("repo", "myproj").unwrap();
        let predicate = Predicate::new("database").unwrap();
        assert_eq!(
            store
                .believed_claim_ids(&subject, &predicate)
                .unwrap()
                .len(),
            2
        );

        // One replacement, a supersession for EACH incumbent, all pointing at it.
        store
            .append(assertion("event:2", "claim:C", "sqlite"))
            .expect("replacement");
        store
            .append(supersession("event:3", "claim:A", "claim:C"))
            .expect("supersede A");
        store
            .append(supersession("event:4", "claim:B", "claim:C"))
            .expect("supersede B");

        assert_eq!(
            store.believed_claim_ids(&subject, &predicate).unwrap(),
            vec![ClaimId::new("claim:C").unwrap()],
        );
    }
}
