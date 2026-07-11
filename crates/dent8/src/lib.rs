//! **dent8** — a memory firewall for coding agents, as a library.
//!
//! This crate is the front door to the dent8 workspace: one import for the event model
//! ([`FactEvent`] and friends, from `dent8-core`), the firewall + stores ([`EventStore`],
//! [`InMemoryEventStore`], `arbitrate`, from `dent8-store`), and an ergonomic [`FactBuilder`]
//! for constructing valid events. The `dent8` *binary* (CLI + MCP server) lives in the
//! `dent8-cli` package; this crate is what `cargo add dent8` should mean.
//!
//! The core loop — write through the firewall, watch it refuse a bad write, replay why:
//!
//! ```
//! use dent8::prelude::*;
//!
//! let mut store = InMemoryEventStore::new();
//!
//! // A trusted fact enters through the firewall (`append` arbitrates before persisting).
//! let fact = FactBuilder::assert("repo:myproj", "database", "postgres")
//!     .authority(AuthorityLevel::High)
//!     .source("user:alice")
//!     .evidence_note("design meeting 2026-07-01")
//!     .recorded_at(1_000)
//!     .seq(0)
//!     .build()?;
//! store.append(fact)?;
//!
//! // A low-authority overwrite of the same fact is refused, not silently applied.
//! let overwrite = FactBuilder::assert("repo:myproj", "database", "mysql")
//!     .authority(AuthorityLevel::Low)
//!     .source("web:scrape")
//!     .evidence_note("some blog post")
//!     .recorded_at(2_000)
//!     .seq_for_fact(1, 0) // a new event (1) challenging the existing fact stream (0)
//!     .build()?;
//! assert!(store.append(overwrite).is_err());
//!
//! // The believed state replays from the surviving events.
//! let events = store.load_fact_events(&FactId::new("fact:repo:myproj:database:0")?)?;
//! let state = replay_fact(&events)?.expect("believed");
//! assert_eq!(state.value, FactValue::Text("postgres".into()));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! For persistence beyond memory, enable `async-store` and use a backend adapter crate
//! (`dent8-store-sqlite`, `dent8-store-postgres`); for the Ed25519 witness primitive, enable
//! `signed-anchor`.

/// The event model, hashing, and per-fact firewall (`dent8-core`), as a module.
pub use dent8_core as core;
/// The store trait, in-memory firewall store, and replay/audit functions (`dent8-store`).
pub use dent8_store as store;

pub use dent8_core::{
    ActorId, Authority, AuthorityLevel, CanonError, ChallengeKind, ChallengeRejection, Confidence,
    ContradictionBasis, EpistemicPolicy, Evidence, EvidenceId, EvidenceKind, ExpirationReason,
    FactEvent, FactEventId, FactEventKind, FactId, FactLifecycle, FactState, FactValue, IdError,
    Predicate, Provenance, RetractionReason, SourceId, Subject, SupersessionReason,
    TimestampMillis, TransitionError, Ttl, ValidationError, apply_event, attestation_message,
    canonical_bytes, event_hash, hash_chain,
};
#[cfg(feature = "async-store")]
pub use dent8_store::AsyncEventStore;
pub use dent8_store::{
    AppendReceipt, EventFilter, EventStore, InMemoryEventStore, IntegrityReceipt, PredicatePolicy,
    PredicateRegistry, ReplayError, StoreError, SubjectProjection, TaintedFact,
    apply_policy_defaults, arbitrate, arbitrate_events, enforce_policy, replay_fact,
    replay_subject, tainted_facts,
};

/// The working vocabulary in one import: `use dent8::prelude::*;`.
pub mod prelude {
    pub use crate::{
        AuthorityLevel, EventStore, FactBuilder, FactEvent, FactEventKind, FactId, FactState,
        FactValue, InMemoryEventStore, Predicate, Subject, TimestampMillis, replay_fact,
        replay_subject,
    };
}

/// Build a valid [`FactEvent`] without spelling out every struct field. The builder owns the
/// boilerplate (confidence, ttl, provenance defaults) and validates the identifier grammar;
/// the *firewall* still arbitrates the finished event on `append` — building an event admits
/// nothing.
///
/// Required before [`build`](FactBuilder::build): a source, a recorded-at instant (explicit —
/// the library never grabs the wall clock silently), ids (via [`seq`](FactBuilder::seq) /
/// [`seq_for_fact`](FactBuilder::seq_for_fact) or explicit [`ids`](FactBuilder::ids)), and at
/// least one evidence entry for an assertion (the model requires it).
#[derive(Debug, Clone)]
pub struct FactBuilder {
    subject: String,
    predicate: String,
    kind: FactEventKind,
    value: Option<FactValue>,
    authority: AuthorityLevel,
    issuer: Option<String>,
    scope: Option<String>,
    confidence: Confidence,
    ttl: Ttl,
    source: Option<String>,
    actor: String,
    tool: Option<String>,
    recorded_at: Option<i64>,
    evidence: Vec<Evidence>,
    evidence_notes: Vec<String>,
    observed_at: Option<i64>,
    valid_from: Option<i64>,
    valid_to: Option<i64>,
    event_id: Option<String>,
    fact_id: Option<String>,
}

impl FactBuilder {
    /// Start an assertion: `subject` in the CLI's `kind:key` grammar (e.g. `repo:myproj`),
    /// a predicate, and the asserted text value.
    #[must_use]
    pub fn assert(
        subject: impl Into<String>,
        predicate: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            subject: subject.into(),
            predicate: predicate.into(),
            kind: FactEventKind::Asserted,
            value: Some(FactValue::Text(value.into())),
            authority: AuthorityLevel::Low,
            issuer: None,
            scope: None,
            confidence: Confidence::ASSERTED,
            ttl: Ttl::Never,
            source: None,
            actor: "actor:dent8".to_string(),
            tool: None,
            recorded_at: None,
            evidence: Vec::new(),
            evidence_notes: Vec::new(),
            observed_at: None,
            valid_from: None,
            valid_to: None,
            event_id: None,
            fact_id: None,
        }
    }

    /// The stated authority level (default [`AuthorityLevel::Low`] — never silently high).
    #[must_use]
    pub fn authority(mut self, level: AuthorityLevel) -> Self {
        self.authority = level;
        self
    }

    /// The authority's issuer/scope metadata (recorded, enforced by the write-boundary gates).
    #[must_use]
    pub fn authority_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// See [`authority_issuer`](Self::authority_issuer).
    #[must_use]
    pub fn authority_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// The provenance source id (e.g. `user:alice`). Required.
    #[must_use]
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// The acting agent id (default `actor:dent8`).
    #[must_use]
    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = actor.into();
        self
    }

    /// The tool that produced the write, recorded in provenance.
    #[must_use]
    pub fn tool(mut self, tool: impl Into<String>) -> Self {
        self.tool = Some(tool.into());
        self
    }

    /// Confidence in millis of probability (default [`Confidence::ASSERTED`]).
    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Retention TTL (default [`Ttl::Never`]).
    #[must_use]
    pub fn ttl(mut self, ttl: Ttl) -> Self {
        self.ttl = ttl;
        self
    }

    /// When the event was recorded, unix millis. Required — the library never reads the wall
    /// clock behind your back; determinism is the product.
    #[must_use]
    pub fn recorded_at(mut self, unix_millis: i64) -> Self {
        self.recorded_at = Some(unix_millis);
        self
    }

    /// Attach a fully-formed [`Evidence`] entry.
    #[must_use]
    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Convenience: attach a [`EvidenceKind::UserStatement`] with this locator text. An
    /// assertion needs at least one evidence entry.
    #[must_use]
    pub fn evidence_note(mut self, locator: impl Into<String>) -> Self {
        self.evidence_notes.push(locator.into());
        self
    }

    /// When the underlying observation happened (unix millis), if distinct from `recorded_at`.
    #[must_use]
    pub fn observed_at(mut self, unix_millis: i64) -> Self {
        self.observed_at = Some(unix_millis);
        self
    }

    /// Asserted valid-time lower bound (unix millis).
    #[must_use]
    pub fn valid_from(mut self, unix_millis: i64) -> Self {
        self.valid_from = Some(unix_millis);
        self
    }

    /// Asserted valid-time upper bound (unix millis).
    #[must_use]
    pub fn valid_to(mut self, unix_millis: i64) -> Self {
        self.valid_to = Some(unix_millis);
        self
    }

    /// Derive ids by sequence number using the CLI's conventions: event `event:{seq}`, fact
    /// `fact:{kind}:{key}:{predicate}:{seq}`. Right when this event *starts* a fact stream.
    #[must_use]
    pub fn seq(self, seq: u64) -> Self {
        self.seq_for_fact(seq, seq)
    }

    /// Derive ids with distinct sequences: this event is `event:{event_seq}`, and it addresses
    /// the fact stream that *started* at `fact_seq` (`fact:{kind}:{key}:{predicate}:{fact_seq}`)
    /// — e.g. a challenge to an existing fact.
    #[must_use]
    pub fn seq_for_fact(mut self, event_seq: u64, fact_seq: u64) -> Self {
        self.event_id = Some(format!("event:{event_seq}"));
        self.fact_id = Some(format!(
            "fact:{}:{}:{fact_seq}",
            self.subject, self.predicate
        ));
        self
    }

    /// Set both ids explicitly (any grammar-valid ids).
    #[must_use]
    pub fn ids(mut self, event_id: impl Into<String>, fact_id: impl Into<String>) -> Self {
        self.event_id = Some(event_id.into());
        self.fact_id = Some(fact_id.into());
        self
    }

    /// Validate and produce the event. Errors name the missing/invalid piece; the returned
    /// event still faces the firewall on `append`.
    pub fn build(self) -> Result<FactEvent, String> {
        let (kind, key) = self
            .subject
            .split_once(':')
            .ok_or_else(|| format!("subject '{}' must be <kind>:<key>", self.subject))?;
        let subject = Subject::new(kind, key).map_err(|e| format!("subject: {e}"))?;
        let predicate = Predicate::new(&self.predicate).map_err(|e| format!("predicate: {e}"))?;
        let source = self
            .source
            .ok_or_else(|| "a source is required (builder.source(\"user:alice\"))".to_string())?;
        let recorded_at = self.recorded_at.ok_or_else(|| {
            "recorded_at is required (builder.recorded_at(unix_millis))".to_string()
        })?;
        let event_id = self
            .event_id
            .ok_or_else(|| "ids are required (builder.seq(n) or builder.ids(...))".to_string())?;
        let fact_id = self
            .fact_id
            .ok_or_else(|| "ids are required (builder.seq(n) or builder.ids(...))".to_string())?;
        let mut evidence = self.evidence;
        for (index, locator) in self.evidence_notes.into_iter().enumerate() {
            evidence.push(Evidence {
                id: EvidenceId::new(format!("evidence:{event_id}:{index}"))
                    .map_err(|e| format!("evidence id: {e}"))?,
                kind: EvidenceKind::UserStatement,
                locator,
                digest: None,
                summary: None,
            });
        }
        let event = FactEvent {
            event_id: FactEventId::new(&event_id).map_err(|e| format!("event id: {e}"))?,
            fact_id: FactId::new(&fact_id).map_err(|e| format!("fact id: {e}"))?,
            kind: self.kind,
            subject,
            predicate,
            value: self.value,
            confidence: self.confidence,
            authority: Authority {
                level: self.authority,
                issuer: self.issuer,
                scope: self.scope,
            },
            ttl: self.ttl,
            provenance: Provenance {
                source: SourceId::new(&source).map_err(|e| format!("source: {e}"))?,
                actor: ActorId::new(&self.actor).map_err(|e| format!("actor: {e}"))?,
                tool: self.tool,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(recorded_at),
                attestation: None,
            },
            evidence,
            observed_at: self.observed_at.map(TimestampMillis::from_unix_millis),
            valid_from: self.valid_from.map(TimestampMillis::from_unix_millis),
            valid_to: self.valid_to.map(TimestampMillis::from_unix_millis),
        };
        event
            .validate()
            .map_err(|e| format!("invalid event: {e}"))?;
        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::prelude::*;

    #[test]
    fn the_builder_produces_a_valid_event_the_firewall_admits() {
        let mut store = InMemoryEventStore::new();
        let fact = FactBuilder::assert("repo:myproj", "database", "postgres")
            .authority(AuthorityLevel::High)
            .source("user:alice")
            .evidence_note("decision record")
            .recorded_at(1_000)
            .seq(0)
            .build()
            .expect("valid event");
        assert_eq!(fact.event_id.as_str(), "event:0");
        assert_eq!(fact.fact_id.as_str(), "fact:repo:myproj:database:0");
        store.append(fact).expect("admitted");
    }

    #[test]
    fn the_firewall_still_arbitrates_built_events() {
        let mut store = InMemoryEventStore::new();
        store
            .append(
                FactBuilder::assert("repo:myproj", "database", "postgres")
                    .authority(AuthorityLevel::High)
                    .source("user:alice")
                    .evidence_note("decision record")
                    .recorded_at(1_000)
                    .seq(0)
                    .build()
                    .expect("valid"),
            )
            .expect("admitted");
        // Same fact stream, weaker authority — refused by arbitration, not by the builder.
        let overwrite = FactBuilder::assert("repo:myproj", "database", "mysql")
            .authority(AuthorityLevel::Low)
            .source("web:scrape")
            .evidence_note("blog post")
            .recorded_at(2_000)
            .seq_for_fact(1, 0)
            .build()
            .expect("valid shape");
        assert!(store.append(overwrite).is_err());
    }

    #[test]
    fn build_errors_name_the_missing_piece() {
        let missing_source = FactBuilder::assert("a:b", "p", "v")
            .recorded_at(1)
            .seq(0)
            .build()
            .unwrap_err();
        assert!(missing_source.contains("source"), "{missing_source}");

        let missing_ids = FactBuilder::assert("a:b", "p", "v")
            .source("user:x")
            .recorded_at(1)
            .build()
            .unwrap_err();
        assert!(missing_ids.contains("ids"), "{missing_ids}");

        let missing_evidence = FactBuilder::assert("a:b", "p", "v")
            .source("user:x")
            .recorded_at(1)
            .seq(0)
            .build()
            .unwrap_err();
        assert!(missing_evidence.contains("evidence"), "{missing_evidence}");

        let bad_subject = FactBuilder::assert("no-colon", "p", "v")
            .source("user:x")
            .recorded_at(1)
            .seq(0)
            .build()
            .unwrap_err();
        assert!(bad_subject.contains("<kind>:<key>"), "{bad_subject}");
    }
}
