//! Core domain model for dent8.
//!
//! The public model intentionally starts with fact events rather than memory
//! items. Materialized memory is a replayed projection of the event log.

pub mod anchor;
pub mod hash;
pub mod ids;
pub mod model;
pub mod policy;
pub mod state;

pub use anchor::{ChainAnchor, anchor_head, verify_anchor};
#[cfg(feature = "signed-anchor")]
pub use anchor::{SignedTreeHead, sign_head, verify_signed_head};
pub use hash::{CanonError, attestation_message, canonical_bytes, event_hash, hash_chain};
pub use ids::{ActorId, EvidenceId, FactEventId, FactId, IdError, SourceId, TimestampMillis};
pub use model::{
    AttestationAlgorithm, Authority, AuthorityLevel, CanonicalJson, ChallengeKind,
    ChallengeRejection, Confidence, ContradictionBasis, EntityRef, Evidence, EvidenceKind,
    ExpirationReason, FactEvent, FactEventKind, FactValue, Predicate, Provenance, RetractionReason,
    SupersessionReason, Ttl, ValidationError, WriteAttestation,
};
pub use policy::EpistemicPolicy;
pub use state::{FactLifecycle, FactState, TransitionError, apply_event};
