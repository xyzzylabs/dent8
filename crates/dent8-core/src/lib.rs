//! Core domain model for dent8.
//!
//! The public model intentionally starts with claim events rather than memory
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
pub use hash::{CanonError, canonical_bytes, event_hash, hash_chain};
pub use ids::{ActorId, ClaimEventId, ClaimId, EvidenceId, IdError, SourceId, TimestampMillis};
pub use model::{
    Authority, AuthorityLevel, CanonicalJson, ClaimEvent, ClaimEventKind, ClaimValue, Confidence,
    ContradictionBasis, EntityRef, Evidence, EvidenceKind, ExpirationReason, Predicate, Provenance,
    RetractionReason, SupersessionReason, Ttl, ValidationError,
};
pub use policy::EpistemicPolicy;
pub use state::{ClaimLifecycle, ClaimState, TransitionError, apply_event};
