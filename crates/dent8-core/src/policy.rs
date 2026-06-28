//! Epistemic policy for counterfactual replay.
//!
//! An [`EpistemicPolicy`] parameterises the replay fold so the same immutable event
//! log can be re-folded under different trust assumptions — "distrust source X",
//! "raise the authority floor", "raise the confidence floor" — with no model
//! invocations. The [`EpistemicPolicy::identity`] policy reproduces the
//! un-parameterised fold exactly, so policy-aware replay is a strict superset of
//! plain replay. See `docs/research/novelty.md` (rank 2).
//!
//! Scope: a policy controls which events are *admitted* into the fold. It does not
//! vary the contradiction-resolution rule (that is hard-coded in `apply_event` —
//! a future knob) and it does not evaluate *freshness*. Freshness is deliberately a
//! separate read-time axis — [`crate::ClaimState::is_expired_at`] — so that valid-time
//! staleness is never conflated with the event-driven lifecycle.

use std::collections::BTreeSet;

use crate::ids::SourceId;
use crate::model::{AuthorityLevel, ClaimEvent, ClaimEventKind, Confidence};

/// A set of trust assumptions applied while replaying a claim-event stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EpistemicPolicy {
    /// Events whose provenance source is in this set are treated as if they never
    /// happened. Distrusting the source that *asserted* a claim makes the whole claim
    /// stream absent under this policy.
    pub distrusted_sources: BTreeSet<SourceId>,
    /// Belief-affecting events (assert/reinforce/contradict/supersede) below this
    /// authority are not admitted. The identity floor is [`AuthorityLevel::Unknown`].
    pub authority_floor: AuthorityLevel,
    /// Belief-affecting events below this confidence are not admitted. The identity
    /// floor is [`Confidence::ZERO`].
    pub confidence_floor: Confidence,
}

impl EpistemicPolicy {
    /// The identity policy: admits every event, so a policy-aware replay reproduces
    /// the plain fold exactly.
    #[must_use]
    pub const fn identity() -> Self {
        Self {
            distrusted_sources: BTreeSet::new(),
            authority_floor: AuthorityLevel::Unknown,
            confidence_floor: Confidence::ZERO,
        }
    }

    /// Whether this policy is the identity (no source distrust, no floors).
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.distrusted_sources.is_empty()
            && self.authority_floor == AuthorityLevel::Unknown
            && self.confidence_floor == Confidence::ZERO
    }

    /// Whether the fold should apply `event`. A non-admitted event is skipped as if it
    /// never occurred — the mechanism behind the "distrust source", "raise the
    /// authority floor", and "raise the confidence floor" counterfactuals.
    #[must_use]
    pub fn admits(&self, event: &ClaimEvent) -> bool {
        if self.distrusted_sources.contains(&event.provenance.source) {
            return false;
        }
        if affects_belief(&event.kind)
            && (event.authority.level < self.authority_floor
                || event.confidence < self.confidence_floor)
        {
            return false;
        }
        true
    }
}

impl Default for EpistemicPolicy {
    fn default() -> Self {
        Self::identity()
    }
}

/// Whether an event kind can change what is believed (and so is subject to the
/// authority and confidence floors). Audit and lifecycle-closing events are not
/// gated: retrieval/decision-use never change state, and expiry/retraction are
/// policy- or system-driven rather than authority challenges.
const fn affects_belief(kind: &ClaimEventKind) -> bool {
    matches!(
        kind,
        ClaimEventKind::Asserted
            | ClaimEventKind::Reinforced { .. }
            | ClaimEventKind::Contradicted { .. }
            | ClaimEventKind::Superseded { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::EpistemicPolicy;
    use crate::ids::SourceId;
    use crate::model::{AuthorityLevel, Confidence};

    #[test]
    fn identity_is_identity() {
        assert!(EpistemicPolicy::identity().is_identity());
        assert!(EpistemicPolicy::default().is_identity());
    }

    #[test]
    fn a_distrusted_source_breaks_identity() {
        let mut policy = EpistemicPolicy::identity();
        policy
            .distrusted_sources
            .insert(SourceId::new("source:web-scrape").expect("valid source"));
        assert!(!policy.is_identity());
    }

    #[test]
    fn a_raised_authority_floor_breaks_identity() {
        let policy = EpistemicPolicy {
            authority_floor: AuthorityLevel::High,
            ..EpistemicPolicy::identity()
        };
        assert!(!policy.is_identity());
    }

    #[test]
    fn a_raised_confidence_floor_breaks_identity() {
        let policy = EpistemicPolicy {
            confidence_floor: Confidence::from_millis(500).expect("confidence"),
            ..EpistemicPolicy::identity()
        };
        assert!(!policy.is_identity());
    }
}
