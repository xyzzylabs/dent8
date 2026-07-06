//! The machine-readable outcome `status` shared by the CLI's `--output json` and the MCP tool
//! results, so the two surfaces cannot drift on the vocabulary a consumer branches on.
//!
//! One enum, one wire spelling. [`Status::as_str`] is the single source of truth; the
//! [`serde::Serialize`] impl and the `From<Status> for serde_json::Value` conversion both delegate
//! to it, so there is no second place a spelling could disagree.

/// A dent8 operation's outcome, as it appears in the top-level `status` field of every
/// `--output json` object and every MCP `structuredContent`.
///
/// Serializes to a stable lowercase `snake_case` string (e.g. `"integrity_issues"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    /// A read/verify/list/conflicts scan completed cleanly with nothing to flag.
    Ok,
    /// A write was admitted by the firewall.
    Accepted,
    /// A write was refused by the firewall (insufficient authority, contradiction of a
    /// canonical fact, or terminal immutability).
    Rejected,
    /// The request was malformed — bad input or a parse error that never reached the firewall.
    Invalid,
    /// A subject carries an unresolved contradiction: emitted by `conflicts` when disputes exist,
    /// and by a `contradict` write that records dissent.
    Contested,
    /// `verify` found a hash-chain or attestation integrity problem.
    IntegrityIssues,
    /// An operational failure (I/O, backend) unrelated to any firewall decision.
    Failed,
}

impl Status {
    /// The stable wire string for this status. The one place the spelling is defined.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Invalid => "invalid",
            Self::Contested => "contested",
            Self::IntegrityIssues => "integrity_issues",
            Self::Failed => "failed",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for Status {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl From<Status> for serde_json::Value {
    fn from(status: Status) -> Self {
        serde_json::Value::String(status.as_str().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::Status;

    #[test]
    fn serialize_and_as_str_and_value_agree() {
        // The three representations must never diverge.
        for status in [
            Status::Ok,
            Status::Accepted,
            Status::Rejected,
            Status::Invalid,
            Status::Contested,
            Status::IntegrityIssues,
            Status::Failed,
        ] {
            let via_str = status.as_str();
            let via_serde = serde_json::to_value(status).expect("serialize");
            let via_into: serde_json::Value = status.into();
            assert_eq!(via_serde, serde_json::Value::String(via_str.to_string()));
            assert_eq!(via_into, via_serde);
            assert_eq!(status.to_string(), via_str);
        }
    }

    #[test]
    fn wire_spellings_are_the_documented_snake_case() {
        assert_eq!(Status::Ok.as_str(), "ok");
        assert_eq!(Status::Accepted.as_str(), "accepted");
        assert_eq!(Status::Rejected.as_str(), "rejected");
        assert_eq!(Status::Invalid.as_str(), "invalid");
        assert_eq!(Status::Contested.as_str(), "contested");
        assert_eq!(Status::IntegrityIssues.as_str(), "integrity_issues");
        assert_eq!(Status::Failed.as_str(), "failed");
    }
}
