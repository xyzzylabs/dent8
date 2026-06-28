//! External tamper-*resistance* anchor for the event-log hash chain.
//!
//! The per-event hash chain ([`crate::hash`]) is tamper-*evident*: altering an event
//! without recomputing its hash is caught on replay. It is **not** tamper-*resistant*
//! against a writer with full store access who edits an event **and** re-hashes the whole
//! log forward — that rewritten chain is internally self-consistent, so an internal
//! re-verify passes (this is the [threat model](../../docs/threat-model.md) T6 residual).
//!
//! The defense is an **external** anchor: a commitment to the chain head (event count +
//! head digest) authenticated by a key the writer does **not** hold (an external witness).
//! If the writer rewrites history the head changes, and the witness's old commitment no
//! longer matches; the writer cannot forge a fresh one without the key.
//!
//! This v0 is a keyed **HMAC-SHA256** commitment over a domain-separated, length-framed
//! `(count, head)` tuple. It is *symmetric*: the verifier must hold the same witness key,
//! which must be kept off the writer's machine for the resistance to hold. An *asymmetric*
//! signed tree head (RFC 6962-style, so anyone can verify a published head) is the
//! production upgrade — it needs a signature dependency this keyless v0 deliberately
//! avoids (it reuses only the SHA-256 already in `hash.rs`).
//!
//! **These functions are the primitive, not a witness deployment.** Resistance holds only
//! if the witness (a) issues the anchor at write time, (b) holds the key off the writer,
//! and (c) publishes a **monotonic, append-only** anchor sequence (non-decreasing
//! `event_count`) so that a *never-issued* anchor or a *rolled-back* old anchor is itself
//! detectable. A writer that holds the key, never anchors, or replays a stale anchor gets
//! no resistance. See the threat model's T6 residuals.

use sha2::{Digest, Sha256};

use crate::hash::{CANON_VERSION, CanonError, hash_chain};
use crate::model::ClaimEvent;

/// Domain-separation prefix for an anchor (tree-head) commitment — distinct from the
/// `0x00` leaf and `0x01` interior-node prefixes used in [`crate::hash`].
const ANCHOR_PREFIX: u8 = 0x02;

/// SHA-256 block size, used by the HMAC construction.
const BLOCK_LEN: usize = 64;

/// An authenticated commitment to a log's chain head at a point in time: the event count
/// and the head digest, MAC'd under a witness key. Storing/publishing this lets a later
/// reader detect a history rewrite that an internal chain re-verify
/// ([`crate::hash_chain`]) cannot.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainAnchor {
    pub event_count: u64,
    /// Lowercase-hex head digest, or `None` for an empty log.
    pub head: Option<String>,
    /// Lowercase-hex HMAC-SHA256 over the framed `(count, head)` under the witness key.
    pub mac: String,
}

/// Commit to the current chain head under `witness_key`. For the anchor to add
/// tamper-*resistance* (not just evidence), the key must be held by a party **other than**
/// the log writer — a writer who also holds the key can simply re-anchor a rewrite.
pub fn anchor_head(events: &[ClaimEvent], witness_key: &[u8]) -> Result<ChainAnchor, CanonError> {
    let head = hash_chain(events)?.pop();
    let event_count = events.len() as u64;
    let mac = hex::encode(hmac_sha256(
        witness_key,
        &anchor_message(event_count, head.as_deref()),
    ));
    Ok(ChainAnchor {
        event_count,
        head,
        mac,
    })
}

/// Verify `anchor` against the current `events` under `witness_key`: recompute the head and
/// count, recompute the MAC, and constant-time-compare. Returns `Ok(false)` (not an error)
/// when the log no longer matches the commitment — i.e. tamper detected, including the
/// re-hashed-forward rewrite an internal re-verify would miss.
///
/// `Err` means verification could not be *performed* (a canonicalization failure), **not**
/// that the anchor is valid — treat it as **not verified**. Never collapse the result with
/// `.is_ok()` or `.unwrap_or(true)`: only `Ok(true)` means verified.
pub fn verify_anchor(
    events: &[ClaimEvent],
    anchor: &ChainAnchor,
    witness_key: &[u8],
) -> Result<bool, CanonError> {
    let head = hash_chain(events)?.pop();
    let event_count = events.len() as u64;
    let expected = hex::encode(hmac_sha256(
        witness_key,
        &anchor_message(event_count, head.as_deref()),
    ));
    Ok(event_count == anchor.event_count
        && head == anchor.head
        && constant_time_eq(expected.as_bytes(), anchor.mac.as_bytes()))
}

/// Domain-separated, length-framed message committed to by an anchor: `ANCHOR_PREFIX ||
/// CANON_VERSION || count(8 BE) || head_present(0|1) [|| len(head)(8 BE) || head]`. The
/// length frame and the present/absent tag make `(count, head)` pairs unambiguous.
fn anchor_message(count: u64, head: Option<&str>) -> Vec<u8> {
    let mut message = vec![ANCHOR_PREFIX, CANON_VERSION];
    message.extend_from_slice(&count.to_be_bytes());
    match head {
        None => message.push(0u8),
        Some(head) => {
            message.push(1u8);
            message.extend_from_slice(&(head.len() as u64).to_be_bytes());
            message.extend_from_slice(head.as_bytes());
        }
    }
    message
}

/// HMAC-SHA256 (RFC 2104) built on the `sha2` already used for the chain — no extra
/// dependency. The key is hashed if it exceeds the block size, then zero-padded.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    for ((byte, inner), outer) in block.iter().zip(ipad.iter_mut()).zip(opad.iter_mut()) {
        *inner ^= byte;
        *outer ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);

    let mut mac = [0u8; 32];
    mac.copy_from_slice(&outer.finalize());
    mac
}

/// Length-independent-result constant-time byte comparison (no early return on mismatch).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---- Asymmetric (publicly-verifiable) anchor — feature `signed-anchor` ----------------
//
// The HMAC anchor above is *symmetric*: the verifier must hold the witness key. A
// **signed tree head** (RFC 6962-style) instead signs the same domain-separated
// `(count, head)` message with an Ed25519 key, so **anyone with the public key can verify
// a published head** — the witness keeps only the private key. This is the upgrade that
// makes the anchor publicly auditable rather than shared-secret.

/// An Ed25519-signed commitment to a log's chain head — a publicly-verifiable tree head.
#[cfg(feature = "signed-anchor")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignedTreeHead {
    pub event_count: u64,
    /// Lowercase-hex head digest, or `None` for an empty log.
    pub head: Option<String>,
    /// Lowercase-hex Ed25519 signature over the framed `(count, head)` message.
    pub signature: String,
}

/// Sign the current chain head with `signing_key`. The signature commits to the same
/// domain-separated message the HMAC anchor uses, so the framings cannot be confused.
#[cfg(feature = "signed-anchor")]
pub fn sign_head(
    events: &[ClaimEvent],
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<SignedTreeHead, CanonError> {
    use ed25519_dalek::Signer;

    let head = hash_chain(events)?.pop();
    let event_count = events.len() as u64;
    let signature = signing_key.sign(&anchor_message(event_count, head.as_deref()));
    Ok(SignedTreeHead {
        event_count,
        head,
        signature: hex::encode(signature.to_bytes()),
    })
}

/// Verify a [`SignedTreeHead`] against the current `events` using only the **public**
/// `verifying_key` — no secret required. Returns `Ok(false)` (not an error) when the log no
/// longer matches the commitment or the signature does not verify (tamper detected).
///
/// `Err` means verification could not be *performed* (a canonicalization failure), **not**
/// that the head is valid — treat it as **not verified**. Never collapse the result with
/// `.is_ok()` or `.unwrap_or(true)`: only `Ok(true)` means verified.
#[cfg(feature = "signed-anchor")]
pub fn verify_signed_head(
    events: &[ClaimEvent],
    head: &SignedTreeHead,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<bool, CanonError> {
    use ed25519_dalek::Signature;

    let recomputed = hash_chain(events)?.pop();
    let event_count = events.len() as u64;
    // Redundant with the signature (which binds both fields) — a cheap short-circuit that
    // also yields a clean `Ok(false)` on a count/head mismatch before the curve op.
    if event_count != head.event_count || recomputed != head.head {
        return Ok(false);
    }
    let Ok(bytes) = hex::decode(&head.signature) else {
        return Ok(false);
    };
    let Ok(bytes) = <[u8; 64]>::try_from(bytes.as_slice()) else {
        return Ok(false);
    };
    let signature = Signature::from_bytes(&bytes);
    // `verify_strict` additionally rejects small-order points and pins one canonical
    // verification equation (vs the plain `verify`); the witness signs with `sign`.
    Ok(verifying_key
        .verify_strict(
            &anchor_message(event_count, recomputed.as_deref()),
            &signature,
        )
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::{ChainAnchor, anchor_head, hmac_sha256, verify_anchor};
    use crate::ids::{ActorId, ClaimEventId, ClaimId, EvidenceId, SourceId, TimestampMillis};
    use crate::model::{
        Authority, AuthorityLevel, ClaimEvent, ClaimEventKind, ClaimValue, Confidence, EntityRef,
        Evidence, EvidenceKind, Predicate, Provenance, Ttl,
    };

    const KEY: &[u8] = b"witness-secret-held-off-the-writer";

    fn asserted(event_id: &str, value: &str) -> ClaimEvent {
        ClaimEvent {
            event_id: ClaimEventId::new(event_id).expect("event id"),
            claim_id: ClaimId::new("claim:1").expect("claim id"),
            kind: ClaimEventKind::Asserted,
            subject: EntityRef::new("repo", "dent8").expect("entity"),
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
                source: SourceId::new("source:test").expect("source"),
                actor: ActorId::new("actor:test").expect("actor"),
                tool: None,
                run_id: None,
                input_digest: None,
                recorded_at: TimestampMillis::from_unix_millis(1),
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
    fn an_anchor_verifies_against_its_own_log() {
        let events = [
            asserted("event:0", "postgres"),
            asserted("event:1", "redis"),
        ];
        let anchor = anchor_head(&events, KEY).expect("anchor");
        assert_eq!(anchor.event_count, 2);
        assert!(anchor.head.is_some());
        assert!(verify_anchor(&events, &anchor, KEY).expect("verify"));
    }

    #[test]
    fn an_empty_log_anchors_and_verifies() {
        let events: [ClaimEvent; 0] = [];
        let anchor = anchor_head(&events, KEY).expect("anchor");
        assert_eq!(anchor.event_count, 0);
        assert!(anchor.head.is_none());
        assert!(verify_anchor(&events, &anchor, KEY).expect("verify"));
    }

    #[test]
    fn a_rehashed_forward_rewrite_is_caught_by_the_anchor() {
        // The operator-with-DB-access attack: edit an event AND recompute the whole chain
        // forward, producing an internally-consistent (re-verifying) log. The external
        // anchor still rejects it because the head changed and the witness MAC cannot be
        // forged without the key.
        let original = [
            asserted("event:0", "postgres"),
            asserted("event:1", "redis"),
        ];
        let anchor = anchor_head(&original, KEY).expect("anchor");

        let rewritten = [
            asserted("event:0", "postgres"),
            asserted("event:1", "mysql"), // the operator's quiet edit
        ];
        // The rewritten log is internally consistent (its own chain re-verifies), yet the
        // external anchor detects the rewrite.
        assert!(
            !verify_anchor(&rewritten, &anchor, KEY).expect("verify"),
            "a re-hashed-forward rewrite must fail anchor verification"
        );
    }

    #[test]
    fn the_wrong_witness_key_does_not_verify() {
        let events = [asserted("event:0", "postgres")];
        let anchor = anchor_head(&events, KEY).expect("anchor");
        assert!(!verify_anchor(&events, &anchor, b"attacker-key").expect("verify"));
    }

    #[test]
    fn a_truncated_log_is_caught_even_if_its_own_chain_is_valid() {
        // Dropping the last event leaves a perfectly valid shorter chain — but the count
        // and head no longer match the anchor.
        let full = [
            asserted("event:0", "postgres"),
            asserted("event:1", "redis"),
        ];
        let anchor = anchor_head(&full, KEY).expect("anchor");
        let truncated = [asserted("event:0", "postgres")];
        assert!(!verify_anchor(&truncated, &anchor, KEY).expect("verify"));
    }

    #[test]
    fn a_tampered_mac_does_not_verify() {
        let events = [asserted("event:0", "postgres")];
        let mut anchor = anchor_head(&events, KEY).expect("anchor");
        anchor.mac = ChainAnchor {
            event_count: anchor.event_count,
            head: anchor.head.clone(),
            mac: "00".repeat(32),
        }
        .mac;
        assert!(!verify_anchor(&events, &anchor, KEY).expect("verify"));
    }

    #[test]
    fn hmac_matches_a_known_rfc4231_vector() {
        // RFC 4231 test case 1: key = 0x0b*20, data = "Hi There".
        let key = [0x0bu8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        assert_eq!(hex::encode(mac), expected);
    }

    #[cfg(feature = "signed-anchor")]
    #[test]
    fn a_signed_tree_head_is_publicly_verifiable_and_tamper_detecting() {
        use super::{sign_head, verify_signed_head};
        use ed25519_dalek::SigningKey;

        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let events = [
            asserted("event:0", "postgres"),
            asserted("event:1", "redis"),
        ];
        let sth = sign_head(&events, &signing_key).expect("sign");

        // Anyone holding only the PUBLIC key can verify the witness's signed head.
        assert!(verify_signed_head(&events, &sth, &verifying_key).expect("verify"));

        // A re-hashed-forward rewrite is detected: the head changes and the signature, which
        // the writer cannot forge without the private key, no longer verifies.
        let rewritten = [
            asserted("event:0", "postgres"),
            asserted("event:1", "mysql"),
        ];
        assert!(!verify_signed_head(&rewritten, &sth, &verifying_key).expect("verify"));

        // A different (attacker) key does not verify the witness's signature.
        let attacker = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert!(!verify_signed_head(&events, &sth, &attacker).expect("verify"));
    }
}
