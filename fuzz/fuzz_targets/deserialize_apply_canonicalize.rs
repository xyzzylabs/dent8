//! Fuzz the most attacker-exposed path in dent8: **untrusted bytes → `ClaimEvent`
//! deserialize → firewall fold → canonicalize/hash/attest**.
//!
//! Every stored log line, Postgres/SQLite `event_json` row, and MCP payload takes this path,
//! so nothing on it may panic, and the canonicalization invariants must hold for *every*
//! event serde accepts — not just ones dent8 itself would construct:
//!
//! 1. `canonical_bytes` is **reload-stable**: parse(canonical(e)) re-canonicalizes to the
//!    identical bytes (otherwise a stored hash would fail after a round-trip).
//! 2. `event_hash` is deterministic over those bytes.
//! 3. `attestation_message` never panics and is independent of any carried attestation.
//! 4. The pure fold (`replay_claim`) accepts or rejects — it must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(event) = serde_json::from_slice::<dent8_core::ClaimEvent>(data) else {
        return;
    };

    // (1) Reload stability: canonical form must be a fixed point through serde.
    let canonical = dent8_core::canonical_bytes(&event).expect("canonicalize accepted event");
    let reparsed: dent8_core::ClaimEvent =
        serde_json::from_slice(&canonical).expect("canonical bytes re-parse");
    let recanonical = dent8_core::canonical_bytes(&reparsed).expect("re-canonicalize");
    assert_eq!(canonical, recanonical, "canonical bytes are not a fixed point");

    // (2) Hashing is total + deterministic over accepted events.
    let first = dent8_core::event_hash(&event, None).expect("hash accepted event");
    let second = dent8_core::event_hash(&reparsed, None).expect("hash reparsed event");
    assert_eq!(first, second, "event hash diverged across a serde round-trip");

    // (3) The attestation message strips the attestation and never panics.
    let message = dent8_core::attestation_message(&event).expect("attestation message");
    let mut stripped = event.clone();
    stripped.provenance.attestation = None;
    assert_eq!(
        message,
        dent8_core::attestation_message(&stripped).expect("attestation message"),
        "attestation message depends on the carried attestation"
    );

    // (4) The pure firewall fold is total: accept or reject, never panic.
    let _ = dent8_store::replay_claim(std::slice::from_ref(&event));
});
