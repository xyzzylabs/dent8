# ADR 0013 - Signed write attestation in provenance

Date: 2026-07-02

## Status

Accepted.

## Context

Signed source identity (ADR 0012) verifies at the write boundary that the caller holds the
source private key — but the proof was ephemeral: the write-payload signature was checked
in-process and **discarded**. Nothing persisted let anyone re-verify, after the fact, that an
event was actually written by the key its source claims. Review flagged the sign-then-discard
as ceremony: it added nothing over the key/grant match check, and the event log carried no
cryptographic attribution.

This is the last window to change the event format cheaply: dent8 is unreleased, so a
format-affecting addition costs nothing today and a migration later.

## Decision

Persist the per-write signature **in the event itself**: `provenance.attestation` is an
optional `WriteAttestation { algorithm, public_key, signature }`.

- **What is signed.** `attestation_message(event)` (dent8-core): the domain tag
  `dent8.event-attestation.v1\0`, then the length-framed canonical bytes of the event with
  `provenance.attestation` stripped (a signature cannot cover itself). Both the signer and
  any later verifier derive the message from the stored event alone, so an attested event is
  **offline-re-verifiable**: recompute the message, check the embedded signature against the
  embedded public key.
- **When it is signed.** At the append choke point (`append_events`), after every op-level
  mutation and immediately before persistence — so the signature covers exactly the stored
  content, and the hash chain covers the attestation bytes. (The assert/derive paths attest
  before computing the user-facing receipt hash; Ed25519 signing is deterministic (RFC 8032),
  so the re-sign at append is byte-identical.) Signing is active exactly when signed identity
  is configured (same detection as the ADR 0012 write gate); unconfigured dev mode writes
  unattested events. The ephemeral write-payload signature from ADR 0012 is **removed** —
  the persisted attestation is the possession proof.
- **How it is verified.** `dent8 verify` (file and backend paths, and therefore the MCP
  `verify` tool and `doctor`) re-verifies every persisted attestation and reports the count;
  an invalid attestation is an integrity failure. On the **file dev store** this is the one
  content-tamper check available without a witness: the file log stores no per-event hash, so
  editing an attested event was previously undetectable — now it breaks the signature. A
  `--no-default-features` build cannot verify (no Ed25519); it honestly reports attestations
  as present but not verifiable.

## Canonical-encoding compatibility (no CANON_VERSION bump)

`attestation` is `#[serde(default, skip_serializing_if = "Option::is_none")]`: an unattested
event serializes **byte-identically** to the pre-attestation encoding, so every existing
stored hash, witness head, and golden fixture keeps verifying. Events carrying the field
produce bytes no v1 event could have emitted (the key never existed before), so there is no
cross-version collision. This is codified as the "adding optional fields" rule in
`dent8-core/src/hash.rs`; any change outside that rule still requires the ADR 0004 item 7
versioning procedure.

## Security properties

This adds, over ADR 0012:

- **Durable attribution**: each attested event carries an Ed25519 proof that the holder of
  `public_key` signed exactly this content — replayable and auditable long after the write,
  by anyone, without dent8's trust files.
- **Content-tamper evidence on the file store**: an edit to an attested event breaks its
  signature even though the file log stores no hash chain.
- **Non-repudiation groundwork**: combined with the witness layer (which pins *when* the
  event existed), an attested event binds *who-wrote-what* to *what-existed-when*.

This does **not** provide:

- **Grant-validity-at-write-time.** Verification checks the signature against the *embedded*
  key. Whether that key was granted the claimed source/authority **at the time of the write**
  requires grant history (grants can rotate/expire); today's check answers "is this the
  content that key signed", and the write-boundary gate (ADR 0012) answers entitlement at
  write time. A future grant-history log could close the gap retroactively.
- Protection against a compromised source key, malware as the same OS user, or direct store
  writes bypassing the CLI/MCP boundary — unchanged from ADR 0012.
- Backfill: events written before this ADR (or in dev mode) are simply unattested; `verify`
  treats them as legitimate v1 events.

## Consequences

- The write path signs one Ed25519 signature per event (sub-millisecond; writes are rare).
- `WriteAuth` slims to subject/authority/source — the write-boundary gate checks entitlement,
  while content integrity moved to the attestation, which covers strictly more (the whole
  event, including evidence and timestamps) than the old summary payload did.
- Multi-agent dogfood stores gain per-agent cryptographic attribution: `codex`,
  `claude-code`, and `cursor` events are each signed by their own source key.
