# ADR 0014 - Grant history and revocation

Date: 2026-07-03

## Status

Accepted.

## Context

ADR 0013 made every write carry a persisted attestation: proof that *this key signed this
content*. Its documented non-goal is **entitlement at write time**: whether that key was
granted the claimed source/authority *when the event was written*. Today that cannot be
answered retroactively:

- `active-grants.json` holds only the **current** grant per source. Rotation overwrites the
  past: after a rotate, events legitimately signed under the old key can no longer be
  distinguished from events signed by a key that was never granted.
- **Revocation does not exist.** If a source key is compromised, the operator can rotate —
  but nothing records *when* trust in the old key ended, so old-key events after the
  compromise look exactly like old-key events before it.
- The gap grows with the log: every attested event written today is an entitlement question
  someone may need answered later.

The signals needed at verification time, for an attested event `E` with key `K`, source `S`,
at `T = E.provenance.recorded_at`: was there a grant binding `S -> K` that was **issued at or
before `T`**, **not revoked before `T`**, and **not expired at `T`**?

## Options considered

**A. A separate, signed, hash-chained grant log** — an append-only JSONL beside
`trust.json` / `active-grants.json` in the identity bundle.

**B. Grants as claim events in the main event log** — a reserved `identity:` subject kind,
reusing the chain, witness, attestation, and replay machinery.

B is philosophically attractive (the identity plane becomes replayable beliefs) but breaks a
load-bearing property from ADR 0012: **identity material is host-local config, independent of
the event backend**. One identity bundle legitimately serves many stores (the file dev log, a
`sqlite://` project store, a shared Postgres); folding grant history into *one* store would
make entitlement verification unavailable — or worse, inconsistent — everywhere else.
Decision: **Option A.**

## Decision

Add an append-only **grant log** to the identity bundle (default
`<bundle>/grant-log.jsonl`, override `DENT8_GRANT_LOG`), maintained automatically by the
grant lifecycle and consulted by `verify`.

### Record shape

One JSON line per lifecycle action:

```json
{
  "action": "issued" | "revoked",
  "grant_signature": "<hex of the SignedSourceGrant's issuer signature>",
  "source": "source:codex",
  "public_key": "<hex source verifying key>",
  "max_authority": "High",
  "scope": "*",
  "expires_at_ms": null,
  "at_ms": 1782970000000,
  "issuer": "owner",
  "record_signature": "<hex Ed25519 over the framed record>",
  "previous_record_hash": "<hex | null>"
}
```

- `record_signature` is the **issuer's** signature over the domain-framed record
  (`dent8.grant-record.v1\0`, length-framed like every other dent8 signing domain) with
  `record_signature` and `previous_record_hash` stripped. A record cannot be forged without
  the issuer key — the same trust root that signs grants.
- `previous_record_hash` hash-chains the log (SHA-256 over the canonical record bytes), so
  deletion or reordering inside the file is tamper-evident; `issued`/`revoked` for the same
  grant are ordered by construction.
- Rotation is not a distinct action: `rotate-source` appends `revoked` (old grant) +
  `issued` (new grant). `bootstrap`, `init --identity`, `agent add`, and `grant-issue`
  append `issued`.
- A new `dent8 identity revoke --source <s>` (and `--grant <path>`) appends `revoked`
  **without** issuing a replacement — the missing compromise response.

`active-grants.json` stays: it is the O(1) *current* view the write path checks; the grant
log is the historical view verification replays. `identity status`/`doctor` gain a
consistency check between the two.

### Verification

`dent8 verify` (identity builds, when a grant log is present) upgrades the attestation check:
for each attested event, resolve `(source, public_key)` against the grant log at
`recorded_at`:

- **entitled** — an `issued` record at or before `T`, no `revoked` before `T`, not expired
  at `T`, and the event's authority within the grant's ceiling and scope;
- **unentitled** — a record set that positively excludes it (an issuance explicitly revoked
  before `T`, or an active grant that is expired, over-ceiling, or out of scope) — an
  **integrity failure**;
- **unknown** — no history for that key (pre-history events, or a foreign bundle) —
  reported honestly, not failed.

The verify summary and JSON gain the three counts.

### Trust model and residuals

- Record authenticity rests on the issuer key (as grants already do). A compromised
  *issuer* key defeats grant history exactly as it defeats grants — unchanged from ADR 0012.
- `at_ms` is asserted by the machine appending the record; the hash chain orders records
  relative to each other, but absolute-time confidence is only as good as the recording
  host. The chain head can later be covered by the witness (see below).
- **Truncation** of the tail (hiding a recent revocation) is not detectable from the file
  alone — the same residual the event log has, with the same remedy: witness coverage of
  the grant-log head. That is deliberately **out of scope here** (SignedTreeHead's format is
  frozen; extending witness coverage is its own decision) and listed as the follow-up.
- Existing stores have attested events but no history. `dent8 identity backfill-grant-log`
  seeds `issued` records from the *current* grant/active-grants with `at_ms = now` — making
  the limitation explicit (entitlement before the backfill stays **unknown**; we do not
  invent history).

## Consequences

- Rotation stops destroying evidence; compromise gains a first-class response (`revoke`);
  every attested event's entitlement becomes decidable going forward.
- The identity bundle grows one file, and the bundle remains store-independent — one
  history serves every backend the host writes to.
- Grant-lifecycle paths (`bootstrap`, `rotate-source`, `grant-issue`, `agent add`) each
  gain an append; failure to append must fail the operation (no silent history gaps).
- `verify` output grows; MCP/doctor inherit it through the shared paths as usual.
