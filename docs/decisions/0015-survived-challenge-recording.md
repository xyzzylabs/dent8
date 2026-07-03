# ADR 0015 - Survived-challenge recording and the earned-supersession gate

Date: 2026-07-03

## Status

Accepted.

## Context

The firewall rejects challenges — a supersession below the incumbent's authority
(`InsufficientAuthority`), a supersession whose *backing claim* is actually weaker than its
stated authority (`LaunderedAuthority`), a retraction/expiration below the incumbent, a
contradiction against a canonical claim (`CanonicalContradiction`). Today a rejected
challenge **leaves no trace**: the candidate event is refused before persistence and only
the caller's error output knows it happened. Two things are lost:

- **The strongest entrenchment signal.** A fact that was *attacked and stood* is better
  evidence than a fact nobody ever tested. `ClaimState.corroborating_sources` deliberately
  measures same-value corroboration only; its own doc comment names the gap: *"surviving a
  contradiction or a rejected supersession is deliberately not counted here (that would
  require recording rejected attempts)"*. This is the open half of earned entrenchment
  ([research/novelty.md](../research/novelty.md) rank 3).
- **The attack audit.** MINJA-style injection probes are invisible: an operator cannot see
  that `source:web-scrape` tried five times to overwrite a canonical fact, because failed
  attempts vanish.

Separately, [`EntityProjection::unearned_supersessions`] audits *admitted* supersessions
after the fact — flagging `AuthorityDowngrade` and `WeakerCorroboration` — but nothing
enforces the corroboration half at write time: an equal-authority, single-source claim can
displace an incumbent backed by many sources.

## Decision

### 1. Record survived challenges as events (default on)

A new event kind on the **incumbent's** stream, written by the op boundary (CLI/MCP shared
`op_*` path) when arbitration rejects a challenge:

```rust
ClaimEventKind::ChallengeRejected {
    challenge: ChallengeKind,        // Supersession | Contradiction | Retraction | Expiration
    by: Option<ClaimId>,             // the challenging claim, when the challenge named one
    rejection: ChallengeRejection,   // InsufficientAuthority | LaunderedAuthority
                                     //   | CanonicalContradiction | WeakerCorroboration
}
```

- The event carries the **challenger's provenance** — the attack attempt is attributed, and
  under signed identity (ADR 0013) the record is *attested by the challenger's own key*: the
  challenger authenticated to make the write, so the record of its failure is signed by it.
- The event's `authority` is the challenger's **effective** authority — the stated level,
  except for a laundered supersession where it is the backing claim's *actual* (lower)
  level. "Survived a High challenge" must mean the challenge was actually High.
- The fold treats it as non-terminal bookkeeping on a live incumbent: it accumulates
  `ClaimState.survived_challenges: BTreeMap<SourceId, AuthorityLevel>` (challenger source →
  highest effective authority that challenged and lost), mirroring `corroborating_sources`.
  `survived_challenges_at_or_above(min)` is the Sybil-resistant read: minting low-authority
  challengers cannot simulate surviving strong attacks.
- Recorded only for challenges that were **real contests lost on strength**: the four
  rejections above, against a live (non-terminal) incumbent. Malformed writes, duplicate
  assertions, terminal-state mutations, and supersessions naming a nonexistent claim
  (`UnbackedSupersession`) are noise or lineage errors, not survived challenges.
- `DENT8_RECORD_CHALLENGES=0` opts out. Recording is **on by default**: silent rejection is
  the same silent-half-coverage failure mode the witness lane exists to end. The rejected
  caller still gets its error unchanged (same exit code); the text/JSON gains a note that
  the incumbent recorded the challenge.

### 2. The earned-supersession gate (opt-in)

`DENT8_ENTRENCHMENT_GATE=1` turns the `WeakerCorroboration` *audit* into a *write-time
gate* at the op boundary: an equal-authority supersession whose backing claim has strictly
weaker authority-weighted corroboration than the incumbent (both measured by
`corroboration_at_or_above` at the shared level) is rejected — and recorded as a survived
challenge like any other. The `AuthorityDowngrade` half needs no gate: the entity-aware
anti-laundering check already blocks it at write time.

Off by default because it changes admission semantics: a genuinely newer fact usually
arrives from *one* source first, and rejecting it until it gathers corroboration trades
plasticity for entrenchment. That is a policy choice an operator must make, not a default.
The projection audit remains the always-on detector either way.

### Compatibility

- **Hashes are untouched.** Existing events' canonical bytes and hashes are unchanged; no
  `CANON_VERSION` bump (same additive rule as ADR 0013). Golden fixtures stay frozen.
- **Forward-compatibility note.** A log *containing* `ChallengeRejected` events cannot be
  read by pre-0.2 binaries (unknown enum variant). This is a capability addition, not a
  format break: old logs verify identically under both.
- `ClaimState.survived_challenges` is `#[serde(default)]`, so previously materialized
  projections deserialize (and are rebuilt from the log as always).

### Trust model and residuals

- The op boundary emits the record; a writer with **raw store access** could append forged
  `ChallengeRejected` events to inflate an incumbent's survival record. Two mitigations
  already in place: `survived_challenges_at_or_above` only counts challenges at an
  authority the forger would have to *hold*, and under signed identity the record's
  attestation must verify against the challenger's key with entitlement at write time
  (ADR 0014). Same boundary trust model as identity enforcement (ADR 0012).
- Survived challenges are consulted by arbitration as of
  [ADR 0017](0017-survived-challenges-in-arbitration.md): the opt-in earned-supersession
  gate (and the entity-level audit) weigh **earned entrenchment** = corroboration + survived
  challenges, so a claim that survived an equal-authority challenge resists the next fresh
  equal-authority replacement. This ADR deliberately delivered recording first — the history
  had to exist and accumulate honestly before a gate consumed it.

## Consequences

- Every rejected challenge becomes replayable evidence: `explain` can say "survived 2
  challenge(s), 1 at ≥High", and an injection probe campaign is visible in the log with the
  attacker's own attestation on it.
- The log grows one bookkeeping event per rejected challenge (bounded by the writer's
  ability to attempt writes at all).
- `dent8-store`'s public API is unchanged (the gate lives at the op boundary); the audit
  keeps working on logs written before this ADR.
