# ADR 0011 - Authority-gated explicit expiration

Status: Accepted

## Context

dent8 has two different freshness concepts:

- **TTL staleness** is a read-time predicate. A fact can remain `Active` while reads mark it
  stale via `ClaimState::is_expired_at`.
- **`claim.expired`** is a durable event. It moves a claim into the terminal `Expired`
  lifecycle and removes it from the believed set, while preserving audit history.

The old v0 semantics treated `claim.expired` as a lifecycle-natural policy close and did not
gate it against the incumbent claim's authority. That created a bypass: a low-authority actor
could not retract or supersede a high-authority fact, but could still terminally close it by
calling `expire`.

## Decision

Explicit expiration is authority-gated like retraction:

- If `event.authority.level < incumbent.authority.level`, `claim.expired` is rejected with
  `InsufficientAuthority`.
- Equal or higher authority may expire the claim.
- TTL staleness remains read-time and non-mutating; it does not require actor authority.
- CLI and MCP `expire` continue to use the same write path as other lifecycle commands, so the
  source->authority ceiling still caps the stated authority before the core fold arbitrates.

## Consequences

- A low-trust source can no longer silently remove a trusted project fact via expiration.
- Operators that perform policy-retention expiration need a source grant high enough to close
  the affected facts.
- Taint analysis remains unchanged: a still-believed derivative is tainted if it depends on a
  source claim that is now `Retracted` or `Expired`.
- Product language must distinguish read-time TTL staleness from explicit terminal expiration.
