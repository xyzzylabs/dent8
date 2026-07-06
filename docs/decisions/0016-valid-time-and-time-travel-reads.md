# ADR 0016 - Valid-time intervals and time-travel reads

Date: 2026-07-03

## Status

Accepted.

## Context

dent8 already distinguishes *when a fact was recorded* (`provenance.recorded_at`, the
transaction-time axis the hash chain orders) from *when it holds* (`valid_from`, feeding the
TTL freshness anchor). But the valid-time axis is half-built, and the read surface is
now-only:

- **No `valid_to`.** A fact with a *known* end of validity ("the deploy freeze lasts until
  March 31") can only approximate it with a TTL — but TTL is a *staleness heuristic* (how
  long until the fact should be re-checked), not an asserted validity boundary. ADR 0005
  names closed valid-time intervals as the missing piece.
- **No time-travel.** "What did we believe last Tuesday?" is unanswerable even though the
  event log contains exactly that information — replay always folds the full log and
  evaluates freshness at wall-clock now.
- `valid_from` exists in the model but was never settable from the CLI, so in practice the
  freshness anchor always collapsed to `recorded_at`.

## Decision

### 1. `valid_to` — the asserted end of validity

`FactEvent.valid_to: Option<TimestampMillis>`, folded into
`FactState.valid_to` at assertion (like `ttl`). Read-time freshness bounds the full
validity window `[valid_from, expires_at)`: `FactState::expires_at()` is the *earliest* of
the TTL bound and `valid_to` (the upper bound), and `FactState::is_fresh_at(now)` also
requires `now >= valid_from` — a fact whose `valid_from` is in the future is **not yet
valid** (`is_not_yet_valid_at`), read as not-fresh with a distinct `[not yet valid]` headline
rather than `[stale]`. `explain`'s receipt carries `fresh`, `not_yet_valid`, and the
`valid_from` / `expires_at` window (the CLI, the MCP `explain` tool, and `resources/read`
mirror them). Lifecycle is untouched — an out-of-window fact is not-fresh to read, not
terminally closed; explicit `expire` remains the authority-gated close (ADR 0011).

Validation rejects `valid_to <= valid_from` when both are set. Expiry is inclusive at the
upper boundary (`expires_at <= now` is stale) and the lower bound is inclusive too
(`now >= valid_from` is valid), matching the existing TTL comparison.

`FactState` stores `valid_from` distinctly from `freshness_anchor` (which still falls back
to `observed_at`/`recorded_at` for the TTL anchor): only an asserted `valid_from` gates the
lower bound, so a future TTL anchor from `observed_at` does not accidentally read as
not-yet-valid.

### 2. The write surface completes the interval

`assert`, `supersede`, `contradict`, and `derive` gain `--valid-from <millis>` / `--valid-to
<millis>` (the shared value-write surface): `assert` stamps its fact; `supersede` and
`contradict` stamp the *replacement* / *opposing* assertion they create; `derive` stamps the
derived assertion. Setting `valid_from` also restores its intended role as the freshness anchor.

### 3. Time-travel reads

`explain` and `replay` gain two independent clocks:

- **`--as-of <millis>` (transaction time)** — fold only events with `recorded_at` at or
  before the instant: the store as it stood then. Trusts `recorded_at` exactly as
  freshness always has (it is appender-supplied); the filtered prefix skips the
  trusted-reload uniqueness gate because it re-checks a *historical* state that was
  admitted event-by-event when written.
- **`--valid-at <millis>` (valid time)** — evaluate freshness/validity at that instant
  instead of wall-clock now: "was this fact valid on March 3rd?".

They compose: `--as-of T --valid-at T` reads the log as of `T` and judges freshness at
`T` — the full "what did we believe, and was it fresh, last Tuesday".

### Compatibility

`valid_to` is `#[serde(default, skip_serializing_if = "Option::is_none")]` — the ADR 0013
optional-field rule — so events written before it keep byte-identical canonical form and
stored hashes; **no `CANON_VERSION` bump**. (Unlike `observed_at`/`valid_from`, which
predate the rule and serialize as explicit `null`s, absence is omitted.)
`FactState.valid_to` is `#[serde(default)]` for previously materialized projections.

## Consequences

- Facts with known validity windows stop abusing TTL, and their expiry is asserted
  content (hash-covered, attested) rather than registry policy.
- Auditing gains the missing tense: a poisoning investigation can ask what the agent
  believed at decision time (`--as-of` at the decision's timestamp) instead of inferring
  it from the current fold.
- MCP time-travel and validity parameters ride the same `op_*` signatures and are now
  exposed as tool arguments: `assert`/`supersede`/`contradict`/`derive` take optional
  `valid_from`/`valid_to` and `explain`/`replay` take optional `as_of`/`valid_at`, advertised
  in their input schemas — surface plumbing over the existing signatures, not a new mechanism.
