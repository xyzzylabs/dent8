# 0004: Canonicalization and Hash Chain

Date: 2026-06-26

## Status

Accepted; **implemented** in `dent8-core/src/hash.rs` (M0). One item amended from the
original plan (JCS → serde_json sorted-key form) and two recorded as decided below
(`schema_version`, `ClaimValue::Json`).

## Context

`AppendReceipt` promises an `event_hash`, and schema 001 has
`previous_event_hash`/`event_hash` columns, but `ClaimEvent` derives no
serialization and the canonicalization format was explicitly left unresolved.
Tamper-evidence is only as strong as deterministic bytes: two logically-equal events
must produce byte-identical input to the hash regardless of map order, whitespace, or
number formatting.

## Decision

1. Derive `serde::{Serialize, Deserialize}` on `ClaimEvent` and sub-types. **Done.**
2. **Amended:** canonicalize with a **sorted-key `serde_json` form** (`to_value` →
   `to_vec`), **not RFC 8785 (JCS)**. The original plan named JCS; the implementation
   does not implement JCS (key order is UTF-8 byte order, not UTF-16; number/escape
   rules differ). They coincide because all keys are ASCII field names and all numbers
   are integers. **Invariant:** no non-ASCII/dynamic object key without bumping
   `CANON_VERSION`. A real JCS crate (`serde_jcs`) is deferred until cross-implementation
   interop is actually required.
3. Hash with **SHA-256** and **RFC 6962-style domain separation** (`0x00` leaf prefix).
   **Amended for injectivity:** the leaf input is length-framed and genesis-tagged —
   `SHA-256(0x00 || CANON_VERSION || len(canonical) || canonical || tag || prev_digest)`
   — and a malformed `previous` is rejected, so no two distinct `(canonical, previous)`
   pairs share a hash input. **Done.**
4. Compute canonical bytes **from the typed Rust struct, never from Postgres JSONB**.
   **Done.**
5. `provenance.recorded_at` is **appender-supplied**; the SQL `DEFAULT now()` is dropped
   from `dent8_claim_events.recorded_at` and `dent8_claim_edges.created_at`.
   `dent8_replay_runs.started_at` stays DB-generated (operational run metadata, not
   replayable event data). **Done.**
6. **Done — `ClaimValue::Json` is canonical by construction.** The variant now holds
   [`CanonicalJson`](../../crates/dent8-core/src/model.rs), a newtype with a private field
   built only via `ClaimValue::json` / `CanonicalJson::new`, which parse the input and
   re-emit it sorted-key + compact (and reject invalid JSON). The canonicalization is
   **re-applied on `Deserialize`**, so the invariant also holds on the trusted-reload path,
   not just at the write boundary. Embedded JSON differing only in key order/whitespace now
   hashes identically, so the "logically-equal → identical bytes" invariant holds for *all*
   fields. (No `CANON_VERSION` bump: the serialized shape is unchanged — a newtype struct
   is transparent — and no persisted log contained a `Json` value.)

   Two number caveats, both consistent with the not-JCS premise above. **(a)** Floats are
   canonicalized via `serde_json`'s `float_roundtrip` feature so `to_string(from_str(x))`
   is stable; without it ~10% of `f64` values (e.g. `13e300`) drift on re-canonicalization,
   which — through the re-canonicalizing `Deserialize` — would change a written value on
   reload and **false-alarm the hash chain**. The feature is therefore mandatory, with float
   idempotency + serde-round-trip regression tests. **(b)** A JSON integer beyond `u64` or a
   high-precision decimal is parsed as `f64` and loses precision on the first canonicalization
   (idempotent thereafter, so it never trips the chain, but lossy). This is documented on
   `CanonicalJson`; callers needing exactness pass such numbers as JSON strings.
7. **Decided — `schema_version` is the out-of-band `CANON_VERSION` constant**, mixed
   into every leaf hash, rather than a per-event field. A per-event field is unnecessary
   while a single encoding version is in force; revisit if multiple encodings must
   coexist in one log.

   **How to introduce a second encoding safely (the deferral is NOT a one-way door).**
   When v2 is needed, do *not* bump the `CANON_VERSION` constant in `hash_leaf` on its
   own — that would re-hash every existing event under `2` and raise a false tamper alarm
   on the whole log. Instead, in the same change:
   1. add a per-event `schema_version: u8` field to `ClaimEvent` with
      `#[serde(default = "…v1")]` and **exclude it from `canonical_bytes`** (mix it into
      the leaf where the constant is today);
   2. mix `event.schema_version` into the leaf instead of the constant.

   Every event already in the log was written under the only encoding that ever existed
   (v1), so it deserializes to `schema_version = 1` and mixes `1` into its leaf — **byte-
   identical to today's `CANON_VERSION = 1`** — so its stored hash, the chain, and any
   witness/anchor signature over it all still verify, with **no data migration**. New
   events carry `2` and the v2 rules; verification dispatches per event. Because the
   backfill-to-v1 is free at that point, adding the field now would be premature churn (it
   touches every `ClaimEvent` construction site) for no integrity gain. The single rule to
   preserve the property: **never change the leaf-mixed version without a per-event field
   to record it.**

## Consequences

Positive:

- Tamper-evidence and cross-implementation deterministic replay become real, not
  slogans.
- Domain separation keeps a future transparency-log/Merkle upgrade non-breaking.
- The narrow `ClaimValue::Json` canonicalization (a type-enforced newtype) avoids
  over-engineering the integer fields while closing the one gap in the bytes invariant.

Negative:

- Adds `serde` + `serde_json` + `sha2` + `hex` and a canonicalization round-trip on
  every append.
- Not interoperable with an external JCS implementation (acceptable — no interop need
  yet; the invariant note guards against silently growing one).

## Follow-Up

- [DONE] `canonical_bytes`, `event_hash`/`hash_chain`, and tests
  (`canonicalize(deserialize(canonicalize(e))) == canonicalize(e)`, key-order
  independence, injective genesis/`previous`, tamper-cascade).
- [DONE] `ClaimValue::Json` is canonical by construction via the `CanonicalJson` newtype
  (item 6) — canonicalized on build *and* on deserialize, with unit + hash-equality tests.
- Wire `hash_chain` into the Postgres transactional append (populate
  `event_hash`/`previous_event_hash`, reverify on replay) — roadmap §2.
- See [storage.md](../storage.md) and [roadmap.md](../roadmap.md) §1.
