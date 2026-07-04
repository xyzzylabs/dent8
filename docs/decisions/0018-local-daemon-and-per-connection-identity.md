# ADR 0018 - Local daemon transport and per-connection identity

Date: 2026-07-04

## Status

**Accepted.** The design is the output of a design panel (four independent proposals, judged on
architecture fit / identity soundness / ecosystem pragmatics, synthesized). The maintainer
signed off on all four decisions below: **local UDS daemon first** (Decision 1), and the
recommended answers to Decisions 2–4 (server-side attestation with a per-connection signer;
read-only end-to-end before writes; the `IdentityContext` refactor as its own no-behavior-change
PR first). Networked MCP-over-HTTP is deferred to ADR 0019.

## Context

The roadmap's next major link is a **shared dent8 service that many agents use over one
transport**, preserving the firewall, identity checks, and replay receipts (docs/interfaces.md,
docs/roadmap.md). The v0 MCP server (`dent8 mcp serve`) speaks newline-delimited JSON-RPC over
**stdio**, deliberately zero-heavy-dep (hand-rolled on `serde_json`, no async/HTTP stack), and
authenticates as **one source per process**: `enforce_write` / `attest_events`
(`crates/dent8-cli/src/identity.rs`) read process env (`DENT8_GRANT`, `DENT8_IDENTITY_KEY`,
`DENT8_TRUST`). A daemon serving many agents needs **per-request identity**: each request must
prove possession of its source key and carry its grant so the firewall authorizes, attributes,
and Ed25519-attests the write to the right source.

### The one fact that decides the design

ADR 0013's write attestation is an Ed25519 signature over the **entire final `ClaimEvent`**:
`attest_events` signs `dent8_core::attestation_message(event)` and `verify_event_attestation`
re-derives that same message from the stored event. But the server mints three fields the
client cannot predict *before* arbitration:

- `event_id = event:{seq}`, where `seq = next_seq(&store)` — a live, shared-store counter
  **re-derived on every `with_write_retry` attempt** under concurrency;
- `recorded_at = now_millis()`;
- the predicate-default TTL that `apply_policy_defaults` folds in **before** signing.

**Consequence.** Any design that has the client pre-compute `provenance.attestation` and the
daemon persist it *cannot re-verify offline* against `op_*`-produced bytes without either (a) a
**prepare→commit round-trip** that freezes `seq`/`recorded_at` before append — which fights the
advisory-lock-serialized concurrency model — or (b) a **daemon-held per-source key** — which
reopens the multi-tenant key-custody problem the scheme exists to eliminate. This is the
load-bearing identity claim of three of the four panel proposals (rmcp-OAuth, REST+envelope,
minimal-zero-dep), and it is false as written. Only a design that keeps attestation
**server-side and unchanged** — and instead makes the *signer* a per-request value — survives.
The one deployment where that is not a custody violation is a **local, per-user daemon**: it
runs as the same OS user that owns the `0600` source key, so "the server reads the key" is the
same trust boundary ADR 0012 already draws.

## Options considered

| Proposal | Transport | Identity | Verdict |
|---|---|---|---|
| **Local UDS daemon** | `tokio::net::UnixListener`, existing JSON-RPC | per-connection signer, attestation stays server-side | **recommended** — only identity story that survives; zero new deps |
| rmcp official | official `rmcp` Streamable HTTP | OAuth2 bearer → grant; client-held attestation | strong ecosystem fit, but client-precomputed attestation is unbuildable (see crux); heavy dep |
| REST + envelope | bespoke REST/HTTP | signed request envelope | envelope signs the *request*, not the *event* — cannot produce the ADR 0013 attestation |
| minimal zero-dep | hand-rolled HTTP + Streamable-MCP | client-precomputed attestation | same attestation impossibility + weakest ecosystem fit |

## Decision (recommended; pending sign-off)

**Ship a per-user LOCAL Unix-socket daemon (`dent8 mcp serve --daemon`) first; defer networked
MCP-over-HTTP to a separate ADR — but pin the identity seam now so the network version is a
transport swap, not a rewrite.**

**Transport + dependency.** `dent8 mcp serve --daemon --socket <path>` on a
`tokio::net::UnixListener` (default `$XDG_RUNTIME_DIR/dent8/dent8.sock`, `0700` dir, `0600`
socket; documented per-user fallback where `$XDG_RUNTIME_DIR` is unset, e.g. macOS), speaking
the **same** newline-delimited JSON-RPC the stdio server already dispatches. **Zero new
crates**: `tokio` is already a default dependency (via `sqlite → sqlx`) *with the `net` feature
enabled* — verified in the default dependency tree — so `UnixListener`/`peer_cred()` are free.
`axum`/`hyper`/`rmcp` are deferred to the network ADR, where the dependency is actually earned.
A per-connection task reads each line and calls the existing `dispatch`; the daemon path
no-op-refuses on non-unix targets.

**Per-connection identity.** Introduce an `IdentityContext { trust_path, active_grants_path,
grant_path, identity_key_path }` and thread it through `enforce_write_authority →
enforce_write / attest_events`. **The CLI builds it from env (byte-identical to today); the
daemon builds ONE PER CONNECTION.** Attestation stays server-side at both existing signing
sites (pre-admit in `op_assert`/`op_derive`; the append choke point) — so ADR 0013 is untouched
and every daemon-written event re-verifies offline exactly like a CLI write. Proof of
possession per connection reuses existing primitives: a `dent8/hello` names the source + grant
+ key; the daemon runs `verify_grant` + `verify_active_grant` + `verify_source_key_matches_grant`,
then issues a single-use, connection-scoped nonce and requires an Ed25519 signature under a
**new framed domain** `dent8.session-challenge.v1\0` (reusing the exact `framed()` construction).
This is the local granularity of the network ADR's future per-request envelope
(`dent8.request.v1\0` over `sha256(body)+nonce+ts+grant_signature`) — the same idea at two
scales.

**Fail-closed + replay/theft.** Nonce single-use and connection-scoped; `peer_cred().uid()`
must equal the daemon uid (refuse cross-user peers at accept); per-write re-read of
`active-grants.json` so `dent8 identity revoke` fails closed on the next write of a *live*
connection (revocation latency = one write, matching ADR 0014). Every persisted
`provenance.attestation.public_key` must equal *that connection's own* grant key — the
cross-agent-confusion guard.

**No firewall bypass (ADR 0003 holds).** Every `tools/call` still flows
`dispatch_tool → op_* → enforce_write_authority → admit → append_events`; the only change is
those functions receive the connection's `IdentityContext` instead of reading env. Concurrency
is unchanged — connections serialize through the same advisory-lock / `with_write_retry`
arbitration.

## Decisions requiring sign-off

1. **First transport = local UDS, not MCP Streamable HTTP.** The crux (per-request identity)
   is a `dispatch`/`op_*` concern independent of wire format; UDS solves it with zero new deps
   and zero custody violation, then the transport swaps. **Tradeoff:** the first slice advances
   *ecosystem interoperability zero* — dogfoodable only by dent8's own CLI shim until the
   network ADR lands. *If ecosystem reach is the priority now,* invert: do `rmcp` read-only
   first and accept a slower identity story. **Recommended: UDS first.**
2. **Attestation stays server-side; per-request identity = per-connection signer, not
   client-precomputed attestation.** Forced by the code (crux). **Tradeoff:** the daemon reads
   the same-user source key — fine locally (the ADR 0012 boundary), does **not** generalize to
   remote multi-tenant. **Recommended: yes.**
3. **Read-only first, then writes.** Ship reads (`list_facts`/`verify`/`explain`/`replay`/
   `conflicts`) end-to-end over the socket to prove the accept loop before any identity code.
   **Recommended: yes.**
4. **Land the `IdentityContext` refactor as its own PR, before any daemon code.** A pure
   refactor of a bounded env-read seam; the CLI path stays byte-identical (preserve the
   attest-before-admit ordering so the receipt hash still matches the persisted event, or
   golden fixtures / offline `verify` break). **Recommended: yes.**

## First slice (proposed PR order)

- **PR 1 — `IdentityContext` refactor (no daemon).** Zero behavior change; all identity/golden
  tests pass unchanged. This is the whole seam for both the daemon and the future network
  transport.
- **PR 2 — `--daemon --socket`, read-only.** `UnixListener` accept loop, per-connection task,
  `peer_cred` uid gate, per-line reuse of `dispatch`. Proves the transport. No new crates.
- **PR 3 — `dent8/hello` + session-challenge.** Nonce → Ed25519 over
  `dent8.session-challenge.v1\0`; build the per-connection `IdentityContext` from the verified
  grant; wire writes to use it.
- **PR 4 — fail-closed enforcement.** Reject unverified/revoked/expired/over-ceiling writes;
  per-write `active-grants.json` re-read; the per-connection attestation-key guard test.
- **PR 5 — thin client shim.** `DENT8_DAEMON_SOCKET` routes CLI writes through the socket →
  immediate multi-agent dogfood on one box.

## Consequences

- **Attribution, not isolation.** `peer_cred` proves same-uid; a same-user process that can
  read the `0600` key still impersonates. The daemon removes the one-server-per-agent
  workaround and gives per-agent provenance/authorization — **not** a security boundary. True
  isolation needs separate OS users or hardware-backed keys, explicitly out of scope.
- **The local shortcut does not generalize to remote.** Writes attest correctly here *because*
  the daemon can read the same-user key. Add a network + multiple tenants and that is a custody
  violation, and the unsolved attestation-over-server-minted-fields problem returns in full.
- **Deferred: ADR 0019 — networked MCP-over-HTTP.** Genuinely harder: remote multi-tenancy
  forbids daemon-held keys, so it needs either a **prepare/commit round-trip** (freeze
  `seq`/`recorded_at`, sign, then append) or an **ADR 0013 amendment** to attest over
  client-determinable content only — which connects to the deferred DB-assigned-ids work. 0018
  must not imply 0019 is a small step.
- **Refactor blast radius (PR 1).** `enforce_write`/`attest_events`/`enforce_write_authority`
  feed CLI, doctor, and status; pin the behavior with the existing golden fixtures.
