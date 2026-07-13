# ADR 0019 - HTTP API as MCP-over-HTTP

Date: 2026-07-13

## Status

**Accepted.** The dent8 HTTP API is the **MCP JSON-RPC surface carried over HTTP** — the
third transport, after stdio ([ADR 0018 context](0018-local-daemon-and-per-connection-identity.md))
and the local Unix-socket daemon, over the *same* `dispatch` firewall path. This ADR is the
"future networked MCP-over-HTTP decision" ADR 0018 deferred. The first increment is
**local-first** (loopback + bearer token); remote multi-tenant identity is a named, deferred
follow-up (below), not this decision.

## Context

`interfaces.md` sketched a bespoke REST surface (`POST /facts/assert`,
`GET /facts/{id}/explain`, …). Building that would **re-map every belief operation to a route
and re-derive every receipt JSON** — a second copy of the machine contract, free to drift from
the CLI/MCP one.

But dent8 already has a complete, tested, machine-contract surface: the MCP server
(`dent8 mcp serve`). `mcp::dispatch` maps the whole belief surface — `assert` / `supersede` /
`retract` / `contradict` / `reinforce` / `expire` / `derive` / `explain` / `replay` /
`list_facts` / `conflicts` / `snapshot` / `whatif` / `verify` / `native_*` — to JSON-RPC
results carrying `status`, structured error `code`s, and `structuredContent`, all through the
unbypassable `op_*` → `arbitrate` → `EventStore::append` path. It runs over stdio and over the
Unix-socket daemon today.

An HTTP transport that carries that same JSON-RPC therefore *is* the HTTP API, for free — and
it is the **standard MCP streamable-HTTP shape**, so real MCP clients (not just dent8's own)
can reach a dent8 server over the network. The roadmap's "HTTP API" and "richer transports
(HTTP/streamable)" converge here.

## Decision

Add HTTP as a third mode of `dent8 mcp serve`:

```
dent8 mcp serve                 # stdio (default)
dent8 mcp serve --daemon        # local Unix socket, per-connection identity (ADR 0018)
dent8 mcp serve --http [--port] # MCP JSON-RPC over HTTP  ← this ADR
```

- **One firewall path.** The HTTP handler reads a JSON-RPC request (or batch) from the POST
  body and calls the **same `dispatch`** stdio and the daemon call. No new op mapping, no
  second receipt format. A write is arbitrated identically; a read carries the same receipt.
- **Endpoint.** `POST /` (and `/mcp`) with `Content-Type: application/json`, body = one
  JSON-RPC message or a batch; response = the JSON-RPC result. `GET /healthz` is an
  unauthenticated liveness probe. That is the whole surface — the "routes" are MCP methods.
- **Trust boundary (local-first increment).** Bind **loopback only** (127.0.0.1 / [::1]),
  validate the `Host` header against localhost forms (anti-DNS-rebinding, as `dent8 ui`
  does), and require a **bearer token** on every non-health request. The token is taken from
  `DENT8_HTTP_TOKEN` or generated per run and printed to stderr — a local process must know it
  to write, closing the "any local TCP client can POST" hole that plain loopback leaves (the
  Unix-socket daemon closes it with `SO_PEERCRED`; TCP cannot, so the token stands in).
- **Write identity.** Writes are attested with the **server's own configured identity**
  (`WriteIdentity::Env`, i.e. `DENT8_GRANT` / `DENT8_IDENTITY_KEY`) — exactly like
  `dent8 mcp serve` over stdio. With no identity configured the server is effectively
  read-only (the write gate in `handle` refuses writes), same as stdio. The bearer token
  authorizes *reaching* the server; the server's identity is *what it writes as*.

## Consequences

- The HTTP API cannot drift from the CLI/MCP contract — it is the same `dispatch`.
- Any HTTP/MCP client can drive the full belief surface; `curl` works
  (`POST / -H 'authorization: bearer <t>' -d '{"jsonrpc":"2.0",...}'`).
- It is **not** a bespoke REST facade. A thin REST veneer (`POST /v1/assert` → the
  corresponding JSON-RPC) can be layered later if demand appears; it would call the same
  `dispatch`, so it too cannot drift.
- `resources/subscribe` push (SSE/streamable) over HTTP is a follow-up; the first increment is
  request/response only (subscriptions pass `None`).

## Deferred — remote multi-tenant identity (the real ADR-0019-next)

The local increment writes as *one* identity (the server's). A **remote, multi-user** service
where each client proves *its own* source key cannot hand the service those private keys. The
options — a session-challenge handshake over HTTP (the daemon's nonce/sign flow, ported), or
short-lived client-signed write attestations, or per-source bearer tokens bound to grants —
are a distinct decision, blocked until a multi-user deployment actually exists. Until then the
HTTP API is explicitly a **loopback/trusted-network** transport, documented as such.

## Non-goals

- No new firewall or write path — HTTP is a transport over `dispatch`.
- No remote multi-tenant auth in this increment (deferred, above).
- No TLS termination in-process — front with a reverse proxy for non-loopback exposure.
