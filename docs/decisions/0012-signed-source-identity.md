# ADR 0012 - Signed source identity

Status: Accepted

## Context

`dent8 authority` already provides a source -> authority ceiling: once an authority registry
exists, a source cannot claim above its registered maximum. That is authz. It does not prove
authn: a caller can still pass `--source source:owner` unless the write boundary verifies that
the caller holds the key for that source.

A signed grant by itself is not enough. If the grant is a bearer token, anyone who can copy it
can impersonate the source. The grant must bind the source id to a source public key, and the
caller must prove possession of the matching private key on each write.

## Decision

Add an opt-in signed source identity layer at the CLI/MCP write boundary.

- An **issuer key** is the owner/admin authority. The operator generates it and configures
  dent8 to trust its public key.
- A **source key** belongs to one agent/source, for example `source:codex` or
  `source:claude-code`.
- A **signed source grant** binds:
  - source id
  - source public key
  - maximum authority
  - issuer name
  - optional subject scope (`*` or exact `<kind>:<key>`)
  - optional expiration as Unix milliseconds
- Every write first checks the existing source->authority ceiling, then, if identity trust is
  configured, verifies the signed grant and signs/verifies a per-write payload with the source
  private key before the candidate event reaches the firewall.
- Signed identity is **opt-in** like the authority registry. If no trust registry exists and
  `DENT8_REQUIRE_IDENTITY` is unset, dev mode remains permissive. If a trust registry exists
  or `DENT8_REQUIRE_IDENTITY=1`, missing/invalid grant/key material fails closed.

## Commands

The v0 CLI is behind `--features identity`:

```sh
mkdir -p .dent8/identities .dent8/grants
dent8 identity issuer-keygen --out .dent8/issuer.key
dent8 identity agent-keygen source:codex --out .dent8/identities/codex.key
export DENT8_TRUST=.dent8/trust.json
dent8 identity trust-add owner .dent8/issuer.key.pub
dent8 identity grant-issue source:codex \
  --public-key .dent8/identities/codex.key.pub \
  --max high \
  --issuer owner \
  --issuer-key .dent8/issuer.key \
  --scope repo:dent8 \
  --out .dent8/grants/codex.grant.json
dent8 identity grant-verify .dent8/grants/codex.grant.json
```

Agent runtime configuration:

```sh
DENT8_TRUST=.dent8/trust.json
DENT8_REQUIRE_IDENTITY=1
DENT8_GRANT=.dent8/grants/codex.grant.json
DENT8_IDENTITY_KEY=.dent8/identities/codex.key
```

## Security properties

This defends against:

- an unregistered or low-trust agent claiming to be a higher-authority source;
- copying a signed grant without also holding the source private key;
- raising the requested authority above the grant ceiling;
- using a grant outside its optional subject scope or after expiration;
- tampering with the write payload before the boundary check.

This does **not** defend against:

- a compromised source private key or malware running as the same OS user;
- a malicious process that can read another agent's private key file;
- direct Postgres writes or a process calling the store adapter without the CLI/MCP boundary;
- a compromised dent8 binary;
- a bad grant issued by a trusted issuer;
- history rewrites after append (that remains the witness layer).

Therefore v0 requires private signing keys to be owner-only (`0600`) on Unix. Stronger
isolation later should use separate OS users, hardware-backed keys, macOS Keychain,
1Password/secret-store integration, or an external signer.

## Consequences

- Multiple agents on one machine can be distinguished if each has a distinct source key and
  grant.
- Teams decide grant levels explicitly. dent8 does not infer trust from agent brand names.
- The local source->authority registry remains useful as a simple authz layer and a dev-mode
  bootstrap path; signed identity is the production authn layer above it.
- MCP deployments should run one dent8 server per agent identity if they need per-agent source
  separation. A shared MCP process can only prove the identity whose key it holds.
