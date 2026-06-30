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

- An **issuer key** is the owner/admin authority. The operator keeps it outside the
  project/agent workspace and configures dent8 to trust its public key.
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

Signed source identity is included in the default CLI build. The secure onboarding path is:

```sh
dent8 init --agent codex --install-mcp
set -a
. .dent8/env
. .dent8/identity.env
set +a
dent8 doctor --source source:codex --write-check
```

For a custom source id, use:

```sh
dent8 init --identity --source source:codex
```

Manual commands remain available:

```sh
dent8 identity bootstrap --source source:codex
dent8 identity grant-verify .dent8/grants/source_codex.grant.json
```

`bootstrap` creates or reuses an operator issuer key outside the project bundle
(`--issuer-key`, `DENT8_ISSUER_KEY`, `$XDG_CONFIG_HOME/dent8/issuer.key`, or
`$HOME/.config/dent8/issuer.key`), then writes the project-local trust registry, source key,
grant, and `.dent8/identity.env`. It refuses to place the issuer private key inside the
project bundle. The lower-level `issuer-keygen`, `agent-keygen`, `trust-add`, and
`grant-issue` commands remain available for manual rotation and custom layouts.

The default issuer key is scoped to the OS user, not the project: bootstrapping several
projects with the default path reuses one owner/admin key. That is acceptable for the v0 local
operator model because agents receive source keys and grants, not the issuer key. It also means
the issuer key is a cross-project root of trust; operators who want project-level blast-radius
isolation should pass a distinct `--issuer-key` outside each project workspace.

Agent runtime configuration:

```sh
DENT8_TRUST=.dent8/trust.json
DENT8_REQUIRE_IDENTITY=1
DENT8_GRANT=.dent8/grants/source_codex.grant.json
DENT8_IDENTITY_KEY=.dent8/identities/source_codex.key
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
- Multiple agents can use one globally installed `dent8` binary and one shared operational
  store, but stdio MCP clients normally launch separate server subprocesses. That is fine:
  provenance comes from each subprocess's grant/key env, and shared memory comes from the
  backend URL.
- Teams decide grant levels explicitly. dent8 does not infer trust from agent brand names.
- The local source->authority registry remains useful as a simple authz layer and a dev-mode
  bootstrap path; signed identity is the production authn layer above it.
- MCP deployments should run one dent8 stdio server process per agent identity if they need
  per-agent source separation. A shared MCP process can only prove the identity whose key it
  holds; a future HTTP/daemon transport needs per-request source authentication.
