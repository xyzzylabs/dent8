# Team identity: distributing keys, grants, and trust

How a team shares one firewalled belief base without ever moving a private key. Every
mechanism here already exists (`dent8 identity …`, [ADR 0013](decisions/0013-signed-write-attestation.md),
[ADR 0014](decisions/0014-grant-history-and-revocation.md)); this page is the operational
pattern.

## The split: what is public, what is secret

Everything the verifier needs is public by construction — signatures and public keys.
Committing them to the repo is the point: every clone can verify every write offline.

| Artifact | Path (bundle default) | Commit? |
|---|---|---|
| Trust registry (issuer public keys) | `.dent8/trust.json` | **yes** |
| Signed grants | `.dent8/grants/*.grant.json` | **yes** |
| Active-grant index | `.dent8/active-grants.json` | **yes** |
| Grant log (issuance/revocation history) | `.dent8/grant-log.jsonl` | **yes** |
| Source private keys | `.dent8/identities/*.key` — or better, no file at all | **never** |
| Generated env files | `.dent8/identity-*.env` (machine-local paths) | no |

The stock `.gitignore` ignores `.dent8/` wholesale, which is right for a solo dev log. A
team splits it:

```gitignore
.dent8/identities/
.dent8/identity-*.env
# trust.json, grants/, active-grants.json, grant-log.jsonl stay committed
```

Prefer keeping private keys out of the filesystem entirely: `keychain:<account>` is
accepted wherever a key path is, backed by the macOS Keychain, any Linux Secret Service
(GNOME Keyring/KWallet via `secret-tool`), or the Windows Credential Manager. A
keychain-backed key is encrypted at rest, locks with the session, and cannot be swept into
a dotfile backup — see the residuals in [threat-model.md](threat-model.md).

## First operator: bootstrap the bundle

```sh
dent8 identity bootstrap --source source:owner
```

This creates the bundle under `.dent8/` and — deliberately — puts the **issuer key outside
the repo** (`~/.config/dent8/issuer.key` by default): cloning the repo must never hand out
the power to mint grants. Commit the public artifacts, keep the issuer key on the
operator's machine (or in their keychain: generate with
`dent8 identity issuer-keygen --out keychain:issuer` and pass
`--issuer-key keychain:issuer` when issuing).

## Onboarding a teammate (remote — the key never travels)

1. **Teammate**, on their own machine — generate straight into their OS keychain:

   ```sh
   dent8 identity agent-keygen source:alice --out keychain:alice
   ```

   This prints the **public** key. Send it to the issuer any convenient way — a PR
   comment is fine; it is public material.

2. **Issuer** — issue and commit the grant (the public key can come from a pasted hex
   file):

   ```sh
   echo '<alice public key hex>' > /tmp/alice.pub
   DENT8_GRANT_LOG=.dent8/grant-log.jsonl \
   dent8 identity grant-issue source:alice \
     --public-key /tmp/alice.pub --max medium --scope 'repo:myproj' \
     --issuer owner --issuer-key keychain:issuer \
     --out .dent8/grants/source_alice.grant.json
   dent8 identity repair-env --source source:alice   # registers the active grant
   git add .dent8/grants .dent8/grant-log.jsonl .dent8/active-grants.json && git commit
   ```

   `repair-env` restores the active-grant registry entry from the signed grant; for a key
   that is not a bundle file (Alice's never left her machine) it skips the env rewrite and
   says so.

   Scope and ceiling are policy: the stock **human > CI > agent** profile
   (`dent8 authority defaults`) pairs naturally with `--max high` for humans, `medium`
   for CI, and narrower subject scopes for single-purpose agents.

3. **Teammate** — pull, point the env at the committed artifacts and the keychain key:

   ```sh
   export DENT8_TRUST=.dent8/trust.json
   export DENT8_GRANT=.dent8/grants/source_alice.grant.json
   export DENT8_ACTIVE_GRANTS=.dent8/active-grants.json
   export DENT8_GRANT_LOG=.dent8/grant-log.jsonl
   export DENT8_IDENTITY_KEY=keychain:alice
   dent8 doctor --source source:alice --write-check
   ```

   `doctor --write-check` proves the whole chain end to end: grant verifies against the
   committed trust registry, the keychain key signs, the firewall admits.

For several agent profiles on **one** machine (Claude Code + Codex + a CI runner sharing
a bundle), `dent8 agent add` does keygen + grant + env in one step — the remote flow above
is for keys that must be born on someone else's machine.

## Rotation and revocation

- **Rotate** (new key, replacement grant, history preserved):
  `dent8 identity rotate-source --source source:alice` — then commit the changed grant
  artifacts. The old key stops verifying; the grant log records the succession.
- **Revoke without replacement** ([ADR 0014](decisions/0014-grant-history-and-revocation.md)):
  `dent8 identity revoke --source source:alice` — commit. Every clone's verification
  refuses the source from the revocation record onward;
  `dent8 identity backfill-grant-log` seeds history for grants that predate the log.

Because revocation is a *committed artifact*, "locking a teammate out" is a normal PR with
review, not an out-of-band scramble.

## CI bots

CI has no user keychain. Store the bot's private key as a CI secret, materialize it to a
`0600` file at job start, and point `DENT8_IDENTITY_KEY` at it; its grant (committed, like
any other) should carry a narrow scope and a `--max medium` ceiling so a compromised
pipeline cannot displace human-asserted facts — that asymmetry is the firewall's job.

## Verifying any clone

Anyone with the repo — no keys at all — can check the full story:

```sh
dent8 identity grant-verify .dent8/grants/source_alice.grant.json
dent8 verify        # hash chain over the log
dent8 witness verify-published   # if the team publishes signed tree heads off-host
```
