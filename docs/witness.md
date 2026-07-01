# Witness Runbook

The witness is dent8's external tamper-evidence layer. The event log already has a hash
chain, but a writer that can rewrite the log could also recompute that chain. A witness
periodically signs the current chain head so a later rewrite or rollback can be detected.

The mechanism is built as `dent8 witness` behind `--features witness`. The operated product
shape is: keep the signing key off the writer, append signed tree heads to a witness log, and
publish the latest head somewhere the writer cannot silently roll back.

## Local Dev Setup

Use this when you want to exercise the flow on one machine. It proves the tooling, but it is
not the strongest security posture because the writer and witness key are colocated.

```sh
cargo build -p dent8-cli --features witness

dent8 init --witness
set -a
. .dent8/env
set +a

DENT8_WITNESS_KEY=.dent8/witness.key dent8 witness keygen

dent8 assert person:alice favorite_drink tea --authority high --source user:alice
DENT8_WITNESS_KEY=.dent8/witness.key dent8 witness sign

dent8 doctor
dent8 witness verify
```

`dent8 init --witness` writes verification config only:

- `DENT8_WITNESS_LOG=.dent8/witness.jsonl`
- `DENT8_WITNESS_PUBKEY=.dent8/witness.key.pub`

It deliberately does not write `DENT8_WITNESS_KEY` into `.dent8/env`; the writer should not
inherit the signing key in an operated setup.

## Separate Witness Setup

Use this shape when the event writer and witness are different processes or hosts.

On the writer:

```sh
dent8 init --witness \
  --witness-log /shared/dent8/witness.jsonl \
  --witness-pubkey /shared/dent8/witness.key.pub
```

On the witness host:

```sh
export DENT8_LOG=/shared/dent8/memory.jsonl
export DENT8_WITNESS_LOG=/shared/dent8/witness.jsonl
export DENT8_WITNESS_KEY=/secure/witness.key

dent8 witness keygen
cp /secure/witness.key.pub /shared/dent8/witness.key.pub
dent8 witness doctor signer
dent8 witness serve 5
```

After the witness host copies the public key, load the generated verifier env in the
writer/agent process and check that it does not include the private signing key:

```sh
set -a
. .dent8/env
set +a

dent8 witness doctor writer
dent8 doctor
```

The witness signs on growth. A later `dent8 witness verify` checks every signed head against
the current log prefix and reports:

- `OK` when all signed prefixes still match.
- `TAMPER` when a previously witnessed prefix was rewritten.
- `ROLLBACK` when the log or witness log moved backwards.

## Doctor Checks

`dent8 doctor` now reports witness status when witness paths are configured:

- configured log and public key paths;
- whether the signing key is present in the writer environment;
- number of signed heads verified;
- latest witnessed event count versus current event count;
- `FAIL` on tamper, rollback, corrupt witness log, or missing public key when signed heads exist.

If the latest witnessed count trails the current event count, `doctor` warns instead of
failing. That means the verified prefix is intact, but recent events have not yet been signed
by the witness cadence.

`dent8 witness doctor <writer|signer|both>` checks the operational split directly:

- `writer` requires `DENT8_WITNESS_LOG` and `DENT8_WITNESS_PUBKEY`, verifies that the public
  key decodes, and fails if `DENT8_WITNESS_KEY` is present in the writer/agent/MCP process.
- `signer` requires `DENT8_WITNESS_LOG` and `DENT8_WITNESS_KEY`, checks the private key
  decodes, checks owner-only permissions on Unix, and verifies that the public key matches.
- `both` is for local demos only; it runs both sets of checks and warns that the roles are
  colocated.

## Security Boundaries

The witness gives tamper evidence, not consensus or blockchain semantics. It has no mining,
tokens, validators, or global network.

The guarantee is only as strong as the witness deployment:

- Same-machine dev witness: catches accidental rewrites and demonstrates the path.
- Separate witness with off-writer signing key: catches a writer that rewrites and recomputes
  the local hash chain.
- Published heads: catch deletion or rollback of the witness log itself.

Remaining product work: key rotation, head publication/monitoring, and a hosted or
team-operated witness service.
