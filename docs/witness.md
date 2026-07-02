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
dent8 witness publish /tmp/dent8-published-heads.jsonl
dent8 witness verify-published /tmp/dent8-published-heads.jsonl
```

`dent8 init --witness` writes verification config only:

- `DENT8_WITNESS_LOG=.dent8/witness.jsonl`
- `DENT8_WITNESS_PUBKEY=.dent8/witness.key.pub`

It deliberately does not write `DENT8_WITNESS_KEY` into `.dent8/env`; the writer should not
inherit the signing key in an operated setup.

## Separate Witness Setup

Use this shape when the event writer and witness are different processes or hosts.

For a runnable local version of this split, use the checked example:

```sh
DENT8="cargo run -q -p dent8-cli --features witness --" ./examples/witness/demo.sh
```

It creates separate writer, signer, and monitor environments in a temporary directory,
publishes a signed head outside the local witness log, and confirms that a rolled-back event
log is rejected by `verify-published`.

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

## Published Heads

The local witness log is useful evidence, but it is still local state. To keep that evidence
available after deletion or rollback of the local witness log, publish signed heads somewhere
the writer cannot rewrite: a CI artifact, Git history, object storage with retention, or a
second host.

After `dent8 witness sign` or while `dent8 witness serve` is running:

```sh
dent8 witness publish /external/dent8-published-heads.jsonl
```

`publish` appends the latest local signed head idempotently: if the same count is already in
the published file it exits successfully without adding a duplicate, and if the published file
is ahead of the local witness log it fails rather than rewriting history. `dent8 witness head`
still prints the latest head as one JSON line for custom publication channels.

From a verifier/monitor process that has the current event log and the witness public key:

```sh
export DENT8_LOG=/shared/dent8/memory.jsonl
export DENT8_WITNESS_PUBKEY=/shared/dent8/witness.key.pub

dent8 witness verify-published /external/dent8-published-heads.jsonl
```

`verify-published` does not read `DENT8_WITNESS_LOG`; it checks the externally saved heads
against the current event log prefix and public key. It fails if the published file is empty,
if the current log is shorter than a published count (`ROLLBACK`), or if a published prefix was
rewritten (`TAMPER`). It exits successfully but warns if the published sequence is valid while
the current log has unwitnessed tail events beyond the latest published count.

All finite witness commands support `--output json` for CI and monitors:

```sh
dent8 --output json witness publish /external/dent8-published-heads.jsonl
dent8 --output json witness verify-published /external/dent8-published-heads.jsonl
dent8 --output json witness doctor writer
```

The JSON includes stable `status`, `tool`, count/path fields, `coverage`
(`complete` / `trailing` / `none` where relevant), and `level: "warn"` when a verification
is valid but has unwitnessed tail events. `witness serve` is intentionally not JSON mode: it is
a long-running signer loop that streams human-readable progress.

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

With `--output json`, `dent8 witness doctor` groups checks into stable `ok`, `warn`, and `fail`
sections so automation can fail on `summary.fail > 0` without scraping text.

## Security Boundaries

The witness gives tamper evidence, not consensus or blockchain semantics. It has no mining,
tokens, validators, or global network.

The guarantee is only as strong as the witness deployment:

- Same-machine dev witness: catches accidental rewrites and demonstrates the path.
- Separate witness with off-writer signing key: catches a writer that rewrites and recomputes
  the local hash chain.
- Published heads plus `verify-published`: make deletion or rollback of the witness log
  insufficient to erase retained evidence, assuming the published-heads file lives outside the
  writer's control.

Remaining product work: key rotation, managed head publication/monitoring, and a hosted or
team-operated witness service.
