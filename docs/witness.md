# Witness Runbook

The witness is dent8's external tamper-evidence layer. The event log already has a hash
chain, but a writer that can rewrite the log could also recompute that chain. A witness
periodically signs the current chain head so a later rewrite or rollback can be detected.

The mechanism is the stock `dent8 witness` command. The operated product
shape is: keep the signing key off the writer, append signed tree heads to a witness log, and
publish the latest head somewhere the writer cannot silently roll back. That shape is
**packaged** in [`examples/witness-operated/`](../examples/witness-operated/) — a Docker
Compose split (signer / publisher / monitor as separate services over a shared Postgres
store, built from the repo [`Dockerfile`](../Dockerfile)) plus hardened systemd units for
bare-metal signer/monitor hosts; the monitor alerts by exiting non-zero on a
`tamper`/`rollback` verdict. The packaged publisher/monitor cover grant-log heads too when
signed identity is in use, retaining revocation evidence off-host with the event heads. In
the compose split, the private signing-key volume is mounted only into the signer; the
publisher receives the witness logs and public key read-only, then writes to the external
publication volume. The runnable Compose demo
([`examples/witness-operated/demo.sh`](../examples/witness-operated/demo.sh)) starts that split,
publishes a head for one Postgres-backed write, deletes `dent8_event_log`, and confirms the
monitor exits on a rollback alarm. For a long-lived local stack (writer env + host-visible
published heads + ALERT file), use `scripts/operated-witness-up.sh` /
`status` / `smoke` / `down` from the repo root.

## Local Dev Setup

Use this when you want to exercise the flow on one machine. It proves the tooling, but it is
not the strongest security posture because the writer and witness key are colocated.

```sh
cargo build -p dent8-cli

dent8 init --witness
set -a
. .dent8/env
set +a

DENT8_WITNESS_KEY=.dent8/witness.key dent8 witness keygen

dent8 assert person:alice favorite_drink tea --authority high --source source:local
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
DENT8="cargo run -q -p dent8-cli --" ./examples/witness/demo.sh
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
is valid but has unwitnessed tail events. On failure, `status` carries the machine-readable
verdict so a monitor never has to parse the prose `message`:

- `tamper` — an already-witnessed prefix no longer verifies (history rewritten, or wrong
  public key); exit 1.
- `rollback` — the event log (or the witness/published sequence itself) went backwards below
  a witnessed count; exit 1.
- `conflict` — `publish` found a published head at the same count that does not match the
  local head; exit 1.
- `cannot_verify` — the check could not be performed (for example a corrupt head); exit 2.
- `failed` — a setup/config failure (missing file, unreadable key); exit 1.

`--output json` may be placed before or after the witness subcommand
(`dent8 --output json witness verify` and `dent8 witness verify --output json` are
equivalent).

`witness serve` is a long-running loop, so its JSON mode streams **NDJSON** — one compact
JSON object per line — instead of a single document. Signed heads go to **stdout**, so a
collector tailing stdout sees exactly the signed-head record stream; lifecycle and
diagnostics go to **stderr**:

```json
{"event":"head_signed","tool":"witness serve","lane":"events","head":{"event_count":12,"head":"…","signature":"…"},"signed_total":3}
{"event":"head_signed","tool":"witness serve","lane":"grants","head":{"record_count":2,"head":"…","signature":"…"}}
```

Stderr events: `started` (with `interval_seconds`, `witness_log_path`, `max_heads`),
`warning` (a prior witnessed head no longer matches — rewrite/rollback under the witness),
`error` (a failed tick; serve keeps going), and `stopped` (with `reason:
"max_heads_reached" | "consecutive_errors"`). Exit codes are unchanged from text mode.

## Grant-Log Coverage

With signed identity in use, the witness also covers the **grant log** (ADR 0014): `sign` and
`serve` append a signed `(record_count, head)` for the grant log into
`DENT8_WITNESS_GRANTS_LOG` whenever one is discoverable, and `witness verify` re-checks every
signed head against the current grant log. Grant history is issuer-signed and hash-chained,
but a truncated *tail* (hiding a fresh revocation) is a valid-looking prefix — only the
witnessed head betrays it, surfacing as `ROLLBACK`.

The grants-witness file itself is still local state, so publish it too:

```sh
dent8 witness publish /external/heads.jsonl --grants /external/grant-heads.jsonl
dent8 witness verify-published /external/heads.jsonl --grants /external/grant-heads.jsonl
```

`--grants` idempotently appends the latest signed grant-log head to its own external
sequence with the event lane's exact semantics: republishing the same count is a no-op, a
published sequence ahead of the local one is `ROLLBACK`, a mismatched head at the same count
is `CONFLICT`. `verify-published --grants` re-checks every published grant-log head against
the *current* grant log — a writer who scrubs a revocation and deletes the local
grants-witness file is still caught by the published copy. When a grants-witness log exists
locally and `publish` runs without `--grants`, it says so (a text note and an
`unpublished_grants_witness_log` JSON field) rather than silently half-covering. In JSON
output both commands gain a `grants` object with the published/current record counts and
coverage.

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
- Publisher without the private key: keeps the operational publication loop from becoming a
  second signer; compromising it can withhold or attempt to roll back published heads, but it
  cannot forge a new signed head.

The packaged deployment (compose + systemd) lives in
[`examples/witness-operated/`](../examples/witness-operated/), including key-rotation and
publication-channel guidance. Remaining product work: *managed/hosted* operation — running
the signer and publication channel as a service rather than on your own second host.
