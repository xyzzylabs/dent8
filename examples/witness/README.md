# Witness Operator Split

This example shows the intended split between an event writer and the witness signer. It can
run on one machine for development, but the security value comes from keeping the private
witness key out of the writer/agent/MCP environment.

Run the end-to-end local demo from a clone:

```sh
DENT8="cargo run -q -p dent8-cli --features witness --" ./examples/witness/demo.sh
```

The demo creates three separate environments in a temporary directory:

- **writer**: `DENT8_LOG`, `DENT8_WITNESS_LOG`, `DENT8_WITNESS_PUBKEY`.
- **signer**: `DENT8_LOG`, `DENT8_WITNESS_LOG`, `DENT8_WITNESS_KEY`.
- **monitor**: `DENT8_LOG`, `DENT8_WITNESS_PUBKEY`.

It then writes one fact, signs the tree head, publishes that head to an external JSONL file,
and proves that a rolled-back event log is rejected by `verify-published`.

To wire the same shape manually, first build a witness-capable CLI:

```sh
cargo build -p dent8-cli --features witness
```

First configure verifier paths for the writer or agent process:

```sh
dent8 init --witness \
  --witness-log /shared/dent8/witness.jsonl \
  --witness-pubkey /shared/dent8/witness.key.pub
```

Then generate the key on the signer side and copy only the public key into the shared verifier
path:

```sh
export DENT8_LOG=/shared/dent8/memory.jsonl
export DENT8_WITNESS_LOG=/shared/dent8/witness.jsonl
export DENT8_WITNESS_KEY=/secure/dent8/witness.key

dent8 witness keygen
cp /secure/dent8/witness.key.pub /shared/dent8/witness.key.pub
dent8 witness doctor signer
dent8 witness serve 5
```

After the public key exists, load the verifier env in the writer/agent process:

```sh
set -a
. .dent8/env
set +a

dent8 witness doctor writer
dent8 doctor
```

Verification:

```sh
dent8 witness verify
dent8 witness publish /external/dent8-published-heads.jsonl
dent8 witness verify-published /external/dent8-published-heads.jsonl
```

Publish heads somewhere the writer cannot rewrite, then verify that external file from a
monitor/CI process with `DENT8_LOG` and `DENT8_WITNESS_PUBKEY`.
Without that external publication, a local witness log can still be rolled back by someone who
controls the same storage.
