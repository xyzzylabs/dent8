# Production integrity track

How to move dent8 from “firewall correct in the lab” to **integrity-ready in production** —
without confusing that with hosted SaaS productization.

The integrity thesis needs three things to hold under real multi-agent use:

1. **Arbitration admits legitimate work and blocks the attack classes it models**  
   (designed corpora + reviewed session traces).
2. **Writes are attributed and authority-bounded**  
   (signed identity + source ceilings; team playbook in [team-identity.md](team-identity.md)).
3. **Tamper resistance against a writer who can rewrite the store**  
   (operated witness: key off-writer, published heads, monitor) — [witness.md](witness.md),
   [`examples/witness-operated/`](../examples/witness-operated/).

Core enforcement (1–2 in-process) is **built**. The open integrity work is *evidence*,
*operation*, and *coverage*, not a new fold.

## One-command gate

```sh
# corpora + every shipped reviewed trace under evals/traces/
scripts/integrity-check.sh

# also verify the local dogfood store + witness (no lag)
scripts/integrity-check.sh --local-store

# hermetic multi-agent doctor --write-check (codex/claude/cursor/grok) + role-split witness
scripts/integrity-check.sh --multi-agent
# or directly:
scripts/integrity-multi-agent.sh

# local monorepo dogfood: sign (key only for this call), publish, verify-published
scripts/dogfood-witness-ops.sh

# Docker operated-witness rollback demo (signer/publisher/monitor)
scripts/integrity-check.sh --operated-witness
```

`scripts/integrity-check.sh` exits non-zero on designed or reviewed false positives, a failed
`verify`, or a lagging/failed local witness when `--local-store` is used. CI runs the default
gate plus `scripts/integrity-multi-agent.sh` on every PR; the full Docker operated-witness
demo runs on pushes to `main`.

## Checklist (definition of integrity-ready)

| # | Check | How |
|---|--------|-----|
| I1 | Designed attack corpus still blocks | `dent8 eval` (also in integrity-check) |
| I2 | Designed legitimate corpus 0 FP | `dent8 eval` / frozen test |
| I3 | Shipped reviewed traces 0 FP | `evals/traces/*.redacted.json` via integrity-check |
| I4 | External / early-user legitimate traffic | capture → prepare → human finalize → `--trace` (below) |
| I5 | Signed identity for every production writer | `dent8 identity` / `init --identity`; [team-identity.md](team-identity.md) |
| I6 | Doctor write-check green per agent | `dent8 doctor --agent all --write-check` |
| I7 | Local witness covers the log (dev) | `DENT8_WITNESS_KEY=… dent8 witness sign` then `witness verify` |
| I8 | **Operated** witness (production) | signer ≠ writer; publish + monitor; [examples/witness-operated/](../examples/witness-operated/) |
| I9 | No silent native-memory bypass | `native_scan` / hooks; receipt-bearing export only |

**Production integrity** for a team monorepo means I1–I3 + I5–I9. **I4** is required before
claiming “does not tax legitimate revision” on *external* traffic — maintainer dogfood is
integration evidence only.

## Legitimate-traffic capture (I4)

Use a **bounded, intentionally benign** session only:

```sh
# records every completed store decision for one process tree
scripts/capture-legitimate-session.sh \
  --agent codex \
  --session session:pseudonymous-001 \
  -- dent8 assert repo:sample database postgres --authority high --source source:human

# or interactive:
scripts/capture-legitimate-session.sh --agent grok-build --session session:… --shell
```

Then:

```sh
dent8 eval prepare .dent8/evals/<capture>.jsonl --out .dent8/evals/<capture>.review.json
# classify each op legitimate|exclude; set reviewer + basis; redact; privacy.content=redacted
dent8 eval finalize .dent8/evals/<capture>.review.json --out evals/traces/<name>.redacted.json
dent8 eval --trace evals/traces/<name>.redacted.json
scripts/integrity-check.sh
```

Full schema and privacy rules: [evals.md](evals.md), [evals/traces/README.md](../evals/traces/README.md).

### What counts as evidence

| Artifact | Counts as |
|----------|-----------|
| Designed benign corpus (22 writes) | Lab false-positive rate |
| Maintainer dogfood redacted traces (CLI / Claude / Cursor / Grok) | Integration evidence |
| Independent early-user redacted traces | Product / launch evidence |
| Synthetic example under `evals/traces/` | Format fixture only |

## Operated witness (I8)

Local `dent8 witness sign` on the writer machine is **dev hygiene**, not resistance.
Production:

```sh
# packaged split (signer / publisher / monitor over Postgres)
./examples/witness-operated/demo.sh
# or compose up signer + publisher + monitor, point writers at the shared store
```

Writers get `DENT8_WITNESS_LOG` + `DENT8_WITNESS_PUBKEY` only — never `DENT8_WITNESS_KEY`.
Monitors alert on `TAMPER` / `ROLLBACK` and on a growing unwitnessed tail.

## Recommended sequence

1. Keep `scripts/integrity-check.sh` + `scripts/integrity-multi-agent.sh` green in CI.  
2. On this monorepo after agent sessions:  
   `scripts/dogfood-doctor.sh --write-check --witness-ops`  
3. Deploy the operated-witness compose (or systemd units) against the team Postgres store.  
4. Capture ≥1 **independent** early-user legitimate session per agent profile you claim to
   support (`scripts/capture-legitimate-session.sh`). Maintainer multi-agent traces are
   integration evidence only.  
5. Only then claim integrity-ready production for that deployment shape.

Control-plane (Tauri) and launch marketing are **product** tracks — they help adoption but
do not substitute for I4 and I8.
