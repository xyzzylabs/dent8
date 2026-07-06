# Operated witness deployment

The witness *primitive* (`dent8 witness`) is tamper-**evident** on its own; it becomes
tamper-**resistant** only when operated with the right separation (threat model T6):

| Role | Sees | Must never see |
|---|---|---|
| **writer** — your agents/CLI/MCP | the store, the public key | the private witness key |
| **signer** — separate infrastructure | the store (read), the private key | — |
| **monitor** — anywhere | the store (read), **published** heads, the public key | the private key |

The signer signs a tree head whenever the log grows; heads are **published** to a channel the
writer cannot touch; the monitor re-verifies every published head against the live log. A
writer who rewrites or truncates witnessed history is caught even if it also rewrites the
*local* witness log — the published copies survive.

## Compose (the packaged split)

[`compose.yml`](compose.yml) runs the split as services, building the repo's
[`Dockerfile`](../../Dockerfile) (Postgres + SQLite + witness build):

```sh
cd examples/witness-operated
docker compose up -d --build db signer publisher monitor
docker compose --profile demo run --rm demo-writer   # one trusted write to witness
docker compose logs -f signer publisher monitor
```

- `signer` generates the keypair on first run into the `witness-keys` volume — the only
  place the private key exists — and runs `dent8 witness serve`. When signed identity is
  configured, the same signer also writes grant-log heads to `DENT8_WITNESS_GRANTS_LOG`.
- `publisher` idempotently appends the latest head plus the **public** key into the
  `published` volume (the stand-in for object storage / a git repo / another host). If a
  grants-witness log exists, it publishes the grant-log head to `grant-heads.jsonl` in the
  same external channel.
- `monitor` loops `dent8 --output json witness verify-published`; once `grant-heads.jsonl`
  exists, it adds `--grants` and verifies grant history too. On a `tamper` / `rollback`
  verdict its container **exits non-zero and stays down** — the alert hook (`docker compose
  ps` shows it; wire real alerting to container exit).
- your **writer** points `DENT8_STORE_URL` at the exposed Postgres (port 5432) with no
  witness key in its env — prove the split with `dent8 witness doctor writer` (writer host)
  and `dent8 witness doctor signer` (signer container).

Verify end to end, then tear down with `docker compose down -v`.

## systemd (bare-metal signer/monitor hosts)

[`systemd/`](systemd/) has hardened units for the same roles: the cadence signer as a
long-running service (`dent8-witness-signer.service`, key provisioned once with
`dent8 witness keygen` under the service user) and the monitor as a oneshot + timer whose
**unit failure is the alarm** (`OnFailure=`, or scrape failed units).

## Semantics the monitor relies on

`witness verify-published` exit codes and JSON `status` (see [docs/witness.md](../../docs/witness.md)):

- `ok` (exit 0) — every published head verifies; `coverage: trailing` + `level: "warn"` just
  means recent events aren't witnessed *yet*.
- `tamper` / `rollback` (exit 1) — **alarm**: witnessed history was rewritten, or the log /
  published sequence went backwards.
- `cannot_verify` (exit 2) — the check could not run (corrupt head): investigate.
- `failed` (exit 1) — setup/transient (store unreachable, missing file): retry, don't page.

## Production notes

- **Publication channel.** The compose `published` volume models the property that matters:
  *the writer cannot modify it*. In production use object storage with retention/versioning,
  a git repo the writer can't force-push, or a second host. `publish` already refuses to
  publish behind an existing external sequence.
- **Key rotation.** Generate a new keypair on the signer, distribute the new public key to
  monitors, and start a fresh published sequence for it; keep the old sequence + public key
  for verifying history witnessed under the old key. Heads are independent signatures — old
  ones stay verifiable forever with the old public key.
- **One signer per store.** Multiple signers would interleave counts in one witness log;
  run one `serve` per event store (scale monitors freely instead).
- **The store is shared, not trusted.** The signer/monitor read the same Postgres the writer
  writes — that's the point: they verify its *history* against signatures the writer cannot
  forge. Give them read-only credentials.
- **Grant history.** If the deployment also uses signed identity (ADR 0014), the signer
  covers the grant log automatically. The packaged publisher/monitor now publish and verify
  `grant-heads.jsonl` once `DENT8_WITNESS_GRANTS_LOG` exists, so revocation history is
  retained off-host too (see docs/witness.md, "Grant-Log Coverage").
