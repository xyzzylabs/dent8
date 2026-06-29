# dent8 belief history as DuckDB-queryable Parquet

dent8's write path is the append-only event log (file or Postgres). The **analytical lane** is
a read-only export of it: `dent8 export [out.parquet]` writes the whole log to a flattened,
columnar Parquet table that **DuckDB reads directly** — no embedded engine in the binary, and
the log stays the source of truth. Use it for forensics, audit queries, replay-at-scale, and
benchmark aggregation.

It is gated behind `--features export` so the stock `dent8` carries no arrow/parquet stack.

## The schema — one row per event

| column | meaning |
| --- | --- |
| `sequence` | position in the global event order |
| `event_id`, `claim_id` | the event and the claim it acts on |
| `kind` | `claim.asserted`, `claim.superseded`, `claim.retracted`, … |
| `subject_kind`, `subject_key`, `predicate` | the fact's subject + predicate |
| `value` | the raw value (null for lifecycle events and for redacted values) |
| `value_kind` | `text` / `json` / `redacted`, or null when the event carries no value — so redacted is never confused with absent, and Text vs JSON need not be guessed from the string |
| `authority`, `source`, `actor` | who wrote it, at what authority (`authority` is a stable name, not a debug string) |
| `recorded_at_ms` | write time (unix millis) |
| `derived_from` | a **list** of source claim ids — the `DerivedFrom` dependency edges ([ADR 0010](../../docs/decisions/0010-evidence-edges-and-retraction-taint.md)); `UNNEST` it, don't string-split (a claim id may contain any character) |
| `event_json` | the full canonical event, for anything the columns omit |

## Queries

```sh
dent8 export audit.parquet

# writes by source
duckdb -c "SELECT source, count(*) AS writes FROM 'audit.parquet' GROUP BY 1 ORDER BY 2 DESC"

# the dependency graph — what was derived from what (derived_from is a list; UNNEST it)
duckdb -c "SELECT claim_id, UNNEST(derived_from) AS source_claim FROM 'audit.parquet' WHERE derived_from IS NOT NULL"

# event timeline for one entity
duckdb -c "SELECT sequence, kind, value, authority, source FROM 'audit.parquet'
           WHERE subject_kind='repo' AND subject_key='myproj' ORDER BY sequence"

# DuckDB is the bridge to other tools — re-emit in any format it supports
duckdb -c "COPY (SELECT * FROM 'audit.parquet') TO 'audit.json' (FORMAT json)"
```

The export is backend-aware: with `DENT8_DATABASE_URL` set (and a `--features postgres,export`
build) it snapshots the Postgres log instead of the file.

## Run the worked example

[`demo.sh`](demo.sh) builds a small belief history (asserts, a derivation, and a retraction
that poisons the derivative), exports it, and runs the queries above. From a clone:

```sh
DENT8="cargo run -q -p dent8-cli --features export --" ./examples/duckdb/demo.sh
```

(The export needs only `dent8`; the queries additionally need the [`duckdb`](https://duckdb.org)
CLI — `demo.sh` prints the queries to run if it is not installed.)
