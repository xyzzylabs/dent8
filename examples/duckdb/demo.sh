#!/usr/bin/env bash
# Builds a small belief history through the firewall, exports it to Parquet, and runs a few
# DuckDB queries over it — the analytical/forensics lane. The export is read-only: the event
# log stays the source of truth; the Parquet is a derived snapshot DuckDB reads directly (no
# embedded engine in the binary).
#
# Requires a `dent8` built with the export feature, plus the `duckdb` CLI for the queries
# (the export itself needs no DuckDB). From a clone:
#   DENT8="cargo run -q -p dent8-cli --features export --" ./examples/duckdb/demo.sh
# or install it: `cargo install --git https://github.com/xyzzylabs/dent8 --features export dent8-cli`
set -euo pipefail

DENT8="${DENT8:-dent8}"
DENT8_LOG="$(mktemp -t dent8-duckdb-demo.XXXXXX)"
OUT="$(mktemp -t dent8-events.XXXXXX).parquet"
export DENT8_LOG
trap 'rm -f "$DENT8_LOG" "$OUT"' EXIT

echo "# 1. Build a belief history (asserts, a derivation, a retraction of the source)"
$DENT8 assert repo myproj database postgres high source:owner
$DENT8 assert repo myproj language rust high source:owner
# A fact derived FROM another fact — records a claim->claim dependency edge (ADR 0010).
$DENT8 derive service api datastore postgres high source:agent repo myproj database
# Retract the source fact: its derivative is now poisoned (verify/export surface the taint).
$DENT8 retract repo myproj database high source:owner

echo
echo "# 2. Export the whole log to Parquet"
$DENT8 export "$OUT"

echo
if ! command -v duckdb >/dev/null 2>&1; then
  echo "# (duckdb CLI not found — install it from https://duckdb.org to run the queries below)"
  echo "#   duckdb -c \"SELECT source, count(*) FROM '$OUT' GROUP BY 1\""
  exit 0
fi

echo "# 3. Query it with DuckDB"
echo
echo "## writes by source"
duckdb -c "SELECT source, count(*) AS writes FROM '$OUT' GROUP BY 1 ORDER BY 2 DESC"

echo "## event timeline (kind per claim, in order)"
duckdb -c "SELECT sequence, kind, claim_id FROM '$OUT' ORDER BY sequence"

echo "## the dependency graph — what was derived from what"
duckdb -c "SELECT claim_id, derived_from FROM '$OUT' WHERE derived_from IS NOT NULL"

echo "## re-emit as a second Parquet (DuckDB is the bridge to other tools)"
duckdb -c "COPY (SELECT * FROM '$OUT') TO '/dev/stdout' (FORMAT json)" | head -1
