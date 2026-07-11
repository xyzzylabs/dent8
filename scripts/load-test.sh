#!/usr/bin/env bash
# Concurrency load test for the async backends (roadmap: post-v0.6 item 3).
#
# Phase A — throughput + id uniqueness: N writers assert M distinct facts each, in
# parallel, against one shared store. Invariants: every write accepted; the store holds
# exactly N*M events; every event id is unique.
#
# Phase B — arbitration under contention: the same N writers all supersede ONE
# subject+predicate at equal authority, in parallel. This hammers the id-reservation and
# write-conflict retry path. Invariants: every supersession eventually admitted (the
# retry path absorbs conflicts); the end state believes exactly one value; `verify` is
# green over the whole log.
#
#   scripts/load-test.sh [WRITERS] [WRITES_PER_WRITER]     # default 8 x 25, SQLite
#   DENT8_BIN=target/release/dent8 scripts/load-test.sh 16 50
#
# Uses the embedded SQLite backend (the stock build's shared-store path). For Postgres,
# point DENT8_STORE_URL at a database before running and skip the init below.
set -euo pipefail

WRITERS="${1:-8}"
WRITES="${2:-25}"
BIN="${DENT8_BIN:-dent8}"

WORK="$(mktemp -d -t dent8-load-test.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
DB="$WORK/load.db"
export DENT8_STORE_URL="sqlite://$DB"
export DENT8_AUTHORITY="$WORK/authority.json"
unset DENT8_LOG DENT8_TRUST DENT8_GRANT DENT8_IDENTITY_KEY DENT8_REQUIRE_IDENTITY \
  DENT8_REQUIRE_AUTHORITY DENT8_DAEMON_SOCKET 2>/dev/null || true

echo "# dent8 load test: $WRITERS writers x $WRITES writes, backend $DENT8_STORE_URL"
"$BIN" --version

writer_a() {
  local writer="$1"
  for i in $(seq 1 "$WRITES"); do
    "$BIN" assert "load:w$writer" "fact_$i" "value_${writer}_$i" \
      --authority high --source "user:w$writer" >/dev/null
  done
}

echo "## phase A: distinct facts, parallel writers"
START=$(date +%s)
pids=()
for w in $(seq 1 "$WRITERS"); do writer_a "$w" & pids+=($!); done
fail=0
for pid in "${pids[@]}"; do wait "$pid" || fail=1; done
ELAPSED=$(( $(date +%s) - START ))
[ "$fail" = 0 ] || { echo "FAIL: a phase-A writer exited nonzero"; exit 1; }
TOTAL=$((WRITERS * WRITES))
echo "phase A: $TOTAL writes in ${ELAPSED}s ($(( ELAPSED > 0 ? TOTAL / ELAPSED : TOTAL )) writes/s)"

count_sql() { sqlite3 "$DB" "$1"; }
EVENTS=$(count_sql "SELECT COUNT(*) FROM dent8_event_log;")
DISTINCT=$(count_sql "SELECT COUNT(DISTINCT event_id) FROM dent8_event_log;")
[ "$EVENTS" = "$TOTAL" ] || { echo "FAIL: expected $TOTAL events, store has $EVENTS"; exit 1; }
[ "$DISTINCT" = "$EVENTS" ] || { echo "FAIL: duplicate event ids ($DISTINCT distinct of $EVENTS)"; exit 1; }
echo "phase A invariants: $EVENTS events, all ids unique"

echo "## phase B: $WRITERS writers supersede one fact, $WRITES rounds each"
"$BIN" assert contended:fact value seed --authority high --source user:seed >/dev/null
writer_b() {
  local writer="$1"
  for i in $(seq 1 "$WRITES"); do
    "$BIN" supersede contended:fact value "v_${writer}_$i" \
      --authority high --source "user:w$writer" >/dev/null
  done
}
START=$(date +%s)
pids=()
for w in $(seq 1 "$WRITERS"); do writer_b "$w" & pids+=($!); done
fail=0
for pid in "${pids[@]}"; do wait "$pid" || fail=1; done
ELAPSED=$(( $(date +%s) - START ))
[ "$fail" = 0 ] || { echo "FAIL: a phase-B writer exited nonzero (retry path exhausted?)"; exit 1; }
echo "phase B: $TOTAL contended supersessions in ${ELAPSED}s ($(( ELAPSED > 0 ? TOTAL / ELAPSED : TOTAL )) writes/s)"

EVENTS=$(count_sql "SELECT COUNT(*) FROM dent8_event_log;")
DISTINCT=$(count_sql "SELECT COUNT(DISTINCT event_id) FROM dent8_event_log;")
[ "$DISTINCT" = "$EVENTS" ] || { echo "FAIL: duplicate event ids after contention"; exit 1; }
BELIEVED=$("$BIN" --output json explain contended:fact value | python3 -c "import json,sys; print(json.load(sys.stdin)['value']['text'])")
echo "phase B invariants: $EVENTS total events, all ids unique, believed = $BELIEVED (exactly one)"

echo "## verify over the full log"
"$BIN" verify >/dev/null
echo "OK: verify green — arbitration held under contention"
