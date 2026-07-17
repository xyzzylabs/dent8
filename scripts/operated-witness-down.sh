#!/usr/bin/env bash
# Tear down the operated-witness compose project.
# Default removes containers; pass --volumes to wipe Postgres + keys + published.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$ROOT/examples/witness-operated"
PROJECT="${COMPOSE_PROJECT_NAME:-dent8-ops}"
COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_DIR/compose.yml")

if [ "${1:-}" = "--volumes" ]; then
  echo "operated-witness: down -v (destroy store + witness volumes)"
  "${COMPOSE[@]}" down -v --remove-orphans
  rm -rf "${DENT8_WITNESS_PUBLISHED_DIR:-$COMPOSE_DIR/published}"/*
else
  echo "operated-witness: down (keep volumes + published/)"
  "${COMPOSE[@]}" down --remove-orphans
fi
echo "operated-witness: stopped"
