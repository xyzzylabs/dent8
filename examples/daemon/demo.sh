#!/usr/bin/env bash
# Runs the local daemon path (ADR 0018) through the real CLI: bootstrap a signed identity, start
# a per-user daemon on a Unix socket, then route several *separate* CLI invocations through it
# with DENT8_DAEMON_SOCKET. Each routed write is arbitrated and Ed25519-attested by the daemon as
# the source, so many processes share one firewalled belief base over one transport — and each
# written event still re-verifies offline exactly like a local write.
#
# Requires the `dent8` binary. Either install it (`cargo install dent8-cli --locked`) and run
# `./demo.sh`, or from a clone:
#   DENT8="cargo run -q -p dent8-cli --" ./examples/daemon/demo.sh
#
# The daemon is a per-user, single-source service: each connection must prove the same source
# key the daemon holds. "Many processes" here means many connections sharing one identity; use
# separate stdio servers or separate daemon instances for distinct per-agent identities.
set -euo pipefail

DENT8="${DENT8:-dent8}"
WORK="$(mktemp -d -t dent8-daemon-demo.XXXXXX)"
SOCK="$WORK/d.sock"
DPID=""
cleanup() {
  [ -n "$DPID" ] && kill "$DPID" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Keep the walkthrough hermetic if the caller's shell is already dogfooding dent8, and keep the
# operator issuer key inside the temp dir so nothing lands in ~/.config.
unset DENT8_STORE_URL DENT8_LOG DENT8_AUTHORITY DENT8_REQUIRE_AUTHORITY DENT8_TRUST \
  DENT8_ACTIVE_GRANTS DENT8_REQUIRE_IDENTITY DENT8_GRANT DENT8_IDENTITY_KEY \
  DENT8_DAEMON_SOCKET DENT8_WITNESS_KEY DENT8_WITNESS_PUBKEY DENT8_WITNESS_LOG
export DENT8_ISSUER_KEY="$WORK/issuer.key"

echo "# 1. Bootstrap a signed belief base (trust + grant + source key) and load its env"
$DENT8 init --dir "$WORK/.dent8" --source source:owner --identity >/dev/null
set -a
. "$WORK/.dent8/env"                 # store + authority registry
. "$WORK/.dent8/identity-owner.env"  # trust + grant + source key
set +a

echo "# 2. Start a per-user daemon on a Unix socket (0600), serving that belief base"
$DENT8 daemon serve --socket "$SOCK" >"$WORK/daemon.log" 2>&1 &
DPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "daemon did not start:"; cat "$WORK/daemon.log"; exit 1; }

# From here on, CLI *writes* route through the daemon; reads stay local against the same store.
export DENT8_DAEMON_SOCKET="$SOCK"

echo
echo "# 3. daemon status confirms reachability and this caller authenticates"
$DENT8 daemon status

echo
echo "# 4. Process A routes a write through the daemon"
$DENT8 assert repo:app deploy_target production --authority high --source source:owner

echo
echo "# 5. Process B (a separate invocation) routes another write to the same belief base"
$DENT8 assert service:api owner platform-team --authority high --source source:owner

echo
echo "# 6. A low-authority override routed through the daemon is rejected, exactly like local"
if $DENT8 supersede repo:app deploy_target staging --authority low --source source:owner; then
  echo "unexpected: low-authority override was accepted" >&2
  exit 1
fi

echo
echo "# 7. One shared belief base built by both processes (read locally)"
$DENT8 facts list

echo
echo "# 8. Verify: the daemon-written events attest as the source and re-verify offline"
$DENT8 verify
