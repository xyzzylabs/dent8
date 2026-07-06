#!/bin/sh
# Witness signer loop: create the signing key on first run (it never leaves the /witness
# volume), then sign new event/grant heads whenever those logs have grown. `dent8 witness
# serve` is the cadence signer with growth detection and a consecutive-error circuit breaker.
set -eu

if [ ! -f "${DENT8_WITNESS_KEY:?}" ]; then
  echo "signer: generating witness keypair at ${DENT8_WITNESS_KEY}"
  dent8 witness keygen
fi

exec dent8 witness serve "${SIGN_INTERVAL_SECONDS:-15}"
