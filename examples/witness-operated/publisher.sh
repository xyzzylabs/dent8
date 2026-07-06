#!/bin/sh
# Publication loop: idempotently append the latest signed head to the published sequence and
# keep the PUBLIC key alongside it, so a monitor needs nothing from the signer's trust
# domain. `publish` refuses to publish behind an existing external sequence (rollback of the
# published file itself is detected). In production, push /published to storage the writer
# cannot touch (object store with retention, a git repo, another host).
set -eu

pub="${DENT8_WITNESS_KEY:?}.pub"
published_heads="${PUBLISHED_HEADS:-/published/heads.jsonl}"
published_grants="${PUBLISHED_GRANTS:-/published/grant-heads.jsonl}"
until [ -f "$pub" ]; do
  echo "publisher: waiting for the signer to generate ${pub}"
  sleep 2
done
cp -f "$pub" /published/witness.key.pub

while true; do
  if [ -f "${DENT8_WITNESS_LOG:?}" ]; then
    if [ -n "${DENT8_WITNESS_GRANTS_LOG:-}" ] && [ -s "$DENT8_WITNESS_GRANTS_LOG" ]; then
      dent8 witness publish "$published_heads" --grants "$published_grants" \
        || echo "publisher: publish failed (will retry)"
    else
      dent8 witness publish "$published_heads" || echo "publisher: publish failed (will retry)"
    fi
  fi
  sleep "${PUBLISH_INTERVAL_SECONDS:-15}"
done
