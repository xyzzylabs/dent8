# Reviewed legitimate-traffic traces

`dent8 eval --trace <FILE>` evaluates human-reviewed attempted operation batches through the
real store-level firewall. This is the non-circular path from designed benign scenarios to
evidence from actual agent sessions: a normal persisted log contains only admitted events, so
it cannot reveal writes the firewall rejected.

The schema is `dent8.legitimate-trace/1`. Each file must declare:

- whether its origin is `captured` or `synthetic`;
- which agent or integration produced it;
- whether embedded content is `redacted` or `raw`;
- a reviewer and review basis establishing that every operation is legitimate traffic;
- one or more independent operation scenarios, each naming its operation, explicitly declaring
  `expected: "admit"`, carrying the trusted, decision-complete `baseline_events` that preceded
  it, and containing the exact attempted `FactEvent` batch.

Multi-event operations are atomic: if one event is rejected, the operation counts as one false
positive. Operations are evaluated independently against their own baseline, so a rejected write
never contaminates a later scenario and event ids may honestly be reused by a later CLI attempt.
Duplicate trace/operation ids, duplicate event ids within one scenario, and structurally invalid
events make the evidence invalid instead of distorting the metric. Text and JSON reports include
only trace/operation ids, counts, privacy warnings, and typed rejection categories; they never
echo fact values, evidence locators, review notes, or error strings.

## Capture and review

Enable capture only for a bounded, intentionally benign task. The recorder is inherited by CLI,
stdio MCP, and a newly started daemon because they share the same `op_*` write functions:

```sh
export DENT8_EVAL_CAPTURE=.dent8/evals/codex-session.jsonl
export DENT8_EVAL_AGENT=codex
export DENT8_EVAL_SESSION=session:pseudonymous-001

# Run the normal agent/session, then stop recording.
unset DENT8_EVAL_CAPTURE DENT8_EVAL_AGENT DENT8_EVAL_SESSION

dent8 eval prepare .dent8/evals/codex-session.jsonl \
  --out .dent8/evals/codex-session.review.json
```

`prepare` writes `dent8.legitimate-trace-review/1`, which is deliberately not accepted by
`dent8 eval --trace`. Review every operation and change `classification` from
`review_required` to `legitimate` or `exclude`; fill `review.reviewer` and `review.basis`.
Redact or consistently pseudonymize values, subject keys, evidence locators/summaries, run ids,
and session ids before sharing. Remove `provenance.attestation` after editing signed event fields,
because the original signature no longer describes the redacted event. Then set
`privacy.content` to `redacted` (or leave it `raw` for local-only analysis) and finalize:

```sh
dent8 eval finalize .dent8/evals/codex-session.review.json \
  --out .dent8/evals/codex-session.trace.json
dent8 eval --trace .dent8/evals/codex-session.trace.json
```

The recorder creates raw JSONL with mode `0600` on Unix and includes a decision-complete
pre-operation baseline in each scenario: prior events for the candidate subject+predicate, each
candidate's own fact stream, supersession targets, and event-id collisions, all in original
global order. Unrelated fact streams are omitted to reduce review size and raw-data exposure; the
closure is parity-tested against full-snapshot replay. Recording is fail-open: an artifact
failure warns on stderr but never changes a write decision. A journal captures completed store
arbitration decisions, including rejections; it does not label any operation legitimate and does
not enter the dent8 event log. Use a separate capture file per agent/session. For a long-running
daemon, configure the variables in the daemon environment and restart it; setting them only in a
proxy client cannot alter the already-running server process.

Run the synthetic format example:

```sh
dent8 eval --trace evals/traces/synthetic_revision.example.json
dent8 eval --trace evals/traces/synthetic_revision.example.json --output json
```

The example is intentionally marked `synthetic` and does **not** count as observed product
evidence. Before sharing a captured trace, replace values, subject keys, locators, and session
identifiers with consistent pseudonyms, set `privacy.content` to `redacted`, and review the
result. A trace marked `raw` is accepted for local analysis but produces a warning and should
not be committed or uploaded.

The checked-in captured maintainer-dogfood fixtures cover:

| File | Agent | Operations |
|------|--------|------------|
| `claude-code-msrv.redacted.json` | Claude Code | 1 |
| `cursor-roadmap.redacted.json` | Cursor | 1 |
| `grok-build-mcp.redacted.json` | Grok Build | 1 |
| `cli-multi-op.redacted.json` | CLI | 5 (assert → reinforce → supersede → assert → retract) |

**4 traces / 8 legitimate operations / 0 false positives.** Project keys, values, ids, sessions,
timestamps, and evidence locators are pseudonymized; original event attestations were removed
after redaction. They are integration evidence for those paths, not independent external-user
evidence.

Gate them (plus the designed corpus) with:

```sh
scripts/integrity-check.sh
```

Capture a new session with `scripts/capture-legitimate-session.sh` (see
[docs/integrity-track.md](../../docs/integrity-track.md)).

This v1 lane measures deterministic store arbitration plus the built-in predicate policy applied
to `assert`/`derive`, matching the captured seam. Authority-ceiling, signed-identity,
content-check, transport, commit, and custom integration-policy failures occur before or after
that seam and are not recorded; do not attribute those outcomes to this false-positive rate.
