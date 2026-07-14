# Content-check hook

dent8's `append` arbitration governs **authority, provenance, and lifecycle** — it never
reads a fact's `value` text. The externally-grounded eval corpus
([evals.md](evals.md)) shows what that means honestly: content-embedded attacks (injected
imperatives, exfil instructions, obfuscated payloads, conditional time-bombs — classes
A/F/G/H, ~20/47 cases) are admitted as inert data *by design*, with "a downstream content
scanner" named as the owning layer.

The content-check hook is that layer's **seam**. dent8 does **not** ship a content
classifier — regexes cannot survive an adversary, and a bundled model would be a false
promise. Instead, the write boundary exposes one pluggable hook: configure an external
command, and dent8 runs it on **every candidate fact** before the fact can be arbitrated,
attested, or persisted. The scanner you attach (LLM Guard, Rebuff, a Lakera Guard or Azure
Prompt Shields bridge, a bespoke model) owns the judgment; dent8 owns making it
un-bypassable at the boundary it controls. This is the same composition philosophy as the
storage backends: the hook is the architecture, scanners are adapters.

## Configuration

Environment variables, like every other dent8 control
([configuration.md](configuration.md)):

| Variable | Default | Purpose |
|---|---|---|
| `DENT8_CONTENT_CHECK_ARGV` | *(unset → fall back to `DENT8_CONTENT_CHECK`)* | Preferred structured scanner command: a JSON array of argv strings, preserving spaces and quoting exactly. Empty disables the hook when `DENT8_CONTENT_CHECK` is also unset. |
| `DENT8_CONTENT_CHECK` | *(unset → pass-through)* | Legacy/convenience scanner command, whitespace-split into program + args (use a wrapper script or `DENT8_CONTENT_CHECK_ARGV` for anything needing quoting). Unset/empty disables the hook entirely — exactly the pre-hook write path, zero overhead. |
| `DENT8_CONTENT_CHECK_TIMEOUT_MS` | `5000` | Per-candidate-fact wall-clock budget. A scanner still running past it is killed and the run counts as a scanner failure. |
| `DENT8_CONTENT_CHECK_FAIL_OPEN` | *(unset / false)* | Failure policy for scanner failures (spawn error, timeout, non-zero exit, malformed verdict). **Default fail-closed.** When true, a failed scan admits the write but still marks it (see below). |

```sh
export DENT8_CONTENT_CHECK_ARGV='["/usr/local/bin/my-scanner","--policy","strict"]'
dent8 assert repo:app note "…"        # every value-carrying write is now scanned
```

## Protocol (`dent8.content-check/1`)

Per candidate fact — an event that carries a `value` — dent8 spawns the command, writes
one JSON payload to its stdin, and reads one JSON verdict object from its stdout. No
daemon, no network dependency in dent8 itself: one short-lived subprocess per candidate
(`std::process`).

Stdin payload:

```json
{
  "protocol": "dent8.content-check/1",
  "event_id": "event:12",
  "fact_id": "fact:repo:app:note:12",
  "event_type": "fact.asserted",
  "subject": { "kind": "repo", "key": "app" },
  "predicate": "note",
  "value": { "kind": "text", "text": "…the content to judge…" },
  "source": "source:agent",
  "authority": "low",
  "evidence": [ { "kind": "UserStatement", "locator": "cli:source:agent", "summary": null } ]
}
```

`value.kind` is `text` (with `text`), `json` (with `json`, a canonical JSON string), or
`redacted`. Evidence locators/summaries are included because they are
attacker-influenceable strings too.

Stdout verdict (exit status must be 0 for *any* verdict; non-zero means the scanner
itself failed):

```json
{"verdict": "allow"}
{"verdict": "reject", "reason": "why"}
{"verdict": "taint",  "reason": "why"}
```

- **`allow`** — the fact is admitted unchanged.
- **`reject`** — the write is refused; nothing is persisted. A multi-event operation
  (e.g. a supersession's replacement + markers) is refused whole, all-or-nothing.
- **`taint`** — the fact is admitted **but marked**, consistent with dent8's existing
  detect-only semantics (retraction taint, read-time freshness): surfaced, never silently
  absorbed. The mark is an ordinary evidence item on the stored event —
  `EvidenceKind::ToolOutput` with locator `content-check:<scanner>` and the scanner's
  `reason` as its summary — so it is covered by the write attestation and the hash chain,
  and `dent8 verify` lists every still-believed content-flagged fact as a
  `CONTENT-FLAGGED` finding (the same way retraction taint reports `TAINTED`).

Unknown verdict strings and malformed output are scanner failures, never a silent allow.
Scanner-supplied `reason` strings are truncated (256 chars) before they are persisted.
Extra fields in the verdict object are tolerated for forward compatibility.

## Failure policy: why fail-closed is the default

If you configured a scanner, you declared that unscanned content must not enter the
store. A scanner that crashes, hangs, or emits garbage therefore **blocks** writes by
default — otherwise an attacker who can crash or wedge the scanner (e.g. with a
pathological payload) holds a bypass, and the control silently degrades to nothing
exactly when it is under attack.

`DENT8_CONTENT_CHECK_FAIL_OPEN=1` flips the trade toward availability: a failed scan
admits the write — but dent8 still stamps it with a content flag
(`content check unavailable (fail-open): …`), so even fail-open never admits unscanned
content *invisibly*: `dent8 verify` reports it until the fact is revised or retracted.

## Where the hook sits (and why there is no bypass)

The hook runs in the shared `op_*` write layer — the same layer as the authority-ceiling
and signed-identity gate — **after** authority enforcement and **before** the candidate
events are arbitrated (`admit`/`append`), attested (ADR 0013), and persisted. Every write
entry point funnels through those ops:

- the CLI write commands (`assert`, `supersede`, `contradict`, `derive`, …),
- `dent8 capture` proposals (stdin/file batches),
- every MCP write tool (stdio server and daemon-proxied connections),
- daemon writes (ADR 0018 authenticated connections).

There is no other path that constructs and persists fact events, so there is no write
entry point that skips the scanner; the `content_check_hook` integration tests in
`crates/dent8-cli/tests/cli_usage.rs` prove each entry point rejects under a reject-all
scanner and that nothing reaches the log. Only **value-carrying** events are scanned:
value-less lifecycle/audit events (supersession markers, retractions, reinforcements,
retrieval records) introduce no new content. Because the taint mark lands *before*
attestation and arbitration, the persisted bytes, the receipt hash, and the signature all
agree.

Same-user processes that route around dent8 entirely (raw store files, provider-native
memory) are the T9 boundary in [threat-model.md](threat-model.md) — the hook governs the
dent8 write path, not the host.

## Wiring real scanners

Any executable that speaks the protocol works. Typical adapters are a few lines:

**LLM Guard** (local Python library):

```python
#!/usr/bin/env python3
import json, sys
from llm_guard.input_scanners import PromptInjection
payload = json.load(sys.stdin)
text = payload["value"].get("text") or payload["value"].get("json") or ""
_, valid, score = PromptInjection().scan(text)
print(json.dumps({"verdict": "allow" if valid else "reject",
                  "reason": f"llm-guard prompt-injection score {score}"}))
```

**Rebuff / Lakera Guard / Azure AI Content Safety (Prompt Shields)** (hosted APIs): the
adapter POSTs the text to the service and maps its detection to a verdict. Keep the
timeout budget in mind (`DENT8_CONTENT_CHECK_TIMEOUT_MS`) and decide the failure policy
deliberately: a network-dependent scanner is exactly the case where fail-closed vs
fail-open matters.

```sh
#!/bin/sh
# lakera-guard-check: reject when Lakera Guard flags the content.
payload="$(cat)"
text="$(printf '%s' "$payload" | jq -r '.value.text // .value.json // ""')"
flagged="$(curl -sf --max-time 4 https://api.lakera.ai/v2/guard \
  -H "Authorization: Bearer $LAKERA_GUARD_API_KEY" \
  -d "$(jq -n --arg c "$text" '{messages: [{role: "user", content: $c}]}')" \
  | jq -r '.flagged')" || exit 1                # curl/parse failure -> scanner failure
if [ "$flagged" = "true" ]; then
  printf '{"verdict":"reject","reason":"flagged by Lakera Guard"}\n'
else
  printf '{"verdict":"allow"}\n'
fi
```

Prefer `taint` over `reject` for advisory signals (low-confidence detections,
policy-of-record scanners) so the write survives but stays visible.

## The reference scanner is a demo, not a defense

[`examples/scanners/demo-content-check.sh`](../examples/scanners/README.md) is a handful
of `grep -E` heuristics that exists to demonstrate the protocol and drive the eval
harness's hook mode. Its rules were written with knowledge of dent8's own eval corpus,
and it deliberately misses the corpus's rot13 and translated payloads — the point is that
the *seam* covers the write path, not that regexes catch attackers. The honest per-class
numbers with it attached are in [evals.md](evals.md), reported separately from (and
without inflating) the core arbitration numbers.

## Limits

- **The scanner's judgment is the scanner's.** dent8 guarantees coverage and failure
  semantics, not detection quality. Obfuscation-robust detection is precisely the hard
  part (eval class H) — choose the attached scanner accordingly.
- **Reads are not scanned.** The hook is a write-boundary control; content already in the
  log (written before the hook was configured) is not retro-scanned. Re-assert or sweep
  with your scanner offline if you need retroactive coverage.
- **Latency.** One subprocess per candidate fact, serial within a write. Budget the
  timeout for hosted APIs; batch-heavy flows (`dent8 capture` with many proposals) pay it
  per proposal.
- **The subprocess sees what dent8 sends.** Secrets in scanner environment/config are the
  operator's responsibility, as with any hook.
