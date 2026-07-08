# Context And Capture: Closing The Loop

dent8's wedge is **multiple coding agents (and a human) sharing one verified fact base about
one repository** — the stale-`CLAUDE.md` problem. That only works if the store actually
touches an agent's session on both ends:

- **Inject** at session start: `dent8 context` emits the currently-believed facts as a
  markdown context pack (or `--output json`).
- **Capture** at session end: `dent8 capture` flushes structured fact proposals back through
  the same firewall path as every other write.
- **Arbitrate** without setup homework: `dent8 authority defaults` seeds the natural trust
  ordering for a repository — **human > CI > agent** — so authority arbitration works before
  anyone invents a trust taxonomy.

There is no daemon and no new write path here. `context` is a read over the same durable
store as `explain`/`facts list`; `capture` dispatches every proposal to the same `op_*`
firewall layer as the interactive CLI and the MCP tools.

## `dent8 context` — the context pack

```sh
dent8 context                       # markdown, ready for CLAUDE.md/AGENTS.md-style injection
dent8 context --output json        # machine-readable
dent8 context --kind repo          # scope by subject kind/key/predicate, like `facts list`
dent8 context --include-stale      # also show believed-but-stale facts, annotated
dent8 context --record-retrieval [--purpose session-start]
                                   # also record a fact.retrieved audit event per emitted fact
```

Semantics, in belief terms:

- **Only currently-believed facts appear.** A superseded, retracted, or expired fact is
  history, not context.
- **Stale and not-yet-valid facts are omitted by default** (and counted in a trailer), or
  annotated inline with `--include-stale` — injected context must not smuggle in a fact past
  its validity window unmarked.
- **A contested fact is flagged, never silently picked**: the line carries a
  `[contested — N rival value(s)]` marker, and the JSON `status` is `contested` instead of
  `ok` whenever the pack carries a live dispute.
- **Every fact carries provenance**: authority, the asserting source, and its
  `dent8://{kind}/{key}/{predicate}` receipt reference — so a generated block pasted into a
  native memory file remains verifiable with `dent8 native reconcile` and
  `dent8 explain`.
- Internal `diagnostic:*` streams are hidden unless `--include-diagnostics` is passed,
  matching `facts list`.
- **`--record-retrieval` closes the read-audit loop**: every fact the pack emits gains a
  `fact.retrieved` audit event on its stream, stamped with `--purpose` (default
  `context-pack`). The audit is recorded *before* the pack is emitted and all-or-nothing,
  so an emitted pack is never un-audited; the markdown itself stays a pure context block,
  and `--output json` reports `recorded_retrievals`. Identity resolves like unattributed
  capture — the active signed grant's source when configured, else `source:agent` at
  `low` — through the normal write boundary. Audit events never change lifecycle, value,
  or authority; `dent8 replay` shows them with their purpose.

## `dent8 capture` — structured fact proposals

```sh
dent8 capture                        # read JSON-lines proposals from stdin
dent8 capture proposals.jsonl        # ... or from a file
dent8 capture proposals.jsonl --consume   # ... and truncate the queue afterwards
dent8 capture proposals.jsonl --consume --keep-failed
                                     # ... keeping rejected/malformed lines for retry
```

Each input line is one proposal:

```json
{"subject": "repo:dent8", "predicate": "cli_binary", "value": "dent8"}
{"op": "supersede", "subject": "repo:dent8", "predicate": "repo.database", "value": "postgres", "authority": "high", "source": "source:human"}
{"op": "used_in_decision", "subject": "repo:dent8", "predicate": "repo.database", "decision": "chose the sqlx driver"}
```

- `op` is `assert` (the default), `supersede`, `reinforce`, `contradict`, `retract`,
  `expire`, or `used_in_decision`; `value` is required for the first three and forbidden
  for the rest.
- **`used_in_decision` closes the report half of the read-audit loop**: it records a
  `fact.used_in_decision` audit event (with the required `decision` field instead of a
  `value`) on the believed fact(s) of the subject+predicate — how an agent reports which
  facts informed a decision, through the queue it already writes. Audit events never
  change lifecycle, value, or authority, and — like dissent — are not authority-gated in
  the fold, so a low-authority agent can report using a high-authority fact; the
  write-boundary gate (source ceiling, grant scope, signed identity) still applies.
- Authority and source resolve **per line**: the proposal's own fields, then the
  `--authority`/`--source` flags, then the active signed grant (`DENT8_GRANT`), then the
  **agent tier of the default profile** — `source:agent` at `low`. Unattributed agent
  capture enters at the bottom of the trust ordering instead of failing or minting
  authority.
- Every line is attempted; one bad proposal does not drop the rest of a session's capture.
  Unknown fields and unknown ops are rejected as malformed (a typo must fail loudly, not
  silently misattribute a write).
- Exit codes: `2` if any line was malformed, `1` if the firewall rejected any proposal —
  a **safety signal** worth surfacing in hook logs, not a crash — else `0`.
- `--consume` truncates the queue after processing; with `--keep-failed`, rejected and
  malformed lines are written back (accepted lines are still removed), so a failed
  proposal survives in the file for inspection/retry instead of only in hook logs. Note a
  kept line is retried verbatim on the next flush — fix or remove it, or it will fail
  again.
- Predicate policy still applies: a registry predicate with an authority floor (for
  example `repo.test_command` at `medium`) rejects an agent-tier proposal, exactly as it
  rejects the same write from `dent8 assert`.

Capture writes through the local op layer, so it follows `DENT8_LOG` / `DENT8_STORE_URL`
like every other command; it does not route through `DENT8_DAEMON_SOCKET`.

## `dent8 authority defaults` — the shipped trust profile

```sh
dent8 authority defaults
```

seeds the source→authority ceiling registry with:

| source         | max authority | natural role                        |
|----------------|---------------|-------------------------------------|
| `source:human` | `high`        | the repository owner's corrections  |
| `source:ci`    | `medium`      | machine-verified observations       |
| `source:agent` | `low`         | agent inference and session capture |

It is merge-only: an existing grant for one of those sources is kept, never downgraded
(`dent8 authority add` still replaces explicitly). `canonical` stays reserved for explicit
policy, because contradicting a canonical fact hard-alarms. Once seeded, the registry is
deny-by-default for unlisted sources, like any other registry
([STATUS.md](STATUS.md) §authority).

With the profile in place the arbitration you want falls out of the fold: an agent cannot
supersede a human-asserted fact, CI can supersede agent guesses but not human decisions,
and a human correction beats both.

## Wiring it into Claude Code hooks

[`examples/agent-hooks/claude-code/settings.sample.json`](../examples/agent-hooks/claude-code/settings.sample.json)
ships the full wiring:

- **`SessionStart`** runs `dent8 context`. A Claude Code `SessionStart` hook's stdout is
  added to the session context, so the believed facts are injected at session start with no
  file to keep fresh.
- **`SessionEnd`** runs `dent8 capture .dent8/proposals.jsonl --consume`. During the
  session the agent appends proposal lines to `.dent8/proposals.jsonl` (instruct it to in
  `CLAUDE.md`, or let it use the dent8 MCP tools directly for immediate writes); the hook
  flushes the queue through the firewall when the session ends and truncates it so the next
  firing does not replay it. A missing queue file is an empty session, not an error.

A minimal `CLAUDE.md` instruction for the queue-file variant:

```markdown
When you learn a durable project fact (database, test command, convention), append one
JSON line to .dent8/proposals.jsonl:
{"subject": "repo:<name>", "predicate": "<predicate>", "value": "<value>"}
Do not edit the "Project facts (dent8)" block by hand — it is generated by `dent8 context`.
```

For agents with MCP configured, the MCP `assert`/`supersede` tools remain the immediate
path; the proposals queue is the zero-MCP fallback that still ends at the same firewall.
Non-hook setups can run the same two commands as session bookends (e.g. a wrapper script
that prepends `dent8 context` output and pipes collected proposals to `dent8 capture`).

## Worked example (this repository)

Seeded against a fresh store for the dent8 repo itself:

```sh
$ dent8 authority defaults
seeded the default authority profile (human > CI > agent) in ./dent8-authority.json:
  added source:human  max=high
  added source:ci  max=medium
  added source:agent  max=low

$ dent8 assert repo:dent8 repo.database "postgres (operational) and embedded sqlite; file dev log by default" --authority high --source source:human
$ dent8 assert repo:dent8 repo.test_command "cargo test --workspace" --authority medium --source source:ci
$ echo '{"subject": "repo:dent8", "predicate": "cli_binary", "value": "dent8"}' | dent8 capture
line 1: ACCEPTED  repo:dent8 cli_binary = "dent8"  (authority=low)
captured 1 proposal(s): 1 accepted, 0 contested, 0 rejected, 0 invalid
```

The generated context pack:

```markdown
## Project facts (dent8)

<!-- generated by `dent8 context` at 1783523090324; regenerate instead of hand-editing -->

Currently-believed facts from the dent8 memory firewall. Each carries its authority and source; verify one with `dent8 explain <subject> <predicate>`.

### repo:dent8

- `cli_binary` = "dent8"  (authority: low, source: source:agent, ref: dent8://repo/dent8/cli_binary)
- `repo.database` = "postgres (operational) and embedded sqlite; file dev log by default"  (authority: high, source: source:human, ref: dent8://repo/dent8/repo.database)
- `repo.test_command` = "cargo test --workspace"  (authority: medium, source: source:ci, ref: dent8://repo/dent8/repo.test_command)
```

And the loop's integrity half — an unattributed agent proposal cannot displace the
human-asserted fact:

```sh
$ echo '{"op": "supersede", "subject": "repo:dent8", "predicate": "repo.database", "value": "mysql"}' | dent8 capture
line 1: REJECTED: firewall rejected the write: insufficient authority: low may not override or remove an incumbent of high
captured 1 proposal(s): 0 accepted, 0 contested, 1 rejected, 0 invalid
$ echo $?
1
```

## What this deliberately is not

- Not a daemon: both commands are one-shot processes over the existing store.
- Not natural-language ingestion: capture takes structured proposals only. Inferring facts
  from prose remains out of scope, like `native scan`/`native reconcile`.
- Not automatic read auditing: `fact.retrieved` is recorded only when
  `context --record-retrieval` asks for it, and `fact.used_in_decision` only when an agent
  reports one through a `used_in_decision` proposal. MCP-side read auditing (e.g.
  auto-auditing `resources/read`) remains roadmap work.
