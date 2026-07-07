# Dogfood Workflow

dent8 should use dent8 as its durable project memory. Provider-native files such as
`AGENTS.md`, `CLAUDE.md`, Cursor rules, or chat history can remind agents what to do, but they
are not the source of truth for project facts.

## Start A Session

Load the local bundle and inspect memory before relying on remembered setup:

```sh
set -a
. .dent8/env
. .dent8/identity-codex.env
set +a

.dent8/bin/dent8 facts list
.dent8/bin/dent8 explain repo:dent8 dogfood.setup
.dent8/bin/dent8 doctor --agent codex --dir .dent8
```

Use the source identity for the agent doing the work:

| Agent | Identity env |
|---|---|
| Codex | `.dent8/identity-codex.env` |
| Claude Code | `.dent8/identity-claude-code.env` |
| Cursor | `.dent8/identity-cursor.env` |

Run the full dogfood acceptance path when the setup itself changed:

```sh
./examples/dogfood/demo.sh
```

## Write Durable Facts

Use dent8 when a decision should survive chat/session context:

```sh
.dent8/bin/dent8 assert repo:dent8 product.next_arc "stable daemon/API contracts before desktop"
.dent8/bin/dent8 supersede repo:dent8 dogfood.setup "SQLite-backed .dent8 bundle with signed Codex/Claude/Cursor identities and witness coverage"
.dent8/bin/dent8 explain repo:dent8 dogfood.setup
```

Prefer `supersede` for changed facts rather than editing native-memory prose. Prefer specific
predicates over paragraphs when possible:

- `repo.database`
- `repo.test_command`
- `dogfood.setup`
- `dogfood.workflow`
- `witness.posture`
- `agent_setup`
- `product.next_arc`
- `release_status`
- `user.preference`

For temporary checks, use `diagnostic:*` subjects with an internal `dent8.*` predicate such as
`dent8.write_check`. They remain auditable but are hidden from normal `facts list` output unless
`--include-diagnostics` is passed.

## Keep Witness Coverage Current

After writes to the local dogfood store, sign a fresh local witness head when the private key is
available:

```sh
export DENT8_WITNESS_GRANTS_LOG=.dent8/witness-grants.jsonl
DENT8_WITNESS_KEY=.dent8/witness.key .dent8/bin/dent8 witness sign
.dent8/bin/dent8 witness verify
```

The signing key is intentionally not in `.dent8/env`; pass it only for signing.

## Bypass Discipline

Agents can still bypass dent8 by writing native memory/rules files or raw storage directly.
For this repo:

1. use MCP/CLI writes for durable project facts;
2. keep native-memory hook guards enforced where the agent supports them;
3. run `dent8 native scan --agent <profile>` when native files changed;
4. run `./examples/dogfood/demo.sh` after setup changes, or at least
   `dent8 doctor --agent <profile> --write-check` for the agent you are using;
5. use `dent8 verify` before trusting a long-running store.

The firewall only arbitrates writes that enter the dent8 boundary. The operational rule is
simple: durable project memory goes through dent8 first.
