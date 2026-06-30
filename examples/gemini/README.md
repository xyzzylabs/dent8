# dent8 with Gemini CLI

Gemini CLI supports local MCP servers through `settings.json`. dent8 exposes
`dent8 mcp serve`, so Gemini can use dent8 as a project memory firewall while keeping
Gemini-native memory (`GEMINI.md` and `/memory`) as a projection or reminder surface.

## Project scope

From the target project:

```sh
mkdir -p .gemini
dent8 init --agent gemini
cp /path/to/dent8/examples/gemini/settings.sample.json .gemini/settings.json
```

Then edit `.gemini/settings.json` and replace `/abs/path/to/project` with the project root.
If you already have Gemini settings, merge only the `mcpServers.dent8` entry.

## CLI install shape

Gemini's `mcp add` command can create the same entry:

```sh
gemini mcp add \
  -s project \
  -e DENT8_LOG="$PWD/.dent8/gemini-memory.jsonl" \
  -e DENT8_AUTHORITY="$PWD/.dent8/authority.json" \
  -e DENT8_REQUIRE_AUTHORITY=1 \
  -e DENT8_TRUST="$PWD/.dent8/trust.json" \
  -e DENT8_REQUIRE_IDENTITY=1 \
  -e DENT8_GRANT="$PWD/.dent8/grants/source_gemini.grant.json" \
  -e DENT8_IDENTITY_KEY="$PWD/.dent8/identities/source_gemini.key" \
  dent8 dent8 mcp serve
```

Use `gemini mcp list` to confirm the server is registered.

## Prompt Gemini

```text
Before relying on durable project facts, inspect dent8 with list_facts or explain.
Record stable project facts in dent8 using source:gemini and the lowest adequate authority.
Use contradict for uncertain conflicts and supersede only when replacing a believed fact.
Run verify before broad edits that depend on remembered facts.
Treat GEMINI.md and /memory as reminders, not the source of truth for stable project facts.
```

Useful first facts:

```text
repo:<project> database
repo:<project> test_command
dependency:<package> version
branch:<branch> status
user:<name> preference
```

## Optional hook guard

After MCP works, merge
[`../agent-hooks/gemini/settings.sample.json`](../agent-hooks/gemini/settings.sample.json)
into `.gemini/settings.json`. The sample runs `dent8 verify` on session boundaries and blocks
direct writes to `GEMINI.md`, `AGENTS.md`, and other native memory/rules files unless you
explicitly set `DENT8_ALLOW_NATIVE_MEMORY_WRITE=1`.
