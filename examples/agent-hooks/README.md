# dent8 agent hook examples

These examples add a local guard around agent-native memory and rules files. They do not
replace MCP. The main write path is still `dent8 mcp serve`, where every candidate fact enters
the claim-event firewall.

Use hooks for three narrow jobs:

- run `dent8 verify` when an agent session starts or stops;
- block direct edits to native memory/rules files such as `MEMORY.md`, `GEMINI.md`,
  `.cursor/rules/*.mdc`, `.devin/rules/*.md`, and `AGENTS.md`;
- re-run `dent8 verify` after native memory/rules files change.

Provider profiles:

- [`codex/hooks.sample.json`](codex/hooks.sample.json)
- [`claude-code/settings.sample.json`](claude-code/settings.sample.json)
- [`gemini/settings.sample.json`](gemini/settings.sample.json)
- [`cascade/hooks.sample.json`](cascade/hooks.sample.json)
- [`cursor/`](cursor/)
- [`grok-build/`](grok-build/)
- [`hecate/`](hecate/)

## Install shape

1. Install the MCP profile for the agent first, from `examples/<agent>/`.
2. Copy the hook sample into the provider's hook config location.
3. Make sure `dent8` is on `PATH`, or replace `dent8 hook native-memory-guard` with the
   absolute path to the binary.
4. Keep `DENT8_HOOK_ENFORCE=1` only after the team has confirmed the hook runs correctly.

The default helper is built into the CLI:

```sh
DENT8_HOOK_MODE=guard-native-memory-write DENT8_HOOK_ENFORCE=1 dent8 hook native-memory-guard
```

Two dependency-light script equivalents are kept for hosts where calling the installed dent8
binary is inconvenient:

- [`bin/dent8-native-memory-guard.py`](bin/dent8-native-memory-guard.py) is the Python fallback.
- [`bin/dent8-native-memory-guard.ts`](bin/dent8-native-memory-guard.ts) is the TypeScript equivalent for Node-based agent setups.

All helpers read hook JSON on stdin, recognize common provider payload shapes, and exit with
code `2` when an enforced native memory/rules write should be blocked. To use the TypeScript
helper, replace `dent8 hook native-memory-guard` with `node .../dent8-native-memory-guard.ts`
on Node versions that support built-in TypeScript type stripping, or run it through your
existing TypeScript runner.

## Why hooks are not enough

Hooks are provider-specific and can be disabled, misconfigured, or bypassed by a different
client. dent8's integrity boundary remains the event-sourced store plus MCP/CLI write path.
The hook layer is a seatbelt around native files, not the engine.
