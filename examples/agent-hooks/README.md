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

The guard is built into the CLI — one command, no extra runtime:

```sh
DENT8_HOOK_MODE=guard-native-memory-write DENT8_HOOK_ENFORCE=1 dent8 hook native-memory-guard
```

It reads hook JSON on stdin, recognizes common provider payload shapes, and exits with code
`2` when an enforced native memory/rules write should be blocked (`DENT8_HOOK_ENFORCE` accepts
`1`/`true`/`yes`/`on`; an unreadable payload under enforcement fails **closed**).

### Contract

The guard speaks the exit-code hook protocol, and the contract below is pinned by tests
(`crates/dent8-cli/tests/agent_hook_examples.rs`) — integrations can rely on it:

- **stdout is always empty.** Some providers interpret hook stdout (Claude Code parses it as
  a decision document); everything the guard says goes to **stderr**, where a blocking
  provider feeds it back to the model.
- **Inputs**: the provider's hook JSON on stdin (any shape — unrecognized shapes simply match
  nothing); `DENT8_HOOK_MODE` selects the behavior; `DENT8_HOOK_ENFORCE` (malformed values
  fail closed — a typo cannot disable enforcement); `DENT8_ALLOW_NATIVE_MEMORY_WRITE`
  (malformed values never grant a bypass).

| `DENT8_HOOK_MODE` | condition | exit code |
| --- | --- | --- |
| `guard-native-memory-write` (default) | no native memory/rules target in the payload | 0 |
| | native target, not enforced | 0 (stderr warns) |
| | native target, enforced | **2** (block) |
| | native target, enforced, bypass flag set | 0 (stderr warns) |
| | unreadable payload, enforced | **2** (fail closed) |
| | unreadable payload, not enforced | 0 |
| `post-write-audit` | no native target | 0 |
| | native target (or unreadable payload) | re-runs `dent8 verify`: 0 ok / 1 fail |
| `session-start` | always | re-runs `dent8 verify`: 0 ok / 1 fail |
| any other value | | **2** (unknown mode) |

### What the guard inspects (and what it can't)

The guard is **best-effort** and matches a write target against the native memory/rules patterns
above. It covers:

- structured file-write tools — a path field like `file_path` / `path` (e.g. `Write`, `Edit`);
- `apply_patch` bodies — the `*** Update File:` / `*** Add File:` / `*** Delete File:` /
  `*** Move to:` headers;
- common shell redirections — `> FILE`, `>> FILE`, and `tee [-a] FILE`.

It does **not** parse every shell write mechanism — `sed -i`, `cp`/`mv`, an interpreter writing a
file (`python -c …`), or an embedded heredoc can still reach a native memory file undetected. A
mere *read* (`cat AGENTS.md`) is intentionally not flagged. This is why the guard is a seatbelt,
not the boundary — see below.

## Why hooks are not enough

Hooks are provider-specific and can be disabled, misconfigured, or bypassed by a different
client. dent8's integrity boundary remains the event-sourced store plus MCP/CLI write path.
The hook layer is a seatbelt around native files, not the engine. For an **in-process** Python
or TypeScript app (LangChain, LlamaIndex, Vercel AI SDK, …) there is no native-memory file to
guard — wire dent8 in as a memory firewall over MCP instead (see
[`../langchain/`](../langchain/) and [`../mcp/`](../mcp/)).
