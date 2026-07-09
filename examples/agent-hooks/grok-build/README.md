# Grok Build hook profile

Use the Grok Build MCP setup in [`../../grok-build/`](../../grok-build/) first.

## Project scope (preferred)

Install the sample as a **project** hook file (not `~/.grok/hooks/`):

```sh
mkdir -p .grok/hooks
cp examples/agent-hooks/grok-build/hooks.sample.json .grok/hooks/dent8.json
```

Grok loads `<project>/.grok/hooks/*.json` when the folder is trusted (`/hooks-trust` or
`--trust`). The sample mirrors Claude Code: session verify + `dent8 context`, enforced
native-memory `PreToolUse`, post-write audit, stop verify, and `SessionEnd` capture (loads
`.dent8/identity-grok-build.env` when present so flushes attribute to `source:grok-build`).

`dent8 doctor --agent grok-build` expects the conventional path `.grok/hooks/dent8.json` and
checks for `dent8 hook native-memory-guard` with `DENT8_HOOK_MODE=guard-native-memory-write`
and `DENT8_HOOK_ENFORCE=1`.

## Claude-compatible alternative

Grok also scans project `.claude/settings.json` when Claude hook compat is on. That can double
fire with a dedicated `.grok/hooks/dent8.json` — prefer one project profile. Do not put the
dogfood store guard in `~/.grok/hooks/` (user-global).

## Hecate-supervised sessions

If Grok Build is launched through Hecate or another supervisor, prefer putting the hook/guard
at the supervisor layer so every supervised agent gets the same dent8 policy. See
[`../hecate/`](../hecate/).
