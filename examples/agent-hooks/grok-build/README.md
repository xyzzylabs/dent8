# Grok Build hook profile

Use the Grok Build MCP setup in [`../../grok-build/`](../../grok-build/) first. If your Grok
Build environment reads Claude-compatible project configuration, adapt the Claude Code hook
sample from [`../claude-code/settings.sample.json`](../claude-code/settings.sample.json).

If Grok Build is launched through Hecate or another supervisor, prefer putting the hook/guard
at the supervisor layer so every supervised agent gets the same dent8 policy.
