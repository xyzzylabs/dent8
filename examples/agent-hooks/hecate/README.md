# Hecate hook profile

Hecate should mount dent8 as an MCP server as shown in [`../../hecate/`](../../hecate/).

For supervised external agents, configure hooks in the child agent profile:

- Codex: [`../codex/hooks.sample.json`](../codex/hooks.sample.json)
- Claude Code: [`../claude-code/settings.sample.json`](../claude-code/settings.sample.json)
- Gemini CLI: [`../gemini/settings.sample.json`](../gemini/settings.sample.json)
- Cascade/Devin Desktop: [`../cascade/hooks.sample.json`](../cascade/hooks.sample.json)

Hecate itself is best used as the policy distributor: pass the same dent8 MCP block and hook
profile to every supervised agent so native memory/rules writes cannot bypass dent8.
