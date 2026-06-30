# Cursor hook profile

Use the regular Cursor MCP example first: [`../../cursor/`](../../cursor/). That is the
authoritative dent8 write path.

Cursor also has a hook surface, but dent8 does not ship a checked JSON hook profile for it yet.
The safe v0 integration is:

1. Keep dent8 mounted through `.cursor/mcp.json`.
2. Put durable project rules exported from dent8 under `.cursor/rules/`.
3. Use the shared helper below in the Cursor pre-write hook equivalent for files under
   `.cursor/rules/` and `AGENTS.md` once the hook schema you are using is confirmed:

```sh
DENT8_HOOK_MODE=guard-native-memory-write \
DENT8_HOOK_ENFORCE=1 \
dent8 hook native-memory-guard
```

The reason this is a README rather than a sample config is intentional: a wrong hook config
creates false confidence. MCP is stable enough for the v0 path; provider hook schemas should
be checked against the client version before being committed to a team repo.
