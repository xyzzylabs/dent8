# Local Daemon Example

This example runs the shared local service path from ADR 0018:

```sh
DENT8="cargo run -q -p dent8 --" ./examples/daemon/demo.sh
```

The script bootstraps a temporary signed identity bundle, starts `dent8 mcp serve --daemon`
on a private Unix socket, routes separate CLI write invocations through
`DENT8_DAEMON_SOCKET`, rejects a low-authority override, and verifies that daemon-written
events still carry offline-verifiable Ed25519 attestations.

The v0 daemon is per-user and single-source. Each client connection must complete
`dent8/hello` + `dent8/prove` and prove the same source key the daemon process holds. That is
useful for many local processes sharing one operator/source identity. For distinct per-agent
provenance, run separate stdio MCP servers against the same backend, or separate daemon
instances with separate source env.
