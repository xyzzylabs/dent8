# 0003: MCP as Adapter

Date: 2026-06-26

## Status

Accepted.

## Context

The MVP target includes coding agents and IDE-like assistants, so MCP is an important integration surface. But dent8 should not be architected as "just an MCP memory server."

## Decision

MCP is an adapter over the core runtime and Postgres store.

The core event model, firewall, replay, and projections must remain protocol-independent.

## Consequences

Positive:

- CLI, HTTP, SDK, and MCP can share the same semantics.
- The core can be tested without protocol transport.
- MCP tools can expose integrity metadata instead of flattening memory into strings.

Negative:

- The MCP server crate should wait until the core write/read path is stable enough.
- The adapter must resist defining convenience semantics that bypass the firewall.

## Follow-Up

- Implement MCP tools after Postgres append and explain queries exist.
- Consider read-only MCP resources for replay and explain artifacts.

