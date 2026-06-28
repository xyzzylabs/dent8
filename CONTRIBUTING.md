# Contributing

dent8 is intentionally correctness-first. Please favor small changes with clear invariants over broad demo-oriented features.

## Development Checks

```sh
cargo fmt --all --check
cargo test --workspace
```

For schema smoke testing:

```sh
cargo run -q -p dent8-cli -- schema postgres
```

## Design Expectations

- Model memory as claim events, not mutable memory items.
- Keep replay deterministic.
- Preserve provenance, evidence, authority, TTL, and lifecycle state.
- Add tests for state transitions and invariants when changing domain behavior.
- Prefer Postgres-backed behavior for runtime storage decisions.

## Commit Scope

Keep commits focused. If a change alters architecture, storage semantics, event names, or public commands, update docs in the same change.

