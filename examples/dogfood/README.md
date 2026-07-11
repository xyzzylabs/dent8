# dent8 dogfood

This example validates the **real local dent8 setup for this repository**. Unlike the other
examples, it is not hermetic: it expects the ignored `.dent8/` bundle, signed agent identity,
MCP config, and witness paths used by local agents.

Run it from the repository root:

```sh
./examples/dogfood/demo.sh
```

It checks the useful path an agent relies on:

1. load `.dent8/env` plus `.dent8/identity-codex.env`;
2. list durable project facts from the shared SQLite store;
3. assert a high-authority diagnostic fact;
4. reject a low-authority supersession of that fact;
5. explain and verify the retained value;
6. sign and verify a local witness head when `.dent8/witness.key` is present;
7. run an advisory read-only `dent8 doctor --all-agents`;
8. run `dent8 doctor --agent <profile> --write-check` for the selected agent;
9. sign again so doctor write probes do not leave an unwitnessed tail, then run an advisory
   read-only all-agents doctor check.

The script writes only `diagnostic:*` streams with the internal `dent8.write_check` predicate.
Normal `dent8 facts list` hides those by default, so repeated dogfood checks do not crowd out
durable project facts.

Environment knobs:

| Variable | Default | Purpose |
|---|---|---|
| `DENT8_DOGFOOD_DIR` | `.dent8` | Bundle directory to validate. |
| `DENT8_DOGFOOD_AGENT` | `codex` | Agent profile used for the final focused doctor check. |
| `DENT8_DOGFOOD_SOURCE` | same as agent | Identity env suffix, e.g. `codex` for `.dent8/identity-codex.env`. |
| `DENT8` | `.dent8/bin/dent8`, then `cargo run -q -p dent8-cli --` | Binary/command to run. |

This is a maintainer workflow, not a packaged acceptance test. CI should keep using hermetic
examples and release scripts.
