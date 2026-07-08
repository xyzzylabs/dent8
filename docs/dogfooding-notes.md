# Dogfooding dent8 on dent8

This repo uses dent8 as its own shared, verified fact base — the "stale-`CLAUDE.md` killer"
thesis, lived. This note records how the fact base was set up and every rough edge hit along
the way. Honesty over polish: where a command needed too many flags or an error lied, it is
here.

## What was set up

- **Seeded store.** `scripts/dogfood-seed.sh` rebuilds `.dent8/` deterministically from
  `scripts/dogfood-facts.jsonl`. The `.dent8/` store itself is gitignored (machine-local
  paths and the local event log), so the script plus the facts file are the committed source
  of truth. The script runs `dent8 init`, sources the generated env, seeds the
  **human > CI > agent** trust profile (`dent8 authority defaults`), and captures 15
  human-authored facts as `source:human` at High authority.
- **15 real facts**, each verified against the repo (no invented values): MSRV 1.94; the
  three CI gates (`cargo test --workspace`, `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`); commit conventions (single
  author, Conventional Commits, no Co-Authored-By / AI attribution); the default authority
  profile; the frozen eval tallies (16/4/27 core arbitration, 25/9/13 with the content-hook
  lane); the content-check hook contract; and the v0.4 roadmap focus plus frozen items.
- **Hooks wired** in `.claude/settings.json`: `SessionStart` → `dent8 context` (inject the
  believed facts) plus a native-memory integrity check; `SessionEnd` →
  `dent8 capture .dent8/proposals.jsonl --consume --keep-failed` (flush agent-queued
  proposals through the firewall); `PreToolUse`/`PostToolUse` guard native-memory writes.
  Each hook command sources `.dent8/env` when present (so it reads the seeded store, not the
  permissive default) and no-ops quietly when `dent8` isn't built.
- **Flagship README example** built from this repo's real `dent8 context` pack.

Capture was fully clean: `15 accepted, 0 contested, 0 rejected, 0 invalid`, every line
printing `ACCEPTED … (authority=high)` — zero silent no-ops.

## Prioritized fix list

### P1 — first-run blockers and silent-wrong-store footguns

1. **`init` and `authority defaults` registries can diverge.** `dent8 init` grants
   `source:local max=high` in `.dent8/authority.json`. The dogfood/capture trust story wants
   `human > CI > agent`, which is a *separate* `dent8 authority defaults` call — and unless
   `.dent8/env` has already been sourced (so `DENT8_AUTHORITY` points at the init registry),
   `authority defaults` writes to a *different* file (`./dent8-authority.json` in the cwd). It
   is easy to end up with two registries and a confusing deny-by-default. Fix idea: let
   `init` seed the profile directly (e.g. via `--agent` or a flag), or have
   `authority defaults` default to the `.dent8/authority.json` that `init` created.
2. **The README "Try it" walkthrough was broken on a clean checkout** (fixed in this PR).
   Two independent bugs a first-run user hits: (a) `.dent8/identity-alice.env` was sourced
   *outside* `set -a`, so `DENT8_GRANT` was never exported and the first `dent8 assert` failed
   exit 2 ("missing --authority"); (b) with `--identity`, the low-authority supersede was
   rejected for a *source mismatch* ("grant source … does not match write source …") rather
   than the "Low can't override High" arbitration story the prose promised. The corrected
   walkthrough drops `--identity`, passes explicit `--authority`/`--source`, and sources env
   inside `set -a` — verified verbatim on a fresh store: the supersede now rejects with
   `insufficient authority: low may not override or remove an incumbent of high`.
3. **Env must be re-sourced in every shell, or writes silently hit a different store.**
   `DENT8_AUTHORITY`, `DENT8_LOG`, and `DENT8_REQUIRE_AUTHORITY=1` live only in `.dent8/env`.
   A command run without `set -a; . .dent8/env; set +a` falls back to the permissive dev
   default log (`./dent8-log.jsonl`), so a user who forgets can read/write a *different, empty*
   store and think their facts vanished. `init` prints the source snippet, which helps, but
   nothing guards the omission. The committed hooks now guard against this by sourcing
   `.dent8/env` themselves; the footgun remains only for ad-hoc CLI use outside the hooks.

### P2 — papercuts on the golden path

4. **Bare `dent8 facts` exits 2.** It is a command group whose only subcommand is `list`;
   `dent8 facts` alone dumps help to stderr and exits non-zero. Following intuition to see
   your facts fails. Make bare `facts` default to `facts list`.
5. **No install/PATH step is surfaced in the flow.** From a clone `dent8` is not on PATH, so
   every command becomes `./target/debug/dent8 …` (the `init` "Next:" hint and the seed output
   even print the absolute path). A one-line `cargo install --path crates/dent8-cli` (or a
   symlink) hint in `init` output would close it.
6. **`dent8 context` markdown embeds a volatile millisecond timestamp**
   (`<!-- generated by dent8 context at 1783547370878 -->`). Pasting the pack into a tracked
   file produces a spurious one-line diff on every regenerate. A `--no-timestamp` /
   deterministic mode would make the pack safe to commit.
7. **`.dent8/proposals.jsonl` is not created by `init`.** It is the file the `SessionEnd`
   hook drains, but it does not exist until something writes it, and a missing file is treated
   as an empty session (silent no-op) — so a path typo loses proposals silently. The seed
   script now `touch`es it; `init` arguably should too.
8. **`dent8 eval` (CLI) prints a 5/5 headline that is not the honest tally.** The
   externally-grounded numbers (16/4/27 arbitration, 25/9/13 with the content-hook lane) live
   only in `docs/evals.md` and the lib tests, so a user who runs the CLI never sees them.
   Surface the 47-case per-class breakdown behind a flag (e.g. `dent8 eval --full`).

### P3 — minor

9. `dent8 context --help` does not state that text output is markdown (you infer it).
10. First build is ~60s and pulls the full arrow/parquet/sqlx tree even for the default
    sqlite build, because `dent8-export` is a workspace member compiled alongside the CLI.
11. `capture --keep-failed` re-writes a rejected line verbatim, so a malformed proposal is
    retried forever until a human fixes or deletes it — worth a note in the capture docs.

## What worked well

- **Capture is loud and idempotent.** Every proposal prints `ACCEPTED`/`REJECTED` with its
  authority and a final tally; no silent drops. `--force` on `init` plus a clean
  `rm -rf .dent8` made the seed fully repeatable.
- **Provenance is real.** Every believed fact carries `(authority, source, uri)` and is
  replayable via `dent8 explain` — the whole point of the fact base, and it holds up.
- **Deny-by-default is announced,** not silent: `authority defaults` tells you unlisted
  sources are now blocked.

## Using the fact base (for agents on this repo)

1. `scripts/dogfood-seed.sh` — rebuild the local store.
2. `dent8 context` — read the believed facts (the `SessionStart` hook injects them
   automatically).
3. To add or correct a fact, append a proposal to `.dent8/proposals.jsonl`; the `SessionEnd`
   hook flushes it via `dent8 capture … --consume --keep-failed`. Human corrections enter as
   `source:human` at High; agent inferences as `source:agent` at Low. The fact base — not a
   hand-edited rules file — is authoritative.
