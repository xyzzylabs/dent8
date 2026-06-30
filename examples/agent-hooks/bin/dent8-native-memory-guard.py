#!/usr/bin/env python3
"""Small hook helper for dent8's agent integration examples.

The script is intentionally conservative: it never writes native memory files.
It can:

- run `dent8 verify` at session start;
- warn or block direct writes to agent-native memory/rules files;
- run `dent8 verify` after a write that touched those files.

Set DENT8_HOOK_MODE to one of:

- session-start
- guard-native-memory-write
- post-write-audit

Set DENT8_HOOK_ENFORCE=1 to turn a guard hit into exit code 2. Most agent hook
systems treat exit code 2 as a blocking policy failure.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any


DEFAULT_PATTERNS = (
    r"(^|/)AGENTS\.md$",
    r"(^|/)CLAUDE(\.local)?\.md$",
    r"(^|/)MEMORY\.md$",
    r"(^|/)GEMINI\.md$",
    r"(^|/)\.cursor/rules/.*\.(md|mdc)$",
    r"(^|/)\.devin/rules/.*\.md$",
    r"(^|/)\.windsurf/rules/.*\.md$",
)

PATH_KEYS = {
    "absolute_path",
    "file",
    "filePath",
    "file_path",
    "new_path",
    "old_path",
    "path",
    "relative_path",
    "target_file",
}


def main() -> int:
    payload = read_payload()
    mode = os.environ.get("DENT8_HOOK_MODE", "guard-native-memory-write")

    if mode == "session-start":
        return run_verify("session start")

    touched = sorted(native_memory_paths(payload))
    if mode == "post-write-audit":
        if touched:
            return run_verify(f"native memory/rules changed: {', '.join(touched)}")
        return 0

    if mode != "guard-native-memory-write":
        print(f"dent8 hook: unknown DENT8_HOOK_MODE={mode}", file=sys.stderr)
        return 2

    if not touched:
        return 0

    message = (
        "dent8 native memory/rules guard: direct writes to "
        f"{', '.join(touched)} bypass the claim-event firewall. "
        "Use dent8 MCP tools or an explicit reviewed export from dent8. "
        "Set DENT8_ALLOW_NATIVE_MEMORY_WRITE=1 to bypass this local guard."
    )
    print(message, file=sys.stderr)

    if os.environ.get("DENT8_ALLOW_NATIVE_MEMORY_WRITE") == "1":
        return 0
    if os.environ.get("DENT8_HOOK_ENFORCE") == "1":
        return 2
    return 0


def read_payload() -> Any:
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"dent8 hook: could not parse hook JSON: {exc}", file=sys.stderr)
        return {}


def native_memory_paths(payload: Any) -> set[str]:
    patterns = compiled_patterns()
    paths = set()
    for value in candidate_strings(payload):
        normalized = value.replace("\\", "/")
        if any(pattern.search(normalized) for pattern in patterns):
            paths.add(normalized)
    return paths


def compiled_patterns() -> list[re.Pattern[str]]:
    raw = os.environ.get("DENT8_NATIVE_MEMORY_PATTERNS")
    patterns = raw.split(os.pathsep) if raw else list(DEFAULT_PATTERNS)
    return [re.compile(pattern) for pattern in patterns if pattern]


def candidate_strings(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in PATH_KEYS and isinstance(child, str):
                yield child
            yield from candidate_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from candidate_strings(child)
    elif isinstance(value, str) and looks_like_path(value):
        yield value


def looks_like_path(value: str) -> bool:
    markers = (
        "/",
        "\\",
        "AGENTS.md",
        "CLAUDE.md",
        "CLAUDE.local.md",
        "GEMINI.md",
        "MEMORY.md",
        ".cursor/rules",
        ".devin/rules",
        ".windsurf/rules",
    )
    return any(marker in value for marker in markers)


def run_verify(reason: str) -> int:
    dent8 = os.environ.get("DENT8_BIN", "dent8")
    print(f"dent8 hook: verify ({reason})", file=sys.stderr)
    try:
        completed = subprocess.run(
            [dent8, "verify"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError:
        print(f"dent8 hook: {dent8!r} not found; skipping verify", file=sys.stderr)
        return 0

    if completed.stdout:
        print(completed.stdout.rstrip(), file=sys.stderr)
    if completed.stderr:
        print(completed.stderr.rstrip(), file=sys.stderr)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
