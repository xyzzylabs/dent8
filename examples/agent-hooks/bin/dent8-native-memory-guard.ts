#!/usr/bin/env node
/*
 * Small TypeScript hook helper for dent8's agent integration examples.
 *
 * This is behavior-compatible with dent8-native-memory-guard.py. It is useful
 * for agent setups that already standardize on Node/TypeScript tooling.
 *
 * Set DENT8_HOOK_MODE to one of:
 *
 * - session-start
 * - guard-native-memory-write
 * - post-write-audit
 *
 * Set DENT8_HOOK_ENFORCE=1 to turn a guard hit into exit code 2. Most agent
 * hook systems treat exit code 2 as a blocking policy failure.
 */

declare const require: (specifier: string) => any;
declare const process: {
  env: Record<string, string | undefined>;
  exitCode?: number;
};

const childProcess = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const DEFAULT_PATTERNS: readonly string[] = [
  String.raw`(^|/)AGENTS\.md$`,
  String.raw`(^|/)CLAUDE(\.local)?\.md$`,
  String.raw`(^|/)MEMORY\.md$`,
  String.raw`(^|/)GEMINI\.md$`,
  String.raw`(^|/)\.cursor/rules/.*\.(md|mdc)$`,
  String.raw`(^|/)\.devin/rules/.*\.md$`,
  String.raw`(^|/)\.windsurf/rules/.*\.md$`,
];

const PATH_KEYS: ReadonlySet<string> = new Set([
  "absolute_path",
  "file",
  "filePath",
  "file_path",
  "new_path",
  "old_path",
  "path",
  "relative_path",
  "target_file",
]);

function main(): number {
  const payload = readPayload();
  const mode = process.env.DENT8_HOOK_MODE ?? "guard-native-memory-write";

  if (mode === "session-start") {
    return runVerify("session start");
  }

  const touched = Array.from(nativeMemoryPaths(payload)).sort();
  if (mode === "post-write-audit") {
    if (touched.length > 0) {
      return runVerify(`native memory/rules changed: ${touched.join(", ")}`);
    }
    return 0;
  }

  if (mode !== "guard-native-memory-write") {
    console.error(`dent8 hook: unknown DENT8_HOOK_MODE=${mode}`);
    return 2;
  }

  if (touched.length === 0) {
    return 0;
  }

  console.error(
    "dent8 native memory/rules guard: direct writes to " +
      `${touched.join(", ")} bypass the claim-event firewall. ` +
      "Use dent8 MCP tools or an explicit reviewed export from dent8. " +
      "Set DENT8_ALLOW_NATIVE_MEMORY_WRITE=1 to bypass this local guard.",
  );

  if (process.env.DENT8_ALLOW_NATIVE_MEMORY_WRITE === "1") {
    return 0;
  }
  if (process.env.DENT8_HOOK_ENFORCE === "1") {
    return 2;
  }
  return 0;
}

function readPayload(): unknown {
  const raw = fs.readFileSync(0, "utf8");
  if (raw.trim() === "") {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch (error: unknown) {
    const message =
      error instanceof Error ? error.message : "unknown JSON parse error";
    console.error(`dent8 hook: could not parse hook JSON: ${message}`);
    return {};
  }
}

function nativeMemoryPaths(payload: unknown): Set<string> {
  const patterns = compiledPatterns();
  const paths = new Set<string>();

  for (const value of candidateStrings(payload)) {
    const normalized = value.replaceAll("\\", "/");
    if (patterns.some((pattern) => pattern.test(normalized))) {
      paths.add(normalized);
    }
  }

  return paths;
}

function compiledPatterns(): RegExp[] {
  const raw = process.env.DENT8_NATIVE_MEMORY_PATTERNS;
  const patterns = raw ? raw.split(path.delimiter) : Array.from(DEFAULT_PATTERNS);
  return patterns.filter((pattern: string) => pattern !== "").map(
    (pattern: string) => new RegExp(pattern),
  );
}

function* candidateStrings(value: unknown): Iterable<string> {
  if (isRecord(value)) {
    for (const [key, child] of Object.entries(value)) {
      if (PATH_KEYS.has(key) && typeof child === "string") {
        yield child;
      }
      yield* candidateStrings(child);
    }
    return;
  }

  if (Array.isArray(value)) {
    for (const child of value) {
      yield* candidateStrings(child);
    }
    return;
  }

  if (typeof value === "string" && looksLikePath(value)) {
    yield value;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function looksLikePath(value: string): boolean {
  const markers = [
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
  ];
  return markers.some((marker) => value.includes(marker));
}

function runVerify(reason: string): number {
  const dent8 = process.env.DENT8_BIN ?? "dent8";
  console.error(`dent8 hook: verify (${reason})`);

  const completed = childProcess.spawnSync(dent8, ["verify"], {
    encoding: "utf8",
  });
  const error = completed.error as { code?: string; message?: string } | undefined;

  if (error?.code === "ENOENT") {
    console.error(`dent8 hook: '${dent8}' not found; skipping verify`);
    return 0;
  }
  if (error) {
    console.error(`dent8 hook: verify failed to start: ${error.message}`);
    return 2;
  }

  if (completed.stdout) {
    console.error(String(completed.stdout).trimEnd());
  }
  if (completed.stderr) {
    console.error(String(completed.stderr).trimEnd());
  }

  return typeof completed.status === "number" ? completed.status : 2;
}

process.exitCode = main();
