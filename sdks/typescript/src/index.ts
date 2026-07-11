/**
 * dent8 — a memory firewall for coding agents, from TypeScript.
 *
 * A deliberately thin SDK: every call runs the `dent8` binary with `--output json`
 * and returns the parsed payload. The wire contract is the product — each payload
 * carries `schema_version`; every error carries a stable `status`
 * (`rejected` / `invalid`) and a machine-readable `code`
 * (`insufficient-authority`, `authority-ceiling`, `content-rejected`, …), thrown
 * here as {@link Dent8Rejected} / {@link Dent8Invalid} so callers branch on
 * `error.code` instead of parsing prose.
 *
 * Because the CLI itself resolves the store (repo-confined `.dent8/` discovery,
 * `DENT8_LOG` / `DENT8_STORE_URL`), routes writes through a local daemon when
 * `DENT8_DAEMON_SOCKET` is set, and defaults `--source` / `--authority` from the
 * active signed grant, this SDK inherits all of that for free.
 *
 * ```ts
 * import { Dent8 } from "dent8";
 *
 * const d8 = new Dent8();
 * d8.assertFact("repo:myproj", "database", "postgres",
 *               { authority: "high", source: "user:alice" });
 * const fact = d8.explain("repo:myproj", "database");
 * ```
 *
 * Requires the `dent8` binary on `PATH` (`cargo install dent8-cli --locked`) or an
 * explicit `new Dent8({ binary })`. For LLM tool-calling agents, prefer the MCP
 * server (`dent8 mcp serve`); this SDK is for programmatic access.
 */

import { spawnSync } from "node:child_process";

/** The JSON output shape this SDK was written against (stamped on every payload). */
export const SCHEMA_VERSION = 1;

/**
 * A wall-clock instant, in any grammar the CLI accepts: unix millis (number),
 * `"now"`, a ±duration offset (`"-7d"`), RFC 3339, or a bare UTC date/datetime.
 */
export type Time = number | string;

/** A parsed `--output json` payload. Field shapes are the CLI's machine contract. */
export type Payload = Record<string, unknown>;

/** Options accepted by every write verb. */
export interface WriteOptions {
  /** Stated authority level; defaults from the active signed grant when omitted. */
  authority?: "low" | "medium" | "high" | "canonical";
  /** Provenance source id; defaults from the active signed grant when omitted. */
  source?: string;
  validFrom?: Time;
  validTo?: Time;
  /** Retention TTL as a human duration (`90d`, `12h`). */
  ttl?: string;
}

/** Options accepted by the read verbs (time-travel clocks). */
export interface ReadOptions {
  asOf?: Time;
  validAt?: Time;
}

/** A failed dent8 operation: `status` says what happened, `code` says why. */
export class Dent8Error extends Error {
  readonly payload: Payload;
  readonly status: string;
  readonly code: string;

  constructor(payload: Payload) {
    const status = typeof payload.status === "string" ? payload.status : "failed";
    const code = typeof payload.code === "string" ? payload.code : "operation-failed";
    const message =
      typeof payload.message === "string"
        ? payload.message
        : typeof payload.error_reason === "string"
          ? payload.error_reason
          : "";
    super(`[${code}] ${message}`);
    this.name = new.target.name;
    this.payload = payload;
    this.status = status;
    this.code = code;
  }
}

/** The firewall (or a write-boundary gate) refused a well-formed request. */
export class Dent8Rejected extends Dent8Error {}

/** The request was malformed or the configuration unusable. */
export class Dent8Invalid extends Dent8Error {}

/** Constructor options for {@link Dent8}. */
export interface Dent8Options {
  /** Path to the `dent8` binary (default: `DENT8_BIN` env, else `dent8` on PATH). */
  binary?: string;
  /** Working directory for store discovery (default: the process cwd). */
  cwd?: string;
  /** Extra environment merged over `process.env`, e.g. `{ DENT8_LOG: "…" }`. */
  env?: Record<string, string>;
  /** Per-call subprocess timeout in milliseconds. */
  timeoutMs?: number;
}

/** A handle on the dent8 belief surface, one subprocess per call. */
export class Dent8 {
  readonly binary: string;
  private readonly cwd?: string;
  private readonly env: Record<string, string>;
  private readonly timeoutMs: number;

  constructor(options: Dent8Options = {}) {
    this.binary = options.binary ?? process.env.DENT8_BIN ?? "dent8";
    this.cwd = options.cwd;
    this.env = options.env ?? {};
    this.timeoutMs = options.timeoutMs ?? 60_000;
  }

  // ---- writes -----------------------------------------------------------------

  /** Assert a fact through the firewall. */
  assertFact(subject: string, predicate: string, value: string, options: WriteOptions = {}): Payload {
    return this.run(["assert", subject, predicate, value], options);
  }

  /** Revise the believed fact via the sanctioned supersession path. */
  supersede(subject: string, predicate: string, value: string, options: WriteOptions = {}): Payload {
    return this.run(["supersede", subject, predicate, value], options);
  }

  /** Record dissent: keep both facts, mark the pair contested. */
  contradict(subject: string, predicate: string, value: string, options: WriteOptions = {}): Payload {
    return this.run(["contradict", subject, predicate, value], options);
  }

  /** Retract the believed fact (terminal; taints derivatives). */
  retract(subject: string, predicate: string, options: WriteOptions = {}): Payload {
    return this.run(["retract", subject, predicate], options);
  }

  /** Corroborate the believed fact from another source (earned entrenchment). */
  reinforce(subject: string, predicate: string, options: WriteOptions = {}): Payload {
    return this.run(["reinforce", subject, predicate], options);
  }

  /** Expire the believed fact (terminal). */
  expire(subject: string, predicate: string, options: WriteOptions = {}): Payload {
    return this.run(["expire", subject, predicate], options);
  }

  /**
   * Assert a fact derived from `basis` (a `[subject, predicate]` pair), recording the
   * dependency edge — if the basis is later retracted, `verify` flags this derivative
   * as tainted.
   */
  derive(
    subject: string,
    predicate: string,
    value: string,
    options: WriteOptions & { basis: [string, string] },
  ): Payload {
    const { basis, ...write } = options;
    return this.run(["derive", subject, predicate, value, "--basis", basis[0], basis[1]], write);
  }

  // ---- reads / audit ----------------------------------------------------------

  /** The believed (or terminal) fact with its integrity receipt. */
  explain(subject: string, predicate: string, options: ReadOptions = {}): Payload {
    return this.run(["explain", subject, predicate], options);
  }

  /** The full event history behind a fact — why it is believed. */
  replay(subject: string, predicate: string, options: ReadOptions = {}): Payload {
    return this.run(["replay", subject, predicate], options);
  }

  /** Every known fact stream, with freshness flags. */
  facts(options: { includeDiagnostics?: boolean } = {}): Payload {
    const args = ["facts", "list"];
    if (options.includeDiagnostics) args.push("--include-diagnostics");
    return this.run(args, {});
  }

  /**
   * Integrity checks: hash chain, lineage, taint, attestations. Findings are a
   * *result*, not an exception: the payload's `status` is `ok` or
   * `integrity_issues` (mirroring the MCP tool). Only a malformed invocation throws.
   */
  verify(): Payload {
    try {
      return this.run(["verify"], {});
    } catch (error) {
      if (error instanceof Dent8Rejected) return error.payload;
      throw error;
    }
  }

  /** Contested facts: `status` is `contested` when disputes exist, `ok` otherwise. */
  conflicts(): Payload {
    return this.run(["conflicts"], {});
  }

  // ---- plumbing ---------------------------------------------------------------

  private run(args: string[], flags: object): Payload {
    const command = [...args];
    for (const [name, value] of Object.entries(flags as Record<string, unknown>)) {
      if (value === undefined || value === null) continue;
      command.push("--" + name.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase()));
      command.push(String(value));
    }
    const completed = spawnSync(this.binary, ["--output", "json", ...command], {
      encoding: "utf8",
      timeout: this.timeoutMs,
      cwd: this.cwd,
      env: { ...process.env, ...this.env },
    });
    if (completed.error) throw completed.error;
    const payload = this.parse(completed.stdout ?? "", completed.stderr ?? "", command);
    if (completed.status === 0) return payload;
    throw completed.status === 2 ? new Dent8Invalid(payload) : new Dent8Rejected(payload);
  }

  private parse(stdout: string, stderr: string, command: string[]): Payload {
    // The machine contract: every --output json result — success and error — is one
    // JSON object on stdout. Anything else (e.g. a clap usage error on stderr) is
    // surfaced as invalid with the raw text preserved.
    const text = stdout.trim();
    if (text) {
      try {
        const payload: unknown = JSON.parse(text);
        if (payload !== null && typeof payload === "object" && !Array.isArray(payload)) {
          return payload as Payload;
        }
      } catch {
        // fall through to the invalid wrapper
      }
    }
    throw new Dent8Invalid({
      status: "invalid",
      code: "invalid-argument",
      message: (stderr || stdout || "").trim() || `no JSON output from: dent8 ${command.join(" ")}`,
    });
  }
}
