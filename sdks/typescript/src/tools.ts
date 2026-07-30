/**
 * Framework-agnostic dent8 belief-surface tools.
 *
 * This module holds the actual logic — the six tools, their JSON-Schema inputs, and the
 * rule that a firewall refusal is surfaced *as a result* rather than thrown — with **zero
 * dependencies**. The thin per-framework adapters ({@link ./ai | `dent8/ai`} for the Vercel
 * AI SDK, {@link ./langchain | `dent8/langchain`} for LangChain.js) are ~20 lines each that
 * wrap these specs in the framework's tool object. Bring your own framework by doing the
 * same over {@link dent8ToolSpecs}.
 *
 * **Design — the agent cannot escalate its own authority.** The tools expose *what* to record
 * (subject, predicate, value); the *source* and *authority* a write carries are deployment
 * configuration passed to {@link dent8ToolSpecs}, never LLM-chosen arguments. An agent wired
 * at `authority: "low"` can propose facts but cannot override a human's — dent8's whole
 * thesis, applied at the tool boundary. (Omit them to let a configured signed grant supply
 * the identity instead.)
 */

import { Dent8, Dent8Invalid, Dent8Rejected, type Payload } from "./index.js";

/** Options shared by every framework adapter. */
export interface Dent8ToolsOptions {
  /** A configured {@link Dent8}; if omitted one is built from `binary` / `cwd` / `env`. */
  client?: Dent8;
  /**
   * The source id every write from these tools carries (e.g. `"source:agent"`).
   * `undefined` defers to a configured signed grant.
   */
  source?: string;
  /**
   * The authority every write carries (`"low"` | `"medium"` | `"high"` | `"canonical"`).
   * `undefined` defers to the grant. Deliberately **not** an LLM argument — the agent
   * cannot pick its own authority.
   */
  authority?: "low" | "medium" | "high" | "canonical";
  binary?: string;
  cwd?: string;
  env?: Record<string, string>;
}

/** A minimal JSON Schema for a tool's arguments (object of string properties). */
export interface ToolInputSchema {
  type: "object";
  properties: Record<string, { type: "string"; description: string }>;
  required: string[];
  additionalProperties: false;
}

/**
 * One dent8 tool, described independently of any agent framework: a name, an LLM-facing
 * description, a JSON-Schema for its arguments, and an `execute` that runs the operation and
 * returns a compact string the model reads back (including firewall refusals).
 */
export interface Dent8ToolSpec {
  name: string;
  description: string;
  inputSchema: ToolInputSchema;
  execute(args: Record<string, unknown>): string;
}

const str = (description: string) => ({ type: "string" as const, description });

const schema = (
  properties: Record<string, { type: "string"; description: string }>,
): ToolInputSchema => ({
  type: "object",
  properties,
  required: Object.keys(properties),
  additionalProperties: false,
});

/**
 * A compact one-line summary of a receipt / explain payload, defensive about the exact shape
 * (assert, supersede and explain nest the value slightly differently).
 */
export function describeReceipt(payload: Payload): string {
  const subject = payload.subject;
  const who =
    subject && typeof subject === "object"
      ? `${(subject as Record<string, unknown>).kind ?? "?"}:${(subject as Record<string, unknown>).key ?? "?"}`
      : "?";
  const rawValue = payload.value ?? payload.current_value ?? {};
  const text =
    rawValue && typeof rawValue === "object"
      ? (rawValue as Record<string, unknown>).text
      : rawValue;
  const parts: string[] = [`${who} ${payload.predicate ?? "?"}`];
  if (text !== undefined && text !== null) parts.push(`= "${text}"`);
  for (const key of ["authority", "lifecycle", "status"] as const) {
    if (payload[key]) parts.push(`${key}=${String(payload[key])}`);
  }
  return parts.join(" ");
}

const asString = (args: Record<string, unknown>, key: string): string => String(args[key] ?? "");

/**
 * Report a failed operation back to the model as a tool result. Only a firewall refusal is
 * described as one (`refusal` is the tool's own wording); a malformed request is the model's
 * own argument bug, and saying "refused" there would teach it the wrong lesson. Anything that
 * is not a dent8 error (a missing binary, a timeout) still throws.
 */
function describeFailure(error: unknown, refusal: string): string {
  if (error instanceof Dent8Rejected) return `${refusal}: ${error.message}`;
  if (error instanceof Dent8Invalid) {
    return `invalid arguments: ${error.message} — fix the subject/predicate/value format and retry`;
  }
  throw error;
}

/**
 * Build the dent8 belief-surface tool specs. The per-framework adapters call this and wrap
 * each spec; call it yourself to target a framework there's no adapter for yet.
 *
 * @returns six specs — `dent8_record_fact`, `dent8_revise_fact`, `dent8_dispute_fact`,
 *   `dent8_explain_fact`, `dent8_list_facts`, `dent8_verify`.
 */
export function dent8ToolSpecs(options: Dent8ToolsOptions = {}): Dent8ToolSpec[] {
  const { client, source, authority, binary, cwd, env } = options;
  const d8 = client ?? new Dent8({ binary, cwd, env });
  const write = { source, authority };

  const record: Dent8ToolSpec = {
    name: "dent8_record_fact",
    description:
      "Record a new project fact through the dent8 firewall. `subject` is `<kind>:<key>` " +
      "(e.g. `repo:myproj`), `predicate` is the attribute (e.g. `deploy_target`), `value` is " +
      "the fact. The firewall may refuse the write (it will not let it override a " +
      "higher-authority fact, or create a duplicate of a unique one); the refusal is returned " +
      "so you can adapt rather than overwrite.",
    inputSchema: schema({
      subject: str("The fact's subject as `<kind>:<key>`, e.g. `repo:myproj`."),
      predicate: str("The attribute being recorded, e.g. `deploy_target`."),
      value: str("The value to record for this subject+predicate."),
    }),
    execute: (args) => {
      try {
        return (
          "recorded: " +
          describeReceipt(
            d8.assertFact(asString(args, "subject"), asString(args, "predicate"), asString(args, "value"), write),
          )
        );
      } catch (error) {
        return describeFailure(error, "refused by the firewall");
      }
    },
  };

  const revise: Dent8ToolSpec = {
    name: "dent8_revise_fact",
    description:
      "Revise the believed fact for a subject+predicate via the sanctioned supersession path. " +
      "Refused if your write cannot out-rank the current incumbent — that refusal is the " +
      "point, so read it rather than retrying.",
    inputSchema: schema({
      subject: str("The fact's subject as `<kind>:<key>`."),
      predicate: str("The attribute to revise."),
      value: str("The new value that should supersede the incumbent."),
    }),
    execute: (args) => {
      try {
        return (
          "revised: " +
          describeReceipt(
            d8.supersede(asString(args, "subject"), asString(args, "predicate"), asString(args, "value"), write),
          )
        );
      } catch (error) {
        return describeFailure(error, "refused by the firewall");
      }
    },
  };

  const dispute: Dent8ToolSpec = {
    name: "dent8_dispute_fact",
    description:
      "Dispute the believed fact: record dissent as a contested pair (both values kept, " +
      "nothing overwritten) instead of silently overriding what is believed.",
    inputSchema: schema({
      subject: str("The fact's subject as `<kind>:<key>`."),
      predicate: str("The attribute in dispute."),
      value: str("The competing value to record alongside the incumbent."),
    }),
    execute: (args) => {
      try {
        return (
          "disputed (kept as a contested pair): " +
          describeReceipt(
            d8.contradict(asString(args, "subject"), asString(args, "predicate"), asString(args, "value"), write),
          )
        );
      } catch (error) {
        return describeFailure(error, "could not record the dispute");
      }
    },
  };

  const explain: Dent8ToolSpec = {
    name: "dent8_explain_fact",
    description:
      "Explain the believed fact for a subject+predicate: its value, authority, freshness, " +
      "and lifecycle — why it is believed. Use this before acting on remembered context.",
    inputSchema: schema({
      subject: str("The fact's subject as `<kind>:<key>`."),
      predicate: str("The attribute to explain."),
    }),
    execute: (args) => {
      try {
        return describeReceipt(d8.explain(asString(args, "subject"), asString(args, "predicate")));
      } catch (error) {
        return describeFailure(
          error,
          `no believed fact for ${asString(args, "subject")} ${asString(args, "predicate")}`,
        );
      }
    },
  };

  const list: Dent8ToolSpec = {
    name: "dent8_list_facts",
    description: "List every known fact stream (subject + predicate) with its freshness flag.",
    inputSchema: schema({}),
    execute: () => {
      const payload = d8.facts();
      const rows = Array.isArray(payload.facts) ? (payload.facts as Record<string, unknown>[]) : [];
      if (rows.length === 0) return "no facts recorded yet";
      return rows
        .map((row) => {
          const subject = (row.subject ?? {}) as Record<string, unknown>;
          return `${subject.kind ?? "?"}:${subject.key ?? "?"} ${row.predicate ?? "?"} (${row.freshness ?? "?"})`;
        })
        .join("; ");
    },
  };

  const verify: Dent8ToolSpec = {
    name: "dent8_verify",
    description:
      "Verify store integrity: the hash chain, lineage, and retraction taint. Returns the " +
      "status and any findings.",
    inputSchema: schema({}),
    execute: () => {
      const payload = d8.verify();
      const summary = payload.report ?? payload.summary ?? "";
      return `status=${payload.status ?? "?"}; ${String(summary)}`.trim();
    },
  };

  return [record, revise, dispute, explain, list, verify];
}
