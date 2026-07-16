# ADR 0021 - LLM verifier adapters are optional signals, not authority

Date: 2026-07-16

## Status

**Accepted.** LLM-as-verifier systems are useful around dent8, but not inside dent8's
deterministic integrity core.

This ADR is motivated by *LLM-as-a-Verifier: A General-Purpose Verification Framework*
([arXiv:2607.05391v2](https://arxiv.org/abs/2607.05391v2)), which frames verification as a
scaling axis for agentic tasks. The paper reports a probabilistic verifier that uses
scoring-token distributions, repeated evaluation, and criteria decomposition to produce
fine-grained scores; it also treats those signals as a task-progress proxy and demonstrates
a Claude Code extension.

## Context

dent8's current differentiator is deterministic memory integrity:

- all writes flow through the same authority/identity/content-check boundary;
- accepted events are append-only, hash chained, signed/attested, replayable, and explainable;
- authority is explicit entrenchment, not model confidence;
- content scanners are pluggable adapters, not built-in truth oracles.

LLM verifiers can help with areas dent8 deliberately does not solve by itself:

- deciding whether free text is suspicious, unsupported, or overgeneralized;
- scoring an agent trajectory against task-specific criteria;
- estimating whether a long-running agent is making progress;
- judging A/B eval runs where dent8 is enabled vs disabled.

But an LLM verifier is probabilistic and provider-shaped. Some verifier designs depend on
token-logit access, which is not uniformly available across frontier APIs, and their outputs
can drift with model, prompt, temperature, and provider changes. Treating such a signal as
the source of authority would collapse dent8 back into "the model says so."

## Decision

Support LLM verifiers only as **optional adapters** around the integrity boundary:

1. **Eval adapter.** A gated, non-default eval lane may use an LLM verifier to score complete
   agent trajectories or dent8-vs-baseline runs. It must report model/prompt/version metadata
   and stay out of hermetic CI unless frozen through fixtures or a deterministic mock.
2. **Content-check adapter.** A verifier may implement the existing
   `dent8.content-check/1` protocol and map its judgment to `allow`, `reject`, or `taint`.
   That keeps the verifier behind the same fail-closed subprocess contract as any other
   scanner.
3. **Debugger signal.** A future debugger may display verifier scores or progress estimates
   beside dent8 receipts, reads, writes, and replay timelines. These are annotations for
   humans and agents, not stored truth.
4. **Proposal-review signal.** A future proposal reviewer may attach verifier output as
   evidence or a content flag. It may not mint higher authority, bypass source ceilings, or
   silently supersede an incumbent fact.

LLM-verifier output can influence policy only through existing typed outcomes: reject a
candidate before persistence, taint an admitted fact, emit eval metrics, or annotate a UI.
It does **not** become authority, canonicality, proof of provenance, or a write-path bypass.

## Consequences

- dent8 can benefit from fast-moving verifier research without making its core correctness
  model depend on a model judge.
- External verifier quality is measurable in a separate lane, while the built-in evals remain
  deterministic and reproducible.
- The existing content-check hook is the correct first integration point; no new write-path
  mechanism is needed.
- The debugger can show "this run may be drifting" without asserting that the verifier is
  ground truth.
- Provider-specific capabilities, especially logit access, stay adapter details.

## Non-goals

- No LLM verifier in the core fold, hash chain, authority calculation, or storage adapter.
- No model score may raise a source's authority ceiling or turn a fact canonical.
- No mandatory hosted verifier dependency for normal CLI/MCP use.
- No claim that verifier scores are formal proofs.
- No training or fine-tuning direction implied by this ADR.

## Implementation notes

The first useful implementation should be small:

1. an example verifier scanner that speaks `dent8.content-check/1` and returns `taint` by
   default for low-confidence findings;
2. an optional eval harness that records `(model, prompt, criteria, score, verdict)` beside
   deterministic dent8 outcomes;
3. a debugger read-only overlay that can display verifier annotations without writing them
   unless the user explicitly stores them as ordinary evidence.

Any persisted verifier output must be auditable like every other fact-adjacent signal:
source, model/provider, prompt or criteria identifier, timestamp, and raw/normalized score
shape must be visible in replay or explain output.
