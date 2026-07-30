"""First-class LlamaIndex tools over the dent8 memory firewall.

Unlike wiring dent8 in over MCP, these are **native LlamaIndex tools** built directly on the
:class:`dent8.Dent8` SDK — no MCP subprocess client to keep in sync, typed arguments, and
firewall refusals surfaced to the agent *as tool results* so it learns and adapts instead of
overwriting.

    from dent8.llamaindex import dent8_tools
    from llama_index.core.agent import FunctionAgent
    from llama_index.llms.openai import OpenAI

    tools = dent8_tools(source="source:agent", authority="low")
    agent = FunctionAgent(tools=tools, llm=OpenAI(model="gpt-4o"))

Install with the extra: ``pip install "dent8[llamaindex]"`` (adds ``llama-index-core``).

**Design — the agent cannot escalate its own authority.** The tools expose *what* to record
(subject, predicate, value); the *source* and *authority* a write carries are deployment
configuration passed to :func:`dent8_tools`, never LLM-chosen arguments. An agent wired at
``authority="low"`` can propose facts but cannot override a human's — dent8's whole thesis,
applied at the tool boundary. (Omit them to let a configured signed grant supply the identity
instead.)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import Dent8, Dent8Error

__all__ = ["dent8_tools"]


def _describe(payload: Dict[str, Any]) -> str:
    """A compact one-line summary of a receipt/explain payload, defensive about the exact
    shape (assert, supersede and explain nest the value slightly differently)."""
    subject = payload.get("subject")
    who = (
        f"{subject.get('kind', '?')}:{subject.get('key', '?')}"
        if isinstance(subject, dict)
        else "?"
    )
    value = payload.get("value") or payload.get("current_value") or {}
    text = value.get("text") if isinstance(value, dict) else value
    parts = [f"{who} {payload.get('predicate', '?')}"]
    if text is not None:
        parts.append(f'= "{text}"')
    for key in ("authority", "lifecycle", "status"):
        if payload.get(key):
            parts.append(f"{key}={payload[key]}")
    return " ".join(str(part) for part in parts)


def dent8_tools(
    client: Optional[Dent8] = None,
    *,
    source: Optional[str] = None,
    authority: Optional[str] = None,
    binary: Optional[str] = None,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
) -> List[Any]:
    """Build the dent8 belief-surface tools for a LlamaIndex agent.

    :param client: a configured :class:`dent8.Dent8`; if omitted one is built from
        ``binary`` / ``cwd`` / ``env``.
    :param source: the source id every write from these tools carries (e.g.
        ``"source:agent"``). ``None`` defers to a configured signed grant.
    :param authority: the authority every write carries (``"low"`` / ``"medium"`` /
        ``"high"`` / ``"canonical"``). ``None`` defers to the grant. Deliberately not an LLM
        argument — the agent cannot pick its own authority.
    :returns: a list of ``llama_index.core.tools`` ``FunctionTool`` s:
        ``dent8_record_fact`` / ``dent8_revise_fact`` / ``dent8_dispute_fact`` /
        ``dent8_explain_fact`` / ``dent8_list_facts`` / ``dent8_verify``.
    """
    try:
        from llama_index.core.tools import FunctionTool
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(
            "dent8.llamaindex needs llama-index-core; install with: "
            "pip install 'dent8[llamaindex]'"
        ) from exc

    dent8 = client if client is not None else Dent8(binary=binary, cwd=cwd, env=env)

    def record_fact(subject: str, predicate: str, value: str) -> str:
        """Record a new project fact through the dent8 firewall. `subject` is `<kind>:<key>`
        (e.g. `repo:myproj`), `predicate` is the attribute (e.g. `deploy_target`), `value` is
        the fact. The firewall may refuse the write (it will not let it override a
        higher-authority fact, or create a duplicate of a unique one); the refusal is returned
        so you can adapt rather than overwrite."""
        try:
            return "recorded: " + _describe(
                dent8.assert_fact(subject, predicate, value, source=source, authority=authority)
            )
        except Dent8Error as error:
            return f"refused by the firewall: {error}"

    def revise_fact(subject: str, predicate: str, value: str) -> str:
        """Revise the believed fact for a subject+predicate via the sanctioned supersession
        path. Refused if your write cannot out-rank the current incumbent — that refusal is
        the point, so read it rather than retrying."""
        try:
            return "revised: " + _describe(
                dent8.supersede(subject, predicate, value, source=source, authority=authority)
            )
        except Dent8Error as error:
            return f"refused by the firewall: {error}"

    def dispute_fact(subject: str, predicate: str, value: str) -> str:
        """Dispute the believed fact: record dissent as a contested pair (both values kept,
        nothing overwritten) instead of silently overriding what is believed."""
        try:
            return "disputed (kept as a contested pair): " + _describe(
                dent8.contradict(subject, predicate, value, source=source, authority=authority)
            )
        except Dent8Error as error:
            return f"could not record the dispute: {error}"

    def explain_fact(subject: str, predicate: str) -> str:
        """Explain the believed fact for a subject+predicate: its value, authority, freshness,
        and lifecycle — why it is believed. Use this before acting on remembered context."""
        try:
            return _describe(dent8.explain(subject, predicate))
        except Dent8Error as error:
            return f"no believed fact for {subject} {predicate}: {error}"

    def list_facts() -> str:
        """List every known fact stream (subject + predicate) with its freshness flag."""
        try:
            payload = dent8.facts()
        except Dent8Error as error:
            return f"could not read the fact list: {error}"
        rows = payload.get("facts", [])
        if not rows:
            return "no facts recorded yet"
        return "; ".join(
            f"{row['subject']['kind']}:{row['subject']['key']} {row['predicate']}"
            f" ({row.get('freshness', '?')})"
            for row in rows
        )

    def verify_integrity() -> str:
        """Verify store integrity: the hash chain, lineage, and retraction taint. Returns the
        status and any findings."""
        try:
            payload = dent8.verify()
        except Dent8Error as error:
            return f"could not verify the store: {error}"
        summary = payload.get("report") or payload.get("summary") or ""
        return f"status={payload.get('status', '?')}; {summary}".strip()

    return [
        FunctionTool.from_defaults(fn=record_fact, name="dent8_record_fact"),
        FunctionTool.from_defaults(fn=revise_fact, name="dent8_revise_fact"),
        FunctionTool.from_defaults(fn=dispute_fact, name="dent8_dispute_fact"),
        FunctionTool.from_defaults(fn=explain_fact, name="dent8_explain_fact"),
        FunctionTool.from_defaults(fn=list_facts, name="dent8_list_facts"),
        FunctionTool.from_defaults(fn=verify_integrity, name="dent8_verify"),
    ]
