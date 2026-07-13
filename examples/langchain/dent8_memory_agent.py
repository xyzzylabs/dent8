#!/usr/bin/env python3
"""Use dent8 as a LangChain agent's memory firewall, over MCP.

dent8 exposes its full belief surface (assert / supersede / retract / verify /
runtime_status / conflicts / list_facts / ...) as MCP tools via ``dent8 mcp serve``.
This wires that server into a LangGraph ReAct agent with ``langchain-mcp-adapters``, so the agent
records and reads project facts *through the firewall*: a low-authority or stale
write is rejected, contradictions surface, and every fact is replayable.

Requires::

    pip install langchain-mcp-adapters langgraph "langchain[openai]"
    export OPENAI_API_KEY=...          # any LangChain-supported model works
    # the `dent8` binary on PATH (e.g. cargo install dent8-cli --locked)

Run::

    python dent8_memory_agent.py

Note: MCP-client APIs move fast. If ``MultiServerMCPClient`` / ``get_tools()`` has
shifted, check the langchain-mcp-adapters README — the dent8 side (``dent8 mcp
serve``) is stable.
"""

from __future__ import annotations

import asyncio
import os

from langchain_mcp_adapters.client import MultiServerMCPClient
from langgraph.prebuilt import create_react_agent


async def main() -> None:
    # Spawn `dent8 mcp serve` (stdio JSON-RPC) and expose its tools to LangChain.
    # DENT8_LOG points the firewall at this agent's memory log; set DENT8_STORE_URL
    # instead for an operational postgres://… / sqlite://… backend. The signed-identity
    # vars carry the source grant this server writes under — v0.8.0 rejects any write above
    # the agent tier without one, so the high-authority write below needs it. Provision the
    # bundle once with `dent8 init --identity --source source:langchain` (see README). The env
    # dict replaces the child environment, so merge os.environ to keep PATH et al.
    def _abs(path: str) -> str:
        return os.path.abspath(path)

    env = {
        **os.environ,
        "DENT8_LOG": _abs("agent-memory.jsonl"),
        "DENT8_AUTHORITY": os.environ.get("DENT8_AUTHORITY", _abs(".dent8/authority.json")),
        "DENT8_REQUIRE_AUTHORITY": os.environ.get("DENT8_REQUIRE_AUTHORITY", "1"),
        "DENT8_TRUST": os.environ.get("DENT8_TRUST", _abs(".dent8/trust.json")),
        "DENT8_REQUIRE_IDENTITY": os.environ.get("DENT8_REQUIRE_IDENTITY", "1"),
        "DENT8_GRANT": os.environ.get(
            "DENT8_GRANT", _abs(".dent8/grants/source_langchain.grant.json")
        ),
        "DENT8_IDENTITY_KEY": os.environ.get(
            "DENT8_IDENTITY_KEY", _abs(".dent8/identities/source_langchain.key")
        ),
    }
    client = MultiServerMCPClient(
        {
            "dent8": {
                "command": "dent8",
                "args": ["mcp", "serve"],
                "transport": "stdio",
                "env": env,
            }
        }
    )
    tools = await client.get_tools()
    print(f"dent8 exposed {len(tools)} firewall tools: {[tool.name for tool in tools]}")

    agent = create_react_agent("openai:gpt-4o-mini", tools)

    # The agent records a fact through the firewall, then verifies integrity. A later
    # low-authority attempt to change it would be *rejected* by dent8, surfaced to the
    # model as a tool error with the reason — not silently applied.
    result = await agent.ainvoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Record that this repo's database is postgres (subject repo:myproj, "
                        "predicate database, authority high, source source:langchain) through "
                        "dent8, then run a dent8 verify and tell me the integrity result."
                    ),
                }
            ]
        }
    )
    print(result["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main())
