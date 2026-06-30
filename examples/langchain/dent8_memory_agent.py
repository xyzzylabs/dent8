#!/usr/bin/env python3
"""Use dent8 as a LangChain agent's memory firewall, over MCP.

dent8 exposes its full belief surface (assert / supersede / retract / verify /
conflicts / list_facts / ...) as MCP tools via ``dent8 mcp serve``. This wires that
server into a LangGraph ReAct agent with ``langchain-mcp-adapters``, so the agent
records and reads project facts *through the firewall*: a low-authority or stale
write is rejected, contradictions surface, and every fact is replayable.

Requires::

    pip install langchain-mcp-adapters langgraph "langchain[openai]"
    export OPENAI_API_KEY=...          # any LangChain-supported model works
    # the `dent8` binary on PATH (e.g. cargo install --path crates/dent8-cli)

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
    # instead for an operational postgres://… / sqlite://… backend. The env dict
    # replaces the child environment, so merge os.environ to keep PATH et al.
    client = MultiServerMCPClient(
        {
            "dent8": {
                "command": "dent8",
                "args": ["mcp", "serve"],
                "transport": "stdio",
                "env": {**os.environ, "DENT8_LOG": os.path.abspath("agent-memory.jsonl")},
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
                        "predicate database, authority high, source owner) through dent8, then "
                        "run a dent8 verify and tell me the integrity result."
                    ),
                }
            ]
        }
    )
    print(result["messages"][-1].content)


if __name__ == "__main__":
    asyncio.run(main())
