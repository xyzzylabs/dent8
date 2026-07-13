#!/usr/bin/env python3
"""A LlamaIndex agent with dent8's belief surface as first-class tools.

Uses the native ``dent8.llamaindex`` adapter — LlamaIndex ``FunctionTool`` s built directly on
the ``dent8`` SDK, no MCP subprocess. The agent records and reads project facts *through the
firewall*: a write it is not authorized to make comes back as a tool result it can read and
adapt to, and it cannot pick its own authority (that is configuration, below).

Requires::

    pip install "dent8[llamaindex]" llama-index-llms-openai
    export OPENAI_API_KEY=...                   # any LlamaIndex-supported model works
    export DENT8_LOG=.dent8/agent-memory.jsonl  # or a DENT8_STORE_URL backend
    # a signing identity so above-agent writes are accepted (see note below), and the
    # `dent8` binary on PATH (cargo install dent8-cli --locked)

Run::

    python dent8_tools_agent.py

Note: the agent below writes at ``authority="low"`` (the agent tier), which needs no signed
identity. If you raise it to ``"high"``, provision one first — ``dent8 init --source
source:agent`` and load ``.dent8/env`` — since above-agent writes must be signed.
"""

from __future__ import annotations

import asyncio

from dent8.llamaindex import dent8_tools
from llama_index.core.agent.workflow import FunctionAgent
from llama_index.llms.openai import OpenAI

# The agent writes as a *low-authority* source: it can propose facts, but the firewall will
# not let it override a human- or CI-asserted one. source/authority are set here, not chosen
# by the model — that is the point.
tools = dent8_tools(source="source:agent", authority="low")

agent = FunctionAgent(
    tools=tools,
    llm=OpenAI(model="gpt-4o-mini"),
    system_prompt="You record and read project facts through the dent8 memory firewall.",
)


async def main() -> None:
    response = await agent.run(
        "Record that repo:myproj uses postgres as its database, then read it back and tell me "
        "why it is believed."
    )
    print(response)


if __name__ == "__main__":
    asyncio.run(main())
