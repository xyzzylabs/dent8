#!/usr/bin/env python3
"""A LangChain agent with dent8's belief surface as first-class tools.

Unlike ``dent8_memory_agent.py`` (which wires dent8 in over MCP), this uses the native
``dent8.langchain`` adapter — LangChain ``StructuredTool`` s built directly on the ``dent8``
SDK, no MCP subprocess. The agent records and reads project facts *through the firewall*: a
write it is not authorized to make comes back as a tool result it can read and adapt to, and
it cannot pick its own authority (that is configuration, below).

Requires::

    pip install "dent8[langchain]" langgraph "langchain[openai]"
    export OPENAI_API_KEY=...             # any LangChain-supported model works
    export DENT8_LOG=/tmp/agent-memory.jsonl   # or a DENT8_STORE_URL backend
    # the `dent8` binary on PATH (cargo install dent8-cli --locked)

Run::

    python dent8_tools_agent.py
"""

from __future__ import annotations

from dent8.langchain import dent8_tools
from langgraph.prebuilt import create_react_agent

# The agent writes as a *low-authority* source: it can propose facts, but the firewall will
# not let it override a human- or CI-asserted one. source/authority are set here, not chosen
# by the model — that is the point.
tools = dent8_tools(source="source:agent", authority="low")

agent = create_react_agent("openai:gpt-4o-mini", tools)


def main() -> None:
    result = agent.invoke(
        {
            "messages": [
                (
                    "user",
                    "Record that repo:myproj uses postgres as its database, then read it "
                    "back and tell me why it is believed.",
                )
            ]
        }
    )
    print(result["messages"][-1].content)


if __name__ == "__main__":
    main()
