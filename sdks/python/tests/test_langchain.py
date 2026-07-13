"""Tests for the first-class LangChain adapter (`dent8.langchain`).

Runs against the real `dent8` binary (like test_client.py) and needs `langchain-core`
(the `dent8[langchain]` extra); skips cleanly when either is absent.
"""

from __future__ import annotations

import os
import shutil

import pytest

pytest.importorskip("langchain_core", reason="install dent8[langchain]")

from dent8 import Dent8  # noqa: E402
from dent8.langchain import dent8_tools  # noqa: E402

BINARY = os.environ.get("DENT8_BIN") or shutil.which("dent8")

pytestmark = pytest.mark.skipif(
    BINARY is None, reason="no dent8 binary (set DENT8_BIN or install dent8-cli)"
)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("DENT8_"):
            monkeypatch.delenv(key)
    env = {
        "DENT8_LOG": str(tmp_path / "memory.jsonl"),
        "DENT8_AUTHORITY": str(tmp_path / "authority.json"),
    }
    return Dent8(binary=BINARY, cwd=str(tmp_path), env=env)


def _by_name(client, **kwargs):
    return {tool.name: tool for tool in dent8_tools(client=client, **kwargs)}


def test_tools_cover_the_belief_surface(client):
    names = set(_by_name(client, source="user:alice", authority="high"))
    assert {
        "dent8_record_fact",
        "dent8_revise_fact",
        "dent8_dispute_fact",
        "dent8_explain_fact",
        "dent8_list_facts",
        "dent8_verify",
    } <= names


def test_record_then_explain_round_trips(client):
    tools = _by_name(client, source="user:alice", authority="high")
    recorded = tools["dent8_record_fact"].invoke(
        {"subject": "repo:myproj", "predicate": "database", "value": "postgres"}
    )
    assert "recorded" in recorded and "postgres" in recorded
    explained = tools["dent8_explain_fact"].invoke(
        {"subject": "repo:myproj", "predicate": "database"}
    )
    assert "postgres" in explained


def test_low_authority_revision_comes_back_as_a_refusal_not_an_exception(client):
    # A human records the fact...
    _by_name(client, source="user:alice", authority="high")["dent8_record_fact"].invoke(
        {"subject": "repo:myproj", "predicate": "database", "value": "postgres"}
    )
    # ...a low-authority agent tries to revise it down. The firewall's refusal is returned
    # as a normal tool result the agent can read, not raised — and the human fact stands.
    agent = _by_name(client, source="web:scrape", authority="low")
    refusal = agent["dent8_revise_fact"].invoke(
        {"subject": "repo:myproj", "predicate": "database", "value": "mysql"}
    )
    assert "refused" in refusal.lower()
    assert "postgres" in agent["dent8_explain_fact"].invoke(
        {"subject": "repo:myproj", "predicate": "database"}
    )


def test_the_agent_tools_do_not_expose_source_or_authority(client):
    # An LLM must not be able to pick its own authority: those are `dent8_tools` config, not
    # tool arguments the model fills in.
    record = _by_name(client, source="source:agent", authority="low")["dent8_record_fact"]
    assert set(record.args) == {"subject", "predicate", "value"}
