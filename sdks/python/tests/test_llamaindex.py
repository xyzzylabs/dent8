"""Tests for the first-class LlamaIndex adapter (`dent8.llamaindex`).

Runs against the real `dent8` binary (like test_client.py) and needs `llama-index-core`
(the `dent8[llamaindex]` extra); skips cleanly when either is absent.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

pytest.importorskip("llama_index.core", reason="install dent8[llamaindex]")

from dent8 import Dent8  # noqa: E402
from dent8.llamaindex import dent8_tools  # noqa: E402

BINARY = os.environ.get("DENT8_BIN") or shutil.which("dent8")

pytestmark = pytest.mark.skipif(
    BINARY is None, reason="no dent8 binary (set DENT8_BIN or install dent8-cli)"
)


def _signing_env(dirpath, source):
    """Bootstrap a self-contained signed identity authorizing ``source`` (a ``source:*`` id) up
    to Canonical under ``dirpath``, returning the DENT8_* signing vars. Above-agent authority now
    requires a valid signed identity; a plain agent-tier client omits these."""
    slug = re.sub(r"[^A-Za-z0-9._-]", "_", source)
    bundle = dirpath / f"id-{slug}"
    subprocess.run(
        [
            BINARY, "identity", "bootstrap",
            "--dir", str(bundle),
            "--source", source,
            "--max", "canonical",
            "--issuer-key", str(dirpath / f"issuer-{slug}.key"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        "DENT8_TRUST": str(bundle / "trust.json"),
        "DENT8_GRANT": str(bundle / "grants" / f"{slug}.grant.json"),
        "DENT8_IDENTITY_KEY": str(bundle / "identities" / f"{slug}.key"),
        "DENT8_ACTIVE_GRANTS": str(bundle / "active-grants.json"),
        "DENT8_REQUIRE_IDENTITY": "1",
    }


class Store:
    """A throwaway store: ``signed(source)`` signs above-agent writes as that ``source:*``
    identity; ``plain()`` is an unsigned agent-tier client on the same store."""

    def __init__(self, dirpath):
        self.dir = dirpath
        self.base = {
            "DENT8_LOG": str(dirpath / "memory.jsonl"),
            "DENT8_AUTHORITY": str(dirpath / "authority.json"),
        }

    def plain(self):
        return Dent8(binary=BINARY, cwd=str(self.dir), env=dict(self.base))

    def signed(self, source):
        env = dict(self.base)
        env.update(_signing_env(self.dir, source))
        return Dent8(binary=BINARY, cwd=str(self.dir), env=env)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("DENT8_"):
            monkeypatch.delenv(key)
    return Store(tmp_path)


def _by_name(client, **kwargs):
    return {tool.metadata.name: tool for tool in dent8_tools(client=client, **kwargs)}


def _run(tool, **kwargs) -> str:
    """Invoke a FunctionTool and return its string result (ToolOutput → str)."""
    return str(tool.call(**kwargs))


def test_tools_cover_the_belief_surface(store):
    names = set(_by_name(store.plain(), source="source:agent", authority="low"))
    assert {
        "dent8_record_fact",
        "dent8_revise_fact",
        "dent8_dispute_fact",
        "dent8_explain_fact",
        "dent8_list_facts",
        "dent8_verify",
    } <= names


def test_record_then_explain_round_trips(store):
    # `repo.database` is High-floored, so the record is an above-agent signed write as `source:alice`.
    client = store.signed("source:alice")
    tools = _by_name(client, source="source:alice", authority="high")
    recorded = _run(
        tools["dent8_record_fact"], subject="repo:myproj", predicate="database", value="postgres"
    )
    assert "recorded" in recorded and "postgres" in recorded
    explained = _run(tools["dent8_explain_fact"], subject="repo:myproj", predicate="database")
    assert "postgres" in explained


def test_low_authority_revision_comes_back_as_a_refusal_not_an_exception(store):
    # A signed human records the fact...
    human = _by_name(store.signed("source:alice"), source="source:alice", authority="high")
    _run(human["dent8_record_fact"], subject="repo:myproj", predicate="database", value="postgres")
    # ...a low-authority agent tries to revise it down. The firewall's refusal is returned as a
    # normal tool result the agent can read, not raised — and the human fact stands.
    agent = _by_name(store.plain(), source="web:scrape", authority="low")
    refusal = _run(
        agent["dent8_revise_fact"], subject="repo:myproj", predicate="database", value="mysql"
    )
    assert "refused" in refusal.lower()
    assert "postgres" in _run(
        agent["dent8_explain_fact"], subject="repo:myproj", predicate="database"
    )


def test_the_agent_tools_do_not_expose_source_or_authority(store):
    # An LLM must not be able to pick its own authority: those are `dent8_tools` config, not
    # tool arguments the model fills in.
    record = _by_name(store.plain(), source="source:agent", authority="low")["dent8_record_fact"]
    params = set(record.metadata.get_parameters_dict().get("properties", {}))
    assert params == {"subject", "predicate", "value"}
