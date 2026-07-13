"""End-to-end tests against the real dent8 binary (the SDK is a thin wrapper, so the
binary IS the unit under test). Point DENT8_BIN at a built binary, or have `dent8` on
PATH; the suite skips cleanly otherwise:

    cargo build -p dent8-cli
    DENT8_BIN=../../target/debug/dent8 python -m pytest
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

from dent8 import SCHEMA_VERSION, Dent8, Dent8Invalid, Dent8Rejected

BINARY = os.environ.get("DENT8_BIN") or shutil.which("dent8")

pytestmark = pytest.mark.skipif(
    BINARY is None, reason="no dent8 binary (set DENT8_BIN or install dent8-cli)"
)


def _signing_env(dirpath, source):
    """Bootstrap a self-contained signed identity authorizing ``source`` (a ``source:*`` id)
    up to Canonical in its own bundle under ``dirpath``, and return the DENT8_* signing vars.
    Above-agent authority (medium/high/canonical) now requires a valid signed identity, so a
    client that makes such a write threads these in; a plain (agent-tier) client omits them so
    the firewall's authority arbitration — not the identity gate — judges its low writes."""
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
    """A throwaway store in permissive dev mode. ``signed(source)`` returns a client that signs
    above-agent writes as that ``source:*`` identity; ``plain()`` returns an unsigned agent-tier
    client on the same store."""

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
    """A throwaway store: every ambient DENT8_* variable is scrubbed (the developer's own shell
    may carry a dogfood store with identity enforcement), then the store paths are pinned to the
    tmp dir."""
    for key in list(os.environ):
        if key.startswith("DENT8_"):
            monkeypatch.delenv(key)
    return Store(tmp_path)


def test_assert_explain_round_trip(store):
    # `repo.database` has a High authority floor, so the assertion is an above-agent write — it
    # must be signed. Signed identities are `source:*`-scoped, so the writer is `source:alice`.
    d8 = store.signed("source:alice")
    written = d8.assert_fact(
        "repo:myproj", "database", "postgres", authority="high", source="source:alice"
    )
    assert written["schema_version"] == SCHEMA_VERSION
    assert written["status"] == "accepted"
    assert written["accepted"] is True

    fact = d8.explain("repo:myproj", "database")
    assert fact["status"] == "ok"
    assert fact["value"]["text"] == "postgres"
    assert fact["authority"] == "high"


def test_firewall_rejection_carries_the_code(store):
    # A signed human writes the high incumbents; an unsigned agent-tier challenger (no grant, so
    # the firewall's *authority* arbitration — not the identity gate — judges it) tries to override.
    human = store.signed("source:alice")
    agent = store.plain()

    # A high fact challenged by a low supersession: pure arbitration — low cannot displace high.
    human.assert_fact("person:alice", "favorite_drink", "tea", authority="high", source="source:alice")
    with pytest.raises(Dent8Rejected) as exc:
        agent.supersede("person:alice", "favorite_drink", "coffee", authority="low", source="note:old")
    assert exc.value.status == "rejected"
    assert exc.value.code == "insufficient-authority"
    assert exc.value.payload["schema_version"] == SCHEMA_VERSION

    # A registered predicate (`database` has a floor in the coding-agent registry) is
    # refused by the policy gate first, with its own code.
    human.assert_fact("repo:myproj", "database", "postgres", authority="high", source="source:alice")
    with pytest.raises(Dent8Rejected) as floor:
        agent.supersede("repo:myproj", "database", "mysql", authority="low", source="web:scrape")
    assert floor.value.code == "below-authority-floor"

    # The incumbents survived both challenges.
    assert human.explain("person:alice", "favorite_drink")["value"]["text"] == "tea"
    assert human.explain("repo:myproj", "database")["value"]["text"] == "postgres"


def test_invalid_input_is_invalid_not_rejected(store):
    # A well-formed agent-tier write with a malformed subject: the invalid-input gate fires on the
    # subject, distinct from a firewall rejection.
    with pytest.raises(Dent8Invalid):
        store.plain().assert_fact("no-colon", "p", "v", authority="low", source="source:agent")


def test_derive_and_taint_flow(store):
    # `repo.database` is High-floored, so every write here is an above-agent signed write.
    d8 = store.signed("source:alice")
    d8.assert_fact("repo:myproj", "database", "postgres", authority="high", source="source:alice")
    derived = d8.derive(
        "service:api",
        "datastore",
        "postgres",
        basis=("repo:myproj", "database"),
        authority="high",
        source="source:alice",
    )
    assert derived["status"] == "accepted"

    d8.retract("repo:myproj", "database", authority="high", source="source:alice")
    report = d8.verify()
    # The basis retraction taints the derivative — a finding, not an exception.
    assert report["status"] == "integrity_issues"
    assert report["ok"] is False


def test_reads_and_time_travel(store):
    # Two signed humans disagree at High over a High-floored predicate: alice asserts, bob dissents.
    alice = store.signed("source:alice")
    bob = store.signed("source:bob")
    alice.assert_fact(
        "repo:myproj",
        "database",
        "postgres",
        authority="high",
        source="source:alice",
        valid_to="2036-01-01",
    )
    listing = alice.facts()
    assert listing["count"] == 1

    history = alice.replay("repo:myproj", "database")
    assert history["events"][0]["kind"] == "fact.asserted"

    # Human time grammar flows through: a week ago the fact did not exist.
    with pytest.raises(Dent8Rejected):
        alice.explain("repo:myproj", "database", as_of="-7d")

    clean = alice.conflicts()
    assert clean["status"] == "ok"
    bob.contradict("repo:myproj", "database", "mysql", authority="high", source="source:bob")
    contested = alice.conflicts()
    assert contested["status"] == "contested"
    assert contested["count"] == 1


def test_missing_binary_reports_clearly(tmp_path):
    ghost = Dent8(binary=str(tmp_path / "definitely-not-dent8"))
    with pytest.raises((FileNotFoundError, OSError)):
        ghost.facts()


def test_binary_contract_matches_sdk_version():
    version = subprocess.run(
        [BINARY, "--version"], capture_output=True, text=True, check=True
    ).stdout.strip()
    assert version.startswith("dent8 ")
