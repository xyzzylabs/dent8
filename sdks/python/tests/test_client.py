"""End-to-end tests against the real dent8 binary (the SDK is a thin wrapper, so the
binary IS the unit under test). Point DENT8_BIN at a built binary, or have `dent8` on
PATH; the suite skips cleanly otherwise:

    cargo build -p dent8-cli
    DENT8_BIN=../../target/debug/dent8 python -m pytest
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from dent8 import SCHEMA_VERSION, Dent8, Dent8Invalid, Dent8Rejected

BINARY = os.environ.get("DENT8_BIN") or shutil.which("dent8")

pytestmark = pytest.mark.skipif(
    BINARY is None, reason="no dent8 binary (set DENT8_BIN or install dent8-cli)"
)


@pytest.fixture()
def d8(tmp_path, monkeypatch):
    """A client pinned to a throwaway store in permissive dev mode: every ambient
    DENT8_* variable is scrubbed (the developer's own shell may carry a dogfood store
    with identity enforcement), then the store paths are pinned to the tmp dir."""
    for key in list(os.environ):
        if key.startswith("DENT8_"):
            monkeypatch.delenv(key)
    env = {
        "DENT8_LOG": str(tmp_path / "memory.jsonl"),
        "DENT8_AUTHORITY": str(tmp_path / "authority.json"),
    }
    return Dent8(binary=BINARY, cwd=str(tmp_path), env=env)


def test_assert_explain_round_trip(d8):
    written = d8.assert_fact(
        "repo:myproj", "database", "postgres", authority="high", source="user:alice"
    )
    assert written["schema_version"] == SCHEMA_VERSION
    assert written["status"] == "accepted"
    assert written["accepted"] is True

    fact = d8.explain("repo:myproj", "database")
    assert fact["status"] == "ok"
    assert fact["value"]["text"] == "postgres"
    assert fact["authority"] == "high"


def test_firewall_rejection_carries_the_code(d8):
    # An unregistered predicate exercises pure arbitration: low cannot displace high.
    d8.assert_fact("person:alice", "favorite_drink", "tea", authority="high", source="user:alice")
    with pytest.raises(Dent8Rejected) as exc:
        d8.supersede("person:alice", "favorite_drink", "coffee", authority="low", source="note:old")
    assert exc.value.status == "rejected"
    assert exc.value.code == "insufficient-authority"
    assert exc.value.payload["schema_version"] == SCHEMA_VERSION

    # A registered predicate (`database` has a floor in the coding-agent registry) is
    # refused by the policy gate first, with its own code.
    d8.assert_fact("repo:myproj", "database", "postgres", authority="high", source="user:alice")
    with pytest.raises(Dent8Rejected) as floor:
        d8.supersede("repo:myproj", "database", "mysql", authority="low", source="web:scrape")
    assert floor.value.code == "below-authority-floor"

    # The incumbents survived both challenges.
    assert d8.explain("person:alice", "favorite_drink")["value"]["text"] == "tea"
    assert d8.explain("repo:myproj", "database")["value"]["text"] == "postgres"


def test_invalid_input_is_invalid_not_rejected(d8):
    with pytest.raises(Dent8Invalid):
        d8.assert_fact("no-colon", "p", "v", authority="high", source="user:alice")


def test_derive_and_taint_flow(d8):
    d8.assert_fact("repo:myproj", "database", "postgres", authority="high", source="user:alice")
    derived = d8.derive(
        "service:api",
        "datastore",
        "postgres",
        basis=("repo:myproj", "database"),
        authority="high",
        source="user:alice",
    )
    assert derived["status"] == "accepted"

    d8.retract("repo:myproj", "database", authority="high", source="user:alice")
    report = d8.verify()
    # The basis retraction taints the derivative — a finding, not an exception.
    assert report["status"] == "integrity_issues"
    assert report["ok"] is False


def test_reads_and_time_travel(d8):
    d8.assert_fact(
        "repo:myproj",
        "database",
        "postgres",
        authority="high",
        source="user:alice",
        valid_to="2036-01-01",
    )
    listing = d8.facts()
    assert listing["count"] == 1

    history = d8.replay("repo:myproj", "database")
    assert history["events"][0]["kind"] == "fact.asserted"

    # Human time grammar flows through: a week ago the fact did not exist.
    with pytest.raises(Dent8Rejected):
        d8.explain("repo:myproj", "database", as_of="-7d")

    clean = d8.conflicts()
    assert clean["status"] == "ok"
    d8.contradict("repo:myproj", "database", "mysql", authority="high", source="user:bob")
    contested = d8.conflicts()
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
