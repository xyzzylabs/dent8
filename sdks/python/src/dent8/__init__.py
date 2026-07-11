"""dent8 — a memory firewall for coding agents, from Python.

A deliberately thin SDK: every call runs the ``dent8`` binary with ``--output json``
and returns the parsed payload as a ``dict``. The wire contract is the product —
each payload carries ``schema_version``; every error carries a stable ``status``
(``rejected`` / ``invalid``) and a machine-readable ``code``
(``insufficient-authority``, ``authority-ceiling``, ``content-rejected``, …), raised
here as :class:`Dent8Rejected` / :class:`Dent8Invalid` so callers branch on
``error.code`` instead of parsing prose.

Because the CLI itself resolves the store (repo-confined ``.dent8/`` discovery,
``DENT8_LOG`` / ``DENT8_STORE_URL`` env), routes writes through a local daemon when
``DENT8_DAEMON_SOCKET`` is set, and defaults ``--source`` / ``--authority`` from the
active signed grant, this SDK inherits all of that for free.

    from dent8 import Dent8

    d8 = Dent8()
    d8.assert_fact("repo:myproj", "database", "postgres",
                   authority="high", source="user:alice")
    fact = d8.explain("repo:myproj", "database")
    assert fact["status"] == "ok"

Requires the ``dent8`` binary on ``PATH`` (``cargo install dent8-cli --locked``) or an
explicit ``Dent8(binary=...)``.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

__all__ = [
    "Dent8",
    "Dent8Error",
    "Dent8Invalid",
    "Dent8Rejected",
    "SCHEMA_VERSION",
]

#: The JSON output shape this SDK was written against (the CLI stamps it on every payload).
SCHEMA_VERSION = 1

#: A wall-clock instant, in any grammar the CLI accepts: unix millis (int), ``"now"``,
#: a ±duration offset (``"-7d"``), RFC 3339, or a bare UTC date/datetime.
Time = Union[int, str]


class Dent8Error(Exception):
    """A failed dent8 operation. ``status`` says what happened (``rejected`` /
    ``invalid``), ``code`` says why (stable kebab-case, e.g.
    ``insufficient-authority``), ``payload`` is the full JSON error object."""

    def __init__(self, payload: Dict[str, Any]) -> None:
        self.payload = payload
        self.status: str = payload.get("status", "failed")
        self.code: str = payload.get("code", "operation-failed")
        self.message: str = payload.get("message", payload.get("error_reason", ""))
        super().__init__(f"[{self.code}] {self.message}")


class Dent8Rejected(Dent8Error):
    """The firewall (or a write-boundary gate) refused a well-formed request."""


class Dent8Invalid(Dent8Error):
    """The request was malformed or the configuration unusable."""


class Dent8:
    """A handle on the dent8 belief surface, one subprocess per call.

    :param binary: path to the ``dent8`` binary (default: ``dent8`` on ``PATH``, or
        the ``DENT8_BIN`` environment variable when set).
    :param cwd: working directory for store discovery (default: the process cwd).
    :param env: extra environment entries merged over ``os.environ`` — e.g.
        ``{"DENT8_LOG": "/tmp/memory.jsonl"}`` to pin a store instead of discovery.
    :param timeout: per-call subprocess timeout in seconds.
    """

    def __init__(
        self,
        binary: Optional[str] = None,
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: float = 60.0,
    ) -> None:
        self.binary = binary or os.environ.get("DENT8_BIN", "dent8")
        self.cwd = cwd
        self.env = env or {}
        self.timeout = timeout

    # ---- writes ---------------------------------------------------------------

    def assert_fact(
        self,
        subject: str,
        predicate: str,
        value: str,
        *,
        authority: Optional[str] = None,
        source: Optional[str] = None,
        valid_from: Optional[Time] = None,
        valid_to: Optional[Time] = None,
        ttl: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Assert a fact through the firewall. Named ``assert_fact`` because
        ``assert`` is a Python keyword; every other verb matches the CLI 1:1."""
        return self._run(
            "assert",
            subject,
            predicate,
            value,
            authority=authority,
            source=source,
            valid_from=valid_from,
            valid_to=valid_to,
            ttl=ttl,
        )

    def supersede(
        self,
        subject: str,
        predicate: str,
        value: str,
        *,
        authority: Optional[str] = None,
        source: Optional[str] = None,
        valid_from: Optional[Time] = None,
        valid_to: Optional[Time] = None,
        ttl: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Revise the believed fact via the sanctioned supersession path."""
        return self._run(
            "supersede",
            subject,
            predicate,
            value,
            authority=authority,
            source=source,
            valid_from=valid_from,
            valid_to=valid_to,
            ttl=ttl,
        )

    def contradict(
        self,
        subject: str,
        predicate: str,
        value: str,
        *,
        authority: Optional[str] = None,
        source: Optional[str] = None,
        valid_from: Optional[Time] = None,
        valid_to: Optional[Time] = None,
        ttl: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record dissent: keep both facts, mark the pair contested."""
        return self._run(
            "contradict",
            subject,
            predicate,
            value,
            authority=authority,
            source=source,
            valid_from=valid_from,
            valid_to=valid_to,
            ttl=ttl,
        )

    def retract(
        self,
        subject: str,
        predicate: str,
        *,
        authority: Optional[str] = None,
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retract the believed fact (terminal; taints derivatives)."""
        return self._run("retract", subject, predicate, authority=authority, source=source)

    def reinforce(
        self,
        subject: str,
        predicate: str,
        *,
        authority: Optional[str] = None,
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Corroborate the believed fact from another source (earned entrenchment)."""
        return self._run("reinforce", subject, predicate, authority=authority, source=source)

    def expire(
        self,
        subject: str,
        predicate: str,
        *,
        authority: Optional[str] = None,
        source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Expire the believed fact (terminal)."""
        return self._run("expire", subject, predicate, authority=authority, source=source)

    def derive(
        self,
        subject: str,
        predicate: str,
        value: str,
        *,
        basis: Tuple[str, str],
        authority: Optional[str] = None,
        source: Optional[str] = None,
        valid_from: Optional[Time] = None,
        valid_to: Optional[Time] = None,
        ttl: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Assert a fact derived from ``basis = (subject, predicate)``, recording the
        dependency edge — if the basis is later retracted, this derivative is flagged
        tainted by ``verify``."""
        basis_subject, basis_predicate = basis
        return self._run(
            "derive",
            subject,
            predicate,
            value,
            "--basis",
            basis_subject,
            basis_predicate,
            authority=authority,
            source=source,
            valid_from=valid_from,
            valid_to=valid_to,
            ttl=ttl,
        )

    # ---- reads / audit ----------------------------------------------------------

    def explain(
        self,
        subject: str,
        predicate: str,
        *,
        as_of: Optional[Time] = None,
        valid_at: Optional[Time] = None,
    ) -> Dict[str, Any]:
        """The believed (or terminal) fact with its integrity receipt; time-travel
        with ``as_of`` / ``valid_at``."""
        return self._run("explain", subject, predicate, as_of=as_of, valid_at=valid_at)

    def replay(
        self,
        subject: str,
        predicate: str,
        *,
        as_of: Optional[Time] = None,
        valid_at: Optional[Time] = None,
    ) -> Dict[str, Any]:
        """The full event history behind a fact — why it is believed."""
        return self._run("replay", subject, predicate, as_of=as_of, valid_at=valid_at)

    def facts(self, *, include_diagnostics: bool = False) -> Dict[str, Any]:
        """Every known fact stream, with freshness flags."""
        args: List[str] = ["facts", "list"]
        if include_diagnostics:
            args.append("--include-diagnostics")
        return self._run(*args)

    def verify(self) -> Dict[str, Any]:
        """Integrity checks: hash chain, lineage, taint, attestations. Findings are a
        *result*, not an exception: the payload's ``status`` is ``ok`` or
        ``integrity_issues`` (mirroring the MCP tool). Only a malformed invocation
        raises."""
        try:
            return self._run("verify")
        except Dent8Rejected as error:
            return error.payload

    def conflicts(self) -> Dict[str, Any]:
        """Contested facts. ``status`` is ``contested`` when disputes exist, ``ok``
        when none do."""
        return self._run("conflicts")

    # ---- plumbing ---------------------------------------------------------------

    def _run(self, *args: str, **flags: Optional[Union[Time, str]]) -> Dict[str, Any]:
        command: List[str] = [self.binary, "--output", "json", *args]
        for name, value in flags.items():
            if value is None:
                continue
            command.append("--" + name.replace("_", "-"))
            command.append(str(value))
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=self.timeout,
            cwd=self.cwd,
            env={**os.environ, **self.env},
            check=False,
        )
        payload = self._parse(completed, command)
        if completed.returncode == 0:
            return payload
        raise (Dent8Invalid if completed.returncode == 2 else Dent8Rejected)(payload)

    @staticmethod
    def _parse(
        completed: "subprocess.CompletedProcess[str]", command: Sequence[str]
    ) -> Dict[str, Any]:
        # The machine contract: every --output json result — success and error — is one
        # JSON object on stdout. Anything else (e.g. a clap usage error on stderr) is
        # surfaced as invalid with the raw text preserved.
        text = completed.stdout.strip()
        if text:
            try:
                payload = json.loads(text)
                if isinstance(payload, dict):
                    return payload
            except json.JSONDecodeError:
                pass
        raise Dent8Invalid(
            {
                "status": "invalid",
                "code": "invalid-argument",
                "message": (completed.stderr or completed.stdout or "").strip()
                or f"no JSON output from: {' '.join(command)}",
            }
        )
