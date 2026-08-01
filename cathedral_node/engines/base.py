"""What every engine adapter provides.

An adapter is a translation layer and nothing more. It does not reimplement any
engine behaviour: it knows which engine command to run, how to read that
engine's own output, and how to express the answer in the node's contract. When
an engine and the node would disagree about a fact, the engine wins.
"""

from __future__ import annotations

import abc
import dataclasses
from pathlib import Path
from typing import Any, Callable

from cathedral_node.lockfile import EnginePin
from cathedral_node.verified import VerifiedRole

Progress = Callable[[str, str], None]


class UnverifiedEngine(RuntimeError):
    """An adapter was asked for an executable path without a verified generation.

    This is the sealed-execution boundary: an adapter has no fallback path to
    resolve, so there is no way to run bytes that one strict verification did not
    cover.
    """


@dataclasses.dataclass(frozen=True, slots=True)
class Qualification:
    """Whether this machine and identity can do this role's work."""

    can_local_test: bool
    can_operate: bool
    blockers: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    notes: list[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "can_local_test": self.can_local_test,
            "can_operate": self.can_operate,
            "blockers": self.blockers,
            "notes": self.notes,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class TestOutcome:
    """The result of a local, non-paying verification."""

    passed: bool
    summary: str
    checks: list[dict[str, Any]]
    identifiers: dict[str, Any] = dataclasses.field(default_factory=dict)
    failure_code: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "summary": self.summary,
            "checks": self.checks,
            "identifiers": self.identifiers,
            "failure_code": self.failure_code,
        }


class Engine(abc.ABC):
    """One role's adapter."""

    role: str
    title: str
    tagline: str

    def __init__(self, pin: EnginePin, verified: VerifiedRole | None = None) -> None:
        self.pin = pin
        # The sealed generation this adapter may execute, or None. It is set once,
        # from one strict group verification, and is the ONLY source of executable
        # paths. An adapter never re-resolves anything from the mutable pointer.
        self._verified = verified

    def bind(self, verified: VerifiedRole) -> "Engine":
        """Return this adapter bound to a verified generation."""
        if not isinstance(verified, VerifiedRole):
            raise TypeError("an engine binds only to a VerifiedRole")
        if verified.role != self.role:
            raise ValueError(f"cannot bind the {verified.role} generation to the {self.role} adapter")
        self._verified = verified
        return self

    @property
    def verified(self) -> VerifiedRole | None:
        return self._verified

    # ---- description ----------------------------------------------------------

    # Keys every ``explain()`` must supply. Enforced by the test suite so a new
    # engine cannot ship an explanation a caller would crash on.
    EXPLAIN_REQUIRED = ("role", "title", "tagline", "what_you_do", "what_you_need", "not_yet_true")

    @abc.abstractmethod
    def explain(self) -> dict[str, Any]:
        """What this track does, what it needs, what it pays, and what is not
        yet true. Rendered for a human; returned verbatim to an agent.

        Must contain every key in ``EXPLAIN_REQUIRED``. Anything else is
        optional and callers must treat it as such.
        """

    @abc.abstractmethod
    def capabilities(self) -> dict[str, Any]:
        """Honest capability reporting: what this build can actually do here."""

    # ---- readiness ------------------------------------------------------------

    @abc.abstractmethod
    def qualify(self, cfg: dict[str, Any]) -> Qualification:
        """Can this machine and identity do the work? Never optimistic."""

    # ---- operations -----------------------------------------------------------

    @abc.abstractmethod
    def local_test(
        self, cfg: dict[str, Any], run_id: str, *, progress: Progress, timeout: float
    ) -> TestOutcome:
        """A verification that costs nothing, pays nothing, and touches no chain."""

    @abc.abstractmethod
    def operate_argv(self, cfg: dict[str, Any], *, dry_run: bool) -> list[str]:
        """The engine command for real operation. Never contains a secret."""

    @abc.abstractmethod
    def operate_env(self, cfg: dict[str, Any]) -> dict[str, str]:
        """Environment for real operation. This is where secrets travel."""

    def interpret_line(self, line: str) -> dict[str, Any] | None:
        """Turn one line of engine output into a node event, or None to drop it.

        This is the "meaningful state changes, not internal noise" filter.
        """
        return None

    # ---- helpers --------------------------------------------------------------

    def bin(self, name: str) -> Path:
        """An executable from the verified generation.

        There is deliberately no fallback: without a bound ``VerifiedRole`` this
        raises rather than resolving a path from mutable state.
        """
        if self._verified is None:
            raise UnverifiedEngine(
                f"the {self.role} engine has no verified generation bound; refusing to resolve "
                f"an executable path")
        return self._verified.bin(name)

    def has_bin(self, name: str) -> bool:
        """Whether the verified generation actually provides ``name``. Unbound means
        no — honest, because nothing is runnable until the group verifies."""
        if self._verified is None:
            return False
        return self._verified.has_bin(name)

    def python(self) -> Path:
        if self._verified is None:
            raise UnverifiedEngine(
                f"the {self.role} engine has no verified generation bound; refusing to resolve "
                f"an interpreter path")
        return self._verified.python

    def child_env(self, cfg: dict[str, Any] | None = None) -> dict[str, str]:
        """The complete environment for a child of THIS verified generation.

        Nothing is inherited. The only additions are the role secrets this adapter
        resolved on purpose, which travel in the environment precisely so they
        never appear in ``argv`` and therefore never in ``ps``.
        """
        if self._verified is None:
            raise UnverifiedEngine(
                f"the {self.role} engine has no verified generation bound; refusing to build "
                f"an environment for a child that has no verified home")
        from cathedral_node import proc as _proc
        secrets = self.operate_env(cfg) if cfg is not None else {}
        return _proc.signed_child_env(home=self._verified.generation_dir, secrets=secrets)

    def source_dir(self) -> Path:
        """The verified generation's inert source tree."""
        if self._verified is None:
            raise UnverifiedEngine(
                f"the {self.role} engine has no verified generation bound; refusing to resolve "
                f"a source path")
        return self._verified.source_dir
