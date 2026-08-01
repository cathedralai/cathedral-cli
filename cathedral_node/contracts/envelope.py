"""The one envelope every command returns.

A command builds an ``Envelope`` and hands it back. The runner decides whether
to print it as JSON (agent) or render it (human). Neither path can produce an
output the other cannot, because there is only one object.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
from typing import Any

from cathedral_node.contracts.codes import Exit
from cathedral_node.contracts.version import PROTOCOL_VERSION, RESULT_SCHEMA


def utcnow() -> str:
    """RFC 3339 UTC with a trailing Z. The only timestamp format we emit."""
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclasses.dataclass(frozen=True, slots=True)
class Remediation:
    """What to do about a failure. ``command`` must be runnable verbatim."""

    summary: str
    command: str | None = None
    docs: str | None = None
    requires_operator: bool = False
    """True when no command can fix this — it needs hardware, money, or a human
    decision. An agent must stop and escalate rather than retry."""

    @property
    def requires_input(self) -> bool:
        """True when ``command`` contains a `<placeholder>` the caller must fill.

        Without this an agent runs the command verbatim, the placeholder fails
        validation, and the next remediation points back at the first — a loop
        whose every step looks like progress.
        """
        return bool(self.command) and "<" in self.command and ">" in self.command

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "command": self.command,
            "docs": self.docs,
            "requires_operator": self.requires_operator,
            "requires_input": self.requires_input,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class ResultError:
    """A failure, in the shape an agent can branch on without reading prose."""

    code: str
    message: str
    remediation: Remediation | None = None
    detail: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": str(self.code),
            "message": self.message,
            "remediation": self.remediation.to_dict() if self.remediation else None,
            "detail": self.detail,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Warning_:
    """Something the operator should know that did not stop the command."""

    code: str
    message: str
    detail: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {"code": str(self.code), "message": self.message, "detail": self.detail}


@dataclasses.dataclass(frozen=True, slots=True)
class NextStep:
    """A suggested follow-up. Agents may execute ``command`` unattended when
    ``safe`` is true; otherwise it needs an operator decision first."""

    description: str
    command: str | None = None
    safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"description": self.description, "command": self.command, "safe": self.safe}


@dataclasses.dataclass(slots=True)
class Envelope:
    """The complete result of one command invocation."""

    command: str
    status: str = "ok"  # ok | failed | blocked
    exit_code: Exit = Exit.OK
    data: dict[str, Any] = dataclasses.field(default_factory=dict)
    data_schema: str | None = None
    error: ResultError | None = None
    warnings: list[Warning_] = dataclasses.field(default_factory=list)
    next_steps: list[NextStep] = dataclasses.field(default_factory=list)
    run_id: str | None = None
    started_at: str = dataclasses.field(default_factory=utcnow)
    finished_at: str | None = None
    dry_run: bool = False

    # ---- construction helpers -------------------------------------------------

    @classmethod
    def ok(cls, command: str, data: dict[str, Any] | None = None, **kw: Any) -> "Envelope":
        return cls(command=command, status="ok", exit_code=Exit.OK, data=data or {}, **kw)

    @classmethod
    def fail(
        cls,
        command: str,
        code: str,
        message: str,
        exit_code: Exit = Exit.WORK_FAILED,
        remediation: Remediation | None = None,
        detail: dict[str, Any] | None = None,
        **kw: Any,
    ) -> "Envelope":
        return cls(
            command=command,
            status="failed",
            exit_code=exit_code,
            error=ResultError(code, message, remediation, detail or {}),
            **kw,
        )

    @classmethod
    def blocked(
        cls,
        command: str,
        code: str,
        message: str,
        remediation: Remediation | None = None,
        exit_code: Exit = Exit.NOT_READY,
        detail: dict[str, Any] | None = None,
        **kw: Any,
    ) -> "Envelope":
        """Nothing was attempted because a precondition is unmet."""
        return cls(
            command=command,
            status="blocked",
            exit_code=exit_code,
            error=ResultError(code, message, remediation, detail or {}),
            **kw,
        )

    def warn(self, code: str, message: str, **detail: Any) -> "Envelope":
        self.warnings.append(Warning_(code, message, detail))
        return self

    def then(self, description: str, command: str | None = None, safe: bool = True) -> "Envelope":
        self.next_steps.append(NextStep(description, command, safe))
        return self

    # ---- serialisation --------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        finished = self.finished_at or utcnow()
        return {
            "schema": RESULT_SCHEMA,
            "protocol_version": PROTOCOL_VERSION,
            "command": self.command,
            "status": self.status,
            "exit_code": int(self.exit_code),
            "dry_run": self.dry_run,
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": finished,
            "duration_ms": _elapsed_ms(self.started_at, finished),
            "data_schema": self.data_schema,
            "data": self.data,
            "error": self.error.to_dict() if self.error else None,
            "warnings": [w.to_dict() for w in self.warnings],
            "next": [n.to_dict() for n in self.next_steps],
        }


def _elapsed_ms(start: str, end: str) -> int:
    try:
        a = _dt.datetime.fromisoformat(start.replace("Z", "+00:00"))
        b = _dt.datetime.fromisoformat(end.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, int((b - a).total_seconds() * 1000))
