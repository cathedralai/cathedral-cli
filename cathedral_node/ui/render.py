"""Rendering an Envelope for a human.

Each command may register a renderer for its ``data`` payload; anything without
one falls back to a generic, still-readable presentation. The envelope's
status, error, warnings, and next steps are rendered here for every command, so
those never differ between commands.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from cathedral_node.contracts import Envelope
from cathedral_node.ui.console import Console

Renderer = Callable[[Console, dict[str, Any], Envelope], None]

_RENDERERS: dict[str, Renderer] = {}


def renders(command: str) -> Callable[[Renderer], Renderer]:
    def decorate(fn: Renderer) -> Renderer:
        _RENDERERS[command] = fn
        return fn

    return decorate


def render(console: Console, env: Envelope) -> None:
    """Render one envelope: the body, then any problem, then what to do next.

    A command-specific renderer only runs when there is a payload for it. A
    blocked or failed envelope often carries no ``data`` at all — nothing was
    attempted — and its meaningful output is the problem block below. Calling a
    body renderer with an empty payload used to raise a KeyError that escaped as
    a traceback, which is the worst thing a first-time operator can be shown.
    """
    body = _RENDERERS.get(env.command)
    if body is not None and env.data:
        try:
            body(console, env.data, env)
        except (KeyError, TypeError, IndexError, ValueError) as exc:
            # A renderer bug must never hide the result. Fall back to something
            # readable and say plainly that the presentation, not the run, broke.
            console.blank()
            console.warn("display", f"could not render this result in full ({type(exc).__name__})")
            _generic(console, env.data)
    elif env.data:
        _generic(console, env.data)

    for warning in env.warnings:
        console.blank()
        console.warn("note", warning.message)

    if env.error is not None:
        remediation = env.error.remediation
        console.problem(
            what=env.error.message,
            why=_why(env),
            action=remediation.command if remediation else None,
            docs=remediation.docs if remediation else None,
        )
        if remediation and remediation.requires_operator:
            console.note(
                "This needs a decision or resource no command can supply. "
                "It is not a retryable failure.",
                indent=4,
            )
        elif remediation and remediation.summary and not remediation.command:
            console.note(remediation.summary, indent=4)

    if env.next_steps:
        console.next_steps([(step.description, step.command) for step in env.next_steps])


def _why(env: Envelope) -> str:
    """The 'why it matters' half of an error. Prefers the remediation summary,
    falls back to the machine code so the line is never empty."""
    if env.error is None:
        return ""
    if env.error.remediation and env.error.remediation.summary:
        return env.error.remediation.summary
    return f"error code {env.error.code}"


def _generic(console: Console, data: dict[str, Any]) -> None:
    pairs: list[tuple[str, Any]] = []
    for key, value in data.items():
        if isinstance(value, (dict, list)):
            continue
        pairs.append((key.replace("_", " "), value))
    if pairs:
        console.blank()
        console.kv_block(pairs, indent=4)
