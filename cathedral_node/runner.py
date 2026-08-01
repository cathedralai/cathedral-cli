"""Command dispatch, output mode, and the process-wide guarantees.

Every command is a function ``(Context) -> Envelope``. This module is the only
place that decides what reaches stdout, what the exit code is, and how an
unexpected exception is turned into a contract-shaped failure. A command never
calls ``print`` or ``sys.exit``.
"""

from __future__ import annotations

import dataclasses
import json
import os
import shlex
import signal
import sys
import traceback
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cathedral_node import paths
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.envelope import NextStep, ResultError, Warning_, utcnow
from cathedral_node.redact import redact_text, redact_value
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import render
from cathedral_node.ui.theme import Style


@dataclasses.dataclass
class Context:
    """Everything a command is allowed to know about how it was invoked."""

    args: Any
    console: Console
    json_mode: bool
    assume_yes: bool
    dry_run: bool
    verbose: bool
    run_id: str
    home: Path
    started_at: str = dataclasses.field(default_factory=utcnow)
    """When the invocation began. Commands build their envelope at the end, so
    without this ``duration_ms`` would measure envelope construction — always
    near zero, and useless to an agent making timeout decisions."""

    def confirm(self, question: str, *, destructive: bool = False) -> bool:
        """Ask for confirmation.

        Never blocks on a prompt in a non-interactive context. Without a TTY and
        without ``--yes``, this returns False and the caller must fail with
        ``usage.confirmation_required`` naming the flag — a required
        confirmation must never be hidden inside an interactive prompt.
        """
        if self.assume_yes:
            return True
        if self.json_mode or not sys.stdin.isatty():
            return False
        prefix = "This cannot be undone. " if destructive else ""
        answer = input(f"  {prefix}{question} [y/N] ").strip().lower()
        return answer in ("y", "yes")

    def needs_confirmation(self, command: str, what: str) -> Envelope:
        """The failure to return when confirmation could not be obtained."""
        return Envelope.blocked(
            command,
            C.E_CONFIRMATION_REQUIRED,
            f"{what} needs explicit confirmation",
            exit_code=Exit.USAGE,
            remediation=Remediation(
                summary="Nothing was changed. Re-run with --yes to confirm without a prompt.",
                command=f"{_argv_prefix()} --yes",
            ),
        )


Command = Callable[[Context], Envelope]

_REGISTRY: dict[str, Command] = {}


def command(name: str) -> Callable[[Command], Command]:
    def decorate(fn: Command) -> Command:
        _REGISTRY[name] = fn
        return fn

    return decorate


def registry() -> dict[str, Command]:
    return dict(_REGISTRY)


# Flags that describe HOW to render or preview, not WHAT to do. Only these are
# dropped when composing the "re-run with --yes" remedy; the positional role and
# operative flags (--engine, --all, --runs, --keep-days N, ...) must be kept, or
# the suggested command would confirm a different, narrower operation than the one
# that actually needed confirming — and report success for it.
_MODE_FLAGS = frozenset({"--json", "--quiet", "-q", "--verbose", "-v", "--dry-run", "--yes", "-y"})


def _argv_prefix() -> str:
    # shlex.quote every token: a role or value containing a space, a quote, or a
    # shell metacharacter (`;`, `|`, `$`, …) must remain a single safe argument
    # when the remedy is pasted into a shell — never break, and never become an
    # injectable command.
    kept = [a for a in sys.argv[1:] if a not in _MODE_FLAGS]
    return "cathedral " + " ".join(shlex.quote(a) for a in kept)


def new_run_id(prefix: str = "run") -> str:
    """A short, sortable, collision-free identifier an agent can quote back."""
    stamp = utcnow().replace("-", "").replace(":", "").replace("T", "-")[:15]
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:6]}"


def execute(name: str, fn: Command, ctx: Context) -> int:
    """Run one command and produce exactly one result. Returns the exit code."""
    interrupted = {"flag": False}

    def on_interrupt(_signum: int, _frame: Any) -> None:
        interrupted["flag"] = True
        raise KeyboardInterrupt

    # SIGTERM as well as SIGINT. SIGTERM is what a supervisor, `kill`, Docker,
    # systemd and a CI timeout send — the signal an agent managing a subprocess
    # actually uses. Handling only SIGINT meant those all died at exit 143 with
    # no envelope and no run record, which is the opposite of the documented
    # "durable state was flushed" promise.
    previous: dict[int, Any] = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, on_interrupt)
        except (ValueError, OSError):  # not the main thread
            previous.pop(signum, None)

    try:
        env = fn(ctx)
    except KeyboardInterrupt:
        env = Envelope.fail(
            name,
            C.E_RUN_INTERRUPTED,
            "interrupted before completion",
            exit_code=Exit.CANCELLED,
            remediation=Remediation(
                summary="Durable state was written. Nothing was left half-applied.",
                command=f"cathedral status --run {ctx.run_id}",
            ),
            run_id=ctx.run_id,
        )
    except BrokenPipeError:
        # `| head` closed our stdout. Not an error worth reporting.
        try:
            sys.stdout.close()
        except Exception:  # noqa: BLE001
            pass
        return int(Exit.OK)
    except Exception as exc:  # noqa: BLE001 - the boundary that must never leak a traceback
        env = _classify(name, exc, ctx)
    finally:
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError):
                pass

    if env.run_id is None:
        env.run_id = ctx.run_id
    env.dry_run = env.dry_run or ctx.dry_run
    # The invocation's clock, not the envelope's: a command that builds its
    # result last would otherwise always report a duration of zero.
    env.started_at = ctx.started_at
    env.finished_at = env.finished_at or utcnow()

    emit(env, ctx)
    return int(env.exit_code)


def _redact_envelope(env: Envelope) -> None:
    """Redact every part of the envelope a renderer or serialiser can read, in
    place, so the human view and the JSON envelope are sanitised from one source.
    A public value the config layer registered (the weight-policy key) is exempt
    by the redactor, so it stays readable in both views."""
    env.data = redact_value(env.data)
    if env.error is not None:
        rem = env.error.remediation
        env.error = ResultError(
            code=env.error.code,
            message=redact_text(env.error.message),
            remediation=(
                Remediation(
                    summary=redact_text(rem.summary),
                    command=redact_text(rem.command) if rem.command else rem.command,
                    docs=redact_text(rem.docs) if rem.docs else rem.docs,
                    requires_operator=rem.requires_operator,
                )
                if rem
                else None
            ),
            detail=redact_value(env.error.detail),
        )
    env.warnings = [
        Warning_(w.code, redact_text(w.message), redact_value(w.detail)) for w in env.warnings
    ]
    env.next_steps = [
        NextStep(
            redact_text(n.description),
            redact_text(n.command) if n.command else n.command,
            n.safe,
        )
        for n in env.next_steps
    ]


def emit(env: Envelope, ctx: Context) -> None:
    """Write the result. Under ``--json``, one envelope to stdout. Otherwise the
    human rendering to stdout as well (so it can be captured or piped); diagnostics
    go to stderr, which stays empty in normal operation.

    Emission is inside its own guard because it runs *after* the command's error
    boundary. A failure while rendering must not turn a completed run into a
    traceback: the exit code is already decided, and the operator still needs to
    be told what happened.
    """
    # Redact the envelope's payload ONCE, in place, so both paths are sanitized
    # from a single source. The human renderer reads env.data / env.error /
    # env.warnings / env.next_steps directly (ui/render.py), so redacting only the
    # JSON dict would leave `config show` and stderr leaking a secret embedded in a
    # config value. redaction is a backstop; the terminal must be protected too.
    _redact_envelope(env)
    if ctx.json_mode:
        # _redact_envelope covers the human render's fields; redact_value over the
        # whole serialized dict is the comprehensive belt for JSON, so any string
        # leaf not enumerated above is still masked.
        json.dump(redact_value(env.to_dict()), sys.stdout, indent=2, sort_keys=False, default=str)
        sys.stdout.write("\n")
        sys.stdout.flush()
        return

    try:
        render(ctx.console, env)
    except Exception as exc:  # noqa: BLE001 - last line of defence before the terminal
        ctx.console.blank()
        ctx.console.fail("display", f"could not render this result ({type(exc).__name__})")
        ctx.console.note(
            f"The command itself finished with status {env.status} (exit {int(env.exit_code)}). "
            f"Re-run with --json to see the full result.",
            indent=6,
        )
        if os.environ.get("CATHEDRAL_TRACEBACK"):
            traceback.print_exc(file=sys.stderr)
    ctx.console.blank()


def _classify(name: str, exc: Exception, ctx: Context) -> Envelope:
    """Turn an escaped exception into the most accurate failure we can name.

    Only genuinely unexpected exceptions become ``INTERNAL``. A known condition
    reaching this boundary — a malformed config, an unreadable file, a lost
    network — is the operator's situation, not our bug, and telling them "this
    is a bug in the node" would send them to the wrong place.
    """
    from cathedral_node.config import ConfigError
    from cathedral_node.paths import UnsafeRunId

    if isinstance(exc, UnsafeRunId):
        return Envelope.fail(
            name,
            C.E_USAGE,
            str(exc),
            exit_code=Exit.USAGE,
            remediation=Remediation(
                summary="A run id is a single path component: letters, digits, dot, dash, "
                "underscore. Nothing was read or written.",
                command="cathedral status --limit 25",
            ),
            run_id=ctx.run_id,
        )

    from cathedral_node.lockfile import UntrustedSource

    if isinstance(exc, UntrustedSource):
        return Envelope.fail(
            name, C.E_CONFIG_INVALID, str(exc), exit_code=Exit.CONFIG_INVALID,
            remediation=Remediation(
                summary="This node installs engines only from Cathedral repositories, pinned to a "
                        "full commit SHA.",
                command="cathedral update --check",
                requires_operator=True,
            ),
            run_id=ctx.run_id,
        )

    if isinstance(exc, ConfigError):
        return Envelope.fail(
            name,
            C.E_CONFIG_INVALID,
            str(exc),
            exit_code=Exit.CONFIG_INVALID,
            remediation=Remediation(
                summary=getattr(exc, "remedy", None) or "Correct the configuration and retry.",
                command=f"cathedral config show {getattr(ctx.args, 'role', '') or ''}".strip(),
            ),
            detail={"field": getattr(exc, "field", None)},
            run_id=ctx.run_id,
        )

    if isinstance(exc, PermissionError):
        return Envelope.fail(
            name, C.E_DISK_LOW, f"permission denied: {exc.filename or exc}",
            exit_code=Exit.NOT_READY,
            remediation=Remediation(
                summary="The node could not read or write a path it owns.",
                command=f"ls -la {paths.home()}",
            ),
            run_id=ctx.run_id,
        )

    if isinstance(exc, (TimeoutError,)):
        return Envelope.fail(
            name, C.E_UPSTREAM_FAILED, "the operation timed out",
            exit_code=Exit.TIMEOUT,
            remediation=Remediation(summary="State was preserved. Safe to retry.",
                                    command=f"cathedral status --run {ctx.run_id}"),
            run_id=ctx.run_id,
        )

    if isinstance(exc, OSError) and getattr(exc, "errno", None) in (28,):  # ENOSPC
        return Envelope.fail(
            name, C.E_DISK_LOW, "no space left on the device",
            exit_code=Exit.NOT_READY,
            remediation=Remediation(summary="Free space, then retry.",
                                    command="cathedral cleanup --runs --yes"),
            run_id=ctx.run_id,
        )

    return _internal_failure(name, exc, ctx)


def _internal_failure(name: str, exc: Exception, ctx: Context) -> Envelope:
    """Turn a bug into something an agent can report and an operator can send."""
    bundle = paths.logs_dir() / f"{ctx.run_id}-crash.log"
    try:
        bundle.parent.mkdir(parents=True, exist_ok=True)
        bundle.write_text(
            f"command: {name}\nrun_id: {ctx.run_id}\nat: {utcnow()}\n\n"
            + "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        )
        location = str(bundle)
    except OSError:
        location = "(could not be written)"

    if os.environ.get("CATHEDRAL_TRACEBACK"):
        traceback.print_exc(file=sys.stderr)

    return Envelope.fail(
        name,
        C.E_INTERNAL,
        f"internal error in `{name}`: {type(exc).__name__}",
        exit_code=Exit.INTERNAL,
        remediation=Remediation(
            summary=f"This is a bug in the node, not in your setup. Diagnostics: {location}",
            command=None,
            requires_operator=True,
        ),
        detail={"exception": type(exc).__name__, "diagnostics": location},
        run_id=ctx.run_id,
    )


def build_console(json_mode: bool, quiet: bool = False) -> Console:
    """Where the human view goes.

    Human mode writes to **stdout**, so redirecting or piping a command captures
    what the operator just watched. It used to write to stderr unconditionally,
    which meant `cathedral doctor > log.txt` produced an empty file and
    `cathedral doctor | grep hotkey` matched nothing — failing silently, in the
    exact situation where someone is trying to save output for support.

    In ``--json`` mode the console is silent and stdout carries only the
    envelope, so the agent contract is unchanged.
    """
    stream = sys.stderr if json_mode else sys.stdout
    return Console(stream=stream, style=Style(stream=stream), quiet=quiet or json_mode)
