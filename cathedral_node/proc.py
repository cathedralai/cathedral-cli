"""Running engine subprocesses safely.

Two rules this module exists to enforce:

1. A secret never appears in ``argv``. Anything sensitive is passed through the
   child's environment, so it never shows up in ``ps`` output or a shell history.
2. Engine stdout and stderr are diagnostics, not results. They are captured into
   the run's log and, when the operator asks, streamed — but they are never
   mixed into the JSON envelope on our stdout.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path

from cathedral_node.redact import redact_text

# Environment names whose values are secret. Set from the secrets store, never
# logged, never echoed. Matching is by suffix so provider-specific names work.
SECRET_SUFFIXES = ("_KEY", "_TOKEN", "_SECRET", "_PASSWORD", "_SEED", "_MNEMONIC", "_PRIVATE")

# --- the one signed-child environment -----------------------------------------
#
# Every process built from a signed release — the venv builder, pip, the import and
# closure probes, the entrypoint self-checks, each engine's local test, the version
# probe, the census, and the long-running `cathedral start` child — gets EXACTLY
# this, plus the role secrets the caller resolved on purpose.
#
# The list is short because the danger is not any single variable. `PYTHONPATH`
# plants a `sitecustomize.py` that executes before the first line of signed code;
# `LD_PRELOAD` and `DYLD_INSERT_LIBRARIES` inject a shared object; `VIRTUAL_ENV`
# and `PYTHONHOME` relocate the interpreter's idea of its own installation;
# `PIP_INDEX_URL` and the proxy variables redirect the network the install is
# supposed not to use; the cloud credential variables hand a signed child an
# identity nobody granted it. Enumerating those to *exclude* them is a losing game,
# because the next one has not been invented yet. So nothing is inherited, and the
# allowlist is what is left.
SIGNED_CHILD_ALLOWLIST = ("PATH", "HOME", "TMPDIR", "LC_ALL", "LANG",
                          "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE",
                          "PYTHONUNBUFFERED", "NO_COLOR")
SIGNED_CHILD_PATH = "/usr/bin:/bin"


def signed_child_env(*, home: Path | str, tmpdir: Path | str | None = None,
                     secrets: Mapping[str, str] | None = None,
                     extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """The complete environment for a child built from a signed release.

    Nothing is inherited. ``secrets`` are the role credentials the caller resolved
    deliberately from the secret store — they travel here rather than in ``argv``
    so they never reach ``ps`` — and ``extra`` is for values a specific check needs
    (pip's offline pins, for instance), named at the call site so they are visible
    in review.
    """
    env = {
        "PATH": SIGNED_CHILD_PATH,
        "HOME": str(home),
        "TMPDIR": str(tmpdir if tmpdir is not None else home),
        "LC_ALL": "C",
        "LANG": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUNBUFFERED": "1",
        "NO_COLOR": "1",
    }
    env.update({str(k): str(v) for k, v in (extra or {}).items()})
    env.update({str(k): str(v) for k, v in (secrets or {}).items()})
    return env


def env_leaks(env: Mapping[str, str], *, allow: Iterable[str] = ()) -> list[str]:
    """Names in ``env`` that are neither on the allowlist nor deliberately allowed.
    Used by the gate tests to prove no host variable crossed the boundary."""
    permitted = set(SIGNED_CHILD_ALLOWLIST) | set(allow)
    return sorted(name for name in env if name not in permitted)


def is_secret_name(name: str) -> bool:
    upper = name.upper()
    return any(upper.endswith(sfx) for sfx in SECRET_SUFFIXES)


class ProcessResult:
    __slots__ = ("returncode", "stdout", "stderr", "duration_ms", "argv", "timed_out")

    def __init__(
        self,
        returncode: int,
        stdout: str,
        stderr: str,
        duration_ms: int,
        argv: Sequence[str],
        timed_out: bool = False,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.duration_ms = duration_ms
        self.argv = list(argv)
        self.timed_out = timed_out

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def tail(self, lines: int = 12) -> str:
        """The last few lines of combined output, redacted. For error detail."""
        combined = (self.stderr or self.stdout or "").strip().splitlines()
        return redact_text("\n".join(combined[-lines:]))


def run(
    argv: Sequence[str],
    *,
    inherit_env: bool,
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    timeout: float | None = 900.0,
    stdin_text: str | None = None,
    log_path: Path | None = None,
) -> ProcessResult:
    """Run one command to completion.

    ``inherit_env`` has no default and never will. A default meant call sites
    inherited the host environment by omission — the one way a boundary gets
    crossed without anybody deciding to cross it. Signed children pass
    ``inherit_env=False`` with :func:`signed_child_env`; host probes (``lscpu``,
    ``docker``) pass ``inherit_env=True`` because finding a host tool is what they
    are for, and say so at the call site.
    """
    child_env = dict(os.environ) if inherit_env else {}
    child_env.update(env or {})
    child_env.setdefault("PYTHONUNBUFFERED", "1")
    # Engines must not colour output we are going to parse or re-render.
    child_env.setdefault("NO_COLOR", "1")

    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(  # noqa: S603 - argv is built from pinned engine paths
            list(argv),
            env=child_env,
            cwd=str(cwd) if cwd else None,
            input=stdin_text,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",  # never crash on non-UTF-8 engine output
            timeout=timeout,
            check=False,
        )
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = 124
        out = _decode(exc.stdout)
        err = _decode(exc.stderr) + f"\n[timed out after {timeout}s]"
    except FileNotFoundError as exc:
        rc = 127
        out = ""
        err = str(exc)
    except OSError as exc:
        # PermissionError (a non-executable file), an exec format error, or any
        # other launch failure. This is a controlled failure, not a crash: return
        # a non-zero result so the caller can diagnose an incomplete environment
        # instead of letting the exception escape as a traceback. 126 is the
        # conventional "found but not executable" code.
        rc = 126
        out = ""
        err = f"could not launch {argv[0] if argv else '?'}: {exc}"

    duration = int((time.monotonic() - started) * 1000)

    if log_path is not None:
        _append_log(log_path, argv, out, err, rc, duration)

    return ProcessResult(rc, out, err, duration, argv, timed_out)


def stream(
    argv: Sequence[str],
    *,
    on_line: Callable[[str], None],
    inherit_env: bool,
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    log_path: Path | None = None,
    stop: threading.Event | None = None,
    on_start: Callable[[subprocess.Popen], None] | None = None,
) -> ProcessResult:
    """Run a long-lived engine, delivering each output line as it arrives.

    Returns when the child exits or ``stop`` is set. On stop the child's whole
    process **group** gets SIGTERM, then SIGKILL after a grace period, so durable
    state gets flushed and no descendant is orphaned.

    ``inherit_env`` is explicit here for the same reason as in :func:`run`, and it
    matters most here: this is the path a real ``cathedral start`` takes, and it is
    the longest-lived child the node has.

    ``on_start`` is called with the live ``Popen`` before any output is processed,
    so the caller can persist durable ownership of the child and its process group
    *before* the run is reported as started. Anything recorded after the first line
    of output is a window in which a crash leaves an unowned child running.
    """
    child_env = dict(os.environ) if inherit_env else {}
    child_env.update(env or {})
    child_env.setdefault("PYTHONUNBUFFERED", "1")
    child_env.setdefault("NO_COLOR", "1")

    started = time.monotonic()
    collected: list[str] = []
    reader_error: dict[str, BaseException] = {}

    try:
        proc = subprocess.Popen(  # noqa: S603
            list(argv),
            env=child_env,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",  # never crash on non-UTF-8 engine output
            bufsize=1,
            start_new_session=True,
        )
    except OSError as exc:
        # A launch failure (missing/non-executable) is a controlled result, not a
        # traceback — 126 for "found but not executable", 127 for "not found".
        rc = 127 if isinstance(exc, FileNotFoundError) else 126
        duration = int((time.monotonic() - started) * 1000)
        return ProcessResult(rc, "", f"could not launch {argv[0] if argv else '?'}: {exc}",
                             duration, argv)

    # Captured while the child certainly exists. After the leader exits this is
    # unrecoverable, and every cleanup path below needs it.
    try:
        child_pgid: int | None = os.getpgid(proc.pid)
    except OSError:
        child_pgid = proc.pid

    if on_start is not None:
        # Ownership is durable before the first line is read, so a crash here
        # cannot leave a running child nobody has a record of.
        #
        # And if it CANNOT be made durable, the child must not survive the attempt.
        # The window between spawn and publication is the one interval in which
        # signed code is executing with nothing on disk saying who owns it; leaving
        # a child alive there is exactly the orphan every later refusal depends on
        # not existing. So the group is terminated and proven stopped before the
        # failure is allowed to propagate.
        try:
            on_start(proc)
        except BaseException as exc:
            stopped = _terminate(proc, pgid=child_pgid)
            with contextlib.suppress(Exception):
                if proc.stdout is not None:
                    proc.stdout.close()
            if not stopped:
                # The escalation to SIGKILL did not empty the group. Saying nothing
                # and re-raising the original error would hand the caller a failure
                # it would read as "nothing is running" — and the next prune would
                # delete text a surviving descendant is still faulting in. This is
                # the worse failure, so it is the one that gets reported.
                raise GroupTerminationError(
                    f"ownership could not be published ({exc}) and the child's process group "
                    f"{child_pgid} could not be proven stopped; "
                    f"{len(_group_members(child_pgid))} process(es) survive"
                ) from exc
            raise

    def pump() -> None:
        assert proc.stdout is not None
        try:
            for raw in proc.stdout:
                # Redact BEFORE it reaches the callback, the log, or the terminal.
                line = redact_text(raw.rstrip("\n"))
                collected.append(line)
                if log_path is not None:
                    _append_line(log_path, line)
                on_line(line)
        except BaseException as exc:  # noqa: BLE001 - a reader failure must not vanish
            reader_error["exc"] = exc

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()

    try:
        while proc.poll() is None:
            if stop is not None and stop.is_set():
                _terminate(proc, pgid=child_pgid)
                break
            if reader_error:
                # The reader is dead; without draining, a chatty child fills the
                # pipe and blocks forever. Terminate its process group now.
                _terminate(proc, pgid=child_pgid)
                break
            time.sleep(0.05)
    except KeyboardInterrupt:
        _terminate(proc, pgid=child_pgid)
        raise
    finally:
        reader.join(timeout=2.0)
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass

    rc = proc.poll()
    rc = rc if rc is not None else -1
    # A reader-thread failure (a decode fault, a raising callback, a persistence
    # error) must never be reported as a clean success — that would hide lost or
    # corrupt output behind exit 0.
    if reader_error and rc == 0:
        rc = 70
    duration = int((time.monotonic() - started) * 1000)
    # Redact + strip controls from the exception text before it leaves this layer.
    stderr = "" if not reader_error else redact_text(f"reader failed: {reader_error['exc']}")
    return ProcessResult(rc, "\n".join(collected), stderr, duration, argv)


def probe(
    argv: Sequence[str],
    *,
    inherit_env: bool,
    stdin_bytes: bytes | None = None,
    timeout: float = 15.0,
    env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
) -> ProcessResult:
    """A bounded, self-contained probe: run ``argv`` in its own process group and
    TERM→KILL the whole group on timeout, so a hung entrypoint (or any descendant)
    can never linger. Output is decoded as UTF-8 with replacement and redacted.
    A launch failure or a timeout is a controlled non-zero result, never a raise.

    ``inherit_env=False`` runs with ONLY ``env`` (a scrubbed environment), so a
    hostile ``LD_PRELOAD``/``DYLD_*``/``SSH_ASKPASS`` in the caller's environment
    cannot reach the child.
    """
    if inherit_env:
        child_env = dict(os.environ) if env is None else {**os.environ, **env}
    else:
        child_env = dict(env or {})
    child_env.setdefault("NO_COLOR", "1")
    child_env.setdefault("PYTHONUNBUFFERED", "1")
    started = time.monotonic()
    try:
        child = subprocess.Popen(  # noqa: S603
            list(argv),
            stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=child_env,
            cwd=str(cwd) if cwd else None,
            start_new_session=True,  # its own process group, so we can kill descendants
        )
    except OSError as exc:
        rc = 127 if isinstance(exc, FileNotFoundError) else 126
        return ProcessResult(rc, "", redact_text(str(exc)),
                             int((time.monotonic() - started) * 1000), argv)
    timed_out = False
    try:
        out, _ = child.communicate(input=stdin_bytes, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate(child)
        try:
            out, _ = child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            out = b""
    rc = child.returncode if child.returncode is not None else -1
    if timed_out:
        rc = 124
    text = _decode(out)
    return ProcessResult(rc, redact_text(text), "",
                         int((time.monotonic() - started) * 1000), argv, timed_out=timed_out)


class GroupTerminationError(RuntimeError):
    """A child's process group could not be proven stopped."""


def _group_id(proc: subprocess.Popen, known: int | None = None) -> int | None:
    """The child's process group, preferring the id captured when it was spawned.

    Asking the kernel *after* termination is too late: once the leader has exited,
    ``os.getpgid`` raises, the group id is lost, and a check that then finds "no
    members" is really finding "no way to look". Every launcher here uses
    ``start_new_session=True``, so the group id is the child pid, and it is
    captured while the child certainly exists.
    """
    if known is not None:
        return known
    try:
        return os.getpgid(proc.pid)
    except OSError:
        return proc.pid or None


def _group_members(pgid: int | None) -> list[int]:
    if pgid is None:
        return []
    from cathedral_node import state as _state
    return [pid for pid in _state.process_group_members(pgid) if pid != os.getpid()]


def _await_group_exit(proc: subprocess.Popen, pgid: int | None = None,
                      timeout: float = 10.0) -> bool:
    """Wait until nothing from the child's process group is left, and reap the leader.

    Returning from ``_terminate`` says a signal was delivered, not that the group is
    gone. A caller about to report failure — and whose caller may then delete the
    generation those processes are executing — needs the stronger statement, so this
    returns whether the group is *actually* empty and the caller is expected to act
    on the answer.
    """
    pgid = _group_id(proc, pgid)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(Exception):
            proc.wait(timeout=0.05)
        if proc.poll() is not None and not _group_members(pgid):
            return True
        time.sleep(0.05)
    with contextlib.suppress(Exception):
        proc.wait(timeout=0.1)
    return proc.poll() is not None and not _group_members(pgid)


def _terminate(proc: subprocess.Popen, grace: float = 8.0, pgid: int | None = None) -> bool:
    """SIGTERM the process group, then SIGKILL it. Returns whether it is gone.

    The wait is on the GROUP, not on the leader. Waiting for the leader alone was
    the defect: a server that exits promptly on TERM while a descendant ignores it
    satisfied the old loop, so the escalation to SIGKILL never happened and the
    descendant simply carried on — still executing the generation the caller was
    about to delete.
    """
    pgid = _group_id(proc, pgid)

    def signal_group(sig: int) -> None:
        if pgid is not None:
            try:
                os.killpg(pgid, sig)
                return
            except (ProcessLookupError, PermissionError, OSError):
                pass
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.send_signal(sig)

    signal_group(signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        with contextlib.suppress(Exception):
            proc.wait(timeout=0.05)
        if proc.poll() is not None and not _group_members(pgid):
            return True
        time.sleep(0.1)

    signal_group(signal.SIGKILL)
    return _await_group_exit(proc, pgid, timeout=10.0)


def _decode(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _append_log(path: Path, argv: Iterable[str], out: str, err: str, rc: int, ms: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(f"\n$ {redact_text(' '.join(argv))}\n")
        if out.strip():
            fh.write(redact_text(out.rstrip()) + "\n")
        if err.strip():
            fh.write(redact_text(err.rstrip()) + "\n")
        fh.write(f"[exit {rc} in {ms}ms]\n")


def _append_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(redact_text(line) + "\n")
