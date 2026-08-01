"""`cathedral logs` — meaningful state changes, not internal noise.

By default this shows the node's own event stream: the decisions and outcomes.
``--raw`` shows the engine's unfiltered output for when something has gone wrong
and the noise is exactly what you need.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from cathedral_node import lockfile, paths, state
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("logs")
def logs(ctx: Context) -> Envelope:
    run_id = getattr(ctx.args, "run", None)
    role = getattr(ctx.args, "role", None)
    lines = int(getattr(ctx.args, "lines", 40) or 40)
    follow = bool(getattr(ctx.args, "follow", False))
    raw = bool(getattr(ctx.args, "raw", False))

    if not run_id:
        candidates = state.list_runs(role, limit=1)
        if not candidates:
            return Envelope.fail(
                "logs", C.E_RUN_NOT_FOUND,
                f"no runs recorded{' for ' + role if role else ''}",
                exit_code=Exit.NOT_FOUND,
                remediation=Remediation(
                    summary="Run something first.",
                    command=f"cathedral test {role or 'distill'}",
                ),
            )
        run_id = candidates[0].run_id

    record = state.load_run(run_id)
    if record is None:
        return Envelope.fail(
            "logs", C.E_RUN_NOT_FOUND, f"no run named {run_id}", exit_code=Exit.NOT_FOUND,
            remediation=Remediation(summary="List recent runs.", command="cathedral status"),
        )
    record = state.reconcile(record)

    if raw:
        return _raw(ctx, record, lines, follow)

    events = list(state.read_events(run_id))
    shown = events[-lines:]

    if not ctx.json_mode:
        ctx.console.title(f"Run {run_id}", f"{record.role} · {record.status}")
        ctx.console.blank()
        for event in shown:
            _print_event(ctx.console, event)

    if follow and record.status == "running":
        seen = len(events)
        try:
            while True:
                time.sleep(0.5)
                fresh = list(state.read_events(run_id, since=seen))
                for event in fresh:
                    seen += 1
                    if not ctx.json_mode:
                        _print_event(ctx.console, event)
                current = state.load_run(run_id)
                if current is None or state.reconcile(current).status != "running":
                    break
        except KeyboardInterrupt:
            pass
        events = list(state.read_events(run_id))
        shown = events[-lines:]

    data = {
        "run_id": run_id,
        "role": record.role,
        "status": record.status,
        "event_count": len(events),
        "events": shown,
        "run_dir": paths.relative_to_home(paths.run_dir(run_id)),
    }
    env = Envelope.ok("logs", data)
    env.data_schema = schema_id("logs")
    return env


def _raw(ctx: Context, record: state.RunRecord, lines: int, follow: bool) -> Envelope:
    path = paths.run_dir(record.run_id) / "engine.log"
    if not path.exists():
        return Envelope.fail(
            "logs", C.E_RUN_NOT_FOUND, f"no engine output recorded for {record.run_id}",
            exit_code=Exit.NOT_FOUND,
            remediation=Remediation(summary="This run produced no engine log.",
                                    command=f"cathedral logs --run {record.run_id}"),
        )
    text = path.read_text(errors="replace").splitlines()
    tail = text[-lines:]
    if not ctx.json_mode:
        ctx.console.title(f"Engine output · {record.run_id}", paths.relative_to_home(path))
        ctx.console.blank()
        for line in tail:
            ctx.console.write("  " + line)
    if follow:
        _follow_file(ctx, path)
    data = {"run_id": record.run_id, "raw": True, "lines": tail,
            "file": paths.relative_to_home(path), "total_lines": len(text)}
    env = Envelope.ok("logs", data)
    env.data_schema = schema_id("logs")
    return env


def _follow_file(ctx: Context, path: Path) -> None:
    try:
        with path.open("r", errors="replace") as fh:
            fh.seek(0, 2)
            while True:
                line = fh.readline()
                if not line:
                    time.sleep(0.4)
                    continue
                if not ctx.json_mode:
                    ctx.console.write("  " + line.rstrip())
    except KeyboardInterrupt:
        pass


def _print_event(console: Console, event: dict[str, Any]) -> None:
    status = str(event.get("status", "INFO")).upper()
    name = str(event.get("event", "")).lower()[:11]
    detail = event.get("detail", "")
    timestamp = str(event.get("ts", ""))[11:19]
    prefix = console.style.dim(timestamp + " ") if timestamp else ""
    if status == "PASS":
        console.write(f"  {prefix}{console.style.green(console.glyphs.ok)} "
                      f"{console.style.dim(name.ljust(11))} {detail}")
    elif status in ("FAIL", "ERROR"):
        console.write(f"  {prefix}{console.style.red(console.glyphs.fail)} "
                      f"{console.style.dim(name.ljust(11))} {detail}")
    else:
        console.write(f"  {prefix}{console.style.dim(console.glyphs.info)} "
                      f"{console.style.dim(name.ljust(11))} {detail}")


@renders("logs")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    # Lines were streamed as they were read; only the summary is left to print.
    console.blank()
    if data.get("raw"):
        console.info("lines", f"{len(data['lines'])} of {data['total_lines']}")
    else:
        console.info("events", str(data["event_count"]))
    console.info("status", data.get("status", ""))
