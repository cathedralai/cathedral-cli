"""`cathedral cleanup` — reclaim space without losing anything you configured.

Configuration and secrets are never removed by any variant, including
``--all``. Removing those is a decision that deserves its own explicit act, not
a flag on a housekeeping command.
"""

from __future__ import annotations

import shutil
import time
from typing import Any

from cathedral_node import lockfile, paths, state
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.engines import installer
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("cleanup")
def cleanup(ctx: Context) -> Envelope:
    role = getattr(ctx.args, "role", None)
    do_runs = bool(getattr(ctx.args, "runs", False))
    do_engine = bool(getattr(ctx.args, "engine", False))
    do_all = bool(getattr(ctx.args, "all", False))
    keep_days = int(getattr(ctx.args, "keep_days", 7) or 7)

    if not (do_runs or do_engine or do_all):
        do_runs = True  # the safe default

    if do_all:
        do_runs = do_engine = True

    roles = [role] if role else list(lockfile.ROLES)
    running = [r for r in roles if state.running_run(r) is not None]
    if do_engine and running:
        return Envelope.blocked(
            "cleanup", C.E_ALREADY_RUNNING,
            f"{', '.join(running)} is running; nothing was removed",
            exit_code=Exit.LOCKED,
            remediation=Remediation(summary="Stop it first.", command=f"cathedral stop {running[0]}"),
        )

    cutoff = time.time() - keep_days * 86400
    removable_runs = []
    if do_runs:
        for record in state.list_runs(role, limit=10_000):
            if record.status == "running":
                continue
            directory = paths.run_dir(record.run_id)
            if not directory.exists():
                continue
            try:
                if directory.stat().st_mtime > cutoff:
                    continue
            except OSError:
                continue
            removable_runs.append({"run_id": record.run_id, "role": record.role,
                                   "status": record.status, "bytes": _size(directory)})

    removable_engines = []
    if do_engine:
        for name in roles:
            directory = paths.engine_dir(name)
            if directory.exists():
                # Report the directory even when it holds a half-finished
                # install with no receipt: that is exactly the state an
                # operator needs this command to clear.
                removable_engines.append({
                    "role": name,
                    "bytes": _size(directory),
                    "path": paths.relative_to_home(directory),
                })

    reclaim = sum(r["bytes"] for r in removable_runs) + sum(e["bytes"] for e in removable_engines)
    data: dict[str, Any] = {
        "runs": removable_runs,
        "engines": removable_engines,
        "bytes_to_reclaim": reclaim,
        "keep_days": keep_days,
        "preserved": ["configuration", "secrets"],
        "applied": False,
    }

    if ctx.dry_run:
        env = Envelope.ok("cleanup", data)
        env.data_schema = schema_id("cleanup")
        env.dry_run = True
        return env

    if removable_engines and not ctx.assume_yes:
        return ctx.needs_confirmation(
            "cleanup", f"Removing the {', '.join(e['role'] for e in removable_engines)} engine(s)"
        )

    for item in removable_runs:
        shutil.rmtree(paths.run_dir(item["run_id"]), ignore_errors=True)

    # `uninstall` refuses whenever the release pointer still names a role, so its
    # answer is the whole point. Reporting success over a refusal would tell an
    # operator their disk was reclaimed when the engine is still there — and, worse,
    # imply the node is now uninstalled when it is in fact still active.
    failures: list[dict[str, str]] = []
    for item in removable_engines:
        removed, detail = installer.uninstall(item["role"])
        item["removed"] = removed
        item["detail"] = detail
        if not removed:
            failures.append({"role": item["role"], "detail": detail})

    data["applied"] = not failures
    data["refused"] = failures
    if failures:
        first = failures[0]
        return Envelope.fail(
            "cleanup", C.E_ENGINE_INSTALL_FAILED,
            f"{len(failures)} engine(s) were not removed", exit_code=Exit.WORK_FAILED,
            remediation=Remediation(summary=first["detail"], command="cathedral status"),
            detail=data)
    env = Envelope.ok("cleanup", data)
    env.data_schema = schema_id("cleanup")
    if removable_engines:
        env.then("Reinstall when you need it", f"cathedral setup {removable_engines[0]['role']}")
    return env


def _size(path) -> int:
    total = 0
    try:
        for entry in path.rglob("*"):
            if entry.is_file():
                try:
                    total += entry.stat().st_size
                except OSError:
                    continue
    except OSError:
        pass
    return total


def _human(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} GB"


@renders("cleanup")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    verb = "would remove" if not data["applied"] else "removed"
    console.title("Cleanup", f"keeping runs newer than {data['keep_days']} days")
    console.blank()
    console.info(verb + " runs", str(len(data["runs"])))
    if data["engines"]:
        console.info(verb + " engines", ", ".join(e["role"] for e in data["engines"]))
    console.info("space", _human(data["bytes_to_reclaim"]))
    console.blank()
    console.ok("preserved", ", ".join(data["preserved"]))
