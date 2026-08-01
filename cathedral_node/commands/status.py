"""`cathedral status` — what is running, and what happened."""

from __future__ import annotations

import datetime as _dt
from typing import Any

from cathedral_node import config, lockfile, paths, revocation, state
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.engines import installer
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("status")
def status(ctx: Context) -> Envelope:
    run_id = getattr(ctx.args, "run", None)
    if run_id:
        return _one_run(run_id)

    role_filter = getattr(ctx.args, "role", None)
    limit = int(getattr(ctx.args, "limit", 10) or 10)
    lock = lockfile.load()
    roles = [role_filter] if role_filter else list(lockfile.ROLES)

    # ONE strict verification for the whole command, and the shared lifecycle lease
    # is held for the whole report. Releasing it first would let an activation commit
    # between the verification and the lines that describe it, so the report would
    # describe a node that no longer exists.
    with installer.active_view(lock) as (states, _group, active_detail):
        return _report(lock, roles, limit, states, active_detail)


def _report(lock, roles, limit, states, active_detail) -> Envelope:
    reports: dict[str, Any] = {}
    for role in roles:
        installed = states[role]
        holder = state.running_run(role)
        recent = [state.reconcile(r).to_dict() for r in state.list_runs(role, limit=limit)]
        last_test = next(
            (r for r in recent if r["kind"] == "test"), None
        )
        reports[role] = {
            "installed": installed.to_dict(),
            "running": holder is not None,
            "run": holder,
            "configured": paths.config_file(role).exists(),
            "config_problems": config.validate(role, config.load(role)),
            "last_test": last_test,
            "recent_runs": recent[:limit],
        }

    data = {
        "home": str(paths.home()),
        "roles": reports,
        "any_running": any(r["running"] for r in reports.values()),
        "active_release": active_detail,
        "revocation": revocation.status(now=_dt.datetime.now(_dt.timezone.utc)),
    }
    env = Envelope.ok("status", data)
    env.data_schema = schema_id("status")
    return env


def _one_run(run_id: str) -> Envelope:
    record = state.load_run(run_id)
    if record is None:
        return Envelope.fail(
            "status", C.E_RUN_NOT_FOUND, f"no run named {run_id}", exit_code=Exit.NOT_FOUND,
            remediation=Remediation(summary="List recent runs.", command="cathedral status"),
        )
    record = state.reconcile(record)
    events = list(state.read_events(run_id))
    data = {
        "run": record.to_dict(),
        "event_count": len(events),
        "events": events[-40:],
        "run_dir": paths.relative_to_home(paths.run_dir(run_id)),
    }
    env = Envelope.ok("status", data)
    env.data_schema = schema_id("run_status")
    return env


@renders("status")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    if "run" in data and "roles" not in data:
        record = data["run"]
        console.title(f"Run {record['run_id']}", record["role"] + " · " + record["kind"])
        console.blank()
        console.kv_block(
            [
                ("status", record["status"]),
                ("started", record["started_at"]),
                ("finished", record["finished_at"] or "—"),
                ("exit code", record["exit_code"] if record["exit_code"] is not None else "—"),
                ("detail", record["detail"] or "—"),
                ("events", data["event_count"]),
            ],
            indent=4,
        )
        if data["events"]:
            console.blank()
            console.rule("events")
            for event in data["events"]:
                glyph = {"PASS": console.ok, "FAIL": console.fail, "ERROR": console.fail}.get(
                    event.get("status", "INFO"), console.info
                )
                glyph(event.get("event", "").lower()[:11], event.get("detail", ""))
        return

    console.title("Status", data["home"])
    for role, report in data["roles"].items():
        console.blank()
        console.rule(role)
        installed = report["installed"]
        if not installed["installed"]:
            console.info("engine", f"not installed · pinned {installed['expected_short_revision']}")
        elif installed["revision_drift"]:
            console.warn("engine", f"{installed['short_revision']} differs from pin "
                                   f"{installed['expected_short_revision']}")
        else:
            console.ok("engine", installed["short_revision"])

        if report["running"]:
            run = report["run"] or {}
            console.ok("running", f"pid {run.get('pid')} · since {run.get('since')} · run {run.get('run_id')}")
        else:
            console.info("running", "no")

        last = report["last_test"]
        if last:
            glyph = console.ok if last["status"] == "completed" else console.fail
            glyph("last test", f"{last['status']} · {last['started_at']} · {last['detail']}")
        else:
            console.info("last test", "never run")

        for problem in report["config_problems"]:
            console.warn("config", problem)

        recent = [r for r in report["recent_runs"]][:5]
        if recent:
            console.blank()
            console.table(
                ["run", "kind", "status", "started"],
                [[r["run_id"], r["kind"], r["status"], r["started_at"]] for r in recent],
                indent=6,
            )
