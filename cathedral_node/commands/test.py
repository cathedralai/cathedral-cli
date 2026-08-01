"""`cathedral test <role>` — the verified local test.

The single most important command in the product. It must:

* cost nothing, pay nothing, and touch no chain;
* exercise the real engine, not a fixture that returns success;
* fail closed — a verification that cannot be completed is a failure, never a
  pass with a warning; and
* finish fast enough that a first-time operator waits for it.
"""

from __future__ import annotations

from typing import Any

from cathedral_node import config, engines, lockfile, paths, state
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.engines import installer
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders

DEFAULT_TIMEOUT = 600.0


@command("test")
def test(ctx: Context) -> Envelope:
    role = ctx.args.role
    lock = lockfile.load()
    if role not in lock.engines:
        return Envelope.fail(
            "test", C.E_UNKNOWN_ROLE, f"unknown role {role!r}", exit_code=Exit.USAGE,
            remediation=Remediation(summary=f"Known roles: {', '.join(lockfile.ROLES)}."),
        )

    # One strict verification, held under the shared lifecycle lock for the whole
    # test, and revalidated immediately before the engine subprocess starts.
    try:
        with installer.verified_active_group(lock) as active:
            return _test_verified(ctx, role, lock, active)
    except installer.ActiveStateError as exc:
        engine = engines.load(role, lock)
        return Envelope.blocked(
            "test", C.E_ENGINE_NOT_INSTALLED,
            f"the {engine.title} engine is not installed as a verified signed release",
            remediation=Remediation(
                summary=f"Nothing was run: {exc}", command=f"cathedral setup {role}"),
            detail={"reason": str(exc)},
        )
    except installer.InstallError as exc:
        return Envelope.blocked(
            "test", C.E_ALREADY_RUNNING, str(exc), exit_code=Exit.LOCKED,
            remediation=Remediation(summary="Nothing was run.", command="cathedral status"))


def _test_verified(ctx: Context, role: str, lock, active) -> Envelope:
    engine = engines.load(role, lock, active.group)
    installed = installer.state_from_group(lock.pin(role), active.group)
    if not installed.installed:
        return Envelope.blocked(
            "test",
            C.E_ENGINE_NOT_INSTALLED,
            f"the {engine.title} engine is not installed",
            remediation=Remediation(
                summary="Nothing was run. Install the pinned engine first.",
                command=f"cathedral setup {role}",
            ),
        )

    cfg = config.load(role)
    qualification = engine.qualify(cfg)
    if not qualification.can_local_test:
        blocker = next((b for b in qualification.blockers if "local_test" in b.get("blocks", [])), None)
        return Envelope.blocked(
            "test",
            (blocker or {}).get("code", C.E_CONFIG_INVALID),
            f"this machine cannot run the {engine.title} local test",
            remediation=Remediation(
                summary=(blocker or {}).get("what", "a precondition is unmet"),
                command=(blocker or {}).get("fix"),
                requires_operator=bool((blocker or {}).get("requires_operator")),
            ),
            detail={"blockers": qualification.blockers},
        )

    timeout = float(getattr(ctx.args, "timeout", 0) or DEFAULT_TIMEOUT)

    if ctx.dry_run:
        env = Envelope.ok(
            "test",
            {
                "role": role,
                "would_run": engine.capabilities()["local_test"],
                "engine_revision": installed.revision,
                "pays": "nothing",
                "touches_chain": False,
            },
        )
        env.data_schema = schema_id("test")
        env.dry_run = True
        return env

    record = state.create_run(ctx.run_id, role, "test", f"{engine.title} local test")
    ctx.console.title(f"{engine.title} local test", ctx.console.join("pays nothing", "no chain access"))
    state.emit_event(ctx.run_id, "TEST_STARTED", stage="start", detail=engine.title,
                     fields={"role": role})

    def progress(label: str, detail: str) -> None:
        ctx.console.progress(label, detail)
        state.emit_event(ctx.run_id, "TEST_PROGRESS", stage=label, detail=detail)

    try:
        outcome = active.launch(engine.local_test, cfg, ctx.run_id, progress=progress,
                                timeout=timeout)
    except installer.ActiveStateError as exc:
        state.finish_run(record, "failed", int(Exit.NOT_READY), str(exc))
        state.emit_event(ctx.run_id, "TEST_REFUSED", stage="verify", status="FAIL", detail=str(exc))
        return Envelope.blocked(
            "test", C.E_ENGINE_NOT_INSTALLED,
            "the active release changed after verification; no engine was run",
            exit_code=Exit.NOT_READY,
            remediation=Remediation(summary=str(exc), command="cathedral status"),
            run_id=ctx.run_id, detail={"reason": str(exc)})

    for check in outcome.checks:
        # Carry the check's own identifiers into the event. `cathedral evidence`
        # searches events, so an id that only ever appeared in the result
        # envelope would be unfindable ten minutes later — which defeats the
        # point of returning exact identifiers at all.
        state.emit_event(
            ctx.run_id,
            "CHECK",
            stage="verify",
            status="PASS" if check["passed"] else "FAIL",
            detail=f"{check['name']}: {check.get('detail', '')}",
            fields={k: v for k, v in check.items()
                    if k not in ("name", "detail", "passed", "label")},
        )

    state.emit_event(
        ctx.run_id, "IDENTIFIERS", stage="done", status="INFO",
        detail=f"{len(outcome.identifiers)} identifier(s) from this run",
        fields=dict(outcome.identifiers),
    )

    data = {
        "role": role,
        "engine_revision": installed.revision,
        "passed": outcome.passed,
        "summary": outcome.summary,
        "checks": outcome.checks,
        "identifiers": outcome.identifiers,
        "checks_passed": sum(1 for c in outcome.checks if c["passed"]),
        "checks_total": len(outcome.checks),
        "run_dir": str(paths.run_dir(ctx.run_id)),
        "pays": "nothing",
        "touches_chain": False,
    }

    record.artifacts = dict(outcome.identifiers)

    if outcome.passed:
        state.finish_run(record, "completed", 0, outcome.summary)
        state.emit_event(ctx.run_id, "TEST_PASSED", stage="done", status="PASS", detail=outcome.summary)
        env = Envelope.ok("test", data, run_id=ctx.run_id)
        env.data_schema = schema_id("test")
        env.then(f"Read what {engine.title} pays for", f"cathedral explain {role}")
        env.then("Generate an agent instruction block", f"cathedral agent-brief {role}")
        if qualification.can_operate:
            env.then(f"Start {engine.title}", f"cathedral start {role}")
        else:
            env.then("See what live operation still needs", f"cathedral doctor {role}")
        return env

    state.finish_run(record, "failed", int(Exit.VERIFY_FAILED), outcome.summary)
    state.emit_event(ctx.run_id, "TEST_FAILED", stage="done", status="FAIL", detail=outcome.summary)
    env = Envelope.fail(
        "test",
        outcome.failure_code or C.E_VERIFY_DIFFERENTIAL,
        outcome.summary,
        exit_code=Exit.VERIFY_FAILED,
        remediation=Remediation(
            summary="The verification did not pass. Nothing was submitted anywhere.",
            command=outcome.remediation or f"cathedral logs {role} --run {ctx.run_id}",
        ),
        run_id=ctx.run_id,
    )
    env.data = data
    env.data_schema = schema_id("test")
    return env


def _label(check: dict[str, Any]) -> str:
    """The short column label for a check.

    An engine may supply one; otherwise the check's name is a full sentence and
    the first word alone would read as noise ("the", "a"), so fall back to the
    name truncated as a whole.
    """
    explicit = check.get("label")
    if explicit:
        return str(explicit)[:11]
    name = str(check.get("name", ""))
    first = name.split(" ", 1)[0]
    if len(first) >= 4 and len(name) <= 11:
        return name
    return first if len(first) >= 4 else name[:11]


@renders("test")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    if env.dry_run:
        console.title("Local test (dry run)", data.get("role", ""))
        capability = data.get("would_run", {})
        console.info("proves", capability.get("what_it_proves", ""))
        console.info("credentials", "none needed" if not capability.get("requires_credentials") else "needed")
        console.info("network", "not needed" if not capability.get("requires_network") else "needed")
        return

    console.blank()
    for check in data.get("checks", []):
        (console.ok if check.get("passed") else console.fail)(_label(check), check.get("detail", ""))

    if "passed" in data:
        console.blank()
        if data["passed"]:
            console.ok("verified", data.get("summary", ""))
        else:
            console.fail("failed", data.get("summary", ""))

    identifiers = data.get("identifiers") or {}
    shown = [(k.replace("_", " "), v) for k, v in identifiers.items()
             if not isinstance(v, (dict, list)) and v is not None]
    if shown:
        console.blank()
        console.kv_block(shown, indent=6)

    task_ids = identifiers.get("task_ids")
    if isinstance(task_ids, list) and task_ids:
        console.blank()
        console.info("challenges", ", ".join(task_ids))
