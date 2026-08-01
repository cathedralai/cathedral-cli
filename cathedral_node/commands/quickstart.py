"""`cathedral quickstart` — clean machine to verified local test.

The guided path. It is also fully non-interactive: `cathedral quickstart distill
--yes --json` performs the same steps unattended, so an agent and a human take
identical routes and reach identical state. There is no separate "interactive
mode" that does something the flags cannot.
"""

from __future__ import annotations

import sys
from typing import Any

from cathedral_node import config, engines, lockfile, machine, paths, state
from cathedral_node.commands import _release
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.engines import installer
from cathedral_node.engines import installer as _installer_state
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("quickstart")
def quickstart(ctx: Context) -> Envelope:
    lock = lockfile.load()
    role = getattr(ctx.args, "role", None)

    if role is None:
        return _choose(ctx, lock)

    engine = engines.load(role, lock)
    steps: list[dict[str, Any]] = []
    console = ctx.console

    console.title(console.join("Cathedral", engine.title), engine.tagline)

    # 1 — what this is
    explanation = engine.explain()
    console.blank()
    console.para(explanation["what_you_do"], indent=4)
    detail = explanation.get("how_you_are_scored") or explanation.get("what_you_verify")
    if isinstance(detail, list):
        detail = "You verify: " + "; ".join(detail).lower() + "."
    if detail:
        console.blank()
        console.note(detail, indent=4)

    # Before anything is installed, and before anyone can spend.
    #
    # These disclosures existed only in `cathedral explain <role>` — one command
    # sideways from the path this command pushes you down. Someone could reach
    # "your node works" having never seen that the track pays nothing today, or
    # that a Compute measurement must be approved before you buy the hardware.
    warning = explanation.get("before_you_spend")
    if warning:
        console.blank()
        console.rule("before you spend money")
        console.para(warning, indent=4)

    not_yet = [item for item in explanation.get("not_yet_true", []) if item]
    if not_yet:
        console.blank()
        console.rule("not yet true")
        console.bullets(not_yet, indent=4)

    steps.append({"step": "explain", "status": "ok", "disclosed": len(not_yet) + bool(warning)})

    # 2 — qualification
    console.blank()
    console.rule("1 · does this machine qualify")
    interpreter = machine.python_probe()
    if interpreter.verdict == "no":
        return _blocked(ctx, role, steps, C.E_PYTHON_TOO_OLD, interpreter.detail,
                        "Install Python 3.11-3.13 and run quickstart again.")
    console.ok("python", interpreter.detail)
    console.ok("home", str(paths.home()))
    steps.append({"step": "qualify", "status": "ok"})

    # 3 — install
    console.blank()
    console.rule("2 · install the pinned engine")
    pin = lock.pin(role)
    current = _installer_state.state(pin)
    if current.installed and not current.drift:
        console.ok("engine", f"already at {current.short_revision}")
        steps.append({"step": "install", "status": "skipped", "detail": "already installed"})
    elif ctx.dry_run:
        console.info("engine", f"would install {pin.short_revision}")
        steps.append({"step": "install", "status": "dry-run"})
    elif paths.recovery_required():
        return _blocked(ctx, role, steps, C.E_ENGINE_INSTALL_FAILED,
                        "a previous release transaction was interrupted; recover before installing",
                        "cathedral recover", exit_code=Exit.NOT_READY)
    else:
        source, reason = _release.resolve(ctx)
        if source is None:
            return _blocked(ctx, role, steps, C.E_ENGINE_INSTALL_FAILED, reason,
                            f"cathedral setup {role} --release <bundle-dir>", exit_code=Exit.NOT_READY)
        ok, detail, _ = installer.install_release(
            source.bundle_dir, lock, source.signers_path, identity=source.identity,
            on_progress=lambda label, note: console.progress(label, note),
            log_path=paths.logs_dir() / f"setup-{role}.log",
        )
        if not ok:
            return _blocked(ctx, role, steps, C.E_ENGINE_INSTALL_FAILED, detail,
                            f"cathedral setup {role} --release <bundle-dir>", exit_code=Exit.UPSTREAM)
        console.ok("engine", detail)
        steps.append({"step": "install", "status": "ok", "detail": detail})
        cfg_seed = config.load(role)
        config.save(role, cfg_seed)
        # Re-bind the adapter to the group that was just verified and committed,
        # inside a lease: writing the validator's engine TOML reads the verified
        # source tree, which must not happen after the lease is released.
        with _installer_state.active_view(lock) as (_states, group, _detail):
            engine = engines.load(role, lock, group)
            if role == "validator":
                engine.write_engine_config(cfg_seed)

    # 4 — configuration
    console.blank()
    console.rule("3 · configuration")
    cfg = config.load(role)
    problems = config.validate(role, cfg)
    missing_identity = role in lockfile.MINER_ROLES and not cfg.get("hotkey")
    if missing_identity:
        console.info("hotkey", "not set — the local test does not need one")
        console.command(f"cathedral config set {role} hotkey <your-ss58-address>", indent=6)
    for problem in problems:
        console.warn("config", problem)
    if not problems and not missing_identity:
        console.ok("config", paths.relative_to_home(paths.config_file(role)))
    steps.append({"step": "configure", "status": "ok", "problems": problems})

    # 5 — the verified local test
    console.blank()
    console.rule("4 · verified local test")
    if ctx.dry_run:
        console.info("test", "would run — pays nothing, touches no chain")
        steps.append({"step": "test", "status": "dry-run"})
        outcome = None
    else:
        run_id = ctx.run_id + "-test"
        record = state.create_run(run_id, role, "test", f"{engine.title} quickstart test")
        # The engine subprocess runs under a lease, revalidated immediately before
        # the child starts — exactly as `cathedral test` does. Quickstart is a
        # convenience wrapper, not a second, weaker execution path.
        try:
            with _installer_state.verified_active_group(lock) as lease:
                bound = engines.load(role, lock, lease.group)
                outcome = lease.launch(
                    bound.local_test, cfg, run_id,
                    progress=lambda label, note: console.progress(label, note),
                    timeout=600.0)
        except (_installer_state.ActiveStateError, _installer_state.InstallError) as exc:
            return _blocked(ctx, role, steps, C.E_ENGINE_NOT_INSTALLED, str(exc),
                            f"cathedral setup {role}", exit_code=Exit.NOT_READY)
        from cathedral_node.commands.test import _label

        for check in outcome.checks:
            (console.ok if check["passed"] else console.fail)(_label(check), check.get("detail", ""))
            state.emit_event(run_id, "CHECK", stage="verify",
                             status="PASS" if check["passed"] else "FAIL",
                             detail=f"{check['name']}: {check.get('detail','')}")
        state.finish_run(record, "completed" if outcome.passed else "failed",
                         0 if outcome.passed else int(Exit.VERIFY_FAILED), outcome.summary)
        steps.append({
            "step": "test", "status": "ok" if outcome.passed else "failed",
            "summary": outcome.summary, "run_id": run_id,
            "identifiers": outcome.identifiers,
        })
        console.blank()
        if outcome.passed:
            console.ok("verified", outcome.summary)
        else:
            console.fail("failed", outcome.summary)

    qualification = engine.qualify(cfg)
    # Say what was verified, not that the node is ready. For Compute the two are
    # very different: a policy gate passing on synthetic evidence is not a
    # working confidential VM, and reading it that way costs real money.
    verified_claim = (
        f"{outcome.summary[0].upper()}{outcome.summary[1:]}."
        if outcome and outcome.passed and outcome.summary
        else "The local test passed."
    )
    data = {
        "role": role,
        "steps": steps,
        "verified": bool(outcome and outcome.passed),
        "verified_claim": verified_claim,
        "can_operate": qualification.can_operate,
        "blockers": qualification.blockers,
        "notes": qualification.notes,
        "next_command": f"cathedral start {role}" if qualification.can_operate else f"cathedral doctor {role}",
    }

    if outcome is not None and not outcome.passed:
        env = Envelope.fail(
            "quickstart", outcome.failure_code or C.E_VERIFY_DIFFERENTIAL, outcome.summary,
            exit_code=Exit.VERIFY_FAILED,
            remediation=Remediation(summary="Setup completed but verification did not pass.",
                                    command=outcome.remediation or f"cathedral doctor {role}"),
        )
        env.data, env.data_schema = data, schema_id("quickstart")
        return env

    env = Envelope.ok("quickstart", data)
    env.data_schema = schema_id("quickstart")
    env.then("Read what this role pays for", f"cathedral explain {role}")
    if role in lockfile.MINER_ROLES and not cfg.get("hotkey"):
        env.then("Set the hotkey you want to be scored under",
                 f"cathedral config set {role} hotkey <your-ss58-address>")
    env.then("Get an instruction block for a coding agent", f"cathedral agent-brief {role}")
    if qualification.can_operate:
        env.then(f"Start {engine.title}", f"cathedral start {role}")
    else:
        env.then("See what live operation still needs", f"cathedral doctor {role}")
    return env


def _choose(ctx: Context, lock: lockfile.Lock) -> Envelope:
    """No role given. Present the three, with what each needs, and stop.

    Deliberately not an interactive menu: the choice has real consequences
    (Compute needs hardware you may have to buy), so it belongs to the operator,
    made explicitly, not to a default in a prompt.
    """
    options = []
    for role in lockfile.ROLES:
        engine = engines.load(role, lock)
        cfg = config.load(role)
        qualification = engine.qualify(cfg)
        explanation = engine.explain()
        options.append({
            "role": role,
            "title": engine.title,
            "tagline": engine.tagline,
            "needs": explanation.get("what_you_need", []),
            "can_local_test_now": qualification.can_local_test,
            "command": f"cathedral quickstart {role}",
        })

    console = ctx.console
    console.title("Cathedral", "one node · two ways to mine · one way to validate")
    for option in options:
        console.blank()
        console.rule(option["title"].lower())
        console.para(option["tagline"], indent=4)
        console.blank()
        console.bullets(option["needs"][:3], indent=6)
        console.blank()
        console.command(option["command"], indent=4)

    data = {"options": options, "chosen": None}
    env = Envelope.ok("quickstart", data)
    env.data_schema = schema_id("quickstart_choices")
    env.then("Read what a role does before installing anything", "cathedral explain <role>")
    env.then("Check what this machine can do", "cathedral doctor")
    return env


def _blocked(
    ctx: Context,
    role: str,
    steps: list[dict[str, Any]],
    code: str,
    detail: str,
    fix: str,
    exit_code: Exit = Exit.NOT_READY,
) -> Envelope:
    env = Envelope.blocked("quickstart", code, detail, exit_code=exit_code,
                           remediation=Remediation(summary="Quickstart stopped here.", command=fix))
    env.data = {"role": role, "steps": steps, "verified": False}
    env.data_schema = schema_id("quickstart")
    return env


@renders("quickstart")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    if data.get("chosen") is None and "options" in data:
        return  # already rendered above
    console.blank()
    if data.get("verified"):
        console.rule("done")
        console.blank()
        console.para(data.get("verified_claim", "The local test passed."), indent=4)
        console.para("Nothing was spent and nothing reached the chain.", indent=4)
    for note in data.get("notes", [])[:2]:
        console.note(note, indent=4)
