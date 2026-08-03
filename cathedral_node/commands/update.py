"""`cathedral update` and `cathedral rollback` — moving between signed releases.

Updates come only from a signed release bundle — a configured HTTPS channel or an
explicit ``--release <dir>`` — applied as one node-wide transaction that switches
the whole compute+distill+validator group atomically and rolls the group back on
any failure. There is no unsigned lockfile adoption. An interrupted transaction is
finished or undone by ``cathedral recover``; a deliberate rollback is a newly-signed
release at a higher version that selects the retained prior generation set, never a
local rebuild from revision history.
"""

from __future__ import annotations

from typing import Any

from cathedral_node import lockfile, paths, state
from cathedral_node.commands import _release
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.engines import installer

from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("update")
def update(ctx: Context) -> Envelope:
    if getattr(ctx.args, "to", None):
        return Envelope.fail(
            "update", C.E_CONFIG_INVALID,
            "unsigned lockfile updates are no longer supported; updates come from a signed release",
            exit_code=Exit.USAGE,
            remediation=Remediation(summary="Use a signed release channel or --release <bundle-dir>.",
                                    command="cathedral update --release <bundle-dir>", requires_operator=True))
    lock = lockfile.load()
    paths.ensure_layout()
    check_only = bool(getattr(ctx.args, "check", False)) or ctx.dry_run

    # One verification for the whole command; every consumer below reads it.
    current, _group, active_detail = installer.install_states(lock)
    current_version = next((s.release_version for s in current.values() if s.release_version), None)

    # Resolving a release may require nothing but a report (`--check`), so a missing
    # release source is only a hard block when actually applying.
    source, reason = _release.resolve(ctx)
    if source is None:
        data: dict[str, Any] = {"plan": [], "current_version": current_version,
                                "available_version": None, "release_source": None, "detail": reason,
                                "applied": False, "recovery_required": paths.recovery_required()}
        if check_only:
            env = Envelope.ok("update", data)
            env.data_schema = schema_id("update")
            env.dry_run = True
            return env
        return Envelope.blocked("update", C.E_ENGINE_INSTALL_FAILED, "no signed release available",
                                exit_code=Exit.NOT_READY,
                                remediation=Remediation(summary=reason,
                                                        command="cathedral update --release <bundle-dir>",
                                                        requires_operator=True))

    base_exec, parent_reason = installer.trusted_base_executable()
    if base_exec is None:
        return Envelope.blocked("update", C.E_ENGINE_PARENT_UNSUPPORTED, parent_reason,
                                exit_code=Exit.NOT_READY,
                                remediation=Remediation(summary=parent_reason,
                                                        command="python3.11 cathedral update"))

    ok, vreason, bundle = installer.verify_bundle(source.bundle_dir, source.signers_path,
                                                  identity=source.identity, base_exec=base_exec)
    if not ok or bundle is None:
        return Envelope.fail("update", C.E_ENGINE_INSTALL_FAILED, "the signed release did not verify",
                             exit_code=Exit.UPSTREAM,
                             remediation=Remediation(summary=vreason, command="cathedral status"))

    available = bundle.authorization.release_version
    plan = [{"role": r, "from_version": current[r].release_version, "to_version": available,
             "changes": (current[r].release_version != available) or not current[r].installed}
            for r in lockfile.ROLES]
    data = {"plan": plan, "current_version": current_version, "available_version": available,
            "signer": source.identity, "applied": False, "recovery_required": paths.recovery_required(),
            "active_release": active_detail}

    if check_only:
        env = Envelope.ok("update", data)
        env.data_schema = schema_id("update")
        env.dry_run = True
        if any(p["changes"] for p in plan):
            env.then("Apply this signed release", "cathedral update --yes")
        return env

    if paths.recovery_required():
        return Envelope.blocked("update", C.E_ENGINE_INSTALL_FAILED,
                                "a previous release transaction was interrupted", exit_code=Exit.NOT_READY,
                                remediation=Remediation(summary="Finish or undo it first.",
                                                        command="cathedral recover"))

    running = [r for r in lockfile.ROLES if state.running_run(r) is not None]
    if running:
        return Envelope.blocked("update", C.E_ALREADY_RUNNING,
                                f"{', '.join(running)} is running; nothing was changed", exit_code=Exit.LOCKED,
                                remediation=Remediation(summary="Stop running roles before updating.",
                                                        command=f"cathedral stop {running[0]}"), detail=data)

    if not any(p["changes"] for p in plan):
        data["applied"] = True
        env = Envelope.ok("update", data)
        env.data_schema = schema_id("update")
        return env

    if not ctx.assume_yes:
        return ctx.needs_confirmation("update", f"Applying signed release v{available}")

    ok, detail, result = installer.install_release(
        source.bundle_dir, lock, source.signers_path, identity=source.identity,
        on_progress=lambda label, note: ctx.console.progress(label, note),
        log_path=paths.logs_dir() / "update.log",
        revocation_channel=_release.channel(ctx))
    if not ok:
        # Do not claim the prior release "was kept": whether it was depends on
        # whether the rollback completed, and when it did not the node is left with
        # an interrupted transaction that `cathedral recover` still has to finish.
        pending = paths.recovery_required()
        message = ("the update failed and an interrupted transaction is still recorded"
                   if pending else "the update failed and the prior release was kept")
        data["recovery_required"] = pending
        return Envelope.fail("update", C.E_ENGINE_INSTALL_FAILED, message,
                             exit_code=Exit.UPSTREAM,
                             remediation=Remediation(
                                 summary=detail,
                                 command="cathedral recover" if pending else "cathedral status"),
                             detail=data)
    data.update({"applied": True, "result": result})
    env = Envelope.ok("update", data)
    env.data_schema = schema_id("update")
    env.then("Verify the engines", "cathedral test distill")
    return env


@command("rollback")
def rollback(ctx: Context) -> Envelope:
    paths.ensure_layout()
    lock = lockfile.load()

    # An interrupted transaction is undone by recovery (offline, no rebuild).
    if paths.recovery_required():
        if ctx.dry_run:
            env = Envelope.ok("rollback", {"recovery_required": True, "applied": False})
            env.data_schema = schema_id("rollback")
            env.dry_run = True
            return env
        if not ctx.assume_yes:
            return ctx.needs_confirmation("rollback", "Roll back the interrupted release")
        ok, detail = installer.recover(lock)
        if not ok:
            return Envelope.fail("rollback", C.E_ENGINE_INSTALL_FAILED, "rollback failed",
                                 exit_code=Exit.UPSTREAM,
                                 remediation=Remediation(summary=detail, command="cathedral status"))
        env = Envelope.ok("rollback", {"applied": True, "recovery_required": False, "detail": detail})
        env.data_schema = schema_id("rollback")
        return env

    # Otherwise a deliberate rollback is a newly-signed, higher-version release.
    active, _group, _detail = installer.install_states(lock)
    version = next((s.release_version for s in active.values() if s.release_version), None)
    data = {"applied": False, "active_version": version, "recovery_required": False}
    env = Envelope.ok("rollback", data)
    env.data_schema = schema_id("rollback")
    env.then("Roll back by installing a newer signed release that selects the prior generation set",
             "cathedral update --release <bundle-dir>")
    return env


@renders("update")
def _render_update(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.title("Update", f"signed by {data.get('signer', '?')}" if data.get("signer") else "")
    console.info("current", f"v{data.get('current_version')}" if data.get("current_version") else "none")
    console.info("available", f"v{data.get('available_version')}" if data.get("available_version") else "?")
    changing = [p["role"] for p in data.get("plan", []) if p.get("changes")]
    if data.get("applied"):
        console.ok("applied", "the signed release is active" if changing else "already up to date")
    elif changing:
        console.info("would change", ", ".join(changing))
    else:
        console.ok("up to date", "no change")


@renders("rollback")
def _render_rollback(console: Console, data: dict[str, Any], env: Envelope) -> None:
    if data.get("applied"):
        console.ok("rolled back", data.get("detail", "done"))
    elif data.get("recovery_required"):
        console.info("recovery", "an interrupted release would be rolled back")
    else:
        console.info("active", f"v{data.get('active_version')}" if data.get("active_version") else "none")
