"""`cathedral setup <role>` — install the signed release and write config.

A release always covers the whole node (compute + distill + validator), so setup
installs and activates the entire signed group in one transaction; the named role is
what its config and next steps are reported for. Idempotent: re-running the same
signed release is a no-op that still returns success.
"""

from __future__ import annotations

from typing import Any

from cathedral_node import config, engines, lockfile, paths, state
from cathedral_node.commands import _release
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.engines import installer
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("setup")
def setup(ctx: Context) -> Envelope:
    role = ctx.args.role
    lock = lockfile.load()
    if role not in lock.engines:
        return Envelope.fail("setup", C.E_UNKNOWN_ROLE, f"unknown role {role!r}", exit_code=Exit.USAGE,
                             remediation=Remediation(summary=f"Known roles: {', '.join(lockfile.ROLES)}.",
                                                     command="cathedral capabilities --json"))
    paths.ensure_layout()
    pin = lock.pin(role)
    # Read the current state under the lease. The install itself takes the
    # exclusive form of the same lock and re-verifies, so the lease is released
    # first rather than held across the transaction it would deadlock with.
    with installer.active_view(lock) as (states, group, _active_detail):
        engine = engines.load(role, lock, group)
    log_path = paths.logs_dir() / f"setup-{role}.log"

    # Read-only paths never recover; a mutating one refuses and points to recovery.
    if paths.recovery_required() and not ctx.dry_run:
        return Envelope.blocked("setup", C.E_ENGINE_INSTALL_FAILED,
                                "a previous release transaction was interrupted",
                                exit_code=Exit.NOT_READY,
                                remediation=Remediation(
                                    summary="Finish or undo it explicitly before installing again.",
                                    command="cathedral recover"))

    base_exec, parent_reason = installer.trusted_base_executable()
    if base_exec is None:
        return Envelope.blocked("setup", C.E_ENGINE_PARENT_UNSUPPORTED,
                                "engine installs require running the node under Python 3.11-3.13",
                                exit_code=Exit.NOT_READY,
                                remediation=Remediation(summary=parent_reason,
                                                        command=f"python3.11 cathedral setup {role}"),
                                detail={"reason": parent_reason})

    source, reason = _release.resolve(ctx)
    if source is None:
        return Envelope.blocked("setup", C.E_ENGINE_INSTALL_FAILED, "no signed release to install",
                                exit_code=Exit.NOT_READY,
                                remediation=Remediation(summary=reason,
                                                        command=f"cathedral setup {role} --release <bundle-dir>",
                                                        requires_operator=True))

    if ctx.dry_run:
        ok, vreason, bundle = installer.verify_bundle(source.bundle_dir, source.signers_path,
                                                      identity=source.identity, base_exec=base_exec)
        data = {"role": role, "release_verified": ok, "detail": vreason or "ok",
                "release_version": bundle.authorization.release_version if bundle else None,
                "signer": source.identity, "source": str(source.bundle_dir),
                "current": states[role].to_dict()}
        env = Envelope.ok("setup", data)
        env.data_schema = schema_id("setup")
        env.dry_run = True
        return env

    ctx.console.title(f"Installing the signed release for {engine.title}", source.identity)
    events: list[dict[str, Any]] = []

    def progress(label: str, detail: str) -> None:
        ctx.console.progress(label, detail)
        events.append(state.emit_event(ctx.run_id, "SETUP", stage=label, detail=detail))

    ok, detail, result = installer.install_release(source.bundle_dir, lock, source.signers_path,
                                                   identity=source.identity, on_progress=progress,
                                                   log_path=log_path)
    if not ok:
        return Envelope.fail("setup", C.E_ENGINE_INSTALL_FAILED,
                             "could not install the signed release",
                             exit_code=Exit.UPSTREAM,
                             remediation=Remediation(summary=detail,
                                                     command=f"cathedral setup {role} --release <bundle-dir>",
                                                     docs=f"Full output: {paths.relative_to_home(log_path)}",
                                                     requires_operator=True),
                             detail={"reason": detail, "log": str(log_path)})

    # Seed configuration for the named role so `config show` is never empty.
    cfg = config.load(role)
    config.save(role, cfg)
    if role == "validator":
        # Writing the engine's TOML reads the verified source tree, so it happens
        # inside a fresh lease over the group the transaction just committed.
        with installer.active_view(lock) as (_states, _g, _d):
            engines.load(role, lock, _g).write_engine_config(cfg)

    # Re-read once, after the transaction, through one verification held for the
    # whole of the qualification that follows it.
    with installer.active_view(lock) as (after, after_group, _after_detail):
        installed = after[role]
        engine = engines.load(role, lock, after_group)
        qualification = engine.qualify(cfg)
    data = {
        "role": role, "installed": installed.to_dict(), "release": result,
        "roles": {r: after[r].to_dict() for r in lockfile.ROLES},
        "config_file": str(paths.config_file(role)), "config_problems": config.validate(role, cfg),
        "can_local_test": qualification.can_local_test, "can_operate": qualification.can_operate,
        "blockers": qualification.blockers, "notes": qualification.notes, "detail": detail,
    }
    env = Envelope.ok("setup", data)
    env.data_schema = schema_id("setup")
    if qualification.can_local_test:
        env.then("Verify it works here, paying nothing", f"cathedral test {role}")
    for blocker in qualification.blockers:
        if blocker.get("fix"):
            env.then(blocker["what"], blocker["fix"])
    env.then("Get an instruction block for a coding agent", f"cathedral agent-brief {role}")
    return env


@renders("setup")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    if env.dry_run:
        console.title("Setup (dry run)", data["role"])
        console.info("release", f"v{data['release_version']} by {data['signer']}"
                     if data.get("release_version") else "not verified")
        console.ok("verified", data["detail"]) if data["release_verified"] else console.fail("verify", data["detail"])
        console.info("source", data["source"])
        return
    installed = data["installed"]
    release = data.get("release", {})
    console.blank()
    console.ok("installed", f"release v{release.get('release_version')} at {installed['short_revision']}")
    console.info("signed by", release.get("signer_identity", "?"))
    for other, st in data.get("roles", {}).items():
        console.info(other, "active" if st["installed"] else "not active")
    console.info("config", data["config_file"])
    for problem in data["config_problems"]:
        console.warn("config", problem)
    for note in data["notes"]:
        console.note(note, indent=6)
    console.blank()
    console.ok("local test", "ready") if data["can_local_test"] else console.info("local test", "blocked")
    console.ok("live operation", "ready") if data["can_operate"] else console.info(
        "live operation", "needs more setup")
