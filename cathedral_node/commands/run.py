"""`cathedral start|stop|resume|cancel` — the operating lifecycle.

Predictable startup, shutdown, interruption, and restart is a product feature
here, not an implementation detail:

* ``start`` takes the role lock, so a second start reports who holds it rather
  than racing.
* Ctrl-C or SIGTERM sends the engine a TERM, waits for it to flush, records the
  run as interrupted, and exits with ``CANCELLED``.
* ``resume`` continues from the recorded state; the engines already keep durable
  fences and journals, so this restarts them against the same run directory
  rather than inventing a checkpoint they do not have.
"""

from __future__ import annotations

import signal
from pathlib import Path
import threading
from typing import Any

from cathedral_node import config, engines, lockfile, paths, state
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.engines import installer
from cathedral_node.proc import stream
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("start")
def start(ctx: Context) -> Envelope:
    role = ctx.args.role

    # Checked before anything else, because it is unconditional. Reporting a
    # missing engine first would send an agent off to install one and only then
    # hit a wall no command can pass.
    if bool(getattr(ctx.args, "broadcast", False)):
        if role != "validator":
            return Envelope.fail(
                "start", C.E_USAGE, "--broadcast applies only to the validator",
                exit_code=Exit.USAGE,
                remediation=Remediation(summary="Remove --broadcast."),
            )
        return Envelope.blocked(
            "start",
            C.E_CHAIN_WRITES_REFUSED,
            "this node does not enable chain writes, with or without --yes",
            exit_code=Exit.UNSUPPORTED,
            remediation=Remediation(
                summary=(
                    "Weight submission needs a registered validator wallet with a permit and is an "
                    "owner decision, and it is gated behind Gate 6 of the launch specification. "
                    "There is deliberately no way to do it from here and no supported way around "
                    "this node: the single-publisher fence, the pending-attempt journal and the "
                    "signed authorization all live on this path, and an engine invoked directly "
                    "would hold none of them. Do not retry."
                ),
                docs="cathedral explain validator",
                requires_operator=True,
            ),
        )

    lock = lockfile.load()
    # The whole verify-to-launch sequence happens under the SHARED lifecycle lock,
    # against one sealed group. An install, update, recovery or rollback takes the
    # exclusive form of the same lock, so it cannot interleave; and the launch
    # itself revalidates the exact pointer, floor, trust root, lock, receipts and
    # managed tree before the first child starts.
    try:
        with installer.verified_active_group(lock) as active:
            return _start_verified(ctx, role, lock, active)
    except installer.ActiveStateError as exc:
        return Envelope.blocked(
            "start", C.E_ENGINE_NOT_INSTALLED,
            f"the {role} engine is not installed as a verified signed release",
            remediation=Remediation(summary=f"Nothing was started: {exc}",
                                    command=f"cathedral setup {role}"),
            detail={"reason": str(exc)},
        )
    except installer.InstallError as exc:
        return Envelope.blocked(
            "start", C.E_ALREADY_RUNNING, str(exc), exit_code=Exit.LOCKED,
            remediation=Remediation(summary="Nothing was started.", command="cathedral status"),
        )


def _start_verified(ctx: Context, role: str, lock, active) -> Envelope:
    engine = engines.load(role, lock, active.group)
    installed = installer.state_from_group(lock.pin(role), active.group)

    if not installed.installed:
        return Envelope.blocked(
            "start", C.E_ENGINE_NOT_INSTALLED, f"the {engine.title} engine is not installed",
            remediation=Remediation(summary="Nothing was started.", command=f"cathedral setup {role}"),
        )

    cfg = config.load(role)
    problems = config.validate(role, cfg)
    if problems:
        return Envelope.blocked(
            "start", C.E_CONFIG_INVALID, problems[0], exit_code=Exit.CONFIG_INVALID,
            remediation=Remediation(summary="Nothing was started.", command=f"cathedral config show {role}"),
            detail={"problems": problems},
        )

    qualification = engine.qualify(cfg)
    if not qualification.can_operate:
        blocker = next((b for b in qualification.blockers if "operate" in b.get("blocks", [])), {})
        return Envelope.blocked(
            "start",
            blocker.get("code", C.E_CONFIG_INVALID),
            f"this machine cannot operate {engine.title}: {blocker.get('what', 'a precondition is unmet')}",
            remediation=Remediation(
                summary="Nothing was started.",
                command=blocker.get("fix"),
                requires_operator=bool(blocker.get("requires_operator")),
            ),
            detail={"blockers": qualification.blockers},
        )


    holder = state.running_run(role)
    if holder is not None:
        return Envelope.blocked(
            "start",
            C.E_ALREADY_RUNNING,
            f"{engine.title} is already running",
            exit_code=Exit.LOCKED,
            remediation=Remediation(
                summary=f"Started at {holder.get('since')} as pid {holder.get('pid')}.",
                command=f"cathedral status {role}",
            ),
            detail={"pid": holder.get("pid"), "run_id": holder.get("run_id"), "since": holder.get("since")},
        )

    once = bool(getattr(ctx.args, "once", False))
    argv = engine.operate_argv(cfg, dry_run=ctx.dry_run)
    if once and role == "validator" and "--once" not in argv:
        argv.append("--once")

    if ctx.dry_run:
        env = Envelope.ok("start", {
            "role": role,
            "would_run": _safe_argv(argv),
            "secrets_supplied": sorted(engine.operate_env(cfg)),
            "broadcast": False,
            "touches_chain": role == "validator" and not ctx.dry_run,
        })
        env.data_schema = schema_id("start")
        env.dry_run = True
        return env

    record = state.create_run(ctx.run_id, role, "operate", f"{engine.title} running")
    env_extra = engine.operate_env(cfg)
    log_path = paths.run_dir(ctx.run_id) / "engine.log"

    ctx.console.title(f"{engine.title} running", f"run {ctx.run_id}")
    if role == "validator":
        ctx.console.info("chain", "dry run — no weights are submitted")
    ctx.console.info("stop", "ctrl-c, or `cathedral stop " + role + "` from another terminal")
    ctx.console.blank()

    state.emit_event(ctx.run_id, "STARTED", stage="start", detail=engine.title,
                     fields={"role": role, "engine_revision": installed.revision})

    stop_flag = threading.Event()
    counters = {"events": 0, "failures": 0}

    def on_line(line: str) -> None:
        interpreted = engine.interpret_line(line)
        if interpreted is None:
            return
        counters["events"] += 1
        if interpreted.get("status") in ("FAIL", "ERROR"):
            counters["failures"] += 1
        state.emit_event(
            ctx.run_id,
            interpreted["event"],
            stage=interpreted.get("stage", ""),
            status=interpreted.get("status", "INFO"),
            detail=interpreted.get("detail", ""),
        )
        if ctx.json_mode:
            return
        if interpreted.get("passthrough"):
            ctx.console.write(interpreted["detail"])
        else:
            status = interpreted.get("status", "INFO")
            label = interpreted["event"].lower()[:11]
            if status == "PASS":
                ctx.console.ok(label, interpreted.get("detail", ""))
            elif status in ("FAIL", "ERROR"):
                ctx.console.fail(label, interpreted.get("detail", ""))
            else:
                ctx.console.info(label, interpreted.get("detail", ""))

    def on_term(_signum: int, _frame: Any) -> None:
        stop_flag.set()

    try:
        previous_term = signal.signal(signal.SIGTERM, on_term)
    except ValueError:
        previous_term = None

    verified = active.group.role(role)

    # The validator is the only role that can ever publish, so it is the only role
    # that takes the publisher fence — and it takes it BEFORE the child starts and
    # holds it until the owned process group is proven gone. The role lock is a
    # per-home singleton; the fence is keyed by (network, netuid, validator hotkey)
    # in a host-wide location, so two CATHEDRAL_HOMEs configured for the same
    # on-chain identity contend for the same fence instead of both running.
    #
    # Honest scope: this is a host-wide fence. Revision 5's remote linearizable
    # lease and fencing token — the thing that makes "exactly one publisher"
    # true across HOSTS — is Gate 3 work and is NOT implemented here.
    fence = None
    if role == "validator":
        identity_netuid = cfg.get("netuid")
        identity_hotkey = cfg.get("wallet_hotkey") or cfg.get("hotkey") or ""
        fence = state.PublisherFence(int(identity_netuid or 0),
                                     f"{cfg.get('network', 'unknown')}:{identity_hotkey}",
                                     run_id=ctx.run_id)
        try:
            fence.acquire()
        except state.PublisherBusy as busy:
            return Envelope.blocked(
                "start", C.E_ALREADY_RUNNING,
                "another validator is already publishing for this identity",
                exit_code=Exit.LOCKED,
                remediation=Remediation(
                    summary=(f"The publisher fence for {busy.identity} is held by pid {busy.pid} "
                             f"since {busy.since}. Exactly one publisher may exist for a "
                             f"(network, netuid, hotkey); nothing was started."),
                    command=f"cathedral status {role}"),
                detail={"identity": busy.identity, "pid": busy.pid})

    try:
        with state.RoleLock(role, ctx.run_id) as role_lock:
            # Recorded BEFORE the child can exist. A launcher killed between the
            # spawn and the publication would otherwise leave a record saying no
            # child was ever started, while one is running.
            role_lock.begin_spawn(generation=verified.generation,
                                  lock_digest=active.group.lock_digest)

            def own(child) -> None:
                # Durable ownership — child pid, process group, kernel start
                # identity, euid, verified generation — is on disk before the first
                # line of output is read. Recording it later leaves a window in
                # which a crash orphans a running child nobody has a record of, and
                # a second `start` would then be allowed.
                role_lock.claim_child(child.pid, generation=verified.generation,
                                      lock_digest=active.group.lock_digest)

            # Revalidate, then launch. Everything in `argv` came from the sealed
            # VerifiedRole, so a pointer swap cannot change *what* runs — and this
            # call means it cannot let anything run at all. The child inherits
            # nothing: `child_env` is the fixed signed-child allowlist plus exactly
            # the role secrets this adapter resolved.
            result = active.launch(stream, argv, on_line=on_line,
                                   inherit_env=False, env=engine.child_env(cfg),
                                   log_path=log_path, stop=stop_flag, on_start=own,
                                   bind_program=Path(argv[0]))
            # `stream` returns only after waiting on the child, so its exit status
            # has been collected. That reaping — not an empty process group — is
            # what proves this launch is finished and lets the lease close.
            role_lock.child_reaped()
    except installer.ActiveStateError as exc:
        state.finish_run(record, "failed", int(Exit.NOT_READY), str(exc))
        state.emit_event(ctx.run_id, "START_REFUSED", stage="verify", status="FAIL", detail=str(exc))
        return Envelope.blocked(
            "start", C.E_ENGINE_NOT_INSTALLED,
            "the active release changed after verification; nothing was started",
            exit_code=Exit.NOT_READY,
            remediation=Remediation(summary=str(exc), command="cathedral status"),
            run_id=ctx.run_id, detail={"reason": str(exc)},
        )
    except (state.OwnershipLost, state.LedgerError) as exc:
        # The durable claim behind this launch could not be established or was taken
        # away. No child has been spawned at this point, and none may be: a process
        # with no durable record is one nothing can later prove is running.
        state.finish_run(record, "failed", int(Exit.NOT_READY), str(exc))
        state.emit_event(ctx.run_id, "START_REFUSED", stage="claim", status="FAIL", detail=str(exc))
        return Envelope.blocked(
            "start", C.E_ALREADY_RUNNING, "the launch could not be durably claimed",
            exit_code=Exit.NOT_READY,
            remediation=Remediation(summary=f"Nothing was started: {exc}",
                                    command=f"cathedral status {role}"),
            run_id=ctx.run_id, detail={"reason": str(exc)},
        )
    except state.LockHeld as held:
        return Envelope.blocked(
            "start", C.E_ALREADY_RUNNING, f"{engine.title} is already running",
            exit_code=Exit.LOCKED,
            remediation=Remediation(summary=f"Held by pid {held.pid} since {held.since}.",
                                    command=f"cathedral status {role}"),
            detail={"pid": held.pid, "run_id": held.run_id},
        )
    except KeyboardInterrupt:
        state.finish_run(record, "interrupted", int(Exit.CANCELLED), "stopped by the operator")
        state.emit_event(ctx.run_id, "INTERRUPTED", stage="stop", status="INFO",
                         detail="stopped by the operator")
        env = Envelope.fail(
            "start", C.E_RUN_INTERRUPTED, "stopped by the operator", exit_code=Exit.CANCELLED,
            remediation=Remediation(summary="State was flushed before exit.",
                                    command=f"cathedral resume {ctx.run_id}"),
            run_id=ctx.run_id,
        )
        env.data = {"role": role, "events": counters["events"], "run_dir": str(paths.run_dir(ctx.run_id))}
        env.data_schema = schema_id("start")
        return env
    finally:
        if previous_term is not None:
            try:
                signal.signal(signal.SIGTERM, previous_term)
            except ValueError:
                pass
        if fence is not None:
            # Held until the owned process group is provably gone: releasing while a
            # descendant still runs would let a second publisher start beside it.
            _release_fence_when_group_is_gone(fence, role, ctx.run_id)

    stopped_by_signal = stop_flag.is_set()
    data = {
        "role": role,
        "engine_revision": installed.revision,
        "events": counters["events"],
        "failures": counters["failures"],
        "exit_code": result.returncode,
        "duration_ms": result.duration_ms,
        "run_dir": str(paths.run_dir(ctx.run_id)),
        "log": str(log_path),
        "stopped_by_operator": stopped_by_signal,
    }

    if stopped_by_signal:
        state.finish_run(record, "interrupted", int(Exit.CANCELLED), "stopped on request")
        env = Envelope.fail("start", C.E_RUN_INTERRUPTED, "stopped on request",
                            exit_code=Exit.CANCELLED,
                            remediation=Remediation(summary="State was flushed before exit.",
                                                    command=f"cathedral resume {ctx.run_id}"),
                            run_id=ctx.run_id)
        env.data, env.data_schema = data, schema_id("start")
        return env

    if result.returncode != 0:
        state.finish_run(record, "failed", int(Exit.UPSTREAM), f"engine exited {result.returncode}")
        state.emit_event(ctx.run_id, "ENGINE_FAILED", stage="run", status="FAIL",
                         detail=f"exit {result.returncode}")
        env = Envelope.fail(
            "start", C.E_UPSTREAM_FAILED, f"the {engine.title} engine exited {result.returncode}",
            exit_code=Exit.UPSTREAM,
            remediation=Remediation(summary="The engine stopped on its own.",
                                    command=f"cathedral logs {role} --run {ctx.run_id} --raw"),
            run_id=ctx.run_id,
        )
        env.data, env.data_schema = data, schema_id("start")
        return env

    state.finish_run(record, "completed", 0, f"{counters['events']} events")
    state.emit_event(ctx.run_id, "STOPPED", stage="stop", status="INFO", detail="engine exited cleanly")
    env = Envelope.ok("start", data, run_id=ctx.run_id)
    env.data_schema = schema_id("start")
    return env


@command("stop")
def stop(ctx: Context) -> Envelope:
    role = ctx.args.role
    holder = state.running_run(role)
    if holder is None:
        return Envelope.ok("stop", {"role": role, "was_running": False, "detail": "not running"})

    if ctx.dry_run:
        env = Envelope.ok("stop", {"role": role, "was_running": True, "would_stop_pid": holder["pid"]})
        env.dry_run = True
        return env

    stopped, detail = state.stop_role(role)
    data = {"role": role, "was_running": True, "stopped": stopped, "detail": detail,
            "pid": holder.get("pid"), "run_id": holder.get("run_id")}
    if not stopped:
        return Envelope.fail(
            "stop", C.E_NOT_RUNNING, f"could not stop {role}: {detail}", exit_code=Exit.WORK_FAILED,
            remediation=Remediation(summary=detail, command=f"cathedral status {role}"),
            detail=data,
        )
    env = Envelope.ok("stop", data)
    env.data_schema = schema_id("stop")
    return env


@command("resume")
def resume(ctx: Context) -> Envelope:
    run_id = ctx.args.run
    record = state.load_run(run_id)
    if record is None:
        return Envelope.fail(
            "resume", C.E_RUN_NOT_FOUND, f"no run named {run_id}", exit_code=Exit.NOT_FOUND,
            remediation=Remediation(summary="List recent runs.", command="cathedral status"),
        )
    record = state.reconcile(record)

    if record.status == "running":
        return Envelope.blocked(
            "resume", C.E_ALREADY_RUNNING, f"{run_id} is still running", exit_code=Exit.LOCKED,
            remediation=Remediation(summary=f"pid {record.pid}", command=f"cathedral logs --run {run_id} -f"),
        )
    if record.status == "completed":
        return Envelope.ok("resume", {"run_id": run_id, "status": "completed",
                                      "detail": "nothing to resume"})

    if ctx.dry_run:
        env = Envelope.ok("resume", {"run_id": run_id, "role": record.role,
                                     "would_restart": True, "previous_status": record.status})
        env.dry_run = True
        return env

    # The engines keep their own durable fences and journals, so resuming is
    # starting them again against the same configuration and runtime root. This
    # is honest: the node is not claiming a checkpoint the engines do not have.
    env = Envelope.ok("resume", {
        "run_id": run_id,
        "role": record.role,
        "previous_status": record.status,
        "resumes_by": "restarting the engine against its durable state",
        "new_command": f"cathedral start {record.role}",
    })
    env.data_schema = schema_id("resume")
    env.then(f"Restart {record.role}", f"cathedral start {record.role}")
    return env


@command("cancel")
def cancel(ctx: Context) -> Envelope:
    run_id = ctx.args.run
    record = state.load_run(run_id)
    if record is None:
        return Envelope.fail(
            "cancel", C.E_RUN_NOT_FOUND, f"no run named {run_id}", exit_code=Exit.NOT_FOUND,
            remediation=Remediation(summary="List recent runs.", command="cathedral status"),
        )
    record = state.reconcile(record)
    if record.status != "running":
        return Envelope.ok("cancel", {"run_id": run_id, "status": record.status,
                                      "cancelled": False, "detail": "already finished"})
    if ctx.dry_run:
        env = Envelope.ok("cancel", {"run_id": run_id, "would_cancel": True})
        env.dry_run = True
        return env
    stopped, detail = state.stop_role(record.role)
    state.finish_run(record, "cancelled", int(Exit.CANCELLED), "cancelled by request")
    env = Envelope.ok("cancel", {"run_id": run_id, "cancelled": stopped, "detail": detail,
                                 "state_preserved": True})
    env.data_schema = schema_id("cancel")
    return env


def _release_fence_when_group_is_gone(fence, role: str, run_id: str = "",
                                      timeout: float = 30.0) -> None:
    """Hold the publisher fence until nothing from the owned process group is left.

    The fence is not about our own parent process exiting; it is about the identity
    no longer being served. A descendant that outlives the CLI is still a publisher,
    so the fence stays taken while it is alive.
    """
    import time as _time

    deadline = _time.monotonic() + timeout
    while True:
        # The lease, not the process group, decides. A descendant that called
        # `setsid()` is not in the group and would make the group look empty while
        # it is still serving the identity — and releasing on a *timeout* is worse
        # still: it hands the fence to a second publisher precisely in the case
        # where we failed to establish that the first one stopped.
        leases, problem = state.open_leases(role)
        if problem is None and not leases:
            fence.release()
            return
        if _time.monotonic() > deadline:
            # Fail closed. The fence is held by a descriptor this process owns, so
            # it is released when this process exits and not one moment before —
            # never on a timer, and never while a lease is open or unreadable.
            if run_id:
                state.emit_event(run_id, "FENCE_HELD", stage="stop", status="WARN",
                                 detail=(f"the {role} publisher fence is held until this process "
                                         f"exits: an unfinished launch lease remains"))
            return
        _time.sleep(0.1)


def _safe_argv(argv: list[str]) -> list[str]:
    """argv never carries a secret, but re-check before printing it anyway."""
    from cathedral_node.redact import redact_text

    return [redact_text(a) for a in argv]


@renders("start")
def _render_start(console: Console, data: dict[str, Any], env: Envelope) -> None:
    if env.dry_run:
        console.title("Start (dry run)", data["role"])
        console.blank()
        console.info("would run", " ".join(data["would_run"]))
        if data["secrets_supplied"]:
            console.info("secrets", ", ".join(data["secrets_supplied"]) + " (through the environment)")
        console.info("chain", "no")
        return
    console.blank()
    if data.get("stopped_by_operator"):
        console.info("stopped", "on request")
    console.info("events", str(data.get("events", 0)))
    if data.get("failures"):
        console.warn("failures", str(data["failures"]))
    console.info("logs", data.get("log", ""))


@renders("stop")
def _render_stop(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.blank()
    if not data["was_running"]:
        console.info(data["role"], "not running")
    elif data.get("stopped"):
        console.ok(data["role"], data["detail"])
    else:
        console.fail(data["role"], data["detail"])
