"""`cathedral doctor` — can this machine and identity do the work?

Answers the question an operator actually has, which is not "is my Python new
enough" but "will this work, and if not, what do I do". Every failed check
carries the command that fixes it; every check that no command can fix says so
explicitly, so an agent stops instead of retrying forever.
"""

from __future__ import annotations

from typing import Any

from cathedral_node import config, engines, lockfile, machine, paths
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.engines import installer
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("doctor")
def doctor(ctx: Context) -> Envelope:
    role = getattr(ctx.args, "role", None)
    lock = lockfile.load()
    roles = [role] if role else list(lockfile.ROLES)

    checks: list[dict[str, Any]] = []

    # --- the machine itself, which every role shares --------------------------
    interpreter = machine.python_probe()
    checks.append(_check("python", interpreter, required=True,
                         fix="Install Python 3.11, 3.12, or 3.13 and re-run.",
                         code=C.E_PYTHON_TOO_OLD))
    checks.append(_check("platform", machine.os_probe(), required=False,
                         fix="Linux is the supported host for real operation. "
                             "Local tests run anywhere.",
                         code=C.E_PLATFORM_UNSUPPORTED))
    checks.append(_check("cpu", machine.cpu_probe(), required=True,
                         fix="At least two logical cores are needed.",
                         code=C.E_MEMORY_LOW))
    checks.append(_check("memory", machine.memory_probe(), required=False,
                         fix="4 GB or more is recommended.", code=C.E_MEMORY_LOW))
    checks.append(_check("disk", machine.disk_probe(paths.home()), required=True,
                         fix="Free disk space, or use a larger CATHEDRAL_HOME.",
                         code=C.E_DISK_LOW))
    checks.append(_check("git", machine.tool_probe("git", required=True,
                                                   purpose="needed to fetch pinned engines"),
                         required=True, fix="Install git.", code=C.E_TOOL_MISSING))
    checks.append(_check("network", machine.network_probe(), required=False,
                         fix="Local tests work offline. Live operation needs the feed.",
                         code=C.E_NETWORK))

    for problem in config.secrets_file_problems():
        checks.append({
            "name": "secret store", "verdict": "no", "required": True, "passed": False,
            "detail": problem, "code": str(C.E_SECRET_UNSAFE_SOURCE),
            "fix": f"chmod 600 {paths.secrets_file()}", "requires_operator": False,
        })

    # --- per role ---------------------------------------------------------------
    # `qualify()` runs installed code, so the lease stays held for the whole sweep.
    with installer.active_view(lock) as (states, group, _active_detail):
        return _diagnose(ctx, lock, roles, checks, states, group)


def _diagnose(ctx: Context, lock, roles, checks, states, group) -> Envelope:
    role_reports: dict[str, Any] = {}
    for name in roles:
        engine = engines.load(name, lock, group)
        installed = states[name]
        cfg = config.load(name)
        problems = config.validate(name, cfg)
        qualification = engine.qualify(cfg)

        role_checks: list[dict[str, Any]] = [
            {
                "name": "engine",
                "verdict": "yes" if installed.installed and not installed.drift else "no",
                "required": True,
                "passed": installed.installed and not installed.drift,
                "detail": (
                    f"{lock.pin(name).distribution} at {installed.revision[:12]}"
                    if installed.installed and installed.revision
                    else "not installed"
                )
                + (" — differs from the pinned revision" if installed.drift else ""),
                "code": str(C.E_ENGINE_REVISION_DRIFT if installed.drift else C.E_ENGINE_NOT_INSTALLED),
                "fix": f"cathedral setup {name}",
                "requires_operator": False,
            }
        ]
        for problem in problems:
            role_checks.append({
                "name": f"{name} configuration", "verdict": "no", "required": True, "passed": False,
                "detail": problem, "code": str(C.E_CONFIG_INVALID),
                "fix": f"cathedral config set {name} <field> <value>", "requires_operator": False,
            })
        for blocker in qualification.blockers:
            # The engine reports "not installed" as a blocker too. Reporting it
            # again here would show the operator the same problem twice with two
            # different wordings, which reads like two problems.
            if blocker.get("code") == str(C.E_ENGINE_NOT_INSTALLED):
                continue
            # A blocker that stops live operation but not the local test is a
            # different severity from one that stops everything, and rendering
            # both with the same mark told the operator they were equal.
            blocks = blocker.get("blocks", [])
            stops_everything = "local_test" in blocks
            role_checks.append({
                "name": _blocker_label(blocker),
                "verdict": "no",
                "required": stops_everything,
                "passed": False,
                "blocks_local_test": stops_everything,
                "detail": blocker.get("what", ""),
                "code": blocker.get("code", ""),
                "fix": blocker.get("fix"),
                "requires_operator": bool(blocker.get("requires_operator")),
                "blocks": blocker.get("blocks", []),
            })

        role_reports[name] = {
            "role": name,
            "title": engine.title,
            "can_local_test": qualification.can_local_test,
            "can_operate": qualification.can_operate,
            "notes": qualification.notes,
            "checks": role_checks,
            "engine": installed.to_dict(),
        }

    hardware = {
        "tdx": machine.tdx_probe().to_dict(),
        "gpu": machine.gpu_probe().to_dict(),
        "container_runtime": machine.container_runtime_probe().to_dict(),
    }

    blocking = [c for c in checks if c["required"] and not c["passed"]]
    ready_roles = [r for r, report in role_reports.items() if report["can_local_test"]]

    data = {
        "machine": machine.summary(),
        "home": str(paths.home()),
        "checks": checks,
        "hardware": hardware,
        "roles": role_reports,
        "ready_for_local_test": ready_roles,
        "blocking_count": len(blocking),
    }

    if blocking:
        first = blocking[0]
        env = Envelope.blocked(
            "doctor",
            first.get("code") or C.E_TOOL_MISSING,
            f"{first['name']}: {first['detail']}",
            exit_code=Exit.NOT_READY,
            remediation=Remediation(
                summary=f"{len(blocking)} check(s) must pass before anything can run.",
                command=first.get("fix"),
                requires_operator=bool(first.get("requires_operator")),
            ),
        )
        env.data = data
        env.data_schema = schema_id("doctor")
        return env

    env = Envelope.ok("doctor", data)
    env.data_schema = schema_id("doctor")
    if not ready_roles:
        env.warn("doctor.no_role_ready", "No role can run a local test yet. Run `cathedral setup <role>`.")
    else:
        for name in ready_roles:
            env.then(f"Run the {name} local test", f"cathedral test {name}")
    return env


_BLOCKER_LABELS = {
    "identity.hotkey_missing": "hotkey",
    "hardware.no_tdx": "intel tdx",
    "config.field_required": "config",
    "install.engine_missing": "engine",
    "install.revision_drift": "engine",
}


def _blocker_label(blocker: dict[str, Any]) -> str:
    """A short column label. The full sentence goes in the value, so the two
    columns say different things instead of repeating one another."""
    return _BLOCKER_LABELS.get(str(blocker.get("code", "")), "blocked")


def _check(name: str, probe: machine.Probe, *, required: bool, fix: str, code: str) -> dict[str, Any]:
    passed = probe.verdict == "yes" or (probe.verdict == "unknown" and not required)
    return {
        "name": name,
        "verdict": probe.verdict,
        "required": required,
        "passed": passed,
        "detail": probe.detail,
        "code": str(code) if not passed else None,
        "fix": fix if not passed else None,
        "requires_operator": False,
    }


@renders("doctor")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.title("Machine check",
                  console.join(data["machine"]["system"], "python " + data["machine"]["python"]))

    for check in data["checks"]:
        line = check["detail"]
        if check["passed"]:
            console.ok(check["name"], line)
        elif check["required"]:
            console.fail(check["name"], line)
        else:
            console.warn(check["name"], line)

    hardware = data["hardware"]
    console.blank()
    console.rule("confidential compute")
    for label, key in (("intel tdx", "tdx"), ("nvidia gpu", "gpu"), ("container", "container_runtime")):
        probe = hardware[key]
        glyph = {"yes": console.ok, "no": console.info, "unknown": console.info}[probe["verdict"]]
        glyph(label, probe["detail"])

    for role, report in data["roles"].items():
        console.blank()
        console.rule(f"{report['title'].lower()}")
        for check in report["checks"]:
            if check["passed"]:
                console.ok(check["name"], check["detail"])
            elif check.get("required", True):
                console.fail(check["name"], check["detail"])
            else:
                # Needed to go live, not to test locally. Marking it ✗ next to a
                # genuine blocker said the two were equally in the way.
                console.warn(check["name"], check["detail"] + " (needed to go live)")
            if not check["passed"]:
                if check.get("fix"):
                    console.command(check["fix"], indent=6)
                elif check.get("requires_operator"):
                    console.note("No command fixes this — it needs hardware or an operator decision.",
                                 indent=6)

        # Role notes belong to the role, not to whichever check printed last.
        if report["notes"]:
            console.blank()
            for note in report["notes"]:
                console.note(note, indent=4)

        console.blank()
        for label, able in (("local test", report["can_local_test"]), ("live", report["can_operate"])):
            (console.ok if able else console.info)(label, "ready" if able else "not ready")
