"""`cathedral capabilities` — what this node can actually do, right now.

The discovery endpoint. An agent calls this first: it learns the protocol
version, the command surface, the exit codes, and — importantly — which
operations are genuinely available on this machine versus which need hardware,
credentials, or an owner decision it cannot supply.

Honest capability reporting means a capability is only ``available: true`` when
running it here would work. "Implemented upstream" is not "available".
"""

from __future__ import annotations

from typing import Any

from cathedral_node import config, engines, lockfile, machine, paths
from cathedral_node.contracts import Envelope
from cathedral_node.contracts.codes import Exit, describe, retryable
from cathedral_node.contracts.version import (
    CAPABILITIES_SCHEMA,
    EVENT_SCHEMA,
    PROTOCOL_VERSION,
    RESULT_SCHEMA,
    schema_id,
)
from cathedral_node.engines import installer
from cathedral_node.runner import Context, command, registry
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("capabilities")
def capabilities(ctx: Context) -> Envelope:
    lock = lockfile.load()

    # One verification, and the lease is held while every adapter is questioned:
    # `qualify()` and `capabilities()` run installed code, so they must not execute
    # after the lease that authorized those paths has been released.
    with installer.active_view(lock) as (states, group, _detail):
        engine_reports = _engine_reports(lock, states, group)
    return _envelope(ctx, lock, engine_reports)


def _engine_reports(lock, states, group) -> dict[str, Any]:
    engine_reports: dict[str, Any] = {}
    for role in lockfile.ROLES:
        engine = engines.load(role, lock, group)
        installed = states[role]
        cfg = config.load(role)
        qualification = engine.qualify(cfg)
        engine_reports[role] = {
            "title": engine.title,
            "tagline": engine.tagline,
            "installed": installed.to_dict(),
            "pinned": lock.pin(role).to_dict(),
            "can_local_test": qualification.can_local_test,
            "can_operate": qualification.can_operate,
            "capabilities": engine.capabilities(),
        }

    return engine_reports


def _envelope(ctx: Context, lock, engine_reports: dict[str, Any]) -> Envelope:
    """Build the public report after the verified engine lease is released."""

    data = {
        "protocol_version": PROTOCOL_VERSION,
        "schemas": {
            "result": RESULT_SCHEMA,
            "event": EVENT_SCHEMA,
            "capabilities": CAPABILITIES_SCHEMA,
        },
        "commands": sorted(registry()),
        "roles": list(lockfile.ROLES),
        "miner_roles": list(lockfile.MINER_ROLES),
        "exit_codes": {
            member.name.lower(): {
                "code": int(member),
                "meaning": describe(member),
                "retryable": retryable(member),
            }
            for member in Exit
        },
        "conventions": {
            "result_stream": "stdout",
            "diagnostic_stream": "stderr",
            "non_interactive": "every command runs unattended; --yes supplies any confirmation",
            "idempotent": ["setup", "config set", "secret set", "cleanup", "stop"],
            "resumable": ["mine", "validate"],
            "secrets": "never in argv, output, logs, or committed config",
        },
        "machine": machine.summary(),
        "home": str(paths.home()),
        "engines": engine_reports,
        "excluded": lock.excluded,
        "requires_owner_decision": _owner_gated(engine_reports),
    }

    env = Envelope.ok("capabilities", data)
    env.data_schema = CAPABILITIES_SCHEMA
    return env


def _owner_gated(reports: dict[str, Any]) -> list[dict[str, str]]:
    """Everything no command can unlock, collected in one place so an agent
    reads it once instead of discovering it three failures later."""
    gated = []
    for role, report in reports.items():
        for name, capability in report["capabilities"].items():
            if isinstance(capability, dict) and capability.get("requires_operator"):
                gated.append(
                    {
                        "role": role,
                        "capability": name,
                        "detail": capability.get("detail", ""),
                    }
                )
    return gated


@renders("capabilities")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.title("Capabilities", f"protocol {data['protocol_version']}")

    for role, report in data["engines"].items():
        console.blank()
        console.rule(report["title"].lower())
        console.para(report["tagline"], indent=4)
        console.blank()

        installed = report["installed"]
        if installed["installed"]:
            drift = " (differs from pin)" if installed["revision_drift"] else ""
            console.ok("engine", f"{installed['short_revision']}{drift}")
        else:
            console.info("engine", console.join("not installed", f"pinned at {report['pinned']['short_revision']}"))

        for name, capability in report["capabilities"].items():
            if not isinstance(capability, dict) or "available" not in capability:
                continue
            label = name.replace("_", " ")
            detail = capability.get("detail") or capability.get("what_it_proves", "")
            if capability["available"]:
                console.ok(label, detail or "available")
            elif capability.get("requires_operator"):
                console.info(label, detail or "needs an owner decision")
            else:
                console.info(label, detail or "not available here")

    if data["requires_owner_decision"]:
        console.blank()
        console.rule("needs an owner, not a command")
        for item in data["requires_owner_decision"]:
            console.info(item["role"], f"{item['capability'].replace('_', ' ')} — {item['detail']}")

    console.blank()
    console.rule("agent contract")
    console.kv_block(
        [
            ("protocol", data["protocol_version"]),
            ("result", data["schemas"]["result"] + " on stdout"),
            ("events", data["schemas"]["event"] + " on stderr and in each run directory"),
            ("commands", str(len(data["commands"]))),
        ],
        indent=4,
    )
