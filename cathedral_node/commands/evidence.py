"""`cathedral evidence <id>` — resolve any identifier this node emitted.

An agent that reported ``task_id synthvuln:1d8e7f60:2`` three hours ago can hand
that string back and get the run, the event, and the surrounding context. This
is what makes the identifiers in every envelope worth returning: they are
addressable, not decorative.
"""

from __future__ import annotations

from typing import Any

from cathedral_node import paths, state
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("evidence")
def evidence(ctx: Context) -> Envelope:
    needle = str(ctx.args.identifier)

    # A run id resolves directly.
    record = state.load_run(needle)
    if record is not None:
        record = state.reconcile(record)
        events = list(state.read_events(needle))
        data = {
            "identifier": needle,
            "kind": "run",
            "run": record.to_dict(),
            "matches": events,
            "match_count": len(events),
            "run_dir": paths.relative_to_home(paths.run_dir(needle)),
        }
        env = Envelope.ok("evidence", data)
        env.data_schema = schema_id("evidence")
        return env

    # Otherwise search every run's events and artifacts for the string.
    matches: list[dict[str, Any]] = []
    for candidate in state.list_runs(limit=500):
        for event in state.read_events(candidate.run_id):
            if _contains(event, needle):
                matches.append({"run_id": candidate.run_id, "role": candidate.role,
                                "event": event})
                if len(matches) >= 50:
                    break
        if len(matches) >= 50:
            break

    if not matches:
        return Envelope.fail(
            "evidence", C.E_EVIDENCE_MISSING,
            f"no run recorded the identifier {needle}",
            exit_code=Exit.NOT_FOUND,
            remediation=Remediation(
                summary="Identifiers are recorded per run and removed by `cathedral cleanup`.",
                command="cathedral status --limit 25",
            ),
        )

    runs = sorted({m["run_id"] for m in matches})
    data = {
        "identifier": needle,
        "kind": "identifier",
        "matches": matches,
        "match_count": len(matches),
        "runs": runs,
    }
    env = Envelope.ok("evidence", data)
    env.data_schema = schema_id("evidence")
    env.then("See the whole run", f"cathedral status --run {runs[0]}")
    return env


def _contains(value: Any, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, dict):
        return any(_contains(v, needle) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains(v, needle) for v in value)
    return False


@renders("evidence")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.title("Evidence", data["identifier"])
    if data["kind"] == "run":
        record = data["run"]
        console.blank()
        console.kv_block(
            [("role", record["role"]), ("kind", record["kind"]), ("status", record["status"]),
             ("started", record["started_at"]), ("events", data["match_count"])],
            indent=4,
        )
        return

    console.blank()
    console.info("found in", f"{data['match_count']} event(s) across {len(data['runs'])} run(s)")
    console.blank()
    console.table(
        ["run", "event", "detail"],
        [[m["run_id"], m["event"].get("event", ""), m["event"].get("detail", "")]
         for m in data["matches"][:12]],
        indent=4,
    )
