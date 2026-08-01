"""`cathedral recover` — finish or undo an interrupted release transaction.

Recovery is explicit and locked. It re-verifies the retained signed release, every
generation's manifest, and the persisted authorization before committing a pending
group, or restores the prior committed group offline. Read-only commands only report
that recovery is required; they never perform it.
"""

from __future__ import annotations

from typing import Any

from cathedral_node import lockfile, paths
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.engines import installer
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("recover")
def recover(ctx: Context) -> Envelope:
    paths.ensure_layout()
    lock = lockfile.load()
    if not paths.recovery_required():
        return Envelope.ok("recover", {"recovery_required": False, "detail": "nothing to recover"})
    if ctx.dry_run:
        env = Envelope.ok("recover", {"recovery_required": True,
                                      "detail": "an interrupted transaction would be recovered or rolled back"})
        env.dry_run = True
        return env
    ok, detail = installer.recover(lock)
    if not ok:
        return Envelope.fail("recover", C.E_ENGINE_INSTALL_FAILED, "recovery failed",
                             exit_code=Exit.UPSTREAM,
                             remediation=Remediation(summary=detail, command="cathedral status"))
    return Envelope.ok("recover", {"recovery_required": False, "recovered": True, "detail": detail})


@renders("recover")
def _render(console: Console, data: dict[str, Any], env: Envelope) -> None:
    if not data.get("recovery_required", False) and not data.get("recovered"):
        console.ok("recover", data.get("detail", "nothing to recover"))
        return
    if env.dry_run:
        console.info("recover", data["detail"])
        return
    console.ok("recovered", data.get("detail", "done"))
