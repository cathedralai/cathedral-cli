"""`cathedral secret` — credentials, handled once, correctly.

A secret is only ever accepted on **stdin**. Not as an argument, because argv is
world-readable through ``ps``; not from an interactive prompt alone, because an
agent cannot drive one. ``cathedral secret set NAME --stdin`` works identically
for a human typing and a script piping.

Nothing here ever prints a stored value, including through an error message.
"""

from __future__ import annotations

import sys
from typing import Any

from cathedral_node import config, paths
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


@command("secret.list")
def secret_list(ctx: Context) -> Envelope:
    entries = config.describe_secrets()
    data = {
        "secrets": entries,
        "count": len(entries),
        "file": str(paths.secrets_file()),
        "permissions_ok": not config.secrets_file_problems(),
        "note": "Values are never printed. The fingerprint identifies a secret without revealing it.",
    }
    env = Envelope.ok("secret.list", data)
    env.data_schema = schema_id("secrets")
    for problem in config.secrets_file_problems():
        env.warn("secret.unsafe_permissions", problem)
    return env


@command("secret.set")
def secret_set(ctx: Context) -> Envelope:
    name = ctx.args.name

    if config.is_forbidden_secret(name):
        return Envelope.fail(
            "secret.set",
            C.E_COLDKEY_REFUSED,
            f"`{name}` names key material Cathedral never needs",
            exit_code=Exit.USAGE,
            remediation=Remediation(
                summary=(
                    "Cathedral never needs a coldkey, seed, mnemonic, or private key — not for "
                    "mining, not for validating. Nothing was stored, and stdin was not read."
                ),
                command="cathedral explain distill",
                requires_operator=True,
            ),
        )

    if not name.replace("_", "").isalnum() or not name.isupper():
        return Envelope.fail(
            "secret.set",
            C.E_USAGE,
            f"`{name}` is not a valid secret name",
            exit_code=Exit.USAGE,
            remediation=Remediation(
                summary="Use an uppercase environment-variable name, e.g. DISTILL_API_KEY.",
                command="cathedral secret set DISTILL_API_KEY --stdin",
            ),
        )

    if sys.stdin.isatty() and not getattr(ctx.args, "stdin", False):
        return Envelope.blocked(
            "secret.set",
            C.E_SECRET_UNSAFE_SOURCE,
            "a secret is only read from stdin",
            exit_code=Exit.USAGE,
            remediation=Remediation(
                summary=(
                    "Passing a credential as an argument would put it in your shell history and in "
                    "`ps` output for every user on this host."
                ),
                command=f"printf '%s' \"$MY_KEY\" | cathedral secret set {name} --stdin",
            ),
        )

    value = sys.stdin.read().strip()
    if not value:
        return Envelope.fail(
            "secret.set",
            C.E_SECRET_MISSING,
            "stdin was empty, so nothing was stored",
            exit_code=Exit.USAGE,
            remediation=Remediation(
                summary="Provide the value on stdin.",
                command=f"printf '%s' \"$MY_KEY\" | cathedral secret set {name} --stdin",
            ),
        )

    if ctx.dry_run:
        env = Envelope.ok("secret.set", {"name": name, "written": False,
                                         "would_store_bytes": len(value)})
        env.data_schema = schema_id("secrets")
        env.dry_run = True
        return env

    from cathedral_node.redact import fingerprint

    config.set_secret(name, value)
    data = {
        "name": name,
        "written": True,
        "fingerprint": fingerprint(value),
        "file": str(paths.secrets_file()),
        "mode": "0600",
    }
    env = Envelope.ok("secret.set", data)
    env.data_schema = schema_id("secrets")
    env.then("Point a configuration field at it",
             f"cathedral config set distill api_key_secret {name}")
    return env


@command("secret.remove")
def secret_remove(ctx: Context) -> Envelope:
    name = ctx.args.name
    if ctx.dry_run:
        env = Envelope.ok("secret.remove", {"name": name, "removed": False})
        env.dry_run = True
        return env
    removed = config.delete_secret(name)
    if not removed:
        return Envelope.fail(
            "secret.remove", C.E_SECRET_MISSING, f"no secret named {name} is stored",
            exit_code=Exit.NOT_FOUND,
            remediation=Remediation(summary="List what is stored.", command="cathedral secret list"),
        )
    env = Envelope.ok("secret.remove", {"name": name, "removed": True})
    env.data_schema = schema_id("secrets")
    return env


@renders("secret.list")
def _render_list(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.title("Secrets", data["file"])
    if not data["secrets"]:
        console.blank()
        console.info("stored", "none")
        console.note("Store one with: printf '%s' \"$MY_KEY\" | cathedral secret set MY_KEY --stdin",
                     indent=6)
        return
    console.blank()
    console.table(
        ["name", "fingerprint"],
        [[s["name"], s["fingerprint"]] for s in data["secrets"]],
        indent=4,
    )
    console.blank()
    console.note(data["note"], indent=4)


@renders("secret.set")
def _render_set(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.blank()
    if not data.get("written"):
        console.info("would store", data["name"])
        return
    console.ok("stored", console.join(data["name"], data["fingerprint"]))
    console.info("file", f"{data['file']} (mode {data['mode']})")
