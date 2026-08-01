"""`cathedral config` — read and write configuration safely.

Nothing here ever holds a credential. A field that needs one holds the *name* of
a secret, which is why ``cathedral config show`` is safe to run on a shared
screen or paste into an issue.
"""

from __future__ import annotations

import re
from typing import Any

from cathedral_node import config, engines, lockfile, paths
from cathedral_node import redact
from cathedral_node.engines import installer
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import schema_id
from cathedral_node.runner import Context, command
from cathedral_node.ui.console import Console
from cathedral_node.ui.render import renders


def _keep_public_fields_readable(role: str, values: dict[str, Any]) -> None:
    """Exempt ONLY the validator's `weight_policy_key` from value-shape redaction,
    and only when it is exactly 64 hex characters.

    The redaction backstop masks anything 64-hex-shaped, which would blank this
    PUBLIC 32-byte key in `--json` while the human view shows it — the operator is
    told to read and verify it. The exemption is deliberately narrow: exempting
    every non-secret field would leak an embedded credential, e.g. an `api_base`
    holding `https://host/?api_key=SECRET`. Requiring an exact 64-hex value means
    the exempted string cannot carry a credential, and no other field is touched.
    Known-secret values always take precedence over this (see redact.redact_value).
    """
    key = values.get("weight_policy_key")
    if isinstance(key, str) and re.fullmatch(r"[0-9a-fA-F]{64}", key):
        redact.register_public_values([key])


@command("config.show")
def config_show(ctx: Context) -> Envelope:
    roles = [ctx.args.role] if getattr(ctx.args, "role", None) else list(lockfile.ROLES)
    payload: dict[str, Any] = {}
    problems: dict[str, list[str]] = {}
    for role in roles:
        values = config.load(role)
        _keep_public_fields_readable(role, values)
        payload[role] = {
            "file": str(paths.config_file(role)),
            "exists": paths.config_file(role).exists(),
            "values": values,
        }
        found = config.validate(role, values)
        if found:
            problems[role] = found

    data = {
        "roles": payload,
        "problems": problems,
        "secrets_file": str(paths.secrets_file()),
        "note": "No credential is stored here. Secret-valued fields hold the name of a secret.",
    }
    env = Envelope.ok("config.show", data)
    env.data_schema = schema_id("config")
    if problems:
        env.warn("config.invalid", f"{sum(len(v) for v in problems.values())} configuration problem(s)")
    return env


@command("config.get")
def config_get(ctx: Context) -> Envelope:
    role, field = ctx.args.role, ctx.args.field
    values = config.load(role)
    _keep_public_fields_readable(role, values)
    if field not in values:
        return Envelope.fail(
            "config.get", C.E_CONFIG_FIELD_REQUIRED, f"`{field}` is not a {role} field",
            exit_code=Exit.NOT_FOUND,
            remediation=Remediation(summary="List the fields and what they mean.",
                                    command=f"cathedral config schema {role}"),
        )
    env = Envelope.ok("config.get", {"role": role, "field": field, "value": values[field]})
    env.data_schema = schema_id("config_value")
    return env


@command("config.set")
def config_set(ctx: Context) -> Envelope:
    role, field, raw = ctx.args.role, ctx.args.field, ctx.args.value

    if field.lower() in config.FORBIDDEN_FIELDS:
        return Envelope.fail(
            "config.set",
            C.E_COLDKEY_REFUSED,
            f"`{field}` is never accepted",
            exit_code=Exit.USAGE,
            remediation=Remediation(
                summary=(
                    "Cathedral never needs a coldkey, seed, or mnemonic. Configure a hotkey "
                    "address instead; if a service credential is needed, use `cathedral secret set`."
                ),
                command=f"cathedral config set {role} hotkey <your-ss58-address>",
            ),
        )

    known = {f.name for f in config.schema(role)}
    if field not in known:
        return Envelope.fail(
            "config.set", C.E_CONFIG_FIELD_REQUIRED, f"`{field}` is not a {role} field",
            exit_code=Exit.USAGE,
            remediation=Remediation(summary=f"Known fields: {', '.join(sorted(known))}.",
                                    command=f"cathedral config schema {role}"),
        )

    field_spec = next(f for f in config.schema(role) if f.name == field)
    if _looks_like_a_secret_value(field_spec, raw):
        return Envelope.fail(
            "config.set",
            C.E_SECRET_UNSAFE_SOURCE,
            f"`{field}` holds the *name* of a secret, not its value",
            exit_code=Exit.USAGE,
            remediation=Remediation(
                summary=(
                    "A value passed on a command line is visible in `ps` and your shell history. "
                    "Store the secret, then point this field at its name."
                ),
                command=f"cathedral secret set {field_spec.default or 'MY_SECRET'} --stdin",
            ),
        )

    values = config.load(role)
    previous = values.get(field)
    values[field] = _coerce(raw, previous if previous is not None else field_spec.default)

    problems = config.validate(role, values)
    fatal = [p for p in problems if f"`{field}`" in p]
    if fatal:
        return Envelope.fail(
            "config.set", C.E_CONFIG_INVALID, fatal[0], exit_code=Exit.CONFIG_INVALID,
            remediation=Remediation(summary="Nothing was written.",
                                    command=f"cathedral config schema {role}"),
        )

    owner_fields = config.OWNER_CONTROLLED.get(role, ())
    if ctx.dry_run:
        env = Envelope.ok("config.set", {
            "role": role, "field": field, "from": previous, "to": values[field],
            "owner_controlled": field in owner_fields, "written": False,
        })
        env.data_schema = schema_id("config_value")
        env.dry_run = True
        return env

    if role == "validator":
        # The validator's engine TOML is *derived* from this value, and deriving it
        # reads the verified generation's shipped default. Three things follow.
        #
        # The adapter must be bound to its verified role: an unbound one renders
        # from an empty base and silently drops whatever the signed release
        # shipped. The lease must be held while it renders, for the same reason
        # every other installed-code path holds it. And the derived file must be
        # produced and checked BEFORE the node config is committed — otherwise a
        # render that fails leaves the node config saying one thing and the engine
        # config another, which is a partial success reported as a whole one.
        try:
            with installer.active_view(lockfile.load()) as (_states, group, detail):
                if group is None:
                    return Envelope.blocked(
                        "config.set", C.E_ENGINE_NOT_INSTALLED,
                        "the validator engine is not installed as a verified signed release",
                        exit_code=Exit.NOT_READY,
                        remediation=Remediation(
                            summary=(f"Nothing was written: {detail}. The engine configuration is "
                                     f"derived from the verified generation, so it cannot be "
                                     f"written without one."),
                            command="cathedral setup validator"))
                bound = engines.load(role, lockfile.load(), group)
                derived = bound.render_engine_config(values)
        except (installer.ActiveStateError, installer.InstallError) as exc:
            return Envelope.blocked(
                "config.set", C.E_ENGINE_NOT_INSTALLED,
                "the validator engine configuration could not be derived", exit_code=Exit.NOT_READY,
                remediation=Remediation(summary=f"Nothing was written: {exc}",
                                        command="cathedral status validator"))
        except ValueError as exc:
            return Envelope.fail(
                "config.set", C.E_CONFIG_INVALID,
                "the derived validator engine configuration is not valid",
                exit_code=Exit.CONFIG_INVALID,
                remediation=Remediation(summary=f"Nothing was written: {exc}",
                                        command="cathedral config show validator"))
        # Both writes are atomic and only happen once the derived form is known good.
        config.save(role, values)
        bound.commit_engine_config(derived)
    else:
        config.save(role, values)

    data = {
        "role": role, "field": field, "from": previous, "to": values[field],
        "file": str(paths.config_file(role)),
        "owner_controlled": field in owner_fields,
        "remaining_problems": [p for p in problems if p not in fatal],
    }
    env = Envelope.ok("config.set", data)
    env.data_schema = schema_id("config_value")
    if field in owner_fields:
        env.warn("config.owner_controlled",
                 f"`{field}` is owner-controlled; updates will preserve it")
    for problem in data["remaining_problems"]:
        env.warn("config.invalid", problem)
    return env


@command("config.schema")
def config_schema(ctx: Context) -> Envelope:
    roles = [ctx.args.role] if getattr(ctx.args, "role", None) else list(lockfile.ROLES)
    for role in roles:
        _keep_public_fields_readable(
            role, {f.name: f.default for f in config.schema(role)}
        )
    data = {
        "roles": {
            role: {
                "fields": [f.to_dict() for f in config.schema(role)],
                "owner_controlled": list(config.OWNER_CONTROLLED.get(role, ())),
            }
            for role in roles
        },
        "never_accepted": sorted(config.FORBIDDEN_FIELDS),
    }
    env = Envelope.ok("config.schema", data)
    env.data_schema = schema_id("config_schema")
    return env


def _looks_like_a_secret_value(field: config.Field, raw: str) -> bool:
    """A secret-reference field being handed something that is clearly a value.

    Environment-variable names are short, uppercase, and have no punctuation
    beyond an underscore. Anything else in that slot is almost certainly the
    credential itself, which we refuse before it reaches the shell history.
    """
    if not field.secret_ref:
        return False
    return not (raw.isupper() and raw.replace("_", "").isalnum() and len(raw) <= 64)


def _coerce(raw: str, like: Any) -> Any:
    """Match the type of the existing value or the default, so `netuid 39` does
    not silently become the string "39" and break an engine flag."""
    if isinstance(like, bool):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(like, int) and not isinstance(like, bool):
        try:
            return int(raw)
        except ValueError:
            return raw
    if isinstance(like, float):
        try:
            return float(raw)
        except ValueError:
            return raw
    return raw


@renders("config.show")
def _render_show(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.title("Configuration", data["secrets_file"] + " holds secrets, separately")
    for role, report in data["roles"].items():
        console.blank()
        console.rule(role)
        if not report["exists"]:
            console.info("file", "not written yet — showing defaults")
        pairs = [(k, v if v != "" else console.style.dim("(empty)")) for k, v in report["values"].items()]
        console.kv_block(pairs, indent=4)
        for problem in data["problems"].get(role, []):
            console.warn("problem", problem)
    console.blank()
    console.note(data["note"], indent=4)


@renders("config.schema")
def _render_schema(console: Console, data: dict[str, Any], env: Envelope) -> None:
    console.title("Configuration fields")
    for role, report in data["roles"].items():
        console.blank()
        console.rule(role)
        rows = []
        for field in report["fields"]:
            marker = "owner" if field["name"] in report["owner_controlled"] else (
                "secret name" if field["is_secret_reference"] else ""
            )
            rows.append([field["name"], str(field["default"] if field["default"] is not None else ""),
                         marker, field["description"]])
        console.table(["field", "default", "", "meaning"], rows, indent=4)
    console.blank()
    console.note("Never accepted in any field: " + ", ".join(data["never_accepted"]), indent=4)


@renders("config.set")
def _render_set(console: Console, data: dict[str, Any], env: Envelope) -> None:
    if "field" not in data:
        return
    console.blank()
    verb = "would set" if env.dry_run else "set"
    console.ok(verb, f"{data.get('role', '')}.{data['field']} = {data.get('to')}")
    if data.get("from") is not None and data["from"] != data.get("to"):
        console.info("was", str(data["from"]))


@renders("config.get")
def _render_get(console: Console, data: dict[str, Any], env: Envelope) -> None:
    if "field" not in data:
        return
    console.blank()
    console.info(data["field"], str(data.get("value", "")))
