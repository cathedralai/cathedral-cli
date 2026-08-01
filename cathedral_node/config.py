"""Configuration and secrets.

Two stores, deliberately separate:

* ``config/<role>.toml`` — everything safe to read, commit to a private repo,
  paste into an issue, or show on screen. Never contains a credential.
* ``secrets.env`` — 0600, never printed, never passed as an argument, never
  committed. Values only ever reach an engine through its environment.

A configuration field that *needs* a credential stores the **name** of the
secret, not the secret. That is what makes ``cathedral config show`` safe to run
in front of anyone.
"""

from __future__ import annotations

import dataclasses
import os
import re
import stat
import tomllib
from pathlib import Path
from typing import Any

from cathedral_node import paths
from cathedral_node.redact import fingerprint

# A Bittensor SS58 hotkey. We validate shape only — proving ownership is the
# chain's job, not ours.
SS58_RE = re.compile(r"^5[1-9A-HJ-NP-Za-km-z]{46,47}$")

# Never accepted, in any field, under any name. Asking for a coldkey is a
# product decision we have made once, here.
FORBIDDEN_FIELDS = frozenset(
    {"coldkey", "coldkey_mnemonic", "coldkey_seed", "mnemonic", "seed", "private_key", "coldkeypub"}
)


class ConfigError(Exception):
    """Raised with a message written for the operator, not the developer."""

    def __init__(self, message: str, field: str | None = None, remedy: str | None = None) -> None:
        super().__init__(message)
        self.field = field
        self.remedy = remedy


@dataclasses.dataclass(slots=True)
class Field:
    name: str
    description: str
    required: bool = False
    default: Any = None
    secret_ref: bool = False
    """True when this field names a secret rather than holding one."""
    choices: tuple[str, ...] | None = None
    example: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "required": self.required,
            "default": self.default,
            "is_secret_reference": self.secret_ref,
            "choices": list(self.choices) if self.choices else None,
            "example": self.example,
        }


SCHEMAS: dict[str, tuple[Field, ...]] = {
    "distill": (
        Field("hotkey", "Your SN39 miner hotkey (SS58 public address). Never a coldkey.",
              example="5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX"),
        Field("network", "Bittensor network label.", default="finney", choices=("finney", "test")),
        Field("netuid", "Subnet id.", default=39),
        Field("model", "Model id your agent solves with.", default="hermes3"),
        Field("api_base", "OpenAI-compatible endpoint your model is served from.",
              default="http://localhost:11434/v1",
              example="http://localhost:11434/v1"),
        Field("api_key_secret", "Name of the secret holding your model API key. "
              "A local model server usually needs none.",
              secret_ref=True, default="DISTILL_API_KEY"),
        Field("validator_url", "Validator base URL for live dispatch. Leave empty for local work.",
              default=""),
        Field("max_turns", "Agent tool-call budget per task.", default=24),
    ),
    "compute": (
        Field("hotkey", "Your SN39 worker hotkey (SS58 public address). Never a coldkey.",
              example="5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX"),
        Field("network", "Bittensor network label.", default="finney", choices=("finney", "test")),
        Field("netuid", "Subnet id.", default=39),
        Field("host", "Address the worker binds. Loopback unless you serve TLS.", default="127.0.0.1"),
        Field("port", "Worker port.", default=8901),
        Field("tls_certificate", "PEM certificate path. Required for any non-loopback bind.", default=""),
        Field("tls_private_key", "PEM private key path, readable only by the worker.", default=""),
        Field("bearer_token_secret", "Name of the secret holding the worker bearer token.",
              secret_ref=True, default="COMPUTE_BEARER_TOKEN"),
    ),
    "validator": (
        Field("network", "Bittensor network label.", default="finney", choices=("finney", "test")),
        Field("netuid", "Subnet id.", default=39),
        Field("wallet_name", "Bittensor wallet name holding your validator hotkey.", default="validator"),
        Field("wallet_hotkey", "Validator hotkey name inside that wallet.", default="default"),
        Field("publisher_url", "Signed score feed.", default="https://api.cathedral.computer"),
        Field("interval_secs", "Seconds between ticks.", default=1500),
        Field("provenance", "Audit mode.", default="shadow",
              choices=("off", "shadow", "authority", "full", "thin")),
        Field("burn_fraction", "Owner-controlled share sent to burn. Preserved across updates.",
              default=0.10),
        Field("burn_destination", "Owner-controlled burn destination. Empty means the live subnet owner.",
              default=""),
        Field("lane_allocation", "Owner-controlled per-lane allocation. Preserved across updates.",
              default=""),
    ),
}

# Owner policy an update must never silently change. `cathedral update` diffs
# these and refuses to proceed if a new default would move one.
OWNER_CONTROLLED = {
    "validator": ("burn_fraction", "burn_destination", "lane_allocation", "wallet_name", "wallet_hotkey"),
}


def schema(role: str) -> tuple[Field, ...]:
    try:
        return SCHEMAS[role]
    except KeyError:
        raise ConfigError(f"unknown role {role!r}") from None


def defaults(role: str) -> dict[str, Any]:
    return {f.name: f.default for f in schema(role) if f.default is not None}


def load(role: str) -> dict[str, Any]:
    """Read a role's config, filled out with defaults. Missing file is empty."""
    path = paths.config_file(role)
    values = defaults(role)
    if path.exists():
        try:
            values.update(tomllib.loads(path.read_text()))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(
                f"{paths.relative_to_home(path)} is not valid TOML: {exc}",
                remedy=f"cathedral config reset {role}",
            ) from exc
    return values


def save(role: str, values: dict[str, Any]) -> Path:
    """Write a role's config. Refuses to persist anything credential-shaped."""
    for key in values:
        if key.lower() in FORBIDDEN_FIELDS:
            raise ConfigError(
                f"`{key}` is never stored in configuration",
                field=key,
                remedy="Cathedral never needs a coldkey, seed, or mnemonic. "
                "Use a hotkey address and, if a service key is needed, `cathedral secret set`.",
            )
    paths.ensure_layout()
    path = paths.config_file(role)
    path.write_text(_to_toml(role, values))
    path.chmod(0o600)
    return path


def validate(role: str, values: dict[str, Any]) -> list[str]:
    """Problems with this configuration, in operator language. Empty means good."""
    problems: list[str] = []
    fields = {f.name: f for f in schema(role)}

    for key in values:
        if key.lower() in FORBIDDEN_FIELDS:
            problems.append(f"`{key}` must not be in configuration — Cathedral never uses one")

    for field in schema(role):
        raw = values.get(field.name)
        present = raw not in (None, "")
        if field.required and not present:
            problems.append(f"`{field.name}` is required — {field.description}")
        if present and field.choices and str(raw) not in field.choices:
            problems.append(f"`{field.name}` must be one of {', '.join(field.choices)} (found {raw!r})")

    hotkey = values.get("hotkey")
    if hotkey:
        if not SS58_RE.match(str(hotkey)):
            problems.append(
                "`hotkey` does not look like an SS58 address — it should start with 5 and be 48 characters"
            )

    if role == "compute":
        host = str(values.get("host", ""))
        loopback = host in ("127.0.0.1", "::1", "localhost", "")
        cert, key = values.get("tls_certificate"), values.get("tls_private_key")
        if not loopback and not (cert and key):
            problems.append(
                f"`host` is {host} but no TLS certificate is configured — a worker reachable off-host "
                "must serve its own TLS"
            )
        for label, path_value in (("tls_certificate", cert), ("tls_private_key", key)):
            if path_value and not Path(str(path_value)).expanduser().exists():
                problems.append(f"`{label}` points at {path_value}, which does not exist")
        if key:
            problems.extend(_key_permission_problems(Path(str(key)).expanduser()))

    if role == "validator":
        burn = values.get("burn_fraction")
        if burn is not None:
            try:
                burn_f = float(burn)
            except (TypeError, ValueError):
                problems.append("`burn_fraction` must be a number between 0 and 1")
            else:
                if not 0.0 <= burn_f <= 1.0:
                    problems.append(f"`burn_fraction` must be between 0 and 1 (found {burn_f})")
        interval = values.get("interval_secs")
        if interval is not None and int(interval) < 60:
            problems.append("`interval_secs` below 60 will be throttled by the chain's write cooldown")

    return problems


def _key_permission_problems(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        mode = path.stat().st_mode
    except OSError:
        return []
    if mode & (stat.S_IRGRP | stat.S_IROTH):
        return [
            f"`tls_private_key` at {path} is readable by other users on this host "
            f"(mode {stat.filemode(mode)}); run `chmod 600 {path}`"
        ]
    return []


def _to_toml(role: str, values: dict[str, Any]) -> str:
    lines = [
        f"# Cathedral node — {role} configuration",
        "# Managed by `cathedral config set`. Safe to read: it holds no credentials,",
        "# only the *names* of secrets kept in $CATHEDRAL_HOME/secrets.env.",
        "",
    ]
    known = {f.name: f for f in schema(role)}
    for name in list(known) + [k for k in values if k not in known]:
        if name not in values:
            continue
        field = known.get(name)
        if field and field.description:
            lines.append(f"# {field.description}")
        lines.append(f"{name} = {_toml_value(values[name])}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


# --- secrets -------------------------------------------------------------------

def read_secrets() -> dict[str, str]:
    """Load the secret store. Returns names to values; callers must not log it."""
    path = paths.secrets_file()
    if not path.exists():
        return {}
    out: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, _, value = line.partition("=")
        out[name.strip()] = value.strip().strip("'\"")
    return out


def set_secret(name: str, value: str) -> None:
    """Store one secret at 0600. Overwrites an existing entry of that name."""
    paths.ensure_layout()
    path = paths.secrets_file()
    existing = read_secrets()
    existing[name] = value
    body = [
        "# Cathedral node secrets. Mode 0600, never committed, never printed.",
        "# Values reach engines through the process environment only.",
        "",
    ]
    body += [f"{k}={v}" for k, v in sorted(existing.items())]
    path.write_text("\n".join(body) + "\n")
    path.chmod(0o600)


def delete_secret(name: str) -> bool:
    existing = read_secrets()
    if name not in existing:
        return False
    del existing[name]
    path = paths.secrets_file()
    body = [
        "# Cathedral node secrets. Mode 0600, never committed, never printed.",
        "# Values reach engines through the process environment only.",
        "",
    ] + [f"{k}={v}" for k, v in sorted(existing.items())]
    path.write_text("\n".join(body) + "\n")
    path.chmod(0o600)
    return True


def describe_secrets() -> list[dict[str, Any]]:
    """What is stored, described without revealing anything."""
    out = []
    for name, value in sorted(read_secrets().items()):
        out.append({"name": name, "present": True, "fingerprint": fingerprint(value)})
    return out


def secrets_file_problems() -> list[str]:
    path = paths.secrets_file()
    if not path.exists():
        return []
    mode = path.stat().st_mode
    if mode & (stat.S_IRGRP | stat.S_IROTH | stat.S_IWGRP | stat.S_IWOTH):
        return [f"{paths.relative_to_home(path)} is accessible to other users (mode {stat.filemode(mode)})"]
    return []


def secret_environment(role: str, values: dict[str, Any]) -> dict[str, str]:
    """Resolve this role's secret references into an environment mapping.

    A missing secret is simply absent — the caller decides whether that blocks
    the operation, because a local model server legitimately needs no key.
    """
    store = read_secrets()
    env: dict[str, str] = {}
    for field in schema(role):
        if not field.secret_ref:
            continue
        name = str(values.get(field.name) or field.default or "")
        if not name:
            continue
        # Also honour a value already exported by the operator's shell.
        value = store.get(name) or os.environ.get(name)
        if value:
            env[name] = value
    return env
