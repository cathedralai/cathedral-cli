"""Reading and checking the pinned engine revisions."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from cathedral_node import paths

ROLES = ("distill", "compute", "validator")
MINER_ROLES = ("distill", "compute")


@dataclasses.dataclass(frozen=True, slots=True)
class EnginePin:
    role: str
    repository: str
    revision: str
    branch: str
    distribution: str
    description: str
    # The launch install profile — part of the pinned, reviewable contract and
    # bound into the generation receipt and the signed release lock. A generation
    # that omits a required extra (e.g. the validator's `integration` seam) is not
    # launch-correct.
    extras: tuple[str, ...] = ()
    entrypoints: tuple[str, ...] = ()
    server_entrypoints: tuple[str, ...] = ()
    launch_mode: str = "default"
    protocol: str = "1.0.0"

    @property
    def short_revision(self) -> str:
        return self.revision[:12]

    @property
    def install_target(self) -> str:
        """The pip install specifier: ``<src>`` or ``<src>[extra,extra]``."""
        return f"[{','.join(self.extras)}]" if self.extras else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "repository": self.repository,
            "revision": self.revision,
            "short_revision": self.short_revision,
            "branch": self.branch,
            "distribution": self.distribution,
            "description": self.description,
            "extras": list(self.extras),
            "entrypoints": list(self.entrypoints),
            "server_entrypoints": list(self.server_entrypoints),
            "launch_mode": self.launch_mode,
            "protocol": self.protocol,
        }


@dataclasses.dataclass(frozen=True, slots=True)
class Lock:
    engines: dict[str, EnginePin]
    excluded: dict[str, str]
    python_requirement: str
    protocol_version: str
    source: Path

    def pin(self, role: str) -> EnginePin:
        try:
            return self.engines[role]
        except KeyError:
            raise KeyError(f"unknown role {role!r}; known roles: {', '.join(sorted(self.engines))}") from None

    def to_dict(self) -> dict[str, Any]:
        return {
            "engines": {r: p.to_dict() for r, p in self.engines.items()},
            "excluded": self.excluded,
            "python": self.python_requirement,
            "protocol_version": self.protocol_version,
        }


# Engine sources this node will clone from. A lockfile is plain JSON with no
# signature, so `--to` would otherwise let any file redirect an install to an
# arbitrary repository — whose build backend then runs as the operator during
# `pip install`. Verifying a signature is the right long-term answer; until
# there is one to verify, constrain the destination and say so.
ALLOWED_HOST = "github.com"
ALLOWED_OWNER = "cathedralai"


class UntrustedSource(ValueError):
    """A lockfile naming a repository this node will not install from."""


def is_trusted_repository(repository: str) -> bool:
    """True only for ``https://github.com/cathedralai/<repo>``.

    Parse the URL and validate the real host and first path segment. A substring
    test (``"github.com/cathedralai/" in url``) accepts a hostile
    ``https://attacker.example/github.com/cathedralai/evil.git`` and
    ``https://github.com@attacker.example/...`` — either of which would run an
    attacker's build backend as the operator during ``pip install``.
    """
    parsed = urlparse(repository)
    if parsed.scheme != "https":
        return False
    if (parsed.hostname or "").lower() != ALLOWED_HOST:
        return False
    segments = [segment for segment in parsed.path.split("/") if segment]
    return len(segments) >= 2 and segments[0].lower() == ALLOWED_OWNER


def load(path: Path | None = None, *, trusted: bool | None = None) -> Lock:
    """Read a lockfile.

    ``trusted`` defaults to True for the repository's own lockfile and False for
    any other, which is what makes `--to` safe to point at a file you were sent.
    """
    src = path or paths.lockfile()
    if trusted is None:
        trusted = path is None or Path(src).resolve() == paths.lockfile().resolve()
    raw = json.loads(src.read_text())

    if not trusted:
        for role, spec in raw.get("engines", {}).items():
            repository = str(spec.get("repository", ""))
            if not is_trusted_repository(repository):
                raise UntrustedSource(
                    f"the {role} engine would be installed from {repository!r}, which is not a "
                    f"Cathedral repository. Nothing was changed."
                )
            revision = str(spec.get("revision", ""))
            if len(revision) != 40 or not all(c in "0123456789abcdef" for c in revision.lower()):
                raise UntrustedSource(
                    f"the {role} pin {revision!r} is not a full commit SHA. Nothing was changed."
                )
    profile = raw.get("launch_profile", {})
    engines = {
        role: EnginePin(
            role=role,
            repository=spec["repository"],
            revision=spec["revision"],
            branch=spec.get("branch", "main"),
            distribution=spec["distribution"],
            description=spec.get("role", ""),
            extras=tuple(profile.get(role, {}).get("extras", [])),
            entrypoints=tuple(profile.get(role, {}).get("entrypoints", [])),
            server_entrypoints=tuple(profile.get(role, {}).get("server_entrypoints", [])),
            launch_mode=profile.get(role, {}).get("launch_mode", "default"),
            protocol=profile.get(role, {}).get("protocol", raw.get("compatibility", {}).get("protocol_version", "1.0.0")),
        )
        for role, spec in raw.get("engines", {}).items()
    }
    compat = raw.get("compatibility", {})
    return Lock(
        engines=engines,
        excluded=raw.get("excluded", {}),
        python_requirement=compat.get("python", ">=3.11"),
        protocol_version=compat.get("protocol_version", "1.0.0"),
        source=src,
    )
