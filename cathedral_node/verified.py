"""Sealed, immutable runtime state.

Two values live here and nothing else. They are the *only* legitimate description
of what the node may execute:

``VerifiedRole``
    One role's generation as it was proven on disk: the generation id, the
    generation/source/venv directories, the interpreter, the receipt path and its
    frozen contents, and the exact set of executables the signed release
    authorizes.

``VerifiedActiveGroup``
    The whole node-wide group: release version, lock digest, signer identity, the
    digest of the exact pointer document that named it, and an immutable
    role -> :class:`VerifiedRole` map.

Both are **sealed**: construction requires a private token held only by the strict
group verifier in :mod:`cathedral_node.engines.installer`. Holding one is proof
that the signature, the retained manifest, the replay floor, the trust root, the
current lock, the revocation cache, every receipt and every managed file verified
*together, once*. They are frozen and slotted, every nested map is a
``MappingProxyType`` and every nested sequence a tuple, so a consumer cannot
mutate one and cannot be handed a live view of anything that can change.

The point is narrow and important: a caller that has one of these never needs to
re-resolve a path, and therefore never re-reads ``active-release.json``. There is
no window between "verified" and "executed" in which mutable state is consulted
again.
"""

from __future__ import annotations

import types
from pathlib import Path
from typing import Any, Iterator, Mapping

__all__ = ["VerifiedRole", "VerifiedActiveGroup", "SealError", "freeze"]

# The construction token. Only the strict verifier imports it.
_SEAL = object()


class SealError(TypeError):
    """A sealed value was constructed outside the strict verifier."""


def freeze(value: Any) -> Any:
    """Deeply immutable view of parsed JSON: dict -> MappingProxyType, list -> tuple."""
    if isinstance(value, Mapping):
        return types.MappingProxyType({str(k): freeze(v) for k, v in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(v) for v in value)
    return value


def _immutable(_self: Any, *_args: Any, **_kwargs: Any) -> None:
    raise AttributeError(f"{type(_self).__name__} is immutable")


class VerifiedRole:
    """One role's proven generation. Every executable path a runtime consumer uses
    comes from here, never from the mutable pointer."""

    __slots__ = ("role", "generation", "generation_dir", "source_dir", "venv_dir",
                 "python", "receipt", "receipt_data", "entrypoints")

    def __init__(self, seal: Any, *, role: str, generation: str, generation_dir: Path,
                 source_dir: Path, venv_dir: Path, python: Path, receipt: Path,
                 receipt_data: Mapping[str, Any], entrypoints: Any) -> None:
        if seal is not _SEAL:
            raise SealError("VerifiedRole is constructed only by strict group verification")
        object.__setattr__(self, "role", str(role))
        object.__setattr__(self, "generation", str(generation))
        object.__setattr__(self, "generation_dir", Path(generation_dir))
        object.__setattr__(self, "source_dir", Path(source_dir))
        object.__setattr__(self, "venv_dir", Path(venv_dir))
        object.__setattr__(self, "python", Path(python))
        object.__setattr__(self, "receipt", Path(receipt))
        object.__setattr__(self, "receipt_data", freeze(receipt_data))
        object.__setattr__(self, "entrypoints", tuple(sorted({str(e) for e in entrypoints})))

    __setattr__ = _immutable
    __delattr__ = _immutable

    def bin(self, name: str) -> Path:
        """An executable inside this verified venv.

        The name must be one the signed release authorized for this role (plus the
        interpreter itself) and must be a single path component, so a caller can
        never steer execution outside the generation that was verified.
        """
        if not isinstance(name, str) or not name or "/" in name or name in (".", ".."):
            raise ValueError(f"{name!r} is not a single executable name")
        if name not in self.entrypoints:
            raise ValueError(f"{name!r} is not an entrypoint the signed release authorizes for "
                             f"{self.role}")
        return self.venv_dir / "bin" / name

    def has_bin(self, name: str) -> bool:
        try:
            return self.bin(name).is_file()
        except ValueError:
            return False

    def to_dict(self) -> dict[str, Any]:
        """A reporting view. Not authorization — the sealed value is."""
        return {"role": self.role, "generation": self.generation,
                "generation_dir": str(self.generation_dir), "venv": str(self.venv_dir),
                "python": str(self.python), "receipt": str(self.receipt),
                "entrypoints": list(self.entrypoints)}

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"VerifiedRole(role={self.role!r}, generation={self.generation!r})"


class VerifiedActiveGroup:
    """The node-wide group of verified roles, as proven by one strict verification."""

    __slots__ = ("release_version", "lock_digest", "identity", "pointer_digest", "_roles")

    def __init__(self, seal: Any, *, release_version: int, lock_digest: str, identity: str,
                 pointer_digest: str, roles: Mapping[str, VerifiedRole]) -> None:
        if seal is not _SEAL:
            raise SealError("VerifiedActiveGroup is constructed only by strict group verification")
        if not all(isinstance(r, VerifiedRole) for r in roles.values()):
            raise SealError("a verified group holds only VerifiedRole values")
        object.__setattr__(self, "release_version", int(release_version))
        object.__setattr__(self, "lock_digest", str(lock_digest))
        object.__setattr__(self, "identity", str(identity))
        object.__setattr__(self, "pointer_digest", str(pointer_digest))
        object.__setattr__(self, "_roles", types.MappingProxyType(dict(roles)))

    __setattr__ = _immutable
    __delattr__ = _immutable

    @property
    def roles(self) -> "types.MappingProxyType[str, VerifiedRole]":
        return self._roles

    def role(self, role: str) -> VerifiedRole:
        try:
            return self._roles[role]
        except KeyError:
            raise KeyError(f"the verified group does not contain the {role!r} role") from None

    def generations(self) -> dict[str, str]:
        return {role: verified.generation for role, verified in self._roles.items()}

    def __contains__(self, role: object) -> bool:
        return role in self._roles

    def __iter__(self) -> Iterator[str]:
        return iter(self._roles)

    def to_dict(self) -> dict[str, Any]:
        return {"release_version": self.release_version, "lock_digest": self.lock_digest,
                "identity": self.identity, "pointer_digest": self.pointer_digest,
                "roles": {r: v.to_dict() for r, v in self._roles.items()}}

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return (f"VerifiedActiveGroup(release_version={self.release_version}, "
                f"lock_digest={self.lock_digest[:12]}…, roles={sorted(self._roles)})")
