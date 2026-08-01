"""Engine adapters, resolved by role."""

from __future__ import annotations

from cathedral_node import lockfile
from cathedral_node.engines.base import Engine, Qualification, TestOutcome, UnverifiedEngine
from cathedral_node.engines.compute import ComputeEngine
from cathedral_node.engines.distill import DistillEngine
from cathedral_node.engines.validator import ValidatorEngine
from cathedral_node.verified import VerifiedActiveGroup

_CLASSES = {
    "distill": DistillEngine,
    "compute": ComputeEngine,
    "validator": ValidatorEngine,
}


def load(role: str, lock: lockfile.Lock | None = None,
         group: VerifiedActiveGroup | None = None) -> Engine:
    """The adapter for one role, bound to its pinned revision.

    Pass the sealed ``group`` from one strict verification to bind the adapter to
    the exact generation that verified. Without it the adapter can still describe
    itself (explain, capabilities, qualify) but cannot resolve any executable path.
    """
    lock = lock or lockfile.load()
    try:
        cls = _CLASSES[role]
    except KeyError:
        raise KeyError(f"unknown role {role!r}") from None
    verified = group.role(role) if group is not None and role in group else None
    return cls(lock.pin(role), verified)


def all_engines(lock: lockfile.Lock | None = None,
                group: VerifiedActiveGroup | None = None) -> dict[str, Engine]:
    lock = lock or lockfile.load()
    return {role: load(role, lock, group) for role in _CLASSES}


__all__ = ["Engine", "Qualification", "TestOutcome", "UnverifiedEngine", "load", "all_engines"]
