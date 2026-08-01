"""Protocol and schema versioning.

An agent pins ``protocol_version``. The rules, which the test suite enforces:

* PATCH — wording, added optional fields inside ``data``.
* MINOR — new commands, new optional envelope fields, new non-fatal warnings.
  An agent written against an earlier MINOR keeps working.
* MAJOR — anything that can break a correct agent: a removed field, a changed
  type, a changed exit code, a renamed command.

``cathedral capabilities`` reports this so an agent can refuse to drive a node
whose MAJOR it does not know.
"""

from __future__ import annotations

PROTOCOL_VERSION = "1.0.0"
"""Semantic version of the whole machine-facing contract."""

PROTOCOL_MAJOR = int(PROTOCOL_VERSION.split(".", 1)[0])

RESULT_SCHEMA = "cathedral.node.result.v1"
"""Schema id of the single envelope every command writes to stdout."""

EVENT_SCHEMA = "cathedral.node.event.v1"
"""Schema id of one line in a run's event stream."""

CAPABILITIES_SCHEMA = "cathedral.node.capabilities.v1"
LOCKFILE_SCHEMA = "cathedral.node.lock.v1"
CONFIG_SCHEMA = "cathedral.node.config.v1"
STATE_SCHEMA = "cathedral.node.runstate.v1"


def schema_id(name: str) -> str:
    """Schema id for a ``data`` payload, e.g. ``schema_id("doctor")``."""
    return f"cathedral.node.{name}.v1"


def compatible(requested: str) -> bool:
    """True when an agent pinned to ``requested`` can safely drive this build."""
    try:
        major = int(str(requested).split(".", 1)[0])
    except (ValueError, AttributeError):
        return False
    return major == PROTOCOL_MAJOR
