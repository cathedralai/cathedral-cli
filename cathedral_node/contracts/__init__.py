"""The stable machine-facing contract.

Everything an agent depends on lives here: the envelope schema, the protocol
version, the exit codes, and the error codes. The human presentation layer in
``cathedral_node.ui`` renders these same objects; it never produces its own.
"""

from cathedral_node.contracts.envelope import (
    Envelope,
    Remediation,
    NextStep,
    ResultError,
    Warning_,
)
from cathedral_node.contracts.codes import Exit, ErrorCode
from cathedral_node.contracts.version import (
    PROTOCOL_VERSION,
    RESULT_SCHEMA,
    EVENT_SCHEMA,
    schema_id,
)

__all__ = [
    "Envelope",
    "Remediation",
    "NextStep",
    "ResultError",
    "Warning_",
    "Exit",
    "ErrorCode",
    "PROTOCOL_VERSION",
    "RESULT_SCHEMA",
    "EVENT_SCHEMA",
    "schema_id",
]
