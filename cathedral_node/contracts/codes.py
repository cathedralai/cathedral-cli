"""Exit codes and error codes.

Exit codes are part of the MAJOR contract: an agent branches on them without
parsing text. They are grouped so an agent can classify a failure it has never
seen before — ``10 <= code < 20`` is always "this machine or config is not
ready", ``20 <= code < 30`` is always "the work itself failed".
"""

from __future__ import annotations

from enum import IntEnum


class Exit(IntEnum):
    """Process exit codes. Stable within a MAJOR protocol version."""

    # 0-9 — the command reached a definite, successful conclusion.
    OK = 0
    """The operation completed. For verifications, the verdict was PASS."""

    # 10-19 — the environment is not ready. Nothing was attempted.
    NOT_READY = 10
    """A precondition failed. ``error.remediation`` says how to fix it."""
    UNSUPPORTED = 11
    """This machine cannot do this, and no command changes that (e.g. no TDX)."""
    CONFIG_INVALID = 12
    """Configuration is missing, malformed, or internally inconsistent."""
    CREDENTIAL_MISSING = 13
    """A required secret is not present. Never says what the secret is worth."""
    LOCKED = 14
    """Another process holds this role's lock. Includes its pid and run id."""

    # 20-29 — the work ran and produced a negative result. This is not an error
    # in the CLI; it is an honest answer.
    VERIFY_FAILED = 20
    """Fail-closed verification refused the evidence. The node worked correctly."""
    WORK_FAILED = 21
    """The engine ran and could not complete the work."""
    TIMEOUT = 22
    """A bounded operation exceeded its deadline. State is preserved."""

    # 30-39 — the request itself was wrong.
    USAGE = 30
    """Bad arguments. Never emitted after any side effect."""
    NOT_FOUND = 31
    """A named run, artifact, or identifier does not exist."""
    INCOMPATIBLE = 32
    """Protocol or engine version mismatch. Agent should stop and re-discover."""

    # 40-49 — the outside world.
    NETWORK = 40
    """A required remote was unreachable. Always safe to retry."""
    UPSTREAM = 41
    """A pinned engine failed in a way this layer does not model."""

    # 50+ — the operator or the OS interrupted us.
    CANCELLED = 50
    """Interrupted. Durable state was flushed; ``resume`` will continue."""
    INTERNAL = 70
    """A bug in this CLI. Always includes a diagnostic bundle path."""


_RETRYABLE = frozenset({Exit.NETWORK, Exit.TIMEOUT, Exit.LOCKED, Exit.UPSTREAM})


def retryable(code: Exit | int) -> bool:
    """True when an identical retry could succeed without operator action."""
    return Exit(code) in _RETRYABLE


# Per-member descriptions. An IntEnum member's ``__doc__`` is the *class*
# docstring, not the string written beneath it, so reading `member.__doc__`
# produces the same sentence sixteen times. These are the published meanings.
DESCRIPTIONS: dict[Exit, str] = {
    Exit.OK: "Completed. For a verification, the verdict was PASS.",
    Exit.NOT_READY: "A precondition failed. `error.remediation` says how to fix it.",
    Exit.UNSUPPORTED: "This machine cannot do this, and no command changes that.",
    Exit.CONFIG_INVALID: "Configuration is missing, malformed, or internally inconsistent.",
    Exit.CREDENTIAL_MISSING: "A required secret is not present.",
    Exit.LOCKED: "Another process holds this role's lock. Its pid and run id are in `detail`.",
    Exit.VERIFY_FAILED: "Fail-closed verification refused the evidence. The node worked correctly.",
    Exit.WORK_FAILED: "The engine ran and could not complete the work.",
    Exit.TIMEOUT: "A bounded operation exceeded its deadline. State is preserved.",
    Exit.USAGE: "Bad arguments. Never emitted after any side effect.",
    Exit.NOT_FOUND: "A named run, artifact, or identifier does not exist.",
    Exit.INCOMPATIBLE: "Protocol or engine version mismatch. Stop and re-discover.",
    Exit.NETWORK: "A required remote was unreachable. Always safe to retry.",
    Exit.UPSTREAM: "A pinned engine failed in a way this layer does not model.",
    Exit.CANCELLED: "Interrupted. Durable state was flushed; `resume` will continue.",
    Exit.INTERNAL: "A bug in this CLI. Always includes a diagnostics bundle path.",
}


def describe(code: Exit) -> str:
    return DESCRIPTIONS.get(code, "")


class ErrorCode(str):
    """A stable, machine-matchable error identifier.

    Dotted lowercase. An agent matches on the exact string or on a prefix:
    ``err.startswith("config.")`` classifies every configuration problem.
    """

    __slots__ = ()


# Environment and hardware
E_PYTHON_TOO_OLD = ErrorCode("env.python_too_old")
E_TOOL_MISSING = ErrorCode("env.tool_missing")
E_DISK_LOW = ErrorCode("env.disk_low")
E_MEMORY_LOW = ErrorCode("env.memory_low")
E_PLATFORM_UNSUPPORTED = ErrorCode("env.platform_unsupported")
E_NO_TDX = ErrorCode("hardware.no_tdx")
E_NO_CONTAINER_RUNTIME = ErrorCode("env.no_container_runtime")

# Installation
E_ENGINE_NOT_INSTALLED = ErrorCode("install.engine_missing")
E_ENGINE_INSTALL_FAILED = ErrorCode("install.failed")
E_ENGINE_PARENT_UNSUPPORTED = ErrorCode("env.engine_python_unsupported")
E_ENGINE_REVISION_DRIFT = ErrorCode("install.revision_drift")

# Configuration and identity
E_CONFIG_MISSING = ErrorCode("config.missing")
E_CONFIG_INVALID = ErrorCode("config.invalid")
E_CONFIG_FIELD_REQUIRED = ErrorCode("config.field_required")
E_IDENTITY_MISSING = ErrorCode("identity.hotkey_missing")
E_IDENTITY_INVALID = ErrorCode("identity.hotkey_invalid")
E_COLDKEY_REFUSED = ErrorCode("identity.coldkey_refused")
E_SECRET_MISSING = ErrorCode("secret.missing")
E_SECRET_UNSAFE_SOURCE = ErrorCode("secret.unsafe_source")

# Runtime
E_ALREADY_RUNNING = ErrorCode("run.already_running")
E_NOT_RUNNING = ErrorCode("run.not_running")
E_RUN_NOT_FOUND = ErrorCode("run.not_found")
E_RUN_INTERRUPTED = ErrorCode("run.interrupted")
# A lookup miss, not a verification refusal: the `verify.` family is documented
# as exit 20 fail-closed, and an unknown identifier is neither.
E_EVIDENCE_MISSING = ErrorCode("run.identifier_unknown")

# Verification — the fail-closed family
E_VERIFY_DIFFERENTIAL = ErrorCode("verify.differential_failed")
E_VERIFY_ATTESTATION = ErrorCode("verify.attestation_failed")
E_VERIFY_SIGNATURE = ErrorCode("verify.signature_failed")
E_VERIFY_POLICY = ErrorCode("verify.policy_refused")
E_VERIFY_FRESHNESS = ErrorCode("verify.stale")


# Contract and compatibility
E_PROTOCOL_INCOMPATIBLE = ErrorCode("contract.protocol_incompatible")
E_CHAIN_WRITES_REFUSED = ErrorCode("contract.chain_writes_refused")
E_ENGINE_INCOMPATIBLE = ErrorCode("contract.engine_incompatible")

# Outside world
E_NETWORK = ErrorCode("network.unreachable")
E_UPSTREAM_FAILED = ErrorCode("upstream.failed")

# Usage
E_USAGE = ErrorCode("usage.invalid")
E_UNKNOWN_ROLE = ErrorCode("usage.unknown_role")
E_CONFIRMATION_REQUIRED = ErrorCode("usage.confirmation_required")

E_INTERNAL = ErrorCode("internal.error")
