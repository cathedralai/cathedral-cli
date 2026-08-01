"""Where the node keeps things.

One root, one layout, overridable with ``CATHEDRAL_HOME`` so a test or a second
node on the same host is completely independent. Nothing outside this root is
written, with the single exception of the engine venvs, which live under it too.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_HOME = "CATHEDRAL_HOME"


def home() -> Path:
    """The node root. ``$CATHEDRAL_HOME`` or ``~/.cathedral``."""
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser().resolve()
    return Path.home() / ".cathedral"


def repo_root() -> Path:
    """The checked-out unified repository (where ``cathedral.lock.json`` sits)."""
    return Path(__file__).resolve().parent.parent


def lockfile() -> Path:
    """The node's pinned lockfile. ``$CATHEDRAL_LOCKFILE`` overrides the repo's own
    (used by tests and by an operator running a node from an alternate pin set)."""
    override = os.environ.get("CATHEDRAL_LOCKFILE")
    return Path(override).expanduser() if override else repo_root() / "cathedral.lock.json"


# --- per-node directories ------------------------------------------------------

def config_dir() -> Path:
    return home() / "config"


def config_file(role: str) -> Path:
    return config_dir() / f"{role}.toml"


def secrets_file() -> Path:
    """0600, never printed, never passed on a command line."""
    return home() / "secrets.env"


def trusted_signers() -> Path:
    """The trust root for verifying signed releases and re-verifying the active
    group. It is configured out of band — ``$CATHEDRAL_ALLOWED_SIGNERS`` or a fixed
    file under the node root — and must be root-owned and non-writable; it is never
    read from the release pointer or chosen per command for active verification."""
    override = os.environ.get("CATHEDRAL_ALLOWED_SIGNERS")
    return Path(override).expanduser() if override else home() / "allowed_signers"


def revocation_signers() -> Path:
    """The trust root for the *separate offline revocation authority*.

    Deliberately not the release trust root: a compromised release key must not be
    able to sign away its own revocation. Configured out of band exactly like the
    release trust root, and subject to the same ownership and mode checks.
    """
    override = os.environ.get("CATHEDRAL_REVOCATION_SIGNERS")
    return Path(override).expanduser() if override else home() / "revocation_signers"


def engines_dir() -> Path:
    return home() / "engines"


def engine_dir(role: str) -> Path:
    """One isolated tree per engine. The engines have colliding package and
    console-script names, so they can never share an environment."""
    return engines_dir() / role


def engine_generations_dir(role: str) -> Path:
    """Immutable per-install generations. A generation is built, verified, and
    hashed under its own id; the node never mutates one in place."""
    return engine_dir(role) / "generations"


def engine_generation_dir(role: str, generation: str) -> Path:
    return engine_generations_dir(role) / generation


def active_release_pointer() -> Path:
    """The single node-wide atomic pointer naming the active generation of every
    role in the release. Activation switches the whole group at once; there is no
    per-role active pointer, so roles can never drift onto mismatched releases."""
    return engines_dir() / "active-release.json"


def release_journal() -> Path:
    """The durable transaction journal for prepare/activate/rollback/recover."""
    return engines_dir() / "release-journal.jsonl"


def transaction_lock() -> Path:
    """The node-wide **lifecycle lock**.

    Install, update, recovery and rollback take it exclusively; every runtime read
    or process launch takes it *shared* for the whole operation. One file, two
    modes, so an activation can never interleave with a verify-then-execute
    sequence that has already begun.
    """
    return engines_dir() / "release.lock"


def release_floor() -> Path:
    """A durable, monotonic record of the highest committed signed ``release_version``
    and its lock digest. The replay floor is read from here — never from the group
    pointer — so a pending, missing, or corrupt pointer can never reset it to zero."""
    return engines_dir() / "release-floor.json"


def activation_journal() -> Path:
    """Append-only record of every *committed* activation. Distinct from the general
    release journal: it exists if and only if the node has ever committed a group,
    so it is one of the witnesses that a missing floor is not "fresh"."""
    return engines_dir() / "activation-journal.jsonl"


def activation_marker() -> Path:
    """Written once, at the first committed activation, and never removed. A node
    with this marker has activated a release, so a missing replay floor is lost
    anti-rollback state rather than a fresh install."""
    return engines_dir() / "activated"


def ownership_ledger() -> Path:
    """Append-only record of every launch lease: intent, ownership, release.

    Separate from the role lock because it answers a different question. The role
    lock is *current* state and can be deleted — by a crash, by a bad release, by
    an operator. The ledger is history, and history is what tells a later prune
    that a launch happened whose end was never recorded.

    It is also why deletion does not depend on scanning command lines. A descendant
    can exec a different binary, rewrite its argv, or hold mapped code with no path
    left anywhere in the process table; the ledger still says a lease was opened and
    never closed.
    """
    return state_dir() / "ownership-ledger.jsonl"


def ownership_ledger_marker() -> Path:
    """Written once, when the first launch lease is ever opened, and never removed.

    It is what makes a *missing* ledger different from a node that has never
    launched anything. Without it, deleting the ledger turns "a launch was opened
    and never closed" into "no history at all", and the deletion it was blocking
    goes ahead while the process is still running.
    """
    return state_dir() / "ownership-ledger.started"


def ownership_ledger_lock() -> Path:
    """Serialises ledger compaction. Compaction rewrites history, so it may never
    interleave with another compaction or be read half-written."""
    return state_dir() / "ownership-ledger.lock"


def rollback_ledger() -> Path:
    """Append-only record of every offline rollback.

    Deliberately separate from the external release floor: the floor answers "what
    is the lowest release this node will ever accept again", while this answers
    "which exact prior digest was restored, when, and why". Conflating them would
    let an audit question be answered by a value the transaction also has to move.
    """
    return engines_dir() / "rollback-ledger.jsonl"


def retained_releases_dir() -> Path:
    """Where signed manifests and signatures are retained for offline re-verification."""
    return engines_dir() / "releases"


def _read_group_pointer() -> dict | None:
    pointer = active_release_pointer()
    if pointer.is_symlink() or not pointer.is_file():
        return None
    try:
        import json as _json
        data = _json.loads(pointer.read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _safe_generation(value) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if "/" in value or value in ("..", "."):
        return None
    return value


def reported_generation(role: str) -> str | None:
    """The committed generation id for ``role`` **for reporting only**.

    This is a lenient read of mutable state and is *never* an authorization or an
    execution path. Nothing that launches a process, opens an interpreter, or
    resolves a managed file may call it: those paths come from a sealed
    :class:`~cathedral_node.verified.VerifiedRole` produced by one strict
    verification, so the pointer cannot change between the check and the exec.

    The execution-path helpers that used to live here (``engine_src``,
    ``engine_venv``, ``engine_bin``, ``engine_receipt``) were exactly that
    verify-then-swap window and have been removed.
    """
    data = _read_group_pointer()
    if data is None or data.get("state") != "active":
        return None
    return _safe_generation((data.get("generations") or {}).get(role))


def recovery_required() -> bool:
    """True when the group pointer names a pending (in-flight) transaction. A
    read-only path reports this; it must never itself mutate or recover."""
    data = _read_group_pointer()
    return bool(data) and data.get("state") == "pending"


def engine_legacy_dir(role: str) -> Path:
    """A pre-generation (v2) install, if any, for explicit one-time migration."""
    return engine_dir(role)


def runs_dir() -> Path:
    return home() / "runs"


RUN_ID_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class UnsafeRunId(ValueError):
    """A run id that is not usable as a single path component."""


def run_dir(run_id: str) -> Path:
    """The directory for one run.

    The id is validated, not merely joined. It arrives from the command line and
    from the *contents* of a run record, and `Path / "../x"` escapes the runs
    directory while `Path / "/abs"` discards the left side entirely — giving
    both an arbitrary read and, through the record, an arbitrary write.
    """
    if not RUN_ID_RE.match(str(run_id)):
        raise UnsafeRunId(f"{run_id!r} is not a valid run id")
    resolved = (runs_dir() / run_id).resolve()
    root = runs_dir().resolve()
    if resolved != root and root not in resolved.parents:
        raise UnsafeRunId(f"{run_id!r} resolves outside the runs directory")
    return runs_dir() / run_id


def state_dir() -> Path:
    return home() / "state"


def role_state(role: str) -> Path:
    return state_dir() / f"{role}.json"


def role_lock(role: str) -> Path:
    return state_dir() / f"{role}.lock"


def logs_dir() -> Path:
    return home() / "logs"


def cache_dir() -> Path:
    return home() / "cache"


def ensure_layout() -> None:
    """Create the directories. Idempotent; safe to call on every invocation."""
    for path in (home(), config_dir(), engines_dir(), runs_dir(), state_dir(), logs_dir(), cache_dir()):
        path.mkdir(parents=True, exist_ok=True)
    home().chmod(0o700)
    config_dir().chmod(0o700)


def relative_to_home(path: Path) -> str:
    """A **display** path that never leaks a home directory into logs or output.

    Never put this in a JSON payload: `$CATHEDRAL_HOME/runs/x` is not a path an
    agent can open. Machine-readable fields carry the absolute path and let
    redaction handle the home directory.
    """
    try:
        return "$CATHEDRAL_HOME/" + str(Path(path).resolve().relative_to(home()))
    except ValueError:
        return str(path)
