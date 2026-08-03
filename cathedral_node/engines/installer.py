"""Installing a signed release as an immutable, node-wide group of generations.

The model is verify-then-install, offline, and whole-node:

1. A release engineer publishes a **signed bundle** — one canonical manifest for the
   whole node plus, per role, the inert source archive and the *complete* hash-pinned
   wheel closure. :class:`cathedral_node.release_lock.AuthorizedBundle` turns it into
   a value that exists only after the signature and every artifact hash have verified.
2. Nothing untrusted runs before that. Each role's generation is built by the trusted
   parent interpreter and populated with ``pip --no-index --require-hashes --no-deps
   --only-binary=:all:`` from the already-verified local wheels only — no index, no
   dependency resolution, no source build, no build backend. A malicious PEP 517
   backend is never invoked because source is never built.
3. Each generation is verified in place (interpreter is a byte-copy of the trusted
   parent; declared entrypoints run and any nonzero exit fails). The receipt is
   written, the *complete* generation — source, venv, receipt and the generation root
   — is frozen read-only, and only then is the whole thing re-verified. Any failure at
   any step removes the incomplete generation before it can be named by anything.
4. All roles are prepared and health-checked, then the node-wide ``active-release``
   pointer is switched **atomically** to the new group. Any failure leaves — or
   restores — the complete prior group offline, without executing anything. No error
   path ever deletes the generation named by the committed pointer.
5. Recovery of an interrupted transaction is explicit and locked. Pending and prior
   are verified *independently and completely*, through the same verifier as the
   active group; an unverified prior is never written and never started.

Two structural properties matter more than any individual check:

**Verified state is sealed.** :func:`verify_group_pointer` is the one verifier for
active, pending and prior groups, and the only thing that can construct a
:class:`~cathedral_node.verified.VerifiedActiveGroup`. Every consumer — state,
start, test, status, doctor, capabilities, quickstart, no-op update, recovery,
rollback — receives that sealed value and takes every executable, source, venv,
receipt and configuration path from it. Nothing re-resolves a path from the mutable
pointer afterwards, and there is no process-global verdict cache to poison.

**One lifecycle lock, two modes.** Runtime reads and process launches hold
:func:`lifecycle_lock` *shared* for the whole operation and revalidate immediately
before the first child starts; install, update, recovery and rollback hold it
*exclusively*. An activation therefore cannot interleave with a verify-then-execute
sequence that has already begun.

This protects against transaction failure, crash, replay, downgrade, and tampering
by anything that is not already running as this node's operating-system user. It
does **not** claim protection from a hostile process with the same OS identity: that
needs a separate immutable filesystem or privilege boundary, which this node does
not have.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import email.parser
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat as _stat
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from cathedral_node import lockfile, paths, proc, release_lock, revocation, safeio
from cathedral_node import state as run_state
from cathedral_node import verified as verified_values
from cathedral_node.contracts.envelope import utcnow
from cathedral_node.lockfile import EnginePin
from cathedral_node.release_lock import AuthorizedBundle
from cathedral_node.verified import VerifiedActiveGroup, VerifiedRole

RECEIPT_SCHEMA = "cathedral.node.engine_receipt.v5"
POINTER_SCHEMA = "cathedral.node.active_release.v1"
FLOOR_SCHEMA = "cathedral.node.release_floor.v2"
_MIN = (3, 11)
_MAX = (3, 14)
_GEN_ID_RE = re.compile(r"^gen-[0-9a-f]{12}-[0-9a-f]{16}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_RELEASE_VERSION = 2**31

# The exact receipt key set — an unknown field is a forgery signal, not something
# to ignore. Every one of these is bound to signed, on-disk, or trusted-parent
# state by `_verify_generation`; a field with no security or audit meaning does not
# belong in the schema at all.
_RECEIPT_KEYS = {
    "schema", "role", "generation", "repository", "revision", "distribution", "version",
    "parent_base_executable", "parent_base_sha256", "venv_python", "venv_python_sha256",
    "venv_python_stat", "manifest_sha256", "source_sha256", "release_version",
    "signer_identity", "lock_digest", "extras", "entrypoints", "server_entrypoints",
    "launch_mode", "protocol", "installed_at",
}
_RECEIPT_STRING_FIELDS = (
    "schema", "role", "generation", "repository", "revision", "distribution", "version",
    "parent_base_executable", "parent_base_sha256", "venv_python", "venv_python_sha256",
    "manifest_sha256", "source_sha256", "signer_identity", "lock_digest", "launch_mode",
    "protocol", "installed_at",
)
_RECEIPT_LIST_FIELDS = ("extras", "entrypoints", "server_entrypoints")
_STAT_KEYS = ("uid", "gid", "mode", "device", "inode", "size")

_POINTER_KEYS = {"schema", "state", "generations", "release_version", "identity",
                 "lock_digest", "signature_digest", "allowed_signers", "prior", "at"}
_FLOOR_KEYS = {"schema", "release_version", "lock_digest", "identity", "committed_at"}

# Every group state this node will verify. `prior` is a committed-active document
# retained inside a pending pointer; it is verified exactly as strictly.
GROUP_ACTIVE = "active"
GROUP_PENDING = "pending"
GROUP_PRIOR = "prior"


class InstallError(Exception):
    """A refusal to install or trust an environment, with an operator message."""


class ActiveStateError(Exception):
    """The active group could not be verified. Every runtime path fails closed here."""


class Supervisor(Protocol):
    """How the transaction stops and restarts the roles a node actually runs. The
    installer owns the atomic pointer switch; the supervisor owns the processes.

    ``start`` takes the **verified group** and the exact roles to start — never a
    bare mapping of generation identifiers, which would let a caller start bytes
    that no verification ever covered. ``readiness`` must prove each role is
    actually serving via a role-specific one-shot check, not merely that a process
    exists.
    """

    def running_roles(self) -> list[str]: ...
    def stop(self, roles: list[str]) -> None: ...
    def start(self, group: VerifiedActiveGroup, roles: list[str]) -> None: ...
    def readiness(self, roles: list[str]) -> tuple[bool, str]: ...


@dataclasses.dataclass(frozen=True, slots=True)
class InstallState:
    role: str
    installed: bool
    revision: str | None
    expected_revision: str
    installed_at: str | None
    python: str | None
    drift: bool
    generation: str | None = None
    release_version: int | None = None
    signer_identity: str | None = None
    recovery_required: bool = False
    detail: str = ""

    @property
    def short_revision(self) -> str:
        return (self.revision or "")[:12]

    @property
    def expected_short_revision(self) -> str:
        return self.expected_revision[:12]

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role, "installed": self.installed, "revision": self.revision,
            "short_revision": self.short_revision or None,
            "expected_revision": self.expected_revision,
            "expected_short_revision": self.expected_short_revision,
            "installed_at": self.installed_at, "python": self.python,
            "revision_drift": self.drift, "generation": self.generation,
            "release_version": self.release_version, "signer_identity": self.signer_identity,
            "recovery_required": self.recovery_required,
        }


def _not_installed(role: str, pin_revision: str, detail: str = "",
                   recovery_required: bool = False) -> InstallState:
    return InstallState(role, False, None, pin_revision, None, None, False,
                        recovery_required=recovery_required, detail=detail)


# --- trust anchor and node target ----------------------------------------------

def trusted_base_executable() -> tuple[Path | None, str]:
    """The base executable of the running parent, if it is a supported CPython."""
    import platform
    if platform.python_implementation() != "CPython":
        return None, f"engine installs need CPython; running under {platform.python_implementation()}"
    if not (_MIN <= sys.version_info[:2] < _MAX):
        running = ".".join(str(v) for v in sys.version_info[:3])
        return None, (f"engine installs require running the node under Python 3.11-3.13; this "
                      f"process is Python {running}.")
    base = getattr(sys, "_base_executable", None) or sys.executable
    if not base or not Path(base).exists():
        return None, "the running interpreter has no resolvable base executable"
    return Path(base), ""


def _canonical(path: Path | str) -> str:
    """The canonical absolute path, with symlinks resolved. Receipts record and
    re-check canonical paths so a swapped symlink cannot change what a recorded
    path means."""
    return os.path.realpath(str(path))


def _node_target(base_exec: Path) -> tuple[tuple[int, int] | None, str, str, str]:
    """The (python_info, abi, platform) the wheels must target, queried from the
    trusted base itself. This runs only the trusted interpreter, never bundle code."""
    # The trusted parent is signed-release code's ancestor, not a host tool: it is
    # scrubbed like every other signed child, so a hostile PYTHONPATH cannot change
    # the ABI or platform this node believes it is targeting.
    probe = proc.run([str(base_exec), "-I", "-c",
                      "import sysconfig,sys;print(sys.version_info.major,sys.version_info.minor);"
                      "print(f'cp{sys.version_info.major}{sys.version_info.minor}');"
                      "print(sysconfig.get_platform())"], timeout=60,
                     inherit_env=False,
                     env=proc.signed_child_env(home=base_exec.parent))
    lines = [ln.strip() for ln in probe.stdout.splitlines() if ln.strip()]
    if not probe.ok or len(lines) < 3:
        return None, "", "", "could not query the trusted interpreter's platform"
    try:
        major, minor = (int(x) for x in lines[0].split())
    except ValueError:
        return None, "", "", "could not parse the trusted interpreter version"
    return (major, minor), lines[1], lines[2], ""


def _sha256_file(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _stat_identity(path: Path) -> dict[str, Any]:
    info = os.stat(path)
    return {"uid": info.st_uid, "gid": info.st_gid, "mode": info.st_mode & 0o7777,
            "device": info.st_dev, "inode": info.st_ino, "size": info.st_size}


def _digest(document: Any) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _aware_utc(value: Any) -> _dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


# --- generation identity and containment ---------------------------------------

def _new_generation_id(revision: str) -> str:
    return f"gen-{revision[:12]}-{os.urandom(8).hex()}"


def _no_symlinked_ancestors(path: Path, stop: Path) -> tuple[bool, str]:
    """No component from ``stop`` down to ``path`` may be a symlink — otherwise a
    swapped ancestor redirects a build or a prune outside the managed tree."""
    chain: list[Path] = []
    cursor = path
    while True:
        chain.append(cursor)
        if cursor == stop or cursor.parent == cursor:
            break
        cursor = cursor.parent
    for component in chain:
        if component.is_symlink():
            return False, f"{component} is a symlink"
    return True, "ok"


def _safe_generation_dir(role: str, generation: str) -> Path:
    if role not in lockfile.ROLES:
        raise InstallError(f"unknown engine role {role!r}")
    if not _GEN_ID_RE.match(generation):
        raise InstallError(f"invalid generation id {generation!r}")
    generations = paths.engine_generations_dir(role)
    gen = paths.engine_generation_dir(role, generation)
    ok, reason = _no_symlinked_ancestors(gen.parent, paths.home())
    if not ok:
        raise InstallError(f"refusing to build through {reason}")
    if generations.exists() and gen.resolve().parent != generations.resolve():
        raise InstallError("generation path escapes the generations directory")
    for managed in (gen, gen / "source", gen / "venv", gen / "receipt.json"):
        if managed.is_symlink():
            raise InstallError(f"{managed} is a symlink; refusing to build through it")
    return gen


# --- durable journal + atomic writes -------------------------------------------

def _journal(event: str, **fields: Any) -> None:
    """Append one transaction record — through the hardened writer.

    A plain append follows a symlink, writes happily into a FIFO, accepts a hard
    link another user can also write, and never fsyncs the directory the file was
    created in. These records are the only account of what this node did to itself,
    so they are held to the same standard as the files they describe.
    """
    safeio.secure_append(paths.release_journal(), (json.dumps(
        {"ts": utcnow(), "event": event, **fields}, sort_keys=True) + "\n").encode())


def _record_rollback(outcome: str, prior: dict | None, reason: str,
                     from_pointer: dict | None = None) -> None:
    """Append one auditable rollback record.

    Written for a refusal as well as a restoration: "we declined to roll back to
    this prior, and here is why" is exactly the record an operator needs, and
    leaving it out would make a refused rollback indistinguishable from one that
    never happened.
    """
    entry = {
        "ts": utcnow(), "outcome": outcome, "reason": reason,
        "from_release_version": (from_pointer or {}).get("release_version"),
        "from_lock_digest": (from_pointer or {}).get("lock_digest"),
        "to_release_version": (prior or {}).get("release_version"),
        "to_lock_digest": (prior or {}).get("lock_digest"),
        "to_generations": dict(sorted(((prior or {}).get("generations") or {}).items())),
    }
    safeio.secure_append(paths.rollback_ledger(),
                         (json.dumps(entry, sort_keys=True) + "\n").encode())


def _record_activation(release_version: int, lock_digest: str, generations: dict[str, str]) -> None:
    """Append-only proof that this node has committed an activation, plus a marker
    that is never removed. Together they are what makes "the replay floor is missing"
    distinguishable from "this node has never activated anything"."""
    entry = {"ts": utcnow(), "release_version": release_version, "lock_digest": lock_digest,
             "generations": dict(sorted(generations.items()))}
    safeio.secure_append(paths.activation_journal(),
                         (json.dumps(entry, sort_keys=True) + "\n").encode())
    # The marker names the release it witnesses. A bare timestamp could not tell a
    # healer whether the witness belonged to the release now committed or to the one
    # before it, so healing a v2 activation could "succeed" on a v1 marker.
    safeio.secure_write_atomic(paths.activation_marker(), json.dumps(
        {"ts": utcnow(), "release_version": release_version, "lock_digest": lock_digest},
        sort_keys=True).encode())
    # The launch-history witness belongs to an *activated* node, not only to one
    # that has started a role: without it, a deleted ledger on a fresh install is
    # indistinguishable from a deleted ledger on a node with a live child.
    with contextlib.suppress(OSError):
        run_state.mark_launch_history()

def _write_json_atomic(path: Path, document: dict[str, Any]) -> None:
    """One ``os.replace`` per durable state change. See :mod:`cathedral_node.safeio`."""
    safeio.secure_write_atomic(
        path, (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8"))


def _read_pointer() -> dict | None:
    return paths._read_group_pointer()


def _valid_generation_map(value: Any) -> bool:
    return (isinstance(value, dict) and set(value.keys()) == set(lockfile.ROLES)
            and all(isinstance(g, str) and _GEN_ID_RE.match(g) for g in value.values())
            and len(set(value.values())) == len(value))


def _parse_pointer_document(data: Any, *, allow_prior: bool) -> tuple[dict | None, str]:
    """The exact pointer schema, applied recursively.

    ``prior`` is not "a dictionary": it is a complete committed-active pointer
    document and is parsed with the identical rules. A forged prior therefore cannot
    even be read, let alone written or started.
    """
    if not isinstance(data, dict) or set(data.keys()) != _POINTER_KEYS:
        return None, "the pointer has an unexpected shape"
    if data["schema"] != POINTER_SCHEMA:
        return None, "the pointer schema is invalid"
    if data["state"] not in (GROUP_ACTIVE, GROUP_PENDING):
        return None, "the pointer state is invalid"
    if not (isinstance(data["release_version"], int) and not isinstance(data["release_version"], bool)
            and 1 <= data["release_version"] <= _MAX_RELEASE_VERSION):
        return None, "the pointer release_version is not a positive bounded integer"
    for key in ("identity", "lock_digest", "signature_digest", "allowed_signers", "at"):
        if not isinstance(data[key], str) or not data[key]:
            return None, f"the pointer {key} is not a non-empty string"
    for key in ("lock_digest", "signature_digest"):
        if not _HEX64_RE.match(data[key]):
            return None, f"the pointer {key} is not a lowercase sha256 digest"
    if _aware_utc(data["at"]) is None:
        return None, "the pointer timestamp is not aware UTC"
    if not _valid_generation_map(data["generations"]):
        return None, "the pointer generation map is not the full 3-role set"
    if data["prior"] is not None:
        if not allow_prior:
            return None, "a prior pointer may not itself carry a prior"
        prior, reason = _parse_pointer_document(data["prior"], allow_prior=False)
        if prior is None:
            return None, f"the pointer prior is malformed: {reason}"
        if prior["state"] != GROUP_ACTIVE:
            return None, "the pointer prior is not a committed active group"
    return data, "ok"


def _read_pointer_strict() -> tuple[bool, dict | None, str]:
    """Parse the group pointer with an exact, recursive key set and typed fields. A
    pointer with an unknown key, a wrong type, a malformed generation map, or a
    malformed prior is a tamper signal — it fails closed rather than being read
    leniently."""
    pointer = paths.active_release_pointer()
    if pointer.is_symlink():
        return False, None, "the active-release pointer is a symlink"
    if not pointer.is_file():
        return True, None, "no active release"
    try:
        data = json.loads(pointer.read_text())
    except (OSError, ValueError):
        return False, None, "the active-release pointer is unreadable"
    parsed, reason = _parse_pointer_document(data, allow_prior=True)
    if parsed is None:
        return False, None, f"the active-release pointer is invalid: {reason}"
    return True, parsed, "ok"


def _pointer_digest(pointer: dict) -> str:
    return release_lock.digest_bytes(release_lock.canonical_bytes(pointer))


# --- the one lifecycle lock, two modes -----------------------------------------

@contextlib.contextmanager
def lifecycle_lock(*, exclusive: bool, timeout: float = 120.0) -> Iterator[None]:
    """The node-wide lifecycle lock.

    Exclusive for install, update, recovery and rollback; shared for every runtime
    read and for the whole verify-to-launch sequence. Held on a descriptor kept open
    for the duration, so it is released the instant the holder dies.

    The lock file's inode is proved before *and* after acquisition — an advisory
    lock on a symlinked, replaced, hard-linked, foreign-owned, group-accessible or
    non-regular file excludes nobody, and a lock that excludes nobody is worse than
    no lock at all because the code above it believes it is serialised.
    """
    paths.engines_dir().mkdir(parents=True, exist_ok=True)
    busy = ("another release lifecycle operation is in progress" if exclusive else
            "a release install, update, recovery or rollback is in progress")
    try:
        with safeio.secure_lock(paths.transaction_lock(), exclusive=exclusive,
                                timeout=timeout, busy_message=busy):
            yield
    except safeio.SecureOpenError as exc:
        raise InstallError(str(exc)) from exc


def _transaction(timeout: float = 120.0):
    """The exclusive form of the lifecycle lock: one install/recover at a time, and
    never while a runtime read or launch holds the shared form."""
    return lifecycle_lock(exclusive=True, timeout=timeout)


# --- venv build + trust check --------------------------------------------------

def _verify_venv_python(venv: Path, base_exec: Path, base_sha: str) -> tuple[bool, str]:
    venv_python = venv / "bin" / "python"
    if venv_python.is_symlink() or not venv_python.is_file() or not os.access(venv_python, os.X_OK):
        return False, f"the venv python at {venv_python} is not a regular executable"
    if _sha256_file(venv_python) != base_sha:
        return False, f"the venv python is not a byte copy of the trusted interpreter {base_exec}"
    base_probe = proc.run([str(base_exec), "-I", "-c", "import sys;print(sys.base_prefix)"],
                          timeout=60, inherit_env=False,
                          env=proc.signed_child_env(home=venv.parent))
    expected_base = Path(base_probe.stdout.strip()).resolve() if base_probe.ok and base_probe.stdout.strip() else None
    probe = proc.run([str(venv_python), "-I", "-c",
                      "import sys;print(sys.prefix);print(sys.base_prefix);print(sys.executable)"],
                     timeout=60, inherit_env=False,
                     env=proc.signed_child_env(home=venv.parent))
    lines = [ln.strip() for ln in probe.stdout.splitlines()]
    if not probe.ok or len(lines) < 3 or expected_base is None:
        return False, "the venv python did not run or the base prefix is unknown"
    try:
        ok = (Path(lines[0]).resolve() == venv.resolve()
              and Path(lines[1]).resolve() == expected_base
              and Path(lines[2]).resolve() == venv_python.resolve())
    except OSError:
        return False, "could not resolve the venv interpreter's reported paths"
    return (True, "ok") if ok else (False, "the venv interpreter's prefixes are not what was built")


# --- whole-environment manifest (drift only) -----------------------------------

def _bytecode_present(root: Path) -> str | None:
    """Any ``.pyc`` or ``__pycache__`` under ``root``. Compiled bytecode is
    executable state we did not measure at install, so its mere presence is a
    refusal — the generation is built and run with bytecode writing disabled."""
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if path.name.endswith(".pyc") or "__pycache__" in rel.parts:
            return str(rel)
    return None


def _strip_bytecode(root: Path) -> None:
    """Remove all compiled bytecode a fresh venv ships (its bundled pip/setuptools
    are precompiled) so the frozen generation contains only measured ``.py`` source.
    The engines never invoke pip at runtime, so stripping it is safe, and bytecode
    writing is disabled thereafter."""
    for cache in list(root.rglob("__pycache__")):
        if cache.is_dir() and not cache.is_symlink():
            shutil.rmtree(cache, ignore_errors=True)
    for pyc in list(root.rglob("*.pyc")):
        with contextlib.suppress(OSError):
            pyc.unlink()


def _hash_tree(root: Path) -> tuple[list[list[Any]], str]:
    """Every file, dir and contained symlink under ``root`` with content, size, mode
    and owner. An escaping symlink, or any compiled bytecode, is a hard error."""
    bytecode = _bytecode_present(root)
    if bytecode is not None:
        return [], f"unmeasured bytecode present at {bytecode}"
    entries: list[list[Any]] = []
    root_resolved = root.resolve()
    for path in sorted(root.rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            target = os.readlink(path)
            resolved = (path.parent / target).resolve()
            if os.path.isabs(target) or not (resolved == root_resolved or root_resolved in resolved.parents):
                return [], f"{rel} is a symlink escaping the environment"
            st = path.lstat()
            entries.append([rel, "link", target, 0, st.st_mode & 0o7777, st.st_uid, st.st_gid])
        elif path.is_dir():
            st = path.stat()
            entries.append([rel, "dir", "", 0, st.st_mode & 0o7777, st.st_uid, st.st_gid])
        elif path.is_file():
            st = path.stat()
            entries.append([rel, "file", _sha256_file(path) or "unreadable", st.st_size,
                            st.st_mode & 0o7777, st.st_uid, st.st_gid])
    return entries, ""


def _local_manifest(gen_dir: Path, pin: EnginePin) -> tuple[bool, str, str]:
    source_entries, reason = _hash_tree(gen_dir / "source")
    if reason:
        return False, "", reason
    venv_entries, reason = _hash_tree(gen_dir / "venv")
    if reason:
        return False, "", reason
    profile = {"extras": sorted(pin.extras), "entrypoints": sorted(pin.entrypoints),
               "server_entrypoints": sorted(pin.server_entrypoints),
               "launch_mode": pin.launch_mode, "protocol": pin.protocol}
    return True, _digest({"source": source_entries, "venv": venv_entries, "profile": profile}), ""


def _freeze_readonly(root: Path) -> None:
    """Strip every write bit from a subtree so no ``.pyc`` (or anything else) can be
    written into the immutable generation at runtime."""
    for path in [root, *root.rglob("*")]:
        if path.is_symlink():
            continue
        with contextlib.suppress(OSError):
            os.chmod(path, path.stat().st_mode & ~0o222)


def _freeze_generation(gen_dir: Path) -> None:
    """Freeze the *complete* generation: source, venv, the receipt, and the
    generation root itself. Freezing only the trees left the receipt — the document
    every consumer reads as provenance — writable inside a supposedly immutable
    generation."""
    receipt = gen_dir / "receipt.json"
    if receipt.is_file() and not receipt.is_symlink():
        with contextlib.suppress(OSError):
            os.chmod(receipt, receipt.stat().st_mode & ~0o222)
    with contextlib.suppress(OSError):
        os.chmod(gen_dir, gen_dir.stat().st_mode & ~0o022)


def _force_rmtree(path: Path) -> None:
    """Remove a managed tree even though generations are deliberately frozen.

    A directory with its write bit stripped cannot have its children unlinked, so
    restoring the write bit on the *file* being removed does not help — the parent
    is what has to be writable. Without this, cleaning up a failed install or
    pruning an old generation silently left the frozen tree on disk, and a node
    that "removed" an incomplete generation had not removed anything.
    """
    with contextlib.suppress(OSError):
        if path.is_dir() and not path.is_symlink():
            for root, _dirs, _files in os.walk(path):
                with contextlib.suppress(OSError):
                    os.chmod(root, os.stat(root).st_mode | 0o700)

    def _chmod_retry(func, target, _exc):
        with contextlib.suppress(OSError):
            os.chmod(target, 0o700)
            with contextlib.suppress(OSError):
                os.chmod(Path(target).parent, 0o700)
            func(target)
    with contextlib.suppress(OSError):
        shutil.rmtree(path, onerror=_chmod_retry)


# --- the exact, monotonic replay floor -----------------------------------------

@dataclasses.dataclass(frozen=True, slots=True)
class Floor:
    release_version: int
    lock_digest: str
    identity: str
    committed_at: str


def _activation_witnesses() -> list[str]:
    """Everything that proves this node has already activated a release.

    A missing replay floor is "fresh" only when the pointer, the retained releases,
    the generations, the activation journal and the activation marker are *all*
    absent. The one carve-out is the transaction currently in flight: the pending
    pointer, and the retained release and generations that pending pointer names,
    were created seconds ago by the exclusive transaction that is asking. Counting
    those would make every first install refuse itself, which is not fail-closed,
    just broken. Everything else — including a retained release or a generation
    nothing in flight refers to — is a witness.
    """
    found: list[str] = []
    pointer_path = paths.active_release_pointer()
    inflight: dict | None = None
    if pointer_path.is_symlink():
        found.append("an active-release pointer")
    elif pointer_path.exists():
        document = paths._read_group_pointer()
        if isinstance(document, dict) and document.get("state") == GROUP_PENDING:
            inflight = document
        else:
            found.append("an active-release pointer")
    inflight_digest = str((inflight or {}).get("lock_digest") or "")
    inflight_gens = {(r, g) for r, g in ((inflight or {}).get("generations") or {}).items()}

    marker = paths.activation_marker()
    if marker.exists() or marker.is_symlink():
        found.append("an activation marker")
    journal = paths.activation_journal()
    if journal.exists() or journal.is_symlink():
        found.append("an activation journal")
    retained = paths.retained_releases_dir()
    with contextlib.suppress(OSError):
        if retained.is_dir() and any(p.name != inflight_digest for p in retained.iterdir()):
            found.append("retained signed releases")
    for role in lockfile.ROLES:
        generations = paths.engine_generations_dir(role)
        with contextlib.suppress(OSError):
            if generations.is_dir() and any((role, p.name) not in inflight_gens
                                            for p in generations.iterdir()):
                found.append(f"{role} generations")
                break
    return found


def _read_floor() -> tuple[bool, Floor | None, str]:
    """The durable replay floor, read fail-closed and parsed exactly.

    Returns ``(ok, floor, reason)``. ``floor is None`` with ``ok`` true means, and
    only means, that this node has genuinely never activated a release.
    """
    path = paths.release_floor()
    if path.is_symlink():
        return False, None, "the replay floor is a symlink"
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        witnesses = _activation_witnesses()
        if witnesses:
            return False, None, ("the durable replay floor is missing but this node has "
                                 f"already activated a release ({', '.join(witnesses)})")
        return True, None, "ok"
    except OSError as exc:
        return False, None, f"the replay floor could not be opened safely: {exc}"
    try:
        info = os.fstat(fd)
        if not _stat.S_ISREG(info.st_mode):
            return False, None, "the replay floor is not a regular file"
        if info.st_uid not in (0, os.geteuid()):
            return False, None, "the replay floor is foreign-owned"
        if info.st_mode & 0o022:
            return False, None, "the replay floor is writable by group or others"
        raw = os.read(fd, 1 << 16)
    finally:
        os.close(fd)
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False, None, "the durable replay floor is corrupt"
    if not isinstance(data, dict) or set(data.keys()) != _FLOOR_KEYS:
        return False, None, "the durable replay floor has an unknown or missing field"
    if data["schema"] != FLOOR_SCHEMA:
        return False, None, "the durable replay floor schema is unrecognised"
    version = data["release_version"]
    if not (isinstance(version, int) and not isinstance(version, bool)
            and 1 <= version <= _MAX_RELEASE_VERSION):
        return False, None, "the replay floor release_version is not a positive bounded integer"
    digest = data["lock_digest"]
    if not (isinstance(digest, str) and _HEX64_RE.match(digest)):
        return False, None, "the replay floor lock_digest is not a lowercase sha256 digest"
    identity = data["identity"]
    if identity != release_lock.RELEASE_IDENTITY:
        return False, None, "the replay floor names a different release identity"
    if _aware_utc(data["committed_at"]) is None:
        return False, None, "the replay floor committed_at is not aware UTC"
    return True, Floor(version, digest, identity, data["committed_at"]), "ok"


def _commit_floor(release_version: int, lock_digest: str) -> None:
    """Raise the floor monotonically, inside the exclusive transaction.

    Same version and same digest is idempotent. Same version and a different digest,
    or any lower version, is a hard refusal. Corrupt state is *never* repaired by
    overwrite — the evidence is preserved and an operator has to look at it.
    """
    ok, floor, reason = _read_floor()
    if not ok:
        raise InstallError(f"refusing to move the replay floor: {reason}")
    if floor is not None:
        if release_version < floor.release_version:
            raise InstallError(
                f"refusing to lower the replay floor from {floor.release_version} to "
                f"{release_version}")
        if release_version == floor.release_version:
            if lock_digest != floor.lock_digest:
                raise InstallError(
                    "refusing to replace the replay floor: a different release claims "
                    f"version {release_version}")
            return  # identical release: idempotent, nothing to write
    _write_json_atomic(paths.release_floor(), {
        "schema": FLOOR_SCHEMA, "release_version": release_version, "lock_digest": lock_digest,
        "identity": release_lock.RELEASE_IDENTITY, "committed_at": utcnow()})
    with contextlib.suppress(OSError):
        os.chmod(paths.release_floor(), 0o600)


def _floor_bounds() -> tuple[bool, int, str | None, str]:
    """The floor as the bundle verifier wants it: (ok, version, digest, reason)."""
    ok, floor, reason = _read_floor()
    if not ok:
        return False, 0, None, reason
    if floor is None:
        return True, 0, None, "ok"
    return True, floor.release_version, floor.lock_digest, "ok"


# --- executable self-check -----------------------------------------------------

# A minimal, allowlisted environment for every engine subprocess: no inherited
# PYTHON*/LD_PRELOAD/DYLD_* can influence a signed engine's imports, and bytecode
# writing is disabled so a generation never gains an unmeasured ``.pyc``.
def _scrubbed_engine_env(gen_dir: Path) -> dict[str, str]:
    """The one signed-child environment, from the one builder."""
    return proc.signed_child_env(home=gen_dir)

_SERVER_READY_WINDOW = 2.0  # a server must still be up after this; a crash exits sooner


def _self_check(venv: Path, pin: EnginePin, gen_dir: Path) -> tuple[bool, str]:
    env = _scrubbed_engine_env(gen_dir)
    run = proc.probe([str(venv / "bin" / "python"), "-I", "-B", "-c", "print('ok')"],
                     timeout=30, env=env, inherit_env=False)
    if run.returncode != 0 or run.stdout.strip() != "ok":
        return False, "the installed interpreter did not execute a trivial program"
    for entrypoint in pin.entrypoints:
        result = proc.probe([str(venv / "bin" / entrypoint), "--help"], timeout=20,
                            env=env, inherit_env=False)
        if result.timed_out:
            return False, f"client entrypoint {entrypoint!r} hung on --help"
        if result.returncode != 0:
            return False, f"client entrypoint {entrypoint!r} exited {result.returncode} on --help"
    for entrypoint in pin.server_entrypoints:
        # A server must LAUNCH AND STAY UP: it is terminated by the bounded probe
        # (timed_out) if healthy. Any exit within the window — clean or not — means it
        # did not stay serving and fails. (Real per-role readiness is proven again by
        # the supervisor at activation.)
        result = proc.probe([str(venv / "bin" / entrypoint)], timeout=_SERVER_READY_WINDOW,
                            env=env, inherit_env=False)
        if not result.timed_out:
            return False, (f"server entrypoint {entrypoint!r} exited {result.returncode} instead of "
                           f"staying up")
    return True, "ok"


# --- preparing one role's generation -------------------------------------------

# pip needs two extra names, and they are named here rather than inherited: the
# offline pins are part of the install contract, not part of the host.
_PIP_EXTRA = {"PIP_CONFIG_FILE": "/dev/null", "PIP_NO_INDEX": "1"}


def _prepare_generation(role: str, spec: release_lock.RoleRelease, bundle: AuthorizedBundle,
                        pin: EnginePin, base_exec: Path, base_sha: str, node_abi: str,
                        node_platform: str, on_progress: Callable[[str, str], None],
                        log_path: Path | None) -> str:
    """Build, verify, receipt, freeze and re-verify one generation.

    Any failure removes the incomplete generation before returning, so a half-built
    tree can never be named by a pointer, pruned around, or mistaken for a prior.
    """
    generation = _new_generation_id(spec.revision)
    gen_dir = _safe_generation_dir(role, generation)
    gen_dir.mkdir(parents=True, exist_ok=False)
    try:
        return _build_generation(role, generation, gen_dir, spec, bundle, pin, base_exec,
                                 base_sha, node_abi, node_platform, on_progress, log_path)
    except BaseException:
        _force_rmtree(gen_dir)
        _journal("PREPARE_FAILED", role=role, generation=generation)
        raise


def _build_generation(role: str, generation: str, gen_dir: Path,
                      spec: release_lock.RoleRelease, bundle: AuthorizedBundle, pin: EnginePin,
                      base_exec: Path, base_sha: str, node_abi: str, node_platform: str,
                      on_progress: Callable[[str, str], None], log_path: Path | None) -> str:
    # Inert source archive: provenance only. Copied, RE-HASHED at the destination
    # (a copy could be raced), and never built.
    source = gen_dir / "source"
    source.mkdir()
    os.chmod(source, 0o700)
    shutil.copy(bundle.source_archive(role), source / "source.tar")
    if _sha256_file(source / "source.tar") != spec.source_sha256:
        raise InstallError(f"{role}: the staged source archive does not match the signed hash")

    on_progress("environment", f"{role}: python {'.'.join(str(v) for v in sys.version_info[:2])} (trusted parent)")
    venv = gen_dir / "venv"
    build = proc.run([str(base_exec), "-I", "-m", "venv", "--copies", str(venv)], timeout=300,
                     log_path=log_path, inherit_env=False,
                     env=proc.signed_child_env(home=gen_dir))
    if not build.ok:
        raise InstallError(f"{role}: could not create the engine environment: {build.tail(4)}")
    ok, detail = _verify_venv_python(venv, base_exec, base_sha)
    if not ok:
        raise InstallError(f"{role}: {detail}")

    # Independently cross-check each wheel's internal metadata and the closure
    # BEFORE installing: filename vs METADATA name/version, WHEEL tags vs this ABI
    # and platform, and every reachable Requires-Dist present in the signed set.
    wheelhouse = bundle.directory / "roles" / role / spec.artifacts_root
    ok, detail = _verify_wheels(wheelhouse, spec, node_abi, node_platform)
    if not ok:
        raise InstallError(f"{role}: {detail}")

    # Offline, hash-pinned, wheels-only install. Requirements reference each wheel by
    # its validated single-component filename relative to the wheelhouse (cwd), so no
    # attacker-influenced path is ever interpolated into the requirements file.
    requirements = gen_dir / "requirements.txt"
    requirements.write_text("".join(f"./{a.file} --hash=sha256:{a.sha256}\n" for a in spec.artifacts))
    pip_tmp = gen_dir / "pip-tmp"
    pip_tmp.mkdir()
    env = proc.signed_child_env(home=gen_dir, tmpdir=pip_tmp, extra=_PIP_EXTRA)
    on_progress("install", f"{role}: {len(spec.artifacts)} signed wheels, offline")
    pip = proc.run([str(venv / "bin" / "python"), "-I", "-B", "-m", "pip", "install",
                    "--no-index", "--require-hashes", "--no-deps", "--only-binary=:all:",
                    "--no-compile", "-r", str(requirements)],
                   timeout=1800, inherit_env=False, env=env, cwd=wheelhouse, log_path=log_path)
    _force_rmtree(pip_tmp)
    # The requirements file was scaffolding for pip. Leaving it in the generation root
    # would be unmeasured content inside an otherwise fully measured generation.
    with contextlib.suppress(OSError):
        requirements.unlink()
    if not pip.ok:
        raise InstallError(f"{role}: offline install failed: {pip.tail(8)}")

    # The declared distribution must import; the receipt records the VERIFIED
    # installed version, cross-checked against the signed release.
    dist_ok, installed_version, dist_detail = _verify_distribution(venv, pin, gen_dir)
    if not dist_ok:
        raise InstallError(f"{role}: {dist_detail}")
    if installed_version != spec.version:
        raise InstallError(f"{role}: installed {pin.distribution} {installed_version!r} != signed {spec.version!r}")
    closure_ok, closure_detail = _verify_closure(venv, pin, gen_dir)
    if not closure_ok:
        raise InstallError(f"{role}: dependency closure/markers not satisfied: {closure_detail}")

    # Strip the venv's own precompiled bytecode, then require none remains, then
    # freeze the trees read-only so nothing can be written while the generation is live.
    _strip_bytecode(venv)
    bytecode = _bytecode_present(venv) or _bytecode_present(source)
    if bytecode is not None:
        raise InstallError(f"{role}: unexpected bytecode after install at {bytecode}")
    _freeze_readonly(venv)
    _freeze_readonly(source)

    on_progress("self-check", f"{role}: running declared entrypoints")
    ok, detail = _self_check(venv, pin, gen_dir)
    if not ok:
        raise InstallError(f"{role}: {detail}")
    # Post-health full-tree reverify: the self-check must not have produced bytecode.
    bytecode = _bytecode_present(venv) or _bytecode_present(source)
    if bytecode is not None:
        raise InstallError(f"{role}: bytecode appeared during the health check at {bytecode}")

    ok, manifest_sha, detail = _local_manifest(gen_dir, pin)
    if not ok:
        raise InstallError(f"{role}: {detail}")

    venv_python = venv / "bin" / "python"
    receipt = {
        "schema": RECEIPT_SCHEMA, "role": role, "generation": generation,
        "repository": spec.repository, "revision": spec.revision,
        "distribution": spec.distribution, "version": installed_version,
        "parent_base_executable": _canonical(base_exec), "parent_base_sha256": base_sha,
        "venv_python": str(venv_python), "venv_python_sha256": _sha256_file(venv_python),
        "venv_python_stat": _stat_identity(venv_python), "manifest_sha256": manifest_sha,
        "source_sha256": spec.source_sha256, "release_version": bundle.authorization.release_version,
        "signer_identity": bundle.authorization.identity, "lock_digest": bundle.authorization.lock_digest,
        "extras": list(spec.extras), "entrypoints": list(spec.entrypoints),
        "server_entrypoints": list(spec.server_entrypoints), "launch_mode": spec.launch_mode,
        "protocol": spec.protocol, "installed_at": utcnow(),
    }
    _write_json_atomic(gen_dir / "receipt.json", receipt)

    # Write, freeze the COMPLETE generation (receipt and root included), then
    # re-verify what is actually on disk through the same strict verifier every
    # runtime read uses. A generation that cannot pass its own verifier is removed
    # by the caller rather than published.
    _freeze_generation(gen_dir)
    expected = _expected(spec, bundle.authorization.release_version,
                         bundle.authorization.lock_digest, bundle.authorization.identity)
    ok, _data, reason = _verify_generation(pin, generation, expected, base_exec=base_exec,
                                           base_sha=base_sha)
    if not ok:
        raise InstallError(f"{role}: the freshly prepared generation did not re-verify: {reason}")
    _journal("PREPARED", role=role, generation=generation, release_version=bundle.authorization.release_version)
    return generation


def _verify_distribution(venv: Path, pin: EnginePin, gen_dir: Path) -> tuple[bool, str, str]:
    probe = proc.run([str(venv / "bin" / "python"), "-I", "-B", "-c", _IMPORT_PROBE, pin.distribution],
                     timeout=120, env=_scrubbed_engine_env(gen_dir), inherit_env=False)
    parts = probe.stdout.split()
    status = parts[0] if parts else "missing"
    version = parts[1] if len(parts) > 1 else ""
    if not probe.ok or status != "importable":
        return False, "", f"{pin.distribution} did not import from the installed wheels"
    for entrypoint in (*pin.entrypoints, *pin.server_entrypoints):
        script = venv / "bin" / entrypoint
        if not script.is_file() or script.is_symlink():
            return False, "", (f"required entrypoint {entrypoint!r} is missing — is the "
                               f"{pin.launch_mode!r} profile (extras {list(pin.extras)}) in the signed closure?")
    return True, version, "ok"


_IMPORT_PROBE = r"""
import importlib.metadata as m, importlib.util as u, sys
try:
    dist = m.distribution(sys.argv[1])
    tops = [t for t in (dist.read_text("top_level.txt") or "").splitlines() if t.strip()]
    if not tops:
        # top_level.txt is optional metadata that modern build backends omit;
        # derive the importable roots from the installed file records instead.
        roots = set()
        for f in (dist.files or []):
            first = f.parts[0]
            if len(f.parts) == 1 and first.endswith(".py"):
                first = first[:-3]
            roots.add(first)
        tops = sorted(r for r in roots if r.isidentifier())
except Exception:
    print("missing"); raise SystemExit
ok = bool(tops) and all(u.find_spec(t) is not None for t in tops)
print(("importable" if ok else "not-importable") + " " + (dist.version or ""))
"""


def _verify_closure(venv: Path, pin: EnginePin, gen_dir: Path) -> tuple[bool, str]:
    """After install, evaluate every applicable dependency marker and version
    constraint for THIS interpreter and platform using pip's vendored packaging, so a
    wheel set whose markers/versions do not match the runtime is rejected."""
    probe = proc.run([str(venv / "bin" / "python"), "-I", "-B", "-c", _CLOSURE_PROBE,
                      pin.distribution, *pin.extras], timeout=120,
                     env=_scrubbed_engine_env(gen_dir), inherit_env=False)
    try:
        result = json.loads(probe.stdout.strip() or "{}")
    except json.JSONDecodeError:
        return False, "the dependency-closure probe did not report"
    if result.get("error"):
        return False, str(result["error"])
    problems = result.get("problems") or []
    if problems:
        return False, "; ".join(problems[:4])
    return True, "ok"


_CLOSURE_PROBE = r'''
import importlib.metadata as m, json, re, sys
try:
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.markers import default_environment
except Exception as e:
    print(json.dumps({"error": "packaging is unavailable to evaluate markers: %s" % e})); raise SystemExit
def norm(n): return re.sub(r"[-_.]+", "-", n).strip("-").lower()
target = sys.argv[1]; requested = set(sys.argv[2:])
installed = {}
for d in m.distributions():
    try: installed[norm(d.metadata["Name"])] = d.version
    except Exception: pass
problems = []
def applicable(req, extras):
    if req.marker is None: return True
    for ex in [""] + sorted(extras):
        env = default_environment(); env["extra"] = ex
        try:
            if req.marker.evaluate(env): return True
        except Exception: return True
    return False
def check(distname, extras):
    try: dist = m.distribution(distname)
    except Exception:
        problems.append("distribution %s is not installed" % distname); return
    for req_str in (dist.requires or []):
        try: req = Requirement(req_str)
        except Exception: continue
        if not applicable(req, extras): continue
        nm = norm(req.name)
        if nm not in installed:
            problems.append("missing dependency %s" % req.name)
        elif req.specifier and not req.specifier.contains(installed[nm], prereleases=True):
            problems.append("%s %s does not satisfy %s" % (req.name, installed[nm], req.specifier))
check(target, requested)
for name in list(installed):
    if name != norm(target): check(name, set())
print(json.dumps({"problems": problems}))
'''


# --- independent wheel-metadata and closure cross-check ------------------------

def _verify_wheels(wheelhouse: Path, spec: release_lock.RoleRelease,
                   node_abi: str, node_platform: str) -> tuple[bool, str]:
    closure = {release_lock.normalized_name(a.name) for a in spec.artifacts}
    requested = {e.lower() for e in spec.extras}
    for artifact in spec.artifacts:
        wheel = wheelhouse / artifact.file
        try:
            with zipfile.ZipFile(wheel) as archive:
                info = _wheel_dist_info(archive, artifact.name)
                if info is None:
                    return False, f"{artifact.file} has no matching .dist-info/METADATA"
                metadata = email.parser.Parser().parsestr(
                    archive.read(f"{info}/METADATA").decode("utf-8", "replace"))
                wheel_md = email.parser.Parser().parsestr(
                    archive.read(f"{info}/WHEEL").decode("utf-8", "replace"))
        except (zipfile.BadZipFile, KeyError, OSError, RuntimeError, ValueError):
            return False, f"{artifact.file} is not a readable wheel"
        if release_lock.normalized_name(metadata.get("Name", "")) != release_lock.normalized_name(artifact.name):
            return False, f"{artifact.file}: internal Name disagrees with the signed filename"
        if (metadata.get("Version") or "") != artifact.version:
            return False, f"{artifact.file}: internal Version disagrees with the signed release"
        if not _tags_compatible(wheel_md.get_all("Tag") or [], node_abi, node_platform):
            return False, f"{artifact.file}: wheel tags are not compatible with {node_abi}/{node_platform}"
        for req in (metadata.get_all("Requires-Dist") or []):
            name, extra, has_marker = _parse_requires(req)
            if name is None:
                continue
            if extra is not None:
                if extra.lower() not in requested:
                    continue  # gated by an extra we did not request
            elif has_marker:
                continue  # a platform/python conditional; do not force it into the closure
            if release_lock.normalized_name(name) not in closure:
                return False, f"incomplete closure: {artifact.name} requires {name!r}, absent from the signed set"
    return True, "ok"


def _wheel_dist_info(archive: zipfile.ZipFile, name: str) -> str | None:
    want = release_lock.normalized_name(name)
    for entry in archive.namelist():
        if entry.endswith(".dist-info/METADATA") and entry.count("/") == 1:
            try:
                parsed = email.parser.Parser().parsestr(archive.read(entry).decode("utf-8", "replace"))
            except (KeyError, RuntimeError, ValueError):
                continue
            if release_lock.normalized_name(parsed.get("Name", "")) == want:
                return entry[: -len("/METADATA")]
    return None


def _parse_requires(req: str) -> tuple[str | None, str | None, bool]:
    head, _, marker = req.partition(";")
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", head)
    if not match:
        return None, None, False
    extra_match = re.search(r"""extra\s*==\s*["']([^"']+)["']""", marker)
    return match.group(1), (extra_match.group(1) if extra_match else None), bool(marker.strip())


def _tags_compatible(tags: list[str], node_abi: str, node_platform: str) -> bool:
    plat_norm = re.sub(r"[-.]", "_", node_platform)
    # A Linux node accepts the standard portable-Linux wheel tags for its own
    # architecture: manylinux (glibc) and musllinux (musl) are the forms PyPI
    # actually distributes; a bare linux_<arch> tag is what a local build emits.
    # The architecture must match exactly — the prefix alone never suffices.
    arch = plat_norm.split("_", 1)[1] if plat_norm.startswith("linux_") else None
    for tag in tags:
        parts = tag.split("-")
        if len(parts) != 3:
            continue
        _py, abi, plat = parts
        if abi == "none" and plat == "any":
            return True
        abi_ok = abi in (node_abi, "abi3", "none")
        plat_ok = plat == "any" or plat in plat_norm or plat_norm.startswith(plat.split("_")[0]) or (
            arch is not None and plat.endswith(f"_{arch}")
            and plat.startswith(("manylinux", "musllinux", "linux")))
        if abi_ok and plat_ok:
            return True
    return False


# --- the node-wide transaction -------------------------------------------------

def verify_bundle(bundle_dir: Path, allowed_signers_path: Path, *, identity: str,
                  base_exec: Path) -> tuple[bool, str, AuthorizedBundle | None]:
    """Verify a candidate bundle for **acquisition**: the installation and update
    window applies here and nowhere else."""
    python_info, abi, platform_token, reason = _node_target(base_exec)
    if python_info is None:
        return False, reason, None
    # The floor is durable and fail-closed: a missing/corrupt floor after activation
    # is refused, never treated as zero, so it cannot be reset to enable replay.
    fok, floor_version, floor_digest, freason = _floor_bounds()
    if not fok:
        return False, freason, None
    return AuthorizedBundle.verify(
        bundle_dir, allowed_signers_path=allowed_signers_path, identity=identity,
        python_info=python_info, abi=abi, platform_token=platform_token,
        min_release_version=floor_version, active_lock_digest=floor_digest,
        now=_dt.datetime.now(_dt.timezone.utc), mode=release_lock.CANDIDATE_ACQUISITION,
    )


def install_release(bundle_dir: Path, lock: lockfile.Lock, allowed_signers_path: Path, *,
                    identity: str, supervisor: Supervisor | None = None,
                    on_progress: Callable[[str, str], None] = lambda _l, _d: None,
                    log_path: Path | None = None, revocation_channel: str | None = None,
                    lock_timeout: float = 120.0) -> tuple[bool, str, dict[str, Any]]:
    """Verify a signed bundle and switch the whole node to it in one transaction.

    A release always covers the entire node (compute + distill + validator); there
    is no per-role subset, so a partial or role-steered release cannot be applied.
    """
    try:
        with _transaction(lock_timeout):
            return _install_release(bundle_dir, lock, allowed_signers_path, identity=identity,
                                    supervisor=supervisor, on_progress=on_progress,
                                    log_path=log_path, revocation_channel=revocation_channel)
    except InstallError as exc:
        return False, str(exc), {}
    except Exception as exc:  # noqa: BLE001 - an install never surfaces a raw traceback
        # Any other failure inside the transaction (an unwritable receipt, a full
        # disk) has already unwound its own generation; report it as a refusal so
        # the caller cannot mistake a traceback for an ambiguous outcome.
        return False, f"the install transaction failed and was unwound: {exc}", {}


def _install_release(bundle_dir, lock, allowed_signers_path, *, identity, supervisor,
                     on_progress, log_path, revocation_channel) -> tuple[bool, str, dict[str, Any]]:
    now = _dt.datetime.now(_dt.timezone.utc)
    base_exec, reason = trusted_base_executable()
    if base_exec is None:
        raise InstallError(reason)
    base_sha = _sha256_file(base_exec)
    if base_sha is None:
        raise InstallError(f"cannot read the trusted base executable at {base_exec}")
    python_info, node_abi, node_platform, target_reason = _node_target(base_exec)
    if python_info is None:
        raise InstallError(target_reason)

    # Revocation first, and before any bundle code path: acquiring a candidate needs
    # signed revocation state that is both present AND inside its validity window. A
    # channel outage degrades to the retained snapshot only while that snapshot is
    # still fresh; no snapshot, or an expired one, refuses the acquisition outright.
    on_progress("revocation", "signed revocation state")
    revocation.refresh(revocation_channel, now=now)
    trust_text = _release_trust_text(allowed_signers_path)
    rok, rreason, rstate = revocation.enforce(
        "", trust_text, identity, now=now, policy=revocation.ACQUISITION)
    if not rok or rstate is None:
        raise InstallError(f"refusing to acquire a release: {rreason}")

    on_progress("verify", "signature and every artifact hash")
    fok, floor_version, floor_digest, freason = _floor_bounds()
    if not fok:
        raise InstallError(freason)

    # An existing pointer must verify completely before anything is installed over
    # it. Installing on top of an unverifiable active group would launder a tampered
    # or interrupted node into a "successful" update.
    pok, pointer, preason = _read_pointer_strict()
    if not pok:
        raise InstallError(f"refusing to install over unreadable release state: {preason}")
    active_group: VerifiedActiveGroup | None = None
    if pointer is not None:
        if pointer["state"] != GROUP_ACTIVE:
            raise InstallError("a previous release transaction was interrupted; run `cathedral recover` "
                               "before installing or updating")
        aok, areason, active_group = verify_group_pointer(pointer, GROUP_ACTIVE, lock,
                                                          Path(paths.trusted_signers()),
                                                          base_exec=base_exec, now=now)
        if not aok or active_group is None:
            raise InstallError(f"refusing to update: the existing active group does not verify "
                               f"({areason}). Nothing was installed and nothing was started.")
        if active_group.release_version > floor_version:
            floor_version, floor_digest = active_group.release_version, active_group.lock_digest

    ok, reason, bundle = AuthorizedBundle.verify(
        bundle_dir, allowed_signers_path=allowed_signers_path, identity=identity,
        python_info=python_info, abi=node_abi, platform_token=node_platform,
        min_release_version=floor_version, active_lock_digest=floor_digest,
        now=now, mode=release_lock.CANDIDATE_ACQUISITION)
    if not ok or bundle is None:
        raise InstallError(f"the release bundle did not verify: {reason}")
    auth = bundle.authorization
    # The full enforcement, now that the candidate's own digest is known — still
    # before a single generation directory is created, so neither the candidate
    # interpreter nor any declared entrypoint can run for a revoked release or a
    # revoked signer.
    rok, rreason, _rstate = revocation.enforce(
        auth.lock_digest, trust_text, identity, now=now, policy=revocation.ACQUISITION)
    if not rok:
        raise InstallError(f"refusing to acquire release {auth.release_version}: {rreason}")

    # A signed release describes exactly the node-wide role set, and the local lock
    # must pin the same three roles — no subset, in either direction.
    if set(auth.roles.keys()) != set(lockfile.ROLES) or set(lock.engines.keys()) != set(lockfile.ROLES):
        raise InstallError("a release must cover exactly the compute, distill and validator roles")

    # A true no-op: the same signed release is already active, and the whole active
    # group has just re-verified above. An idempotent update never papers over a
    # tampered current generation, because an unverified group already refused.
    if active_group is not None and active_group.lock_digest == auth.lock_digest:
        # An idempotent re-apply is also the repair path. If a previous run committed
        # the release but died before writing its witnesses, this is where they are
        # healed — otherwise the node would carry a committed release with no
        # activation marker forever, and a later missing floor would read as fresh.
        healed = _heal_activation_witnesses(active_group)
        detail = f"release {auth.release_version} already active"
        if healed:
            detail = f"{detail} — healed missing activation witnesses ({', '.join(healed)})"
        return True, detail, {
            "generations": active_group.generations(), "release_version": auth.release_version,
            "signer_identity": auth.identity, "lock_digest": auth.lock_digest,
            "healed_witnesses": healed}

    signature_digest = release_lock.digest_bytes((Path(bundle_dir) / "release.json.sig").read_bytes())

    prepared: dict[str, str] = {}
    try:
        for role in lockfile.ROLES:
            pin = lock.pin(role)
            authorized, why, _spec = release_lock.authorize_role(
                auth, role, repository=pin.repository, revision=pin.revision,
                distribution=pin.distribution, extras=list(pin.extras),
                entrypoints=list(pin.entrypoints), server_entrypoints=list(pin.server_entrypoints),
                protocol=pin.protocol, launch_mode=pin.launch_mode)
            if not authorized:
                raise InstallError(why)
            spec = auth.role(role)
            prepared[role] = _prepare_generation(role, spec, bundle, pin, base_exec, base_sha,
                                                  node_abi, node_platform, on_progress, log_path)
    except Exception:
        _cleanup_uncommitted(prepared)
        _discard_unreferenced_release(auth.lock_digest)
        raise

    # Retain the signed manifest+signature durably (atomic, mandatory) BEFORE the
    # pointer moves, so recovery and active verification can always re-verify offline.
    # If it cannot be made durable the install fails — and takes its own debris with
    # it, so the next attempt starts from the same state as the first.
    try:
        _retain_signed_release(bundle_dir, auth)
    except (InstallError, OSError) as exc:
        _cleanup_uncommitted(prepared)
        _discard_unreferenced_release(auth.lock_digest)
        _clear_retry_blockers(None if active_group is None else pointer)
        raise InstallError(f"the signed release could not be retained: {exc}") from exc
    # `prior` is captured ONLY from the group that just verified completely. An
    # unverified or merely well-formed pointer is never promoted into a restorable
    # prior.
    # Exactly one generation of history: the prior's own `prior` is dropped, so a
    # pointer never carries a chain. `_safe_prune` keeps precisely these two
    # generations per role, so a deeper chain could only ever name pruned bytes.
    prior = {**pointer, "prior": None} if active_group is not None else None
    running_before = _roles_running()

    pending = {"schema": POINTER_SCHEMA, "state": GROUP_PENDING, "generations": prepared,
               "release_version": auth.release_version, "identity": auth.identity,
               "lock_digest": auth.lock_digest, "signature_digest": signature_digest,
               "allowed_signers": str(allowed_signers_path),
               "prior": prior, "at": utcnow()}
    try:
        _write_json_atomic(paths.active_release_pointer(), pending)
    except (InstallError, OSError) as exc:
        # The pending pointer never landed, so nothing on disk references these
        # generations or this retained release. They must go: left behind, they are
        # activation witnesses, and the next `_read_floor` would see witnesses with
        # no floor beside them and fail closed forever on a node that in fact never
        # committed anything.
        _cleanup_uncommitted(prepared, keep_group=prior)
        _discard_unreferenced_release(auth.lock_digest)
        _clear_retry_blockers(None if active_group is None else pointer)
        raise InstallError(f"the release pointer could not be written: {exc}") from exc
    try:
        _journal("ACTIVATING", generations=prepared, release_version=auth.release_version)
    except OSError as exc:
        # The PENDING POINTER IS ALREADY ON DISK. Unwinding here — or reporting that
        # nothing happened — would describe a node that does not exist: the very
        # next read sees an interrupted transaction. So nothing is removed and the
        # caller is told the true state, which is that recovery must finish it.
        raise InstallError(
            f"the pending release pointer was written but the activation journal could not be "
            f"({exc}). Nothing was unwound: an interrupted transaction is recorded and "
            f"`cathedral recover` must finish or undo it.") from exc

    ok, detail, pending_group = _qualify_and_switch(pending, lock, supervisor, running_before,
                                                    base_exec=base_exec, now=now)
    if not ok or pending_group is None:
        rolled_back, rollback_detail = _rollback_group(
            prior, lock, supervisor, running_before, base_exec=base_exec, now=now,
            from_pointer=pending)
        # The event NAME is the durable claim. Writing "ROLLED_BACK" for a rollback
        # that did not happen — even with recovered=False alongside it — tells every
        # later reader, and every operator scanning the journal, that this node was
        # returned to its prior release. It was not.
        _journal("ROLLED_BACK" if rolled_back else "ROLLBACK_INCOMPLETE",
                 reason=detail, rollback=rollback_detail,
                 release_version=auth.release_version, recovered=rolled_back)
        if not rolled_back:
            # The rollback did not complete. Something may still be executing the
            # generation we prepared, and the pointer is whatever the rollback left.
            # Removing those files now would delete text a live process can still
            # fault in, so nothing is cleaned up and the operator is told both halves.
            raise InstallError(
                f"activation failed ({detail}) AND the rollback did not complete "
                f"({rollback_detail}); nothing was removed. Run `cathedral recover`.")
        _cleanup_uncommitted(prepared, keep_group=prior)
        _discard_unreferenced_release(auth.lock_digest)
        _clear_retry_blockers(prior)
        raise InstallError(f"activation failed, rolled back to the prior release: {detail}")

    # Raise the durable floor, then commit. On a crash between the two, the floor is
    # already >= this release and the pointer is still pending -> recovery re-commits.
    try:
        _commit_floor(auth.release_version, auth.lock_digest)
        _write_json_atomic(paths.active_release_pointer(), {**pending, "state": GROUP_ACTIVE})
    except (InstallError, OSError) as exc:
        # Before deciding this failed, look at what is actually on disk. The publish
        # is one `os.replace`, and a failure *after* it — the directory fsync, for
        # instance — leaves the pointer committed. Unwinding then would remove the
        # files a committed release names.
        published_ok, published, _published_reason = _read_pointer_strict()
        if published_ok and published is not None and published["state"] == GROUP_ACTIVE \
                and published.get("lock_digest") == auth.lock_digest:
            witnesses = (f"the release is active, but the commit did not finish cleanly ({exc}); "
                         f"re-run the same install to heal it")
            _safe_prune(active=prepared, prior=prior)
            return True, f"release {auth.release_version} active — {witnesses}", {
                "generations": prepared, "release_version": auth.release_version,
                "signer_identity": auth.identity, "lock_digest": auth.lock_digest,
                "witnesses_incomplete": True}
        # The floor or the commit failed. Nothing has been declared active, so the
        # node must be left able to retry: no activation witness may survive that
        # would make a later `_read_floor` treat this node as "already activated".
        rolled_back, rollback_detail = _rollback_group(
            prior, lock, supervisor, running_before, base_exec=base_exec, now=now,
            from_pointer=pending)
        if rolled_back:
            _cleanup_uncommitted(prepared, keep_group=prior)
            _discard_unreferenced_release(auth.lock_digest)
            _clear_retry_blockers(prior)
        raise InstallError(f"the activation could not be committed ({exc}); "
                           f"rollback: {rollback_detail}") from exc
    # PAST THE POINT OF NO RETURN. The floor is raised and the pointer is committed,
    # so this release IS active. A failure to write the witnesses that come after is
    # a real problem — a later missing-floor read depends on them — but reporting it
    # as a failed install would be false, and would invite an operator to "retry"
    # something that already happened. Report success, say exactly what is missing,
    # and let the idempotent retry heal it.
    witnesses = ""
    try:
        _record_activation(auth.release_version, auth.lock_digest, prepared)
        _journal("ACTIVE", generations=prepared, release_version=auth.release_version)
    except OSError as exc:
        witnesses = (f"the release is active, but its activation witnesses could not be written "
                     f"({exc}); re-run the same install to heal them")
    _safe_prune(active=prepared, prior=prior)
    _migrate_legacy_after_active()
    detail = f"release {auth.release_version} active"
    if witnesses:
        detail = f"{detail} — {witnesses}"
    return True, detail, {"generations": prepared, "release_version": auth.release_version,
                          "signer_identity": auth.identity, "lock_digest": auth.lock_digest,
                          "witnesses_incomplete": bool(witnesses)}


def _heal_activation_witnesses(group: VerifiedActiveGroup) -> list[str]:
    """Write the activation witnesses a committed release should already have.

    Safe because it is only reachable with a fully verified committed group whose
    pointer equals the floor: the activation being recorded is one that provably
    happened. Only what is missing is written, so this never invents history.
    """
    missing = _missing_activation_witnesses({"release_version": group.release_version,
                                             "lock_digest": group.lock_digest})
    if missing:
        _record_activation(group.release_version, group.lock_digest, group.generations())
    return missing


def _qualify_and_switch(pending: dict, lock: lockfile.Lock, supervisor: Supervisor | None,
                        running_before: list[str], *, base_exec: Path, now: _dt.datetime,
                        ) -> tuple[bool, str, VerifiedActiveGroup | None]:
    """Verify the pending group through the one verifier, then (if roles are running)
    stop the prior set, start the **verified** set, and prove per-role readiness."""
    ok, reason, group = verify_group_pointer(pending, GROUP_PENDING, lock,
                                             Path(paths.trusted_signers()),
                                             base_exec=base_exec, now=now)
    if not ok or group is None:
        return False, reason, None
    if not running_before:
        return True, "ok", group  # nothing to restart; the pointer switch is the activation
    if supervisor is None:
        return False, (f"roles are running ({', '.join(running_before)}) but no supervisor was "
                       f"provided to stop and restart them; refusing to switch under them"), None
    stopped, stop_detail = _prove_stopped(supervisor, list(running_before))
    if not stopped:
        return False, stop_detail, None
    try:
        supervisor.start(group, list(running_before))
        ready, detail = supervisor.readiness(running_before)
    except Exception as exc:  # noqa: BLE001 - a supervisor error is a rollback, not a crash
        return False, f"supervisor error: {exc}", None
    return (ready, detail, group if ready else None)


def _rollback_group(prior: dict | None, lock: lockfile.Lock, supervisor: Supervisor | None,
                    running_before: list[str], *, base_exec: Path | None = None,
                    now: _dt.datetime | None = None,
                    from_pointer: dict | None = None) -> tuple[bool, str]:
    """Restore the exact prior group — but only after verifying it independently and
    completely, through the same verifier as the active group.

    A prior that does not verify is never written and never started. That is the
    whole point: a forged ``prior`` inside a pending pointer must not be able to
    select executable generations.
    """
    # Order matters and is the whole safety property: verify the prior, then STOP
    # and prove the pending process group is gone, and only then move the pointer.
    # A pointer published over a still-running process describes bytes that are not
    # what is executing.
    if prior is not None:
        ok, reason, group = verify_group_pointer(prior, GROUP_PRIOR, lock,
                                                 Path(paths.trusted_signers()),
                                                 base_exec=base_exec, now=now)
        if not ok or group is None:
            _journal("PRIOR_REFUSED", reason=reason)
            _record_rollback("refused", prior, reason, from_pointer)
            return False, (f"the recorded prior release did not verify ({reason}); it was neither "
                           f"restored nor started")
    else:
        group = None

    stopped, stop_detail = _prove_stopped(supervisor, list(running_before))
    if not stopped:
        _journal("ROLLBACK_BLOCKED", reason=stop_detail)
        _record_rollback("blocked", prior, stop_detail, from_pointer)
        return False, f"rollback did not proceed: {stop_detail}"

    if prior is None:
        try:
            _clear_pointer()
        except OSError as exc:
            # The pending pointer is still on disk. Recording ROLLED_BACK here would
            # claim a fresh node while an interrupted transaction is still what the
            # next read finds.
            _journal("ROLLBACK_INCOMPLETE", reason=f"the pending pointer could not be removed: {exc}")
            _record_rollback("blocked", None, f"the pending pointer could not be removed: {exc}",
                             from_pointer)
            return False, (f"the pending release pointer could not be removed ({exc}); the "
                           f"interrupted transaction is still recorded")
        if paths.recovery_required():
            _journal("ROLLBACK_INCOMPLETE", reason="the pending pointer survived removal")
            return False, "the pending release pointer survived removal; nothing was rolled back"
        _record_rollback("cleared", None, "no prior release to restore", from_pointer)
        return True, "no prior release to restore; the pointer was cleared"

    if not running_before or supervisor is None:
        # Nothing to restart, so publishing IS the restoration.
        _write_json_atomic(paths.active_release_pointer(), prior)
        _record_rollback("restored", prior, "restored offline; no role was running",
                         from_pointer)
        return True, "restored the verified prior release"

    # A role has to come back up. The prior pointer is NOT published yet: if the
    # restart or the readiness check fails after it were published, the pointer
    # would read as a healthy committed group, `recovery_required()` would be
    # false, and the next `cathedral recover` would answer "nothing to recover"
    # about a node whose validator never came back. The interrupted transaction's
    # pending pointer stays on disk as the witness until the prior group is
    # genuinely serving.
    try:
        supervisor.start(group, list(running_before))
        ready, detail = supervisor.readiness(running_before)
    except Exception as exc:  # noqa: BLE001
        _record_rollback("restart_failed", prior, f"supervisor error: {exc}", from_pointer)
        return False, (f"the prior release verified but could not be restarted ({exc}); the "
                       f"interrupted transaction is still recorded and recovery is still required")
    if not ready:
        _record_rollback("restart_failed", prior, detail, from_pointer)
        return False, (f"the prior release verified but did not become ready ({detail}); the "
                       f"interrupted transaction is still recorded and recovery is still required")
    _write_json_atomic(paths.active_release_pointer(), prior)
    _record_rollback("restored", prior, "restored and restarted", from_pointer)
    return True, "restored and restarted the verified prior release"


def _clear_pointer() -> None:
    with contextlib.suppress(OSError):
        paths.active_release_pointer().unlink()


def _prove_stopped(supervisor: Supervisor | None, roles: list[str]) -> tuple[bool, str]:
    """Stop ``roles`` and *prove* the processes are gone.

    ``stop`` returning is not evidence. Until the old process group has actually
    exited, the generation it is executing is still live code: publishing a new
    pointer over it leaves a running process whose bytes no longer match the
    pointer, and removing its files removes text a running process may still fault
    in. Both are refused until termination is proven, by asking the supervisor
    which roles it still considers running and by checking this node's own durable
    role locks.
    """
    if not roles:
        return True, "no role was running"
    if supervisor is None:
        return False, (f"roles are running ({', '.join(roles)}) but no supervisor was provided "
                       f"to stop them")
    try:
        supervisor.stop(list(roles))
        still = set(supervisor.running_roles() or [])
    except Exception as exc:  # noqa: BLE001 - a supervisor error is a refusal, not a crash
        return False, f"supervisor error while stopping: {exc}"
    lingering = sorted((still & set(roles)) | (set(_roles_running()) & set(roles)))
    if lingering:
        return False, (f"{', '.join(lingering)} did not terminate; refusing to publish a pointer "
                       f"or remove files a running process may still execute")
    return True, "stopped"


def _roles_running() -> list[str]:
    """Which roles must be proven stopped before the group pointer may move.

    Deliberately not ``running_run``. The run record is written by the launcher and
    describes what the launcher *believed*; a killed launcher leaves it absent or
    finished while the process group it started is still executing. Publishing a new
    pointer on that evidence produces a node whose status names generation B while
    generation A is what is actually running.

    Ownership and the launch ledger are durable and survive the launcher, so they
    decide. A role whose state cannot be established counts as running: refusing to
    switch is recoverable, switching under a live process is not.
    """
    running: list[str] = []
    for role in lockfile.ROLES:
        if run_state.running_run(role) is not None:
            running.append(role)
            continue
        blocked, _reason = run_state.deletion_blocked(role)
        if blocked:
            running.append(role)
    return running


def _retain_signed_release(bundle_dir: Path, auth: release_lock.ReleaseAuthorization) -> None:
    """Copy the signed manifest+signature into the retained store atomically. This is
    mandatory: if it cannot be made durable, the install fails rather than leave a
    release that cannot later be re-verified."""
    keep = paths.retained_releases_dir() / auth.lock_digest
    keep.mkdir(parents=True, exist_ok=True)
    for name in ("release.json", "release.json.sig"):
        source = Path(bundle_dir) / name
        try:
            data = source.read_bytes()
        except OSError as exc:
            raise InstallError(f"cannot read {name} to retain the signed release: {exc}") from exc
        fd, tmp = tempfile.mkstemp(prefix=".tmp.", dir=str(keep))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, keep / name)
        except OSError as exc:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise InstallError(f"cannot durably retain {name}: {exc}") from exc
    dir_fd = os.open(str(keep), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _clear_retry_blockers(committed: dict | None) -> None:
    """Remove anything a failed, fully-unwound attempt left that would make a later
    read believe this node has activated a release.

    A node that never committed must look exactly as it did before the attempt.
    Otherwise `_read_floor` sees an activation witness with no floor beside it, and
    fails closed forever on a node that in fact has nothing to protect — turning a
    failed install into an unrecoverable one.
    """
    if committed is not None:
        return  # a real committed group is present; its witnesses are legitimate
    pointer = paths.active_release_pointer()
    if pointer.is_symlink() or pointer.is_file():
        document = paths._read_group_pointer()
        if not (isinstance(document, dict) and document.get("state") == GROUP_ACTIVE):
            with contextlib.suppress(OSError):
                pointer.unlink()
    # The marker and the activation journal are written only at commit; if this node
    # has never committed, their presence can only be debris from an attempt that
    # did not.
    if not _has_committed_activation():
        for witness in (paths.activation_marker(), paths.activation_journal()):
            with contextlib.suppress(OSError):
                if witness.is_symlink() or witness.is_file():
                    witness.unlink()
        retained = paths.retained_releases_dir()
        with contextlib.suppress(OSError):
            if retained.is_dir() and not any(retained.iterdir()):
                retained.rmdir()


def _has_committed_activation() -> bool:
    """True when a committed active pointer or a durable replay floor exists. Either
    one is proof this node really did activate a release at some point."""
    document = paths._read_group_pointer()
    if isinstance(document, dict) and document.get("state") == GROUP_ACTIVE:
        return True
    floor_path = paths.release_floor()
    return floor_path.is_file() or floor_path.is_symlink()


def _discard_unreferenced_release(lock_digest: str) -> None:
    """Remove a retained release nothing points at.

    Without this a failed *first* install would leave a retained release behind, and
    the node would no longer look fresh — turning an install that changed nothing
    into a permanently fail-closed replay floor.
    """
    referenced: set[str] = set()
    for group in (_read_pointer(),):
        if isinstance(group, dict):
            if isinstance(group.get("lock_digest"), str):
                referenced.add(group["lock_digest"])
            prior = group.get("prior")
            if isinstance(prior, dict) and isinstance(prior.get("lock_digest"), str):
                referenced.add(prior["lock_digest"])
    if lock_digest in referenced or not _HEX64_RE.match(str(lock_digest)):
        return
    _force_rmtree(paths.retained_releases_dir() / lock_digest)


def _cleanup_uncommitted(prepared: dict[str, str], keep_group: dict | None = None) -> None:
    """Remove freshly-prepared generations that were never committed. Never touch a
    generation named by the committed (or retained-prior) pointer."""
    protected = _protected_generations(keep_group)
    for role, generation in prepared.items():
        if (role, generation) in protected:
            continue
        blocked, reason = run_state.deletion_blocked(role)
        if blocked:
            _journal("CLEANUP_SKIPPED", role=role, generation=generation, reason=reason)
            continue
        gen_dir = paths.engine_generation_dir(role, generation)
        if gen_dir.is_dir() and not gen_dir.is_symlink():
            _force_rmtree(gen_dir)


def _protected_generations(*groups: dict | None) -> set[tuple[str, str]]:
    protected: set[tuple[str, str]] = set()
    for group in (_read_pointer(), *groups):
        if isinstance(group, dict):
            for role, generation in (group.get("generations") or {}).items():
                if isinstance(generation, str):
                    protected.add((role, generation))
            prior = group.get("prior")
            if isinstance(prior, dict):
                for role, generation in (prior.get("generations") or {}).items():
                    if isinstance(generation, str):
                        protected.add((role, generation))
    return protected


def _safe_prune(active: dict[str, str], prior: dict | None) -> None:
    """Keep the active and immediately-prior generation of each role; remove older
    ones. Guarded so a failure can never delete an active generation — and skipped
    entirely for any role whose ownership cannot be proven finished, because a live
    descendant is still faulting text out of the generation a prune would remove."""
    keep = _protected_generations()  # reads the committed pointer (active + its prior)
    for role, generation in active.items():
        keep.add((role, generation))
    if isinstance(prior, dict):
        for role, generation in (prior.get("generations") or {}).items():
            keep.add((role, generation))
    for role in lockfile.ROLES:
        root = paths.engine_generations_dir(role)
        if not root.is_dir():
            continue
        blocked, reason = run_state.deletion_blocked(role)
        if blocked:
            _journal("PRUNE_SKIPPED", role=role, reason=reason)
            continue
        for child in list(root.iterdir()):
            if child.is_dir() and not child.is_symlink() and (role, child.name) not in keep:
                _force_rmtree(child)


# --- strict group verification -------------------------------------------------

def _release_trust_text(allowed_signers_path: Path) -> str:
    """The release trust file's contents, or empty. Revocation needs the text to
    compute the signer fingerprints it may have revoked; an unreadable trust root is
    already a refusal everywhere else, so an empty string here simply means no
    fingerprint matches and the other checks still speak."""
    ok, _reason, text = release_lock.read_trust_file(Path(allowed_signers_path))
    return text if ok and text else ""


def _trust_names_identity(allowed_signers: str, identity: str) -> bool:
    for line in allowed_signers.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and identity in stripped.split()[0].split(","):
            return True
    return False


def _expected(spec: release_lock.RoleRelease, release_version: int, lock_digest: str,
              identity: str) -> dict[str, Any]:
    """Every launch-relevant fact the receipt must equal, taken from the SIGNED role
    spec and the verified pointer — the receipt's own claims are never trusted."""
    return {"repository": spec.repository, "revision": spec.revision, "distribution": spec.distribution,
            "version": spec.version, "source_sha256": spec.source_sha256, "extras": sorted(spec.extras),
            "entrypoints": sorted(spec.entrypoints), "server_entrypoints": sorted(spec.server_entrypoints),
            "launch_mode": spec.launch_mode, "protocol": spec.protocol,
            "release_version": release_version, "signer_identity": identity, "lock_digest": lock_digest}


def verify_group_pointer(pointer: dict | None, expected_state: str, lock: lockfile.Lock,
                         trusted_signers: Path, *, base_exec: Path | None = None,
                         now: _dt.datetime | None = None,
                         ) -> tuple[bool, str, VerifiedActiveGroup | None]:
    """The one verifier for **active, pending and prior** groups.

    ``pointer`` is the exact document to verify, or ``None`` to read the on-disk
    active pointer strictly. ``expected_state`` is one of ``active``, ``pending`` or
    ``prior``; it selects the floor relationship and the manifest validation mode and
    nothing else, so all three states get identical scrutiny of the signature, the
    retained manifest, the trust root, revocation, the lock, and every generation.

    It verifies, in order:

    1. the exact recursive pointer schema and the expected state;
    2. the pinned signer identity and the trust root taken from configuration;
    3. the retained manifest and signature under the named release digest;
    4. cached, signed revocation state, offline;
    5. the replay-floor relationship for this state;
    6. current lock authorization for every one of exactly three roles;
    7. every generation, receipt, interpreter and managed file.

    On success it returns the sealed :class:`VerifiedActiveGroup` — the only value
    from which a runtime consumer may take an executable path.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    if expected_state not in (GROUP_ACTIVE, GROUP_PENDING, GROUP_PRIOR):
        return False, f"unknown group state {expected_state!r}", None

    if pointer is None:
        pok, pointer, preason = _read_pointer_strict()
        if not pok:
            return False, preason, None
        if pointer is None:
            return False, "no active release", None
    else:
        parsed, reason = _parse_pointer_document(pointer, allow_prior=(expected_state != GROUP_PRIOR))
        if parsed is None:
            return False, f"the {expected_state} pointer is invalid: {reason}", None
        pointer = parsed

    on_disk_state = pointer["state"]
    if expected_state == GROUP_PENDING and on_disk_state != GROUP_PENDING:
        return False, "the pointer does not name a pending transaction", None
    if expected_state in (GROUP_ACTIVE, GROUP_PRIOR) and on_disk_state != GROUP_ACTIVE:
        return False, "recovery required (an interrupted transaction is pending)", None

    identity = release_lock.RELEASE_IDENTITY
    # The pointer's own identity is informational, but it must equal the pinned signer;
    # a mismatch is a tamper signal even though trust itself comes from config below.
    if pointer["identity"] != identity:
        return False, "the pointer identity is not the pinned release signer", None
    # The trust root comes from configuration, NEVER the pointer's allowed_signers field.
    tok, treason, allowed = release_lock.read_trust_file(Path(trusted_signers))
    if not tok or allowed is None:
        return False, f"trust root: {treason}", None
    if not _trust_names_identity(allowed, identity):
        return False, f"the trust root does not authorize {identity}", None

    if base_exec is None:
        base_exec, breason = trusted_base_executable()
        if base_exec is None:
            return False, breason, None
    base_sha = _sha256_file(base_exec)
    if base_sha is None:
        return False, f"cannot read the trusted base executable at {base_exec}", None
    python_info, abi, platform_token, treason2 = _node_target(base_exec)
    if python_info is None:
        return False, treason2, None

    fok, floor, freason = _read_floor()
    if not fok:
        return False, freason, None

    # --- the floor relationship, per state ------------------------------------
    version, digest = pointer["release_version"], pointer["lock_digest"]
    if expected_state in (GROUP_ACTIVE, GROUP_PRIOR):
        # A committed pointer must equal the floor exactly. Anything else is either
        # a rollback below the floor or a floor that lost the activation it recorded.
        if floor is None:
            return False, ("the durable replay floor is absent while a committed release is "
                           "active"), None
        if version != floor.release_version or digest != floor.lock_digest:
            return False, (f"the committed release ({version}) does not exactly equal the durable "
                           f"replay floor ({floor.release_version})"), None
        manifest_mode = release_lock.RETAINED_RUNTIME
    else:
        if floor is not None:
            if version < floor.release_version:
                return False, "the pending release is older than the durable floor", None
            if version == floor.release_version and digest != floor.lock_digest:
                return False, "the pending release digest disagrees with the floor", None
        # Rule: a pending release the floor ALREADY names was acquired and committed
        # before the interruption — finishing it must not reapply the acquisition
        # window. A pending release not yet committed to the floor is still an
        # acquisition and must remain inside its activation window.
        committed = floor is not None and version == floor.release_version and digest == floor.lock_digest
        manifest_mode = release_lock.PENDING_RECOVERY if committed else release_lock.CANDIDATE_ACQUISITION

    # --- cached signed revocation state, offline ------------------------------
    # The policy differs by what is being authorized. Restoring a prior release is an
    # offline rollback: it claims current global revocation status, so it fails
    # closed on a stale snapshot. Continuing to run an already-verified group makes
    # no such claim and degrades to last-known-good, loudly. A *pending* group that
    # the floor does not yet name is still an acquisition and is held to the same
    # freshness rule as a fresh install.
    if expected_state == GROUP_PRIOR:
        revocation_policy = revocation.ROLLBACK
    elif expected_state == GROUP_PENDING and manifest_mode == release_lock.CANDIDATE_ACQUISITION:
        revocation_policy = revocation.ACQUISITION
    else:
        revocation_policy = revocation.RETAINED_RUNTIME
    revok, revreason, _revstate = revocation.enforce(
        digest, allowed, identity, now=now, policy=revocation_policy)
    if not revok:
        return False, revreason, None

    # --- the retained signed release ------------------------------------------
    keep = paths.retained_releases_dir() / digest
    if keep.is_symlink() or (keep / "release.json").is_symlink() or (keep / "release.json.sig").is_symlink():
        return False, "the retained signed release path is a symlink", None
    try:
        release_bytes = (keep / "release.json").read_bytes()
        signature = (keep / "release.json.sig").read_bytes()
    except OSError:
        return False, "the retained signed release is missing", None
    if release_lock.digest_bytes(signature) != pointer["signature_digest"]:
        return False, "the retained signature digest does not match the pointer", None
    vok, vreason, authz = release_lock.verify_manifest(
        release_bytes, signature, allowed, identity, python_info=python_info, abi=abi,
        platform_token=platform_token, now=now, mode=manifest_mode)
    if not vok or authz is None:
        return False, f"retained release did not re-verify: {vreason}", None
    if authz.lock_digest != digest:
        return False, "the retained manifest digest does not match the pointer", None
    if authz.release_version != version:
        return False, "the retained release_version does not match the pointer", None
    if not (set(authz.roles.keys()) == set(lockfile.ROLES)
            == set(pointer["generations"].keys()) == set(lock.engines.keys())):
        return False, "the group is not exactly the compute/distill/validator set", None

    # --- every generation, receipt, interpreter and managed file --------------
    roles: dict[str, VerifiedRole] = {}
    for role in lockfile.ROLES:
        pin = lock.pin(role)
        aok, areason, spec = release_lock.authorize_role(
            authz, role, repository=pin.repository, revision=pin.revision, distribution=pin.distribution,
            extras=list(pin.extras), entrypoints=list(pin.entrypoints),
            server_entrypoints=list(pin.server_entrypoints), protocol=pin.protocol, launch_mode=pin.launch_mode)
        if not aok:
            return False, f"{role}: {areason}", None
        expected = _expected(spec, version, digest, identity)
        generation = pointer["generations"][role]
        gok, data, greason = _verify_generation(pin, generation, expected, base_exec=base_exec,
                                                base_sha=base_sha)
        if not gok or data is None:
            return False, f"{role}: {greason}", None
        gen_dir = paths.engine_generation_dir(role, generation)
        roles[role] = VerifiedRole(
            verified_values._SEAL, role=role, generation=generation, generation_dir=gen_dir,
            source_dir=gen_dir / "source", venv_dir=gen_dir / "venv",
            python=gen_dir / "venv" / "bin" / "python", receipt=gen_dir / "receipt.json",
            receipt_data=data,
            entrypoints=("python", *spec.entrypoints, *spec.server_entrypoints))

    group = VerifiedActiveGroup(
        verified_values._SEAL, release_version=version, lock_digest=digest, identity=identity,
        pointer_digest=_pointer_digest(pointer), roles=roles)
    return True, "ok", group


def verify_active_group(lock: lockfile.Lock, trusted_signers_path: Path, *,
                        base_exec: Path | None = None, now=None,
                        ) -> tuple[bool, str, VerifiedActiveGroup | None]:
    """Verify the committed active group named by the on-disk pointer. Thin, named
    wrapper over :func:`verify_group_pointer`; there is exactly one implementation."""
    return verify_group_pointer(None, GROUP_ACTIVE, lock, Path(trusted_signers_path),
                                base_exec=base_exec, now=now)


# --- the runtime lifecycle guard -----------------------------------------------

class VerifiedGroupLease:
    """A verified group held under the shared lifecycle lock.

    ``lease.group`` is the sealed value every consumer reads paths from.
    ``lease.launch(fn, ...)`` revalidates the exact pointer, floor, trust root, lock,
    receipts and managed tree and only then calls ``fn`` — so the first child of a
    command cannot start against state that changed after verification. Nothing in
    the runtime resolves an executable path any other way.
    """

    __slots__ = ("_lock", "_trusted", "_base_exec", "group")

    def __init__(self, lock: lockfile.Lock, trusted: Path, base_exec: Path | None,
                 group: VerifiedActiveGroup) -> None:
        self._lock = lock
        self._trusted = trusted
        self._base_exec = base_exec
        self.group = group

    def role(self, role: str) -> VerifiedRole:
        return self.group.role(role)

    def revalidate(self) -> VerifiedActiveGroup:
        """Re-run the complete verification and require byte-identical results."""
        ok, reason, fresh = verify_group_pointer(None, GROUP_ACTIVE, self._lock, self._trusted,
                                                 base_exec=self._base_exec)
        if not ok or fresh is None:
            raise ActiveStateError(f"the active release stopped verifying: {reason}")
        if (fresh.pointer_digest != self.group.pointer_digest
                or fresh.lock_digest != self.group.lock_digest
                or fresh.release_version != self.group.release_version
                or fresh.generations() != self.group.generations()):
            raise ActiveStateError(
                "the active release changed after it was verified; nothing was started")
        for role, before in self.group.roles.items():
            after = fresh.role(role)
            if after.receipt_data != before.receipt_data or after.venv_dir != before.venv_dir:
                raise ActiveStateError(
                    f"the {role} generation changed after it was verified; nothing was started")
        return fresh

    def launch(self, call: Callable[..., Any], *args: Any, bind_program: Path | None = None,
               **kwargs: Any) -> Any:
        """Revalidate, then start the child. Never call a launcher any other way.

        ``bind_program`` closes the last window in the sequence. Revalidation ends,
        and then ``Popen`` resolves the program *by name* — so between the two, the
        interpreter can be replaced and the child execs bytes nothing verified.
        Executing an already-open descriptor would remove the name lookup entirely,
        but macOS refuses ``exec`` of ``/dev/fd/N``, so the binding is done the way
        this platform allows: a descriptor is held open across the spawn, its bytes
        are hashed *through that descriptor*, and the first thing that happens after
        the spawn — before start is reported and before a single line of output is
        read — is a check that the name still resolves to that exact inode. A swap
        in the gap is detected at the first moment it can be, and the child's whole
        process group is terminated before anything trusts it.
        """
        if bind_program is None:
            self.revalidate()
            return call(*args, **kwargs)

        import hashlib
        try:
            fd = os.open(str(bind_program), os.O_RDONLY | os.O_NOFOLLOW)
        except OSError as exc:
            raise ActiveStateError(
                f"the verified program {bind_program.name} could not be opened: {exc}") from exc
        try:
            held = os.fstat(fd)
            if not _stat.S_ISREG(held.st_mode):
                raise ActiveStateError(f"{bind_program.name} is not a regular file")
            digest = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1 << 20)
                if not chunk:
                    break
                digest.update(chunk)
            bound = digest.hexdigest()

            # Revalidate LAST, so the verified state is the newest thing known, and
            # the descriptor we hold is what its digest is compared against.
            self.revalidate()
            by_name = _sha256_file(bind_program)
            if by_name != bound:
                raise ActiveStateError(
                    f"{bind_program.name} changed between being opened and being verified")

            user_on_start = kwargs.get("on_start")

            def on_start(child: Any) -> None:
                try:
                    current = os.stat(str(bind_program), follow_symlinks=False)
                except OSError as exc:
                    raise ActiveStateError(
                        f"{bind_program.name} vanished as the child started: {exc}") from exc
                if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
                    raise ActiveStateError(
                        f"{bind_program.name} was replaced between verification and execution; "
                        f"the child was terminated before it was trusted")
                if user_on_start is not None:
                    user_on_start(child)

            kwargs["on_start"] = on_start
            return call(*args, **kwargs)
        finally:
            os.close(fd)


@contextlib.contextmanager
def verified_active_group(lock: lockfile.Lock, trusted_signers: Path | None = None, *,
                          base_exec: Path | None = None, timeout: float = 120.0,
                          ) -> Iterator[VerifiedGroupLease]:
    """Take the shared lifecycle lock, verify the active group strictly, and hold the
    lock for the whole operation — a complete read, or a process launch.

    Raises :class:`ActiveStateError` if the group does not verify, so a caller cannot
    proceed on unverified state by forgetting to check a boolean.
    """
    trusted = Path(trusted_signers) if trusted_signers is not None else paths.trusted_signers()
    with lifecycle_lock(exclusive=False, timeout=timeout):
        ok, reason, group = verify_group_pointer(None, GROUP_ACTIVE, lock, trusted,
                                                 base_exec=base_exec)
        if not ok or group is None:
            raise ActiveStateError(reason)
        yield VerifiedGroupLease(lock, trusted, base_exec, group)


# --- state (read-only) ---------------------------------------------------------

@contextlib.contextmanager
def active_view(lock: lockfile.Lock, *, timeout: float = 120.0) -> Iterator[tuple[
        dict[str, InstallState], VerifiedActiveGroup | None, str]]:
    """One verification, held under the shared lifecycle lock for the whole command.

    ``install_states`` answers the same question but releases the lease before
    returning, which is fine for a value a command only prints and wrong for a
    command that then executes installed code or mutates state: between the release
    and the use, an activation can commit underneath it. Every command that goes on
    to *do* something takes this instead, and stays inside the ``with``.
    """
    if paths.recovery_required():
        yield (_recovery_required_states(lock), None, "recovery required")
        return
    try:
        with verified_active_group(lock, timeout=timeout) as lease:
            group = lease.group
            yield ({role: state_from_group(lock.pin(role), group) for role in lock.engines},
                   group, "ok")
    except (ActiveStateError, InstallError) as exc:
        reason = str(exc)
        yield ({role: _not_installed(role, lock.pin(role).revision, reason)
                for role in lock.engines}, None, reason)


def _recovery_required_states(lock: lockfile.Lock) -> dict[str, InstallState]:
    return {role: _not_installed(role, lock.pin(role).revision,
                                 "an interrupted release transaction is pending",
                                 recovery_required=True)
            for role in lock.engines}


def install_states(lock: lockfile.Lock) -> tuple[dict[str, InstallState], VerifiedActiveGroup | None, str]:
    """Every role's state from **one** verification.

    Commands that report on more than one role must use this: verifying per role
    would run the whole signature/receipt/filesystem check three times and, worse,
    could report three different answers for one node.
    """
    if paths.recovery_required():
        return ({role: _not_installed(role, lock.pin(role).revision,
                                      "an interrupted release transaction is pending",
                                      recovery_required=True)
                 for role in lock.engines}, None, "recovery required")
    try:
        with verified_active_group(lock) as lease:
            group = lease.group
            states = {}
            for role in lock.engines:
                if role not in group:
                    states[role] = _not_installed(role, lock.pin(role).revision,
                                                  "the verified group has no such role")
                    continue
                states[role] = _state_from(lock.pin(role), group.role(role), group)
            return states, group, "ok"
    except (ActiveStateError, InstallError) as exc:
        reason = str(exc)
        return ({role: _not_installed(role, lock.pin(role).revision, reason) for role in lock.engines},
                None, reason)


def state_from_group(pin: EnginePin, group: VerifiedActiveGroup) -> InstallState:
    """A role's state read straight out of an already-verified group. This is how a
    command that holds a lease reports installation facts — it never re-verifies and
    never re-reads the pointer."""
    if pin.role not in group:
        return _not_installed(pin.role, pin.revision, "the verified group has no such role")
    return _state_from(pin, group.role(pin.role), group)


def _state_from(pin: EnginePin, role_value: VerifiedRole, group: VerifiedActiveGroup) -> InstallState:
    data = role_value.receipt_data
    revision = data.get("revision")
    return InstallState(
        role=pin.role, installed=True, revision=revision, expected_revision=pin.revision,
        installed_at=data.get("installed_at"), python=str(role_value.python),
        drift=bool(revision) and revision != pin.revision, generation=role_value.generation,
        release_version=group.release_version, signer_identity=group.identity)


def state(pin: EnginePin) -> InstallState:
    """A pure read: the installed generation as re-verified against the signed
    release, or that recovery is required. It never mutates state or runs recovery.

    There is no verdict cache. A previous success in this process proves nothing
    about the bytes on disk now, and a cache keyed on cheap metadata was exactly how
    a same-process tamper stayed trusted.
    """
    role = pin.role
    if paths.recovery_required():
        return _not_installed(role, pin.revision, "an interrupted release transaction is pending",
                              recovery_required=True)
    try:
        lock = lockfile.load()
    except Exception:  # noqa: BLE001 - a bad lockfile is not-installed, not a crash
        return _not_installed(role, pin.revision, "the lockfile could not be read")
    try:
        with verified_active_group(lock) as lease:
            if role not in lease.group:
                return _not_installed(role, pin.revision, "the verified group has no such role")
            return _state_from(pin, lease.group.role(role), lease.group)
    except (ActiveStateError, InstallError) as exc:
        return _not_installed(role, pin.revision, str(exc))


def _receipt_types_ok(data: dict[str, Any]) -> str | None:
    """Every field's type, before any of them is compared to anything."""
    for key in _RECEIPT_STRING_FIELDS:
        if not isinstance(data.get(key), str) or not data[key]:
            return f"receipt {key} is not a non-empty string"
    for key in _RECEIPT_LIST_FIELDS:
        value = data.get(key)
        if not isinstance(value, list) or any(not isinstance(x, str) or not x for x in value):
            return f"receipt {key} is not a list of non-empty strings"
        if len(set(value)) != len(value):
            return f"receipt {key} contains duplicates"
    version = data.get("release_version")
    if not (isinstance(version, int) and not isinstance(version, bool)
            and 1 <= version <= _MAX_RELEASE_VERSION):
        return "receipt release_version is not a positive bounded integer"
    for key in ("parent_base_sha256", "venv_python_sha256", "manifest_sha256", "source_sha256",
                "lock_digest"):
        if not _HEX64_RE.match(data[key]):
            return f"receipt {key} is not a lowercase sha256 digest"
    if _aware_utc(data["installed_at"]) is None:
        return "receipt installed_at is not an aware UTC timestamp"
    stat_block = data.get("venv_python_stat")
    if not isinstance(stat_block, dict) or set(stat_block.keys()) != set(_STAT_KEYS):
        return "receipt venv_python_stat has an unknown or missing key"
    for key in _STAT_KEYS:
        value = stat_block[key]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return f"receipt venv_python_stat.{key} is not a non-negative integer"
    return None


def _verify_generation(pin: EnginePin, generation: str | None, expected: dict[str, Any], *,
                       base_exec: Path, base_sha: str) -> tuple[bool, dict | None, str]:
    """Verify one generation on disk AND cross-bind **every** field of its receipt.

    Half the fields are bound to the signed release, the rest to the trusted parent
    interpreter and to the filesystem: the receipt's own claims are never evidence
    for themselves. A field that could not be bound to anything would not be in the
    schema.
    """
    role = pin.role
    if role not in lockfile.ROLES:
        return False, None, "unknown role"
    if not (isinstance(generation, str) and _GEN_ID_RE.match(generation)):
        return False, None, "invalid generation id"
    gen_dir = paths.engine_generation_dir(role, generation)
    ok, reason = _no_symlinked_ancestors(gen_dir, paths.home())
    if not ok:
        return False, None, f"a managed ancestor is a symlink: {reason}"
    for managed in (gen_dir, gen_dir / "source", gen_dir / "venv", gen_dir / "receipt.json"):
        if managed.is_symlink():
            return False, None, f"{managed.name} is a symlink"
    receipt_path = gen_dir / "receipt.json"
    if not receipt_path.is_file():
        return False, None, "no receipt"
    try:
        if os.stat(receipt_path).st_mode & 0o022:
            return False, None, "the receipt is writable by group or others"
        if os.stat(gen_dir).st_mode & 0o022:
            return False, None, "the generation directory is writable by group or others"
        data = json.loads(receipt_path.read_text())
    except (OSError, ValueError):
        return False, None, "unreadable receipt"
    if not isinstance(data, dict) or set(data.keys()) != _RECEIPT_KEYS:
        return False, None, "receipt has an unexpected or missing field"
    type_problem = _receipt_types_ok(data)
    if type_problem is not None:
        return False, None, type_problem
    if data["schema"] != RECEIPT_SCHEMA:
        return False, None, "receipt schema mismatch"
    if data["role"] != role or data["generation"] != generation:
        return False, None, "receipt does not match the generation"

    # --- bound to the signed release ------------------------------------------
    if _canonical_name(str(data["distribution"])) != _canonical_name(str(expected["distribution"])):
        return False, None, "receipt distribution does not match the signed release"
    for key in ("repository", "revision", "version", "source_sha256", "launch_mode", "protocol",
                "release_version", "signer_identity", "lock_digest"):
        if data.get(key) != expected[key]:
            return False, None, f"receipt {key} does not match the signed release"
    for key in ("extras", "entrypoints", "server_entrypoints"):
        if sorted(data.get(key) or []) != expected[key]:
            return False, None, f"receipt {key} does not match the signed release"

    # --- bound to the trusted parent interpreter ------------------------------
    if data["parent_base_executable"] != _canonical(base_exec):
        return False, None, "receipt parent_base_executable is not this node's trusted interpreter"
    if data["parent_base_sha256"] != base_sha:
        return False, None, "receipt parent_base_sha256 is not the current trusted interpreter digest"
    if data["venv_python_sha256"] != data["parent_base_sha256"]:
        return False, None, "receipt interpreter digest is not its trusted-parent digest"

    # --- bound to the filesystem ----------------------------------------------
    source_archive = gen_dir / "source" / "source.tar"
    if source_archive.is_symlink() or not source_archive.is_file():
        return False, None, "the retained source archive is missing or a symlink"
    if _sha256_file(source_archive) != expected["source_sha256"]:
        return False, None, "the retained source archive does not match the signed source hash"
    venv_python = gen_dir / "venv" / "bin" / "python"
    if venv_python.is_symlink() or not venv_python.is_file():
        return False, None, "venv python missing"
    if data["venv_python"] != str(venv_python):
        return False, None, "receipt venv_python is not this generation's interpreter path"
    if _sha256_file(venv_python) != data["venv_python_sha256"]:
        return False, None, "venv python changed"
    recorded = data["venv_python_stat"]
    try:
        current = _stat_identity(venv_python)
    except OSError:
        return False, None, "venv python unstat-able"
    for key in _STAT_KEYS:
        if current.get(key) != recorded.get(key):
            return False, None, f"venv python {key} changed"
    if current["mode"] & 0o022:
        return False, None, "venv python is writable by others"
    ok, manifest_sha, reason = _local_manifest(gen_dir, pin)
    if not ok:
        return False, None, reason
    if manifest_sha != data["manifest_sha256"]:
        return False, None, "the installed environment changed since install"
    return True, data, ""


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip("-").lower()


# --- explicit, locked recovery -------------------------------------------------

def recover(lock: lockfile.Lock, *, supervisor: Supervisor | None = None) -> tuple[bool, str]:
    """Finish or undo an interrupted transaction.

    Pending and prior are verified *independently*: a valid pending group is
    committed; otherwise, and only if the floor does not already name pending, an
    independently verified prior is restored and restarted. Generations are never
    mixed between the two groups, and a supervisor stop/start/readiness failure is
    propagated as a recovery failure rather than swallowed.
    """
    try:
        with _transaction():
            return _recover(lock, supervisor)
    except InstallError as exc:
        return False, str(exc)
    except OSError as exc:
        # An OSError from a *post-commit* write escaped this function entirely, so
        # the caller saw a crash and the next `recover` saw an ACTIVE pointer and
        # said "nothing to recover" — with the witnesses still missing. What matters
        # is the durable state, not which exception type carried the news.
        committed, detail = _describe_committed_state()
        return False, (f"recovery could not complete ({exc}); {detail}")


def _describe_committed_state() -> tuple[bool, str]:
    """What is actually on disk, for a caller that must not guess from an exception."""
    ok, pointer, reason = _read_pointer_strict()
    if not ok or pointer is None:
        return False, f"the release pointer could not be read ({reason})"
    if pointer["state"] == GROUP_ACTIVE:
        missing = _missing_activation_witnesses(pointer)
        if missing:
            return True, (f"release {pointer['release_version']} IS committed and active, but "
                          f"{', '.join(missing)} are missing; re-run the install to heal them")
        return True, f"release {pointer['release_version']} is committed and active"
    return False, "an interrupted transaction is still recorded; run `cathedral recover` again"


def _missing_activation_witnesses(pointer: dict) -> list[str]:
    """Which witnesses are missing *for this exact release*.

    Checking only that the files are non-empty was the defect: a v1 marker and a v1
    journal satisfied that test while v2 was the committed release, so healing
    reported success and left the node describing the wrong activation.
    """
    missing: list[str] = []
    version, digest = pointer.get("release_version"), pointer.get("lock_digest")
    marker = paths.activation_marker()
    ok, data, _reason = safeio.secure_read(marker, limit=1 << 16)
    recorded = None
    if ok and data:
        try:
            recorded = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            recorded = None
    if (not isinstance(recorded, dict) or recorded.get("release_version") != version
            or recorded.get("lock_digest") != digest):
        missing.append("the activation marker for this release")
    journal = paths.activation_journal()
    jok, jdata, _jreason = safeio.secure_read(journal, limit=1 << 20)
    entries = []
    if jok and jdata:
        for line in jdata.decode("utf-8", "replace").splitlines():
            with contextlib.suppress(ValueError):
                entries.append(json.loads(line))
    if not any(isinstance(e, dict) and e.get("release_version") == version
               and e.get("lock_digest") == digest for e in entries):
        missing.append("the activation journal entry for this release")
    return missing


def _recover(lock: lockfile.Lock, supervisor) -> tuple[bool, str]:
    now = _dt.datetime.now(_dt.timezone.utc)
    pok, pointer, preason = _read_pointer_strict()
    if not pok:
        return False, f"the release pointer cannot be parsed: {preason}"
    if pointer is None or pointer["state"] != GROUP_PENDING:
        return True, "nothing to recover"
    prior = pointer["prior"] if isinstance(pointer.get("prior"), dict) else None
    generations = dict(pointer["generations"])
    running_before = _roles_running()

    fok, floor, freason = _read_floor()
    if not fok:
        return False, f"refusing to recover: {freason}"
    floor_names_pending = (floor is not None
                           and floor.release_version == pointer["release_version"]
                           and floor.lock_digest == pointer["lock_digest"])

    ok, reason, pending_group = verify_group_pointer(pointer, GROUP_PENDING, lock,
                                                     paths.trusted_signers(), now=now)
    if ok and pending_group is not None:
        hok, detail = _commit_pending(pointer, pending_group, supervisor, running_before)
        if hok:
            return True, "recovered and committed the pending release"
        reason = detail

    if floor_names_pending:
        # The floor already recorded this release. Rolling back now would take the
        # node below its own anti-replay record, so recovery stops for an operator
        # instead of silently weakening the floor.
        return False, (f"the pending release {pointer['release_version']} is already committed to "
                       f"the replay floor but does not verify ({reason}); refusing to roll back "
                       f"below the floor. Operator repair is required.")

    rok, rdetail = _rollback_group(prior, lock, supervisor, running_before, now=now,
                                   from_pointer=pointer)
    if not rok:
        _journal("RECOVERY_FAILED", reason=reason, rollback=rdetail)
        return False, f"the interrupted release did not verify ({reason}) and {rdetail}"
    _journal("RECOVERED_ROLLBACK", reason=reason)
    _cleanup_uncommitted(generations, keep_group=prior)
    _discard_unreferenced_release(pointer["lock_digest"])
    return True, f"rolled back the interrupted release: {reason}"


def _commit_pending(pointer: dict, group: VerifiedActiveGroup, supervisor,
                    running_before: list[str]) -> tuple[bool, str]:
    if running_before:
        stopped, stop_detail = _prove_stopped(supervisor, list(running_before))
        if not stopped:
            return False, stop_detail
        try:
            supervisor.start(group, list(running_before))
            ready, detail = supervisor.readiness(running_before)
        except Exception as exc:  # noqa: BLE001
            return False, f"supervisor error: {exc}"
        if not ready:
            return False, detail
    try:
        _commit_floor(pointer["release_version"], pointer["lock_digest"])
    except InstallError as exc:
        return False, str(exc)
    _write_json_atomic(paths.active_release_pointer(), {**pointer, "state": GROUP_ACTIVE})
    _record_activation(pointer["release_version"], pointer["lock_digest"], pointer["generations"])
    _journal("RECOVERED_COMMIT", generations=pointer["generations"])
    _safe_prune(active=pointer["generations"],
                prior=pointer["prior"] if isinstance(pointer.get("prior"), dict) else None)
    return True, "ok"


# --- migration + teardown ------------------------------------------------------

def _migrate_legacy_after_active() -> None:
    """Only after a new group is active and healthy: remove any pre-generation (v2)
    ``venv``/``installed.json`` so nothing can fall back to it. The legacy install is
    kept untouched until this point, so a failed upgrade never destroys it."""
    removed = False
    for role in lockfile.ROLES:
        for legacy in (paths.engine_dir(role) / "venv", paths.engine_dir(role) / "installed.json",
                       paths.engine_dir(role) / "src"):
            if legacy.exists() and not legacy.is_symlink():
                _force_rmtree(legacy) if legacy.is_dir() else legacy.unlink()
                removed = True
    if removed:
        _journal("MIGRATED_FROM_V2")


def uninstall(role: str) -> tuple[bool, str]:
    """Remove a role's whole engine tree, or refuse and say why.

    Deletion is never authorized by ``reported_generation``: that is a lenient read
    of mutable state, and asking it "is this generation active?" answers the wrong
    question twice over — it says nothing about a *pending* transaction, and it can
    change between the check and the ``rmtree``. Instead the exclusive lifecycle
    lock is held for the whole decision, the pointer is parsed strictly, and any
    reference at all — active, pending, or the retained prior — refuses.
    """
    if role not in lockfile.ROLES:
        return False, f"unknown role {role!r}"
    try:
        # A bounded wait. Removing an engine is destructive and interactive, so an
        # operator is owed "something else is happening" within seconds rather than
        # a command that appears to hang for two minutes behind an install.
        with _transaction(timeout=15.0):
            ok, pointer, reason = _read_pointer_strict()
            if not ok:
                return False, (f"refusing to remove the {role} engine: the release pointer cannot "
                               f"be parsed ({reason})")
            if pointer is not None:
                referenced = set((pointer.get("generations") or {}).keys())
                prior = pointer.get("prior")
                if isinstance(prior, dict):
                    referenced |= set((prior.get("generations") or {}).keys())
                if role in referenced:
                    state_name = pointer["state"]
                    return False, (f"the {role} engine is named by the {state_name} release "
                                   f"pointer; roll it back or recover before removing it")
            # Not "is the role running" — "can anything still be executing these
            # bytes". An unreadable record, a record from before this boot, and a
            # dead leader with a live descendant all answer yes to the second
            # question and no to the first, and all three are reasons to refuse.
            blocked, reason = run_state.deletion_blocked(role)
            if blocked:
                return False, f"refusing to remove the {role} engine: {reason}"
            target = paths.engine_dir(role)
            if target.is_symlink():
                return False, f"{target} is a symlink; refusing to remove through it"
            if not target.exists():
                return False, f"the {role} engine is not installed"
            _force_rmtree(target)
            if target.exists():
                return False, f"the {role} engine tree could not be removed"
            _journal("UNINSTALLED", role=role)
            return True, f"removed the {role} engine"
    except InstallError as exc:
        return False, str(exc)
