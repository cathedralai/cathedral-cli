"""Opening security state without being redirected, replaced, or lied to.

Every durable security file this node reads — the replay floor, the revocation
cache and its sequence floor, the lifecycle lock — is a target. The attacks are
always the same shape:

* **symlink** — point the name at something else and the reader follows it;
* **file type** — hand back a FIFO or a device so the read blocks or lies;
* **owner** — a file another user controls;
* **mode** — a file another user can rewrite between two of our reads;
* **replacement** — swap the file *after* the check and *before* the use, so the
  descriptor we validated is no longer the path we act on.

The answers here are boring and uniform. Open once with ``O_NOFOLLOW`` and do
every check on the descriptor with ``fstat`` — never on the path, which can change
underneath a ``stat``/``open`` pair. For a lock, take the flock first and then
prove the path still resolves to the same ``(device, inode)`` we hold, because a
lock on a replaced file is not a lock on anything.

Refusals are values, not exceptions: security code has to be able to say "no, and
here is why" on a path that is also the error path.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import stat as _stat
import time
from pathlib import Path
from typing import Iterator

__all__ = ["SecureOpenError", "secure_read", "secure_write_atomic", "secure_lock",
           "describe_refusal", "identity_problem"]

_MAX_READ = 1 << 22  # 4 MiB: every security document here is tiny


class SecureOpenError(Exception):
    """A security file could not be opened safely."""


def _anchor() -> Path | None:
    """The node root, resolved once.

    Symlinks *above* the root are the platform's own business — macOS resolves
    ``/tmp`` to ``/private/tmp`` and ``/var`` to ``/private/var``, and refusing
    those would refuse every real node. Symlinks *below* it are nobody's business
    but an attacker's.
    """
    try:
        from cathedral_node import paths
        return Path(paths.home()).resolve()
    except Exception:  # noqa: BLE001 - a missing root is not a reason to crash a read
        return None


def _walk_below_anchor(path: Path) -> tuple[int | None, str, str | None]:
    """``(parent_fd, leaf_name, problem)``.

    ``O_NOFOLLOW`` refuses a symlink at the *final* component only. Every
    directory above it is still resolved normally, so a symlinked ``engines`` or
    ``engines/revocation`` redirects the revocation cache, the replay floor and
    their lock together — the file each name resolves to is attacker-chosen, and
    every descriptor check then passes on the wrong file.

    So the descent is explicit: from the node root, one component at a time,
    each opened ``O_NOFOLLOW | O_DIRECTORY`` relative to the last. The caller then
    opens the leaf relative to ``parent_fd``, which is a directory nothing could
    have substituted along the way.
    """
    anchor = _anchor()
    if anchor is None:
        return None, path.name, None
    try:
        relative = path.resolve().parent.relative_to(anchor)
    except (ValueError, OSError):
        try:
            # Not under the node root (an out-of-band trust root, the host-wide
            # publisher fence). The final-component protections still apply.
            path.parent.relative_to(anchor)
        except ValueError:
            return None, path.name, None
        relative = Path()
    # `resolve()` above was only used to decide *whether* the file is under the
    # root. The descent itself uses the unresolved components, so a symlink planted
    # in the middle is refused rather than silently followed.
    try:
        relative = path.parent.relative_to(anchor)
    except ValueError:
        return None, path.name, None
    try:
        fd = os.open(str(anchor), os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        return None, path.name, f"the node root could not be opened ({exc.strerror})"
    for component in relative.parts:
        if component in ("..", "."):
            os.close(fd)
            return None, path.name, "resolves through a parent-directory reference"
        try:
            nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except OSError as exc:
            os.close(fd)
            if exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
                return None, path.name, f"is reached through a symlinked directory ({component})"
            if exc.errno == errno.ENOENT:
                return None, path.name, None      # absent: the caller's own concern
            return None, path.name, f"could not be reached safely ({exc.strerror})"
        os.close(fd)
        fd = nxt
    return fd, path.name, None


def _chain_identity(path: Path) -> list[tuple[int, int]] | None:
    """``(dev, ino)`` of every directory from the anchor down to ``path``'s parent.

    A single descent proves the chain was clean *at that moment*. It does not
    survive a directory being renamed or replaced while we work: one process ends
    up holding a lock on the detached old inode while another takes the lock on the
    new visible one, and both believe they hold "the" lock. Comparing the whole
    chain again at the end turns that into a refusal.
    """
    anchor = _anchor()
    if anchor is None:
        return None
    try:
        relative = path.parent.relative_to(anchor)
    except ValueError:
        return None
    chain: list[tuple[int, int]] = []
    try:
        fd = os.open(str(anchor), os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        chain.append((info.st_dev, info.st_ino))
        for component in relative.parts:
            try:
                nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except OSError:
                return None
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            chain.append((info.st_dev, info.st_ino))
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)
    return chain


def _chain_still_current(path: Path, chain: list[tuple[int, int]] | None) -> bool:
    """Re-descend from the anchor and require the identical chain."""
    if chain is None:
        return True
    return _chain_identity(path) == chain


@contextlib.contextmanager
def _hardened_parent(path: Path) -> Iterator[tuple[int | None, str]]:
    parent_fd, leaf, problem = _walk_below_anchor(Path(path))
    if problem:
        raise SecureOpenError(describe_refusal(Path(path), problem))
    try:
        yield parent_fd, leaf
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def _identity_ok(info: os.stat_result) -> str | None:
    """Everything that must be true of a security file, checked on a descriptor."""
    if not _stat.S_ISREG(info.st_mode):
        return "is not a regular file"
    if info.st_nlink != 1:
        return f"has {info.st_nlink} links; a hard-linked security file is refused"
    if info.st_uid not in (0, os.geteuid()):
        return "is foreign-owned"
    if info.st_mode & 0o022:
        return "is writable by group or others"
    return None


def identity_problem(info: os.stat_result) -> str | None:
    """Public form of the descriptor identity check, for callers that hold their
    own descriptor (the publisher fence) but must apply the same rules."""
    return _identity_ok(info)


def describe_refusal(path: Path, problem: str) -> str:
    return f"{path.name} {problem}"


def secure_read(path: Path, *, limit: int = _MAX_READ) -> tuple[bool, bytes | None, str]:
    """Read a security file, or say exactly why it cannot be trusted.

    ``O_NONBLOCK`` matters as much as ``O_NOFOLLOW`` here. Opening a FIFO for
    reading blocks until somebody writes to it, so a named pipe left where the
    replay floor or the revocation cache belongs does not merely fail the type
    check — it never reaches the type check, and every read of that file hangs
    forever. Refusing a wrong file type is only a refusal if the refusal returns.

    Returns ``(ok, data, reason)``. ``data is None`` with ``ok`` true means the
    file is simply absent, which is a fact some callers are entitled to act on.
    """
    path = Path(path)
    try:
        parent_fd, leaf, problem = _walk_below_anchor(path)
    except OSError as exc:
        return False, None, describe_refusal(path, f"could not be reached safely ({exc})")
    if problem:
        return False, None, describe_refusal(path, problem)
    try:
        fd = os.open(leaf if parent_fd is not None else str(path),
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    except FileNotFoundError:
        if parent_fd is not None:
            os.close(parent_fd)
        return True, None, "absent"
    except OSError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            return False, None, describe_refusal(path, "is a symlink")
        return False, None, describe_refusal(path, f"could not be opened safely ({exc.strerror})")
    if parent_fd is not None:
        os.close(parent_fd)
    try:
        problem = _identity_ok(os.fstat(fd))
        if problem:
            return False, None, describe_refusal(path, problem)
        info = os.fstat(fd)
        if info.st_size > limit:
            return False, None, describe_refusal(path, f"is larger than {limit} bytes")
        return True, os.read(fd, limit), "ok"
    except OSError as exc:
        return False, None, describe_refusal(path, f"could not be read ({exc.strerror})")
    finally:
        os.close(fd)


def secure_write_atomic(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Replace a security file in one step.

    The staged file is fsynced, renamed over the target, and the *directory* is
    fsynced too — otherwise a crash can lose the rename even though the bytes were
    durable. A caller that needs two files replaced together must put them in one
    document; there is no two-rename form here, because there is no way to make
    two renames atomic.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    chain = _chain_identity(path)
    with _hardened_parent(path) as (parent_fd, leaf):
        staged = f".tmp.{os.getpid()}.{os.urandom(6).hex()}"
        staged_target = staged if parent_fd is not None else str(path.parent / staged)
        final_target = leaf if parent_fd is not None else str(path)
        fd = os.open(staged_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
                     dir_fd=parent_fd)
        try:
            try:
                _write_all(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(staged_target, final_target, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(staged_target, dir_fd=parent_fd)
            raise
        own_fd = parent_fd if parent_fd is not None else os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(own_fd)
        finally:
            if parent_fd is None:
                os.close(own_fd)
        if not _chain_still_current(path, chain):
            # The bytes are durable, but they are durable somewhere the node no
            # longer reaches by this name. Reporting success would tell the caller
            # its security file was published when a later read will not find it.
            raise SecureOpenError(describe_refusal(
                path, "was published into a directory that was replaced during the write"))


def _write_all(fd: int, data: bytes) -> None:
    """``os.write`` may write fewer bytes than it was given.

    A partial append leaves a truncated JSON line in an append-only history, which
    the reader then refuses as unreadable — the whole file, not just that line.
    """
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "the write made no progress")
        view = view[written:]


def secure_append(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Append to an append-only security record, or refuse.

    A plain ``open(path, "a")`` follows a symlink, happily appends to a FIFO,
    accepts a hard-linked file another user can also write, and — because it
    resolves the name again on every call — can be pointed at a different inode
    between two appends. An append-only history that an attacker can redirect is
    not a history.

    So: ``O_NOFOLLOW`` and ``O_NONBLOCK`` on the open, the same descriptor identity
    check every other security file gets, an exclusive lock, and a proof that the
    descriptor is still the inode the name resolves to *after* the lock is held.
    The write is fsynced before returning, because a record still in the page cache
    when the launcher is killed is a record that never existed.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
    parent_fd, leaf, problem = _walk_below_anchor(path)
    if problem:
        if parent_fd is not None:
            os.close(parent_fd)
        raise SecureOpenError(describe_refusal(path, problem))
    try:
        fd = os.open(leaf if parent_fd is not None else str(path), flags, mode, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise SecureOpenError(describe_refusal(path, "is a symlink")) from exc
        raise SecureOpenError(
            describe_refusal(path, f"could not be opened safely ({exc.strerror})")) from exc
    try:
        problem = _identity_ok(os.fstat(fd))
        if problem:
            raise SecureOpenError(describe_refusal(path, problem))
        fcntl.flock(fd, fcntl.LOCK_EX)
        opened = os.fstat(fd)
        try:
            # Re-stat through the SAME anchored descriptor, without following a
            # symlink. `os.stat(str(path))` resolved the whole name again and
            # followed the final component, so the comparison could be made against
            # whatever a freshly planted link pointed at.
            named = (os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                     if parent_fd is not None else os.stat(str(path), follow_symlinks=False))
        except OSError as exc:
            raise SecureOpenError(
                describe_refusal(path, f"vanished while being appended to ({exc.strerror})")) from exc
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):  # noqa: SIM102
            raise SecureOpenError(
                describe_refusal(path, "was replaced by a different file while it was open"))
        problem = _identity_ok(named)
        if problem:
            raise SecureOpenError(describe_refusal(path, problem))
        _write_all(fd, data)
        os.fsync(fd)
    except OSError as exc:
        raise SecureOpenError(
            describe_refusal(path, f"could not be appended to ({exc.strerror})")) from exc
    finally:
        os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


@contextlib.contextmanager
def secure_create_exclusive(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Create a file that must not already exist, through the anchored descent.

    ``O_EXCL`` is what makes a claim atomic — exactly one caller wins the file —
    but a bare ``os.open`` still resolves every directory above it normally, so the
    claim can be made inside an attacker's directory.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _hardened_parent(path) as (parent_fd, leaf):
        fd = os.open(leaf if parent_fd is not None else str(path),
                     os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode,
                     dir_fd=parent_fd)
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)


def _prove_lock_identity(path: Path, held: os.stat_result, parent_fd: int | None) -> None:
    """Refuse a lock file that is not the one this lock has always been on.

    `flock` excludes other holders *of the same inode*. Replace the file at the
    name and the next process opens a different inode, locks it against nobody, and
    both believe they are serialised — mutual exclusion silently becomes none at
    all, and neither side can see it from its own descriptor.

    So the identity is durable. The first acquisition records the inode the lock
    lives on; every later one must find that same inode. A mismatch is not repaired
    here: it means either the file was replaced under a live holder, or the lock was
    removed while something depended on it, and both need an operator rather than a
    guess.
    """
    identity = Path(f"{path}.id")
    expected = f"{held.st_dev}:{held.st_ino}".encode()
    ok, data, _reason = secure_read(identity, limit=1 << 12)
    if not ok:
        raise SecureOpenError(describe_refusal(identity, "cannot be read, so the lock it names "
                                                         "cannot be trusted"))
    if data is None:
        secure_write_atomic(identity, expected)
        return
    if data.strip() != expected:
        raise SecureOpenError(describe_refusal(
            path, "is not the file this lock was established on; it was replaced or removed while "
                  "something still depended on it"))


@contextlib.contextmanager
def secure_lock(path: Path, *, exclusive: bool, timeout: float = 120.0,
                busy_message: str = "another operation holds the lock") -> Iterator[int]:
    """Hold a hardened advisory lock.

    Beyond the usual ``flock``: the lock file is opened ``O_NOFOLLOW``, proven to
    be a correctly-owned regular file on the descriptor, and — after the lock is
    taken — proven still to be the same ``(device, inode)`` the name resolves to.
    That last check is the one that matters: an attacker who replaces the lock file
    while we wait would otherwise leave two processes each holding "the" lock on
    different inodes, which is indistinguishable from no lock at all.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    chain = _chain_identity(path)
    parent_fd, leaf, problem = _walk_below_anchor(path)
    if problem:
        if parent_fd is not None:
            os.close(parent_fd)
        raise SecureOpenError(describe_refusal(path, problem))
    try:
        # O_NONBLOCK for the same reason as in `secure_read`: a FIFO where the
        # lock file belongs would otherwise block the open forever, and a lock that
        # never returns is indistinguishable from a lock that is always held.
        fd = os.open(leaf if parent_fd is not None else str(path),
                     os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600,
                     dir_fd=parent_fd)
    except OSError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        raise SecureOpenError(
            describe_refusal(path, f"could not be opened safely ({exc.strerror})")) from exc
    try:
        problem = _identity_ok(os.fstat(fd))
        if problem:
            raise SecureOpenError(describe_refusal(path, problem))

        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if time.monotonic() > deadline:
                    raise SecureOpenError(busy_message) from exc
                time.sleep(0.05)

        # The lock is held. Prove it is a lock on the file this name means *now* —
        # resolved through the same anchored, symlink-free descent, so a directory
        # swapped in while we waited cannot make a different inode answer to it.
        try:
            named = (os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                     if parent_fd is not None else os.stat(str(path), follow_symlinks=False))
        except OSError as exc:
            raise SecureOpenError(
                describe_refusal(path, "was removed while its lock was taken")) from exc
        held = os.fstat(fd)
        if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
            raise SecureOpenError(
                describe_refusal(path, "was replaced while its lock was taken"))
        problem = _identity_ok(named)
        if problem:
            raise SecureOpenError(describe_refusal(path, f"was replaced: it {problem}"))
        if not _chain_still_current(path, chain):
            # A directory above the lock was renamed or replaced while we waited.
            # The descriptor is still a valid lock — on an inode nothing can reach
            # by this name any more — so a second holder would take "the" lock on
            # the new one and neither would be excluding the other.
            raise SecureOpenError(describe_refusal(
                path, "is reached through a directory that was replaced while the lock was taken"))
        _prove_lock_identity(path, held, parent_fd)
        yield fd
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)
