"""Hardened advisory locks and crash-safe writes.

Two primitives the whole lifecycle depends on, in one place so they cannot drift
apart:

:func:`hardened_lock`
    A ``flock`` on a file that is opened with ``O_NOFOLLOW`` and then *proved* to
    be the file we meant to lock. An advisory lock is only as good as the inode it
    is taken on: a symlinked, replaced, hard-linked, foreign-owned, group-writable
    or non-regular lock file lets an attacker hold a different inode and watch two
    "mutually exclusive" transactions run at once. Every one of those is refused,
    and the identity is re-checked *after* the lock is acquired so a replacement
    during the wait is caught rather than inherited.

:func:`write_file_atomic`
    One ``os.replace`` per durable state change, with the payload fsynced before
    the rename and the directory fsynced after it. A crash therefore leaves either
    the whole previous file or the whole new one, never a torn pair.

Where two files must change together, the answer is not two ``os.replace`` calls —
it is one file that contains both. :func:`write_file_atomic` is what that single
container is written with.
"""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import stat as _stat
import tempfile
import time
from pathlib import Path
from typing import Iterator


class LockError(Exception):
    """The lock could not be taken safely. Always fail closed on this."""


class LockBusy(LockError):
    """Someone else holds the lock. Distinct from "the lock is untrustworthy"."""


def _describe_mode(mode: int) -> str:
    return oct(mode & 0o7777)


def _check_lock_identity(fd: int, path: Path) -> None:
    """Everything that must be true of a lock file, checked on the open descriptor.

    Checking the *descriptor* rather than the path is the point: a path check can
    be invalidated the instant after it returns.
    """
    info = os.fstat(fd)
    if not _stat.S_ISREG(info.st_mode):
        raise LockError(f"{path} is not a regular file; refusing to lock it")
    if info.st_nlink != 1:
        raise LockError(f"{path} has {info.st_nlink} links; refusing a hard-linked lock")
    if info.st_uid not in (0, os.geteuid()):
        raise LockError(f"{path} is owned by uid {info.st_uid}; refusing a foreign-owned lock")
    if info.st_mode & 0o077:
        raise LockError(f"{path} is mode {_describe_mode(info.st_mode)}; a lock file must not be "
                        f"readable or writable by group or others")


def _same_inode(fd: int, path: Path) -> bool:
    """Is the descriptor still the file at ``path``?

    Called after the lock is held. If it is false, the file was replaced while we
    waited, so the lock we hold protects an inode nobody else will contend on.
    """
    try:
        on_disk = os.lstat(path)
    except OSError:
        return False
    held = os.fstat(fd)
    return (on_disk.st_dev, on_disk.st_ino) == (held.st_dev, held.st_ino)


@contextlib.contextmanager
def hardened_lock(path: Path, *, exclusive: bool, timeout: float = 120.0,
                  create_mode: int = 0o600) -> Iterator[int]:
    """Take an advisory lock on ``path``, proving the inode both before and after.

    Yields the open descriptor. Raises :class:`LockBusy` if the lock is held by
    someone else for longer than ``timeout``, and :class:`LockError` if the lock
    file itself cannot be trusted.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    try:
        fd = os.open(str(path), flags, create_mode)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            raise LockError(f"{path} is a symlink; refusing to lock through it") from exc
        raise LockError(f"{path} could not be opened safely: {exc}") from exc
    try:
        _check_lock_identity(fd, path)
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if time.monotonic() > deadline:
                    raise LockBusy(f"{path} is held by another process") from exc
                time.sleep(0.05)
        # The lock is held. If the path no longer names this inode, the file was
        # swapped while we waited and this lock excludes nobody.
        if not _same_inode(fd, path):
            raise LockError(f"{path} was replaced while the lock was being acquired; "
                            f"refusing to proceed on an orphaned lock")
        _check_lock_identity(fd, path)
        try:
            yield fd
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def write_file_atomic(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Replace ``path`` with ``data`` in one ``os.replace``.

    The staged file is fsynced before the rename and the directory after it, so a
    crash at any point leaves exactly one complete version on disk.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp.", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        tmp = ""
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def read_file_strict(path: Path, *, limit: int = 1 << 20) -> tuple[bool, bytes | None, str]:
    """Read a durable state file, or say exactly why it cannot be trusted.

    ``O_NOFOLLOW`` on the final component, regular-file and ownership checks on the
    open descriptor, and a hard size cap. Returns ``(ok, data, reason)`` with
    ``data is None`` and ``ok`` true only when the file is simply absent.
    """
    path = Path(path)
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return True, None, "absent"
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            return False, None, f"{path.name} is a symlink"
        return False, None, f"{path.name} could not be opened safely: {exc}"
    try:
        info = os.fstat(fd)
        if not _stat.S_ISREG(info.st_mode):
            return False, None, f"{path.name} is not a regular file"
        if info.st_uid not in (0, os.geteuid()):
            return False, None, f"{path.name} is foreign-owned"
        if info.st_mode & 0o022:
            return False, None, f"{path.name} is writable by group or others"
        if info.st_size > limit:
            return False, None, f"{path.name} is larger than {limit} bytes"
        return True, os.read(fd, limit), "ok"
    finally:
        os.close(fd)


__all__ = ["LockError", "LockBusy", "hardened_lock", "write_file_atomic", "read_file_strict"]
