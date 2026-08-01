"""Durable run state, locks, and the event stream.

Three guarantees this module provides, all of them things an agent depends on:

* One role runs once per node. A second ``start`` gets ``LOCKED`` with the pid
  and run id of the process that already holds it, not a confusing crash.
* Every run has a directory, a record, and an append-only event log. After an
  interruption the record still describes what happened.
* Events are the same objects the terminal renders and ``--json`` prints.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

from cathedral_node import paths
from cathedral_node.contracts.envelope import utcnow
from cathedral_node.contracts.version import EVENT_SCHEMA
from cathedral_node.redact import redact_text, redact_value


# --- run records ---------------------------------------------------------------

@dataclasses.dataclass(slots=True)
class RunRecord:
    run_id: str
    role: str
    kind: str  # test | mine | validate
    status: str  # running | completed | failed | cancelled | interrupted
    started_at: str
    finished_at: str | None = None
    pid: int | None = None
    exit_code: int | None = None
    detail: str = ""
    artifacts: dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "cathedral.node.run.v1",
            "run_id": self.run_id,
            "role": self.role,
            "kind": self.kind,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "pid": self.pid,
            "exit_code": self.exit_code,
            "detail": self.detail,
            "artifacts": self.artifacts,
        }


def _record_path(run_id: str) -> Path:
    return paths.run_dir(run_id) / "run.json"


def is_valid_run_id(run_id: str) -> bool:
    return bool(paths.RUN_ID_RE.match(str(run_id)))


def create_run(run_id: str, role: str, kind: str, detail: str = "") -> RunRecord:
    record = RunRecord(
        run_id=run_id,
        role=role,
        kind=kind,
        status="running",
        started_at=utcnow(),
        pid=os.getpid(),
        detail=detail,
    )
    save_run(record)
    return record


def save_run(record: RunRecord) -> None:
    directory = paths.run_dir(record.run_id)
    directory.mkdir(parents=True, exist_ok=True)
    tmp = directory / "run.json.tmp"
    tmp.write_text(json.dumps(redact_value(record.to_dict()), indent=2) + "\n")
    tmp.replace(directory / "run.json")


def finish_run(record: RunRecord, status: str, exit_code: int, detail: str = "") -> RunRecord:
    record.status = status
    record.exit_code = exit_code
    record.finished_at = utcnow()
    if detail:
        record.detail = detail
    save_run(record)
    return record


def load_run(run_id: str) -> RunRecord | None:
    """Load a run record, or None.

    A *lookup* tolerates an id that is not a run id — `cathedral evidence` probes
    arbitrary identifiers here — while `run_dir` stays strict, so nothing
    unvalidated is ever used to build a path we write to.
    """
    if not is_valid_run_id(run_id):
        return None
    path = _record_path(run_id)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return RunRecord(
        run_id=data["run_id"],
        role=data.get("role", ""),
        kind=data.get("kind", ""),
        status=data.get("status", "unknown"),
        started_at=data.get("started_at", ""),
        finished_at=data.get("finished_at"),
        pid=data.get("pid"),
        exit_code=data.get("exit_code"),
        detail=data.get("detail", ""),
        artifacts=data.get("artifacts", {}),
    )


def list_runs(role: str | None = None, limit: int = 25) -> list[RunRecord]:
    """Recent runs, newest first.

    Sorted by ``started_at``, not by directory name. Run ids begin with the
    command (``test-``, ``start-``), so a name sort groups by command and only
    then by time — which made "the most recent run" mean "the most recent run
    whose verb sorts last", and sent ``cathedral logs`` to the wrong one.
    """
    root = paths.runs_dir()
    if not root.exists():
        return []

    records = []
    for directory in root.iterdir():
        if not directory.is_dir():
            continue
        record = load_run(directory.name)
        if record is None or (role and record.role != role):
            continue
        records.append(record)

    records.sort(key=lambda r: (r.started_at, r.run_id), reverse=True)
    return records[:limit]


def reconcile(record: RunRecord) -> RunRecord:
    """Correct a record whose process died without finishing it.

    Without this, a killed run stays "running" forever and ``status`` lies.
    """
    if record.status != "running" or record.pid is None:
        return record
    if _pid_alive(record.pid):
        return record
    record.status = "interrupted"
    record.finished_at = record.finished_at or utcnow()
    record.detail = record.detail or "the process ended without recording a result"
    save_run(record)
    return record


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


# --- events --------------------------------------------------------------------

def event_log(run_id: str) -> Path:
    return paths.run_dir(run_id) / "events.jsonl"


def _safe_event_log(run_id: str) -> Path | None:
    try:
        return event_log(run_id)
    except paths.UnsafeRunId:
        return None


RESERVED_EVENT_FIELDS = frozenset({"schema", "ts", "run_id", "event", "stage", "status", "detail"})


def emit_event(
    run_id: str,
    event: str,
    *,
    stage: str = "",
    status: str = "INFO",
    detail: str = "",
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Append one event. Returns it so a caller can also render it live.

    Engine-supplied data arrives as ``fields``, an explicit dict, rather than
    ``**kwargs``. An engine legitimately names one of its own fields ``event``,
    and splatting that bound it to this function's parameter — a TypeError
    raised at the call site, before any defensive code inside could run. Taking
    a dict makes the collision impossible instead of merely handled; any key
    that would shadow an envelope field is prefixed rather than dropped, so it
    stays searchable by ``cathedral evidence``.
    """
    extra = {
        (f"engine_{key}" if key in RESERVED_EVENT_FIELDS else key): value
        for key, value in (fields or {}).items()
    }
    payload = {
        "schema": EVENT_SCHEMA,
        "ts": utcnow(),
        "run_id": run_id,
        "event": event,
        "stage": stage,
        "status": status,
        "detail": redact_text(detail),
        **redact_value(extra),
    }
    path = event_log(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload) + "\n")
    return payload


def read_events(run_id: str, since: int = 0) -> Iterator[dict[str, Any]]:
    path = _safe_event_log(run_id)
    if path is None or not path.exists():
        return iter(())

    def generate() -> Iterator[dict[str, Any]]:
        with path.open("r", encoding="utf-8") as fh:
            for index, line in enumerate(fh):
                if index < since:
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    return generate()


# --- durable child ownership ---------------------------------------------------
#
# A role lock that records only the CLI's own pid answers the wrong question. What
# the node needs to know before it starts a second copy, or signals a process
# group, is not "is the parent alive" but "is the child I started still the process
# occupying that pid".
#
# So ownership records the child pid, its process-group id, the kernel's own start
# identity for that pid, the effective uid, and the verified generation it was
# started from. Three failures fall out of that:
#
# * a killed CLI parent no longer permits a second start, because the orphaned
#   child is still recorded and still alive;
# * PID reuse no longer permits signalling an unrelated process, because the
#   recorded start identity will not match the new occupant of that pid;
# * "stopped" means every member of the process group is gone, not that the one pid
#   we happened to hold a handle to exited.

OWNERSHIP_SCHEMA = "cathedral.node.child_ownership.v3"
_OWNERSHIP_KEYS = {"schema", "role", "run_id", "parent_pid", "child_pid", "pgid",
                   "start_identity", "boot_id", "euid", "generation", "lock_digest",
                   "token", "since", "spawn_state"}

# How far a launcher had got when the record was last written. The middle value is
# the one that matters: between deciding to spawn and recording what was spawned
# there is an interval in which a child can exist that nothing on disk names, and a
# launcher killed there must not leave a record that reads as "nothing started".
SPAWN_CLAIMED = "claimed"        # the role lock is held; no spawn attempted yet
SPAWN_IN_FLIGHT = "spawning"     # a spawn is about to happen or is happening now
SPAWN_OWNED = "owned"            # the child pid and process group are recorded

# Ownership verdicts. Deletion and signalling ask different questions of the same
# record, and conflating them is how a stale record either wedges a node forever or
# authorises deleting bytes something is still executing.
OWNERSHIP_ABSENT = "absent"                # no record: nothing owns this role
OWNERSHIP_LIVE = "live"                    # a process from this record is running
OWNERSHIP_TERMINATED = "terminated"        # valid record, same boot, nothing alive
OWNERSHIP_UNVERIFIABLE = "unverifiable"    # a record exists but cannot be trusted
OWNERSHIP_STALE_BOOT = "stale_boot"        # recorded before the current boot


def boot_identity() -> str:
    """A kernel-stable discriminator for "this boot".

    `ps -o lstart=` has one-second resolution and no notion of a reboot, so on its
    own it cannot tell a live process from a pid reused after a restart — and a
    stale record that looks live is a licence to signal a stranger. The boot time
    makes every pre-reboot record recognisably from another era.
    """
    global _BOOT_IDENTITY
    if _BOOT_IDENTITY is not None:
        return _BOOT_IDENTITY
    identity = ""
    try:
        # Linux: the kernel's own per-boot UUID. `btime` has one-second resolution
        # and is shared across containers on one host, so two boots inside the same
        # second — or two namespaces — would be indistinguishable by it.
        boot_uuid = Path("/proc/sys/kernel/random/boot_id")
        if boot_uuid.is_file():
            value = boot_uuid.read_text().strip()
            if value:
                identity = f"boot_id:{value}"
        proc_stat = Path("/proc/stat")
        if not identity and proc_stat.is_file():                  # Linux fallback
            for line in proc_stat.read_text().splitlines():
                if line.startswith("btime "):
                    identity = f"btime:{line.split()[1]}"
                    break
        if not identity:                                          # macOS / BSD
            out = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.boottime"],  # noqa: S603
                                 capture_output=True, text=True, timeout=10)
            if out.returncode == 0 and out.stdout.strip():
                identity = "kern.boottime:" + " ".join(out.stdout.split())
    except (OSError, subprocess.SubprocessError):
        identity = ""
    _BOOT_IDENTITY = identity
    return identity


_BOOT_IDENTITY: str | None = None


# --- the append-only launch-lease ledger --------------------------------------
#
# The role lock says what is running now; the ledger says what was ever started and
# whether its end was recorded. Deletion asks the ledger, because the lock can be
# missing exactly when it matters most — a launcher killed between spawning a child
# and recording it leaves no lock entry at all, and a descendant that execs another
# binary leaves nothing in the process table to recognise either.

LEASE_SCHEMA = "cathedral.node.launch_lease.v1"
LEASE_INTENT = "intent"      # a spawn is about to happen
LEASE_OWNED = "owned"        # the child and its process group are known
LEASE_RELEASED = "released"  # the whole group has been proven stopped


LEASE_GONE = "gone"          # positively proven finished: nothing can be running
LEASE_MAX_BYTES = 1 << 21    # compact well below the reader's ceiling


class LedgerError(Exception):
    """The launch ledger could not be written. Never swallowed: a lease that could
    not be recorded is a child that must not be started."""


def _append_lease(event: str, role: str, lease: str, **fields: Any) -> None:
    """Append one lease event through the hardened security-file primitives.

    Durability is the whole point: an intent still in the page cache when the
    launcher is killed is an intent that never existed. So is provenance — a
    history that a symlink, a hard link, a FIFO or a swapped inode can redirect
    proves nothing, so the append refuses all four rather than following them.
    """
    from cathedral_node import safeio
    record = {"schema": LEASE_SCHEMA, "ts": utcnow(), "event": event, "role": role,
              "lease": lease, "boot_id": boot_identity(), **fields}
    path = paths.ownership_ledger()
    try:
        _mark_ledger_started()
        # ONE lock covers both the append and the compaction. With two, a compaction
        # could replace the file between another writer's open and its fsync, and
        # that writer would durably flush a record into an inode with no name — the
        # append reports success and the history simply does not contain it.
        with safeio.secure_lock(paths.ownership_ledger_lock(), exclusive=True, timeout=60.0,
                                busy_message="another process holds the launch ledger"):
            _compact_ledger_locked()
            safeio.secure_append(path, (json.dumps(record, sort_keys=True) + "\n").encode())
    except safeio.SecureOpenError as exc:
        raise LedgerError(f"the launch ledger could not be appended to: {exc}") from exc
    except OSError as exc:
        raise LedgerError(f"the launch ledger could not be appended to: {exc}") from exc


def mark_launch_history() -> None:
    """Public form of the witness write, for the installer.

    An activated node must carry the witness even before it has started anything,
    or "no ledger and no witness" would be ambiguous between a fresh install and a
    history that was deleted — and the ambiguity would have to be resolved in
    favour of deletion on every fresh node.
    """
    _mark_ledger_started(opened_a_lease=False)


def _mark_ledger_started(*, opened_a_lease: bool = True) -> None:
    """A durable witness for what the ledger is expected to contain.

    Without it a *deleted* ledger is indistinguishable from a node that has never
    started anything, and "no history" reads as "nothing is running" — exactly the
    state an attacker or a careless cleanup produces while a child is still
    executing. The witness records two different facts, because they have different
    safe answers: this node is one where leases get recorded (written at
    activation), and this node has actually opened one (written at the first
    append). It is never removed and never downgraded.
    """
    from cathedral_node import safeio
    marker = paths.ownership_ledger_marker()
    current = _ledger_witness()
    if current is not None and (current.get("opened") or not opened_a_lease):
        return
    safeio.secure_write_atomic(marker, json.dumps(
        {"schema": LEASE_SCHEMA, "started": (current or {}).get("started") or utcnow(),
         "opened": bool(opened_a_lease) or bool((current or {}).get("opened"))},
        sort_keys=True).encode())


def _ledger_witness() -> dict[str, Any] | None:
    from cathedral_node import safeio
    ok, data, _reason = safeio.secure_read(paths.ownership_ledger_marker(), limit=1 << 14)
    if not ok:
        return {"started": "", "opened": True}      # unreadable: assume the stronger fact
    if data is None:
        return None
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return {"started": "", "opened": True}
    return parsed if isinstance(parsed, dict) else {"started": "", "opened": True}


def _ledger_has_history() -> bool:
    witness = _ledger_witness()
    return bool(witness) and bool(witness.get("opened"))


def _compact_ledger_locked() -> None:
    """Bound the ledger without ever losing an open lease.

    The reader refuses anything past a fixed ceiling — a ledger that grows past it
    would fail closed forever, which is safe but bricks the node. Compaction keeps
    every event of every lease that is not positively finished, plus a record of
    what was dropped, and commits with one atomic replace: a crash leaves either
    the whole old file or the whole new one, never a truncated history.
    """
    from cathedral_node import safeio
    path = paths.ownership_ledger()
    try:
        if not path.exists() or path.stat().st_size <= LEASE_MAX_BYTES:
            return
    except OSError:
        return
    events, problem = read_lease_events()
    if problem is not None:
        return              # an unreadable ledger is a refusal elsewhere, not a rewrite here
    finished = {str(r.get("lease")) for r in events if r.get("event") == LEASE_RELEASED}
    keep = [r for r in events if str(r.get("lease")) not in finished]
    dropped = len(events) - len(keep)
    keep.append({"schema": LEASE_SCHEMA, "ts": utcnow(), "event": "compacted",
                 "role": "", "lease": "", "boot_id": boot_identity(),
                 "dropped": dropped, "kept": len(keep)})
    safeio.secure_write_atomic(
        path, ("".join(json.dumps(r, sort_keys=True) + "\n" for r in keep)).encode())


def read_lease_events(role: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
    """``(events, problem)``. A ledger that cannot be read is a refusal, not an empty
    history — the difference decides whether a deletion is allowed."""
    from cathedral_node import safeio
    ok, data, reason = safeio.secure_read(paths.ownership_ledger(), limit=1 << 22)
    if not ok:
        return [], f"the ownership ledger {reason}"
    if data is None or not data.strip():
        # Absent. That is a fact only on a node that has never opened a lease; on
        # any other, the history was deleted or replaced, and the processes it
        # described do not stop existing because their record did.
        if _ledger_witness() is None and paths.activation_marker().exists():
            # The witness is gone too — and this node has activated a release, so
            # the witness should exist. Two files erased together is not a fresh
            # node; it is a node whose history was removed.
            return [], ("the launch ledger and its witness are both missing on a node that has "
                        "activated a release; its launch history was removed")
        if _ledger_has_history():
            return [], ("the launch ledger is missing but this node has opened launch leases "
                        "before; its history was removed or replaced")
        return [], None
    events: list[dict[str, Any]] = []
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            return [], "the ownership ledger contains an unreadable entry"
        if not isinstance(record, dict) or record.get("schema") != LEASE_SCHEMA:
            return [], "the ownership ledger contains an entry of an unknown shape"
        if role is None or record.get("role") == role:
            events.append(record)
    return events, None


def open_leases(role: str) -> tuple[list[dict[str, Any]], str | None]:
    """Leases for ``role`` whose end was never recorded, newest state per lease."""
    events, problem = read_lease_events(role)
    if problem is not None:
        return [], problem
    latest: dict[str, dict[str, Any]] = {}
    for record in events:
        lease = str(record.get("lease", ""))
        if lease:
            latest[lease] = record
    return [r for r in latest.values() if r.get("event") != LEASE_RELEASED], None


def lease_liveness(record: dict[str, Any]) -> tuple[str, str]:
    """``(verdict, detail)`` for one open lease.

    The only verdicts that permit deletion are the ones backed by proof. An empty
    process group is not proof: a descendant can call ``setsid()`` and leave the
    group entirely while still running, so "no members" means "I found nothing",
    which is a different statement from "nothing exists". A lease is finished when
    its owner recorded that it finished, when an operator's stop proved it, or when
    a reboot made it impossible for anything from it to still be running.
    """
    lease = str(record.get("lease", ""))[:8]
    recorded_boot = str(record.get("boot_id") or "")
    current_boot = boot_identity()
    if not recorded_boot or not current_boot:
        return OWNERSHIP_UNVERIFIABLE, (
            f"launch lease {lease} cannot be placed against a known boot, so nothing about it "
            f"can be proven")
    if recorded_boot != current_boot:
        # A known, different boot. Everything from it is provably gone — that is the
        # one thing a reboot does prove — and the pids and pgids it names now belong
        # to strangers, so this retires without anything being signalled.
        return LEASE_GONE, (f"launch lease {lease} belongs to a previous boot; nothing from it "
                            f"can still be running")
    if record.get("event") == LEASE_INTENT:
        parent = int(record.get("parent_pid") or -1)
        if parent > 0 and parent != os.getpid() and _pid_alive(parent):
            return OWNERSHIP_LIVE, f"launch lease {lease} is being opened by pid {parent}"
        return OWNERSHIP_UNVERIFIABLE, (
            f"launch lease {lease} recorded a spawn that was never confirmed; a child may be "
            f"running that nothing names")
    pgid = int(record.get("pgid") or -1)
    if pgid <= 0:
        return OWNERSHIP_UNVERIFIABLE, f"launch lease {lease} records no process group"
    try:
        members = [pid for pid in process_group_members(pgid) if pid != os.getpid()]
    except ProbeUnavailable as exc:
        return OWNERSHIP_UNVERIFIABLE, f"launch lease {lease} could not be probed: {exc}"
    if members:
        return OWNERSHIP_LIVE, (f"launch lease {lease} still has {len(members)} live process(es) "
                                f"in process group {pgid}")
    # Empty group, open lease. A child that called setsid() is no longer in this
    # group and is not visible here, and its end was never recorded by anything.
    return OWNERSHIP_UNVERIFIABLE, (
        f"launch lease {lease} has an empty process group but its end was never recorded; a "
        f"process that left the group may still be running. Run `cathedral stop` to resolve it")


def processes_using(path: Path) -> list[int]:
    """Live pids whose command line names ``path``.

    Evidence that does not depend on the ownership record at all. A record can be
    deleted by a crash, by a bad release, or by a well-meaning operator; the
    processes it described keep running regardless, and this is how the node can
    still see them. Without it, "no record" was indistinguishable from "nothing is
    running", and deleting on that reading is how a live process loses the text it
    is faulting in.
    """
    try:
        out = subprocess.run(["/bin/ps", "-eo", "pid=,command="],  # noqa: S603
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProbeUnavailable(f"the process table could not be read: {exc}") from exc
    if out.returncode != 0:
        raise ProbeUnavailable(f"ps exited {out.returncode}")
    needle = str(path)
    found = []
    for line in out.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit():
            continue
        pid = int(parts[0])
        if pid == os.getpid():
            continue
        # An ARGUMENT must start with the path. Substring matching anywhere in the
        # command line would also match a process that merely mentions the path —
        # a shell script containing it, or this very probe's own arguments.
        if any(arg.startswith(needle) for arg in parts[1].split()):
            found.append(pid)
    return found


# The identity of a *process*, not of a pid. `ps -o lstart=` has one-second
# resolution and no other discriminator, so two processes occupying one pid within
# the same second are indistinguishable by it — and a pid freed by SIGKILL can be
# reallocated well inside one second. Everything that authorizes a signal or a
# deletion rests on this field, so it is read from the kernel at its native
# resolution and combined with the process group and owner the kernel reports.
_LOWRES = "lowres:"
_PROC_PIDTBSDINFO = 3
_PROC_BSDINFO_SIZE = 136
_BSDINFO_UID = 20
_BSDINFO_PGID = 100
_BSDINFO_START = 120


def _libproc_identity(pid: int) -> str | None:
    """macOS: ``proc_pidinfo(PROC_PIDTBSDINFO)`` — microsecond start time."""
    import ctypes
    import ctypes.util
    import struct
    try:
        lib = ctypes.CDLL(ctypes.util.find_library("proc") or "/usr/lib/libproc.dylib",
                          use_errno=True)
    except OSError:
        return None
    buf = ctypes.create_string_buffer(_PROC_BSDINFO_SIZE)
    try:
        written = lib.proc_pidinfo(ctypes.c_int(int(pid)), ctypes.c_int(_PROC_PIDTBSDINFO),
                                   ctypes.c_uint64(0), buf, ctypes.c_int(_PROC_BSDINFO_SIZE))
    except (OSError, ValueError, AttributeError):
        return None
    if int(written) != _PROC_BSDINFO_SIZE:
        return None
    raw = buf.raw
    uid = struct.unpack_from("=I", raw, _BSDINFO_UID)[0]
    pgid = struct.unpack_from("=I", raw, _BSDINFO_PGID)[0]
    sec, usec = struct.unpack_from("=QQ", raw, _BSDINFO_START)
    return f"mac:{sec}.{usec:06d}:{pgid}:{uid}"


def _procfs_identity(pid: int) -> str | None:
    """Linux: field 22 of ``/proc/<pid>/stat`` — start time in clock ticks."""
    try:
        with open(f"/proc/{int(pid)}/stat", "rb") as handle:
            data = handle.read(4096).decode("utf-8", "replace")
        uid = os.stat(f"/proc/{int(pid)}").st_uid
    except (OSError, ValueError):
        return None
    try:
        fields = data[data.rindex(")") + 2:].split()
        pgrp, starttime = fields[2], fields[19]
    except (ValueError, IndexError):
        return None
    return f"linux:{starttime}:{pgrp}:{uid}"


def process_start_identity(pid: int) -> str | None:
    """The kernel's own notion of *which* process holds this pid.

    A pid is a slot, not an identity: kill a process and the number is handed to
    something else. This is what distinguishes the process we started from whatever
    now occupies its number, and it is what turns "signal this pgid" from a hope
    into a check — so it is taken from the kernel at full resolution wherever the
    platform offers it, and marked ``lowres:`` where it does not.
    """
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return None
    for probe in (_procfs_identity, _libproc_identity):
        identity = probe(pid)
        if identity:
            return identity
    try:
        out = subprocess.run(["/bin/ps", "-p", str(pid), "-o", "lstart="],  # noqa: S603
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    identity = out.stdout.strip()
    return f"{_LOWRES}{identity}" if identity else None


def identity_is_kernel_grade(identity: str) -> bool:
    """False for the one-second fallback. A comparison that cannot exclude
    same-second pid reuse must never be the thing that authorizes a signal."""
    return bool(identity) and not identity.startswith(_LOWRES)


class ProbeUnavailable(Exception):
    """The kernel could not be asked. Distinct from "the answer was nothing"."""


def process_group_members(pgid: int) -> list[int]:
    """Every **live** pid in ``pgid``. Termination means this is empty.

    Zombies are excluded, and that exclusion is load-bearing rather than tidy. A
    child that has exited but not yet been reaped still appears in ``ps`` with its
    process group intact. Counting it means "has everything stopped?" answers no
    for as long as nobody calls ``wait()`` — so a stop would burn its whole grace
    period and then report failure about a process that died immediately. A zombie
    executes nothing and holds no file open; it is a table entry, not a process
    that can still run the generation we are about to prune.
    """
    try:
        out = subprocess.run(["/bin/ps", "-eo", "pid=,pgid=,state="],  # noqa: S603
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        # Returning [] here was the defect. "I could not ask" and "nothing is
        # running" are opposite answers, and collapsing them made a failed probe
        # read as proof of termination — which then authorized deleting the
        # generation those unseen processes were executing.
        raise ProbeUnavailable(f"the process table could not be read: {exc}") from exc
    if out.returncode != 0:
        raise ProbeUnavailable(f"ps exited {out.returncode}")
    members = []
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
            continue
        if int(parts[1]) != int(pgid):
            continue
        if parts[2].upper().startswith("Z"):
            continue
        members.append(int(parts[0]))
    return members


@dataclasses.dataclass(frozen=True, slots=True)
class ChildOwnership:
    """Everything needed to prove a recorded child is still the process we started."""

    role: str
    run_id: str
    parent_pid: int
    child_pid: int
    pgid: int
    start_identity: str
    boot_id: str
    euid: int
    generation: str
    lock_digest: str
    token: str
    since: str
    spawn_state: str = SPAWN_CLAIMED

    def to_dict(self) -> dict[str, Any]:
        return {"schema": OWNERSHIP_SCHEMA, "role": self.role, "run_id": self.run_id,
                "parent_pid": self.parent_pid, "child_pid": self.child_pid, "pgid": self.pgid,
                "start_identity": self.start_identity, "boot_id": self.boot_id, "euid": self.euid,
                "generation": self.generation, "lock_digest": self.lock_digest,
                "token": self.token, "since": self.since, "spawn_state": self.spawn_state}

    @classmethod
    def parse(cls, data: Any) -> "ChildOwnership | None":
        if not isinstance(data, dict) or set(data.keys()) != _OWNERSHIP_KEYS:
            return None
        if data["schema"] != OWNERSHIP_SCHEMA:
            return None
        try:
            return cls(role=str(data["role"]), run_id=str(data["run_id"]),
                       parent_pid=int(data["parent_pid"]), child_pid=int(data["child_pid"]),
                       pgid=int(data["pgid"]), start_identity=str(data["start_identity"]),
                       boot_id=str(data["boot_id"]), euid=int(data["euid"]),
                       generation=str(data["generation"]),
                       lock_digest=str(data["lock_digest"]), token=str(data["token"]),
                       since=str(data["since"]), spawn_state=str(data["spawn_state"]))
        except (TypeError, ValueError):
            return None

    def from_this_boot(self) -> bool:
        current = boot_identity()
        return bool(current) and bool(self.boot_id) and current == self.boot_id

    # What the recorded leader pid currently holds.
    LEADER_GONE = "gone"          # nothing occupies that pid
    LEADER_OURS = "ours"          # our process, identity and group both match
    LEADER_FOREIGN = "foreign"    # something else took the pid
    LEADER_UNPROVEN = "unproven"  # the identity available cannot exclude pid reuse

    def leader_state(self) -> str:
        """Distinguish "our leader exited" from "someone else has its pid".

        Collapsing those two was what let a reused pid be laundered into ownership:
        the identity check failed, but any process sitting in the stored group was
        then treated as ours, and `stop_role` would signal it. They are different
        facts with opposite safe answers, so they get different names.
        """
        if not _pid_alive(self.child_pid):
            return self.LEADER_GONE
        identity = process_start_identity(self.child_pid)
        if identity is None:
            return self.LEADER_UNPROVEN
        if identity != self.start_identity:
            return self.LEADER_FOREIGN
        # A match is only worth something if the thing that matched can tell two
        # processes apart. The one-second fallback cannot: a pid freed by SIGKILL
        # can be reallocated inside the same second, and the recorded string would
        # match a completely different process. That is UNPROVEN, not OURS.
        if not (identity_is_kernel_grade(identity)
                and identity_is_kernel_grade(self.start_identity)):
            return self.LEADER_UNPROVEN
        try:
            if os.getpgid(self.child_pid) != self.pgid:
                return self.LEADER_FOREIGN
        except OSError:
            return self.LEADER_GONE
        return self.LEADER_OURS

    def leader_alive(self) -> bool:
        """Is the exact process we started still running?"""
        return self.leader_state() == self.LEADER_OURS

    def alive(self) -> bool:
        """Is ANY process from this ownership still running?

        Asking only about the recorded leader was the first defect: a server that
        exits while the worker it forked keeps running leaves a live descendant in
        the same process group — still executing the signed generation — and a
        leader-only check called that dead.

        Treating *any* occupant of the stored group as ours was the opposite defect.
        A process group's id is its leader's pid, so the group can only be recycled
        once that pid is free; if something else now holds it, this record describes
        nothing we own and nothing we may signal.
        """
        if not self.from_this_boot():
            # Recorded before the current boot. Nothing from it can be running, and
            # the pid and pgid numbers may since have been handed to strangers, so
            # this is never "alive" and never something to signal.
            return False
        state = self.leader_state()
        if state == self.LEADER_OURS:
            return True
        if state in (self.LEADER_FOREIGN, self.LEADER_UNPROVEN):
            # Either something else holds the pid, or nothing available can prove it
            # does not. Both are "this record does not describe anything we own",
            # which is not the same as "the bytes are safe to delete" — that part is
            # `ownership_status`'s UNVERIFIABLE, and it fails closed.
            return False
        return bool(self.group_members())

    def group_members(self) -> list[int]:
        """Live members of the owned process group, or none across a boot boundary.

        A pgid from a previous boot names whatever now happens to hold that number,
        which is not ours; treating those as members would be inventing ownership.
        """
        if not self.from_this_boot():
            return []
        return process_group_members(self.pgid)

    def boot_identity_known(self) -> bool:
        return bool(boot_identity()) and bool(self.boot_id)


def write_ownership(ownership: ChildOwnership) -> None:
    from cathedral_node import safeio
    path = paths.role_lock(ownership.role)
    safeio.secure_write_atomic(
        path, (json.dumps(ownership.to_dict(), sort_keys=True, indent=2) + "\n").encode("utf-8"))


def write_ownership_document(path: Path, data: bytes) -> None:
    """Place an ownership document verbatim, through the hardened writer.

    For tests that must construct a record this node cannot parse: the shape is the
    point, so it may not be built by the dataclass, but it still has to arrive the
    way a real one does — same mode, same atomic replace, same anchored parent.
    """
    from cathedral_node import safeio
    safeio.secure_write_atomic(path, data)


def read_ownership(role: str) -> ChildOwnership | None:
    from cathedral_node import safeio
    ok, data, _reason = safeio.secure_read(paths.role_lock(role), limit=1 << 16)
    if not ok or data is None:
        return None
    try:
        return ChildOwnership.parse(json.loads(data.decode("utf-8")))
    except (UnicodeDecodeError, ValueError):
        return None


def ownership_status(role: str) -> tuple[str, ChildOwnership | None, str]:
    """``(verdict, ownership, detail)`` — the one place a role's ownership is judged.

    The verdicts are separate because the questions are. "May I signal this?" and
    "May I delete the bytes it was running?" have different safe answers for the
    same record, and a single boolean forced one of them to be wrong.
    """
    path = paths.role_lock(role)
    from cathedral_node import safeio
    ok, data, reason = safeio.secure_read(path, limit=1 << 16)
    if not ok:
        return OWNERSHIP_UNVERIFIABLE, None, f"the {role} ownership record {reason}"
    if data is None:
        return OWNERSHIP_ABSENT, None, f"no {role} ownership record"
    try:
        parsed = ChildOwnership.parse(json.loads(data.decode("utf-8")))
    except (UnicodeDecodeError, ValueError):
        parsed = None
    if parsed is None:
        # A record that exists but cannot be read is the most dangerous state of
        # all: something wrote it, so something may be running, and we cannot tell
        # what. Fail closed rather than guess it away.
        return OWNERSHIP_UNVERIFIABLE, None, (
            f"the {role} ownership record is malformed; refusing to assume nothing is running")
    if not parsed.boot_identity_known():
        # We could not learn which boot this is, or the record does not say. That is
        # not the same as knowing the record is stale — it is knowing nothing — and
        # a stale verdict would let `stop` delete a record describing live processes.
        return OWNERSHIP_UNVERIFIABLE, parsed, (
            f"the boot identity is unavailable, so the {role} ownership record cannot be placed "
            f"in this boot or a previous one")
    if not parsed.from_this_boot():
        return OWNERSHIP_STALE_BOOT, parsed, (
            f"the {role} ownership record was written before the current boot; its pid and "
            f"process group may now belong to unrelated processes")
    if parsed.child_pid <= 0:
        if parsed.parent_pid != os.getpid() and _pid_alive(parsed.parent_pid):
            return OWNERSHIP_LIVE, parsed, f"{role} is starting (claimed by pid {parsed.parent_pid})"
        if parsed.spawn_state == SPAWN_IN_FLIGHT:
            # The launcher died between deciding to spawn and publishing what it
            # spawned. A child may exist and nothing on disk names it, so this is
            # exactly the state that must not read as "nothing was started".
            return OWNERSHIP_UNVERIFIABLE, parsed, (
                f"the {role} launcher died while a spawn was in flight; a child may be running "
                f"that was never recorded")
        return OWNERSHIP_TERMINATED, parsed, f"the {role} claim was never used to start a child"

    state = parsed.leader_state()
    if state == ChildOwnership.LEADER_UNPROVEN:
        # The pid is occupied and the identity we have cannot prove by whom. The
        # group id IS that pid, so every "member" of the group is equally unproven;
        # reading them as ours is how a one-second identity laundered a recycled
        # pid into a live claim, and then into a signal.
        return OWNERSHIP_UNVERIFIABLE, parsed, (
            f"pid {parsed.child_pid} cannot be proven to be the process the {role} record "
            f"describes; nothing about its process group may be assumed")
    if state == ChildOwnership.LEADER_FOREIGN:
        # The recorded pid is in use by something that is not ours. A process
        # group's id IS its leader's pid, so this record describes nothing we own.
        return OWNERSHIP_UNVERIFIABLE, parsed, (
            f"pid {parsed.child_pid} is held by a different process than the {role} record "
            f"describes; its process group is not ours to signal")
    try:
        members = parsed.group_members()
    except ProbeUnavailable as exc:
        return OWNERSHIP_UNVERIFIABLE, parsed, (
            f"the {role} process group could not be probed: {exc}")
    if state == ChildOwnership.LEADER_OURS:
        return OWNERSHIP_LIVE, parsed, f"{role} is running as pid {parsed.child_pid}"
    if members:
        # The leader's pid is free, so the group cannot have been recycled: a new
        # group with this id would need a process holding that exact pid. These are
        # our orphans.
        return OWNERSHIP_LIVE, parsed, (
            f"the {role} leader exited but its process group still has {len(members)} live "
            f"member(s)")
    return OWNERSHIP_TERMINATED, parsed, f"nothing from the {role} ownership record is running"


def deletion_blocked(role: str) -> tuple[bool, str]:
    """May the bytes this role was running be pruned, replaced, or removed?

    Only when nothing can still be executing them, and the ownership record is not
    the only thing consulted. A record can be deleted by a crash or by a stale
    release; the processes it described keep running, so an *independent* look at
    the process table asks whether anything is executing out of this role's
    generations at all. Without that, an absent record read as proof of safety —
    which is precisely the state a crashed launcher leaves behind.
    """
    # 1. The ledger. This is the proof, not a hint: it records that a launch was
    #    started and that its end was never recorded, and it keeps saying so when
    #    the role lock has been deleted and when the running descendant has exec'd
    #    something with no trace of the generation left anywhere in its argv.
    leases, problem = open_leases(role)
    if problem is not None:
        return True, f"{problem}; refusing to remove anything on an unreadable history"
    for record in leases:
        verdict, detail = lease_liveness(record)
        if verdict != LEASE_GONE:
            return True, f"{detail}; refusing to remove bytes it may still be executing"

    # 2. The process table, as corroboration only. It catches a process the ledger
    #    somehow missed; it can never be the reason deletion is *allowed*, because a
    #    descendant can exec another binary and leave nothing here to find.
    generations = paths.engine_generations_dir(role)
    try:
        users = processes_using(generations) if generations.exists() else []
    except ProbeUnavailable as exc:
        return True, (f"the process table could not be read ({exc}), so nothing can be proven "
                      f"about what is executing out of the {role} generations")
    if users:
        return True, (f"{len(users)} live process(es) are executing out of the {role} generations "
                      f"(pids {sorted(users)[:4]}); refusing to remove bytes they may still need")

    # 3. The current role record.
    verdict, _ownership, detail = ownership_status(role)
    if verdict in (OWNERSHIP_ABSENT, OWNERSHIP_TERMINATED):
        return False, detail
    if verdict == OWNERSHIP_STALE_BOOT:
        return True, (f"{detail}. Run `cathedral stop {role}` to clear it before removing "
                      f"anything.")
    if verdict == OWNERSHIP_UNVERIFIABLE:
        return True, f"{detail}. Nothing will be removed until it is resolved."
    return True, f"{detail}; refusing to remove bytes a live process may still execute"


# --- locks ---------------------------------------------------------------------

class OwnershipLost(Exception):
    """The claim a launch depends on is gone. Always fatal to that launch."""


class LockHeld(Exception):
    def __init__(self, pid: int, run_id: str, since: str) -> None:
        super().__init__(f"role is already running as pid {pid} (run {run_id})")
        self.pid = pid
        self.run_id = run_id
        self.since = since


class RoleLock:
    """An advisory, self-healing lock. A lock whose owner is gone is reclaimed
    rather than requiring the operator to delete a stale file."""

    def __init__(self, role: str, run_id: str) -> None:
        self.role = role
        self.run_id = run_id
        self.path = paths.role_lock(role)
        self._acquired = False
        self._owned = False
        self._token = os.urandom(16).hex()
        self._lease = os.urandom(16).hex()
        self._reaped = False

    def __enter__(self) -> "RoleLock":
        self.acquire()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.release()

    def claim_child(self, child_pid: int, *, generation: str = "", lock_digest: str = "") -> ChildOwnership:
        """Record durable ownership of the signed child, before start is reported.

        Called from the launcher's ``on_start`` hook, so there is no window in
        which a child is running and nothing on disk says who owns it.
        """
        try:
            pgid = os.getpgid(child_pid)
        except OSError:
            # The leader exited between spawn and publication. Every launcher here
            # uses `start_new_session=True`, so the group id IS the child pid — and
            # recording it matters most in exactly this case, because a descendant
            # may have outlived the leader and the group is the only handle on it.
            pgid = int(child_pid)
        ownership = ChildOwnership(
            role=self.role, run_id=self.run_id, parent_pid=os.getpid(), child_pid=int(child_pid),
            pgid=int(pgid), start_identity=process_start_identity(child_pid) or "",
            boot_id=boot_identity(), euid=os.geteuid(), generation=generation,
            lock_digest=lock_digest, token=self._token, since=utcnow(),
            spawn_state=SPAWN_OWNED)
        # The LEDGER FIRST, then the record. The ledger is the primary proof and the
        # record is the convenient copy, so the history must never be the one that
        # lags: a launcher killed between the two would otherwise leave a record
        # saying "owned" and a history saying "a spawn was never confirmed", and
        # every later reader would fail closed on a launch that was in fact fully
        # published. Written this way the durable history is always at least as
        # advanced as the record.
        _append_lease(LEASE_OWNED, self.role, self._lease, parent_pid=os.getpid(),
                      child_pid=ownership.child_pid, pgid=ownership.pgid,
                      start_identity=ownership.start_identity, generation=ownership.generation,
                      lock_digest=ownership.lock_digest, euid=ownership.euid, run_id=self.run_id)
        write_ownership(ownership)
        self._owned = True
        return ownership

    def child_reaped(self) -> None:
        """The launcher waited on its child and got its exit status.

        That is the one observation that proves the process this lease named is
        finished — the kernel does not hand out an exit status twice, and it cannot
        be forged by a pid that was recycled. It is what lets `release` close the
        lease instead of leaving it for an operator.
        """
        self._reaped = True

    def begin_spawn(self, *, generation: str = "", lock_digest: str = "") -> None:
        """Record that a spawn is about to happen, BEFORE the child can exist.

        Without this, a launcher SIGKILLed between `Popen` returning and ownership
        being published leaves a record that still says `child_pid = -1`. A later
        read sees a dead parent and no child and concludes "nothing was started" —
        while the child is running. Marking the intent first turns that into "a
        child may exist and was never recorded", which fails closed.
        """
        current = read_ownership(self.role)
        if current is None or current.token != self._token:
            # Returning quietly here let the caller spawn anyway, with no durable
            # intent behind it — the exact window this method exists to close. If
            # the record we are about to upgrade is gone or is somebody else's, the
            # launch has already lost its claim and must not produce a process.
            raise OwnershipLost(
                f"the {self.role} ownership record is missing or belongs to another launcher; "
                f"refusing to spawn a child that nothing durably claims")
        write_ownership(dataclasses.replace(
            current, spawn_state=SPAWN_IN_FLIGHT, generation=generation or current.generation,
            lock_digest=lock_digest or current.lock_digest))
        # The durable half. The role record can be deleted; this cannot, and it is
        # what a later prune consults.
        _append_lease(LEASE_INTENT, self.role, self._lease, parent_pid=os.getpid(),
                      generation=generation or current.generation,
                      lock_digest=lock_digest or current.lock_digest, euid=os.geteuid())

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"schema": OWNERSHIP_SCHEMA, "role": self.role, "run_id": self.run_id,
                   "parent_pid": os.getpid(), "child_pid": -1, "pgid": -1,
                   "start_identity": "", "boot_id": boot_identity(), "euid": os.geteuid(),
                   "generation": "", "lock_digest": "", "token": self._token, "since": utcnow(),
                   "spawn_state": SPAWN_CLAIMED}
        # O_EXCL makes creation atomic: exactly one process wins the file. A
        # read-then-replace left a window in which two starts both saw "free" and
        # the second clobbered the first. Reclaim a dead owner, then create.
        while True:
            holder = self.holder()
            if holder is not None:
                raise LockHeld(holder["pid"], holder.get("run_id", "unknown"), holder.get("since", ""))
            from cathedral_node import safeio
            try:
                safeio.secure_create_exclusive(self.path, json.dumps(payload).encode())
            except FileExistsError:
                continue  # lost the race; re-check the now-present holder
            except safeio.SecureOpenError as exc:
                raise OwnershipLost(
                    f"the {self.role} ownership record could not be claimed safely: {exc}") from exc
            self._acquired = True
            return

    def holder(self) -> dict[str, Any] | None:
        """Who holds this lock, or None if free. Clears a lock nobody owns.

        A record is only a holder when the **child** it names is provably still the
        process that was started: alive, in the recorded process group, with the
        kernel start identity it had when it was claimed. That is what makes a
        killed CLI parent stop being a licence to start a second copy — the orphan
        it left behind is still the holder — and what stops PID reuse turning a
        recycled number into a live claim.
        """
        verdict, ownership, detail = ownership_status(self.role)
        if verdict == OWNERSHIP_ABSENT:
            # No record — but the record is deletable and the ledger is not. An open
            # lease that nothing has proven finished means a previous launcher may
            # still have a child alive, and starting a second one would put two
            # processes on one role with one identity.
            blocking, why = self._blocking_lease()
            if blocking is not None:
                return {"pid": None, "parent_pid": None, "pgid": blocking.get("pgid"),
                        "run_id": str(blocking.get("run_id", "")), "since": str(blocking.get("ts", "")),
                        "role": self.role, "generation": str(blocking.get("generation", "")),
                        "detail": why, "unresolved": "open_lease"}
            return None
        if verdict == OWNERSHIP_LIVE and ownership is not None:
            pid = ownership.child_pid if ownership.child_pid > 0 else ownership.parent_pid
            return {"pid": pid, "parent_pid": ownership.parent_pid, "pgid": ownership.pgid,
                    "run_id": ownership.run_id, "since": ownership.since, "role": ownership.role,
                    "generation": ownership.generation, "detail": detail}
        if verdict == OWNERSHIP_TERMINATED:
            # "Terminated" here means the recorded process group is empty. That is
            # not the same as "this launch is finished": a descendant that called
            # `setsid()` is outside the group and outside this verdict entirely. The
            # ledger is what knows whether the launch was ever closed, so a second
            # owner may not be admitted until it says so.
            blocking, why = self._blocking_lease()
            if blocking is not None:
                return {"pid": None, "parent_pid": None, "pgid": blocking.get("pgid"),
                        "run_id": str(blocking.get("run_id", "")), "since": "",
                        "role": self.role, "generation": str(blocking.get("generation", "")),
                        "detail": why, "unresolved": "open_lease"}
            # Provably nothing running, provably ours, and no unfinished lease.
            if ownership is not None and (ownership.parent_pid == os.getpid()
                                          or not _pid_alive(ownership.parent_pid)
                                          or ownership.child_pid > 0):
                self.path.unlink(missing_ok=True)
            return None
        # UNVERIFIABLE or STALE_BOOT: not a live holder, and NOT something to clear
        # here. `holder()` is called from read-only paths; silently deleting a record
        # it cannot understand is exactly the guess that must not be made. It reads
        # as "not free" so a second start refuses, and `stop_role` resolves it.
        return {"pid": None, "parent_pid": None, "pgid": None,
                "run_id": (ownership.run_id if ownership else ""), "since": "",
                "role": self.role, "generation": (ownership.generation if ownership else ""),
                "detail": detail, "unresolved": verdict}

    def _blocking_lease(self) -> tuple[dict[str, Any] | None, str]:
        """An open lease for this role that is not this lock's own, if any."""
        leases, problem = open_leases(self.role)
        if problem is not None:
            return {"lease": ""}, f"{problem}; refusing to start a second owner on an unreadable history"
        for record in leases:
            if str(record.get("lease")) == self._lease:
                continue
            verdict, detail = lease_liveness(record)
            if verdict != LEASE_GONE:
                return record, detail
        return None, ""

    def release(self) -> None:
        """Drop the claim, but only ours.

        The token, not the pid, decides: after `claim_child` the record names the
        child, so a pid comparison would refuse to release a lock this process does
        in fact own.
        """
        if not self._acquired:
            return
        ownership = read_ownership(self.role)
        if ownership is not None and ownership.token == self._token:
            # Matching the token proves the record is ours. It does not prove the
            # processes are gone: a launcher that exits while a descendant keeps
            # running would otherwise delete the only durable record of what is
            # still executing, and the next prune would have nothing to refuse on.
            if ownership.child_pid > 0 and ownership.alive():
                self._acquired = False
                return
            self.path.unlink(missing_ok=True)
            # A released lease is a *proof*, and an empty process group is not one:
            # a child that called `setsid()` left the group and is invisible to it.
            # Only this launcher having reaped its own child proves the thing it
            # started is finished, so anything else leaves the lease open for an
            # explicit stop to resolve.
            if self._reaped or ownership.child_pid <= 0:
                _append_lease(LEASE_RELEASED, self.role, self._lease, proof="reaped",
                              detail="the launcher reaped its child before releasing the role")
        self._acquired = False
        self._owned = False


def running_run(role: str) -> dict[str, Any] | None:
    """The live run for a role, or None. Reconciles a dead owner first."""
    lock = RoleLock(role, "probe")
    return lock.holder()


# --- the single-publisher fence ------------------------------------------------

def _publisher_lock_dir() -> Path:
    """The canonical, host-wide location of publisher fences. It is deliberately
    NOT under ``CATHEDRAL_HOME``: two nodes with different homes but the *same*
    on-chain identity must contend for the same fence, or both would publish."""
    override = os.environ.get("CATHEDRAL_PUBLISHER_LOCK_DIR")
    base = Path(override) if override else Path(tempfile.gettempdir()) / "cathedral-publisher"
    base.mkdir(parents=True, exist_ok=True)
    try:
        base.chmod(0o700)
    except OSError:
        pass
    return base


class PublisherBusy(Exception):
    def __init__(self, pid: Any, identity: str, since: str) -> None:
        super().__init__(f"the publisher identity {identity} is already active as pid {pid}")
        self.pid = pid
        self.identity = identity
        self.since = since


class PublisherFence:
    """One weight publisher per ``(netuid, hotkey)`` across the whole host.

    Held with ``flock`` on a descriptor kept open for the process's lifetime, so
    the fence is released the instant the holder dies — a crashed or killed parent
    never leaves an orphan that lets a second process publish. The identity, not the
    home directory, is the key, so ``CATHEDRAL_HOME=/a`` and ``CATHEDRAL_HOME=/b``
    running the same hotkey cannot both hold it.
    """

    def __init__(self, netuid: int, hotkey: str, run_id: str = "") -> None:
        self.identity = f"{netuid}:{hotkey}"
        safe = re.sub(r"[^0-9A-Za-z._-]", "_", self.identity)[:200]
        self.path = _publisher_lock_dir() / f"{safe}.lock"
        self.run_id = run_id
        self._fd: int | None = None

    def __enter__(self) -> "PublisherFence":
        self.acquire()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.release()

    def acquire(self) -> None:
        """Take the fence, on an inode proved to be the one this name means.

        The hardening matters more here than anywhere else: a fence taken on a
        symlinked or replaced file excludes nobody, and the failure mode is two
        publishers for one identity — the single thing the whole vector contract
        rests on.
        """
        from cathedral_node import safeio
        try:
            fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError as exc:
            raise PublisherBusy(None, self.identity,
                                f"the fence file could not be opened safely: {exc}") from exc
        try:
            problem = safeio.identity_problem(os.fstat(fd))
            if problem:
                raise PublisherBusy(None, self.identity, f"the fence file {problem}")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except PublisherBusy:
            os.close(fd)
            raise
        except OSError as exc:
            held = self._read(fd)
            os.close(fd)
            raise PublisherBusy(held.get("pid"), self.identity, held.get("since", "")) from exc
        try:
            named = os.stat(str(self.path), follow_symlinks=False)
            held_stat = os.fstat(fd)
            if (named.st_dev, named.st_ino) != (held_stat.st_dev, held_stat.st_ino):
                raise PublisherBusy(None, self.identity,
                                    "the fence file was replaced while it was being taken")
        except OSError as exc:
            os.close(fd)
            raise PublisherBusy(None, self.identity, f"the fence file vanished: {exc}") from exc
        except PublisherBusy:
            os.close(fd)
            raise
        os.ftruncate(fd, 0)
        os.write(fd, json.dumps({"pid": os.getpid(), "identity": self.identity,
                                 "run_id": self.run_id, "since": utcnow()}).encode())
        os.fsync(fd)
        self._fd = fd

    @staticmethod
    def _read(fd: int) -> dict[str, Any]:
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            data = os.read(fd, 8192)
            return json.loads(data or b"{}")
        except (OSError, ValueError):
            return {}

    def holder(self) -> dict[str, Any] | None:
        """Who holds the fence, or None if free — a non-destructive probe."""
        if not self.path.exists():
            return None
        fd = os.open(str(self.path), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            data = self._read(fd)
            os.close(fd)
            return data
        # We got it — nobody holds it. Release immediately; we were only probing.
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        return None

    def release(self) -> None:
        if self._fd is None:
            return
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None


def _journal_stop(role: str, message: str) -> None:
    """An append-only note that a stop resolved an unusual ownership state."""
    with contextlib.suppress(OSError):
        path = paths.state_dir() / "stop-journal.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"ts": utcnow(), "role": role, "detail": message}) + "\n")


def _retire_prior_boot_leases(role: str) -> None:
    """Record the end of leases a reboot already ended.

    A known previous boot proves nothing from those leases survives, so they must
    not block deletion forever — and nothing is signalled to retire them, because
    the pids and pgids they name now belong to strangers.
    """
    leases, problem = open_leases(role)
    if problem is not None:
        return
    for record in leases:
        verdict, detail = lease_liveness(record)
        if verdict == LEASE_GONE:
            with contextlib.suppress(LedgerError):
                _append_lease(LEASE_RELEASED, role, str(record.get("lease", "")),
                              proof="previous boot", detail=detail)


def _close_finished_leases(role: str) -> tuple[bool, str]:
    """Record the end of every open lease for ``role`` after a proven stop.

    This is the ONLY observational path that closes a lease, and it exists because
    an operator's `cathedral stop` is a deliberate act with a proof behind it: the
    process group was signalled and observed empty. Passive emptiness never closes
    a lease — see `lease_liveness` — because a descendant can leave the group.

    The honest limit is written into the record it produces: `proof="stop"` means
    "the group this lease named was signalled and is empty", not "no process
    started by this lease exists anywhere on the machine". POSIX process groups
    cannot express the latter.
    """
    _retire_prior_boot_leases(role)
    leases, problem = open_leases(role)
    if problem is not None:
        return False, problem
    for record in leases:
        pgid = int(record.get("pgid") or -1)
        if pgid > 0:
            try:
                if [pid for pid in process_group_members(pgid) if pid != os.getpid()]:
                    return False, (f"launch lease {str(record.get('lease', ''))[:8]} still has live "
                                   f"processes in process group {pgid}")
            except ProbeUnavailable as exc:
                return False, f"the process group of an open lease could not be probed ({exc})"
        elif record.get("event") == LEASE_INTENT:
            # A spawn that was never confirmed. There is no group to signal and no
            # pid to check, and `Popen` may have returned before the launcher died —
            # so a child may exist that nothing has ever named. Closing this on the
            # absence of a process group id is closing it on no evidence at all.
            parent = int(record.get("parent_pid") or -1)
            if parent > 0 and parent != os.getpid() and _pid_alive(parent):
                return False, (f"launch lease {str(record.get('lease', ''))[:8]} is still being "
                               f"opened by pid {parent}")
            return False, (f"launch lease {str(record.get('lease', ''))[:8]} recorded a spawn that "
                           f"was never confirmed; a child may exist that nothing names. It cannot "
                           f"be closed by inference — resolve it explicitly")
        try:
            _append_lease(LEASE_RELEASED, role, str(record.get("lease", "")), proof="stop",
                          detail="the process group was signalled and observed empty")
        except LedgerError as exc:
            return False, str(exc)
    return True, "closed"


def _ownership_from_lease(role: str) -> tuple["ChildOwnership | None", str]:
    """Rebuild ownership from the ledger when the role record is gone.

    The record is deletable — by a crash, a bad release, or an operator — and its
    absence used to make `stop` report "not running" while the child it described
    kept running. The ledger is append-only and still names the child, its group
    and its kernel start identity, so a stop can be performed on it.
    """
    leases, problem = open_leases(role)
    if problem is not None:
        return None, problem
    for record in leases:
        if record.get("event") != LEASE_OWNED:
            continue
        verdict, detail = lease_liveness(record)
        if verdict in (LEASE_GONE,):
            continue
        # Reconstructing from "some pid is in this group" is how a stop reaches a
        # stranger: process group ids are recycled, and the lease names numbers, not
        # processes. The recorded kernel start identity and euid must still describe
        # what holds the leader pid, or nothing here may be signalled.
        recorded_identity = str(record.get("start_identity", ""))
        child_pid = int(record.get("child_pid") or -1)
        live_identity = process_start_identity(child_pid) if child_pid > 0 else None
        if (not identity_is_kernel_grade(recorded_identity) or live_identity != recorded_identity
                or int(record.get("euid", -1)) != os.geteuid()):
            return None, (f"an open lease names pid {child_pid}, but it cannot be proven to be "
                          f"the process the lease recorded; nothing about it may be signalled")
        try:
            ownership = ChildOwnership(
                role=role, run_id=str(record.get("run_id", "")),
                parent_pid=int(record.get("parent_pid") or -1),
                child_pid=int(record.get("child_pid") or -1), pgid=int(record.get("pgid") or -1),
                start_identity=str(record.get("start_identity", "")),
                boot_id=str(record.get("boot_id", "")), euid=int(record.get("euid") or os.geteuid()),
                generation=str(record.get("generation", "")),
                lock_digest=str(record.get("lock_digest", "")), token="",
                since=str(record.get("ts", "")), spawn_state=SPAWN_OWNED)
        except (TypeError, ValueError):
            return None, "an open lease could not be read as ownership"
        return ownership, detail
    return None, ""


def stop_role(role: str, grace: float = 10.0) -> tuple[bool, str]:
    """Stop a running role and prove the whole process group is gone.

    Ownership is validated before anything is signalled. Signalling a stored pgid
    without checking that the recorded child still occupies it is how a stop
    command reaches an unrelated process that happened to inherit the number.

    "Stopped" then means every member of the group has exited — not that the one
    pid we held a handle to did. A surviving descendant is still executing the
    generation the caller is about to prune.
    """
    verdict, ownership, detail = ownership_status(role)
    if verdict == OWNERSHIP_ABSENT:
        recovered, why = _ownership_from_lease(role)
        if recovered is None:
            closed, close_why = _close_finished_leases(role)
            if not closed:
                return False, close_why
            return False, "not running"
        # The record is gone but the ledger still names a child. Stop what it names.
        ownership, verdict, detail = recovered, OWNERSHIP_LIVE, why
    if verdict == OWNERSHIP_UNVERIFIABLE:
        # Nothing here can be signalled — there is no trustworthy pgid to signal —
        # and the record must not be removed on a guess either. That covers a
        # malformed record, an unknown boot identity, a pid now held by a stranger,
        # and a process-table probe that failed: in every one of them the honest
        # answer is "I cannot tell", and reporting a completed stop would be a lie
        # that authorises the next deletion.
        return False, detail
    if verdict == OWNERSHIP_STALE_BOOT and ownership is not None:
        # Provably dead: it was recorded before this boot, so nothing from it can be
        # running. That is the one thing about a stale record we DO know, and it is
        # enough to clear it — without ever signalling numbers that now belong to
        # somebody else.
        paths.role_lock(role).unlink(missing_ok=True)
        _retire_prior_boot_leases(role)
        # An explicit stop resolves the leases it can prove, exactly as the
        # signalling path does — otherwise clearing a pre-reboot record would leave
        # a lease from *this* boot open forever and nothing could ever be removed.
        closed, why = _close_finished_leases(role)
        if not closed:
            return False, why
        _journal_stop(role, "cleared a pre-reboot ownership record without signalling")
        return True, ("cleared an ownership record from a previous boot; nothing from it could "
                      "still be running")
    if ownership is None:
        return False, detail
    if ownership.child_pid <= 0:
        # Claimed but never started a child. Only the claiming parent can be gone.
        if _pid_alive(ownership.parent_pid) and ownership.parent_pid != os.getpid():
            return False, f"{role} is starting (claimed by pid {ownership.parent_pid})"
        paths.role_lock(role).unlink(missing_ok=True)
        return True, "no child had been started"
    if verdict == OWNERSHIP_TERMINATED:
        paths.role_lock(role).unlink(missing_ok=True)
        closed, why = _close_finished_leases(role)
        if not closed:
            return False, why
        return True, "already gone"
    if ownership.euid != os.geteuid():
        return False, f"{role} was started by uid {ownership.euid}; refusing to signal it"

    def _members() -> list[int]:
        return [pid for pid in ownership.group_members() if pid != os.getpid()]

    try:
        _members()
    except ProbeUnavailable as exc:
        return False, (f"the {role} process group could not be probed ({exc}); refusing to report "
                       f"a stop that cannot be verified")

    try:
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(ownership.pgid, sig)
            except ProcessLookupError:
                break
            except PermissionError:
                return False, f"process group {ownership.pgid} belongs to another user"
            deadline = time.monotonic() + (grace if sig == signal.SIGTERM else 5.0)
            while time.monotonic() < deadline:
                if not _members():
                    paths.role_lock(role).unlink(missing_ok=True)
                    closed, why = _close_finished_leases(role)
                    if not closed:
                        return False, why
                    return True, (f"stopped process group {ownership.pgid}"
                                  if sig == signal.SIGTERM else
                                  f"killed process group {ownership.pgid}")
                time.sleep(0.1)
        remaining = _members()
    except ProbeUnavailable as exc:
        return False, (f"the {role} process group could not be probed while stopping ({exc}); "
                       f"the ownership record is kept")
    if not remaining:
        # The group drained between the final poll and here. That is a completed
        # stop and must be reported as one — this exit used to call a function that
        # did not exist, so the one race that reached it raised NameError out of a
        # public command instead of closing the lease.
        paths.role_lock(role).unlink(missing_ok=True)
        closed, why = _close_finished_leases(role)
        if not closed:
            return False, why
        return True, f"stopped process group {ownership.pgid}"
    return False, (f"process group {ownership.pgid} still has {len(remaining)} member(s) after "
                   f"{grace:.0f}s; the role lock is kept so nothing prunes bytes they may execute")
