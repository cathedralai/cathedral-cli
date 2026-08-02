"""Gate 0: the signed-release-bundle boundary and the node-wide install transaction.

Every test is a named counterexample from Revision 5 and the independent audits, and
every test runs for real and offline against a located CPython 3.11-3.13 as the
trusted parent — so there are no skips. If no such interpreter exists this file
errors (the node cannot run at all without one); it does not skip.

Four assertions are attached to *every* rejection, because a refusal that still
started a process, still reported a successful no-op, still weakened the replay
floor, or still mutated verified state is not a refusal:

1. no engine or installer subprocess started;
2. no successful no-op was reported;
3. the active pointer and the replay floor did not weaken;
4. existing verified state is byte-identical where rollback is allowed.

``assertNoWeakening`` and ``ProcessSpy`` implement 1-4; the individual tests name
the mutation. ``tests/gate0_manifest.json`` maps every requirement to the node IDs
here, and ``tests/conftest.py`` refuses to let the gate report green unless the
collected set equals that manifest exactly.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import errno
import itertools
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

_COUNTER = itertools.count()

from cathedral_node import lockfile, paths, release_lock, revocation
from cathedral_node import proc as proc_module
from cathedral_node.engines import installer
from cathedral_node.release_lock import AuthorizedBundle
from cathedral_node.verified import VerifiedActiveGroup, VerifiedRole

from _bundle_fixture import IDENTITY, BundleFixture, locate_trusted_python

# The verifying clock MUST track the same clock the fixture stamps releases with,
# not a pinned date. `BundleFixture.bundle` sets created_at to the real now minus a
# day; release_lock refuses anything more than _MAX_SKEW (6h) ahead of the verifying
# clock. Pinned at 2026-07-31T00:00Z, this suite went permanently red at 06:00Z that
# day -- every release the fixture built was suddenly "too far in the future" -- and
# nothing noticed, because there was no CI. Read once at import so a single run still
# compares against one instant.
_NOW = dt.datetime.now(dt.timezone.utc)
ROLES = ("distill", "compute", "validator")


# ==============================================================================
# harness
# ==============================================================================

class ProcessSpy:
    """Records every subprocess this node launches.

    ``engine_calls`` is the subset that matters for a refusal: anything executed
    from inside a generation, and any ``pip``/``venv`` invocation. Verification's
    own probes of the *trusted parent* interpreter and of ``ssh-keygen`` are not
    engine or installer subprocesses and are deliberately not counted.
    """

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self._originals: dict[str, object] = {}

    def __enter__(self) -> "ProcessSpy":
        for name in ("run", "probe", "stream"):
            original = getattr(proc_module, name)
            self._originals[name] = original

            def make(original):
                def spy(argv, *a, **kw):
                    self.calls.append([str(x) for x in argv])
                    return original(argv, *a, **kw)
                return spy
            setattr(proc_module, name, make(original))
        return self

    def __exit__(self, *_exc) -> None:
        for name, original in self._originals.items():
            setattr(proc_module, name, original)

    @property
    def engine_calls(self) -> list[list[str]]:
        found = []
        for argv in self.calls:
            joined = " ".join(argv)
            if "/generations/" in joined:
                found.append(argv)
            elif "-m" in argv and ("pip" in argv or "venv" in argv):
                found.append(argv)
        return found


def _suppress_chmod(path: Path, mode: int) -> None:
    with contextlib.suppress(OSError):
        os.chmod(path, mode)


def _floor_of(raw: bytes | None):
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        return data["release_version"], data["lock_digest"]
    except (ValueError, KeyError, TypeError):
        return None


class Gate0Base(unittest.TestCase):
    """A fresh, virgin node per test. Use for install-transaction counterexamples."""

    @classmethod
    def setUpClass(cls):
        cls.trusted = locate_trusted_python()
        if cls.trusted is None:
            raise RuntimeError("Gate 0 requires a CPython 3.11-3.13 interpreter present; none was found")
        cls._root = Path(tempfile.mkdtemp(prefix="gate0-cls-"))
        cls.fx = BundleFixture(cls._root, cls.trusted)
        cls._orig_base = installer.trusted_base_executable
        installer.trusted_base_executable = staticmethod(lambda: (cls.trusted, ""))

    @classmethod
    def tearDownClass(cls):
        installer.trusted_base_executable = cls._orig_base
        installer._force_rmtree(cls._root)

    # ---- environment ---------------------------------------------------------
    def _use_home(self, home: Path) -> None:
        self.home = home
        os.environ["CATHEDRAL_HOME"] = str(home)
        # Trust roots and the lockfile are configured out of band, exactly like a
        # real node: verification reads them from configuration, never the pointer.
        os.environ["CATHEDRAL_ALLOWED_SIGNERS"] = str(self.fx.signers)
        os.environ["CATHEDRAL_REVOCATION_SIGNERS"] = str(self.fx.revocation_signers)
        self._lockfile = home / "test-cathedral.lock.json"
        os.environ["CATHEDRAL_LOCKFILE"] = str(self._lockfile)

    def setUp(self):
        self._use_home(Path(tempfile.mkdtemp(prefix="gate0-home-")))
        self.set_lock()
        paths.ensure_layout()
        self.fx.install_revocation(self.home)

    def tearDown(self):
        for key in ("CATHEDRAL_HOME", "CATHEDRAL_ALLOWED_SIGNERS", "CATHEDRAL_LOCKFILE",
                    "CATHEDRAL_REVOCATION_SIGNERS"):
            os.environ.pop(key, None)
        installer._force_rmtree(self.home)

    def set_lock(self, plan=None):
        self.fx.write_lockfile(self._lockfile, plan)
        self.lock = lockfile.load()
        return self.lock

    # ---- bundles -------------------------------------------------------------
    def _dir(self, name: str) -> Path:
        return self._root / f"bundle-{next(_COUNTER)}-{name}"

    def bundle(self, name: str, version: int = 1, **kw) -> Path:
        return self.fx.make_bundle(self._dir(name), version, **kw)

    def verify(self, bundle_dir, *, min_version=0, active_digest=None, now=_NOW,
               mode=release_lock.CANDIDATE_ACQUISITION):
        return AuthorizedBundle.verify(
            bundle_dir, allowed_signers_path=self.fx.signers, identity=IDENTITY,
            python_info=self.fx.py_info, abi=self.fx.abi, platform_token=self.fx.platform,
            min_release_version=min_version, active_lock_digest=active_digest, now=now, mode=mode)

    def install(self, bundle_dir, lock=None, **kw):
        return installer.install_release(bundle_dir, lock or self.lock, self.fx.signers,
                                         identity=IDENTITY, **kw)

    def verify_active(self, *, now=None):
        return installer.verify_active_group(self.lock, self.fx.signers, now=now)

    # ---- pointer/receipt helpers --------------------------------------------
    def pointer_doc(self) -> dict:
        return json.loads(paths.active_release_pointer().read_text())

    def write_pointer(self, document: dict) -> None:
        paths.active_release_pointer().write_text(json.dumps(document))

    def write_floor(self, version: int, digest: str, **overrides) -> None:
        """Reconstruct an exact durable floor. Tests use this to reproduce the real
        crash states (pending written, floor not yet raised) that a live node reaches
        between two fsyncs."""
        path = paths.release_floor()
        document = {"schema": installer.FLOOR_SCHEMA, "release_version": version,
                    "lock_digest": digest, "identity": release_lock.RELEASE_IDENTITY,
                    "committed_at": "2026-07-31T00:00:00+00:00", **overrides}
        if path.exists():
            os.chmod(path, 0o600)
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
        os.chmod(path, 0o600)

    def floor_doc(self) -> dict:
        return json.loads(paths.release_floor().read_text())

    def generation_dir(self, role: str, pointer: dict | None = None) -> Path:
        pointer = pointer or self.pointer_doc()
        return paths.engine_generation_dir(role, pointer["generations"][role])

    def receipt_path(self, role: str, pointer: dict | None = None) -> Path:
        return self.generation_dir(role, pointer) / "receipt.json"

    def read_receipt(self, role: str, pointer: dict | None = None) -> dict:
        return json.loads(self.receipt_path(role, pointer).read_text())

    def write_receipt(self, path: Path, document: dict) -> None:
        """Receipts are frozen read-only inside the generation; a tamperer would
        chmod first, so the test does too."""
        os.chmod(path, 0o600)
        path.write_text(json.dumps(document))
        os.chmod(path, 0o400)

    def unlock_dir(self, path: Path) -> None:
        """Make a frozen directory writable for the duration of a test.

        Directory modes are part of the measured whole-environment manifest, so a
        chmod that is not undone changes the manifest and breaks the baseline. This
        registers the restore, so a test can never forget.
        """
        mode = path.stat().st_mode & 0o7777
        self.addCleanup(lambda: _suppress_chmod(path, mode))
        os.chmod(path, 0o755)

    def protect(self, path: Path) -> None:
        """Restore a file's exact bytes and mode after the test, so a class-level
        installed node survives a destructive mutation."""
        saved = path.read_bytes()
        mode = path.stat().st_mode & 0o7777
        parent_mode = path.parent.stat().st_mode & 0o7777

        def restore():
            with contextlib.suppress(OSError):
                os.chmod(path.parent, 0o755)
            if path.is_symlink():
                with contextlib.suppress(OSError):
                    path.unlink()
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
            with contextlib.suppress(OSError):
                path.write_bytes(saved)
            with contextlib.suppress(OSError):
                os.chmod(path, mode)
            with contextlib.suppress(OSError):
                os.chmod(path.parent, parent_mode)
        self.addCleanup(restore)

    # ---- the four rejection assertions ---------------------------------------
    def weakening_snapshot(self) -> dict:
        def read(path: Path):
            try:
                return path.read_bytes()
            except OSError:
                return None
        generations = {}
        for role in ROLES:
            root = paths.engine_generations_dir(role)
            generations[role] = sorted(p.name for p in root.iterdir()) if root.is_dir() else []
        return {"pointer": read(paths.active_release_pointer()),
                "floor": read(paths.release_floor()),
                "generations": generations}

    def assertNoWeakening(self, before: dict, *, pointer_may_change: bool = False,
                          generations_may_change: bool = False) -> None:
        after = self.weakening_snapshot()
        old, new = _floor_of(before["floor"]), _floor_of(after["floor"])
        if old is not None:
            self.assertIsNotNone(new, "the replay floor disappeared")
            self.assertGreaterEqual(new[0], old[0], "the replay floor version decreased")
            if new[0] == old[0]:
                self.assertEqual(new[1], old[1], "the replay floor digest changed at the same version")
        if not pointer_may_change:
            self.assertEqual(after["pointer"], before["pointer"], "the active pointer changed")
        if not generations_may_change:
            self.assertEqual(after["generations"], before["generations"],
                             "verified generation state was not byte-identical")

    def assertStartsNoProcess(self, spy: ProcessSpy) -> None:
        self.assertEqual([], spy.engine_calls,
                         f"a rejected mutation started {len(spy.engine_calls)} engine/installer "
                         f"subprocess(es): {spy.engine_calls[:2]}")

    def assertNoSuccessfulNoOp(self, ok: bool, detail: str) -> None:
        self.assertFalse(ok, f"a rejected state reported success: {detail}")
        self.assertNotIn("already active", detail)

    def assertRejected(self, label: str, *, now=None) -> str:
        """One mutation, all four assertions."""
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, reason, group = self.verify_active(now=now)
            state = installer.state(self.lock.pin("validator"))
        self.assertFalse(ok, f"{label} was NOT rejected")
        self.assertIsNone(group)
        self.assertFalse(state.installed, f"{label} still reported an installed engine")
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)
        return reason


class SharedNodeCase(Gate0Base):
    """One installed node per test class.

    Installing three real venvs costs seconds, so the node is built once and each
    test restores the mutable surface it is allowed to touch (pointer, floor,
    receipts, retained release, revocation cache). ``tearDown`` proves the baseline
    still verifies and rebuilds the node if a test destroyed it, so no test can
    silently inherit another's damage.
    """

    VERSIONS = (1,)
    PLAN_FROM_LOCK = False
    _node_home: Path | None = None
    _bundles: dict = {}
    _plan: dict | None = None

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._node_home = None
        cls._bundles = {}

    @classmethod
    def tearDownClass(cls):
        if cls._node_home is not None:
            installer._force_rmtree(cls._node_home)
        super().tearDownClass()

    @classmethod
    def _build_node(cls):
        if cls._node_home is not None:
            installer._force_rmtree(cls._node_home)
        cls._node_home = Path(tempfile.mkdtemp(prefix="gate0-node-"))
        os.environ["CATHEDRAL_HOME"] = str(cls._node_home)
        os.environ["CATHEDRAL_ALLOWED_SIGNERS"] = str(cls.fx.signers)
        os.environ["CATHEDRAL_REVOCATION_SIGNERS"] = str(cls.fx.revocation_signers)
        lock_path = cls._node_home / "test-cathedral.lock.json"
        if cls.PLAN_FROM_LOCK and cls._plan is None:
            # Stub wheels shaped exactly like the repository's real pins — same
            # distribution names, entrypoints, extras, launch modes and revisions —
            # so the REAL engine adapters can be bound to a verified generation.
            os.environ.pop("CATHEDRAL_LOCKFILE", None)
            cls._plan = cls.fx.plan_from_lock(lockfile.load())
        os.environ["CATHEDRAL_LOCKFILE"] = str(lock_path)
        cls.fx.write_lockfile(lock_path, cls._plan)
        paths.ensure_layout()
        cls.fx.install_revocation(cls._node_home)
        lock = lockfile.load()
        cls._bundles = {}
        for version in cls.VERSIONS:
            bundle = cls.fx.make_bundle(cls._root / f"shared-{next(_COUNTER)}-v{version}", version,
                                        plan=cls._plan)
            cls._bundles[version] = bundle
            ok, detail, _ = installer.install_release(bundle, lock, cls.fx.signers, identity=IDENTITY)
            if not ok:
                raise RuntimeError(f"the shared Gate-0 node could not be installed: {detail}")

    def setUp(self):
        if type(self)._node_home is None:
            type(self)._build_node()
        self._use_home(type(self)._node_home)
        self.lock = lockfile.load()
        self.bundles = type(self)._bundles
        self._destructive = False
        self._baseline = self._mutable_snapshot()

    def rebuild_after(self) -> None:
        """Declare that this test legitimately destroys the node (a rollback prunes
        generations, for instance) so the shared node is rebuilt rather than the
        next test inheriting the damage."""
        self._destructive = True

    def tearDown(self):
        self._restore_mutable(self._baseline)
        # Run the addCleanup restores registered by `protect` before checking.
        self.doCleanups()
        self._restore_mutable(self._baseline)
        destructive = getattr(self, "_destructive", False)
        ok, reason, _ = (False, "declared destructive", None) if destructive else self.verify_active()
        for key in ("CATHEDRAL_HOME", "CATHEDRAL_ALLOWED_SIGNERS", "CATHEDRAL_LOCKFILE",
                    "CATHEDRAL_REVOCATION_SIGNERS"):
            os.environ.pop(key, None)
        if not ok:
            type(self)._build_node()
            if not destructive:
                self.fail(f"this test left the shared node unverifiable and it was rebuilt: {reason}")

    # ---- mutable-surface snapshot -------------------------------------------
    def _mutable_files(self) -> list[Path]:
        files = [paths.active_release_pointer(), paths.release_floor(),
                 paths.activation_marker(), paths.activation_journal(),
                 revocation.cache_file(), revocation.floor_file()]
        pointer = paths._read_group_pointer()
        if isinstance(pointer, dict):
            for role, generation in (pointer.get("generations") or {}).items():
                files.append(paths.engine_generation_dir(role, generation) / "receipt.json")
        retained = paths.retained_releases_dir()
        if retained.is_dir():
            for child in retained.iterdir():
                files.extend([child / "release.json", child / "release.json.sig"])
        return files

    def _mutable_snapshot(self) -> dict:
        snapshot = {}
        for path in self._mutable_files():
            try:
                snapshot[str(path)] = (path.read_bytes(), path.stat().st_mode & 0o7777)
            except OSError:
                snapshot[str(path)] = None
        return snapshot

    def _restore_mutable(self, snapshot: dict) -> None:
        for name, value in snapshot.items():
            path = Path(name)
            if value is None:
                with contextlib.suppress(OSError):
                    if path.is_symlink() or path.is_file():
                        path.unlink()
                continue
            data, mode = value
            with contextlib.suppress(OSError):
                if path.is_symlink():
                    path.unlink()
                path.parent.mkdir(parents=True, exist_ok=True)
                if path.exists():
                    os.chmod(path, 0o600)
                path.write_bytes(data)
                os.chmod(path, mode)


# ==============================================================================
# release_lock: the AuthorizedBundle boundary
# ==============================================================================

class TestReleaseVerification(Gate0Base):
    def test_a_valid_bundle_verifies_and_binds_version_identity_digest(self):
        ok, reason, ab = self.verify(self.bundle("valid"))
        self.assertTrue(ok, reason)
        self.assertEqual(ab.authorization.release_version, 1)
        self.assertEqual(ab.authorization.identity, IDENTITY)
        self.assertEqual(len(ab.authorization.lock_digest), 64)
        self.assertEqual(set(ab.authorization.roles), set(ROLES))

    def test_a_bad_signature_is_refused(self):
        b = self.bundle("badsig")
        sig = b / "release.json.sig"
        sig.write_bytes(sig.read_bytes()[:-16])
        ok, reason, _ = self.verify(b)
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_a_forged_signer_is_refused(self):
        """Structurally valid, signed by a key the trust root does not authorize."""
        b = self.bundle("forged", key=self.fx.foreign_key())
        ok, reason, _ = self.verify(b)
        self.assertFalse(ok)
        self.assertIn("signature", reason)

    def test_a_tampered_manifest_is_refused(self):
        b = self.bundle("tamper")
        doc = json.loads((b / "release.json").read_bytes())
        doc["release_version"] = 999
        (b / "release.json").write_bytes(release_lock.canonical_bytes(doc))
        self.assertFalse(self.verify(b)[0])

    def test_an_unsigned_bundle_is_refused(self):
        self.assertFalse(self.verify(self.bundle("unsigned", sign=False))[0])

    def test_a_duplicate_key_is_rejected(self):
        with self.assertRaises(ValueError):
            release_lock.parse_strict(b'{"a":1,"a":2}')

    def test_noncanonical_json_is_rejected(self):
        with self.assertRaises(ValueError):
            release_lock.parse_strict(b'{"b":1, "a":2}')

    def test_non_finite_constants_are_rejected(self):
        for blob in (b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}'):
            with self.assertRaises(ValueError):
                release_lock.parse_strict(blob)

    def test_an_unknown_top_level_field_is_refused(self):
        b = self.bundle("unknown", mutate=lambda m: {**m, "surprise": 1})
        self.assertFalse(self.verify(b)[0])

    def test_an_unknown_role_field_is_refused(self):
        def mut(m):
            m["roles"]["distill"]["surprise"] = 1
            return m
        self.assertFalse(self.verify(self.bundle("unkrole", mutate=mut))[0])

    def test_a_forged_revision_is_not_authorized_by_the_local_lock(self):
        """A signed release naming a revision the local lock does not pin is not
        authorized for this node, however valid its signature."""
        def mut(m):
            m["roles"]["distill"]["revision"] = "9" * 40
            return m
        ok, reason, bundle = self.verify(self.bundle("forgedrev", mutate=mut))
        self.assertTrue(ok, reason)
        pin = self.lock.pin("distill")
        authorized, why, _spec = release_lock.authorize_role(
            bundle.authorization, "distill", repository=pin.repository, revision=pin.revision,
            distribution=pin.distribution, extras=list(pin.extras), entrypoints=list(pin.entrypoints),
            server_entrypoints=list(pin.server_entrypoints), protocol=pin.protocol,
            launch_mode=pin.launch_mode)
        self.assertFalse(authorized, why)

    def test_an_expired_release_is_refused_for_acquisition(self):
        self.assertFalse(self.verify(self.bundle("valid2"),
                                     now=dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc))[0])

    def test_an_expired_release_still_verifies_for_retained_runtime(self):
        """Signed-bundle expiry is an acquisition window, not a runtime kill switch."""
        b = self.bundle("retained")
        future = dt.datetime(2100, 1, 1, tzinfo=dt.timezone.utc)
        self.assertFalse(self.verify(b, now=future)[0])
        ok, reason, _ = self.verify(b, now=future, mode=release_lock.RETAINED_RUNTIME)
        self.assertTrue(ok, reason)

    def test_an_unknown_validation_mode_is_refused(self):
        ok, reason, _ = self.verify(self.bundle("mode"), mode="whatever")
        self.assertFalse(ok)
        self.assertIn("mode", reason)

    def test_a_future_created_at_is_refused(self):
        def mut(m):
            m["created_at"] = "2099-01-01T00:00:00+00:00"
            m["expires_at"] = "2099-02-01T00:00:00+00:00"
            return m
        self.assertFalse(self.verify(self.bundle("future", mutate=mut))[0])

    def test_expiry_before_creation_is_refused(self):
        def mut(m):
            m["created_at"] = "2026-07-10T00:00:00+00:00"
            m["expires_at"] = "2026-07-01T00:00:00+00:00"
            return m
        self.assertFalse(self.verify(self.bundle("order", mutate=mut))[0])

    def test_an_unbounded_lifetime_is_refused(self):
        def mut(m):
            m["created_at"] = "2026-01-01T00:00:00+00:00"
            m["expires_at"] = "2099-01-01T00:00:00+00:00"
            return m
        self.assertFalse(self.verify(self.bundle("life", mutate=mut))[0])

    def test_a_naive_timestamp_is_refused(self):
        self.assertFalse(self.verify(self.bundle(
            "naive", mutate=lambda m: {**m, "expires_at": "2027-01-01T00:00:00"}))[0])

    def test_a_naive_verifying_clock_is_refused(self):
        ok, reason, _ = self.verify(self.bundle("nownaive"), now=dt.datetime(2026, 7, 31))
        self.assertFalse(ok)
        self.assertIn("aware", reason)

    def test_a_foreign_abi_or_platform_is_refused(self):
        self.assertFalse(self.verify(self.bundle("abi", mutate=lambda m: {**m, "abi": ["cp999"]}))[0])
        self.assertFalse(self.verify(self.bundle("plat", mutate=lambda m: {**m, "platforms": ["nope"]}))[0])

    def test_a_foreign_python_version_range_is_refused(self):
        def mut(m):
            m["python"] = {"min": [3, 20], "max_exclusive": [3, 21]}
            return m
        self.assertFalse(self.verify(self.bundle("pyver", mutate=mut))[0])

    def test_a_release_missing_a_role_is_refused(self):
        def mut(m):
            del m["roles"]["compute"]
            return m
        self.assertFalse(self.verify(self.bundle("2role", mutate=mut))[0])

    def test_an_unknown_role_is_refused(self):
        def mut(m):
            m["roles"]["mystery"] = m["roles"]["compute"]
            return m
        self.assertFalse(self.verify(self.bundle("4role", mutate=mut))[0])

    def test_replay_semantics(self):
        b = self.bundle("v5", version=5)
        digest = self.verify(b)[2].authorization.lock_digest
        self.assertFalse(self.verify(b, min_version=5, active_digest="deadbeef")[0],
                         "different release at floor")
        self.assertTrue(self.verify(b, min_version=5, active_digest=digest)[0],
                        "identical release is idempotent")
        self.assertFalse(self.verify(b, min_version=6)[0], "below floor is a downgrade")

    def test_a_world_writable_allowed_signers_is_refused(self):
        os.chmod(self.fx.signers, 0o666)
        try:
            self.assertFalse(self.verify(self.bundle("ww"))[0])
        finally:
            os.chmod(self.fx.signers, 0o600)

    def test_a_symlinked_allowed_signers_is_refused(self):
        link = self.home / "signers-link"
        os.symlink(self.fx.signers, link)
        ok, _, _ = AuthorizedBundle.verify(
            self.bundle("symsign"), allowed_signers_path=link, identity=IDENTITY,
            python_info=self.fx.py_info, abi=self.fx.abi, platform_token=self.fx.platform,
            min_release_version=0, active_lock_digest=None, now=_NOW)
        self.assertFalse(ok)

    def test_an_extra_unsigned_artifact_is_refused(self):
        b = self.bundle("extra")
        (b / "roles" / "distill" / "wheels" / "sneaky-1.0-py3-none-any.whl").write_bytes(b"malware")
        self.assertFalse(self.verify(b)[0])

    def test_an_unexpected_top_level_bundle_file_is_refused(self):
        b = self.bundle("toplevel")
        (b / "extra.txt").write_text("x")
        self.assertFalse(self.verify(b)[0])

    def test_an_unexpected_role_directory_file_is_refused(self):
        b = self.bundle("roledir")
        (b / "roles" / "distill" / "notes.txt").write_text("x")
        self.assertFalse(self.verify(b)[0])

    def test_a_wrong_wheel_hash_is_refused(self):
        b = self.bundle("wheelhash")
        wheel = next((b / "roles" / "distill" / "wheels").glob("*.whl"))
        wheel.write_bytes(wheel.read_bytes() + b"x")
        self.assertFalse(self.verify(b)[0])

    def test_a_symlinked_source_archive_is_refused(self):
        b = self.bundle("symsrc")
        src = b / "roles" / "distill" / "source.tar"
        src.unlink()
        os.symlink("/etc/hosts", src)
        self.assertFalse(self.verify(b)[0])

    def test_a_control_char_wheel_filename_is_refused(self):
        def mut(m):
            m["roles"]["distill"]["requirements"][0]["file"] = "--evil-1.0-py3-none-any.whl"
            return m
        self.assertFalse(self.verify(self.bundle("ctrl", mutate=mut))[0])

    def test_a_duplicate_normalized_package_is_refused(self):
        def mut(m):
            reqs = m["roles"]["validator"]["requirements"]
            dupe = dict(reqs[0])
            dupe["file"] = dupe["file"].replace("pv", "pv_", 1)  # same normalized name, new file
            reqs.append(dupe)
            return m
        self.assertFalse(self.verify(self.bundle("dupe", mutate=mut))[0])


class TestAuthorizationImmutability(Gate0Base):
    def test_authorized_bundle_cannot_be_forged(self):
        with self.assertRaises(TypeError):
            AuthorizedBundle(object(), Path("/"), None)  # type: ignore[arg-type]

    def test_authorization_roles_are_read_only(self):
        ab = self.verify(self.bundle("immut"))[2]
        with self.assertRaises((TypeError, AttributeError)):
            ab.authorization.roles["distill"] = None  # type: ignore[index]
        with self.assertRaises(AttributeError):
            ab.authorization.release_version = 99  # type: ignore[misc]

    def test_role_and_artifact_are_immutable(self):
        ab = self.verify(self.bundle("immut2"))[2]
        role = ab.authorization.role("validator")
        with self.assertRaises(AttributeError):
            role.revision = "x"  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            role.artifacts[0].sha256 = "x"  # type: ignore[misc]


# ==============================================================================
# the install transaction (virgin node per test)
# ==============================================================================

class TestInstallTransaction(Gate0Base):
    def _installed(self, role):
        return installer.state(self.lock.pin(role)).installed

    def test_a_signed_release_installs_all_three_roles_and_persists_provenance(self):
        ok, detail, _res = self.install(self.bundle("full"))
        self.assertTrue(ok, detail)
        states, group, _reason = installer.install_states(self.lock)
        for role in ROLES:
            self.assertTrue(states[role].installed, role)
            self.assertEqual(states[role].release_version, 1)
            self.assertEqual(states[role].signer_identity, IDENTITY)
        self.assertTrue((group.role("validator").venv_dir / "bin" / "pv-preview").is_file())
        self.assertTrue(paths.activation_marker().exists())
        self.assertTrue(paths.activation_journal().exists())

    def test_a_malicious_source_archive_is_never_built(self):
        self.install(self.bundle("mal", source_tar=self.fx.mal_tar))
        self.assertFalse(self.fx.sentinel_created(),
                         "source must never be built; a malicious setup.py must not run")

    def test_no_install_subprocess_runs_when_the_signature_fails(self):
        b = self.bundle("nosub")
        (b / "release.json.sig").write_bytes((b / "release.json.sig").read_bytes()[:-16])
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, detail, _ = self.install(b)
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)

    def test_pip_runs_offline_and_hardened_with_a_minimal_environment(self):
        captured: dict = {}
        envs: list[dict] = []
        original = installer.proc.run

        def spy(argv, **kw):
            argv_str = [str(a) for a in argv]
            if kw.get("inherit_env") is False and (
                    "/generations/" in " ".join(argv_str) or "-m" in argv_str):
                envs.append(kw.get("env") or {})
            if "-m" in argv_str and "pip" in argv_str and "install" in argv_str:
                captured["argv"] = argv_str
                captured["env"] = kw.get("env")
                captured["inherit"] = kw.get("inherit_env")
            return original(argv, **kw)

        installer.proc.run = spy
        try:
            ok, detail, _ = self.install(self.bundle("hardpip"))
        finally:
            installer.proc.run = original
        self.assertTrue(ok, detail)
        self.assertIs(captured.get("inherit"), False)
        env = captured.get("env") or {}
        self.assertEqual(env.get("PIP_NO_INDEX"), "1")
        self.assertEqual(env.get("PIP_CONFIG_FILE"), "/dev/null")
        self.assertEqual(env.get("PYTHONDONTWRITEBYTECODE"), "1")
        for flag in ("--no-index", "--require-hashes", "--no-deps", "--only-binary=:all:",
                     "--no-compile"):
            self.assertIn(flag, captured.get("argv", []))
        # Minimal, allowlisted environment for EVERY signed-engine subprocess: no
        # host PYTHONPATH, venv selector, preload, proxy or credential variable
        # crosses the boundary.
        allowed = set(proc_module.SIGNED_CHILD_ALLOWLIST) | {"PIP_CONFIG_FILE", "PIP_NO_INDEX"}
        self.assertTrue(envs, "no scrubbed engine subprocess was observed")
        for observed in envs:
            self.assertEqual(set(observed) - allowed, set(),
                             f"an engine subprocess inherited {sorted(set(observed) - allowed)}")
            self.assertEqual(observed.get("PATH"), "/usr/bin:/bin")

    def test_a_base_only_validator_closure_is_rejected(self):
        plan = self.fx.role_plan()
        plan["validator"]["wheels"] = [self.fx.w["pv"]]  # omit pvx -> integration entrypoint absent
        plan["validator"]["roots"] = {"pv": "pvpkg"}
        self.set_lock(plan)
        ok, detail, _ = self.install(self.bundle("baseonly", plan=plan))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIsNone(paths.reported_generation("validator"))

    def test_an_unsatisfiable_dependency_version_constraint_is_rejected(self):
        plan = self.fx.role_plan()
        plan["validator"].update(dist="pvver", wheels=[self.fx.w["pvver"], self.fx.w["pvx"]],
                                 roots={"pvver": "pvverpkg", "pvx": "pvxpkg"})
        self.set_lock(plan)
        ok, detail, _ = self.install(self.bundle("badver", plan=plan))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("closure", detail.lower())

    def test_role_readiness_and_liveness_matrix(self):
        """Every named readiness failure fails the install and leaves nothing active:
        immediate clean exit, immediate nonzero exit, exit after readiness, a client
        that hangs on --help, and a client that exits nonzero."""
        cases = {
            "server_exits_clean": ("pclean", "pcleanpkg"),
            "server_exits_nonzero": ("pbad", "pbadpkg"),
            "server_exits_after_readiness": ("plate", "platepkg"),
            "client_hangs_on_help": ("phang", "phangpkg"),
            "client_exits_nonzero": ("pcbad", "pcbadpkg"),
        }
        for label, (dist, module) in cases.items():
            with self.subTest(case=label):
                plan = self.fx.role_plan()
                plan["distill"].update(dist=dist, wheels=[self.fx.w[dist]], roots={dist: module})
                self.set_lock(plan)
                ok, detail, _ = self.install(self.bundle(f"ready-{label}", plan=plan))
                self.assertNoSuccessfulNoOp(ok, detail)
                self.assertIsNone(paths.reported_generation("distill"))

    def test_a_wheel_whose_internal_metadata_disagrees_is_rejected(self):
        # distill's signed wheel keeps the "pd" filename but holds the pc wheel's
        # bytes; the manifest hash is updated to match (so the artifact-hash check
        # passes) and re-signed — only the internal METADATA cross-check can catch it.
        import hashlib
        b = self.bundle("metamismatch")
        pd_wheel = next((b / "roles" / "distill" / "wheels").glob("pd-*.whl"))
        pd_wheel.write_bytes(self.fx.w["pc"].read_bytes())
        doc = json.loads((b / "release.json").read_bytes())
        req = doc["roles"]["distill"]["requirements"][0]
        req["sha256"] = hashlib.sha256(pd_wheel.read_bytes()).hexdigest()
        req["size"] = pd_wheel.stat().st_size
        (b / "release.json").write_bytes(release_lock.canonical_bytes(doc))
        sig = self.fx.sign(b / "release.json")
        shutil.move(str(sig), str(b / "release.json.sig"))
        ok, detail, _ = self.install(b)
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertTrue("metadata" in detail.lower() or "internal" in detail.lower(),
                        f"the wheel-metadata cross-check should reject it: {detail}")

    def test_generations_are_frozen_read_only_including_the_receipt(self):
        ok, detail, _ = self.install(self.bundle("frozen"))
        self.assertTrue(ok, detail)
        _states, group, _r = installer.install_states(self.lock)
        role = group.role("validator")
        self.assertFalse(role.python.stat().st_mode & 0o222,
                         "the venv python must not be writable after prepare")
        self.assertFalse(role.receipt.stat().st_mode & 0o222,
                         "the receipt must be frozen with the rest of the generation")
        self.assertFalse(role.generation_dir.stat().st_mode & 0o022,
                         "the generation root must not be group/other writable")

    def test_the_durable_floor_survives_a_destroyed_pointer(self):
        self.install(self.bundle("floor", version=5))
        paths.active_release_pointer().unlink()
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, detail, _ = self.install(self.bundle("floor-replay", version=3))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)

    def test_a_release_that_is_not_the_full_role_set_is_refused(self):
        def mut(m):
            del m["roles"]["compute"]
            return m
        ok, detail, _ = self.install(self.bundle("2role", mutate=mut))
        self.assertNoSuccessfulNoOp(ok, detail)

    def test_failed_activation_health_rolls_back_and_preserves_the_prior_group(self):
        self.install(self.bundle("g1", version=1))
        prior = {r: paths.reported_generation(r) for r in ROLES}
        floor_before = paths.release_floor().read_bytes()

        class BadSupervisor:
            """Stops cleanly; the NEW group never becomes ready, the prior one does.

            The distinction is the test. A supervisor that also fails the prior
            group's readiness is a different scenario — the transaction can neither
            commit nor unwind — and it must leave recovery required rather than a
            restored pointer, which is proven separately.
            """

            def __init__(self):
                self.started = []

            def running_roles(self):
                return sorted(_RUNNING)

            def stop(self, roles):
                _RUNNING.difference_update(roles)

            def start(self, group, roles):
                self.started.append(group.lock_digest)
                _RUNNING.update(roles)

            def readiness(self, roles):
                if len(self.started) <= 1:
                    return False, "injected readiness failure"
                return True, "the prior group is ready"

        original_running = installer.run_state.running_run
        _RUNNING.clear()
        _RUNNING.update(("distill", "validator"))
        installer.run_state.running_run = _patched_running_run
        try:
            ok, detail, _ = self.install(self.bundle("g2", version=2), supervisor=BadSupervisor())
        finally:
            installer.run_state.running_run = original_running
            _RUNNING.clear()
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertEqual({r: paths.reported_generation(r) for r in prior}, prior,
                         "the prior group must be restored exactly")
        self.assertEqual(paths.release_floor().read_bytes(), floor_before,
                         "a failed activation must not move the replay floor")
        for role in ROLES:
            self.assertTrue(self._installed(role), f"{role} prior generation must still verify")

    def test_read_only_state_reports_recovery_required_and_never_mutates(self):
        self.install(self.bundle("ro"))
        pointer = paths.active_release_pointer()
        doc = json.loads(pointer.read_text())
        doc["state"] = "pending"
        pointer.write_text(json.dumps(doc))
        before = pointer.read_text()
        st = installer.state(self.lock.pin("validator"))
        self.assertTrue(st.recovery_required)
        self.assertFalse(st.installed)
        self.assertEqual(pointer.read_text(), before, "a read-only call must not mutate the pointer")

    def test_recovery_commits_a_valid_pending_group(self):
        self.install(self.bundle("rec"))
        doc = self.pointer_doc()
        self.write_pointer({**doc, "state": "pending"})
        ok, detail = installer.recover(self.lock)
        self.assertTrue(ok, detail)
        self.assertIsNotNone(paths.reported_generation("validator"))

    def test_receipt_write_failure_leaves_no_generation_or_pointer(self):
        original = installer._write_json_atomic

        def failing(path, document):
            if path.name == "receipt.json":
                raise OSError("injected receipt write failure")
            return original(path, document)

        installer._write_json_atomic = failing
        try:
            ok, detail, _ = self.install(self.bundle("recfail"))
        finally:
            installer._write_json_atomic = original
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertFalse(paths.active_release_pointer().exists(), "no pointer may survive")
        self.assertFalse(paths.release_floor().exists(), "the floor must not have moved")
        for role in ROLES:
            root = paths.engine_generations_dir(role)
            self.assertEqual([] if not root.is_dir() else list(root.iterdir()), [],
                             f"an incomplete {role} generation was left behind")
        retained = paths.retained_releases_dir()
        self.assertEqual([] if not retained.is_dir() else list(retained.iterdir()), [],
                         "an unreferenced retained release was left behind")

    def test_pending_pointer_write_failure_leaves_no_committed_state(self):
        original = installer._write_json_atomic

        def failing(path, document):
            if path == paths.active_release_pointer():
                raise OSError("injected pointer write failure")
            return original(path, document)

        installer._write_json_atomic = failing
        try:
            ok, detail, _ = self.install(self.bundle("ptrfail"))
        except OSError:
            ok, detail = False, "pointer write failed"
        finally:
            installer._write_json_atomic = original
        self.assertFalse(ok, detail)
        self.assertFalse(paths.active_release_pointer().exists())
        self.assertFalse(paths.activation_marker().exists())

    def test_an_incomplete_generation_is_removed_when_preparation_fails(self):
        original = installer._self_check
        installer._self_check = lambda venv, pin, gen_dir: (False, "injected self-check failure")
        try:
            ok, detail, _ = self.install(self.bundle("prepfail"))
        finally:
            installer._self_check = original
        self.assertNoSuccessfulNoOp(ok, detail)
        for role in ROLES:
            root = paths.engine_generations_dir(role)
            self.assertEqual([] if not root.is_dir() else list(root.iterdir()), [],
                             f"an incomplete {role} generation survived")

    def test_a_concurrent_transaction_is_refused_not_interleaved(self):
        with installer.lifecycle_lock(exclusive=True):
            with ProcessSpy() as spy:
                ok, detail, _ = installer.install_release(
                    self.bundle("concurrent"), self.lock, self.fx.signers, identity=IDENTITY,
                    lock_timeout=0.5)
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("progress", detail)
        self.assertStartsNoProcess(spy)

    def test_a_stale_role_lock_is_reclaimed_and_stop_is_idempotent(self):
        from cathedral_node import state as run_state
        dead = 2 ** 31 - 1
        run_state.write_ownership(run_state.ChildOwnership(
            role="distill", run_id="dead", parent_pid=dead, child_pid=dead, pgid=dead,
            start_identity="mac:1.000000:1:0", boot_id=run_state.boot_identity(),
            euid=os.geteuid(), generation="", lock_digest="", token="stale",
            since="2026-01-01T00:00:00Z", spawn_state=run_state.SPAWN_OWNED))
        self.assertIsNone(run_state.running_run("distill"), "a dead owner's lock must be reclaimed")
        self.assertEqual(run_state.stop_role("distill"), (False, "not running"))
        self.assertEqual(run_state.stop_role("distill"), (False, "not running"))

    def test_an_obsolete_ownership_record_is_not_silently_reclaimed(self):
        """Reclaiming a *dead owner* is not the same as reclaiming a record we
        cannot read. A record in a shape this node does not understand was written
        by something, so something may be running."""
        from cathedral_node import state as run_state
        lock_path = paths.role_lock("distill")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        run_state.write_ownership_document(lock_path, json.dumps(
            {"pid": 2 ** 31 - 1, "run_id": "dead", "since": "2026-01-01T00:00:00Z"}).encode())
        holder = run_state.running_run("distill")
        self.assertIsNotNone(holder, "an unreadable record must not read as free")
        self.assertEqual(holder.get("unresolved"), run_state.OWNERSHIP_UNVERIFIABLE)
        stopped, detail = run_state.stop_role("distill")
        self.assertFalse(stopped, "a record that cannot be understood must not be cleared")
        self.assertTrue(lock_path.exists())
        self.assertTrue(run_state.deletion_blocked("distill")[0])


class TestChannelDelivery(Gate0Base):
    """The HTTPS channel mode fetches only inert bytes, then runs the identical
    verification — a tampered channel is refused before any artifact is trusted."""

    def _serve(self, directory: Path):
        import functools
        import http.server
        import socketserver
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))

        class Quiet(socketserver.TCPServer):
            allow_reuse_address = True

            def handle_error(self, *_a):
                pass
        httpd = Quiet(("127.0.0.1", 0), handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        return f"http://127.0.0.1:{httpd.server_address[1]}"

    def test_channel_fetch_verifies_and_installs(self):
        from cathedral_node.commands import _release
        base = self._serve(self.bundle("channel"))
        cache = self.home / "cache" / "fetched"
        got, reason = _release.fetch_channel(base, cache, self.fx.signers, IDENTITY)
        self.assertIsNotNone(got, reason)
        ok, detail, _ = installer.install_release(got, self.lock, self.fx.signers, identity=IDENTITY)
        self.assertTrue(ok, detail)
        self.assertTrue(installer.state(self.lock.pin("validator")).installed)

    def test_a_tampered_channel_manifest_is_refused_before_download(self):
        from cathedral_node.commands import _release
        bundle = self.bundle("channelbad")
        sig = bundle / "release.json.sig"
        sig.write_bytes(sig.read_bytes()[:-16])  # break the signature
        base = self._serve(bundle)
        cache = self.home / "cache" / "fetchedbad"
        got, _reason = _release.fetch_channel(base, cache, self.fx.signers, IDENTITY)
        self.assertIsNone(got, "a tampered channel manifest must be refused")
        self.assertFalse((cache / "roles").exists(),
                         "no artifacts may be fetched for an unverified manifest")

    def test_a_plaintext_remote_channel_is_refused(self):
        from cathedral_node.commands import _release
        got, _reason = _release.fetch_channel("http://example.com/release", self.home / "c",
                                              self.fx.signers, IDENTITY)
        self.assertIsNone(got)


# ==============================================================================
# sealed verified values and the runtime binding (directive 8.1-8.12)
# ==============================================================================

class _StubQualification:
    can_local_test = True
    can_operate = True
    blockers: list = []
    notes: list = []

    def to_dict(self):
        return {"can_local_test": True, "can_operate": True, "blockers": [], "notes": []}


class _StubEngine:
    """A deterministic adapter bound to a verified role.

    It exists so the *real* start/test control flow in `cathedral_node.commands`
    can be driven end to end without a live engine: the thing under test is the
    lifecycle guard, not the engine's own qualification rules.
    """

    title = "Stub"
    tagline = "deterministic"

    def __init__(self, role, verified):
        self.role = role
        self.verified = verified
        self.ran: list = []

    def qualify(self, _cfg):
        return _StubQualification()

    def capabilities(self):
        return {"local_test": {"available": True, "what_it_proves": "nothing"}}

    def operate_argv(self, _cfg, *, dry_run=False):
        return [str(self.verified.bin("python")), "-c", "print('engine ran')"]

    def operate_env(self, _cfg):
        return {}

    def child_env(self, _cfg=None):
        """The adapter contract the production launch path requires.

        `proc.stream` takes `inherit_env` as a required keyword and the launch
        builds the child's whole environment from the adapter, so a stub without
        this cannot reach the code the runtime-binding tests are about.
        """
        from cathedral_node import proc as _proc
        return _proc.signed_child_env(home=paths.home())

    def interpret_line(self, _line):
        return None

    def local_test(self, _cfg, _run_id, *, progress, timeout):
        from cathedral_node.engines.base import TestOutcome
        self.ran.append(True)
        return TestOutcome(passed=True, summary="stub", checks=[], identifiers={})


class RuntimeBindingCase(SharedNodeCase):
    """Helpers for driving the real start/test paths against a stub engine."""

    def _stub(self, role: str):
        from cathedral_node import config as config_module
        from cathedral_node import engines as engines_module
        stub_holder: dict = {}
        original_load = engines_module.load
        original_validate = config_module.validate

        def fake_load(name, lock=None, group=None):
            verified = group.role(name) if group is not None and name in group else None
            engine = _StubEngine(name, verified)
            stub_holder[name] = engine
            return engine

        engines_module.load = fake_load
        config_module.validate = lambda *_a, **_k: []
        self.addCleanup(lambda: setattr(engines_module, "load", original_load))
        self.addCleanup(lambda: setattr(config_module, "validate", original_validate))
        return stub_holder

    def _context(self, role: str, run_id: str):
        import types as _types
        from cathedral_node import runner
        return runner.Context(
            args=_types.SimpleNamespace(role=role, broadcast=False, once=False, timeout=30),
            console=runner.build_console(json_mode=True, quiet=True), json_mode=True,
            assume_yes=True, dry_run=False, verbose=False, run_id=run_id, home=self.home)

    def _swap_pointer_to_other_generation(self) -> None:
        """A stat-preserving-shaped, well-formed pointer naming a different generation
        map. Any verifier that trusts a cached verdict will miss it."""
        document = self.pointer_doc()
        generations = dict(document["generations"])
        generations["distill"], generations["compute"] = generations["compute"], generations["distill"]
        self.write_pointer({**document, "generations": generations})

    def _tamper_generation(self) -> None:
        target = next(p for p in (self.generation_dir("validator") / "venv").rglob("*.py")
                      if "pvpkg" in str(p))
        self.protect(target)
        os.chmod(target, 0o644)
        target.write_text(target.read_text() + "\n# tampered\n")
        os.chmod(target, 0o444)


class TestVerifiedRuntimeBinding(RuntimeBindingCase):

    # --- 1 -----------------------------------------------------------------
    def test_verified_group_is_private_frozen_and_role_map_is_immutable(self):
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        self.assertIsInstance(group, VerifiedActiveGroup)
        with self.assertRaises(TypeError):
            VerifiedActiveGroup(object(), release_version=1, lock_digest="x", identity="y",
                                pointer_digest="z", roles={})
        with self.assertRaises(TypeError):
            VerifiedRole(object(), role="distill", generation="g", generation_dir=Path("/"),
                         source_dir=Path("/"), venv_dir=Path("/"), python=Path("/"),
                         receipt=Path("/"), receipt_data={}, entrypoints=())
        with self.assertRaises(AttributeError):
            group.release_version = 99
        with self.assertRaises(AttributeError):
            group.role("distill").python = Path("/bin/sh")
        with self.assertRaises(TypeError):
            group.roles["distill"] = None
        with self.assertRaises(TypeError):
            group.role("distill").receipt_data["role"] = "evil"
        self.assertIsInstance(group.role("distill").receipt_data["extras"], tuple)

    # --- 2 -----------------------------------------------------------------
    def test_generation_tamper_after_first_state_is_not_cached(self):
        self.assertTrue(installer.state(self.lock.pin("validator")).installed)
        self._tamper_generation()
        # No cache to clear: the second read re-verifies the bytes on disk.
        self.assertRejected("same-process generation tamper")

    # --- 3 -----------------------------------------------------------------
    def test_retained_release_tamper_after_first_state_is_not_cached(self):
        self.assertTrue(installer.state(self.lock.pin("validator")).installed)
        manifest = paths.retained_releases_dir() / self.pointer_doc()["lock_digest"] / "release.json"
        self.protect(manifest)
        manifest.write_bytes(manifest.read_bytes() + b" ")
        self.assertRejected("same-process retained-manifest tamper")

    # --- 4 -----------------------------------------------------------------
    def test_stat_preserving_pointer_rewrite_is_not_cached(self):
        path = paths.active_release_pointer()
        self.assertTrue(installer.state(self.lock.pin("validator")).installed)
        document = self.pointer_doc()
        before_stat = os.stat(path)
        generations = dict(document["generations"])
        generations["distill"], generations["compute"] = generations["compute"], generations["distill"]
        swapped = json.dumps({**document, "generations": generations}, indent=2, sort_keys=True) + "\n"
        self.assertEqual(len(swapped), before_stat.st_size,
                         "the test must rewrite the pointer at exactly the same size")
        fd = os.open(str(path), os.O_WRONLY)  # no O_TRUNC: same inode, same size
        try:
            os.write(fd, swapped.encode())
        finally:
            os.close(fd)
        os.utime(path, ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns))
        after_stat = os.stat(path)
        self.assertEqual((after_stat.st_size, after_stat.st_mtime_ns, after_stat.st_ino),
                         (before_stat.st_size, before_stat.st_mtime_ns, before_stat.st_ino),
                         "the rewrite must be indistinguishable by stat metadata")
        self.assertRejected("stat-preserving pointer rewrite")

    # --- 5 -----------------------------------------------------------------
    def test_state_python_path_comes_from_verified_role_not_second_pointer_read(self):
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        for role in ROLES:
            state = installer.state(self.lock.pin(role))
            self.assertEqual(state.python, str(group.role(role).python))
            self.assertIn(f"/generations/{group.role(role).generation}/venv/bin/python", state.python)
        # The pointer-reading execution-path helpers no longer exist at all, so a
        # consumer cannot re-resolve a path from mutable state even by accident.
        for removed in ("engine_venv", "engine_bin", "engine_src", "engine_receipt"):
            self.assertFalse(hasattr(paths, removed),
                             f"paths.{removed} re-read the mutable pointer and must not exist")

    # --- 6 -----------------------------------------------------------------
    def test_start_pointer_swap_after_verify_starts_no_process(self):
        from cathedral_node import state as run_state
        from cathedral_node.commands import run as run_command
        stubs = self._stub("validator")
        before = self.weakening_snapshot()
        original_create = run_state.create_run

        def swap_then_create(*a, **kw):
            self._swap_pointer_to_other_generation()
            return original_create(*a, **kw)

        run_state.create_run = swap_then_create
        try:
            with ProcessSpy() as spy:
                with installer.verified_active_group(self.lock) as active:
                    envelope = run_command._start_verified(
                        self._context("validator", "start-swap"), "validator", self.lock, active)
        finally:
            run_state.create_run = original_create
        self.assertNotEqual(envelope.status, "ok", "a post-verification swap must not start")
        self.assertStartsNoProcess(spy)
        self.assertFalse(stubs["validator"].ran)
        self.assertNoWeakening(before, pointer_may_change=True)

    # --- 7 -----------------------------------------------------------------
    def test_start_generation_tamper_after_qualification_starts_no_process(self):
        from cathedral_node import state as run_state
        from cathedral_node.commands import run as run_command
        self._stub("validator")
        before = self.weakening_snapshot()
        original_create = run_state.create_run

        def tamper_then_create(*a, **kw):
            self._tamper_generation()
            return original_create(*a, **kw)

        run_state.create_run = tamper_then_create
        try:
            with ProcessSpy() as spy:
                with installer.verified_active_group(self.lock) as active:
                    envelope = run_command._start_verified(
                        self._context("validator", "start-tamper"), "validator", self.lock, active)
        finally:
            run_state.create_run = original_create
        self.assertNotEqual(envelope.status, "ok")
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)

    # --- 8 -----------------------------------------------------------------
    def test_test_pointer_swap_after_verify_runs_no_engine(self):
        from cathedral_node import state as run_state
        from cathedral_node.commands import test as test_command
        stubs = self._stub("distill")
        before = self.weakening_snapshot()
        original_create = run_state.create_run

        def swap_then_create(*a, **kw):
            self._swap_pointer_to_other_generation()
            return original_create(*a, **kw)

        run_state.create_run = swap_then_create
        try:
            with ProcessSpy() as spy:
                with installer.verified_active_group(self.lock) as active:
                    envelope = test_command._test_verified(
                        self._context("distill", "test-swap"), "distill", self.lock, active)
        finally:
            run_state.create_run = original_create
        self.assertNotEqual(envelope.status, "ok")
        self.assertStartsNoProcess(spy)
        self.assertFalse(stubs["distill"].ran, "no engine may run after a post-verification swap")
        self.assertNoWeakening(before, pointer_may_change=True)

    # --- 9 -----------------------------------------------------------------
    def test_test_generation_tamper_after_qualification_runs_no_engine(self):
        from cathedral_node import state as run_state
        from cathedral_node.commands import test as test_command
        stubs = self._stub("distill")
        before = self.weakening_snapshot()
        original_create = run_state.create_run

        def tamper_then_create(*a, **kw):
            self._tamper_generation()
            return original_create(*a, **kw)

        run_state.create_run = tamper_then_create
        try:
            with ProcessSpy() as spy:
                with installer.verified_active_group(self.lock) as active:
                    envelope = test_command._test_verified(
                        self._context("distill", "test-tamper"), "distill", self.lock, active)
        finally:
            run_state.create_run = original_create
        self.assertNotEqual(envelope.status, "ok")
        self.assertStartsNoProcess(spy)
        self.assertFalse(stubs["distill"].ran)
        self.assertNoWeakening(before)

    # --- 10 ----------------------------------------------------------------
    def test_status_verifies_one_group_and_never_mixes_role_generations(self):
        calls: list = []
        original = installer.verify_group_pointer

        def counting(*a, **kw):
            calls.append(a[1] if len(a) > 1 else kw.get("expected_state"))
            return original(*a, **kw)

        installer.verify_group_pointer = counting
        try:
            states, group, reason = installer.install_states(self.lock)
        finally:
            installer.verify_group_pointer = original
        self.assertEqual(len(calls), 1, f"status must verify exactly once, not {len(calls)} times")
        self.assertEqual(reason, "ok")
        versions = {s.release_version for s in states.values()}
        self.assertEqual(len(versions), 1, "roles reported different release versions")
        self.assertEqual(group.generations(), self.pointer_doc()["generations"])
        # And a pointer that mixes one role's generation with another's is refused
        # outright rather than reported as a working, mixed node.
        self._swap_pointer_to_other_generation()
        self.assertRejected("mixed role/generation pointer")

    # --- 11 ----------------------------------------------------------------
    def test_shared_runtime_guard_blocks_concurrent_activation_until_process_exit(self):
        outcome: dict = {}

        def try_exclusive():
            try:
                with installer.lifecycle_lock(exclusive=True, timeout=0.3):
                    outcome["result"] = "acquired"
            except installer.InstallError as exc:
                outcome["result"] = f"blocked: {exc}"

        with installer.verified_active_group(self.lock) as active:
            self.assertIsInstance(active.group, VerifiedActiveGroup)
            worker = threading.Thread(target=try_exclusive)
            worker.start()
            worker.join(10)
        self.assertIn("blocked", outcome["result"],
                      "an activation must not proceed while a runtime lease is held")
        outcome.clear()
        worker = threading.Thread(target=try_exclusive)
        worker.start()
        worker.join(10)
        self.assertEqual(outcome["result"], "acquired",
                         "the lock must be free once the lease is released")

    # --- 12 ----------------------------------------------------------------
    def test_supervisor_receives_verified_group_not_generation_ids(self):
        received: dict = {}

        class Recording:
            def running_roles(self):
                return sorted(_RUNNING)

            def stop(self, roles):
                received["stopped"] = list(roles)
                _RUNNING.difference_update(roles)

            def start(self, group, roles):
                received["group"] = group
                received["roles"] = list(roles)
                _RUNNING.update(roles)

            def readiness(self, roles):
                return True, "ok"

        class LegacySupervisor(Recording):
            def start(self, generations):  # the old, unsafe signature
                received["legacy"] = generations

        original_running = installer.run_state.running_run
        _RUNNING.clear()
        _RUNNING.add("distill")
        installer.run_state.running_run = _patched_running_run
        try:
            ok, detail, _ = self.install(
                self.fx.make_bundle(self._root / f"sup-{next(_COUNTER)}", 2),
                supervisor=Recording())
            self.assertTrue(ok, detail)
            group = received.get("group")
            self.assertIsInstance(group, VerifiedActiveGroup,
                                  "the supervisor must receive a sealed verified group")
            self.assertEqual(received["roles"], ["distill"])
            self.assertEqual(group.generations(), self.pointer_doc()["generations"])
            # A supervisor that only accepts generation identifiers can no longer be
            # driven at all: the activation fails closed instead of starting bytes
            # nothing verified.
            ok2, detail2, _ = self.install(
                self.fx.make_bundle(self._root / f"sup-legacy-{next(_COUNTER)}", 3),
                supervisor=LegacySupervisor())
            self.assertNoSuccessfulNoOp(ok2, detail2)
            self.assertNotIn("legacy", received)
        finally:
            installer.run_state.running_run = original_running
            _RUNNING.clear()
            type(self)._build_node()

    # --- 38 ----------------------------------------------------------------
    def test_runtime_executes_only_paths_from_the_verified_group_snapshot(self):
        from cathedral_node import engines as engines_module
        from cathedral_node.engines.base import UnverifiedEngine
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        bound = engines_module.load("validator", self.lock, group)
        role = group.role("validator")
        self.assertEqual(bound.python(), role.python)
        self.assertTrue(str(bound.python()).startswith(str(role.venv_dir)))
        with self.assertRaises(ValueError):
            role.bin("evil")           # not an entrypoint the signed release authorizes
        with self.assertRaises(ValueError):
            role.bin("../../bin/sh")   # not a single component
        unbound = engines_module.load("validator", self.lock)
        with self.assertRaises(UnverifiedEngine):
            unbound.python()
        with self.assertRaises(UnverifiedEngine):
            unbound.bin("pv-server")
        self.assertFalse(unbound.has_bin("pv-server"),
                         "an unbound adapter must report nothing runnable, not fall back")


# ==============================================================================
# the active-group tamper matrices (Revision 5 section 8)
# ==============================================================================

class TestActiveGroupTamper(SharedNodeCase):
    """Every launch-relevant field of the active state — pointer, retained signed
    release, receipts, and the managed filesystem — is cross-bound and re-verified.
    Two releases are installed so cross-release and prior-pointer attacks have real
    material to work with."""

    VERSIONS = (1, 2)

    def test_baseline_group_verifies(self):
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        self.assertEqual(set(group.roles), set(ROLES))
        self.assertEqual(group.release_version, 2)

    def test_pointer_field_tampers(self):
        import copy
        document = self.pointer_doc()
        cases = {
            "release_version_bump": ("release_version", document["release_version"] + 5),
            "release_version_zero": ("release_version", 0),
            "release_version_string": ("release_version", "2"),
            "release_version_bool": ("release_version", True),
            "lock_digest": ("lock_digest", "0" * 64),
            "lock_digest_uppercase": ("lock_digest", document["lock_digest"].upper()),
            "lock_digest_short": ("lock_digest", "0" * 63),
            "signature_digest": ("signature_digest", "0" * 64),
            "identity": ("identity", "attacker@evil"),
            "state_pending": ("state", "pending"),
            "state_unknown": ("state", "surprise"),
            "schema": ("schema", "cathedral.node.active_release.v99"),
            "timestamp_naive": ("at", "2026-07-31T00:00:00"),
            "timestamp_garbage": ("at", "yesterday"),
        }
        for label, (field, value) in cases.items():
            with self.subTest(field=label):
                self.write_pointer({**copy.deepcopy(document), field: value})
                self.assertRejected(f"pointer.{label}")
        with self.subTest(field="allowed_signers_ignored"):
            # The trust root comes from config, so a malicious pointer.allowed_signers
            # is IGNORED — it must not redirect trust, and verification still succeeds.
            self.write_pointer({**copy.deepcopy(document), "allowed_signers": "/etc/passwd"})
            ok, reason, _ = self.verify_active()
            self.assertTrue(ok, f"a malicious pointer.allowed_signers must be ignored: {reason}")
        with self.subTest(field="unknown_key"):
            self.write_pointer({**document, "surprise": 1})
            self.assertRejected("pointer unknown key")
        with self.subTest(field="missing_key"):
            self.write_pointer({k: v for k, v in document.items() if k != "at"})
            self.assertRejected("pointer missing key")
        with self.subTest(field="role_map_swap"):
            generations = dict(document["generations"])
            generations["distill"], generations["compute"] = (
                generations["compute"], generations["distill"])
            self.write_pointer({**document, "generations": generations})
            self.assertRejected("pointer role/generation swap")
        with self.subTest(field="missing_role"):
            generations = {k: v for k, v in document["generations"].items() if k != "compute"}
            self.write_pointer({**document, "generations": generations})
            self.assertRejected("pointer missing a role")
        with self.subTest(field="extra_role"):
            generations = {**document["generations"], "mystery": document["generations"]["compute"]}
            self.write_pointer({**document, "generations": generations})
            self.assertRejected("pointer extra role")
        with self.subTest(field="duplicate_generation"):
            generations = dict(document["generations"])
            generations["compute"] = generations["distill"]
            self.write_pointer({**document, "generations": generations})
            self.assertRejected("pointer duplicate generation id")
        with self.subTest(field="generation_traversal"):
            generations = {**document["generations"], "distill": "../../../etc"}
            self.write_pointer({**document, "generations": generations})
            self.assertRejected("pointer generation traversal")
        with self.subTest(field="generation_id_shape"):
            generations = {**document["generations"], "distill": "gen-not-a-real-id"}
            self.write_pointer({**document, "generations": generations})
            self.assertRejected("pointer malformed generation id")
        with self.subTest(field="unreadable"):
            paths.active_release_pointer().write_text("{not json")
            self.assertRejected("unreadable pointer")

    def test_a_symlinked_pointer_is_refused(self):
        pointer = paths.active_release_pointer()
        saved = pointer.read_bytes()
        target = self.home / "decoy-pointer.json"
        target.write_bytes(saved)
        pointer.unlink()
        os.symlink(target, pointer)
        try:
            self.assertRejected("symlinked pointer")
        finally:
            pointer.unlink()
            pointer.write_bytes(saved)

    def test_prior_pointer_tampers(self):
        """`prior` is a full committed pointer document and is parsed just as
        strictly, so a forged prior cannot even be read."""
        import copy
        document = self.pointer_doc()
        real_prior = document["prior"]
        self.assertIsInstance(real_prior, dict,
                              "the second install must retain the prior committed group")
        prior = copy.deepcopy(real_prior)
        for label, forged in {
            "not_a_document": "prior",
            "unknown_key": {**prior, "surprise": 1},
            "missing_key": {k: v for k, v in prior.items() if k != "at"},
            "pending_state": {**prior, "state": "pending"},
            "nested_prior": {**prior, "prior": prior},
            "bad_generations": {**prior, "generations": {"distill": "../etc"}},
        }.items():
            with self.subTest(prior=label):
                self.write_pointer({**document, "prior": forged})
                self.assertRejected(f"prior.{label}")

    def test_retained_manifest_and_signature_tampers(self):
        digest = self.pointer_doc()["lock_digest"]
        keep = paths.retained_releases_dir() / digest
        manifest, signature = keep / "release.json", keep / "release.json.sig"
        original_manifest, original_signature = manifest.read_bytes(), signature.read_bytes()
        other = next(p for p in paths.retained_releases_dir().iterdir() if p.name != digest)
        try:
            with self.subTest(target="manifest_changed"):
                manifest.write_bytes(original_manifest + b" ")
                self.assertRejected("retained manifest tamper")
                manifest.write_bytes(original_manifest)
            with self.subTest(target="signature_changed"):
                signature.write_bytes(original_signature[:-8])
                self.assertRejected("retained signature tamper")
                signature.write_bytes(original_signature)
            with self.subTest(target="manifest_missing"):
                manifest.unlink()
                self.assertRejected("retained manifest missing")
                manifest.write_bytes(original_manifest)
            with self.subTest(target="cross_digest"):
                # The OTHER release's signed bytes, filed under this release's digest.
                manifest.write_bytes((other / "release.json").read_bytes())
                signature.write_bytes((other / "release.json.sig").read_bytes())
                self.assertRejected("cross-digest retained release")
                manifest.write_bytes(original_manifest)
                signature.write_bytes(original_signature)
            with self.subTest(target="cross_signed"):
                forged = self.fx.make_bundle(self._root / f"crosssign-{next(_COUNTER)}", 2,
                                             key=self.fx.foreign_key())
                manifest.write_bytes((forged / "release.json").read_bytes())
                signature.write_bytes((forged / "release.json.sig").read_bytes())
                self.assertRejected("cross-signed retained release")
                manifest.write_bytes(original_manifest)
                signature.write_bytes(original_signature)
            with self.subTest(target="manifest_symlink"):
                manifest.unlink()
                os.symlink("/etc/hosts", manifest)
                self.assertRejected("retained manifest symlink")
                manifest.unlink()
                manifest.write_bytes(original_manifest)
        finally:
            manifest.write_bytes(original_manifest)
            signature.write_bytes(original_signature)

    def test_a_trust_root_that_does_not_authorize_the_release_identity_is_refused(self):
        foreign = self.home / "foreign_signers"
        foreign.write_text("someone@else ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")
        os.chmod(foreign, 0o600)
        ok, reason, group = installer.verify_active_group(self.lock, foreign)
        self.assertFalse(ok)
        self.assertIsNone(group)
        self.assertIn("authorize", reason)

    def test_missing_or_corrupt_floor_fails_closed(self):
        floor = paths.release_floor()
        original = floor.read_bytes()
        try:
            with self.subTest(state="corrupt"):
                floor.write_text("not json")
                self.assertRejected("corrupt floor")
            with self.subTest(state="missing"):
                floor.unlink()
                self.assertRejected("missing floor after activation")
            with self.subTest(state="symlink"):
                decoy = self.home / "decoy-floor.json"
                decoy.write_bytes(original)
                os.symlink(decoy, floor)
                self.assertRejected("symlinked floor")
                floor.unlink()
            with self.subTest(state="group_writable"):
                floor.write_bytes(original)
                os.chmod(floor, 0o666)
                self.assertRejected("group/world-writable floor")
        finally:
            if floor.is_symlink():
                floor.unlink()
            floor.write_bytes(original)
            os.chmod(floor, 0o600)

    def test_filesystem_mutation_matrix(self):
        """Changed, deleted, extra, mode-changed, symlinked, interpreter-swapped,
        bytecode-planted and ancestor-symlinked managed files each fail closed."""
        generation = self.generation_dir("validator")
        package = next(generation.rglob("pvpkg"))
        module = package / "cli.py"
        site_packages = package.parent
        bindir = generation / "venv" / "bin"
        # Directory modes are measured; unlock them once, restored automatically.
        self.unlock_dir(package)
        self.unlock_dir(site_packages)
        self.unlock_dir(bindir)
        self.unlock_dir(generation)

        with self.subTest(mutation="changed"):
            self.protect(module)
            os.chmod(module, 0o644)
            module.write_text(module.read_text() + "\n# tampered\n")
            self.assertRejected("changed managed file")
            os.chmod(module, 0o444)

        with self.subTest(mutation="deleted"):
            saved = module.read_bytes()
            module.unlink()
            self.assertRejected("deleted managed file")
            module.write_bytes(saved)
            os.chmod(module, 0o444)

        with self.subTest(mutation="extra"):
            planted = package / "extra.py"
            planted.write_text("# unsigned\n")
            self.assertRejected("extra managed file")
            planted.unlink()

        with self.subTest(mutation="installed_package_outside_the_closure"):
            intruder = site_packages / "smuggled"
            intruder.mkdir()
            (intruder / "__init__.py").write_text("")
            self.assertRejected("package installed outside the signed closure")
            shutil.rmtree(intruder)

        with self.subTest(mutation="mode_changed"):
            before = module.stat().st_mode & 0o7777
            os.chmod(module, 0o666)
            self.assertRejected("mode-changed managed file")
            os.chmod(module, before)

        with self.subTest(mutation="symlinked"):
            saved = module.read_bytes()
            module.unlink()
            os.symlink("/etc/hosts", module)
            self.assertRejected("symlinked managed file")
            module.unlink()
            module.write_bytes(saved)
            os.chmod(module, 0o444)

        with self.subTest(mutation="bytecode_planted"):
            cache = package / "__pycache__"
            cache.mkdir(exist_ok=True)
            (cache / "cli.cpython-311.pyc").write_bytes(b"poison")
            self.assertRejected("planted bytecode")
            shutil.rmtree(cache)

        with self.subTest(mutation="interpreter_swapped"):
            interpreter = bindir / "python"
            saved = interpreter.read_bytes()
            mode = interpreter.stat().st_mode & 0o7777
            os.chmod(interpreter, 0o755)
            interpreter.write_bytes(b"#!/bin/sh\nexec /bin/true\n")
            self.assertRejected("swapped interpreter")
            interpreter.write_bytes(saved)
            os.chmod(interpreter, mode)

        with self.subTest(mutation="interpreter_symlinked"):
            interpreter = bindir / "python"
            # Move the real interpreter aside rather than deleting it: the receipt
            # binds its inode, and a recreated file would leave the baseline
            # legitimately unverifiable for reasons this subtest is not about.
            stashed = bindir / "python.stashed"
            os.rename(interpreter, stashed)
            os.symlink("/usr/bin/true", interpreter)
            try:
                self.assertRejected("symlinked interpreter")
            finally:
                interpreter.unlink()
                os.rename(stashed, interpreter)

        with self.subTest(mutation="receipt_symlinked"):
            receipt = generation / "receipt.json"
            saved = receipt.read_bytes()
            mode = receipt.stat().st_mode & 0o7777
            receipt.unlink()
            os.symlink("/etc/hosts", receipt)
            self.assertRejected("symlinked receipt")
            receipt.unlink()
            receipt.write_bytes(saved)
            os.chmod(receipt, mode)

        with self.subTest(mutation="ancestor_symlinked"):
            generations = paths.engine_generations_dir("validator")
            moved = generations.parent / "generations.moved"
            generations.rename(moved)
            os.symlink(moved, generations)
            try:
                self.assertRejected("symlinked managed ancestor")
            finally:
                generations.unlink()
                moved.rename(generations)

    def test_a_group_writable_generation_or_receipt_is_refused(self):
        generation = self.generation_dir("compute")
        receipt = generation / "receipt.json"
        original_receipt_mode = receipt.stat().st_mode & 0o7777
        original_dir_mode = generation.stat().st_mode & 0o7777
        try:
            with self.subTest(target="receipt"):
                os.chmod(receipt, 0o646)
                self.assertRejected("group/world-writable receipt")
                os.chmod(receipt, original_receipt_mode)
            with self.subTest(target="generation_dir"):
                os.chmod(generation, 0o777)
                self.assertRejected("group/world-writable generation directory")
        finally:
            os.chmod(generation, original_dir_mode)
            os.chmod(receipt, original_receipt_mode)

    def test_cross_role_receipt_swap(self):
        pointer = self.pointer_doc()
        distill = self.receipt_path("distill", pointer)
        compute = self.receipt_path("compute", pointer)
        a, b = distill.read_text(), compute.read_text()
        try:
            self.write_receipt(distill, json.loads(b))
            self.write_receipt(compute, json.loads(a))
            self.assertRejected("cross-role receipt swap")
        finally:
            self.write_receipt(distill, json.loads(a))
            self.write_receipt(compute, json.loads(b))

    def test_cross_release_generation_selection_is_refused(self):
        """The prior release's generations are still on disk. Pointing the committed
        pointer at them, at the current release's version and digest, is refused by
        the receipt cross-binding."""
        document = self.pointer_doc()
        older = {}
        for role in ROLES:
            root = paths.engine_generations_dir(role)
            candidates = [p.name for p in root.iterdir() if p.name != document["generations"][role]]
            self.assertTrue(candidates, f"the prior {role} generation should be retained")
            older[role] = candidates[0]
        self.write_pointer({**document, "generations": older})
        self.assertRejected("cross-release generation selection")

    def test_a_no_op_reapply_over_a_tampered_generation_does_not_falsely_succeed(self):
        module = next(p for p in (self.generation_dir("validator") / "venv").rglob("*.py")
                      if "pvpkg" in str(p))
        self.protect(module)
        os.chmod(module, 0o644)
        module.write_text(module.read_text() + "\n# tampered\n")
        self.assertFalse(installer.state(self.lock.pin("validator")).installed,
                         "state must report the tampered generation as not installed")
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, detail, _ = self.install(self.bundles[2])
        # Re-applying the byte-identical signed release must NOT be laundered into a
        # successful no-op over a tamper, and must not quietly rebuild over it either.
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("does not verify", detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)

    def test_a_valid_no_op_reapply_is_idempotent_and_reverifies(self):
        before = self.weakening_snapshot()
        calls: list = []
        original = installer.verify_group_pointer

        def counting(*a, **kw):
            calls.append(a[1] if len(a) > 1 else kw.get("expected_state"))
            return original(*a, **kw)

        installer.verify_group_pointer = counting
        try:
            ok, detail, result = self.install(self.bundles[2])
        finally:
            installer.verify_group_pointer = original
        self.assertTrue(ok, detail)
        self.assertIn("already active", detail)
        self.assertIn(installer.GROUP_ACTIVE, calls, "a no-op must re-verify the whole active group")
        self.assertEqual(result["generations"], self.pointer_doc()["generations"])
        self.assertNoWeakening(before)


# ==============================================================================
# receipt binding (directive section 6; falsification tests 32-37)
# ==============================================================================

class TestReceiptBinding(SharedNodeCase):

    def _forge(self, role: str, **changes):
        path = self.receipt_path(role)
        original = json.loads(path.read_text())
        self.protect(path)
        self.write_receipt(path, {**original, **changes})
        return original

    def test_every_required_receipt_field_missing_individually_is_refused(self):
        path = self.receipt_path("validator")
        original = json.loads(path.read_text())
        try:
            for field in sorted(installer._RECEIPT_KEYS):
                with self.subTest(missing=field):
                    self.write_receipt(path, {k: v for k, v in original.items() if k != field})
                    self.assertRejected(f"receipt missing {field}")
        finally:
            self.write_receipt(path, original)

    def test_every_receipt_provenance_field_changed_individually_is_refused(self):
        path = self.receipt_path("validator")
        original = json.loads(path.read_text())
        forgeries = {
            "schema": "cathedral.node.engine_receipt.v4",
            "role": "compute",
            "generation": "gen-000000000000-0000000000000000",
            "repository": "https://github.com/cathedralai/other.git",
            "revision": "9" * 40,
            "distribution": "somethingelse",
            "version": "9.9.9",
            "parent_base_executable": "/usr/bin/python3",
            "parent_base_sha256": "0" * 64,
            "venv_python": "/usr/bin/python3",
            "venv_python_sha256": "0" * 64,
            "venv_python_stat": {"uid": 0, "gid": 0, "mode": 493, "device": 1, "inode": 1, "size": 1},
            "manifest_sha256": "0" * 64,
            "source_sha256": "0" * 64,
            "release_version": 999,
            "signer_identity": "attacker@evil",
            "lock_digest": "0" * 64,
            "extras": [],
            "entrypoints": ["evil"],
            "server_entrypoints": ["evil"],
            "launch_mode": "worker",
            "protocol": "9.9",
            "installed_at": "2026-07-31T00:00:00",
        }
        self.assertEqual(set(forgeries), installer._RECEIPT_KEYS,
                         "every receipt field must have a named forgery")
        try:
            for field, value in forgeries.items():
                with self.subTest(changed=field):
                    self.write_receipt(path, {**original, field: value})
                    self.assertRejected(f"receipt.{field}")
        finally:
            self.write_receipt(path, original)

    def test_an_unknown_receipt_field_is_refused(self):
        path = self.receipt_path("validator")
        original = json.loads(path.read_text())
        try:
            self.write_receipt(path, {**original, "surprise": 1})
            self.assertRejected("unknown receipt field")
        finally:
            self.write_receipt(path, original)

    # --- 34 ----------------------------------------------------------------
    def test_receipt_paths_types_and_timestamp_are_strict(self):
        path = self.receipt_path("compute")
        original = json.loads(path.read_text())
        cases = {
            "base_path_relative": {"parent_base_executable": "python3"},
            "base_path_symlinked_alias": {"parent_base_executable": str(Path("/tmp") / "python")},
            "venv_path_elsewhere": {"venv_python": str(self.home / "python")},
            "installed_at_naive": {"installed_at": "2026-07-31T00:00:00"},
            "installed_at_garbage": {"installed_at": "yesterday"},
            "installed_at_number": {"installed_at": 1},
            "release_version_string": {"release_version": "2"},
            "release_version_zero": {"release_version": 0},
            "release_version_bool": {"release_version": True},
            "extras_not_a_list": {"extras": "integration"},
            "entrypoints_wrong_type": {"entrypoints": [1]},
            "entrypoints_duplicated": {"entrypoints": ["pc-agent", "pc-agent"]},
            "digest_uppercase": {"manifest_sha256": original["manifest_sha256"].upper()},
            "digest_short": {"source_sha256": "0" * 63},
            "empty_string_field": {"protocol": ""},
        }
        try:
            for label, change in cases.items():
                with self.subTest(case=label):
                    self.write_receipt(path, {**original, **change})
                    self.assertRejected(f"receipt {label}")
        finally:
            self.write_receipt(path, original)

    # --- 35 ----------------------------------------------------------------
    def test_malformed_venv_python_stat_refuses_without_exception(self):
        path = self.receipt_path("compute")
        original = json.loads(path.read_text())
        stat_block = dict(original["venv_python_stat"])
        cases = {
            "missing_key": {k: v for k, v in stat_block.items() if k != "size"},
            "extra_key": {**stat_block, "surprise": 1},
            "string_value": {**stat_block, "uid": "root"},
            "negative_value": {**stat_block, "inode": -1},
            "bool_value": {**stat_block, "gid": True},
            "null_value": {**stat_block, "device": None},
            "not_a_mapping": ["uid", "gid"],
            "null_block": None,
            "nested_mapping": {**stat_block, "mode": {"deep": 1}},
        }
        try:
            for label, block in cases.items():
                with self.subTest(case=label):
                    self.write_receipt(path, {**original, "venv_python_stat": block})
                    try:
                        ok, reason, group = self.verify_active()
                    except Exception as exc:  # noqa: BLE001 - that is precisely the bug
                        self.fail(f"malformed nested receipt data raised {exc!r} instead of refusing")
                    self.assertFalse(ok, f"{label} was not refused")
                    self.assertIsNone(group)
                    self.assertTrue(reason)
        finally:
            self.write_receipt(path, original)

    # --- 32 ----------------------------------------------------------------
    def test_regular_interpreter_replacement_with_forged_receipt_fails(self):
        """The strongest available forgery: swap the interpreter for a different
        *regular executable*, then recompute every digest, the stat block and the
        whole-environment manifest so the receipt is internally consistent. It still
        fails, because `parent_base_sha256` is bound to the trusted parent this node
        actually has, not to anything in the generation."""
        generation = self.generation_dir("distill")
        interpreter = generation / "venv" / "bin" / "python"
        receipt_path = generation / "receipt.json"
        original_receipt = json.loads(receipt_path.read_text())
        saved = interpreter.read_bytes()
        mode = interpreter.stat().st_mode & 0o7777
        self.unlock_dir(interpreter.parent)
        try:
            os.chmod(interpreter, 0o755)
            interpreter.write_bytes(b"#!/bin/sh\nexec /usr/bin/true \"$@\"\n")
            os.chmod(interpreter, mode)
            forged_sha = installer._sha256_file(interpreter)
            forged = {**original_receipt,
                      "venv_python_sha256": forged_sha,
                      "parent_base_sha256": forged_sha,
                      "venv_python_stat": installer._stat_identity(interpreter)}
            ok, manifest_sha, why = installer._local_manifest(generation, self.lock.pin("distill"))
            self.assertTrue(ok, why)
            forged["manifest_sha256"] = manifest_sha
            self.write_receipt(receipt_path, forged)
            reason = self.assertRejected("forged interpreter with a recomputed receipt")
            self.assertIn("trusted", reason.lower())
        finally:
            os.chmod(interpreter, 0o755)
            interpreter.write_bytes(saved)
            os.chmod(interpreter, mode)
            self.write_receipt(receipt_path, original_receipt)

    # --- 33 ----------------------------------------------------------------
    def test_changed_source_with_recomputed_local_manifest_fails_signed_source_hash(self):
        generation = self.generation_dir("compute")
        archive = generation / "source" / "source.tar"
        receipt_path = generation / "receipt.json"
        original_receipt = json.loads(receipt_path.read_text())
        saved = archive.read_bytes()
        mode = archive.stat().st_mode & 0o7777
        self.unlock_dir(archive.parent)
        try:
            os.chmod(archive, 0o644)
            archive.write_bytes(b"substituted-provenance")
            os.chmod(archive, mode)
            ok, manifest_sha, why = installer._local_manifest(generation, self.lock.pin("compute"))
            self.assertTrue(ok, why)
            self.write_receipt(receipt_path, {**original_receipt, "manifest_sha256": manifest_sha})
            reason = self.assertRejected("changed source with a recomputed local manifest")
            self.assertIn("source", reason.lower())
        finally:
            os.chmod(archive, 0o644)
            archive.write_bytes(saved)
            os.chmod(archive, mode)
            self.write_receipt(receipt_path, original_receipt)

    # --- 37 ----------------------------------------------------------------
    def test_cached_success_does_not_survive_receipt_tree_or_signature_mutation(self):
        self.assertFalse(hasattr(installer, "_ACTIVE_CACHE"),
                         "a process-global active-verdict cache must not exist")
        self.assertFalse(hasattr(installer, "_verify_active_group_cached"))
        pin = self.lock.pin("validator")
        generation = self.generation_dir("validator")

        with self.subTest(mutation="receipt"):
            self.assertTrue(installer.state(pin).installed)
            receipt = generation / "receipt.json"
            original = json.loads(receipt.read_text())
            self.write_receipt(receipt, {**original, "protocol": "9.9"})
            self.assertFalse(installer.state(pin).installed)
            self.write_receipt(receipt, original)

        with self.subTest(mutation="tree"):
            self.assertTrue(installer.state(pin).installed)
            module = next(p for p in generation.rglob("*.py") if "pvpkg" in str(p))
            saved, mode = module.read_bytes(), module.stat().st_mode & 0o7777
            os.chmod(module, 0o644)
            module.write_text(module.read_text() + "\n# tampered\n")
            self.assertFalse(installer.state(pin).installed)
            module.write_bytes(saved)
            os.chmod(module, mode)

        with self.subTest(mutation="signature"):
            self.assertTrue(installer.state(pin).installed)
            signature = (paths.retained_releases_dir() / self.pointer_doc()["lock_digest"]
                         / "release.json.sig")
            saved = signature.read_bytes()
            signature.write_bytes(saved[:-8])
            self.assertFalse(installer.state(pin).installed)
            signature.write_bytes(saved)

        self.assertTrue(installer.state(pin).installed, "the baseline must still verify")


# ==============================================================================
# recovery and the replay floor (falsification tests 13-24)
# ==============================================================================

# The node's own view of which roles are running, so a test supervisor can model a
# real one: `stop` must actually make `running_run` stop reporting them, because the
# installer refuses to publish a pointer or delete files until it can prove that.
_RUNNING: set[str] = set()


def _patched_running_run(role):
    return {"pid": 999999, "run_id": "test", "since": "2026-07-31T00:00:00Z"}         if role in _RUNNING else None


class RecordingSupervisor:
    """A supervisor that behaves. ``stop`` terminates, and both the supervisor and
    the node's role state stop reporting the roles afterwards."""

    def __init__(self, ready=True):
        self.ready = ready
        self.started: list = []
        self.stopped: list = []

    def running_roles(self):
        return sorted(_RUNNING)

    def stop(self, roles):
        self.stopped.append(list(roles))
        _RUNNING.difference_update(roles)

    def start(self, group, roles):
        self.started.append((group, list(roles)))
        _RUNNING.update(roles)

    def readiness(self, roles):
        return self.ready, ("ok" if self.ready else "injected readiness failure")


class StubbornSupervisor(RecordingSupervisor):
    """A supervisor whose ``stop`` returns without the process group actually
    exiting — the case where believing ``stop`` would publish a pointer over live
    code and then delete the text that code is still executing."""

    def stop(self, roles):
        self.stopped.append(list(roles))  # returns, but nothing terminates


class TestRecoveryAndFloor(SharedNodeCase):
    """Two releases are installed, so pending/prior recovery has real material.

    The interesting crash states are reconstructed exactly: a pending pointer with
    the floor still at the prior release (the crash *before* the floor was raised),
    and a pending pointer the floor already names (the crash *after*).
    """

    VERSIONS = (1, 2)

    def _pending_before_floor_commit(self):
        """Pointer pending at v2, floor still at v1: the pre-commit crash."""
        document = self.pointer_doc()
        prior = document["prior"]
        self.assertIsInstance(prior, dict)
        self.write_pointer({**document, "state": "pending"})
        self.write_floor(prior["release_version"], prior["lock_digest"])
        return document, prior

    def _running(self, roles=ROLES):
        """Model ``roles`` as live processes this node believes it started."""
        original = installer.run_state.running_run
        _RUNNING.clear()
        _RUNNING.update(roles)
        installer.run_state.running_run = _patched_running_run

        def restore():
            installer.run_state.running_run = original
            _RUNNING.clear()
        self.addCleanup(restore)

    # --- 13 ----------------------------------------------------------------
    def test_invalid_nested_prior_is_neither_written_nor_started(self):
        document, prior = self._pending_before_floor_commit()
        forged = {**prior, "lock_digest": "b" * 64}   # a release that was never retained
        self.write_pointer({**document, "state": "pending", "prior": forged})
        # Break the pending group so recovery has to consider the prior at all.
        manifest = paths.retained_releases_dir() / document["lock_digest"] / "release.json"
        self.protect(manifest)
        manifest.write_bytes(b"{}")
        supervisor = RecordingSupervisor()
        self._running()
        with ProcessSpy() as spy:
            ok, detail = installer.recover(self.lock, supervisor=supervisor)
        self.assertFalse(ok, f"a forged prior must not be recoverable: {detail}")
        self.assertEqual(supervisor.started, [], "a forged prior must start no process")
        self.assertStartsNoProcess(spy)
        self.assertEqual(self.pointer_doc()["lock_digest"], document["lock_digest"],
                         "the forged prior must not have been written")
        self.assertEqual(self.floor_doc()["release_version"], prior["release_version"])

    # --- 14 ----------------------------------------------------------------
    def test_valid_prior_is_independently_verified_before_restart(self):
        self.rebuild_after()
        document, prior = self._pending_before_floor_commit()
        installer._force_rmtree(paths.retained_releases_dir() / document["lock_digest"])
        supervisor = RecordingSupervisor()
        self._running()
        ok, detail = installer.recover(self.lock, supervisor=supervisor)
        self.assertTrue(ok, detail)
        restored = self.pointer_doc()
        self.assertEqual(restored["lock_digest"], prior["lock_digest"])
        self.assertEqual(restored["generations"], prior["generations"])
        self.assertEqual(len(supervisor.started), 1)
        group, roles = supervisor.started[0]
        self.assertIsInstance(group, VerifiedActiveGroup,
                              "the prior must be verified before it is started")
        self.assertEqual(group.generations(), prior["generations"])
        self.assertEqual(sorted(roles), sorted(ROLES))

    # --- 15 ----------------------------------------------------------------
    def test_recovery_pending_and_prior_cannot_mix_generations(self):
        self.rebuild_after()
        document, prior = self._pending_before_floor_commit()
        mixed = dict(document["generations"])
        mixed["compute"] = prior["generations"]["compute"]   # one role from the other release
        self.write_pointer({**document, "state": "pending", "generations": mixed})
        supervisor = RecordingSupervisor()
        self._running()
        ok, detail = installer.recover(self.lock, supervisor=supervisor)
        self.assertTrue(ok, detail)
        restored = self.pointer_doc()
        self.assertEqual(restored["generations"], prior["generations"],
                         "recovery must restore one whole group, never a mixture")
        self.assertEqual(restored["lock_digest"], prior["lock_digest"])
        for group, _roles in supervisor.started:
            self.assertEqual(group.generations(), prior["generations"])

    # --- 16 ----------------------------------------------------------------
    def test_floor_raised_pending_never_rolls_back_below_floor(self):
        document = self.pointer_doc()
        self.write_pointer({**document, "state": "pending"})   # floor already names v2
        module = next(p for p in (self.generation_dir("validator", document) / "venv").rglob("*.py")
                      if "pvpkg" in str(p))
        saved, mode = module.read_bytes(), module.stat().st_mode & 0o7777
        os.chmod(module, 0o644)
        module.write_text(module.read_text() + "\n# tampered\n")
        supervisor = RecordingSupervisor()
        try:
            with ProcessSpy() as spy:
                ok, detail = installer.recover(self.lock, supervisor=supervisor)
        finally:
            module.write_bytes(saved)
            os.chmod(module, mode)
        self.assertFalse(ok, "recovery must stop rather than roll back below the floor")
        self.assertIn("floor", detail)
        self.assertEqual(supervisor.started, [])
        self.assertStartsNoProcess(spy)
        self.assertEqual(self.pointer_doc()["state"], "pending",
                         "the pointer must be left for operator repair, not weakened")
        self.assertEqual(self.floor_doc()["lock_digest"], document["lock_digest"])

    def test_offline_rollback_appends_an_auditable_authorization_record(self):
        """Revision 5 keeps the rollback authorization ledger separate from the
        external release floor. A restoration and a refusal both leave a record."""
        self.rebuild_after()
        ledger = paths.rollback_ledger()
        before = ledger.read_text().splitlines() if ledger.exists() else []
        document, prior = self._pending_before_floor_commit()

        # 1. a refusal is recorded, and nothing is restored.
        forged = {**prior, "lock_digest": "b" * 64}
        self.write_pointer({**document, "state": "pending", "prior": forged})
        manifest = paths.retained_releases_dir() / document["lock_digest"] / "release.json"
        self.protect(manifest)
        manifest.write_bytes(b"{}")
        installer.recover(self.lock)
        entries = [json.loads(line) for line in ledger.read_text().splitlines()[len(before):]]
        self.assertTrue(entries, "a refused rollback must still be auditable")
        refusal = entries[-1]
        self.assertEqual(refusal["outcome"], "refused")
        self.assertEqual(refusal["to_lock_digest"], "b" * 64)
        self.assertEqual(refusal["from_lock_digest"], document["lock_digest"])
        self.assertTrue(refusal["reason"])
        self.assertTrue(refusal["ts"])

        # 2. a real restoration records the EXACT prior digest and generation set.
        prefix = ledger.read_text().splitlines()
        seen = len(prefix)
        self._restore_mutable(self._baseline)
        self.doCleanups()
        self._pending_before_floor_commit()
        installer._force_rmtree(paths.retained_releases_dir() / document["lock_digest"])
        ok, detail = installer.recover(self.lock)
        self.assertTrue(ok, detail)
        entries = [json.loads(line) for line in ledger.read_text().splitlines()[seen:]]
        restored = entries[-1]
        self.assertEqual(restored["outcome"], "restored")
        self.assertEqual(restored["to_lock_digest"], prior["lock_digest"])
        self.assertEqual(restored["to_release_version"], prior["release_version"])
        self.assertEqual(restored["to_generations"], dict(sorted(prior["generations"].items())))
        # The ledger is append-only: every earlier line is byte-identical.
        self.assertEqual(ledger.read_text().splitlines()[:seen], prefix,
                         "the rollback ledger must be append-only")

    # --- 17 ----------------------------------------------------------------
    def test_supervisor_restart_failure_makes_recovery_fail(self):
        self.rebuild_after()
        document, prior = self._pending_before_floor_commit()
        supervisor = RecordingSupervisor(ready=False)
        self._running()
        ok, detail = installer.recover(self.lock, supervisor=supervisor)
        self.assertFalse(ok, f"a supervisor failure must propagate: {detail}")
        self.assertIn("readiness", detail.lower())
        self.assertLessEqual(self.floor_doc()["release_version"], document["release_version"])

    # --- 18 ----------------------------------------------------------------
    def test_update_refuses_an_existing_unverified_active_group(self):
        module = next(p for p in (self.generation_dir("validator") / "venv").rglob("*.py")
                      if "pvpkg" in str(p))
        self.protect(module)
        os.chmod(module, 0o644)
        module.write_text(module.read_text() + "\n# tampered\n")
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, detail, _ = self.install(
                self.fx.make_bundle(self._root / f"upd-{next(_COUNTER)}", 3))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("does not verify", detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)

    # --- 19 ----------------------------------------------------------------
    def test_floor_requires_exact_schema_types_and_hex_digest(self):
        floor = paths.release_floor()
        original = json.loads(floor.read_text())
        cases = {
            "missing_key": {k: v for k, v in original.items() if k != "identity"},
            "unknown_key": {**original, "surprise": 1},
            "wrong_schema": {**original, "schema": "cathedral.node.release_floor.v1"},
            "version_zero": {**original, "release_version": 0},
            "version_negative": {**original, "release_version": -1},
            "version_string": {**original, "release_version": "2"},
            "version_bool": {**original, "release_version": True},
            "version_float": {**original, "release_version": 2.0},
            "version_huge": {**original, "release_version": 2 ** 40},
            "digest_uppercase": {**original, "lock_digest": original["lock_digest"].upper()},
            "digest_short": {**original, "lock_digest": "0" * 63},
            "digest_nonhex": {**original, "lock_digest": "z" * 64},
            "digest_missing_type": {**original, "lock_digest": 1},
            "identity_wrong": {**original, "identity": "attacker@evil"},
            "committed_at_naive": {**original, "committed_at": "2026-07-31T00:00:00"},
            "committed_at_garbage": {**original, "committed_at": "recently"},
        }
        try:
            for label, document in cases.items():
                with self.subTest(case=label):
                    os.chmod(floor, 0o600)
                    floor.write_text(json.dumps(document))
                    ok, parsed, reason = installer._read_floor()
                    self.assertFalse(ok, f"floor {label} was accepted")
                    self.assertIsNone(parsed)
                    self.assertTrue(reason)
                    self.assertRejected(f"floor {label}")
        finally:
            os.chmod(floor, 0o600)
            floor.write_text(json.dumps(original, indent=2, sort_keys=True) + "\n")
            os.chmod(floor, 0o600)

    # --- 20 ----------------------------------------------------------------
    def test_same_version_different_digest_cannot_replace_floor(self):
        original = paths.release_floor().read_bytes()
        floor = json.loads(original)
        with self.subTest(case="same_version_different_digest"):
            with installer.lifecycle_lock(exclusive=True):
                with self.assertRaises(installer.InstallError) as caught:
                    installer._commit_floor(floor["release_version"], "c" * 64)
            self.assertIn("different release", str(caught.exception))
            self.assertEqual(paths.release_floor().read_bytes(), original,
                             "a refused floor write must leave the evidence untouched")
        with self.subTest(case="lower_version"):
            with installer.lifecycle_lock(exclusive=True):
                with self.assertRaises(installer.InstallError):
                    installer._commit_floor(floor["release_version"] - 1, floor["lock_digest"])
            self.assertEqual(paths.release_floor().read_bytes(), original)
        with self.subTest(case="idempotent"):
            with installer.lifecycle_lock(exclusive=True):
                installer._commit_floor(floor["release_version"], floor["lock_digest"])
            self.assertEqual(paths.release_floor().read_bytes(), original,
                             "an identical release must be idempotent, not a rewrite")
        with self.subTest(case="corrupt_is_never_repaired_by_overwrite"):
            os.chmod(paths.release_floor(), 0o600)
            paths.release_floor().write_text("not json")
            with installer.lifecycle_lock(exclusive=True):
                with self.assertRaises(installer.InstallError):
                    installer._commit_floor(floor["release_version"] + 1, "d" * 64)
            self.assertEqual(paths.release_floor().read_text(), "not json")
            os.chmod(paths.release_floor(), 0o600)
            paths.release_floor().write_bytes(original)
            os.chmod(paths.release_floor(), 0o600)

    # --- 21 ----------------------------------------------------------------
    def test_active_pointer_must_exactly_equal_floor(self):
        floor = json.loads(paths.release_floor().read_text())
        with self.subTest(case="floor_ahead"):
            self.write_floor(floor["release_version"] + 1, floor["lock_digest"])
            reason = self.assertRejected("floor ahead of the committed pointer")
            self.assertIn("floor", reason)
        with self.subTest(case="floor_digest_differs"):
            self.write_floor(floor["release_version"], "e" * 64)
            self.assertRejected("floor digest differs from the committed pointer")
        with self.subTest(case="floor_behind"):
            self.write_floor(max(1, floor["release_version"] - 1), floor["lock_digest"])
            self.assertRejected("floor behind the committed pointer")

    # --- 22 ----------------------------------------------------------------
    def test_missing_pointer_and_floor_with_retained_state_is_not_fresh(self):
        paths.active_release_pointer().unlink()
        paths.release_floor().unlink()
        ok, floor, reason = installer._read_floor()
        self.assertFalse(ok, "a node with retained state and no floor is not fresh")
        self.assertIsNone(floor)
        for witness in ("marker", "journal", "retained", "generations"):
            self.assertTrue(reason)
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, detail, _ = self.install(
                self.fx.make_bundle(self._root / f"notfresh-{next(_COUNTER)}", 1))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)

    # --- 23 ----------------------------------------------------------------
    def test_crash_matrix_pending_floor_active_preserves_monotonicity(self):
        document = self.pointer_doc()
        prior = document["prior"]
        target = (document["release_version"], document["lock_digest"])

        with self.subTest(crash="pending_written_floor_not_raised"):
            self._pending_before_floor_commit()
            ok, detail = installer.recover(self.lock)
            self.assertTrue(ok, detail)
            after = self.pointer_doc()
            self.assertEqual(after["state"], "active")
            self.assertEqual((after["release_version"], after["lock_digest"]), target)
            self.assertEqual((self.floor_doc()["release_version"],
                              self.floor_doc()["lock_digest"]), target)

        with self.subTest(crash="floor_raised_pointer_still_pending"):
            self.write_pointer({**document, "state": "pending"})
            self.write_floor(*target)
            ok, detail = installer.recover(self.lock)
            self.assertTrue(ok, detail)
            after = self.pointer_doc()
            self.assertEqual(after["state"], "active")
            self.assertEqual((self.floor_doc()["release_version"],
                              self.floor_doc()["lock_digest"]), target)

        with self.subTest(crash="already_committed"):
            self.write_pointer(document)
            self.write_floor(*target)
            ok, detail = installer.recover(self.lock)
            self.assertTrue(ok, detail)
            self.assertEqual(detail, "nothing to recover")
            self.assertEqual(self.pointer_doc()["state"], "active")

        with self.subTest(crash="floor_never_goes_below_the_prior"):
            self.assertGreaterEqual(self.floor_doc()["release_version"],
                                    prior["release_version"])

    # --- 24 ----------------------------------------------------------------
    def test_parallel_update_and_recover_leave_one_consistent_floor_and_pointer(self):
        self.rebuild_after()
        self._pending_before_floor_commit()
        candidate = self.fx.make_bundle(self._root / f"par-{next(_COUNTER)}", 3)
        results: dict = {}
        barrier = threading.Barrier(2, timeout=30)

        def do_recover():
            barrier.wait()
            results["recover"] = installer.recover(self.lock)

        def do_update():
            barrier.wait()
            ok, detail, _ = installer.install_release(candidate, self.lock, self.fx.signers,
                                                      identity=IDENTITY)
            results["update"] = (ok, detail)

        threads = [threading.Thread(target=do_recover), threading.Thread(target=do_update)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(600)
        self.assertIn("recover", results)
        self.assertIn("update", results)
        pointer = self.pointer_doc()
        floor = self.floor_doc()
        self.assertEqual(pointer["state"], "active",
                         f"the node must settle on one committed state: {results}")
        self.assertEqual((pointer["release_version"], pointer["lock_digest"]),
                         (floor["release_version"], floor["lock_digest"]),
                         "the committed pointer and the floor must agree exactly")
        ok, reason, _ = self.verify_active()
        self.assertTrue(ok, f"the settled state must verify: {reason}")


# ==============================================================================
# acquisition expiry and signed revocation (falsification tests 25-31)
# ==============================================================================

class TestExpiryAndRevocation(Gate0Base):

    def _short_lived(self, name: str, version: int, seconds: int = 45):
        now = dt.datetime.now(dt.timezone.utc)
        return self.bundle(name, version,
                           created_at=(now - dt.timedelta(days=1)).isoformat(),
                           expires_at=(now + dt.timedelta(seconds=seconds)).isoformat())

    @staticmethod
    def _wait_until_expired(bundle: Path) -> None:
        expires = dt.datetime.fromisoformat(
            json.loads((bundle / "release.json").read_bytes())["expires_at"])
        while dt.datetime.now(dt.timezone.utc) < expires + dt.timedelta(milliseconds=250):
            import time as _time
            _time.sleep(0.2)

    # --- 25 ----------------------------------------------------------------
    def test_expired_installed_release_remains_valid_but_cannot_be_newly_activated(self):
        candidate = self.bundle("expiry")
        ok, detail, _ = self.install(candidate)
        self.assertTrue(ok, detail)
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=365)
        ok, reason, group = self.verify_active(now=future)
        self.assertTrue(ok, f"an installed release must not die on a timer: {reason}")
        self.assertIsInstance(group, VerifiedActiveGroup)
        # ... but the same bytes may not be newly acquired after the window closes.
        acquired, why, _ = self.verify(candidate, now=future)
        self.assertFalse(acquired, "an expired bundle must not be installable")
        self.assertIn("expired", why)

    # --- 26 ----------------------------------------------------------------
    def test_floor_committed_pending_recovers_after_manifest_expiry(self):
        candidate = self._short_lived("floorpending", 1)
        ok, detail, _ = self.install(candidate)
        self.assertTrue(ok, detail)
        document = self.pointer_doc()
        self.write_pointer({**document, "state": "pending"})   # floor already names it
        self._wait_until_expired(candidate)
        self.assertFalse(self.verify(candidate, now=dt.datetime.now(dt.timezone.utc))[0],
                         "the acquisition window must really have closed")
        ok, detail = installer.recover(self.lock)
        self.assertTrue(ok, f"a floor-committed pending release must still finish: {detail}")
        self.assertEqual(self.pointer_doc()["state"], "active")

    # --- 27 ----------------------------------------------------------------
    def test_uncommitted_expired_pending_restores_only_verified_prior(self):
        ok, detail, _ = self.install(self.bundle("priorlong", 1))
        self.assertTrue(ok, detail)
        prior_pointer = self.pointer_doc()
        candidate = self._short_lived("pendingshort", 2)
        ok, detail, _ = self.install(candidate)
        self.assertTrue(ok, detail)
        document = self.pointer_doc()
        # The realistic crash: pending written, floor not yet raised past the prior.
        self.write_pointer({**document, "state": "pending"})
        self.write_floor(prior_pointer["release_version"], prior_pointer["lock_digest"])
        self._wait_until_expired(candidate)
        supervisor = RecordingSupervisor()
        ok, detail = installer.recover(self.lock, supervisor=supervisor)
        self.assertTrue(ok, detail)
        restored = self.pointer_doc()
        self.assertEqual(restored["lock_digest"], prior_pointer["lock_digest"])
        self.assertEqual(restored["generations"], prior_pointer["generations"])
        ok, reason, _ = self.verify_active()
        self.assertTrue(ok, f"only an independently verified prior may be restored: {reason}")

    # --- 28 ----------------------------------------------------------------
    def test_install_requires_verified_cached_revocation_snapshot(self):
        cache = revocation.cache_file()
        with self.subTest(case="no_cache"):
            cache.unlink()
            revocation.floor_file().unlink(missing_ok=True)
            before = self.weakening_snapshot()
            with ProcessSpy() as spy:
                ok, detail, _ = self.install(self.bundle("norevoke"))
            self.assertNoSuccessfulNoOp(ok, detail)
            self.assertIn("revocation", detail)
            self.assertStartsNoProcess(spy)
            self.assertNoWeakening(before)
        with self.subTest(case="wrong_authority"):
            # Signed by the RELEASE key, not the offline revocation authority.
            raw, sig = self.fx.revocation_snapshot(1, key=self.fx.key)
            self.fx.plant_revocation_cache(raw, sig)
            with ProcessSpy() as spy:
                ok, detail, _ = self.install(self.bundle("wrongauth"))
            self.assertNoSuccessfulNoOp(ok, detail)
            self.assertIn("revocation", detail)
            self.assertStartsNoProcess(spy)

    # --- 29 ----------------------------------------------------------------
    def test_invalid_or_older_revocation_snapshot_preserves_last_good_cache(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw5, sig5 = self.fx.revocation_snapshot(5)
        ok, reason, state = revocation.retain(raw5, sig5, now=now)
        self.assertTrue(ok, reason)
        self.assertEqual(state.sequence, 5)
        cached = revocation.cache_file().read_bytes()

        with self.subTest(case="older_sequence"):
            raw3, sig3 = self.fx.revocation_snapshot(3)
            ok, reason, kept = revocation.retain(raw3, sig3, now=now)
            self.assertFalse(ok)
            self.assertEqual(kept.sequence, 5)
            self.assertEqual(revocation.cache_file().read_bytes(), cached)

        with self.subTest(case="corrupt_signature"):
            raw9, sig9 = self.fx.revocation_snapshot(9)
            ok, reason, kept = revocation.retain(raw9, sig9[:-8], now=now)
            self.assertFalse(ok)
            self.assertEqual(kept.sequence, 5)
            self.assertEqual(revocation.cache_file().read_bytes(), cached)

        with self.subTest(case="unknown_field"):
            raw, sig = self.fx.revocation_snapshot(
                9, mutate=lambda d: {**d, "surprise": 1})
            ok, _reason, kept = revocation.retain(raw, sig, now=now)
            self.assertFalse(ok)
            self.assertEqual(kept.sequence, 5)

        with self.subTest(case="same_sequence_different_content"):
            raw, sig = self.fx.revocation_snapshot(5, revoked_releases=["a" * 64])
            ok, _reason, kept = revocation.retain(raw, sig, now=now)
            self.assertFalse(ok)
            self.assertEqual(revocation.cache_file().read_bytes(), cached)

        with self.subTest(case="wrong_authority"):
            raw, sig = self.fx.revocation_snapshot(9, key=self.fx.key)
            ok, _reason, kept = revocation.retain(raw, sig, now=now)
            self.assertFalse(ok)
            self.assertEqual(kept.sequence, 5)

        with self.subTest(case="newer_is_accepted"):
            raw9, sig9 = self.fx.revocation_snapshot(9)
            ok, reason, kept = revocation.retain(raw9, sig9, now=now)
            self.assertTrue(ok, reason)
            self.assertEqual(kept.sequence, 9)

    # --- 30 ----------------------------------------------------------------
    def test_revoked_active_digest_blocks_restart_offline(self):
        ok, detail, _ = self.install(self.bundle("revoked"))
        self.assertTrue(ok, detail)
        digest = self.pointer_doc()["lock_digest"]
        self.assertTrue(installer.state(self.lock.pin("validator")).installed)
        before = self.weakening_snapshot()
        self.fx.install_revocation(self.home, sequence=2, revoked_releases=[digest])
        with ProcessSpy() as spy:
            ok, reason, group = self.verify_active()
            state = installer.state(self.lock.pin("validator"))
        self.assertFalse(ok, "a revoked active digest must block restart")
        self.assertIsNone(group)
        self.assertIn("revoked", reason)
        self.assertFalse(state.installed)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)

    def test_a_revoked_release_signer_blocks_restart_offline(self):
        ok, detail, _ = self.install(self.bundle("revokedsigner"))
        self.assertTrue(ok, detail)
        self.fx.install_revocation(self.home, sequence=2,
                                   revoked_signers=[self.fx.release_signer_fingerprint()])
        ok, reason, group = self.verify_active()
        self.assertFalse(ok)
        self.assertIsNone(group)
        self.assertIn("signer", reason)

    # --- 31 ----------------------------------------------------------------
    def test_channel_outage_uses_last_good_revocation_cache(self):
        now = dt.datetime.now(dt.timezone.utc)

        def unreachable(_url, _limit):
            raise OSError("channel down")

        ok, reason, state = revocation.refresh("https://releases.invalid", now=now, fetch=unreachable)
        self.assertTrue(ok, reason)
        self.assertIsNotNone(state, "the last known good snapshot must remain authoritative")
        self.assertIn("cache", reason)
        # And a network failure must not be reinterpreted as release-manifest expiry:
        # the install still proceeds on the retained snapshot.
        ok, detail, _ = installer.install_release(
            self.bundle("outage"), self.lock, self.fx.signers, identity=IDENTITY,
            revocation_channel="https://releases.invalid")
        self.assertTrue(ok, f"an outage must degrade to the retained snapshot: {detail}")
        self.assertNotIn("expired", detail,
                         "a network failure must not be reinterpreted as manifest expiry")

    def test_stale_revocation_knowledge_is_reported_explicitly(self):
        now = dt.datetime.now(dt.timezone.utc)
        self.fx.install_revocation(
            self.home, sequence=3,
            issued_at=(now - dt.timedelta(days=40)).isoformat(),
            expires_at=(now - dt.timedelta(days=1)).isoformat())
        report = revocation.status(now=now)
        self.assertTrue(report["available"])
        self.assertTrue(report["stale"], "an expired snapshot must be reported as stale")
        ok, reason, state = revocation.enforce("a" * 64, self.fx.signers.read_text(), IDENTITY,
                                               now=now, policy=revocation.RETAINED_RUNTIME)
        self.assertTrue(ok, reason)
        self.assertIn("stale", reason)
        # Offline rollback is the one operation that claims current global revocation
        # status, so it fails closed outside the freshness window.
        ok, reason, _ = revocation.enforce("a" * 64, self.fx.signers.read_text(), IDENTITY,
                                           now=now, policy=revocation.ROLLBACK)
        self.assertFalse(ok)
        self.assertIn("expired", reason)

    def test_offline_rollback_refuses_stale_revocation_state(self):
        ok, detail, _ = self.install(self.bundle("rbstale1", 1))
        self.assertTrue(ok, detail)
        prior_pointer = self.pointer_doc()
        ok, detail, _ = self.install(self.bundle("rbstale2", 2))
        self.assertTrue(ok, detail)
        document = self.pointer_doc()
        self.write_pointer({**document, "state": "pending"})
        self.write_floor(prior_pointer["release_version"], prior_pointer["lock_digest"])
        installer._force_rmtree(paths.retained_releases_dir() / document["lock_digest"])
        now = dt.datetime.now(dt.timezone.utc)
        self.fx.install_revocation(
            self.home, sequence=9,
            issued_at=(now - dt.timedelta(days=40)).isoformat(),
            expires_at=(now - dt.timedelta(days=1)).isoformat())
        supervisor = RecordingSupervisor()
        ok, detail = installer.recover(self.lock, supervisor=supervisor)
        self.assertFalse(ok, "rollback outside the revocation freshness window must fail closed")
        self.assertEqual(supervisor.started, [])
        self.assertIn("revocation", detail)


# ==============================================================================
# the real engine adapters, bound to a real verified generation
# ==============================================================================

class TestRealAdapterBinding(SharedNodeCase):
    """The repository's actual adapters, against a generation installed from stub
    wheels shaped exactly like `cathedral.lock.json` — same distributions, same
    entrypoints, same extras and launch modes.

    This is where "argv never contains a secret" is proven, because it is the only
    place the real adapters can legitimately resolve an executable path at all.
    """

    PLAN_FROM_LOCK = True

    def test_operate_argv_and_env_come_from_the_verified_generation_and_carry_no_secret(self):
        from cathedral_node import config as config_module
        from cathedral_node import engines as engines_module
        secret = "sk-should-never-appear-1234567890"
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        for role in ROLES:
            with self.subTest(role=role):
                cfg = dict(config_module.defaults(role))
                cfg.update({"hotkey": "5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX",
                            "api_key_secret": secret, "bearer_token_secret": secret})
                adapter = engines_module.load(role, self.lock, group)
                argv = adapter.operate_argv(cfg, dry_run=True)
                joined = " ".join(argv)
                self.assertNotIn(secret, joined, "a credential reached argv")
                verified = group.role(role)
                self.assertTrue(str(argv[0]).startswith(str(verified.venv_dir)),
                                f"{role} argv[0] {argv[0]!r} is outside the verified generation")
                self.assertNotIn(secret, " ".join(adapter.operate_env(cfg)),
                                 "a credential name leaked into an environment key")

    def test_every_adapter_binary_resolves_inside_its_own_verified_generation(self):
        from cathedral_node import engines as engines_module
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        for role in ROLES:
            with self.subTest(role=role):
                verified = group.role(role)
                adapter = engines_module.load(role, self.lock, group)
                pin = self.lock.pin(role)
                for name in (*pin.entrypoints, *pin.server_entrypoints, "python"):
                    resolved = adapter.bin(name)
                    self.assertEqual(resolved.parent.parent, verified.venv_dir)
                    self.assertTrue(resolved.is_file(), f"{role}:{name} is missing")
                # A role may never reach into another role's verified generation.
                for other in ROLES:
                    if other == role:
                        continue
                    self.assertNotEqual(verified.venv_dir, group.role(other).venv_dir)

    def test_the_validator_engine_config_comes_from_the_verified_source_tree(self):
        from cathedral_node import engines as engines_module
        from cathedral_node.engines.base import UnverifiedEngine
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        adapter = engines_module.load("validator", self.lock, group)
        self.assertEqual(adapter.source_dir(), group.role("validator").source_dir)
        unbound = engines_module.load("validator", self.lock)
        with self.assertRaises(UnverifiedEngine):
            unbound.source_dir()


# ==============================================================================
# a real supervisor: real processes, real ports, real process groups
# ==============================================================================

class LoopbackSupervisor:
    """A supervisor that actually starts the verified generation's server.

    The readiness matrix in Revision 5 — wrong endpoint, readiness timeout, hanging
    server, stale PID, process-group cleanup — cannot be proven by a stub that
    returns a boolean. This one launches the real entrypoint from the sealed
    ``VerifiedRole`` in its own session, probes a real loopback port for a real
    path, writes the node's own durable role lock so `running_run` sees what is
    actually running, and proves termination of the whole process **group** rather
    than of the one parent it happens to hold a handle to.

    ``mode`` selects how the server misbehaves; it travels in the child's
    environment, so every case uses the same signed distribution and the same
    lockfile pins. Varying the wheel instead would change what the *previous*
    release is authorized to be, and the test would then fail for a reason that has
    nothing to do with readiness.
    """

    def __init__(self, mode: str = "ready", ready_path: str = "/ready",
                 deadline: float = 5.0) -> None:
        self.mode = mode
        self.arm_once = False
        self.ready_path = ready_path
        self.deadline = deadline
        self.started: list = []
        self.ports: dict[str, int] = {}
        self._procs: dict[str, subprocess.Popen] = {}
        self._pgids: dict[str, int] = {}

    # ---- Supervisor protocol -------------------------------------------------
    def running_roles(self) -> list[str]:
        return [role for role, proc in self._procs.items() if proc.poll() is None]

    def start(self, group: VerifiedActiveGroup, roles: list[str]) -> None:
        self.started.append((group, list(roles)))
        # The failure mode belongs to the release being activated, not to the
        # supervisor forever. Leaving it armed made the *prior* group fail its
        # restart in exactly the same way, so a test that claimed to prove
        # restoration only ever proved a second failure.
        mode = self.mode
        if self.arm_once and mode != "ready":
            self.mode = "ready"
        for role in roles:
            verified = group.role(role)
            entrypoint = next((e for e in verified.entrypoints if e.endswith("-server")), None)
            if entrypoint is None:
                continue
            port = _free_port()
            self.ports[role] = port
            proc = subprocess.Popen(  # noqa: S603 - the path comes from the sealed group
                [str(verified.bin(entrypoint))],
                env={"PATH": "/usr/bin:/bin", "HOME": str(verified.generation_dir),
                     "TMPDIR": str(verified.generation_dir), "LC_ALL": "C", "LANG": "C",
                     "CATHEDRAL_TEST_PORT": str(port), "CATHEDRAL_TEST_MODE": mode},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            self._procs[role] = proc
            self._pgids[role] = os.getpgid(proc.pid)
            _write_role_lock(role, proc.pid)

    def readiness(self, roles: list[str]) -> tuple[bool, str]:
        import urllib.error
        import urllib.request
        for role in roles:
            port = self.ports.get(role)
            if port is None:
                continue
            deadline = time.monotonic() + self.deadline
            served = False
            while time.monotonic() < deadline:
                proc = self._procs.get(role)
                if proc is not None and proc.poll() is not None:
                    return False, f"{role} exited before it became ready"
                try:
                    with urllib.request.urlopen(  # noqa: S310 - loopback only
                            f"http://127.0.0.1:{port}{self.ready_path}", timeout=0.5) as response:
                        if response.status == 200:
                            served = True
                            break
                except urllib.error.HTTPError as exc:
                    return False, (f"{role} is serving, but {self.ready_path} answered {exc.code}: "
                                   f"it is not serving the endpoint this role must serve")
                except (urllib.error.URLError, OSError, TimeoutError):
                    time.sleep(0.1)
            if not served:
                return False, f"{role} did not answer {self.ready_path} within {self.deadline:.0f}s"
        return True, "ready"

    def stop(self, roles: list[str]) -> None:
        for role in list(roles):
            proc = self._procs.get(role)
            pgid = self._pgids.get(role)
            if proc is None:
                _clear_role_lock(role)
                continue
            if pgid is not None:
                with contextlib.suppress(OSError):
                    os.killpg(pgid, signal.SIGTERM)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and proc.poll() is None:
                time.sleep(0.05)
            if proc.poll() is None and pgid is not None:
                with contextlib.suppress(OSError):
                    os.killpg(pgid, signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=5)
            _clear_role_lock(role)
            self._procs.pop(role, None)
            self.ports.pop(role, None)

    def terminated(self, roles: list[str]) -> tuple[bool, str]:
        alive = [r for r in roles if self.group_members(r)]
        return (not alive), ("terminated" if not alive else f"{', '.join(alive)} is still alive")

    # ---- helpers -------------------------------------------------------------
    def group_members(self, role: str) -> list[int]:
        """Every live pid in the role's process group, asked the same way the
        product asks — including the zombie exclusion, so the test and the thing it
        tests agree on what "gone" means."""
        pgid = self._pgids.get(role)
        if pgid is None:
            return []
        from cathedral_node import state as run_state
        return run_state.process_group_members(pgid)

    def shutdown(self) -> None:
        self.stop(list(self._procs))


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _write_role_lock(role: str, pid: int) -> None:
    """Record durable ownership the way the product does.

    Writing the old shape here would have made `running_run` return None while the
    test believed a role was running — so the tests that turn on "a role is running"
    would have passed while proving nothing.
    """
    from cathedral_node import state as run_state
    try:
        pgid = os.getpgid(int(pid))
    except OSError:
        # The pid is already gone. `claim_child` records the child pid as the group
        # id in exactly this case, because every launcher starts a new session, so
        # the fixture records what production would have recorded.
        pgid = int(pid)
    run_state.write_ownership(run_state.ChildOwnership(
        role=role, run_id=f"sup-{role}", parent_pid=os.getpid(), child_pid=int(pid),
        pgid=pgid, start_identity=run_state.process_start_identity(int(pid)) or "",
        boot_id=run_state.boot_identity(), euid=os.geteuid(), generation="", lock_digest="",
        token="test", since="2026-07-31T00:00:00Z",
        spawn_state=run_state.SPAWN_OWNED))


def _clear_role_lock(role: str) -> None:
    with contextlib.suppress(OSError):
        paths.role_lock(role).unlink()


class ReadinessCase(Gate0Base):
    """A node whose distill role is a real, mode-driven server."""

    def serving_plan(self) -> dict:
        plan = self.fx.role_plan()
        plan["distill"].update(dist="pserv", wheels=[self.fx.w["pserv"]],
                               roots={"pserv": "pservpkg"})
        self.set_lock(plan)
        return plan

    def install_serving(self, name: str, version: int, plan: dict, supervisor=None):
        return self.install(self.bundle(name, version, plan=plan), supervisor=supervisor)


class TestReadinessAndLiveness(ReadinessCase):
    """Every named readiness case, against processes that really run.

    Each case installs a healthy release, starts the role for real, and then
    updates to a release whose server misbehaves in exactly one way. Because a role
    is genuinely running, the supervisor path is exercised rather than skipped, and
    `running_run` reads the node's own durable lock rather than a patched stub.
    """

    def _running_node(self, mode: str, deadline: float = 5.0):
        plan = self.serving_plan()
        ok, detail, _ = self.install_serving("serve-v1", 1, plan)
        self.assertTrue(ok, detail)
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        supervisor = LoopbackSupervisor(deadline=deadline)
        self.addCleanup(supervisor.shutdown)
        supervisor.start(group, ["distill"])
        ready, detail = supervisor.readiness(["distill"])
        self.assertTrue(ready, f"the baseline release must actually serve: {detail}")
        supervisor.mode = mode
        # Armed for the NEXT start only — the new release. The prior group's restart
        # must be given a healthy server, or a failed restoration and a refused
        # activation would be indistinguishable.
        supervisor.arm_once = True
        return plan, supervisor

    def test_a_server_on_the_wrong_endpoint_fails_readiness_and_rolls_back(self):
        plan, supervisor = self._running_node("wrong")
        prior = self.pointer_doc()
        ok, detail, _ = self.install_serving("serve-v2-wrong", 2, plan, supervisor)
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("endpoint", detail.lower())
        self.assertEqual(self.pointer_doc()["lock_digest"], prior["lock_digest"],
                         "a role serving the wrong endpoint must not be activated")
        self.assertEqual(self.pointer_doc()["state"], "active",
                         "the prior group must be restored, not left interrupted")
        self.assertTrue(self.verify_active()[0], "and it must verify")

    def test_a_server_that_never_binds_fails_the_readiness_deadline(self):
        plan, supervisor = self._running_node("nobind", deadline=2.0)
        prior = self.pointer_doc()
        ok, detail, _ = self.install_serving("serve-v2-nobind", 2, plan, supervisor)
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("did not answer", detail)
        self.assertEqual(self.pointer_doc()["lock_digest"], prior["lock_digest"])

    def test_a_hanging_server_fails_readiness_rather_than_blocking_the_transaction(self):
        plan, supervisor = self._running_node("hang", deadline=2.0)
        prior = self.pointer_doc()
        started = time.monotonic()
        ok, detail, _ = self.install_serving("serve-v2-hang", 2, plan, supervisor)
        elapsed = time.monotonic() - started
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertLess(elapsed, 240, "a hanging server must not block the transaction")
        self.assertEqual(self.pointer_doc()["lock_digest"], prior["lock_digest"])

    def test_stop_terminates_the_whole_process_group_not_only_the_parent(self):
        plan = self.serving_plan()
        ok, detail, _ = self.install_serving("serve-child", 1, plan)
        self.assertTrue(ok, detail)
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        supervisor = LoopbackSupervisor(mode="child")
        self.addCleanup(supervisor.shutdown)
        supervisor.start(group, ["distill"])
        ready, detail = supervisor.readiness(["distill"])
        self.assertTrue(ready, detail)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(supervisor.group_members("distill")) < 2:
            time.sleep(0.1)
        self.assertGreaterEqual(len(supervisor.group_members("distill")), 2,
                                "the fixture must really have spawned a child to prove this")
        supervisor.stop(["distill"])
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and supervisor.group_members("distill"):
            time.sleep(0.1)
        self.assertEqual(supervisor.group_members("distill"), [],
                         "stop must terminate the process group; an orphaned child would keep "
                         "executing generation bytes a prune is about to delete")
        terminated, detail = supervisor.terminated(["distill"])
        self.assertTrue(terminated, detail)

    def test_a_stale_pid_is_never_accepted_as_a_running_role(self):
        from cathedral_node import state as run_state
        _write_role_lock("compute", 2 ** 31 - 1)
        self.assertIsNone(run_state.running_run("compute"),
                          "a dead owner must not read as a running role")
        self.assertFalse(paths.role_lock("compute").exists(),
                         "a dead owner's lock must be reclaimed, not merely ignored")
        # ... and a genuinely live owner IS respected. It must be another process:
        # a lock naming this pid is "us", which `holder()` correctly reclaims.
        child = subprocess.Popen(["/bin/sh", "-c", "sleep 30"])  # noqa: S603
        self.addCleanup(lambda: (child.kill(), child.wait()))
        _write_role_lock("compute", child.pid)
        self.assertIsNotNone(run_state.running_run("compute"),
                             "a live owner must still hold the role")
        _clear_role_lock("compute")

    def test_stop_and_restart_are_idempotent(self):
        plan = self.serving_plan()
        ok, detail, _ = self.install_serving("serve-idem", 1, plan)
        self.assertTrue(ok, detail)
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        supervisor = LoopbackSupervisor()
        self.addCleanup(supervisor.shutdown)
        for round_number in range(2):
            with self.subTest(round=round_number):
                supervisor.start(group, ["distill"])
                ready, detail = supervisor.readiness(["distill"])
                self.assertTrue(ready, detail)
                supervisor.stop(["distill"])
                terminated, detail = supervisor.terminated(["distill"])
                self.assertTrue(terminated, detail)
                supervisor.stop(["distill"])   # a second stop is a no-op, not an error
        ok, reason, _ = self.verify_active()
        self.assertTrue(ok, f"repeated stop/start must not disturb the verified group: {reason}")


class TestRollbackTermination(Gate0Base):
    """Rollback publishes nothing and deletes nothing until the outgoing process
    group is proven gone."""

    class _UnstoppableSupervisor:
        """Returns from ``stop`` without the process having exited — exactly the
        failure a supervisor's own say-so cannot be trusted to report."""

        def __init__(self, running: list[str]) -> None:
            self._running = list(running)
            self.started: list = []

        def running_roles(self):
            return list(self._running)

        def stop(self, roles):
            pass                      # claims nothing, does nothing

        def start(self, group, roles):
            self.started.append((group, list(roles)))

        def readiness(self, roles):
            return False, "injected readiness failure"

    def test_rollback_refuses_to_publish_or_delete_while_a_process_may_be_running(self):
        ok, detail, _ = self.install(self.bundle("rb-live-1", 1))
        self.assertTrue(ok, detail)
        prior_pointer = self.pointer_doc()
        before = self.weakening_snapshot()

        # A real, live process, recorded in the node's own durable role lock. The
        # supervisor will refuse to kill it, so termination is genuinely unprovable.
        child = subprocess.Popen(["/bin/sh", "-c", "sleep 120"])  # noqa: S603
        self.addCleanup(lambda: (child.kill(), child.wait()))
        _write_role_lock("distill", child.pid)
        self.addCleanup(lambda: _clear_role_lock("distill"))

        supervisor = self._UnstoppableSupervisor(["distill"])
        ok, detail, _ = self.install(self.bundle("rb-live-2", 2), supervisor=supervisor)

        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("did not terminate", detail)
        self.assertEqual(supervisor.started, [],
                         "nothing may be started while the outgoing group is still alive")
        # The pointer is left exactly where the interrupted transaction left it:
        # PENDING. That is the fail-closed answer, not a lapse. Pending is not
        # active, so no runtime path will resolve it and `verify_active_group`
        # refuses; recovery must run, and recovery will try to prove termination
        # again. What must NOT have happened is a commit, or a restoration that
        # published a different group under a live process.
        current = self.pointer_doc()
        self.assertEqual(current["state"], "pending",
                         "a blocked rollback must leave the interrupted transaction visible")
        self.assertEqual(current["prior"]["lock_digest"], prior_pointer["lock_digest"])
        ok, reason, group = self.verify_active()
        self.assertFalse(ok, "a pending pointer must never verify as an active group")
        self.assertIsNone(group)
        self.assertTrue(paths.recovery_required())
        after = self.weakening_snapshot()
        for role in ROLES:
            self.assertGreaterEqual(len(after["generations"][role]),
                                    len(before["generations"][role]),
                                    "a blocked rollback must delete nothing")
        ledger = paths.rollback_ledger()
        self.assertTrue(ledger.exists(), "a blocked rollback is still auditable")
        self.assertEqual(json.loads(ledger.read_text().splitlines()[-1])["outcome"], "blocked")

    def test_a_failed_retention_leaves_a_fresh_node_that_can_retry(self):
        original = installer._retain_signed_release

        def failing(bundle_dir, auth):
            keep = paths.retained_releases_dir() / auth.lock_digest
            keep.mkdir(parents=True, exist_ok=True)
            (keep / "release.json").write_bytes(b"{}")   # a half-written retention
            raise OSError("injected retention failure")

        installer._retain_signed_release = failing
        try:
            ok, detail, _ = self.install(self.bundle("retain-fail"))
        finally:
            installer._retain_signed_release = original
        self.assertNoSuccessfulNoOp(ok, detail)

        # Nothing a later read would mistake for "this node has activated a release"
        # may survive; otherwise the missing replay floor fails closed forever on a
        # node that never activated anything.
        ok, floor, reason = installer._read_floor()
        self.assertTrue(ok, f"a failed attempt must leave the node fresh, not wedged: {reason}")
        self.assertIsNone(floor)
        self.assertFalse(paths.active_release_pointer().exists())
        self.assertFalse(paths.activation_marker().exists())
        retained = paths.retained_releases_dir()
        self.assertEqual([] if not retained.is_dir() else list(retained.iterdir()), [])

        # And the retry succeeds, which is the property that actually matters.
        ok, detail, _ = self.install(self.bundle("retain-retry"))
        self.assertTrue(ok, f"a clean retry must be possible: {detail}")
        self.assertTrue(installer.state(self.lock.pin("validator")).installed)


# ==============================================================================
# the lifecycle lock itself
# ==============================================================================

class TestSecureLockAndReadHardening(Gate0Base):
    """An advisory lock on the wrong inode excludes nobody.

    Each case below is a lock the process would *believe* it held while another
    process held something else — strictly worse than no lock, because the code
    above it stops defending itself once it thinks it is serialised.
    """

    def _lock_path(self) -> Path:
        paths.engines_dir().mkdir(parents=True, exist_ok=True)
        return paths.transaction_lock()

    def _assert_refused(self, label: str) -> str:
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            with self.assertRaises(installer.InstallError, msg=f"{label} was not refused") as caught:
                with installer.lifecycle_lock(exclusive=True, timeout=0.5):
                    pass
            ok, detail, _ = self.install(self.bundle(f"lock-{next(_COUNTER)}"))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)
        return str(caught.exception)

    def test_a_symlinked_lifecycle_lock_is_refused(self):
        lock = self._lock_path()
        decoy = self.home / "decoy.lock"
        decoy.write_bytes(b"")
        lock.unlink(missing_ok=True)
        os.symlink(decoy, lock)
        self.assertIn("safely", self._assert_refused("a symlinked lifecycle lock"))

    def test_a_non_regular_lifecycle_lock_is_refused(self):
        lock = self._lock_path()
        lock.unlink(missing_ok=True)
        os.mkfifo(lock)
        try:
            reason = self._assert_refused("a FIFO lifecycle lock")
            self.assertTrue("regular file" in reason or "safely" in reason, reason)
        finally:
            lock.unlink(missing_ok=True)

    def test_a_group_or_world_writable_lifecycle_lock_is_refused(self):
        lock = self._lock_path()
        lock.write_bytes(b"")
        os.chmod(lock, 0o666)
        self.assertIn("writable", self._assert_refused("a world-writable lifecycle lock"))

    def test_a_hard_linked_lifecycle_lock_is_refused(self):
        lock = self._lock_path()
        lock.unlink(missing_ok=True)
        lock.write_bytes(b"")
        os.link(lock, self.home / "second-name.lock")
        self.assertIn("link", self._assert_refused("a hard-linked lifecycle lock"))

    def test_a_lock_replaced_between_open_and_acquire_is_refused(self):
        """The precise race: the file is swapped after the open and before the flock
        lands, so the descriptor that was validated is no longer what the name means.
        Injected exactly at that instant rather than hoped for."""
        from cathedral_node import safeio
        lock = self._lock_path()
        lock.write_bytes(b"")
        impostor = self.home / "impostor.lock"
        impostor.write_bytes(b"")
        original_flock = safeio.fcntl.flock
        swapped: list[bool] = []

        def swap_then_lock(fd, operation):
            if not swapped:
                swapped.append(True)
                os.replace(impostor, lock)      # a different inode now owns the name
            return original_flock(fd, operation)

        safeio.fcntl.flock = swap_then_lock
        try:
            with self.assertRaises(installer.InstallError) as caught:
                with installer.lifecycle_lock(exclusive=True, timeout=0.5):
                    pass
        finally:
            safeio.fcntl.flock = original_flock
        self.assertIn("replaced", str(caught.exception))

    def test_the_shared_and_exclusive_forms_exclude_each_other(self):
        outcome: dict = {}

        def try_shared():
            try:
                with installer.lifecycle_lock(exclusive=False, timeout=0.3):
                    outcome["shared"] = "acquired"
            except installer.InstallError as exc:
                outcome["shared"] = f"blocked: {exc}"

        with installer.lifecycle_lock(exclusive=True):
            worker = threading.Thread(target=try_shared)
            worker.start()
            worker.join(10)
        self.assertIn("blocked", outcome["shared"],
                      "a runtime read must not proceed during an exclusive transaction")


# ==============================================================================
# revocation: atomic replacement, the sequence floor, and its lock
# ==============================================================================

class TestRevocationCacheAndFloor(Gate0Base):

    def test_the_snapshot_and_signature_are_replaced_in_one_step(self):
        """Two renames leave a window in which a new snapshot sits beside an old
        signature — a pair that verifies as nothing. One container, one rename."""
        now = dt.datetime.now(dt.timezone.utc)
        raw, sig = self.fx.revocation_snapshot(7)
        replacements: list[str] = []
        original = os.replace

        def counting(src, dst, *a, **kw):
            # The publish is directory-relative — the destination is a leaf name
            # resolved against a descriptor that was proven symlink-free — so the
            # name is what identifies it here.
            replacements.append(Path(str(dst)).name)
            return original(src, dst, *a, **kw)

        os.replace = counting
        try:
            ok, reason, state = revocation.retain(raw, sig, now=now)
        finally:
            os.replace = original
        self.assertTrue(ok, reason)
        self.assertEqual(state.sequence, 7)
        cache_writes = [d for d in replacements if d == revocation.cache_file().name]
        self.assertEqual(len(cache_writes), 1,
                         f"the cache pair must be published by exactly one rename: {replacements}")
        siblings = sorted(p.name for p in revocation.cache_file().parent.iterdir()
                          if not p.name.startswith("."))
        self.assertNotIn("snapshot.json.sig", siblings,
                         "no separate signature file may exist to be left behind")

    def test_a_crash_between_the_cache_and_the_floor_leaves_a_usable_pair(self):
        from cathedral_node import safeio
        now = dt.datetime.now(dt.timezone.utc)
        raw, sig = self.fx.revocation_snapshot(11)
        original = safeio.secure_write_atomic

        def fail_on_floor(path, data, **kw):
            if Path(path) == revocation.floor_file():
                raise OSError("injected floor write failure")
            return original(path, data, **kw)

        safeio.secure_write_atomic = fail_on_floor
        try:
            with contextlib.suppress(OSError):
                revocation.retain(raw, sig, now=now)
        finally:
            safeio.secure_write_atomic = original
        # The cache landed, the floor did not. A newer cache under an older floor is
        # acceptable; the reverse is what the floor exists to refuse.
        ok, reason, state = revocation.load_retained(now=now)
        self.assertTrue(ok, f"a crash before the floor write must leave a usable pair: {reason}")
        self.assertEqual(state.sequence, 11)

    def test_a_rolled_back_revocation_cache_is_refused_by_the_sequence_floor(self):
        now = dt.datetime.now(dt.timezone.utc)
        newer, newer_sig = self.fx.revocation_snapshot(20)
        ok, reason, _ = revocation.retain(newer, newer_sig, now=now)
        self.assertTrue(ok, reason)
        fok, floor, _ = revocation.floor_state()
        self.assertTrue(fok)
        self.assertEqual(floor[0], 20)

        # A *validly signed* older snapshot, restored straight over the cache. Every
        # old snapshot is genuinely signed, so only the durable floor can tell that
        # this node already knew something newer.
        older, older_sig = self.fx.revocation_snapshot(4)
        self.fx.stage_revocation_cache(older, older_sig)
        ok, reason, state = revocation.load_retained(now=now)
        self.assertFalse(ok, "a rolled-back revocation cache must be refused")
        self.assertIsNone(state)
        self.assertIn("floor", reason)

        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            iok, detail, _ = self.install(self.bundle("rolledback"))
        self.assertNoSuccessfulNoOp(iok, detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)

    def test_hostile_revocation_state_files_are_refused(self):
        now = dt.datetime.now(dt.timezone.utc)
        cache, floor = revocation.cache_file(), revocation.floor_file()
        saved_cache = cache.read_bytes()
        saved_floor = floor.read_bytes() if floor.exists() else b""

        with self.subTest(target="cache_symlink"):
            decoy = self.home / "decoy-cache.json"
            decoy.write_bytes(saved_cache)
            cache.unlink()
            os.symlink(decoy, cache)
            ok, reason, _ = revocation.load_retained(now=now)
            self.assertFalse(ok)
            self.assertIn("cache", reason)
            cache.unlink()
            cache.write_bytes(saved_cache)
            os.chmod(cache, 0o600)

        with self.subTest(target="cache_world_writable"):
            os.chmod(cache, 0o666)
            ok, reason, _ = revocation.load_retained(now=now)
            self.assertFalse(ok)
            self.assertIn("writable", reason)
            os.chmod(cache, 0o600)

        with self.subTest(target="floor_symlink"):
            decoy = self.home / "decoy-floor.json"
            decoy.write_bytes(saved_floor)
            floor.unlink(missing_ok=True)
            os.symlink(decoy, floor)
            ok, reason, _ = revocation.load_retained(now=now)
            self.assertFalse(ok)
            self.assertIn("floor", reason)
            floor.unlink()
            if saved_floor:
                floor.write_bytes(saved_floor)
                os.chmod(floor, 0o600)

        with self.subTest(target="lock_symlink"):
            lock = revocation.transaction_lock()
            lock.unlink(missing_ok=True)
            os.symlink(self.home / "decoy-lock", lock)
            raw, sig = self.fx.revocation_snapshot(30)
            ok, reason, _ = revocation.retain(raw, sig, now=now)
            self.assertFalse(ok, "a symlinked revocation lock must refuse the transaction")
            self.assertIn("lock", reason)
            lock.unlink()

    def test_concurrent_revocation_retention_is_serialised(self):
        now = dt.datetime.now(dt.timezone.utc)
        results: dict = {}
        barrier = threading.Barrier(2, timeout=30)

        def retain(label, sequence):
            raw, sig = self.fx.revocation_snapshot(sequence)
            barrier.wait()
            results[label] = revocation.retain(raw, sig, now=now)[:2]

        threads = [threading.Thread(target=retain, args=("a", 40)),
                   threading.Thread(target=retain, args=("b", 41))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)
        self.assertEqual(len(results), 2)
        fok, floor, _ = revocation.floor_state()
        self.assertTrue(fok)
        ok, reason, state = revocation.load_retained(now=now)
        self.assertTrue(ok, f"whatever the interleaving, the pair must be coherent: {reason}")
        self.assertGreaterEqual(state.sequence, 40)
        self.assertEqual(state.sequence, floor[0],
                         "the surviving cache and the floor must name the same snapshot")


class TestAcquisitionFreshness(Gate0Base):
    """Stale revocation knowledge may keep a node running. It may not authorize
    anything new. Those are separate questions and are tested separately."""

    def _expire_snapshot(self, sequence: int = 50):
        now = dt.datetime.now(dt.timezone.utc)
        return self.fx.install_revocation(
            self.home, sequence=sequence,
            issued_at=(now - dt.timedelta(days=40)).isoformat(),
            expires_at=(now - dt.timedelta(days=1)).isoformat())

    def test_a_stale_snapshot_does_not_authorize_an_acquisition(self):
        self._expire_snapshot()
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, detail, _ = self.install(self.bundle("staleacq"))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("expired", detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)
        for role in ROLES:
            root = paths.engine_generations_dir(role)
            self.assertEqual([] if not root.is_dir() else list(root.iterdir()), [],
                             "a refused acquisition must build nothing")

    def test_a_stale_snapshot_still_permits_retained_runtime_but_not_rollback(self):
        ok, detail, _ = self.install(self.bundle("staleruntime"))
        self.assertTrue(ok, detail)
        self._expire_snapshot()
        now = dt.datetime.now(dt.timezone.utc)

        # Retained runtime: the node keeps running, and says the knowledge is old.
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, f"a healthy node must not stop on stale revocation: {reason}")
        self.assertIsInstance(group, VerifiedActiveGroup)
        self.assertTrue(revocation.status(now=now)["stale"],
                        "staleness must be reported explicitly, not silently tolerated")

        # Rollback claims current global knowledge, so it refuses.
        digest = self.pointer_doc()["lock_digest"]
        rok, rreason, _ = revocation.enforce(digest, self.fx.signers.read_text(), IDENTITY,
                                             now=now, policy=revocation.ROLLBACK)
        self.assertFalse(rok)
        self.assertIn("expired", rreason)
        # ... and so does a new acquisition.
        aok, areason, _ = revocation.enforce(digest, self.fx.signers.read_text(), IDENTITY,
                                             now=now, policy=revocation.ACQUISITION)
        self.assertFalse(aok)
        self.assertIn("expired", areason)

    def test_a_revoked_signer_is_refused_before_any_candidate_code_runs(self):
        self.fx.install_revocation(self.home, sequence=60,
                                   revoked_signers=[self.fx.release_signer_fingerprint()])
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, detail, _ = self.install(self.bundle("revokedsigneracq"))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("signer", detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)
        for role in ROLES:
            root = paths.engine_generations_dir(role)
            self.assertEqual([] if not root.is_dir() else list(root.iterdir()), [],
                             "a revoked signer must be refused before a generation is created")


# ==============================================================================
# the repeated update chain, the parent environment, and the command lease
# ==============================================================================



class TestInheritedEnvironmentAttack(Gate0Base):
    """A hostile parent environment must not cross into any signed engine check.

    Not a review of the allowlist — an actual attack: every variable below is set
    in this process before a real install, and every subprocess that touches a
    generation is inspected for it.
    """

    HOSTILE = {
        "PYTHONPATH": "/tmp/attacker",
        "PYTHONSTARTUP": "/tmp/attacker/startup.py",
        "PYTHONUSERBASE": "/tmp/attacker",
        "PYTHONWARNINGS": "ignore",
        "LD_PRELOAD": "/tmp/attacker/evil.so",
        "DYLD_INSERT_LIBRARIES": "/tmp/attacker/evil.dylib",
        "DYLD_LIBRARY_PATH": "/tmp/attacker",
        "VIRTUAL_ENV": "/tmp/attacker/venv",
        "CONDA_PREFIX": "/tmp/attacker/conda",
        "PIP_INDEX_URL": "https://attacker.invalid/simple",
        "PIP_EXTRA_INDEX_URL": "https://attacker.invalid/simple",
        "PIP_TRUSTED_HOST": "attacker.invalid",
        "HTTP_PROXY": "http://attacker.invalid:3128",
        "HTTPS_PROXY": "http://attacker.invalid:3128",
        "AWS_SECRET_ACCESS_KEY": "should-never-be-inherited",
        "SSH_AUTH_SOCK": "/tmp/attacker/agent.sock",
    }
    # Derived from the product, not restated. A test that keeps its own copy of the
    # allowlist stops testing the allowlist the moment the two drift.
    ALLOWED = set(proc_module.SIGNED_CHILD_ALLOWLIST) | {"PIP_CONFIG_FILE", "PIP_NO_INDEX"}

    def test_a_hostile_parent_environment_never_crosses_into_a_signed_engine_check(self):
        for key, value in self.HOSTILE.items():
            os.environ[key] = value
            self.addCleanup(os.environ.pop, key, None)

        observed: list[tuple[list[str], dict]] = []
        inherited: list[str] = []
        originals = {name: getattr(installer.proc, name) for name in ("run", "probe")}

        def make(name, original):
            def spy(argv, *a, **kw):
                argv_str = [str(x) for x in argv]
                if "/generations/" in " ".join(argv_str):
                    observed.append((argv_str, dict(kw.get("env") or {})))
                    if kw.get("inherit_env") is not False:
                        inherited.append(f"{name}: {argv_str[0]}")
                return original(argv, *a, **kw)
            return spy

        for name, original in originals.items():
            setattr(installer.proc, name, make(name, original))
        try:
            ok, detail, _ = self.install(self.bundle("hostileenv"))
        finally:
            for name, original in originals.items():
                setattr(installer.proc, name, original)

        self.assertTrue(ok, f"a hostile environment must not break a legitimate install: {detail}")
        self.assertTrue(observed, "no signed engine check was observed")
        self.assertEqual(inherited, [],
                         "a signed engine check inherited the parent environment")
        for argv, env in observed:
            leaked = sorted(set(env) & set(self.HOSTILE))
            self.assertEqual(leaked, [], f"{argv[0]} inherited {leaked}")
            self.assertEqual(sorted(set(env) - self.ALLOWED), [],
                             f"{argv[0]} received unexpected variables")
            self.assertEqual(env.get("PATH"), "/usr/bin:/bin")


class TestLeaseIsNotEscaped(Gate0Base):
    """A command must not read verified state, drop the lease, and then act on what
    it read. The window between those two is exactly the verify-then-swap race."""

    def test_the_reporting_view_holds_the_shared_lease_for_the_whole_body(self):
        ok, detail, _ = self.install(self.bundle("lease"))
        self.assertTrue(ok, detail)
        blocked: dict = {}

        def try_exclusive():
            try:
                with installer.lifecycle_lock(exclusive=True, timeout=0.3):
                    blocked["result"] = "acquired"
            except installer.InstallError as exc:
                blocked["result"] = f"blocked: {exc}"

        with installer.active_view(self.lock) as (states, group, _detail):
            self.assertTrue(states["validator"].installed)
            self.assertIsInstance(group, VerifiedActiveGroup)
            worker = threading.Thread(target=try_exclusive)
            worker.start()
            worker.join(10)
        self.assertIn("blocked", blocked["result"],
                      "an activation ran while a command was still reading verified state")

    def test_uninstall_refuses_a_referenced_role_and_deletes_nothing(self):
        ok, detail, _ = self.install(self.bundle("uninst"))
        self.assertTrue(ok, detail)
        before = {r: sorted(p.name for p in paths.engine_generations_dir(r).iterdir())
                  for r in ROLES}
        for role in ROLES:
            with self.subTest(role=role):
                removed, reason = installer.uninstall(role)
                self.assertFalse(removed, "a referenced engine must never be removed")
                self.assertIn(role, reason)
        self.assertEqual({r: sorted(p.name for p in paths.engine_generations_dir(r).iterdir())
                          for r in ROLES}, before,
                         "a refused uninstall must delete nothing")
        self.assertTrue(installer.state(self.lock.pin("validator")).installed)

    def test_uninstall_refuses_while_a_transaction_holds_the_lifecycle_lock(self):
        ok, detail, _ = self.install(self.bundle("uninstlock"))
        self.assertTrue(ok, detail)
        with installer.lifecycle_lock(exclusive=True):
            removed, reason = installer.uninstall("compute")
        self.assertFalse(removed, "uninstall must take the lifecycle lock, not race it")
        self.assertIn("progress", reason)

    def test_a_failed_pointer_write_leaves_a_fresh_node_that_can_retry(self):
        original = installer._write_json_atomic

        def failing(path, document):
            if Path(path) == paths.active_release_pointer():
                raise OSError("injected pointer write failure")
            return original(path, document)

        installer._write_json_atomic = failing
        try:
            ok, detail, _ = self.install(self.bundle("ptrfail-retry"))
        finally:
            installer._write_json_atomic = original
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertFalse(paths.active_release_pointer().exists())
        ok, floor, reason = installer._read_floor()
        self.assertTrue(ok, f"a node that never committed must still read as fresh: {reason}")
        self.assertIsNone(floor)
        ok, detail, _ = self.install(self.bundle("ptrfail-ok"))
        self.assertTrue(ok, f"a clean retry must be possible: {detail}")

    def test_a_failed_floor_commit_leaves_a_fresh_node_that_can_retry(self):
        original = installer._commit_floor

        def failing(*_a, **_kw):
            raise installer.InstallError("injected floor commit failure")

        installer._commit_floor = failing
        try:
            ok, detail, _ = self.install(self.bundle("floorfail-retry"))
        finally:
            installer._commit_floor = original
        self.assertNoSuccessfulNoOp(ok, detail)
        ok, floor, reason = installer._read_floor()
        self.assertTrue(ok, f"a node that never committed must still read as fresh: {reason}")
        self.assertIsNone(floor)
        ok, detail, _ = self.install(self.bundle("floorfail-ok"))
        self.assertTrue(ok, f"a clean retry must be possible: {detail}")


# ==============================================================================
# revocation: one atomic document, a durable floor, and three freshness policies
# ==============================================================================

class TestRevocationTransaction(Gate0Base):
    """The revocation cache is durable state under attack like any other."""

    def _now(self):
        return dt.datetime.now(dt.timezone.utc)

    def test_the_cache_is_one_document_so_no_crash_can_split_snapshot_from_signature(self):
        """A snapshot and its detached signature must move together.

        Two `os.replace` calls cannot be made atomic, so a crash between them leaves
        a new snapshot beside a signature that does not cover it — a pair that
        verifies as nothing, discovered at the worst possible moment. The product
        answer is one container, and this test both asserts the shape and proves the
        crash window is gone by failing the write itself.
        """
        now = self._now()
        raw5, sig5 = self.fx.revocation_snapshot(5)
        ok, reason, state = revocation.retain(raw5, sig5, now=now)
        self.assertTrue(ok, reason)
        self.assertEqual(state.sequence, 5)
        good = revocation.cache_file().read_bytes()

        # There is exactly one file to replace, and it holds both halves.
        container = json.loads(good)
        self.assertEqual(set(container), {"schema", "snapshot", "signature"})

        # Crash the write of a newer snapshot part-way through.
        raw9, sig9 = self.fx.revocation_snapshot(9)
        original = installer.safeio.secure_write_atomic

        def crash(path, data, **kw):
            if path == revocation.cache_file():
                raise OSError("crash between fsync and rename")
            return original(path, data, **kw)

        revocation.safeio.secure_write_atomic = crash
        try:
            with self.assertRaises(OSError):
                revocation.retain(raw9, sig9, now=now)
        finally:
            revocation.safeio.secure_write_atomic = original

        self.assertEqual(revocation.cache_file().read_bytes(), good,
                         "a failed write must leave the previous pair byte-identical")
        ok, reason, state = revocation.load_retained(now=now)
        self.assertTrue(ok, reason)
        self.assertEqual(state.sequence, 5, "the last known good snapshot must still verify")

    def test_the_durable_floor_refuses_a_rolled_back_cache(self):
        now = self._now()
        raw9, sig9 = self.fx.revocation_snapshot(9)
        ok, reason, _ = revocation.retain(raw9, sig9, now=now)
        self.assertTrue(ok, reason)
        fok, floor, freason = revocation.floor_state()
        self.assertTrue(fok, freason)
        self.assertEqual(floor[0], 9)

        # Restore an older, perfectly valid, correctly signed cache — the shape a
        # backup restore or anything with write access produces.
        raw3, sig3 = self.fx.revocation_snapshot(3)
        self.fx.stage_revocation_cache(raw3, sig3)
        ok, reason, state = revocation.load_retained(now=now)
        self.assertFalse(ok, "a cache below the durable floor must be refused")
        self.assertIsNone(state)
        self.assertIn("floor", reason)

        with self.subTest(case="same sequence, different content"):
            raw9b, sig9b = self.fx.revocation_snapshot(9, revoked_releases=["a" * 64])
            self.fx.stage_revocation_cache(raw9b, sig9b)
            ok, reason, _ = revocation.load_retained(now=now)
            self.assertFalse(ok)
            self.assertIn("floor", reason)

    def test_revocation_state_and_its_lock_refuse_symlinks_types_owners_and_modes(self):
        now = self._now()
        raw, sig = self.fx.revocation_snapshot(4)
        self.assertTrue(revocation.retain(raw, sig, now=now)[0])
        good = revocation.cache_file().read_bytes()

        for target, label in ((revocation.cache_file(), "cache"),
                              (revocation.floor_file(), "floor")):
            saved = target.read_bytes()
            with self.subTest(file=label, attack="symlink"):
                decoy = self.home / f"decoy-{label}"
                decoy.write_bytes(saved)
                target.unlink()
                os.symlink(decoy, target)
                ok, _reason, _state = revocation.load_retained(now=now)
                self.assertFalse(ok, f"a symlinked revocation {label} must be refused")
                target.unlink()
                target.write_bytes(saved)
                os.chmod(target, 0o600)
            with self.subTest(file=label, attack="group_writable"):
                os.chmod(target, 0o666)
                ok, _reason, _state = revocation.load_retained(now=now)
                self.assertFalse(ok, f"a world-writable revocation {label} must be refused")
                os.chmod(target, 0o600)
            with self.subTest(file=label, attack="fifo"):
                target.unlink()
                os.mkfifo(target)
                ok, _reason, _state = revocation.load_retained(now=now)
                self.assertFalse(ok, f"a FIFO revocation {label} must be refused")
                target.unlink()
                target.write_bytes(saved)
                os.chmod(target, 0o600)

        self.assertEqual(revocation.cache_file().read_bytes(), good)
        with self.subTest(file="lock", attack="symlink"):
            lock = revocation.transaction_lock()
            decoy = self.home / "decoy.lock"
            decoy.write_bytes(b"")
            if lock.exists():
                lock.unlink()
            os.symlink(decoy, lock)
            ok, reason, _ = revocation.retain(raw, sig, now=now)
            self.assertFalse(ok, "a symlinked revocation lock must be refused")
            self.assertIn("lock", reason)
            lock.unlink()

    def test_freshness_is_policy_acquisition_and_rollback_refuse_stale_runtime_does_not(self):
        """The three policies are defined and proven separately, because they answer
        different questions: acquiring and rolling back claim *current* global
        knowledge, while continuing to run an installed release does not."""
        now = self._now()
        self.fx.install_revocation(
            self.home, sequence=7,
            issued_at=(now - dt.timedelta(days=40)).isoformat(),
            expires_at=(now - dt.timedelta(days=1)).isoformat())
        trust = self.fx.signers.read_text()

        ok, reason, state = revocation.enforce("a" * 64, trust, IDENTITY, now=now,
                                               policy=revocation.RETAINED_RUNTIME)
        self.assertTrue(ok, f"a healthy installed node must keep running: {reason}")
        self.assertTrue(state.stale)
        self.assertIn("stale", reason)

        for policy in (revocation.ACQUISITION, revocation.ROLLBACK):
            with self.subTest(policy=policy):
                ok, reason, _ = revocation.enforce("a" * 64, trust, IDENTITY, now=now,
                                                   policy=policy)
                self.assertFalse(ok, f"{policy} must not proceed on stale knowledge")
                self.assertIn("expired", reason)

        with self.subTest(policy="unknown"):
            ok, reason, _ = revocation.enforce("a" * 64, trust, IDENTITY, now=now, policy="whatever")
            self.assertFalse(ok)
            self.assertIn("policy", reason)

    def test_a_stale_snapshot_blocks_a_new_acquisition_end_to_end(self):
        now = self._now()
        self.fx.install_revocation(
            self.home, sequence=7,
            issued_at=(now - dt.timedelta(days=40)).isoformat(),
            expires_at=(now - dt.timedelta(days=1)).isoformat())
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, detail, _ = self.install(self.bundle("stale-acq"))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("revocation", detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)

    def test_a_revoked_signer_is_refused_before_any_candidate_code_runs(self):
        """Not merely 'before activation' — before a venv is created, before pip
        runs, and before a single declared entrypoint of the candidate executes."""
        self.fx.install_revocation(
            self.home, sequence=2,
            revoked_signers=[self.fx.release_signer_fingerprint()])
        before = self.weakening_snapshot()
        with ProcessSpy() as spy:
            ok, detail, _ = self.install(self.bundle("revoked-signer"))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("signer", detail)
        self.assertStartsNoProcess(spy)
        self.assertNoWeakening(before)
        for role in ROLES:
            root = paths.engine_generations_dir(role)
            self.assertEqual([] if not root.is_dir() else list(root.iterdir()), [],
                             f"a {role} generation directory was created for a revoked signer")


# ==============================================================================
# the lifecycle lock is itself durable security state
# ==============================================================================

class TestLifecycleLockHardening(Gate0Base):

    def test_the_lifecycle_lock_refuses_symlink_type_owner_and_mode_attacks(self):
        lock = paths.transaction_lock()
        paths.engines_dir().mkdir(parents=True, exist_ok=True)

        with self.subTest(attack="symlink"):
            decoy = self.home / "decoy-lifecycle.lock"
            decoy.write_bytes(b"")
            if lock.exists():
                lock.unlink()
            os.symlink(decoy, lock)
            with self.assertRaises(installer.InstallError):
                with installer.lifecycle_lock(exclusive=True, timeout=0.2):
                    pass
            lock.unlink()

        with self.subTest(attack="fifo"):
            os.mkfifo(lock)
            with self.assertRaises(installer.InstallError):
                with installer.lifecycle_lock(exclusive=True, timeout=0.2):
                    pass
            lock.unlink()

        with self.subTest(attack="group_writable"):
            lock.write_bytes(b"")
            os.chmod(lock, 0o666)
            with self.assertRaises(installer.InstallError):
                with installer.lifecycle_lock(exclusive=True, timeout=0.2):
                    pass
            os.chmod(lock, 0o600)

        with self.subTest(attack="hard_linked"):
            other = paths.engines_dir() / "lifecycle.alias"
            os.link(lock, other)
            with self.assertRaises(installer.InstallError):
                with installer.lifecycle_lock(exclusive=True, timeout=0.2):
                    pass
            other.unlink()

        with self.subTest(case="healthy"):
            with installer.lifecycle_lock(exclusive=True, timeout=5.0):
                pass

    def test_replacing_the_lock_file_during_the_wait_is_detected(self):
        """A lock on a replaced inode excludes nobody, and the code above it believes
        it is serialised. Acquisition therefore proves the descriptor it holds is
        still what the name resolves to."""
        lock = paths.transaction_lock()
        paths.engines_dir().mkdir(parents=True, exist_ok=True)
        lock.write_bytes(b"")
        os.chmod(lock, 0o600)

        replaced = threading.Event()
        failure: dict = {}

        def replace_during_wait():
            # The holder is inside the lock; swap the *name* onto a fresh inode.
            replacement = paths.engines_dir() / "replacement.lock"
            replacement.write_bytes(b"")
            os.chmod(replacement, 0o600)
            os.replace(replacement, lock)
            replaced.set()

        def contender():
            replaced.wait(10)
            try:
                with installer.lifecycle_lock(exclusive=True, timeout=1.0):
                    failure["result"] = "acquired a lock on a replaced inode"
            except installer.InstallError as exc:
                failure["result"] = f"refused: {exc}"

        with installer.lifecycle_lock(exclusive=True, timeout=5.0):
            worker = threading.Thread(target=contender)
            worker.start()
            replace_during_wait()
            worker.join(20)
        self.assertIn("result", failure)
        self.assertTrue(failure["result"].startswith("refused"),
                        f"a replaced lock file must not be usable: {failure['result']}")


# ==============================================================================
# failure leaves a node that can retry; uninstall and cleanup tell the truth
# ==============================================================================

class TestFailureLeavesACleanRetry(Gate0Base):

    def test_a_failed_floor_commit_leaves_a_fresh_node_that_can_retry(self):
        """Nothing was declared active, so nothing may survive that makes a later
        read believe this node has activated a release. Otherwise `_read_floor` sees
        an activation witness with no floor beside it and fails closed forever on a
        node that has nothing to protect."""
        original = installer._commit_floor
        installer._commit_floor = lambda *a, **kw: (_ for _ in ()).throw(
            installer.InstallError("injected floor commit failure"))
        try:
            ok, detail, _ = self.install(self.bundle("floorfail"))
        finally:
            installer._commit_floor = original
        self.assertNoSuccessfulNoOp(ok, detail)

        self.assertFalse(paths.activation_marker().exists(), "an activation marker survived")
        self.assertFalse(paths.activation_journal().exists(), "an activation journal survived")
        self.assertFalse(paths.release_floor().exists(), "the floor moved")
        pointer = paths.active_release_pointer()
        self.assertFalse(pointer.exists() and json.loads(pointer.read_text())["state"] == "active",
                         "a committed pointer survived a failed commit")
        ok, floor, reason = installer._read_floor()
        self.assertTrue(ok, f"the node must still look fresh: {reason}")
        self.assertIsNone(floor)

        # The retry is the proof: same node, same bundle, no operator intervention.
        ok, detail, _ = self.install(self.bundle("floorfail-retry"))
        self.assertTrue(ok, f"a clean retry must succeed: {detail}")
        self.assertTrue(installer.state(self.lock.pin("validator")).installed)

    def test_uninstall_refuses_a_referenced_or_running_role_and_never_asks_the_pointer_leniently(self):
        ok, detail, _ = self.install(self.bundle("uninst"))
        self.assertTrue(ok, detail)

        with self.subTest(case="referenced by the active pointer"):
            removed, reason = installer.uninstall("distill")
            self.assertFalse(removed, "an active role must not be removable")
            self.assertIn("pointer", reason)
            self.assertTrue(paths.engine_dir("distill").exists())

        with self.subTest(case="referenced by a pending pointer"):
            document = self.pointer_doc()
            self.write_pointer({**document, "state": "pending"})
            removed, reason = installer.uninstall("compute")
            self.assertFalse(removed, "a pending transaction still names this role")
            self.assertIn("pending", reason)
            self.write_pointer(document)

        with self.subTest(case="an unparseable pointer refuses rather than deletes"):
            saved = paths.active_release_pointer().read_text()
            paths.active_release_pointer().write_text("{not json")
            removed, reason = installer.uninstall("validator")
            self.assertFalse(removed)
            self.assertIn("cannot", reason)
            paths.active_release_pointer().write_text(saved)

        with self.subTest(case="unreferenced but running"):
            paths.active_release_pointer().unlink()
            from cathedral_node import state as run_state
            lock_path = paths.role_lock("distill")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            lock_path.write_text(json.dumps(
                {"pid": os.getpid(), "run_id": "live", "since": "2026-07-31T00:00:00Z"}))
            self.assertIsNotNone(run_state.running_run("distill"))
            removed, reason = installer.uninstall("distill")
            self.assertFalse(removed)
            self.assertIn("running", reason)
            lock_path.unlink()

        with self.subTest(case="unreferenced and idle"):
            removed, reason = installer.uninstall("distill")
            self.assertTrue(removed, reason)
            self.assertFalse(paths.engine_dir("distill").exists())

    def test_uninstall_is_serialised_by_the_lifecycle_lock(self):
        ok, detail, _ = self.install(self.bundle("uninst-lock"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()
        outcome: dict = {}

        def try_uninstall():
            outcome["result"] = installer.uninstall("compute")

        with installer.lifecycle_lock(exclusive=True, timeout=5.0):
            worker = threading.Thread(target=try_uninstall)
            worker.start()
            worker.join(30)
            self.assertIn("result", outcome)
            removed, reason = outcome["result"]
            self.assertFalse(removed, "uninstall must not proceed while a transaction holds the lock")
            self.assertIn("progress", reason)
        self.assertTrue(paths.engine_dir("compute").exists())

    def test_cleanup_does_not_report_success_when_an_engine_could_not_be_removed(self):
        from types import SimpleNamespace

        from cathedral_node import runner
        from cathedral_node.commands import cleanup as cleanup_command

        ok, detail, _ = self.install(self.bundle("cleanup-refuse"))
        self.assertTrue(ok, detail)   # every role is now named by the active pointer
        ctx = runner.Context(
            args=SimpleNamespace(role=None, runs=False, engine=True, all=False, keep_days=0),
            console=runner.build_console(json_mode=True, quiet=True), json_mode=True,
            assume_yes=True, dry_run=False, verbose=False, run_id="cleanup-test", home=self.home)
        envelope = cleanup_command.cleanup.__wrapped__(ctx) if hasattr(
            cleanup_command.cleanup, "__wrapped__") else cleanup_command.cleanup(ctx)
        self.assertNotEqual(envelope.status, "ok",
                            "cleanup reported success while the engines are still on disk")
        # A failed envelope carries its payload under `error.detail`; `data` is for
        # the success shape. Reading `data` here would have passed on an envelope
        # that said nothing at all.
        payload = envelope.error.detail if envelope.error is not None else envelope.data
        self.assertFalse(payload.get("applied"))
        self.assertTrue(payload.get("refused"),
                        "a refusal must name what it refused and why")
        for entry in payload["refused"]:
            self.assertIn("pointer", entry["detail"])
        for role in ROLES:
            self.assertTrue(paths.engine_dir(role).exists(), f"{role} was removed anyway")


# ==============================================================================
# repeated signed updates, restart, crash recovery and rollback
# ==============================================================================

class TestRepeatedUpdateCycle(Gate0Base):

    def test_repeated_v1_v2_v3_update_restart_crash_recovery_and_rollback(self):
        """One node, three signed releases, a controlled restart at every step, a
        crash between the floor and the pointer, and a rollback — with exactly one
        prior generation retained throughout.

        Each step separately has a unit test above. This proves they compose: that
        the floor only ever rises, that `prior` never becomes a chain, and that the
        node is verifiable after every single transition.
        """
        from cathedral_node import state as run_state
        original_running = installer.run_state.running_run
        _RUNNING.clear()
        installer.run_state.running_run = _patched_running_run
        self.addCleanup(lambda: (_RUNNING.clear(),
                                 setattr(installer.run_state, "running_run", original_running)))

        supervisor = RecordingSupervisor()
        history: list[tuple[int, str]] = []

        def install_version(version: int) -> dict:
            ok, detail, _ = self.install(self.bundle(f"cycle-v{version}", version),
                                         supervisor=supervisor)
            self.assertTrue(ok, f"v{version}: {detail}")
            ok, reason, group = self.verify_active()
            self.assertTrue(ok, f"v{version} must verify after activation: {reason}")
            document = self.pointer_doc()
            floor = self.floor_doc()
            self.assertEqual((floor["release_version"], floor["lock_digest"]),
                             (document["release_version"], document["lock_digest"]),
                             f"v{version}: the committed pointer must equal the floor")
            history.append((floor["release_version"], floor["lock_digest"]))
            self.assertEqual([h[0] for h in history], sorted(h[0] for h in history),
                             "the replay floor moved backwards")
            for role in ROLES:
                retained = sorted(p.name for p in paths.engine_generations_dir(role).iterdir())
                self.assertLessEqual(len(retained), 2,
                                     f"v{version}: {role} retained {len(retained)} generations, "
                                     f"but exactly one prior is kept")
            return document

        v1 = install_version(1)
        # A controlled restart: the roles are running, so the supervisor path runs.
        _RUNNING.update(ROLES)
        v2 = install_version(2)
        self.assertTrue(supervisor.started, "a running node must be restarted through the supervisor")
        self.assertEqual(v2["prior"]["lock_digest"], v1["lock_digest"])
        self.assertIsNone(v2["prior"]["prior"], "prior must never become a chain")

        v3 = install_version(3)
        self.assertEqual(v3["prior"]["lock_digest"], v2["lock_digest"])
        self.assertIsNone(v3["prior"]["prior"])
        # v1's generations are gone: exactly one prior is retained.
        for role in ROLES:
            retained = {p.name for p in paths.engine_generations_dir(role).iterdir()}
            self.assertIn(v3["generations"][role], retained)
            self.assertIn(v2["generations"][role], retained)
            self.assertNotIn(v1["generations"][role], retained,
                             f"{role}: a second prior generation was retained")

        # Crash between the floor commit and the pointer commit, then recover.
        with self.subTest(step="crash after pending, floor already raised"):
            self.write_pointer({**v3, "state": "pending"})
            ok, detail = installer.recover(self.lock, supervisor=supervisor)
            self.assertTrue(ok, detail)
            self.assertEqual(self.pointer_doc()["state"], "active")
            self.assertEqual(self.floor_doc()["release_version"], 3)

        # Crash *before* the floor was raised, so the prior is eligible again.
        with self.subTest(step="rollback to the exact retained prior"):
            self.write_pointer({**v3, "state": "pending"})
            self.write_floor(v2["release_version"], v2["lock_digest"])
            installer._force_rmtree(paths.retained_releases_dir() / v3["lock_digest"])
            ok, detail = installer.recover(self.lock, supervisor=supervisor)
            self.assertTrue(ok, detail)
            restored = self.pointer_doc()
            self.assertEqual(restored["lock_digest"], v2["lock_digest"])
            self.assertEqual(restored["generations"], v2["generations"])
            ok, reason, _ = self.verify_active()
            self.assertTrue(ok, f"the node must verify after rollback: {reason}")
            ledger = [json.loads(line) for line in
                      paths.rollback_ledger().read_text().splitlines()]
            self.assertEqual(ledger[-1]["outcome"], "restored")
            self.assertEqual(ledger[-1]["to_lock_digest"], v2["lock_digest"])


# ==============================================================================
# the environment never crosses into a signed engine check
# ==============================================================================

# ==============================================================================
# the full signed update chain (repair directive: repeated v1 -> v2 -> v3)
# ==============================================================================



# ==============================================================================
# the signed-child environment boundary (runtime follow-up 1)
# ==============================================================================

class TestSignedChildEnvironment(ReadinessCase):
    """No signed child inherits anything. Proven three ways, because the danger is
    not one variable but the *default*: a call site that forgets is a call site that
    inherits."""

    HOSTILE = {
        "PYTHONPATH": None,               # filled in with a real sitecustomize dir
        "PYTHONSTARTUP": "/tmp/evil.py",
        "LD_PRELOAD": "/tmp/evil.so",
        "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
        "VIRTUAL_ENV": "/tmp/not-our-venv",
        "PIP_INDEX_URL": "https://evil.invalid/simple",
        "HTTP_PROXY": "http://evil.invalid:3128",
        "HTTPS_PROXY": "http://evil.invalid:3128",
        "AWS_SECRET_ACCESS_KEY": "should-never-cross",
        "CATHEDRAL_SMUGGLED_TOKEN": "should-never-cross",
    }

    def _poison_environment(self) -> Path:
        hostile_dir = self.home / "hostile"
        hostile_dir.mkdir(exist_ok=True)
        sentinel = self.home / "SENTINEL-inherited-env"
        (hostile_dir / "sitecustomize.py").write_text(
            f"import pathlib\npathlib.Path({str(sentinel)!r}).write_text('pwned')\n")
        hostile = dict(self.HOSTILE)
        hostile["PYTHONPATH"] = str(hostile_dir)
        saved = {k: os.environ.get(k) for k in hostile}
        os.environ.update(hostile)

        def restore():
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        self.addCleanup(restore)
        return sentinel

    def test_every_subprocess_call_site_states_its_inheritance_explicitly(self):
        """A default is what let this happen. There is no default any more, and this
        keeps it that way: `proc.run`, `proc.probe` and `proc.stream` take
        `inherit_env` as a required keyword, and every call site in the product
        names it."""
        import ast as _ast
        offenders: list[str] = []
        for source in sorted(Path("cathedral_node").rglob("*.py")):
            tree = _ast.parse(source.read_text())
            for node in _ast.walk(tree):
                if not isinstance(node, _ast.Call):
                    continue
                func = node.func
                name = None
                if isinstance(func, _ast.Attribute) and func.attr in ("run", "probe", "stream"):
                    base = func.value
                    if isinstance(base, _ast.Name) and base.id in ("proc", "_proc"):
                        name = func.attr
                elif isinstance(func, _ast.Name) and func.id == "stream":
                    name = "stream"
                if name and "inherit_env" not in {kw.arg for kw in node.keywords}:
                    offenders.append(f"{source}:{node.lineno} proc.{name}")
        self.assertEqual(offenders, [],
                         f"these call sites inherit the host environment by omission: {offenders}")

        import inspect as _inspect
        for name in ("run", "probe", "stream"):
            with self.subTest(function=name):
                signature = _inspect.signature(getattr(proc_module, name))
                parameter = signature.parameters["inherit_env"]
                self.assertIs(parameter.default, _inspect.Parameter.empty,
                              f"proc.{name}(inherit_env=...) must have no default")

    def test_the_local_test_path_runs_the_engine_with_nothing_inherited(self):
        from cathedral_node import engines as engines_module
        plan = self.serving_plan()
        ok, detail, _ = self.install_serving("env-localtest", 1, plan)
        self.assertTrue(ok, detail)
        sentinel = self._poison_environment()

        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        adapter = engines_module.load("distill", self.lock, group)
        cfg = {"hotkey": "5" + "1" * 47}
        secrets = set(adapter.operate_env(cfg))
        env = adapter.child_env(cfg)
        # Role secrets the adapter resolved on purpose are the ONE addition; they
        # travel in the environment precisely so they never reach argv.
        leaks = proc_module.env_leaks(env, allow=secrets)
        self.assertEqual(leaks, [], f"the adapter's child environment carries {leaks}")
        for name in self.HOSTILE:
            self.assertNotIn(name, env)
        self.assertEqual(env["PATH"], proc_module.SIGNED_CHILD_PATH)

        # And the real thing: run the verified interpreter with that environment and
        # confirm the planted sitecustomize did not execute.
        result = proc_module.run([str(group.role("distill").python), "-c", "print('ran')"],
                                 inherit_env=False, env=env, timeout=60)
        self.assertTrue(result.ok, result.tail())
        self.assertFalse(sentinel.exists(),
                         "a sitecustomize.py on the inherited PYTHONPATH executed in a signed child")

    def test_the_long_running_start_path_runs_the_engine_with_nothing_inherited(self):
        """`cathedral start` is the longest-lived child the node has, and it used to
        be the one path with no scrubbed mode at all."""
        plan = self.serving_plan()
        ok, detail, _ = self.install_serving("env-start", 1, plan)
        self.assertTrue(ok, detail)
        sentinel = self._poison_environment()
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)
        verified = group.role("distill")

        seen: list[str] = []
        dump = self.home / "child-env.json"
        script = (f"import json,os,pathlib\n"
                  f"pathlib.Path({str(dump)!r}).write_text(json.dumps(dict(os.environ)))\n"
                  f"print('done', flush=True)\n")
        result = proc_module.stream(
            [str(verified.python), "-c", script], on_line=seen.append,
            inherit_env=False,
            env=proc_module.signed_child_env(home=verified.generation_dir,
                                             secrets={"CATHEDRAL_ROLE_TOKEN": "resolved-on-purpose"}))
        self.assertEqual(result.returncode, 0, result.stderr)
        child_env = json.loads(dump.read_text())
        # `__CF_USER_TEXT_ENCODING` is inserted by macOS libc into every process it
        # starts, whatever environment was passed. It is not inherited from us and
        # carries no attacker-controlled value, so it is named here rather than
        # quietly widening the product's allowlist.
        leaks = proc_module.env_leaks(
            child_env, allow=("CATHEDRAL_ROLE_TOKEN", "__CF_USER_TEXT_ENCODING"))
        self.assertEqual(leaks, [], f"the start path leaked {leaks} into the signed child")
        self.assertEqual(child_env.get("CATHEDRAL_ROLE_TOKEN"), "resolved-on-purpose",
                         "an explicitly resolved role secret must still reach the child")
        self.assertFalse(sentinel.exists())

    def test_active_verification_runs_its_probes_with_nothing_inherited(self):
        plan = self.serving_plan()
        ok, detail, _ = self.install_serving("env-verify", 1, plan)
        self.assertTrue(ok, detail)
        sentinel = self._poison_environment()

        observed: list[dict] = []
        original_run, original_probe = installer.proc.run, installer.proc.probe

        def record(fn):
            def wrapper(argv, **kw):
                if kw.get("inherit_env") is False:
                    observed.append(dict(kw.get("env") or {}))
                else:
                    observed.append({"__INHERITED__": " ".join(str(a) for a in argv)})
                return fn(argv, **kw)
            return wrapper

        installer.proc.run = record(original_run)
        installer.proc.probe = record(original_probe)
        try:
            ok, reason, group = self.verify_active()
        finally:
            installer.proc.run, installer.proc.probe = original_run, original_probe
        self.assertTrue(ok, reason)
        self.assertTrue(observed, "active verification ran no subprocess at all")
        for env in observed:
            self.assertNotIn("__INHERITED__", env,
                             f"active verification inherited the host environment: {env}")
            self.assertEqual(proc_module.env_leaks(env, allow=("PIP_CONFIG_FILE", "PIP_NO_INDEX")),
                             [])
        self.assertFalse(sentinel.exists())


# ==============================================================================
# durable child ownership (runtime follow-up 2)
# ==============================================================================

class TestChildOwnership(Gate0Base):
    """Against production ``state`` and ``proc``, not a test supervisor.

    A role lock that records only the CLI's pid answers "is my parent alive", which
    is not the question. These prove it now answers "is the child I started still
    the process occupying that pid, and is its whole group gone".
    """

    def _spawn(self, seconds: int = 120) -> subprocess.Popen:
        child = subprocess.Popen(["/bin/sh", "-c", f"sleep {seconds}"],  # noqa: S603
                                 start_new_session=True)
        self.addCleanup(lambda: (child.kill(), child.wait()))
        return child

    def test_ownership_records_the_child_group_and_kernel_start_identity(self):
        from cathedral_node import state as run_state
        child = self._spawn()
        lock = run_state.RoleLock("distill", "run-own")
        lock.acquire()
        self.addCleanup(lock.release)
        ownership = lock.claim_child(child.pid, generation="gen-abc", lock_digest="d" * 64)
        self.assertEqual(ownership.child_pid, child.pid)
        self.assertEqual(ownership.pgid, os.getpgid(child.pid))
        self.assertTrue(ownership.start_identity, "the kernel start identity must be recorded")
        self.assertEqual(ownership.euid, os.geteuid())
        self.assertEqual(ownership.generation, "gen-abc")
        stored = run_state.read_ownership("distill")
        self.assertEqual(stored, ownership)
        self.assertTrue(stored.alive())

    def test_a_killed_parent_does_not_permit_a_second_start(self):
        """The orphan is still the holder. Recording only the parent pid meant a
        killed CLI freed the role while its child kept running — and the second
        start would then run two copies of a signed engine at once."""
        from cathedral_node import state as run_state
        child = self._spawn()
        lock = run_state.RoleLock("distill", "run-orphan")
        lock.acquire()
        ownership = lock.claim_child(child.pid)
        # Simulate the CLI parent having died: the record names a parent pid that
        # is not alive, but the CHILD still is.
        record = json.loads(paths.role_lock("distill").read_text())
        record["parent_pid"] = 2 ** 31 - 1
        run_state.write_ownership(run_state.ChildOwnership.parse(record))
        holder = run_state.running_run("distill")
        self.assertIsNotNone(holder, "an orphaned child must still hold the role")
        self.assertEqual(holder["pid"], child.pid)
        # Once the orphan is gone the group is empty — but an empty group is a
        # failed search, not a recorded ending, so the role is still held until an
        # explicit stop resolves the launch.
        child.kill()
        child.wait()
        self.assertIsNotNone(run_state.running_run("distill"),
                             "an unfinished launch must keep the role held")
        stopped, detail = run_state.stop_role("distill")
        self.assertTrue(stopped, detail)
        self.assertIsNone(run_state.running_run("distill"))

    def test_pid_reuse_cannot_resurrect_a_dead_claim(self):
        """A pid is a slot, not an identity. A record whose start identity does not
        match the current occupant must not read as running — otherwise `stop` would
        signal a stranger."""
        from cathedral_node import state as run_state
        child = self._spawn()
        lock = run_state.RoleLock("compute", "run-reuse")
        lock.acquire()
        lock.claim_child(child.pid)
        record = json.loads(paths.role_lock("compute").read_text())
        record["start_identity"] = "Thu Jan  1 00:00:00 1970"   # a different process
        run_state.write_ownership(run_state.ChildOwnership.parse(record))
        holder = run_state.running_run("compute")
        self.assertIsNotNone(holder, "a record naming a reused pid must not read as free")
        self.assertEqual(holder["unresolved"], run_state.OWNERSHIP_UNVERIFIABLE,
                         "a mismatched start identity means the pid was reused")
        self.assertIsNone(holder["pid"], "and nothing about it may be offered as running")
        self.assertTrue(paths.role_lock("compute").exists(),
                        "a record that cannot be understood is not deleted on a guess")

    def test_stop_signals_the_recorded_group_and_waits_for_every_member(self):
        from cathedral_node import state as run_state
        # A parent that spawns a child inside its own new session, so the group has
        # two members and terminating only the parent would leave an orphan.
        parent = subprocess.Popen(  # noqa: S603
            ["/bin/sh", "-c", "sleep 120 & sleep 120"], start_new_session=True)
        self.addCleanup(lambda: (parent.kill(), parent.wait()))
        lock = run_state.RoleLock("validator", "run-group")
        lock.acquire()
        ownership = lock.claim_child(parent.pid)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and len(ownership.group_members()) < 2:
            time.sleep(0.1)
        self.assertGreaterEqual(len(ownership.group_members()), 2,
                                "the fixture must really have a multi-member group")
        stopped, detail = run_state.stop_role("validator", grace=8.0)
        self.assertTrue(stopped, detail)
        self.assertEqual(ownership.group_members(), [],
                         "stop must wait until every process-group member is gone")
        self.assertFalse(paths.role_lock("validator").exists())
        self.assertIsNone(run_state.running_run("validator"))

    def test_stop_refuses_to_signal_a_group_it_cannot_prove_it_owns(self):
        from cathedral_node import state as run_state
        child = self._spawn()
        lock = run_state.RoleLock("distill", "run-foreign")
        lock.acquire()
        lock.claim_child(child.pid)
        record = json.loads(paths.role_lock("distill").read_text())
        record["euid"] = os.geteuid() + 4242
        run_state.write_ownership(run_state.ChildOwnership.parse(record))
        stopped, detail = run_state.stop_role("distill", grace=1.0)
        self.assertFalse(stopped)
        self.assertIn("uid", detail)
        self.assertTrue(child.poll() is None, "the process must not have been signalled")

    def test_a_duplicate_start_is_refused_while_the_child_lives(self):
        from cathedral_node import state as run_state
        child = self._spawn()
        first = run_state.RoleLock("distill", "run-first")
        first.acquire()
        first.claim_child(child.pid)
        second = run_state.RoleLock("distill", "run-second")
        with self.assertRaises(run_state.LockHeld) as caught:
            second.acquire()
        self.assertEqual(caught.exception.pid, child.pid)


# ==============================================================================
# the validator configuration projection (runtime follow-up 3)
# ==============================================================================

class TestValidatorConfigProjection(Gate0Base):

    def test_the_projection_is_parsed_and_its_required_fields_verified(self):
        from cathedral_node.engines.validator import ValidatorEngine
        import tomllib
        engine = ValidatorEngine(self.lock.pin("validator"))
        rendered = engine.render_engine_config(
            {"network": "test", "netuid": 39, "wallet_name": "v", "wallet_hotkey": "h"})
        parsed = tomllib.loads(rendered)
        for section, field in ValidatorEngine.REQUIRED_PROJECTED_FIELDS:
            with self.subTest(field=f"{section}.{field}"):
                self.assertIn(field, parsed.get(section, {}),
                              "an empty base must not silently drop the projection")
        self.assertEqual(parsed["network"]["name"], "test")
        self.assertEqual(parsed["network"]["netuid"], 39)

    def test_a_projection_that_would_not_parse_is_refused_before_anything_is_written(self):
        from cathedral_node.engines.validator import ValidatorEngine
        engine = ValidatorEngine(self.lock.pin("validator"))
        original = ValidatorEngine.REQUIRED_PROJECTED_FIELDS
        ValidatorEngine.REQUIRED_PROJECTED_FIELDS = (("network", "a_field_never_projected"),)
        self.addCleanup(lambda: setattr(ValidatorEngine, "REQUIRED_PROJECTED_FIELDS", original))
        with self.assertRaises(ValueError) as caught:
            engine.render_engine_config({"network": "test", "netuid": 39})
        self.assertIn("missing", str(caught.exception))
        self.assertFalse((paths.config_dir() / "validator-engine.toml").exists(),
                         "a failed render must not have written anything")

    def test_the_derived_configuration_is_written_atomically_and_owner_only(self):
        from cathedral_node.engines.validator import ValidatorEngine
        engine = ValidatorEngine(self.lock.pin("validator"))
        rendered = engine.render_engine_config(
            {"network": "test", "netuid": 39, "wallet_name": "v", "wallet_hotkey": "h"})
        managed = engine.commit_engine_config(rendered)
        self.assertTrue(managed.is_file())
        self.assertEqual(managed.stat().st_mode & 0o777, 0o600)
        self.assertEqual(managed.read_text(), rendered)
        siblings = [p.name for p in managed.parent.iterdir() if p.name.startswith(".tmp.")]
        self.assertEqual(siblings, [], "the atomic write left a staging file behind")

    def test_config_set_validator_refuses_when_no_verified_generation_exists(self):
        """The derived file is read out of the verified generation, so without one
        there is nothing honest to write — and the node config must not be committed
        as though there were."""
        from cathedral_node.commands import config_cmd
        import types as _types
        from cathedral_node import runner
        ctx = runner.Context(
            args=_types.SimpleNamespace(role="validator", field="netuid", value="7"),
            console=runner.build_console(json_mode=True, quiet=True), json_mode=True,
            assume_yes=True, dry_run=False, verbose=False, run_id="cfg", home=self.home)
        envelope = config_cmd.config_set(ctx)
        self.assertNotEqual(envelope.status, "ok")
        self.assertFalse((paths.config_dir() / "validator-engine.toml").exists())


# ==============================================================================
# the publisher fence (runtime follow-up 4)
# ==============================================================================

class TestPublisherFence(Gate0Base):

    def test_two_homes_with_the_same_publisher_identity_cannot_both_hold_it(self):
        from cathedral_node import state as run_state
        first = run_state.PublisherFence(39, "finney:validator-hotkey", run_id="a")
        first.acquire()
        self.addCleanup(first.release)

        other_home = Path(tempfile.mkdtemp(prefix="gate0-other-home-"))
        self.addCleanup(lambda: installer._force_rmtree(other_home))
        saved = os.environ["CATHEDRAL_HOME"]
        os.environ["CATHEDRAL_HOME"] = str(other_home)
        try:
            second = run_state.PublisherFence(39, "finney:validator-hotkey", run_id="b")
            with self.assertRaises(run_state.PublisherBusy) as caught:
                second.acquire()
            self.assertEqual(caught.exception.identity, "39:finney:validator-hotkey")
        finally:
            os.environ["CATHEDRAL_HOME"] = saved

        # A different identity is not fenced against this one.
        other = run_state.PublisherFence(39, "finney:a-different-hotkey", run_id="c")
        other.acquire()
        other.release()

    def test_the_fence_refuses_a_symlinked_or_foreign_fence_file(self):
        from cathedral_node import state as run_state
        fence = run_state.PublisherFence(41, "finney:symlink-test", run_id="x")
        decoy = self.home / "decoy-fence.lock"
        decoy.write_bytes(b"")
        os.chmod(decoy, 0o600)
        fence.path.unlink(missing_ok=True)
        os.symlink(decoy, fence.path)
        self.addCleanup(lambda: fence.path.unlink(missing_ok=True))
        with self.assertRaises(run_state.PublisherBusy):
            fence.acquire()

    def test_the_broadcast_refusal_offers_no_way_around_the_node(self):
        """The refusal used to tell operators to run the engine directly, which is
        precisely the path that holds no fence, no journal and no authorization."""
        import inspect as _inspect
        from cathedral_node.commands import run as run_command
        source = _inspect.getsource(run_command.start)
        self.assertNotIn("run the engine", source.lower())
        self.assertNotIn("directly once you have decided", source.lower())
        self.assertIn("no supported way around", source.lower())


# ==============================================================================
# rollback truth (runtime follow-up 6)
# ==============================================================================

class TestRollbackWitness(ReadinessCase):

    def test_a_failed_prior_restart_leaves_recovery_still_required(self):
        """The failure this prevents: publishing the prior pointer, then failing to
        restart, leaves a pointer that reads as a healthy committed group. The next
        `cathedral recover` says "nothing to recover" about a node whose role never
        came back."""
        plan = self.serving_plan()
        ok, detail, _ = self.install_serving("witness-v1", 1, plan)
        self.assertTrue(ok, detail)
        v1 = self.pointer_doc()
        ok, detail, _ = self.install_serving("witness-v2", 2, plan)
        self.assertTrue(ok, detail)
        v2 = self.pointer_doc()

        # The realistic crash: pending v2, floor still at v1, and v2 unverifiable.
        self.write_pointer({**v2, "state": "pending"})
        self.write_floor(v1["release_version"], v1["lock_digest"])
        installer._force_rmtree(paths.retained_releases_dir() / v2["lock_digest"])

        class FailsToRestart:
            def __init__(self):
                self.started = []

            def running_roles(self):
                return []

            def stop(self, roles):
                pass

            def start(self, group, roles):
                self.started.append(list(roles))

            def readiness(self, roles):
                return False, "the prior release did not come back up"

        # A real, live role so the supervisor path is taken, then stopped by the
        # supervisor's own `stop` so termination IS provable — the failure under
        # test is the RESTART, not the stop.
        child = subprocess.Popen(["/bin/sh", "-c", "sleep 60"])  # noqa: S603
        self.addCleanup(lambda: (child.kill(), child.wait()))
        _write_role_lock("distill", child.pid)
        self.addCleanup(lambda: _clear_role_lock("distill"))

        class StopsThenFails(FailsToRestart):
            def stop(self, roles):
                child.kill()
                child.wait()
                _clear_role_lock("distill")

        supervisor = StopsThenFails()
        ok, detail = installer.recover(self.lock, supervisor=supervisor)
        self.assertFalse(ok, "a prior that cannot be restarted is not a successful rollback")
        self.assertIn("recovery is still required", detail)
        self.assertTrue(supervisor.started, "the prior group was started before readiness failed")

        # The witness survives: the pointer is still the interrupted transaction, so
        # recovery still has something to do and says so.
        self.assertTrue(paths.recovery_required(),
                        "the interrupted transaction must remain recorded")
        self.assertEqual(self.pointer_doc()["state"], "pending")
        entry = json.loads(paths.rollback_ledger().read_text().splitlines()[-1])
        self.assertEqual(entry["outcome"], "restart_failed")

    def test_update_does_not_claim_the_prior_release_was_kept_when_recovery_is_pending(self):
        import inspect as _inspect
        from cathedral_node.commands import update as update_command
        source = _inspect.getsource(update_command.update)
        self.assertIn("an interrupted transaction is still recorded", source)
        self.assertIn("recovery_required", source)


# ==============================================================================
# atomicity counterexample 1: the revocation floor after a partial commit
# ==============================================================================

class TestRevocationPartialCommitRecovery(Gate0Base):
    """The cache and the floor are two files, so a crash can land between them.

    The dangerous state is not the crash — it is what the node believes afterwards.
    Cache 11 sitting above floor 9 means the snapshot the floor still names would be
    accepted again if anyone restored it, and the retry that should have healed the
    floor was being rejected as a digest conflict against the wrong sequence.

    Every step below runs in a **fresh interpreter** against the same
    ``CATHEDRAL_HOME``. In-process state would prove nothing about a crash: the
    whole question is what survives on disk and what a new process concludes from
    it.
    """

    def _snapshot(self, sequence: int, **kw) -> tuple[bytes, bytes]:
        return self.fx.revocation_snapshot(sequence, **kw)

    def _in_fresh_interpreter(self, body: str) -> dict:
        """Run ``body`` in a new process against this node, and return its verdict."""
        script = (
            "import json, os, sys, datetime as dt\n"
            f"sys.path.insert(0, {str(Path.cwd())!r})\n"
            "from cathedral_node import paths, revocation, safeio\n"
            "now = dt.datetime.now(dt.timezone.utc)\n"
            "out = {}\n"
            f"{body}\n"
            "print('RESULT:' + json.dumps(out))\n")
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", script], capture_output=True, text=True,
            env={**os.environ, "CATHEDRAL_HOME": str(self.home),
                 "CATHEDRAL_REVOCATION_SIGNERS": str(self.fx.revocation_signers)},
            timeout=120)
        self.assertEqual(result.returncode, 0,
                         f"the fresh interpreter failed:\n{result.stdout}\n{result.stderr}")
        line = next(l for l in result.stdout.splitlines() if l.startswith("RESULT:"))
        return json.loads(line[len("RESULT:"):])

    def _stage(self, raw: bytes, signature: bytes) -> None:
        """Publish ONLY the cache, exactly as a crash before the floor write would."""
        from cathedral_node import safeio
        safeio.secure_write_atomic(revocation.cache_file(),
                                   revocation._encode_cache(raw, signature))

    def test_a_crash_between_cache_and_floor_heals_on_retry_and_never_readmits_the_old_sequence(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw9, sig9 = self._snapshot(9)
        raw11, sig11 = self._snapshot(11)
        raw11_other, sig11_other = self._snapshot(11, revoked_releases=["a" * 64])
        self.assertNotEqual(raw11, raw11_other, "the two sequence-11 snapshots must differ")

        # --- the starting state: sequence 9 accepted and floored ---------------
        ok, reason, state = revocation.retain(raw9, sig9, now=now)
        self.assertTrue(ok, reason)
        self.assertEqual(state.sequence, 9)
        floor = revocation.floor_state()[1]
        self.assertEqual(floor[0], 9)
        digest9 = floor[1]

        # --- the crash: the sequence 11 cache lands, the floor write never does -
        self._stage(raw11, sig11)
        self.assertEqual(revocation.floor_state()[1], (9, digest9),
                         "the fixture must really leave the floor behind")

        # --- a fresh interpreter still accepts sequence 11 ---------------------
        verdict = self._in_fresh_interpreter(
            "ok, reason, st = revocation.load_retained(now=now)\n"
            "out['ok'] = ok; out['reason'] = reason\n"
            "out['sequence'] = st.sequence if st else None\n"
            "out['floor'] = revocation.floor_state()[1]")
        self.assertTrue(verdict["ok"], verdict["reason"])
        self.assertEqual(verdict["sequence"], 11,
                         "the durably written sequence 11 snapshot must remain accepted")

        # --- the retry of the IDENTICAL sequence 11 heals the floor ------------
        # This is the exact rejection the defect produced: the candidate was
        # compared against the *floor's* digest (sequence 9) instead of the digest
        # belonging to the highest sequence actually on disk.
        retry = self._in_fresh_interpreter(
            "raw = revocation._decode_cache(open(revocation.cache_file(),'rb').read())\n"
            "ok, reason, st = revocation.retain(raw[0], raw[1], now=now)\n"
            "out['ok'] = ok; out['reason'] = reason\n"
            "out['floor'] = revocation.floor_state()[1]")
        self.assertTrue(retry["ok"], f"an identical retry must heal, not conflict: {retry['reason']}")
        self.assertEqual(retry["floor"][0], 11, "the floor must heal from 9 to 11")
        digest11 = retry["floor"][1]

        # --- a DIFFERENT sequence 11 is still refused --------------------------
        other = self.home / "other11.json"
        other.write_bytes(raw11_other)
        other_sig = self.home / "other11.sig"
        other_sig.write_bytes(sig11_other)
        rejected = self._in_fresh_interpreter(
            f"raw = open({str(other)!r},'rb').read(); sig = open({str(other_sig)!r},'rb').read()\n"
            "ok, reason, st = revocation.retain(raw, sig, now=now)\n"
            "out['ok'] = ok; out['reason'] = reason\n"
            "out['floor'] = revocation.floor_state()[1]")
        self.assertFalse(rejected["ok"], "a different snapshot at the retained sequence must fail")
        self.assertEqual(rejected["floor"], [11, digest11],
                         "a refused candidate must not move the floor")

        # --- restoring the old, perfectly valid sequence 9 cache stays refused --
        old = self.home / "old9.cache"
        old.write_bytes(revocation._encode_cache(raw9, sig9))
        restored = self._in_fresh_interpreter(
            "from cathedral_node import safeio\n"
            f"safeio.secure_write_atomic(revocation.cache_file(), open({str(old)!r},'rb').read())\n"
            "ok, reason, st = revocation.load_retained(now=now)\n"
            "out['ok'] = ok; out['reason'] = reason\n"
            "out['floor'] = revocation.floor_state()[1]")
        self.assertFalse(restored["ok"],
                         "sequence 9 must never be readmitted after 11 was durably observed")
        self.assertIn("below the durable revocation floor", restored["reason"])

        # --- and again after another restart -----------------------------------
        again = self._in_fresh_interpreter(
            "ok, reason, st = revocation.load_retained(now=now)\n"
            "out['ok'] = ok; out['reason'] = reason\n"
            "out['floor'] = revocation.floor_state()[1]")
        self.assertFalse(again["ok"], "the refusal must survive a restart, not be a one-off")
        self.assertEqual(again["floor"][0], 11)

    def test_a_floor_and_cache_that_disagree_at_the_highest_sequence_fail_closed(self):
        """Healing must never become guessing. If both files claim the same highest
        sequence with different digests, one of them is forged and the node cannot
        tell which."""
        now = dt.datetime.now(dt.timezone.utc)
        raw11, sig11 = self._snapshot(11)
        ok, reason, _ = revocation.retain(raw11, sig11, now=now)
        self.assertTrue(ok, reason)
        # Rewrite the floor with the same sequence and a different digest.
        revocation._write_floor(11, "b" * 64)
        raw_other, sig_other = self._snapshot(11, revoked_releases=["c" * 64])
        ok, reason, _ = revocation.retain(raw_other, sig_other, now=now)
        self.assertFalse(ok)
        self.assertIn("different digests", reason)
        ok, reason, _ = revocation.load_retained(now=now)
        self.assertFalse(ok, "a cache that disagrees with the floor at one sequence is refused")

    def test_healing_only_ever_raises_the_floor(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw12, sig12 = self._snapshot(12)
        self.assertTrue(revocation.retain(raw12, sig12, now=now)[0])
        self.assertEqual(revocation.floor_state()[1][0], 12)
        # A lower cache cannot pull the floor down, on the healing path or any other.
        raw5, sig5 = self._snapshot(5)
        self._stage(raw5, sig5)
        ok, reason, _ = revocation.load_retained(now=now, heal=True)
        self.assertFalse(ok)
        self.assertEqual(revocation.floor_state()[1][0], 12,
                         "healing must never lower the floor")


# ==============================================================================
# atomicity counterexample 2: an orphaned process group blocks deletion
# ==============================================================================

class TestOrphanedProcessGroupBlocksDeletion(Gate0Base):
    """A launcher dies; a descendant does not.

    The ownership record's leader is gone, so every leader-only check calls this
    "not running" — and then a prune or an uninstall deletes the generation the
    descendant is still executing out of. These drive the real `proc.stream`
    launcher, the real ownership record, and the public `install_release` and
    `uninstall` paths. No fixture supervisor decides any of the answers.
    """

    def _launch_through_production(self, role: str, generation: str = "",
                                   lock_digest: str = ""):
        """Start a role through the real launcher in a real launcher PROCESS, then
        kill that process — which is what "the launcher parent exits or crashes"
        actually means.

        It has to be a separate process. `proc.stream` returns only once every
        descendant has closed the child's stdout, so calling it in-process would
        block until the descendant exited, and the state under test — launcher gone,
        descendant alive — would never exist. Killing a real launcher produces it
        exactly: the ownership record is on disk, the recorded leader has exited on
        its own, and a descendant is still running.
        """
        from cathedral_node import state as run_state
        script = (
            "import os, sys\n"
            f"sys.path.insert(0, {str(Path.cwd())!r})\n"
            f"os.environ['CATHEDRAL_HOME'] = {str(self.home)!r}\n"
            "from cathedral_node import proc, state as run_state\n"
            f"lock = run_state.RoleLock({role!r}, 'run-{role}')\n"
            "lock.acquire()\n"
            "def own(child):\n"
            f"    lock.claim_child(child.pid, generation={generation!r}, "
            f"lock_digest={lock_digest!r})\n"
            "    print('OWNED', flush=True)\n"
            "proc.stream(['/bin/sh', '-c', 'sleep 90 & sleep 0.4'], on_line=lambda l: None,\n"
            f"            inherit_env=False, env=proc.signed_child_env(home={str(self.home)!r}),\n"
            "            on_start=own)\n")
        launcher = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env={**os.environ, "CATHEDRAL_HOME": str(self.home)})
        self.addCleanup(lambda: _force_clear_role(role))
        self.addCleanup(lambda: (launcher.kill(), launcher.wait()))

        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            line = launcher.stdout.readline()
            if line.strip() == "OWNED":
                break
            if launcher.poll() is not None:
                self.fail(f"the launcher exited before publishing ownership: "
                          f"{launcher.stderr.read()[:400]}")
        else:
            self.fail("the launcher never published ownership")

        # Kill ONLY the launcher. The child is in its own session, so it survives.
        launcher.kill()
        launcher.wait(timeout=10)

        ownership = run_state.read_ownership(role)
        self.assertIsNotNone(ownership, "the launcher must have left a durable record")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and ownership.leader_alive():
            time.sleep(0.1)
        self.assertFalse(ownership.leader_alive(),
                         "the fixture must really have killed the recorded leader")
        self.assertTrue(ownership.group_members(),
                        "the fixture must really have left a live descendant")
        return ownership, ownership.pgid

    def test_a_live_descendant_of_a_dead_leader_still_owns_the_generation(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("orphan-own"))
        self.assertTrue(ok, detail)
        pointer = self.pointer_doc()
        ownership, _pgid = self._launch_through_production(
            "distill", generation=pointer["generations"]["distill"],
            lock_digest=pointer["lock_digest"])

        self.assertFalse(ownership.leader_alive())
        self.assertTrue(ownership.alive(),
                        "ownership is the process GROUP, not the one pid we happened to name")
        verdict, _own, detail = run_state.ownership_status("distill")
        self.assertEqual(verdict, run_state.OWNERSHIP_LIVE, detail)
        blocked, reason = run_state.deletion_blocked("distill")
        self.assertTrue(blocked, "a live descendant must block deletion")
        self.assertIn("live", reason)
        self.assertIsNotNone(run_state.running_run("distill"),
                             "the role must still read as held")

    def test_uninstall_refuses_while_a_descendant_of_a_dead_leader_lives(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("orphan-uninstall"))
        self.assertTrue(ok, detail)
        pointer = self.pointer_doc()
        generation_dir = self.generation_dir("compute", pointer)
        ownership, pgid = self._launch_through_production(
            "compute", generation=pointer["generations"]["compute"])

        # Clear the pointer so the ONLY thing that can refuse is live ownership.
        paths.active_release_pointer().unlink()
        removed, reason = installer.uninstall("compute")
        self.assertFalse(removed, "uninstall must refuse while a descendant lives")
        self.assertIn("live", reason)
        self.assertTrue(generation_dir.is_dir(),
                        "the generation a live process is executing must survive")

        # Stop the whole owned group, prove termination, and only then may it go.
        stopped, detail = run_state.stop_role("compute", grace=8.0)
        self.assertTrue(stopped, detail)
        self.assertEqual(run_state.process_group_members(pgid), [])
        blocked, _reason = run_state.deletion_blocked("compute")
        self.assertFalse(blocked, "with the group proven stopped, deletion is permitted")
        removed, detail = installer.uninstall("compute")
        self.assertTrue(removed, detail)
        self.assertFalse(paths.engine_dir("compute").exists())

    def test_install_refuses_to_proceed_and_prunes_nothing_while_a_descendant_lives(self):
        ok, detail, _ = self.install(self.bundle("orphan-prune-1", 1))
        self.assertTrue(ok, detail)
        first = self.pointer_doc()
        ok, detail, _ = self.install(self.bundle("orphan-prune-2", 2))
        self.assertTrue(ok, detail)
        before = self.weakening_snapshot()

        owned_generation = first["generations"]["distill"]
        self._launch_through_production("distill", generation=owned_generation)

        # The public install path. A third release would normally prune older
        # generations; it must not get that far, and nothing that exists may be
        # removed, while a descendant is still executing one of them.
        ok, detail, _ = self.install(self.bundle("orphan-prune-3", 3))
        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("distill", detail)

        after = self.weakening_snapshot()
        self.assertIn(owned_generation, after["generations"]["distill"],
                      "the generation a live descendant is executing must survive")
        for role in ROLES:
            self.assertTrue(set(before["generations"][role]) <= set(after["generations"][role]),
                            f"a refused install pruned {role} generations that already existed")
        # The pointer is left PENDING, which is the fail-closed answer rather than a
        # lapse: the rollback could not prove the descendant gone, so the
        # interrupted transaction stays recorded and recovery is required. What must
        # not have happened is a commit, or a deletion.
        self.assertNoWeakening(before, generations_may_change=True, pointer_may_change=True)
        current = self.pointer_doc()
        self.assertEqual(current["state"], "pending")
        self.assertTrue(paths.recovery_required())
        ok, _reason, group = self.verify_active()
        self.assertFalse(ok, "a pending pointer must never verify as an active group")
        self.assertIsNone(group)

    def test_an_ownership_publication_failure_terminates_the_group_before_returning(self):
        """The one interval where signed code runs with nothing on disk owning it.

        If the record cannot be published, the child must not survive the attempt —
        otherwise the orphan every later refusal depends on noticing is invisible.
        """
        seen: dict = {}

        def failing_publication(child) -> None:
            seen["pid"] = child.pid
            seen["pgid"] = os.getpgid(child.pid)
            raise OSError("injected ownership publication failure")

        with self.assertRaises(OSError):
            proc_module.stream(["/bin/sh", "-c", "sleep 60 & sleep 60"],
                               on_line=lambda _l: None, inherit_env=False,
                               env=proc_module.signed_child_env(home=self.home),
                               on_start=failing_publication)
        from cathedral_node import state as run_state
        self.assertIn("pgid", seen, "the child must really have been spawned")
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and run_state.process_group_members(seen["pgid"]):
            time.sleep(0.1)
        self.assertEqual(run_state.process_group_members(seen["pgid"]), [],
                         "a failed ownership publication must leave no live process behind")
        self.assertFalse(paths.role_lock("distill").exists())

    def test_a_malformed_ownership_record_fails_closed_against_deletion(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("orphan-malformed"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()
        record = paths.role_lock("validator")
        record.parent.mkdir(parents=True, exist_ok=True)
        record.write_text("{ this is not json")
        os.chmod(record, 0o600)
        self.addCleanup(lambda: record.unlink(missing_ok=True))

        verdict, _own, detail = run_state.ownership_status("validator")
        self.assertEqual(verdict, run_state.OWNERSHIP_UNVERIFIABLE, detail)
        blocked, reason = run_state.deletion_blocked("validator")
        self.assertTrue(blocked, "a record that cannot be read must not be assumed harmless")
        removed, reason = installer.uninstall("validator")
        self.assertFalse(removed)
        self.assertTrue(paths.engine_dir("validator").exists())
        # And a stop cannot silently "resolve" it by guessing either.
        stopped, detail = run_state.stop_role("validator")
        self.assertFalse(stopped)
        self.assertTrue(record.exists(), "an unreadable record must not be deleted on a guess")

    def test_a_pre_reboot_record_never_authorises_signalling_or_deletion(self):
        """`ps -o lstart=` has one-second resolution and no idea a reboot happened.
        A boot identity is what stops a recycled pid or pgid from satisfying an
        ownership check made before the machine restarted."""
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("orphan-reboot"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()

        bystander = subprocess.Popen(["/bin/sh", "-c", "sleep 45"],  # noqa: S603
                                     start_new_session=True)
        self.addCleanup(lambda: (bystander.kill(), bystander.wait()))
        # The whole launch belongs to the previous boot — the durable lease as much
        # as the role record. Backdating only the record would leave a lease from
        # *this* boot naming a pgid a stranger now holds, which is a different
        # scenario (and one the lease tests cover on its own).
        previous_boot = "kern.boottime:{ sec = 1, usec = 0 }"
        real_boot = run_state.boot_identity
        run_state.boot_identity = lambda: previous_boot
        try:
            lock = run_state.RoleLock("distill", "run-reboot")
            lock.acquire()
            lock.claim_child(bystander.pid)
        finally:
            run_state.boot_identity = real_boot
        record = json.loads(paths.role_lock("distill").read_text())
        self.assertEqual(record["boot_id"], previous_boot)

        verdict, ownership, detail = run_state.ownership_status("distill")
        self.assertEqual(verdict, run_state.OWNERSHIP_STALE_BOOT, detail)
        self.assertFalse(ownership.alive(),
                         "a pre-reboot record must never read as a live owned process")
        self.assertEqual(ownership.group_members(), [],
                         "pids from a previous boot are not members of anything we own")
        blocked, reason = run_state.deletion_blocked("distill")
        self.assertTrue(blocked, "a stale record must not authorize deletion either")
        removed, _reason = installer.uninstall("distill")
        self.assertFalse(removed)

        # Stopping resolves it — by clearing the record, never by signalling numbers
        # that now belong to somebody else.
        stopped, detail = run_state.stop_role("distill")
        self.assertTrue(stopped, detail)
        self.assertIsNone(bystander.poll(),
                          "a process from this boot must never be signalled by a stale record")
        blocked, _reason = run_state.deletion_blocked("distill")
        self.assertFalse(blocked, "once cleared, deletion may proceed")
        removed, detail = installer.uninstall("distill")
        self.assertTrue(removed, detail)

    def test_releasing_the_role_lock_keeps_the_record_while_descendants_live(self):
        from cathedral_node import state as run_state
        lock = run_state.RoleLock("compute", "run-release")
        lock.acquire()
        self.addCleanup(lambda: _force_clear_role("compute"))
        child = subprocess.Popen(["/bin/sh", "-c", "sleep 45 & sleep 0.4"],  # noqa: S603
                                 start_new_session=True)
        ownership = lock.claim_child(child.pid)
        child.wait()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not ownership.group_members():
            time.sleep(0.1)
        self.assertTrue(ownership.group_members())
        lock.release()
        self.assertTrue(paths.role_lock("compute").exists(),
                        "releasing must not discard the only record of a live descendant")
        blocked, _reason = run_state.deletion_blocked("compute")
        self.assertTrue(blocked)
        self.assertTrue(run_state.stop_role("compute", grace=8.0)[0])
        self.assertFalse(paths.role_lock("compute").exists())


def _pid_is_live(pid: int) -> bool:
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _force_clear_role(role: str) -> None:
    """Test teardown: stop whatever the role owns, then drop its record."""
    from cathedral_node import state as run_state
    with contextlib.suppress(Exception):
        ownership = run_state.read_ownership(role)
        if ownership is not None and ownership.pgid > 0:
            with contextlib.suppress(OSError):
                os.killpg(ownership.pgid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        paths.role_lock(role).unlink()


# ==============================================================================
# revocation: the transaction must not report success it did not achieve
# ==============================================================================

class TestRevocationHealFailsClosed(Gate0Base):

    def test_failed_floor_heal_fails_closed_and_never_readmits_the_old_cache(self):
        """A heal that could not be written must not be reported as success.

        Cache 11 above floor 9 is only safe once the floor actually moves. Returning
        ok while the write failed leaves the caller authorized on sequence 11 with
        durable protection still at 9 — so restoring the sequence 9 cache re-admits
        it, which is the exact rollback the floor exists to prevent.
        """
        now = dt.datetime.now(dt.timezone.utc)
        raw9, sig9 = self.fx.revocation_snapshot(9)
        self.assertTrue(revocation.retain(raw9, sig9, now=now)[0])
        raw11, sig11 = self.fx.revocation_snapshot(11)
        self.fx.stage_revocation_cache(raw11, sig11)

        original = revocation._write_floor

        def failing(*_a, **_kw):
            raise OSError("injected floor write failure")

        revocation._write_floor = failing
        try:
            ok, reason, state = revocation.load_retained(now=now, heal=True)
            self.assertFalse(ok, "an unhealable floor must not be reported as usable state")
            self.assertIsNone(state)
            self.assertIn("could not be advanced", reason)
            # And the policy gate that sits on top of it refuses too.
            gate_ok, gate_reason, _ = revocation.enforce(
                "a" * 64, self.fx.signers.read_text(), IDENTITY, now=now,
                policy=revocation.RETAINED_RUNTIME)
            self.assertFalse(gate_ok, gate_reason)
        finally:
            revocation._write_floor = original

        # The floor never moved, so sequence 9 is still what it names — and with the
        # heal refused, nothing ever claimed otherwise.
        self.assertEqual(revocation.floor_state()[1][0], 9)

    def test_a_lock_that_cannot_be_taken_also_fails_closed(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw9, sig9 = self.fx.revocation_snapshot(9)
        self.assertTrue(revocation.retain(raw9, sig9, now=now)[0])
        raw11, sig11 = self.fx.revocation_snapshot(11)
        self.fx.stage_revocation_cache(raw11, sig11)
        # A lock file that cannot be trusted: the heal cannot be serialised, so it
        # cannot be performed, so the read cannot claim success.
        lock_path = revocation.transaction_lock()
        lock_path.unlink(missing_ok=True)
        decoy = self.home / "decoy-revocation.lock"
        decoy.write_bytes(b"")
        os.chmod(decoy, 0o600)
        os.symlink(decoy, lock_path)
        self.addCleanup(lambda: lock_path.unlink(missing_ok=True))
        ok, reason, state = revocation.load_retained(now=now, heal=True)
        self.assertFalse(ok, reason)
        self.assertIsNone(state)


class TestRevocationProvisioningTransaction(Gate0Base):
    """Provisioning is a retention, not a shortcut past one."""

    def test_provisioning_refuses_a_different_digest_at_the_floor_sequence(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw, sig = self.fx.revocation_snapshot(7)
        state = revocation.install_cache(raw, sig, now=now)
        self.assertEqual(state.sequence, 7)
        floor = revocation.floor_state()[1]
        self.assertEqual(floor[0], 7)

        other_raw, other_sig = self.fx.revocation_snapshot(7, revoked_releases=["d" * 64])
        self.assertNotEqual(other_raw, raw)
        with self.assertRaises(revocation.RevocationError) as caught:
            revocation.install_cache(other_raw, other_sig, now=now)
        self.assertIn("different revocation snapshot", str(caught.exception))
        self.assertEqual(revocation.floor_state()[1], floor,
                         "a refused provisioning must not move the floor")

    def test_provisioning_refuses_unverified_bytes(self):
        now = dt.datetime.now(dt.timezone.utc)
        floor_before = revocation.floor_state()[1]
        raw, sig = self.fx.revocation_snapshot(3)
        with self.assertRaises(revocation.RevocationError):
            revocation.install_cache(raw, sig[:-8], now=now)
        self.assertEqual(revocation.floor_state()[1], floor_before,
                         "unverified bytes must never become the last known good snapshot")
        ok, reason, state = revocation.load_retained(now=now)
        self.assertTrue(ok, reason)
        self.assertNotEqual(state.sequence, 3, "the refused snapshot must not be retained")

    def test_concurrent_provisioning_never_lowers_the_revocation_floor(self):
        now = dt.datetime.now(dt.timezone.utc)
        high_raw, high_sig = self.fx.revocation_snapshot(12)
        low_raw, low_sig = self.fx.revocation_snapshot(11)
        results: list[tuple[str, bool]] = []
        barrier = threading.Barrier(2, timeout=30)

        def provision(label, raw, sig):
            barrier.wait()
            try:
                revocation.install_cache(raw, sig, now=now)
                results.append((label, True))
            except revocation.RevocationError:
                results.append((label, False))

        threads = [threading.Thread(target=provision, args=("high", high_raw, high_sig)),
                   threading.Thread(target=provision, args=("low", low_raw, low_sig))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(60)

        floor = revocation.floor_state()[1]
        self.assertIsNotNone(floor)
        self.assertGreaterEqual(floor[0], 11)
        if dict(results).get("high"):
            self.assertEqual(floor[0], 12,
                             "once sequence 12 is accepted the floor may never fall back to 11")
        ok, reason, state = revocation.load_retained(now=now)
        self.assertTrue(ok, reason)
        self.assertEqual(state.sequence, floor[0],
                         "the retained cache and the floor must agree after the race")

    def test_different_equal_sequence_is_refused_before_partial_commit_healing(self):
        """The refusal must come first. A forgery at the retained sequence must not
        be able to move the floor on its way to being rejected."""
        now = dt.datetime.now(dt.timezone.utc)
        raw9, sig9 = self.fx.revocation_snapshot(9)
        self.assertTrue(revocation.retain(raw9, sig9, now=now)[0])
        raw11, sig11 = self.fx.revocation_snapshot(11)
        self.fx.stage_revocation_cache(raw11, sig11)
        floor_before = revocation.floor_state()[1]
        self.assertEqual(floor_before[0], 9, "the fixture must leave the floor lagging")

        forged_raw, forged_sig = self.fx.revocation_snapshot(11, revoked_releases=["e" * 64])
        writes: list = []
        original = revocation._write_floor

        def watching(*a, **kw):
            writes.append(a)
            return original(*a, **kw)

        revocation._write_floor = watching
        try:
            ok, reason, _ = revocation.retain(forged_raw, forged_sig, now=now)
        finally:
            revocation._write_floor = original
        self.assertFalse(ok)
        self.assertIn("different revocation snapshot", reason)
        self.assertEqual(writes, [], "a refused candidate must not reach the floor write at all")
        self.assertEqual(revocation.floor_state()[1], floor_before)


class TestRevocationFloorAheadOfCache(Gate0Base):

    def test_exact_floor_snapshot_repairs_a_restored_older_cache_or_returns_failure(self):
        """Floor 11, cache 9, and the authentic sequence 11 offered back.

        Reporting "already current" was wrong twice over: the only cache on disk was
        a sequence 9 snapshot the floor refuses, so the node had NO usable revocation
        state, and the caller was told everything was fine while holding None.
        """
        now = dt.datetime.now(dt.timezone.utc)
        raw11, sig11 = self.fx.revocation_snapshot(11)
        self.assertTrue(revocation.retain(raw11, sig11, now=now)[0])
        floor = revocation.floor_state()[1]
        self.assertEqual(floor[0], 11)

        # Someone restores the older, perfectly valid sequence 9 cache.
        raw9, sig9 = self.fx.revocation_snapshot(9)
        self.fx.stage_revocation_cache(raw9, sig9)
        ok, reason, _ = revocation.load_retained(now=now)
        self.assertFalse(ok, "the restored older cache must be refused")

        # Offering the authentic snapshot the floor names must REPAIR the cache.
        ok, reason, state = revocation.retain(raw11, sig11, now=now)
        self.assertTrue(ok, reason)
        self.assertIsNotNone(state, "a successful repair must return the state it restored")
        self.assertEqual(state.sequence, 11)
        self.assertIn("restored", reason)

        ok, reason, state = revocation.load_retained(now=now)
        self.assertTrue(ok, f"the node must have usable revocation state again: {reason}")
        self.assertEqual(state.sequence, 11)
        self.assertEqual(revocation.floor_state()[1], floor)

    def test_a_wrong_snapshot_offered_against_a_higher_floor_is_still_refused(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw11, sig11 = self.fx.revocation_snapshot(11)
        self.assertTrue(revocation.retain(raw11, sig11, now=now)[0])
        raw9, sig9 = self.fx.revocation_snapshot(9)
        self.fx.stage_revocation_cache(raw9, sig9)
        forged_raw, forged_sig = self.fx.revocation_snapshot(11, revoked_releases=["f" * 64])
        ok, reason, _ = revocation.retain(forged_raw, forged_sig, now=now)
        self.assertFalse(ok, "only the snapshot the floor actually names may repair the cache")
        cached = revocation._decode_cache(revocation.cache_file().read_bytes())
        self.assertEqual(cached[0], raw9, "a refused repair must not touch the cache")


# ==============================================================================
# ownership: probes, boot identity, and pid reuse
# ==============================================================================

class TestOwnershipProbeFailure(Gate0Base):
    """"I could not ask" is not "nothing is running"."""

    def _break_probe(self):
        from cathedral_node import state as run_state
        original = run_state.process_group_members

        def failing(_pgid):
            raise run_state.ProbeUnavailable("the process table could not be read")

        run_state.process_group_members = failing
        self.addCleanup(lambda: setattr(run_state, "process_group_members", original))

    def _owned_role(self, role: str) -> object:
        from cathedral_node import state as run_state
        child = subprocess.Popen(["/bin/sh", "-c", "sleep 45"], start_new_session=True)  # noqa: S603
        self.addCleanup(lambda: (child.kill(), child.wait()))
        lock = run_state.RoleLock(role, f"run-{role}")
        lock.acquire()
        self.addCleanup(lambda: paths.role_lock(role).unlink(missing_ok=True))
        return lock.claim_child(child.pid)

    def test_group_probe_failure_blocks_prune_and_uninstall(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("probe-fail"))
        self.assertTrue(ok, detail)
        self._owned_role("compute")
        paths.active_release_pointer().unlink()
        self._break_probe()

        verdict, _own, detail = run_state.ownership_status("compute")
        self.assertEqual(verdict, run_state.OWNERSHIP_UNVERIFIABLE, detail)
        blocked, reason = run_state.deletion_blocked("compute")
        self.assertTrue(blocked, "a failed probe must never authorize deletion")
        removed, reason = installer.uninstall("compute")
        self.assertFalse(removed, "uninstall must refuse when the process table cannot be read")
        self.assertTrue(paths.engine_dir("compute").exists())

    def test_group_probe_failure_never_reports_stop_complete_or_removes_ownership(self):
        from cathedral_node import state as run_state
        self._owned_role("distill")
        self._break_probe()
        stopped, detail = run_state.stop_role("distill", grace=2.0)
        self.assertFalse(stopped, "a stop that cannot be verified must not report completion")
        self.assertIn("probe", detail)
        self.assertTrue(paths.role_lock("distill").exists(),
                        "an unverifiable stop must not delete the ownership record")


class TestOwnershipBootIdentity(Gate0Base):

    def test_unavailable_boot_identity_is_unverifiable_and_cannot_be_cleared(self):
        """Unknown is not stale. Treating it as stale let `stop` delete a record that
        may describe live processes, purely because the boot probe failed."""
        from cathedral_node import state as run_state
        child = subprocess.Popen(["/bin/sh", "-c", "sleep 45"], start_new_session=True)  # noqa: S603
        self.addCleanup(lambda: (child.kill(), child.wait()))
        lock = run_state.RoleLock("validator", "run-boot")
        lock.acquire()
        lock.claim_child(child.pid)
        self.addCleanup(lambda: paths.role_lock("validator").unlink(missing_ok=True))

        original = run_state.boot_identity
        run_state.boot_identity = lambda: ""
        self.addCleanup(lambda: setattr(run_state, "boot_identity", original))

        verdict, _own, detail = run_state.ownership_status("validator")
        self.assertEqual(verdict, run_state.OWNERSHIP_UNVERIFIABLE, detail)
        self.assertNotEqual(verdict, run_state.OWNERSHIP_STALE_BOOT)
        blocked, _reason = run_state.deletion_blocked("validator")
        self.assertTrue(blocked)
        stopped, detail = run_state.stop_role("validator")
        self.assertFalse(stopped, "an unknown boot identity must not authorize clearing")
        self.assertTrue(paths.role_lock("validator").exists())
        self.assertIsNone(child.poll(), "and nothing may be signalled on an unknown boot")

    def test_a_known_previous_boot_is_stale_rather_than_unverifiable(self):
        from cathedral_node import state as run_state
        child = subprocess.Popen(["/bin/sh", "-c", "sleep 30"], start_new_session=True)  # noqa: S603
        self.addCleanup(lambda: (child.kill(), child.wait()))
        # The whole launch belongs to the previous boot — the durable lease as much
        # as the role record. A lease left in *this* boot would name a pgid a live
        # process still occupies, which is a different scenario entirely.
        previous_boot = "kern.boottime:{ sec = 1, usec = 0 }"
        real_boot = run_state.boot_identity
        run_state.boot_identity = lambda: previous_boot
        try:
            lock = run_state.RoleLock("compute", "run-oldboot")
            lock.acquire()
            lock.claim_child(child.pid)
        finally:
            run_state.boot_identity = real_boot
        self.assertEqual(json.loads(paths.role_lock("compute").read_text())["boot_id"],
                         previous_boot)
        verdict, _own, _detail = run_state.ownership_status("compute")
        self.assertEqual(verdict, run_state.OWNERSHIP_STALE_BOOT)
        self.assertTrue(run_state.stop_role("compute")[0], "a known previous boot can be cleared")
        self.assertIsNone(child.poll(), "clearing must never signal a process from this boot")
        self.assertEqual(run_state.open_leases("compute")[0], [],
                         "and the lease from that boot must be retired, not left open")


class TestOwnershipPidReuse(Gate0Base):

    def _record_with(self, role: str, **changes) -> object:
        from cathedral_node import state as run_state
        child = subprocess.Popen(["/bin/sh", "-c", "sleep 45 & sleep 45"],  # noqa: S603
                                 start_new_session=True)
        self.addCleanup(lambda: (child.kill(), child.wait()))
        lock = run_state.RoleLock(role, f"run-{role}")
        lock.acquire()
        self.addCleanup(lambda: paths.role_lock(role).unlink(missing_ok=True))
        lock.claim_child(child.pid)
        record = json.loads(paths.role_lock(role).read_text())
        record.update(changes)
        run_state.write_ownership(run_state.ChildOwnership.parse(record))
        return child

    def test_start_identity_mismatch_never_becomes_live_owned_from_pgid_membership(self):
        """The leader pid is in use by something else, and the stored group has
        members. Treating those members as ours was how a stop came to signal a
        stranger — the group id IS the leader's pid, so a foreign occupant means the
        record describes nothing we own."""
        from cathedral_node import state as run_state
        child = self._record_with("distill", start_identity="Thu Jan  1 00:00:00 1970")
        ownership = run_state.read_ownership("distill")
        self.assertEqual(ownership.leader_state(), run_state.ChildOwnership.LEADER_FOREIGN)
        self.assertTrue(ownership.group_members(), "the fixture must really have live members")
        self.assertFalse(ownership.alive(),
                         "bare process-group membership must not manufacture ownership")
        verdict, _own, detail = run_state.ownership_status("distill")
        self.assertEqual(verdict, run_state.OWNERSHIP_UNVERIFIABLE, detail)

    def test_same_boot_reused_pgid_never_authorizes_signal_or_deletion(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("pid-reuse"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()
        child = self._record_with("validator", start_identity="Thu Jan  1 00:00:00 1970")

        blocked, reason = run_state.deletion_blocked("validator")
        self.assertTrue(blocked, "an unownable record must not authorize deletion")
        removed, _reason = installer.uninstall("validator")
        self.assertFalse(removed)
        stopped, detail = run_state.stop_role("validator")
        self.assertFalse(stopped, "a group we cannot prove is ours must never be signalled")
        self.assertIsNone(child.poll(), "the bystander process must be untouched")
        self.assertTrue(paths.role_lock("validator").exists())


# ==============================================================================
# the launch ledger: the proof that survives a deleted record and a re-exec
# ==============================================================================

class TestLaunchLedgerBlocksDeletion(Gate0Base):
    """Command-line scanning is corroboration, never proof.

    A descendant can exec a different binary and keep nothing in its argv that names
    the generation; the ordinary role record can be gone entirely. The append-only
    lease ledger is what still says a launch was opened and never closed.
    """

    def _open_lease_with_untraceable_descendant(self, role: str):
        from cathedral_node import state as run_state
        paths.engine_generations_dir(role).mkdir(parents=True, exist_ok=True)
        lock = run_state.RoleLock(role, f"run-{role}")
        lock.acquire()
        lock.begin_spawn(generation="gen-under-test")
        # `exec` replaces the shell, so the surviving process's argv is `/bin/sleep`
        # and contains no trace of any generation path anywhere.
        child = subprocess.Popen(["/bin/sh", "-c", "exec /bin/sleep 45"],  # noqa: S603
                                 start_new_session=True)
        self.addCleanup(lambda: (child.kill(), child.wait()))
        lock.claim_child(child.pid, generation="gen-under-test")
        return child

    def test_a_deleted_record_and_an_untraceable_descendant_still_block_deletion(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("ledger-block"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()
        child = self._open_lease_with_untraceable_descendant("compute")

        # Remove the ordinary record, exactly as a crash or an operator would.
        paths.role_lock("compute").unlink()
        self.assertEqual(run_state.ownership_status("compute")[0], run_state.OWNERSHIP_ABSENT)
        self.assertEqual(run_state.processes_using(paths.engine_generations_dir("compute")), [],
                         "the descendant must really be invisible to command-line scanning")

        blocked, reason = run_state.deletion_blocked("compute")
        self.assertTrue(blocked, "the ledger must block deletion with no record and no argv trace")
        self.assertIn("launch lease", reason)
        removed, reason = installer.uninstall("compute")
        self.assertFalse(removed, reason)
        self.assertTrue(paths.engine_dir("compute").exists())

        # Once the process is really gone, an explicit stop closes the lease — and
        # it finds the child through the ledger, since the record no longer exists.
        child.kill()
        child.wait()
        # An explicit stop is what resolves the lease. It reports that nothing was
        # running — which is now true — and the ending it records is what finally
        # lets the bytes go.
        stopped, detail = run_state.stop_role("compute")
        self.assertEqual((stopped, detail), (False, "not running"))
        self.assertEqual(run_state.open_leases("compute")[0], [],
                         "the stop must record the ending it proved")
        blocked, _reason = run_state.deletion_blocked("compute")
        self.assertFalse(blocked, "a closed lease must not block forever")
        removed, detail = installer.uninstall("compute")
        self.assertTrue(removed, detail)

    def test_a_spawn_publication_crash_window_blocks_deletion(self):
        """The launcher is killed between `Popen` returning and ownership being
        published. The record still says no child was ever started; the ledger says a
        spawn was in flight and was never confirmed."""
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("spawn-window"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()

        lock = run_state.RoleLock("distill", "run-window")
        lock.acquire()
        lock.begin_spawn(generation="gen-in-flight")
        child = subprocess.Popen(["/bin/sh", "-c", "exec /bin/sleep 45"],  # noqa: S603
                                 start_new_session=True)
        self.addCleanup(lambda: (child.kill(), child.wait()))
        # The launcher dies here: `claim_child` never runs.
        record = run_state.read_ownership("distill")
        self.assertEqual(record.child_pid, -1, "the record must still say no child was recorded")
        self.assertEqual(record.spawn_state, run_state.SPAWN_IN_FLIGHT)

        verdict, _own, detail = run_state.ownership_status("distill")
        self.assertEqual(verdict, run_state.OWNERSHIP_UNVERIFIABLE, detail)
        blocked, reason = run_state.deletion_blocked("distill")
        self.assertTrue(blocked, "a spawn that was never confirmed must block deletion")
        removed, _reason = installer.uninstall("distill")
        self.assertFalse(removed)
        stopped, _detail = run_state.stop_role("distill")
        self.assertFalse(stopped, "an unconfirmed spawn cannot be declared stopped")

    def test_an_unreadable_ledger_blocks_deletion(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("ledger-corrupt"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()
        ledger = paths.ownership_ledger()
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text("{ not json\n")
        os.chmod(ledger, 0o600)
        blocked, reason = run_state.deletion_blocked("validator")
        self.assertTrue(blocked, "an unreadable history is not an empty history")
        self.assertIn("ledger", reason)
        removed, _reason = installer.uninstall("validator")
        self.assertFalse(removed)


# ==============================================================================
# activation witnesses and honest commit reporting
# ==============================================================================

class TestActivationWitnessReporting(Gate0Base):

    def test_activating_journal_failure_reports_pending_recovery_not_unwound(self):
        """The pending pointer is already on disk when the journal write happens.
        Reporting "unwound" would describe a node that does not exist."""
        original = installer._journal

        def failing(event, **fields):
            if event == "ACTIVATING":
                raise OSError("injected activation journal failure")
            return original(event, **fields)

        installer._journal = failing
        try:
            ok, detail, _ = self.install(self.bundle("journal-activating"))
        finally:
            installer._journal = original

        self.assertNoSuccessfulNoOp(ok, detail)
        self.assertIn("Nothing was unwound", detail)
        self.assertIn("recover", detail)
        self.assertTrue(paths.recovery_required(),
                        "the interrupted transaction must be visible to recovery")
        self.assertEqual(self.pointer_doc()["state"], "pending")
        # And recovery can genuinely finish it.
        ok, detail = installer.recover(self.lock)
        self.assertTrue(ok, detail)
        self.assertEqual(self.pointer_doc()["state"], "active")

    def test_post_commit_journal_failure_reports_committed_state_and_retry_heals_witnesses(self):
        """Past the floor and the pointer, the release IS active. Reporting failure
        would invite an operator to retry something that already happened."""
        bundle = self.bundle("journal-post-commit")
        original = installer._record_activation

        def failing(*_a, **_kw):
            raise OSError("injected activation witness failure")

        installer._record_activation = failing
        try:
            ok, detail, result = self.install(bundle)
        finally:
            installer._record_activation = original

        self.assertTrue(ok, f"a committed release must not be reported as a failure: {detail}")
        self.assertIn("active", detail)
        self.assertIn("heal", detail)
        self.assertTrue(result["witnesses_incomplete"])
        self.assertFalse(paths.activation_marker().exists(),
                         "the fixture must really have prevented the witnesses")
        # The release is genuinely active and verifies.
        ok, reason, group = self.verify_active()
        self.assertTrue(ok, reason)

        # Re-applying the same signed release is the repair path.
        ok, detail, result = self.install(bundle)
        self.assertTrue(ok, detail)
        self.assertIn("already active", detail)
        self.assertIn("healed", detail)
        self.assertTrue(paths.activation_marker().exists(),
                        "the retry must heal the missing activation marker")
        self.assertTrue(paths.activation_journal().exists())
        ok, floor, reason = installer._read_floor()
        self.assertTrue(ok, reason)
        self.assertIsNotNone(floor)


class TestPublicStartLauncherCrash(Gate0Base):
    """The launcher crash, driven through `cathedral start` itself.

    The other orphan proofs assemble the launch from `RoleLock` and `proc.stream`.
    That proves those two components, not the command an operator actually runs —
    and the ordering that matters (lock, verify, publish ownership, spawn) lives in
    the command. Here the launcher process calls `commands.run.start` and nothing
    else, and is then killed outright.
    """

    def _crash_public_start(self, role: str, run_id: str):
        from cathedral_node import state as run_state
        script = (
            "import os, sys, types\n"
            f"sys.path.insert(0, {str(Path.cwd())!r})\n"
            f"sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})\n"
            "from cathedral_node import config as config_module, engines as engines_module, runner\n"
            "from cathedral_node.commands import run as run_command\n"
            "from test_gate0 import _StubEngine\n"
            "class _LongRunning(_StubEngine):\n"
            "    def operate_argv(self, _cfg, *, dry_run=False):\n"
            # A detached descendant plus a foreground process: killing the launcher
            # leaves the descendant behind exactly as a real crash would.
            "        return ['/bin/sh', '-c', 'sleep 90 & sleep 120']\n"
            "    def operate_env(self, _cfg):\n"
            "        return {}\n"
            "    def child_env(self, _cfg=None):\n"
            "        from cathedral_node import proc\n"
            f"        return proc.signed_child_env(home={str(self.home)!r})\n"
            "def _load(name, lock=None, group=None):\n"
            "    verified = group.role(name) if group is not None and name in group else None\n"
            "    return _LongRunning(name, verified)\n"
            "engines_module.load = _load\n"
            "config_module.validate = lambda *a, **k: []\n"
            f"ctx = runner.Context(args=types.SimpleNamespace(role={role!r}, broadcast=False,\n"
            "                                                once=False, timeout=300),\n"
            "                     console=runner.build_console(json_mode=True, quiet=True),\n"
            "                     json_mode=True, assume_yes=True, dry_run=False, verbose=False,\n"
            f"                     run_id={run_id!r}, home={str(self.home)!r})\n"
            "envelope = run_command.start(ctx)\n"
            "print('START-RETURNED', envelope.status, flush=True)\n")
        launcher = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=dict(os.environ))
        self.addCleanup(lambda: _force_clear_role(role))
        self.addCleanup(lambda: (launcher.kill(), launcher.wait()))

        deadline = time.monotonic() + 60
        ownership = None
        while time.monotonic() < deadline:
            ownership = run_state.read_ownership(role)
            if ownership is not None and ownership.spawn_state == run_state.SPAWN_OWNED:
                break
            if launcher.poll() is not None:
                self.fail(f"the public start exited before owning a child: "
                          f"{launcher.stdout.read()[:400]} {launcher.stderr.read()[:1200]}")
            time.sleep(0.1)
        else:
            self.fail("`cathedral start` never published child ownership")

        launcher.kill()
        launcher.wait(timeout=10)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and ownership.leader_alive():
            time.sleep(0.1)
        self.assertTrue(ownership.group_members(),
                        "the fixture must really have left a live descendant behind")
        return ownership

    def _journal_events(self) -> list[dict]:
        return [json.loads(line) for line in
                paths.release_journal().read_text().splitlines() if line.strip()]

    def _start_is_refused_without_starting_anything(self, role: str) -> str:
        """Drive the public start command against the current on-disk state."""
        import types as _types
        from cathedral_node import config as config_module
        from cathedral_node import engines as engines_module
        from cathedral_node import runner
        from cathedral_node.commands import run as run_command

        launched: list = []

        class _Recording(_StubEngine):
            def operate_argv(self, _cfg, *, dry_run=False):
                launched.append(True)
                return ["/bin/sh", "-c", "exit 0"]

            def operate_env(self, _cfg):
                return {}

            def child_env(self, _cfg=None):
                return {}

        original_load, original_validate = engines_module.load, config_module.validate
        engines_module.load = lambda name, lock=None, group=None: _Recording(
            name, group.role(name) if group is not None and name in group else None)
        config_module.validate = lambda *_a, **_k: []
        try:
            with ProcessSpy() as spy:
                envelope = run_command.start(runner.Context(
                    args=_types.SimpleNamespace(role=role, broadcast=False, once=False, timeout=30),
                    console=runner.build_console(json_mode=True, quiet=True), json_mode=True,
                    assume_yes=True, dry_run=False, verbose=False, run_id=f"probe-{role}",
                    home=self.home))
        finally:
            engines_module.load, config_module.validate = original_load, original_validate
        self.assertNotEqual(envelope.status, "ok",
                            "an interrupted transaction must not be startable")
        self.assertEqual(launched, [], "nothing may be resolved for execution from a pending pointer")
        self.assertStartsNoProcess(spy)
        return envelope.message if hasattr(envelope, "message") else str(envelope.status)

    def test_a_crashed_public_start_blocks_public_prune_and_uninstall(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("public-crash", version=1))
        self.assertTrue(ok, detail)
        owned_generation = self.pointer_doc()["generations"]["distill"]
        owned_dir = paths.engine_generation_dir("distill", owned_generation)

        ownership = self._crash_public_start("distill", "public-crash-run")
        owned_pgid = ownership.pgid
        self.assertEqual(ownership.generation, owned_generation,
                         "the public start must bind ownership to the verified generation")

        verdict, _own, detail = run_state.ownership_status("distill")
        self.assertEqual(verdict, run_state.OWNERSHIP_LIVE, detail)
        blocked, reason = run_state.deletion_blocked("distill")
        self.assertTrue(blocked, "a crashed public start must leave the generation protected")

        # ---- the next release switches and prunes; with a live orphan it must not --
        events_before = len(self._journal_events())
        ok, detail, _ = self.install(self.bundle("public-crash-2", version=2))
        self.assertFalse(ok, "the next release must not switch out from under a live group")
        self.assertIn("running", detail)

        # (a) The journal reports this exact interrupted state — not a clean failure.
        events = self._journal_events()[events_before:]
        names = [event["event"] for event in events]
        self.assertIn("ACTIVATING", names, "the attempt must be recorded before the pointer moves")
        self.assertIn("ROLLBACK_BLOCKED", names,
                      "a rollback that could not run must say so in the journal")
        self.assertNotIn("ACTIVE", names, "nothing was activated, so nothing may claim it was")
        self.assertNotIn("ROLLED_BACK", names, "nothing was unwound, so nothing may claim it was")
        self.assertIn("running", [e for e in events if e["event"] == "ROLLBACK_BLOCKED"][-1]["reason"])
        self.assertTrue(paths.recovery_required(),
                        "a switch that could neither commit nor unwind must record recovery")
        pending = self.pointer_doc()
        self.assertEqual(pending["state"], "pending")

        # (b) BOTH generations survive: the live one and the prepared one.
        self.assertTrue(owned_dir.exists(),
                        "install pruning deleted a generation a live descendant is using")
        prepared_generation = pending["generations"]["distill"]
        self.assertNotEqual(prepared_generation, owned_generation)
        self.assertTrue(paths.engine_generation_dir("distill", prepared_generation).exists(),
                        "the prepared generation must survive too, or recovery has nothing to finish")

        # (c) Nothing may mistake the pending pointer for what is actually running.
        self.assertIsNone(paths.reported_generation("distill"),
                          "a pending pointer must not report any generation as committed")
        with self.assertRaises(installer.ActiveStateError):
            with installer.verified_active_group(self.lock):
                pass
        self.assertEqual(run_state.read_ownership("distill").generation, owned_generation,
                         "the ownership record must still name the generation that is executing")
        self._start_is_refused_without_starting_anything("distill")

        # (d) Both public deletion paths stay blocked, with and without the record.
        removed, reason = installer.uninstall("distill")
        self.assertFalse(removed, "uninstall must refuse while the owned group lives")
        self.assertTrue(paths.engine_dir("distill").exists())
        paths.role_lock("distill").unlink()
        blocked, reason = run_state.deletion_blocked("distill")
        self.assertTrue(blocked, f"the ledger must still block deletion: {reason}")
        self.assertIn("launch lease", reason)
        removed, _reason = installer.uninstall("distill")
        self.assertFalse(removed)
        self.assertTrue(owned_dir.exists())

        # (e) Recovery is deterministic: it refuses the same way every time while the
        #     group lives, and the state it refuses from never drifts.
        first_ok, first_detail = installer.recover(self.lock)
        second_ok, second_detail = installer.recover(self.lock)
        self.assertFalse(first_ok, first_detail)
        self.assertEqual((first_ok, first_detail), (second_ok, second_detail),
                         "a blocked recovery must be deterministic, not path-dependent")
        self.assertEqual(self.pointer_doc(), pending,
                         "a blocked recovery must not modify the pointer it refused to finish")
        self.assertTrue(owned_dir.exists())

        # ---- stop the whole owned group, then prove everything completes ----------
        with contextlib.suppress(OSError):
            os.killpg(owned_pgid, signal.SIGKILL)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if not [p for p in run_state.process_group_members(owned_pgid)
                        if p != os.getpid()]:
                    break
            except run_state.ProbeUnavailable:
                break
            time.sleep(0.2)
        self.assertTrue(run_state.deletion_blocked("distill")[0],
                        "an empty group is not by itself a recorded ending")
        stopped, detail = run_state.stop_role("distill")
        self.assertFalse(stopped, detail)      # nothing was left to signal
        blocked, reason = run_state.deletion_blocked("distill")
        self.assertFalse(blocked, f"an explicit stop must resolve the launch: {reason}")

        recovered, detail = installer.recover(self.lock)
        self.assertTrue(recovered, detail)
        again_ok, again_detail = installer.recover(self.lock)
        self.assertTrue(again_ok, again_detail)
        self.assertEqual(self.pointer_doc()["state"], "active",
                         "recovery must leave exactly one committed state")
        ok, reason, _group = self.verify_active()
        self.assertTrue(ok, f"the recovered group must verify: {reason}")
        # A committed release still protects its own bytes, so uninstall refuses
        # until the pointer no longer names them — that is a different guard, and it
        # is the last thing standing between the operator and the files.
        removed, why = installer.uninstall("distill")
        self.assertFalse(removed, "a role named by the active pointer must not be removed")
        self.assertIn("active release pointer", why)
        paths.active_release_pointer().unlink()
        removed, detail = installer.uninstall("distill")
        self.assertTrue(removed, detail)


# ==============================================================================
# the launch lease under adversarial conditions
# ==============================================================================

class LeaseCase(Gate0Base):

    def _live_child(self, command: str = "exec /bin/sleep 45"):
        child = subprocess.Popen(["/bin/sh", "-c", command], start_new_session=True)  # noqa: S603
        self.addCleanup(lambda: (child.kill(), child.wait()))
        return child

    def _owned_lease(self, role: str, child, generation: str = "gen-x"):
        from cathedral_node import state as run_state
        paths.engine_generations_dir(role).mkdir(parents=True, exist_ok=True)
        lock = run_state.RoleLock(role, f"run-{role}")
        lock.acquire()
        self.addCleanup(lambda: paths.role_lock(role).unlink(missing_ok=True))
        lock.begin_spawn(generation=generation)
        lock.claim_child(child.pid, generation=generation)
        return lock


class TestLeaseEscapesTheProcessGroup(LeaseCase):

    def test_a_descendant_that_leaves_the_process_group_still_blocks_deletion(self):
        """`setsid()` empties the recorded group without ending anything.

        POSIX gives no way to enumerate what escaped, so an empty group is a failed
        search, not a proof. The lease's end was never recorded, and that is what
        deletion must refuse on.
        """
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("setsid-escape"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()

        # The child leaves its process group and execs something with no trace of
        # the generation anywhere in its command line.
        child = self._live_child(
            "/bin/sh -c 'exec /usr/bin/python3 -c \"import os; os.setsid(); os.execv(\\\"/bin/sleep\\\", [\\\"/bin/sleep\\\", \\\"45\\\"])\"' & "
            "sleep 0.3")
        lock = self._owned_lease("compute", child)
        time.sleep(1.0)
        child.wait(timeout=10)

        recorded = run_state.read_ownership("compute")
        self.assertEqual([pid for pid in run_state.process_group_members(recorded.pgid)
                          if pid != os.getpid()], [],
                         "the fixture must really have emptied the recorded process group")
        self.assertEqual(run_state.processes_using(paths.engine_generations_dir("compute")), [],
                         "and must really be invisible to command-line scanning")

        leases, problem = run_state.open_leases("compute")
        self.assertIsNone(problem)
        self.assertTrue(leases, "the lease must still be open: nothing recorded its end")
        verdict, detail = run_state.lease_liveness(leases[0])
        self.assertNotEqual(verdict, run_state.LEASE_GONE,
                            "an empty group is a failed search, not a proof of death")
        blocked, reason = run_state.deletion_blocked("compute")
        self.assertTrue(blocked, f"an unfinished lease must block deletion: {reason}")
        removed, _reason = installer.uninstall("compute")
        self.assertFalse(removed)
        self.assertTrue(paths.engine_dir("compute").exists())
        del lock

    def test_only_a_recorded_ending_closes_a_lease(self):
        from cathedral_node import state as run_state
        child = self._live_child()
        self._owned_lease("distill", child)
        child.kill()
        child.wait()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and run_state.read_ownership("distill").group_members():
            time.sleep(0.1)
        # The group is empty, but nothing has recorded that the lease ended.
        self.assertTrue(run_state.deletion_blocked("distill")[0],
                        "passive emptiness must not close a lease")
        stopped, detail = run_state.stop_role("distill")
        self.assertTrue(stopped, detail)
        leases, problem = run_state.open_leases("distill")
        self.assertIsNone(problem)
        self.assertEqual(leases, [], "an explicit stop is what records the ending")
        self.assertFalse(run_state.deletion_blocked("distill")[0])


class TestLedgerIsADurableWitness(LeaseCase):

    def test_a_deleted_ledger_is_not_an_empty_history(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("ledger-deleted"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()
        child = self._live_child()
        self._owned_lease("validator", child)
        self.assertTrue(paths.ownership_ledger_marker().exists(),
                        "opening a lease must leave a witness the ledger ever existed")

        paths.ownership_ledger().unlink()
        paths.role_lock("validator").unlink()
        self.assertEqual(run_state.ownership_status("validator")[0], run_state.OWNERSHIP_ABSENT)

        events, problem = run_state.read_lease_events("validator")
        self.assertIsNotNone(problem, "a removed history must be a refusal, not an empty list")
        blocked, reason = run_state.deletion_blocked("validator")
        self.assertTrue(blocked, "a deleted ledger must fail closed while a child lives")
        self.assertIn("missing", reason)
        removed, _reason = installer.uninstall("validator")
        self.assertFalse(removed)

    def test_a_node_that_never_launched_is_not_blocked_by_the_absence(self):
        from cathedral_node import state as run_state
        self.assertFalse(paths.ownership_ledger_marker().exists())
        blocked, _reason = run_state.deletion_blocked("distill")
        self.assertFalse(blocked, "a fresh node must not be blocked by a ledger it never wrote")

    def test_launch_lease_append_refuses_symlink_hardlink_fifo_and_replaced_inode_before_spawn(self):
        from cathedral_node import state as run_state
        ledger = paths.ownership_ledger()
        ledger.parent.mkdir(parents=True, exist_ok=True)
        decoy = self.home / "decoy-ledger.jsonl"

        def refuses(setup, description):
            with contextlib.suppress(OSError):
                ledger.unlink()
            with contextlib.suppress(OSError):
                decoy.unlink()
            setup()
            with self.assertRaises(run_state.LedgerError, msg=description):
                run_state._append_lease(run_state.LEASE_INTENT, "distill", "lease-x")

        def symlink():
            decoy.write_text("")
            os.chmod(decoy, 0o600)
            os.symlink(decoy, ledger)

        def hardlink():
            decoy.write_text("")
            os.chmod(decoy, 0o600)
            os.link(decoy, ledger)

        def fifo():
            os.mkfifo(ledger, 0o600)

        def group_writable():
            ledger.write_text("")
            os.chmod(ledger, 0o660)

        refuses(symlink, "a symlinked ledger must be refused")
        refuses(hardlink, "a hard-linked ledger must be refused")
        refuses(fifo, "a FIFO ledger must be refused")
        refuses(group_writable, "a group-writable ledger must be refused")
        with contextlib.suppress(OSError):
            ledger.unlink()

        # And the replaced-inode case: the file the name resolves to changes while
        # the append holds a descriptor on the original.
        ledger.write_text("")
        os.chmod(ledger, 0o600)
        from cathedral_node import safeio
        original_flock = safeio.fcntl.flock

        def swap_then_lock(fd, operation):
            result = original_flock(fd, operation)
            if getattr(swap_then_lock, "done", False):
                return result
            # Only when the lock just taken is on the LEDGER itself — the append
            # holds the ledger's own lock file first, and swapping then would prove
            # nothing about the descriptor the write lands on.
            try:
                held = os.fstat(fd)
                current = os.stat(ledger)
            except OSError:
                return result
            if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
                return result
            swap_then_lock.done = True
            replacement = self.home / "replacement-ledger.jsonl"
            replacement.write_text("")
            os.chmod(replacement, 0o600)
            os.replace(replacement, ledger)
            return result

        safeio.fcntl.flock = swap_then_lock
        try:
            with self.assertRaises(run_state.LedgerError):
                run_state._append_lease(run_state.LEASE_INTENT, "distill", "lease-y")
        finally:
            safeio.fcntl.flock = original_flock
            swap_then_lock.done = False

    def test_a_refused_ledger_stops_the_public_start_before_any_child_exists(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("ledger-refused"))
        self.assertTrue(ok, detail)
        lock = run_state.RoleLock("distill", "run-refused")
        lock.acquire()
        self.addCleanup(lambda: paths.role_lock("distill").unlink(missing_ok=True))
        # The ledger becomes unwritable after the claim and before the spawn.
        ledger = paths.ownership_ledger()
        ledger.parent.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            ledger.unlink()
        os.mkfifo(ledger, 0o600)
        self.addCleanup(lambda: ledger.unlink(missing_ok=True))
        with ProcessSpy() as spy:
            with self.assertRaises(run_state.LedgerError):
                lock.begin_spawn(generation="gen-x")
        self.assertStartsNoProcess(spy)

    def test_ledger_compaction_preserves_every_open_lease_and_survives_crash_at_each_commit_boundary(self):
        from cathedral_node import state as run_state
        original_max = run_state.LEASE_MAX_BYTES
        run_state.LEASE_MAX_BYTES = 6000
        self.addCleanup(lambda: setattr(run_state, "LEASE_MAX_BYTES", original_max))
        # Two leases that are still open, and several that are finished.
        run_state._append_lease(run_state.LEASE_OWNED, "distill", "open-one",
                                child_pid=1, pgid=1, parent_pid=os.getpid())
        run_state._append_lease(run_state.LEASE_INTENT, "compute", "open-two",
                                parent_pid=os.getpid())
        padding = "x" * 400
        index = 0
        while paths.ownership_ledger().stat().st_size <= run_state.LEASE_MAX_BYTES:
            run_state._append_lease(run_state.LEASE_OWNED, "validator", f"done-{index}",
                                    pad=padding)
            run_state._append_lease(run_state.LEASE_RELEASED, "validator", f"done-{index}",
                                    pad=padding)
            index += 1
            if index > 200:
                self.fail("the ledger never reached the compaction threshold")
        before = paths.ownership_ledger().stat().st_size
        self.assertGreater(index, 1, "the fixture must really have grown the ledger")

        # Crash at the commit boundary: the replace never happens.
        from cathedral_node import safeio
        original_replace = os.replace

        def failing_replace(src, dst, *args, **kwargs):
            # The hardened writer publishes directory-relative, so the destination
            # is a leaf name and the call carries src_dir_fd/dst_dir_fd.
            if Path(str(dst)).name == paths.ownership_ledger().name:
                raise OSError(errno.EIO, "injected crash at the compaction commit")
            return original_replace(src, dst, *args, **kwargs)

        os.replace = failing_replace
        try:
            with contextlib.suppress(OSError, safeio.SecureOpenError, run_state.LedgerError):
                run_state._append_lease(run_state.LEASE_INTENT, "distill", "during-crash",
                                        parent_pid=os.getpid())
        finally:
            os.replace = original_replace

        # The old ledger is intact and every open lease is still there.
        events, problem = run_state.read_lease_events()
        self.assertIsNone(problem, "a failed compaction must leave a readable ledger")
        self.assertEqual(paths.ownership_ledger().stat().st_size, before,
                         "a failed compaction must not truncate the history it could not replace")
        self.assertTrue(run_state.open_leases("distill")[0])
        self.assertTrue(run_state.open_leases("compute")[0])
        self.assertEqual(list(self.home.glob("state/.tmp.*")), [],
                         "a failed compaction must not leave staged files behind")

        # Now let it complete.
        run_state._append_lease(run_state.LEASE_INTENT, "distill", "after-crash",
                                parent_pid=os.getpid())
        self.assertLess(paths.ownership_ledger().stat().st_size, before,
                        "compaction must actually bound the ledger")
        events, problem = run_state.read_lease_events()
        self.assertIsNone(problem)
        surviving = {str(r.get("lease")) for r in events}
        self.assertIn("open-one", surviving, "compaction must preserve every open lease")
        self.assertIn("open-two", surviving)
        self.assertNotIn("done-0", surviving, "and may only drop the finished ones")
        self.assertTrue(any(r.get("event") == "compacted" for r in events),
                        "compaction must record what it dropped")
        self.assertTrue(run_state.deletion_blocked("distill")[0],
                        "an open lease must still block deletion after compaction")


class TestLeaseOwnershipIsExclusive(LeaseCase):

    def test_begin_spawn_aborts_when_the_claim_is_gone(self):
        from cathedral_node import state as run_state
        lock = run_state.RoleLock("distill", "run-lost")
        lock.acquire()
        self.addCleanup(lambda: paths.role_lock("distill").unlink(missing_ok=True))
        paths.role_lock("distill").unlink()          # the claim is taken away
        with ProcessSpy() as spy:
            with self.assertRaises(run_state.OwnershipLost):
                lock.begin_spawn(generation="gen-x")
        self.assertStartsNoProcess(spy)

    def test_begin_spawn_aborts_when_another_launcher_owns_the_record(self):
        from cathedral_node import state as run_state
        first = run_state.RoleLock("compute", "run-first")
        first.acquire()
        self.addCleanup(lambda: paths.role_lock("compute").unlink(missing_ok=True))
        second = run_state.RoleLock("compute", "run-second")
        second._acquired = True                      # a launcher that never won the race
        with self.assertRaises(run_state.OwnershipLost):
            second.begin_spawn(generation="gen-x")

    def test_an_open_lease_prevents_a_second_owner_even_with_no_role_record(self):
        from cathedral_node import state as run_state
        child = self._live_child()
        self._owned_lease("validator", child)
        paths.role_lock("validator").unlink()         # the record is gone; the lease is not

        second = run_state.RoleLock("validator", "run-second")
        with self.assertRaises(run_state.LockHeld):
            second.acquire()
        self.assertIsNotNone(run_state.running_run("validator"),
                             "an unfinished lease must read as a running role")

    def test_an_unreadable_ledger_prevents_a_second_owner(self):
        from cathedral_node import state as run_state
        ledger = paths.ownership_ledger()
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text("{ not json\n")
        os.chmod(ledger, 0o600)
        with self.assertRaises(run_state.LockHeld):
            run_state.RoleLock("distill", "run-blind").acquire()


class TestLeaseIdentityAndBoots(LeaseCase):

    def test_same_second_pid_and_pgid_reuse_never_authorizes_signal(self):
        """One-second resolution cannot tell two processes apart; a pid freed by
        SIGKILL can be handed out well inside that second."""
        from cathedral_node import state as run_state
        first = self._live_child("exec /bin/sleep 30")
        second = self._live_child("exec /bin/sleep 30")
        one = run_state.process_start_identity(first.pid)
        two = run_state.process_start_identity(second.pid)
        self.assertTrue(run_state.identity_is_kernel_grade(one), one)
        self.assertNotEqual(one, two,
                            "two processes started in the same second must be distinguishable")

        # A record carrying only the one-second identity must never authorize a
        # signal, even though its string compares equal to the live process.
        lowres = f"lowres:{time.strftime('%a %b %d %H:%M:%S %Y')}"
        original = run_state.process_start_identity
        run_state.process_start_identity = lambda pid: lowres
        self.addCleanup(lambda: setattr(run_state, "process_start_identity", original))

        lock = run_state.RoleLock("compute", "run-lowres")
        lock.acquire()
        self.addCleanup(lambda: paths.role_lock("compute").unlink(missing_ok=True))
        lock.claim_child(first.pid, generation="gen-x")
        ownership = run_state.read_ownership("compute")
        self.assertEqual(ownership.start_identity, lowres)
        self.assertEqual(ownership.leader_state(), run_state.ChildOwnership.LEADER_UNPROVEN,
                         "a one-second identity match must not be read as proof")
        verdict, _own, detail = run_state.ownership_status("compute")
        self.assertEqual(verdict, run_state.OWNERSHIP_UNVERIFIABLE, detail)
        stopped, detail = run_state.stop_role("compute", grace=1.0)
        self.assertFalse(stopped, "an unprovable identity must never authorize a signal")
        self.assertIsNone(first.poll(), "and the process must be untouched")
        self.assertTrue(run_state.deletion_blocked("compute")[0])

    def test_known_prior_boot_lease_is_retired_without_signaling_reused_ids(self):
        from cathedral_node import state as run_state
        bystander = self._live_child("exec /bin/sleep 30")
        # A lease from a boot we can name, whose recorded pgid now belongs to a
        # completely unrelated process.
        original = run_state.boot_identity
        run_state.boot_identity = lambda: "btime:1"
        try:
            run_state._append_lease(run_state.LEASE_OWNED, "distill", "old-boot",
                                    child_pid=bystander.pid, pgid=os.getpgid(bystander.pid),
                                    parent_pid=os.getpid(), start_identity="whatever")
        finally:
            run_state.boot_identity = original
        self.assertNotEqual(run_state.boot_identity(), "btime:1")

        leases, problem = run_state.open_leases("distill")
        self.assertIsNone(problem)
        verdict, detail = run_state.lease_liveness(leases[0])
        self.assertEqual(verdict, run_state.LEASE_GONE, detail)
        blocked, reason = run_state.deletion_blocked("distill")
        self.assertFalse(blocked, f"a previous boot's lease must not block forever: {reason}")
        run_state._retire_prior_boot_leases("distill")
        self.assertEqual(run_state.open_leases("distill")[0], [],
                         "the retirement must be recorded, not merely inferred each time")
        self.assertIsNone(bystander.poll(),
                          "retiring a previous boot's lease must never signal the ids it names")

    def test_an_unknown_boot_identity_still_fails_closed(self):
        from cathedral_node import state as run_state
        child = self._live_child()
        self._owned_lease("compute", child)
        original = run_state.boot_identity
        run_state.boot_identity = lambda: ""
        self.addCleanup(lambda: setattr(run_state, "boot_identity", original))
        leases, problem = run_state.open_leases("compute")
        self.assertIsNone(problem)
        verdict, _detail = run_state.lease_liveness(leases[0])
        self.assertEqual(verdict, run_state.OWNERSHIP_UNVERIFIABLE)
        self.assertTrue(run_state.deletion_blocked("compute")[0])


class TestPublicStopFindsTheLease(LeaseCase):

    def test_public_stop_recovers_verified_owned_lease_when_role_record_is_missing(self):
        import types as _types
        from cathedral_node import runner
        from cathedral_node import state as run_state
        from cathedral_node.commands import run as run_command

        child = self._live_child("sleep 45 & sleep 45")
        self._owned_lease("distill", child)
        pgid = run_state.read_ownership("distill").pgid
        paths.role_lock("distill").unlink()
        self.assertEqual(run_state.ownership_status("distill")[0], run_state.OWNERSHIP_ABSENT)

        envelope = run_command.stop(runner.Context(
            args=_types.SimpleNamespace(role="distill", broadcast=False, once=False, timeout=30),
            console=runner.build_console(json_mode=True, quiet=True), json_mode=True,
            assume_yes=True, dry_run=False, verbose=False, run_id="stop-lease", home=self.home))
        self.assertEqual(envelope.status, "ok",
                         f"a stop must find the child the ledger names: {envelope}")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                if not [p for p in run_state.process_group_members(pgid) if p != os.getpid()]:
                    break
            except run_state.ProbeUnavailable:
                break
            time.sleep(0.1)
        self.assertEqual([p for p in run_state.process_group_members(pgid) if p != os.getpid()], [],
                         "the whole group the lease named must be gone")
        self.assertEqual(run_state.open_leases("distill")[0], [])
        self.assertFalse(run_state.deletion_blocked("distill")[0])

    def test_stop_closes_lease_when_group_exits_after_final_poll_without_raising(self):
        """The group drains between the last poll and the check after the loop.

        That exit used to call a function that did not exist, so the one race that
        reached it raised NameError out of a public command.
        """
        from cathedral_node import state as run_state
        child = self._live_child()
        self._owned_lease("compute", child)
        real_members = run_state.process_group_members
        calls = {"n": 0}

        def draining(pgid):
            calls["n"] += 1
            if calls["n"] <= 3:
                return [child.pid]           # still there for every poll inside the loop
            return real_members(pgid)        # and gone by the check after it

        run_state.process_group_members = draining
        self.addCleanup(lambda: setattr(run_state, "process_group_members", real_members))
        try:
            stopped, detail = run_state.stop_role("compute", grace=0.2)
        except NameError as exc:
            self.fail(f"the post-loop exit must not raise: {exc}")
        run_state.process_group_members = real_members
        self.assertTrue(stopped, detail)
        self.assertEqual(run_state.open_leases("compute")[0], [],
                         "the lease must be closed by the exit that proved the group empty")


class TestRevocationOutageAndConcurrency(Gate0Base):

    def test_channel_outage_with_cache_ahead_of_floor_never_exports_unfloored_state_or_readmits_old_cache(self):
        """An outage may fall back to the cache. It may not export a snapshot the
        durable floor has not caught up to."""
        now = dt.datetime.now(dt.timezone.utc)
        raw9, sig9 = self.fx.revocation_snapshot(9)
        self.assertTrue(revocation.retain(raw9, sig9, now=now)[0])
        raw11, sig11 = self.fx.revocation_snapshot(11)
        self.fx.stage_revocation_cache(raw11, sig11)
        self.assertEqual(revocation.floor_state()[1][0], 9)

        def unreachable(_url, _limit):
            raise OSError("the revocation channel is down")

        ok, reason, state = revocation.refresh("https://example.invalid/revocation",
                                               now=now, fetch=unreachable)
        self.assertTrue(ok, reason)
        self.assertEqual(state.sequence, 11)
        self.assertEqual(revocation.floor_state()[1][0], 11,
                         "an outage that exports sequence 11 must leave the floor at 11")

        # And the older, perfectly valid snapshot must now be refused for good.
        self.fx.stage_revocation_cache(raw9, sig9)
        ok, reason, state = revocation.load_retained(now=now)
        self.assertFalse(ok, "the floor must refuse the snapshot the outage moved past")
        ok, reason, state = revocation.refresh("https://example.invalid/revocation",
                                               now=now, fetch=unreachable)
        self.assertFalse(ok, "an outage with no usable snapshot must not report success")
        self.assertIsNone(state)

    def test_an_outage_that_cannot_raise_the_floor_reports_no_usable_state(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw9, sig9 = self.fx.revocation_snapshot(9)
        self.assertTrue(revocation.retain(raw9, sig9, now=now)[0])
        raw11, sig11 = self.fx.revocation_snapshot(11)
        self.fx.stage_revocation_cache(raw11, sig11)
        original = revocation._write_floor
        revocation._write_floor = lambda *a, **k: (_ for _ in ()).throw(OSError("read-only"))
        try:
            ok, reason, state = revocation.refresh("https://example.invalid/revocation", now=now,
                                                   fetch=lambda *_a: (_ for _ in ()).throw(OSError("down")))
        finally:
            revocation._write_floor = original
        self.assertFalse(ok, "an unfloored snapshot must never be exported")
        self.assertIsNone(state)
        self.assertEqual(revocation.floor_state()[1][0], 9)

    def test_concurrent_floor_advance_during_heal_never_returns_state_below_final_floor(self):
        """A reader healing 11 while another transaction commits 12."""
        now = dt.datetime.now(dt.timezone.utc)
        raw9, sig9 = self.fx.revocation_snapshot(9)
        self.assertTrue(revocation.retain(raw9, sig9, now=now)[0])
        raw11, sig11 = self.fx.revocation_snapshot(11)
        raw12, sig12 = self.fx.revocation_snapshot(12)
        self.fx.stage_revocation_cache(raw11, sig11)

        # The winner commits sequence 12 in the window between the reader noticing
        # the lag and the reader taking the transaction lock.
        original_lock = revocation.safeio.secure_lock
        fired: list = []

        @contextlib.contextmanager
        def racing(path, **kw):
            if not fired and str(path) == str(revocation.transaction_lock()):
                fired.append(True)
                ok, reason, _ = revocation.retain(raw12, sig12, now=now)
                self.assertTrue(ok, reason)
            with original_lock(path, **kw) as fd:
                yield fd

        revocation.safeio.secure_lock = racing
        try:
            ok, reason, state = revocation.load_retained(now=now, heal=True)
        finally:
            revocation.safeio.secure_lock = original_lock

        floor = revocation.floor_state()[1]
        self.assertEqual(floor[0], 12, "the winning transaction's floor must stand")
        if ok:
            self.assertGreaterEqual(state.sequence, floor[0],
                                    "a read must never return a snapshot below the durable floor")
        else:
            self.assertIsNone(state)
        # Whatever the read decided, sequence 11 is no longer admissible.
        self.fx.stage_revocation_cache(raw11, sig11)
        ok, _reason, _state = revocation.load_retained(now=now, heal=True)
        self.assertFalse(ok, "sequence 11 must be refused once 12 is the durable floor")


class TestRevocationDirectoryRedirection(Gate0Base):
    """``O_NOFOLLOW`` refuses a symlinked file. It says nothing about the
    directories above it, and the revocation cache, the floor and their lock all
    live in one — so a single symlinked parent redirects the whole transaction."""

    def _redirect_parent(self, directory: Path) -> Path:
        elsewhere = self.home / f"attacker-{directory.name}"
        elsewhere.mkdir(parents=True, exist_ok=True)
        os.chmod(elsewhere, 0o700)
        if directory.exists():
            for item in directory.iterdir():
                if item.is_dir():
                    shutil.copytree(item, elsewhere / item.name, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, elsewhere / item.name)
            installer._force_rmtree(directory)
        os.symlink(elsewhere, directory)
        self.addCleanup(lambda: directory.unlink(missing_ok=True))
        return elsewhere

    def test_a_symlinked_revocation_directory_is_refused_by_every_entry_point(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw, sig = self.fx.revocation_snapshot(9)
        self.assertTrue(revocation.retain(raw, sig, now=now)[0])
        self._redirect_parent(revocation.cache_file().parent)

        ok, reason, state = revocation.load_retained(now=now)
        self.assertFalse(ok, "a redirected parent must not be read through")
        self.assertIsNone(state)
        self.assertIn("symlink", reason)

        newer_raw, newer_sig = self.fx.revocation_snapshot(11)
        ok, reason, _ = revocation.retain(newer_raw, newer_sig, now=now)
        self.assertFalse(ok, "a redirected parent must not be written through")
        with self.assertRaises(revocation.RevocationError):
            revocation.install_cache(newer_raw, newer_sig, now=now)
        gate_ok, gate_reason, _ = revocation.enforce(
            "a" * 64, self.fx.signers.read_text(), IDENTITY, now=now,
            policy=revocation.ACQUISITION)
        self.assertFalse(gate_ok, gate_reason)

    def test_a_symlinked_engines_directory_is_refused(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw, sig = self.fx.revocation_snapshot(9)
        self.assertTrue(revocation.retain(raw, sig, now=now)[0])
        self.assertTrue(revocation.floor_state()[0])
        self._redirect_parent(paths.engines_dir())

        ok, reason, _state = revocation.load_retained(now=now)
        self.assertFalse(ok, "an ancestor two levels up redirects the same files")
        fok, _floor, freason = revocation.floor_state()
        self.assertFalse(fok, f"the floor must not be read through a redirected ancestor: {freason}")

    def test_a_redirected_parent_cannot_readmit_a_refused_snapshot(self):
        """The point of the attack: plant an older snapshot behind a redirect."""
        now = dt.datetime.now(dt.timezone.utc)
        raw11, sig11 = self.fx.revocation_snapshot(11)
        self.assertTrue(revocation.retain(raw11, sig11, now=now)[0])
        elsewhere = self._redirect_parent(revocation.cache_file().parent)
        raw9, sig9 = self.fx.revocation_snapshot(9)
        (elsewhere / revocation.cache_file().name).write_bytes(
            revocation._encode_cache(raw9, sig9))
        os.chmod(elsewhere / revocation.cache_file().name, 0o600)

        ok, reason, state = revocation.load_retained(now=now)
        self.assertFalse(ok, "the redirected older snapshot must not be admitted")
        self.assertIsNone(state)

    def test_the_ownership_ledger_is_refused_through_a_redirected_parent(self):
        from cathedral_node import state as run_state
        run_state._append_lease(run_state.LEASE_INTENT, "distill", "lease-a",
                                parent_pid=os.getpid())
        self._redirect_parent(paths.state_dir())
        with self.assertRaises(run_state.LedgerError):
            run_state._append_lease(run_state.LEASE_INTENT, "distill", "lease-b",
                                    parent_pid=os.getpid())
        events, problem = run_state.read_lease_events("distill")
        self.assertIsNotNone(problem, "a redirected ledger must be a refusal, not a history")
        self.assertTrue(run_state.deletion_blocked("distill")[0])


class TestDetachedDescendantThroughPublicCommands(LeaseCase):
    """The whole cycle through public commands, with a child that detaches.

    `cathedral start` → the child calls `setsid()` → `cathedral stop` → a second
    `cathedral start`. The recorded process group empties the moment the child
    detaches, so every check built on that group says "finished" while the process
    is still running and still serving the identity.
    """

    # `setsid()` fails for a process that is already a group leader, and every
    # launcher here starts a new session — so the child forks first and it is the
    # grandchild that detaches. That is also the realistic shape: a server that
    # daemonises, or an engine that re-parents a worker.
    DETACH = ("import os, sys, time\n"
              "if os.fork():\n"
              "    time.sleep(0.5)\n"
              "    os._exit(0)\n"
              "os.setsid()\n"
              "with open(sys.argv[1], 'w') as fh:\n"
              "    fh.write(str(os.getpid()))\n"
              "time.sleep(90)\n")

    def _public_start(self, role: str, run_id: str, body: str):
        script = (
            "import os, sys, types\n"
            f"sys.path.insert(0, {str(Path.cwd())!r})\n"
            f"sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})\n"
            "from cathedral_node import config as config_module, engines as engines_module, runner\n"
            "from cathedral_node.commands import run as run_command\n"
            "from test_gate0 import _StubEngine\n"
            "class _Detaching(_StubEngine):\n"
            "    def operate_argv(self, _cfg, *, dry_run=False):\n"
            f"        return ['/usr/bin/python3', '-c', {body!r}, "
            f"{str(self.home / 'detached.pid')!r}]\n"
            "    def operate_env(self, _cfg):\n"
            "        return {}\n"
            "def _load(name, lock=None, group=None):\n"
            "    verified = group.role(name) if group is not None and name in group else None\n"
            "    return _Detaching(name, verified)\n"
            "engines_module.load = _load\n"
            "config_module.validate = lambda *a, **k: []\n"
            f"ctx = runner.Context(args=types.SimpleNamespace(role={role!r}, broadcast=False,\n"
            "                                                once=False, timeout=300),\n"
            "                     console=runner.build_console(json_mode=True, quiet=True),\n"
            "                     json_mode=True, assume_yes=True, dry_run=False, verbose=False,\n"
            f"                     run_id={run_id!r}, home={str(self.home)!r})\n"
            "envelope = run_command.start(ctx)\n"
            "print('START-RETURNED', envelope.status, flush=True)\n")
        launcher = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=dict(os.environ))
        self.addCleanup(lambda: (launcher.kill(), launcher.wait()))
        return launcher

    def test_a_detached_child_blocks_stop_deletion_and_a_second_start(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("detach"))
        self.assertTrue(ok, detail)
        launcher = self._public_start("distill", "detach-run", self.DETACH)
        self.addCleanup(lambda: _force_clear_role("distill"))

        deadline = time.monotonic() + 60
        ownership = None
        while time.monotonic() < deadline:
            ownership = run_state.read_ownership("distill")
            if ownership is not None and ownership.spawn_state == run_state.SPAWN_OWNED:
                break
            if launcher.poll() is not None:
                self.fail(f"the public start exited early: {launcher.stderr.read()[:900]}")
            time.sleep(0.1)
        self.assertIsNotNone(ownership)

        # Wait for the detached grandchild to publish itself and the recorded group
        # to empty.
        marker = self.home / "detached.pid"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.1)
        self.assertTrue(marker.exists(), "the fixture must really have detached a grandchild")
        detached_pid = int(marker.read_text().strip())

        def kill_detached():
            with contextlib.suppress(OSError):
                os.kill(detached_pid, signal.SIGKILL)

        self.addCleanup(kill_detached)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if not [p for p in run_state.process_group_members(ownership.pgid)
                    if p != os.getpid()]:
                break
            time.sleep(0.1)
        self.assertEqual([p for p in run_state.process_group_members(ownership.pgid)
                          if p != os.getpid()], [],
                         "the recorded process group must really be empty")
        self.assertTrue(_pid_is_live(detached_pid),
                        "and the detached process must really still be running")
        self.assertNotEqual(os.getpgid(detached_pid), ownership.pgid,
                            "it must really be outside the group the node recorded")

        # 1. The lease is still open, so deletion is refused.
        leases, problem = run_state.open_leases("distill")
        self.assertIsNone(problem)
        self.assertTrue(leases, "a detached child must leave its lease open")
        blocked, reason = run_state.deletion_blocked("distill")
        self.assertTrue(blocked, f"a detached child must block deletion: {reason}")

        # 2. A second start must be refused: the role still has an owner.
        second = run_state.RoleLock("distill", "second-start")
        with self.assertRaises(run_state.LockHeld):
            second.acquire()

        # 3. Even after the launcher itself is killed and its record removed.
        launcher.kill()
        launcher.wait(timeout=10)
        paths.role_lock("distill").unlink(missing_ok=True)
        self.assertTrue(run_state.deletion_blocked("distill")[0],
                        "removing the record must not release the detached child's claim")
        with self.assertRaises(run_state.LockHeld):
            run_state.RoleLock("distill", "third-start").acquire()
        removed, _reason = installer.uninstall("distill")
        self.assertFalse(removed)

    def test_a_reused_process_group_is_never_signalled_from_a_lease(self):
        """The record is gone and the lease names numbers a stranger now holds."""
        from cathedral_node import state as run_state
        stranger = self._live_child("sleep 45 & sleep 45")
        killed: list = []
        original_killpg = os.killpg

        def watching(pgid, sig):
            killed.append((pgid, sig))
            return original_killpg(pgid, sig)

        run_state._append_lease(
            run_state.LEASE_OWNED, "compute", "reused",
            child_pid=stranger.pid, pgid=os.getpgid(stranger.pid), parent_pid=os.getpid(),
            euid=os.geteuid(), start_identity="mac:1.000000:1:0", generation="gen-x")
        self.assertIsNone(run_state.read_ownership("compute"))

        os.killpg = watching
        try:
            stopped, detail = run_state.stop_role("compute")
        finally:
            os.killpg = original_killpg
        self.assertFalse(stopped, "a lease that cannot prove its identity must not be stopped")
        self.assertEqual(killed, [], "killpg must never be called on an unproven group")
        self.assertIsNone(stranger.poll(), "the stranger must be untouched")
        self.assertTrue(run_state.deletion_blocked("compute")[0])

    def test_a_lease_from_another_user_is_never_signalled(self):
        from cathedral_node import state as run_state
        child = self._live_child()
        run_state._append_lease(
            run_state.LEASE_OWNED, "validator", "foreign-uid",
            child_pid=child.pid, pgid=os.getpgid(child.pid), parent_pid=os.getpid(),
            euid=os.geteuid() + 4242,
            start_identity=run_state.process_start_identity(child.pid), generation="gen-x")
        killed: list = []
        original_killpg = os.killpg
        os.killpg = lambda pgid, sig: killed.append((pgid, sig))
        try:
            stopped, _detail = run_state.stop_role("validator")
        finally:
            os.killpg = original_killpg
        self.assertFalse(stopped)
        self.assertEqual(killed, [], "a lease recorded under another uid must not be signalled")
        self.assertIsNone(child.poll())


class TestUnconfirmedSpawnIsNeverClosed(LeaseCase):

    def test_an_intent_only_crash_keeps_deletion_blocked_with_no_role_record(self):
        from cathedral_node import state as run_state
        ok, detail, _ = self.install(self.bundle("intent-only"))
        self.assertTrue(ok, detail)
        paths.active_release_pointer().unlink()

        lock = run_state.RoleLock("compute", "run-intent")
        lock.acquire()
        lock.begin_spawn(generation="gen-in-flight")
        # The launcher dies here. `Popen` may already have returned.
        paths.role_lock("compute").unlink()
        self.assertEqual(run_state.ownership_status("compute")[0], run_state.OWNERSHIP_ABSENT)

        leases, problem = run_state.open_leases("compute")
        self.assertIsNone(problem)
        self.assertEqual(leases[0]["event"], run_state.LEASE_INTENT)
        self.assertLessEqual(int(leases[0].get("pgid", -1)), 0,
                             "the fixture must really have no process group recorded")
        blocked, reason = run_state.deletion_blocked("compute")
        self.assertTrue(blocked, "an unconfirmed spawn must block deletion")
        removed, _reason = installer.uninstall("compute")
        self.assertFalse(removed)

        # And an explicit stop must not close it by inference either.
        stopped, detail = run_state.stop_role("compute")
        self.assertFalse(stopped, "an unconfirmed spawn cannot be declared finished")
        self.assertTrue(run_state.open_leases("compute")[0],
                        "the lease must survive a stop that proved nothing")
        self.assertTrue(run_state.deletion_blocked("compute")[0])


class TestLedgerLockIsSingle(LeaseCase):

    def test_a_concurrent_append_is_never_lost_to_compaction(self):
        """Two writers, one of which triggers compaction. With separate locks the
        compaction replaces the file between the other's open and its fsync, and
        that record is durably written into an inode with no name."""
        from cathedral_node import state as run_state
        # A small threshold so compaction fires repeatedly *during* the race. The
        # value is the only thing scaled down; the code path is the real one.
        original_max = run_state.LEASE_MAX_BYTES
        run_state.LEASE_MAX_BYTES = 6000
        self.addCleanup(lambda: setattr(run_state, "LEASE_MAX_BYTES", original_max))
        padding = "y" * 400
        for index in range(12):
            run_state._append_lease(run_state.LEASE_OWNED, "validator", f"old-{index}", pad=padding)
            run_state._append_lease(run_state.LEASE_RELEASED, "validator", f"old-{index}",
                                    pad=padding)

        errors: list = []
        barrier = threading.Barrier(4, timeout=60)

        def writer(name: str):
            try:
                barrier.wait()
                for step in range(6):
                    run_state._append_lease(run_state.LEASE_OWNED, "distill", f"{name}-{step}",
                                            child_pid=1, pgid=1, parent_pid=os.getpid())
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{name}: {exc}")

        threads = [threading.Thread(target=writer, args=(f"w{i}",)) for i in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(120)
        self.assertEqual(errors, [], "no writer may fail")

        events, problem = run_state.read_lease_events()
        self.assertIsNone(problem, "the ledger must still be readable after the race")
        recorded = {str(r.get("lease")) for r in events}
        expected = {f"w{i}-{step}" for i in range(4) for step in range(6)}
        self.assertEqual(expected - recorded, set(),
                         "every appended record must survive the compaction that raced it")
        self.assertTrue(any(r.get("event") == "compacted" for r in events),
                        "the fixture must really have triggered a compaction")


class TestRevocationChannelOutcomes(Gate0Base):
    """Every way the channel can answer badly, against a cache ahead of the floor."""

    def _lagging_floor(self):
        now = dt.datetime.now(dt.timezone.utc)
        raw9, sig9 = self.fx.revocation_snapshot(9)
        self.assertTrue(revocation.retain(raw9, sig9, now=now)[0])
        raw11, sig11 = self.fx.revocation_snapshot(11)
        self.fx.stage_revocation_cache(raw11, sig11)
        self.assertEqual(revocation.floor_state()[1][0], 9)
        return now, (raw9, sig9), (raw11, sig11)

    def _refresh_with(self, now, raw, sig):
        return revocation.refresh("https://example.invalid/revocation", now=now,
                                  fetch=lambda url, _limit: sig if url.endswith(".sig") else raw)

    def test_no_channel_outcome_exports_a_cache_ahead_of_the_durable_floor(self):
        for case in ("invalid signature", "older sequence", "equal sequence, different digest",
                     "expired snapshot", "malformed bytes"):
            with self.subTest(case=case):
                self.setUp()
                now, (raw9, sig9), (raw11, sig11) = self._lagging_floor()
                if case == "invalid signature":
                    raw, sig = self.fx.revocation_snapshot(13)
                    sig = sig[:-40] + b"A" * 39 + b"\n"
                elif case == "older sequence":
                    raw, sig = self.fx.revocation_snapshot(2)
                elif case == "equal sequence, different digest":
                    raw, sig = self.fx.revocation_snapshot(11, revoked_releases=["c" * 64])
                elif case == "expired snapshot":
                    raw, sig = self.fx.revocation_snapshot(
                        13, issued_at="2020-01-01T00:00:00+00:00",
                        expires_at="2020-02-01T00:00:00+00:00")
                else:
                    raw, sig = b"{ not json", self.fx.revocation_snapshot(11)[1]

                ok, reason, state = self._refresh_with(now, raw, sig)
                floor = revocation.floor_state()[1]
                if ok:
                    self.assertIsNotNone(state)
                    self.assertLessEqual(state.sequence, floor[0],
                                         f"{case}: exported a snapshot ahead of the durable floor")
                    self.assertGreaterEqual(floor[0], 11,
                                            f"{case}: the floor must cover what was exported")
                    # And the older snapshot can never be re-admitted afterwards.
                    self.fx.stage_revocation_cache(raw9, sig9)
                    readmitted, _why, _s = revocation.load_retained(now=now)
                    self.assertFalse(readmitted, f"{case}: sequence 9 was re-admitted")
                else:
                    self.assertIsNone(state, f"{case}: a refusal must not carry state")

    def test_a_usable_channel_snapshot_still_advances_normally(self):
        now, _old, _new = self._lagging_floor()
        raw, sig = self.fx.revocation_snapshot(14)
        ok, reason, state = self._refresh_with(now, raw, sig)
        self.assertTrue(ok, reason)
        self.assertEqual(state.sequence, 14)
        self.assertEqual(revocation.floor_state()[1][0], 14)


class TestAncestorReplacementDuringIO(Gate0Base):
    """A directory above a security file, renamed while the file is being locked or
    written. The descriptor stays valid; the name no longer reaches it."""

    def _replace_dir_during(self, directory: Path, hook_name: str, module, target: str):
        """Swap ``directory`` for a fresh one the first time ``hook_name`` runs."""
        original = getattr(module, hook_name)
        state = {"done": False}

        def hook(*a, **kw):
            result = original(*a, **kw)
            if not state["done"] and target in str(a[0] if a else ""):
                state["done"] = True
                detached = self.home / f"detached-{directory.name}"
                shutil.copytree(directory, detached, dirs_exist_ok=True)
                os.rename(directory, self.home / f"old-{directory.name}")
                os.rename(detached, directory)
            return result

        setattr(module, hook_name, hook)
        self.addCleanup(lambda: setattr(module, hook_name, original))
        return state

    def test_a_lock_taken_through_a_replaced_directory_is_refused(self):
        from cathedral_node import safeio
        now = dt.datetime.now(dt.timezone.utc)
        raw, sig = self.fx.revocation_snapshot(5)
        self.assertTrue(revocation.retain(raw, sig, now=now)[0])
        # The revocation transaction lock lives in `engines/`, so that is the
        # directory whose replacement detaches it.
        swapped = self._replace_dir_during(paths.engines_dir(), "flock", safeio.fcntl, "")
        newer, newer_sig = self.fx.revocation_snapshot(6)
        ok, reason, _state = revocation.retain(newer, newer_sig, now=now)
        self.assertTrue(swapped["done"], "the fixture must really have replaced the directory")
        self.assertFalse(ok, "a lock on a detached directory must not be accepted")
        self.assertIn("replaced", reason)

    def test_a_write_published_into_a_replaced_directory_is_not_reported_as_success(self):
        from cathedral_node import safeio
        directory = revocation.cache_file().parent
        directory.mkdir(parents=True, exist_ok=True)
        original_replace = os.replace
        state = {"done": False}

        def replace_then_swap(src, dst, *a, **kw):
            result = original_replace(src, dst, *a, **kw)
            if not state["done"]:
                state["done"] = True
                detached = self.home / "detached-revocation"
                shutil.copytree(directory, detached, dirs_exist_ok=True)
                os.rename(directory, self.home / "old-revocation")
                os.rename(detached, directory)
            return result

        os.replace = replace_then_swap
        try:
            with self.assertRaises(safeio.SecureOpenError) as caught:
                safeio.secure_write_atomic(revocation.cache_file(), b'{"schema": "x"}')
        finally:
            os.replace = original_replace
        self.assertTrue(state["done"])
        self.assertIn("replaced", str(caught.exception))

    def test_a_holder_whose_directory_is_replaced_never_believes_it_holds_the_lock(self):
        """The exact race: `engines/` is replaced while the lock is being taken.

        The descriptor is a perfectly good lock — on an inode nothing reaches by
        that name any more. A second process would take "the" lock on the new
        directory and neither would be excluding the other, so the acquisition that
        was overtaken must fail rather than return.
        """
        from cathedral_node import safeio
        lock_path = revocation.transaction_lock()
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        swapped = self._replace_dir_during(paths.engines_dir(), "flock", safeio.fcntl, "")
        with self.assertRaises(safeio.SecureOpenError) as caught:
            with safeio.secure_lock(lock_path, exclusive=True, timeout=5, busy_message="busy"):
                self.fail("an overtaken acquisition must not be admitted")
        self.assertTrue(swapped["done"])
        self.assertIn("replaced", str(caught.exception))

        # The refusal persists for this lock, because its file is no longer the one
        # the lock was established on — that needs an operator, not a retry.
        with self.assertRaises(safeio.SecureOpenError):
            with safeio.secure_lock(lock_path, exclusive=True, timeout=5, busy_message="busy"):
                self.fail("a replaced lock file must stay refused")

        # A lock whose own state was never disturbed is unaffected: the mechanism
        # refuses a specific broken thing, not locking in general.
        untouched = paths.state_dir() / "untouched.lock"
        with safeio.secure_lock(untouched, exclusive=True, timeout=5, busy_message="busy") as fd:
            self.assertGreater(fd, 0)


class TestVerifyToExecBinding(RuntimeBindingCase):
    """The last window: revalidation has returned and `Popen` has not resolved the
    program yet. Every other mutation test acts earlier than this."""

    def test_replacing_the_program_after_revalidation_starts_nothing_that_survives(self):
        from cathedral_node import state as run_state
        from cathedral_node.commands import run as run_command
        stubs = self._stub("validator")
        before = self.weakening_snapshot()

        swapped: list = []
        spawned: list = []
        original_popen = proc_module.subprocess.Popen

        def recording_popen(*a, **kw):
            child = original_popen(*a, **kw)
            spawned.append(child.pid)
            return child

        proc_module.subprocess.Popen = recording_popen
        self.addCleanup(lambda: setattr(proc_module.subprocess, "Popen", original_popen))
        original_stream = run_command.stream

        def swap_then_stream(argv, **kwargs):
            # Exactly the gap: `launch` has revalidated and bound the descriptor,
            # and the child has not been spawned yet.
            program = Path(argv[0])
            self.protect(program)
            os.chmod(program.parent, 0o755)
            replacement = self.home / "impostor"
            replacement.write_bytes(b"#!/bin/sh\nexit 0\n")
            os.chmod(replacement, 0o755)
            os.replace(replacement, program)
            swapped.append(str(program))
            return original_stream(argv, **kwargs)

        # The swap destroys the interpreter on purpose, so the shared node is
        # rebuilt for the next test rather than inheriting the wreckage.
        self.rebuild_after()
        run_command.stream = swap_then_stream
        try:
            with ProcessSpy() as spy:
                with installer.verified_active_group(self.lock) as active:
                    envelope = run_command._start_verified(
                        self._context("validator", "exec-gap"), "validator", self.lock, active)
        finally:
            run_command.stream = original_stream

        self.assertTrue(swapped, "the fixture must really have replaced the program")
        self.assertNotEqual(envelope.status, "ok",
                            "a program replaced after verification must not produce a start")
        # The refusal must name the binding, and nothing from the swapped program
        # may survive: the check runs before start is reported and before a single
        # line of output is read.
        self.assertIn("replaced between verification and execution",
                      json.dumps(envelope.to_dict() if hasattr(envelope, "to_dict")
                                 else {"error": str(envelope.error)}))
        self.assertTrue(spawned, "the fixture must really have reached the spawn")
        for pid in spawned:
            self.assertFalse(_pid_is_live(pid),
                             f"pid {pid} from the swapped program is still running")
        self.assertFalse(stubs["validator"].ran)
        self.assertNoWeakening(before, pointer_may_change=True)

    def test_the_binding_accepts_an_untouched_program(self):
        from cathedral_node.commands import run as run_command
        self._stub("validator")
        with installer.verified_active_group(self.lock) as active:
            envelope = run_command._start_verified(
                self._context("validator", "exec-clean"), "validator", self.lock, active)
        self.assertNotIn("replaced between verification and execution", str(envelope.error))


class TestCommittedStateIsReportedNotGuessed(Gate0Base):

    def test_a_directory_fsync_failure_after_the_pointer_is_published_reports_committed(self):
        """The publish is one `os.replace`. A failure after it leaves the release
        active, and unwinding would delete the files a committed release names."""
        from cathedral_node import safeio
        original = safeio.secure_write_atomic
        pointer = paths.active_release_pointer()

        def publish_then_fail(path, data, **kw):
            original(path, data, **kw)
            if Path(str(path)).name == pointer.name and b'"active"' in data:
                raise OSError(errno.EIO, "injected directory fsync failure after the publish")

        safeio.secure_write_atomic = publish_then_fail
        try:
            ok, detail, result = self.install(self.bundle("fsync-after"))
        finally:
            safeio.secure_write_atomic = original

        self.assertTrue(ok, f"a committed pointer must not be reported as a failed install: {detail}")
        self.assertEqual(self.pointer_doc()["state"], "active")
        ok, reason, _group = self.verify_active()
        self.assertTrue(ok, reason)

    def test_recovery_reports_committed_state_when_a_post_commit_write_fails(self):
        """An OSError from a post-commit write used to escape `recover` entirely, and
        the next recovery saw an ACTIVE pointer and said there was nothing to do."""
        bundle = self.bundle("recover-oserror")
        ok, detail, _ = self.install(bundle)
        self.assertTrue(ok, detail)
        document = self.pointer_doc()
        self.write_pointer({**document, "state": "pending"})
        paths.activation_marker().unlink(missing_ok=True)

        original = installer._record_activation
        installer._record_activation = lambda *a, **k: (_ for _ in ()).throw(
            OSError(errno.EIO, "injected witness failure"))
        try:
            recovered, detail = installer.recover(self.lock)
        finally:
            installer._record_activation = original
        self.assertFalse(recovered, "an incomplete recovery must not report success")
        self.assertIn("active", detail, f"it must say what is actually committed: {detail}")
        self.assertIn("heal", detail)

        # And the heal is real: re-applying the same release restores the witnesses.
        ok, detail, _ = self.install(bundle)
        self.assertTrue(ok, detail)
        self.assertTrue(paths.activation_marker().exists())

    def test_witness_healing_is_bound_to_the_release_it_witnesses(self):
        """A v1 marker must not satisfy a v2 activation."""
        first = self.bundle("witness-v1", version=1)
        ok, detail, _ = self.install(first)
        self.assertTrue(ok, detail)
        v1_marker = paths.activation_marker().read_bytes()

        second = self.bundle("witness-v2", version=2)
        original = installer._record_activation
        installer._record_activation = lambda *a, **k: (_ for _ in ()).throw(
            OSError(errno.EIO, "injected witness failure"))
        try:
            ok, detail, result = self.install(second, supervisor=_QuietSupervisor())
        finally:
            installer._record_activation = original
        self.assertTrue(ok, detail)
        self.assertTrue(result["witnesses_incomplete"])
        self.assertEqual(paths.activation_marker().read_bytes(), v1_marker,
                         "the fixture must have left the v1 witness in place")

        missing = installer._missing_activation_witnesses(self.pointer_doc())
        self.assertTrue(missing, "a v1 witness must not satisfy a v2 activation")
        ok, detail, result = self.install(second, supervisor=_QuietSupervisor())
        self.assertTrue(ok, detail)
        self.assertIn("healed", detail)
        self.assertNotEqual(paths.activation_marker().read_bytes(), v1_marker,
                            "healing must write the witness for the release that is committed")
        self.assertEqual(installer._missing_activation_witnesses(self.pointer_doc()), [])

    def test_a_fresh_node_rollback_that_cannot_clear_the_pointer_is_not_reported_as_rolled_back(self):
        original_clear = installer._clear_pointer
        original_switch = installer._qualify_and_switch
        installer._clear_pointer = lambda: (_ for _ in ()).throw(
            OSError(errno.EIO, "injected pointer removal failure"))
        installer._qualify_and_switch = lambda *a, **k: (False, "injected activation failure", None)
        try:
            ok, detail, _ = self.install(self.bundle("clear-fail"))
        finally:
            installer._clear_pointer = original_clear
            installer._qualify_and_switch = original_switch
        self.assertNoSuccessfulNoOp(ok, detail)
        events = [json.loads(line) for line in paths.release_journal().read_text().splitlines()
                  if line.strip()]
        names = [event["event"] for event in events]
        self.assertNotIn("ROLLED_BACK", names,
                         "a pointer that could not be removed is not a completed rollback")
        self.assertIn("ROLLBACK_INCOMPLETE", names)
        self.assertTrue(paths.recovery_required(),
                        "the interrupted transaction must still be visible to recovery")

    def test_the_transaction_journals_are_refused_through_hostile_shapes(self):
        """Each record is driven on the path that actually writes it, and each is
        judged by what the node ends up in — not by which exception was raised."""
        def plant(path: Path) -> Path:
            decoy = self.home / f"decoy-{path.name}"
            decoy.write_text("")
            os.chmod(decoy, 0o600)
            with contextlib.suppress(OSError):
                path.unlink()
            os.symlink(decoy, path)
            self.addCleanup(lambda: path.unlink(missing_ok=True))
            return decoy

        with self.subTest(record="release journal"):
            self.setUp()
            decoy = plant(paths.release_journal())
            before = self.weakening_snapshot()
            ok, detail, _ = self.install(self.bundle("hostile-release-journal"))
            self.assertNoSuccessfulNoOp(ok, detail)
            self.assertEqual(decoy.read_text(), "", "nothing may be written through the symlink")
            self.assertNoWeakening(before, pointer_may_change=True)

        with self.subTest(record="activation journal"):
            self.setUp()
            decoy = plant(paths.activation_journal())
            ok, detail, result = self.install(self.bundle("hostile-activation-journal"))
            self.assertEqual(decoy.read_text(), "", "nothing may be written through the symlink")
            if ok:
                # Past the commit the release IS active; the only honest report is
                # "active, with witnesses that could not be written".
                self.assertTrue((result or {}).get("witnesses_incomplete"), detail)
                self.assertIn("heal", detail)
                self.assertTrue(installer._missing_activation_witnesses(self.pointer_doc()))
            else:
                self.assertNoSuccessfulNoOp(ok, detail)

        with self.subTest(record="rollback ledger"):
            self.setUp()
            decoy = plant(paths.rollback_ledger())
            original = installer._qualify_and_switch
            installer._qualify_and_switch = lambda *a, **k: (False, "injected failure", None)
            try:
                ok, detail, _ = self.install(self.bundle("hostile-rollback-ledger"))
            finally:
                installer._qualify_and_switch = original
            self.assertNoSuccessfulNoOp(ok, detail)
            self.assertEqual(decoy.read_text(), "", "nothing may be written through the symlink")


class _QuietSupervisor:
    """Stops and starts without complaint; readiness always passes."""

    def running_roles(self):
        return []

    def stop(self, roles):
        return None

    def start(self, group, roles):
        return None

    def readiness(self, roles):
        return True, "ready"


class _FailingReadiness(_QuietSupervisor):
    def readiness(self, roles):
        return False, "injected readiness failure"


if __name__ == "__main__":
    unittest.main()
