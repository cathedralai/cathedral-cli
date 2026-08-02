"""A deterministic, offline signed-release-bundle fixture for Gate-0 tests.

Builds tiny real wheels for all three roles (distill + compute + validator, the
validator carrying an ``integration`` extra whose entrypoint lives in a second
wheel), assembles them into a bundle, and signs the manifest with a real
``ssh-keygen`` ed25519 key. Everything is offline and uses a located CPython
3.11-3.13 as the trusted parent, so the installer's real code path runs with zero
skips regardless of the interpreter running pytest.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from cathedral_node import lockfile, release_lock, revocation, safeio
from cathedral_node.lockfile import EnginePin, Lock

IDENTITY = "release@cathedral.computer"
REVOCATION_IDENTITY = revocation.REVOCATION_IDENTITY
_REV = {"distill": "1" * 40, "compute": "2" * 40, "validator": "3" * 40}


def locate_trusted_python() -> Path | None:
    for name in ("python3.11", "python3.12", "python3.13"):
        exe = shutil.which(name)
        if not exe:
            cand = Path(f"/opt/homebrew/bin/{name}")
            exe = str(cand) if cand.exists() else None
        if not exe:
            continue
        out = subprocess.run([exe, "-c", "import sys;print(sys._base_executable or sys.executable)"],
                             capture_output=True, text=True)
        base = out.stdout.strip()
        if base and Path(base).exists():
            return Path(base)
    return None


def _sha(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class BundleFixture:
    """Builds wheels once, then can emit any number of (optionally malformed) bundles."""

    def __init__(self, root: Path, trusted: Path):
        self.root = Path(root)
        self.trusted = trusted
        self.wheelhouse = self.root / "wheelhouse"
        self.wheelhouse.mkdir(parents=True, exist_ok=True)
        self.keydir = self.root / "keys"
        self.keydir.mkdir(parents=True, exist_ok=True)
        info = subprocess.run(
            [str(trusted), "-c", "import sysconfig,sys;print(sys.version_info.major,sys.version_info.minor);"
             "print(f'cp{sys.version_info.major}{sys.version_info.minor}');print(sysconfig.get_platform())"],
            capture_output=True, text=True).stdout.split("\n")
        self.py_info = tuple(int(x) for x in info[0].split())
        self.abi = info[1].strip()
        self.platform = info[2].strip()
        self._sentinel = self.root / "SENTINEL-build-ran"
        self._make_key()
        self._build_wheels()

    # ---- signing keys + trust files -------------------------------------------
    def _make_key(self):
        self.key = self.keydir / "id"
        subprocess.run(["/usr/bin/ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(self.key), "-q"], check=True)
        self.signers = self.keydir / "allowed_signers"
        self.signers.write_text(f"{IDENTITY} {(self.keydir / 'id.pub').read_text().strip()}\n")
        os.chmod(self.signers, 0o600)
        # A SEPARATE offline revocation authority: its own key, its own namespace,
        # its own trust file. A compromised release key cannot sign away its own
        # revocation, and the tests prove the node keeps them apart.
        self.revocation_key = self.keydir / "revocation-id"
        subprocess.run(["/usr/bin/ssh-keygen", "-t", "ed25519", "-N", "", "-f",
                        str(self.revocation_key), "-q"], check=True)
        self.revocation_signers = self.keydir / "revocation_signers"
        self.revocation_signers.write_text(
            f"{REVOCATION_IDENTITY} {(self.keydir / 'revocation-id.pub').read_text().strip()}\n")
        os.chmod(self.revocation_signers, 0o600)

    def sign(self, path: Path, key: Path | None = None, namespace: str | None = None) -> Path:
        sig = Path(str(path) + ".sig")
        sig.unlink(missing_ok=True)  # ssh-keygen -Y sign prompts (hangs) if .sig exists
        subprocess.run(["/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(key or self.key), "-n",
                        namespace or release_lock.NAMESPACE, str(path)], check=True, capture_output=True)
        return sig

    # ---- the offline revocation authority ------------------------------------
    def release_signer_fingerprint(self) -> str:
        return sorted(revocation.signer_fingerprints(self.signers.read_text(), IDENTITY))[0]

    def revocation_snapshot(self, sequence: int = 1, *, revoked_releases=(), revoked_signers=(),
                            issued_at: str | None = None, expires_at: str | None = None,
                            key: Path | None = None, mutate=None) -> tuple[bytes, bytes]:
        """Canonical, signed revocation bytes. ``mutate`` receives the document so a
        test can forge one field at a time."""
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc)
        document = {
            "schema": revocation.SNAPSHOT_SCHEMA, "sequence": sequence,
            "issued_at": issued_at or (now - _dt.timedelta(hours=1)).isoformat(),
            "expires_at": expires_at or (now + _dt.timedelta(days=30)).isoformat(),
            "revoked_release_digests": sorted(revoked_releases),
            "revoked_signer_fingerprints": sorted(revoked_signers),
            "signer_key_id": "cathedral-revocation-2026",
        }
        if mutate:
            document = mutate(document)
        raw = release_lock.canonical_bytes(document)
        staged = self.root / f"revocation-{sequence}-{os.urandom(4).hex()}.json"
        staged.write_bytes(raw)
        sig = self.sign(staged, key=key or self.revocation_key, namespace=revocation.NAMESPACE)
        signature = Path(sig).read_bytes()
        staged.unlink(missing_ok=True)
        Path(sig).unlink(missing_ok=True)
        return raw, signature

    def install_revocation(self, home: Path, sequence: int = 1, *, advance_floor: bool = True,
                           **kw) -> tuple[bytes, bytes]:
        """Place a valid last-known-good snapshot in a node's cache.

        Goes through the node's own verified provisioning transaction, so a test can
        never construct a cache shape or a floor relationship the product does not
        itself produce.

        ``advance_floor=False`` does not ask the product for a weaker transaction —
        there is no such thing, and a flag that skipped the floor would be a
        production footgun. It simulates the crash: the cache reached disk and the
        floor write never did.
        """
        raw, signature = self.revocation_snapshot(sequence, **kw)
        (Path(home) / "engines" / "revocation").mkdir(parents=True, exist_ok=True)
        if advance_floor:
            revocation.install_cache(raw, signature)
        else:
            self.stage_revocation_cache(raw, signature)
        return raw, signature

    def plant_revocation_cache(self, raw: bytes, signature: bytes) -> None:
        """Place bytes in the cache WITHOUT verifying them.

        Only for cases whose whole point is hostile or unverifiable content — a
        snapshot signed by the release key instead of the offline revocation
        authority, for instance. Kept separate from `stage_revocation_cache` so a
        test cannot plant unverifiable bytes by accident and then prove nothing.
        """
        safeio.secure_write_atomic(revocation.cache_file(), revocation._encode_cache(raw, signature))

    def stage_revocation_cache(self, raw: bytes, signature: bytes) -> None:
        """Publish a cache without its floor — a crash between the two writes.

        The bytes are verified first, so this stages a state the product could
        really reach, not one it would have refused outright.
        """
        ok, reason, _snapshot = revocation.verify_snapshot(
            raw, signature, self.revocation_signers.read_text(),
            now=_dt.datetime.now(_dt.timezone.utc))
        if not ok:
            raise AssertionError(f"the fixture may only stage verifiable bytes: {reason}")
        safeio.secure_write_atomic(revocation.cache_file(), revocation._encode_cache(raw, signature))

    # ---- wheels ---------------------------------------------------------------
    def _wheel(self, name: str, module: str, scripts: dict[str, str], extra_dep: str | None = None,
               server_exit: int | None = None) -> Path:
        src = self.root / f"src-{name}"
        (src / module).mkdir(parents=True, exist_ok=True)
        (src / module / "__init__.py").write_text("")
        body = "import sys\n"
        for func, kind in scripts.items():
            fn = func.replace("-", "_")
            if kind == "client":
                body += f"def {fn}():\n    print('{func} ok')\n"
            elif kind == "client_hang":
                body += f"def {fn}():\n    import time\n    time.sleep(120)\n"
            elif kind == "client_bad":
                body += f"def {fn}():\n    sys.exit(3)\n"
            elif kind == "server_ok":
                body += f"def {fn}():\n    import time\n    print('up', flush=True)\n    time.sleep(30)\n"
            elif kind == "server_clean_exit":
                body += f"def {fn}():\n    print('up', flush=True)\n    sys.exit(0)\n"
            elif kind == "server_exit_after_ready":
                body += (f"def {fn}():\n    import time\n    print('up', flush=True)\n"
                         f"    time.sleep(0.3)\n    sys.exit(0)\n")
            elif kind == "server_modal":
                # ONE server whose behaviour is chosen by the supervisor's
                # environment. The readiness matrix has to vary behaviour without
                # varying the signed distribution: a different wheel per case would
                # change the lockfile pins too, and then the "before" release would
                # stop verifying for reasons that have nothing to do with readiness.
                #
                # With no port in the environment it simply stays up, so the
                # installer's own bounded self-check — which runs with a scrubbed
                # environment — still passes.
                body += (
                    f"def {fn}():\n"
                    f"    import os, time\n"
                    f"    port = os.environ.get('CATHEDRAL_TEST_PORT')\n"
                    f"    mode = os.environ.get('CATHEDRAL_TEST_MODE', 'ready')\n"
                    f"    if not port:\n"
                    f"        print('up', flush=True)\n"
                    f"        time.sleep(30)\n"
                    f"        return\n"
                    f"    if mode == 'nobind':\n"
                    f"        time.sleep(300)\n"
                    f"        return\n"
                    f"    if mode == 'hang':\n"
                    f"        import socket\n"
                    f"        s = socket.socket()\n"
                    f"        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                    f"        s.bind(('127.0.0.1', int(port)))\n"
                    f"        s.listen(8)\n"
                    f"        print('up', flush=True)\n"
                    f"        while True:\n"
                    f"            try:\n"
                    f"                s.accept()\n"
                    f"            except OSError:\n"
                    f"                break\n"
                    f"            time.sleep(300)\n"
                    f"        return\n"
                    f"    if mode == 'child':\n"
                    f"        import subprocess, sys as _s\n"
                    f"        subprocess.Popen([_s.executable, '-c', 'import time;time.sleep(300)'])\n"
                    f"    served = '/other' if mode == 'wrong' else '/ready'\n"
                    f"    import http.server\n"
                    f"    class H(http.server.BaseHTTPRequestHandler):\n"
                    f"        def do_GET(self):\n"
                    f"            self.send_response(200 if self.path == served else 404)\n"
                    f"            self.end_headers()\n"
                    f"            self.wfile.write(b'ok')\n"
                    f"        def log_message(self, *a):\n"
                    f"            pass\n"
                    f"    srv = http.server.HTTPServer(('127.0.0.1', int(port)), H)\n"
                    f"    print('up', flush=True)\n"
                    f"    srv.serve_forever()\n")
            elif kind == "server_bad":
                body += f"def {fn}():\n    sys.exit({server_exit})\n"
        (src / module / "cli.py").write_text(body)
        dep = f'[project.optional-dependencies]\nintegration=["{extra_dep}"]\n' if extra_dep else ""
        eps = "".join(f'{func}="{module}.cli:{func.replace("-", "_")}"\n' for func in scripts)
        (src / "pyproject.toml").write_text(
            f'[build-system]\nrequires=["setuptools"]\nbuild-backend="setuptools.build_meta"\n'
            f'[project]\nname="{name}"\nversion="0.0.1"\n{dep}[project.scripts]\n{eps}'
            f'[tool.setuptools.packages.find]\nwhere=["."]\n')
        # Build the synthetic test wheels with the Gate 0 development
        # environment. The trusted parent is intentionally a bare CPython on
        # some supported hosts, including setup-python, and is tested as such by
        # the real installer path below. Requiring a build backend in that bare
        # parent makes every test fail during fixture setup before the installer
        # is exercised. The development environment pins setuptools, so this
        # remains reproducible and offline after provisioning.
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-build-isolation", "--no-deps",
                        "-w", str(self.wheelhouse), str(src)], check=True, capture_output=True)
        return next(self.wheelhouse.glob(f"{name.replace('-', '_')}-*.whl"))

    def _build_wheels(self):
        self.w = {
            "pd": self._wheel("pd", "pdpkg", {"pd-agent": "client", "pd-server": "server_ok"}),
            "pc": self._wheel("pc", "pcpkg", {"pc-agent": "client"}),
            "pv": self._wheel("pv", "pvpkg", {"pv-server": "server_ok"}, extra_dep="pvx"),
            "pvx": self._wheel("pvx", "pvxpkg", {"pv-preview": "client"}),
            "pbad": self._wheel("pbad", "pbadpkg", {"pd-agent": "client", "pd-server": "server_bad"}, server_exit=2),
            # The role-readiness and liveness matrix, one wheel per named failure.
            "pclean": self._wheel("pclean", "pcleanpkg",
                                  {"pd-agent": "client", "pd-server": "server_clean_exit"}),
            "plate": self._wheel("plate", "platepkg",
                                 {"pd-agent": "client", "pd-server": "server_exit_after_ready"}),
            "phang": self._wheel("phang", "phangpkg",
                                 {"pd-agent": "client_hang", "pd-server": "server_ok"}),
            "pcbad": self._wheel("pcbad", "pcbadpkg",
                                 {"pd-agent": "client_bad", "pd-server": "server_ok"}),
            # The real readiness and liveness matrix, driven by the supervisor's
            # environment: the right path, the wrong path, no bind at all, an accept
            # that never answers, or a server that spawns a child so process-group
            # cleanup is provable rather than assumed.
            "pserv": self._wheel("pserv", "pservpkg",
                                 {"pd-agent": "client", "pd-server": "server_modal"}),
            # A validator whose signed extra pins a version the closure cannot satisfy.
            "pvver": self._wheel("pvver", "pvverpkg", {"pv-server": "server_ok"}, extra_dep="pvx>=9.9"),
        }
        # a malicious sdist that WOULD write a sentinel if ever built
        mal = self.root / "malsrc"
        mal.mkdir(exist_ok=True)
        (mal / "setup.py").write_text(
            f"import pathlib;pathlib.Path({str(self._sentinel)!r}).write_text('pwned');raise SystemExit\n")
        import tarfile
        self.mal_tar = self.root / "malicious-source.tar"
        with tarfile.open(self.mal_tar, "w") as t:
            t.add(mal / "setup.py", arcname="setup.py")

    def sentinel_created(self) -> bool:
        return self._sentinel.exists()

    def _entry(self, wheel: Path, root_module: str) -> dict:
        fn = wheel.name
        return {"file": fn, "name": fn.split("-")[0], "version": "0.0.1",
                "size": wheel.stat().st_size, "sha256": _sha(wheel),
                "tags": ["py3-none-any"], "root": [root_module]}

    # ---- the standard 3-role plan --------------------------------------------
    def role_plan(self) -> dict:
        return {
            "distill": {"dist": "pd", "extras": [], "eps": ["pd-agent"], "seps": ["pd-server"],
                        "mode": "cybergym", "wheels": [self.w["pd"]], "roots": {"pd": "pdpkg"}},
            "compute": {"dist": "pc", "extras": [], "eps": ["pc-agent"], "seps": [],
                        "mode": "worker", "wheels": [self.w["pc"]], "roots": {"pc": "pcpkg"}},
            "validator": {"dist": "pv", "extras": ["integration"], "eps": ["pv-preview"],
                          "seps": ["pv-server"], "mode": "integration",
                          "wheels": [self.w["pv"], self.w["pvx"]], "roots": {"pv": "pvpkg", "pvx": "pvxpkg"}},
        }

    def plan_from_lock(self, lock: Lock) -> dict:
        """A plan of stub wheels shaped exactly like the repo's real lockfile pins —
        same distribution names, entrypoints, extras, launch modes and revisions — so
        a bundle built from it is authorized by the real ``cathedral.lock.json``."""
        import re
        plan = {}
        for role, pin in lock.engines.items():
            module = "m_" + re.sub(r"[^0-9a-z]+", "_", pin.distribution.lower())
            scripts = {ep: "client" for ep in pin.entrypoints}
            scripts.update({ep: "server_ok" for ep in pin.server_entrypoints})
            if not scripts:
                scripts = {f"{pin.distribution}-noop": "client"}
            wheel = self._wheel(pin.distribution, module, scripts)
            plan[role] = {"dist": pin.distribution, "extras": list(pin.extras),
                          "eps": list(pin.entrypoints), "seps": list(pin.server_entrypoints),
                          "mode": pin.launch_mode, "wheels": [wheel],
                          "roots": {wheel.name.split("-")[0]: module},
                          "repository": pin.repository, "revision": pin.revision}
        return plan

    def write_lockfile(self, path: Path, plan: dict | None = None) -> Path:
        """Write a cathedral.lock.json matching ``plan`` so ``lockfile.load()`` (via
        ``$CATHEDRAL_LOCKFILE``) and the installer agree on the pins."""
        plan = plan or self.role_plan()
        engines = {}
        profile = {}
        for role, r in plan.items():
            engines[role] = {
                "repository": r.get("repository", f"https://github.com/cathedralai/cathedral-{role}.git"),
                "revision": r.get("revision", _REV[role]), "distribution": r["dist"], "role": role}
            profile[role] = {"extras": r["extras"], "entrypoints": r["eps"],
                             "server_entrypoints": r["seps"], "launch_mode": r["mode"], "protocol": "1.0.0"}
        Path(path).write_text(json.dumps({
            "schema": "cathedral.node.lock.v1", "engines": engines, "excluded": {},
            "launch_profile": profile,
            "compatibility": {"python": ">=3.11,<3.14", "protocol_version": "1.0.0"}}))
        return Path(path)

    def make_lock(self, plan: dict | None = None) -> Lock:
        plan = plan or self.role_plan()
        engines = {}
        for role, r in plan.items():
            engines[role] = EnginePin(
                role=role, repository=f"https://github.com/cathedralai/cathedral-{role}.git",
                revision=_REV[role], branch="main", distribution=r["dist"], description=role,
                extras=tuple(r["extras"]), entrypoints=tuple(r["eps"]),
                server_entrypoints=tuple(r["seps"]), launch_mode=r["mode"], protocol="1.0.0")
        return Lock(engines=engines, excluded={}, python_requirement=">=3.11",
                    protocol_version="1.0.0", source=Path("cathedral.lock.json"))

    def make_bundle(self, out: Path, version: int, plan: dict | None = None, *, sign: bool = True,
                    source_tar: Path | None = None, mutate=None, key: Path | None = None,
                    created_at: str | None = None, expires_at: str | None = None) -> Path:
        plan = plan or self.role_plan()
        out = Path(out)
        roles_manifest = {}
        for role, r in plan.items():
            rd = out / "roles" / role
            (rd / "wheels").mkdir(parents=True, exist_ok=True)
            for w in r["wheels"]:
                shutil.copy(w, rd / "wheels")
            src = source_tar or (self.root / "inert.tar")
            if not Path(src).exists():
                Path(src).write_bytes(b"inert-source")
            shutil.copy(src, rd / "source.tar")
            roles_manifest[role] = {
                "repository": r.get("repository", f"https://github.com/cathedralai/cathedral-{role}.git"),
                "revision": r.get("revision", _REV[role]), "distribution": r["dist"], "version": "0.0.1",
                "source_sha256": _sha(rd / "source.tar"), "extras": r["extras"],
                "entrypoints": r["eps"], "server_entrypoints": r["seps"], "launch_mode": r["mode"],
                "protocol": "1.0.0", "artifacts_root": "wheels",
                "requirements": [self._entry(w, r["roots"][w.name.split("-")[0]]) for w in r["wheels"]]}
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc)
        created = created_at or (now - _dt.timedelta(days=1)).isoformat()
        expires = expires_at or (now + _dt.timedelta(days=30)).isoformat()
        manifest = {"schema": release_lock.RELEASE_SCHEMA, "release_version": version, "identity": IDENTITY,
                    "created_at": created, "expires_at": expires,
                    "python": {"min": [3, 11], "max_exclusive": [3, 14]}, "abi": [self.abi],
                    "platforms": [self.platform], "roles": roles_manifest}
        if mutate:
            manifest = mutate(manifest)
        out.mkdir(parents=True, exist_ok=True)
        (out / "release.json").write_bytes(release_lock.canonical_bytes(manifest))
        if sign:
            sig = self.sign(out / "release.json", key=key)
            shutil.move(str(sig), str(out / "release.json.sig"))
        return out

    def foreign_key(self) -> Path:
        """A second, untrusted release-shaped key: a 'forged signer' whose signature
        is structurally valid but is not the pinned identity's."""
        key = self.keydir / "foreign"
        if not key.exists():
            subprocess.run(["/usr/bin/ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(key), "-q"],
                           check=True)
        return key
