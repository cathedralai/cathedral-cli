"""Verifying and authorizing a signed release *bundle* before anything runs.

The node never builds unverified source and never resolves dependencies over the
network. A release engineer publishes a **bundle**: one canonical manifest for the
whole node (compute + distill + validator), a detached SSH signature over its exact
bytes, and — per role — the inert source archive plus the *complete transitive*
set of wheels that constitute an offline install. This module turns that bundle
into a single sealed :class:`AuthorizedBundle` value that is **constructible only
after** the manifest signature and every inert artifact hash have verified.

  fetch inert bytes  ->  AuthorizedBundle.verify (signature + every artifact hash)
  ->  install offline (`pip --no-index --no-deps --require-hashes --only-binary`)
  ->  no untrusted code ever runs before verification, and no build backend or
      dependency resolver runs at all.

Everything is fail-closed: the verifier is a root-owned, non-symlink ``ssh-keygen``
from an absolute allowlist run in a scrubbed environment; the local
``allowed_signers`` trust file is opened once with ``O_NOFOLLOW`` and its ancestors'
ownership and modes are checked; the manifest must be exact canonical ASCII JSON
with no duplicate, unknown, non-finite, or empty security fields; artifact and wheel
names must be single-component PEP 427 ASCII; the bundle may contain nothing beyond
the signed set; timestamps must be aware UTC within a bounded, ordered lifetime; and
the signed ``release_version`` is monotonic against a durable floor. The node ONLY
verifies; it never holds, loads, or generates a signing seed.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import os
import re
import stat as _stat
import tempfile
import types
from pathlib import Path
from typing import Any

from cathedral_node import proc

NAMESPACE = "cathedral-release"
RELEASE_SCHEMA = "cathedral.release.v2"
ROLES = ("distill", "compute", "validator")

# The one identity a release must be signed as. Pinned in code AND required in the
# operator's root-owned allowed_signers; the trusted signer is never inferred from
# the contents of the trust file.
RELEASE_IDENTITY = "release@cathedral.computer"

_ALLOWED_VERIFIERS = ("/usr/bin/ssh-keygen", "/bin/ssh-keygen")

# --- manifest validation modes --------------------------------------------------
#
# Signed-bundle expiry is an ACQUISITION window, not a runtime kill switch. The
# three modes make that distinction explicit and impossible to get wrong by
# accident, because the mode is a required argument at every call site.
#
#   CANDIDATE_ACQUISITION  installing or updating to a new candidate. The bundle
#                          must be inside `created_at <= now < expires_at`.
#   RETAINED_RUNTIME       re-verifying an already-installed release before start,
#                          test, state, restart, or a no-op update. Signature,
#                          canonical form, timestamp ordering and lifetime, ABI,
#                          platform, roles, digest, floor, revocation, receipts and
#                          filesystem all still apply; the *acquisition window* does
#                          not, so an installed node does not die on a timer.
#   PENDING_RECOVERY       finishing a transaction whose release the floor already
#                          names. The acquisition decision was made and committed
#                          before the crash; reapplying the window would strand the
#                          node between two releases.
CANDIDATE_ACQUISITION = "candidate_acquisition"
RETAINED_RUNTIME = "retained_runtime"
PENDING_RECOVERY = "pending_recovery"
_MODES = (CANDIDATE_ACQUISITION, RETAINED_RUNTIME, PENDING_RECOVERY)
_ENFORCES_ACQUISITION_WINDOW = frozenset({CANDIDATE_ACQUISITION})

# Bounds. A release lives at most this long and may be at most this far in the
# future relative to the verifying clock; artifacts and bundles are size-capped so
# a hostile manifest cannot describe an unbounded read.
_MAX_SKEW = _dt.timedelta(hours=6)
_MAX_LIFETIME = _dt.timedelta(days=400)
_MAX_RELEASE_VERSION = 2**31
_MAX_WHEEL_SIZE = 4 * 2**30           # 4 GiB per wheel
_MAX_BUNDLE_BYTES = 16 * 2**30        # 16 GiB per bundle
_MAX_ARTIFACTS_PER_ROLE = 4096

# Exact key sets — an unknown key in a security-relevant object is a refusal.
_MANIFEST_KEYS = {"schema", "release_version", "identity", "created_at", "expires_at",
                  "python", "abi", "platforms", "roles"}
_PYTHON_KEYS = {"min", "max_exclusive"}
_ROLE_KEYS = {"repository", "revision", "distribution", "version", "source_sha256",
              "extras", "entrypoints", "server_entrypoints", "launch_mode", "protocol",
              "artifacts_root", "requirements"}
_WHEEL_KEYS = {"file", "name", "version", "size", "sha256", "tags", "root"}

# A single-component PEP 427 wheel filename in strict ASCII: name-version(-build)?-
# pytag-abitag-plattag.whl, starting alphanumeric, no separators or controls.
_WHEEL_FILE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._]*[A-Za-z0-9])?)"
    r"-(?P<ver>[A-Za-z0-9][A-Za-z0-9._+!]*)"
    r"(?:-(?P<build>[0-9][A-Za-z0-9._]*))?"
    r"-(?P<py>[A-Za-z0-9.]+)-(?P<abi>[A-Za-z0-9.]+)-(?P<plat>[A-Za-z0-9._]+)\.whl$")
_ROOT_COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")  # non-empty ascii token


def canonical_bytes(document: Any) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).strip("-").lower()


# --- the trusted verifier and its inputs ---------------------------------------

def _trusted_verifier() -> str | None:
    for candidate in _ALLOWED_VERIFIERS:
        try:
            if Path(candidate).is_symlink():
                continue
            info = os.stat(candidate)
        except OSError:
            continue
        if not _stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            continue
        return candidate
    return None


def verifier_available() -> bool:
    return _trusted_verifier() is not None


def _owner_ok(info: os.stat_result) -> bool:
    return info.st_uid in (0, os.geteuid()) and not (info.st_mode & 0o022)


def read_trust_file(path: Path) -> tuple[bool, str, str | None]:
    """Open ``allowed_signers`` once with ``O_NOFOLLOW`` and read from that same
    descriptor — no stat/read TOCTOU. The file's real path and every real ancestor
    must be owned by root or this user and not writable by others, so no other user
    can substitute a key. The path is canonicalised first, so benign system symlinks
    (``/var`` -> ``/private/var``) are fine while an attacker cannot insert a
    writable or foreign-owned directory into the resolved chain."""
    path = Path(path)
    try:
        parent = path.parent.resolve()  # resolve ancestors (benign /var symlinks), not the file
    except OSError as exc:
        return False, f"the allowed_signers path could not be resolved: {exc}", None
    target = parent / path.name
    for ancestor in [parent, *parent.parents]:
        try:
            info = os.lstat(ancestor)
        except OSError as exc:
            return False, f"cannot stat {ancestor}: {exc}", None
        if not _owner_ok(info):
            return False, f"{ancestor} is foreign-owned or writable by others", None
    try:
        # O_NOFOLLOW on the final component: a symlinked trust file is refused here.
        fd = os.open(str(target), os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        return False, f"the allowed_signers file could not be opened safely (symlink?): {exc}", None
    try:
        info = os.fstat(fd)
        if not _stat.S_ISREG(info.st_mode):
            return False, "the allowed_signers file is not a regular file", None
        if not _owner_ok(info):
            return False, "the allowed_signers file is foreign-owned or writable by others", None
        data = os.read(fd, 1 << 20)
    finally:
        os.close(fd)
    try:
        return True, "ok", data.decode("utf-8")
    except UnicodeDecodeError:
        return False, "the allowed_signers file is not valid UTF-8", None


def _scrubbed_env(home: Path, tmpdir: Path) -> dict[str, str]:
    """The verifier is a signed-release decision too, so it gets the same
    environment every other signed child gets."""
    return proc.signed_child_env(home=home, tmpdir=tmpdir)


def _verify_signature(message: bytes, signature: bytes, allowed_signers: str,
                      identity: str, namespace: str, timeout: float) -> bool:
    exe = _trusted_verifier()
    if exe is None:
        return False
    if not (message and signature and allowed_signers and identity and namespace):
        return False
    if any(ch in identity for ch in "\n\r\x00") or any(ch in namespace for ch in "\n\r\x00 "):
        return False
    with tempfile.TemporaryDirectory(prefix="cathedral-lock-") as tmp:
        base = Path(tmp)
        home = base / "home"
        home.mkdir(mode=0o700)
        signers = base / "allowed_signers"
        sig = base / "message.sig"
        signers.write_text(allowed_signers, encoding="utf-8")
        sig.write_bytes(signature)
        result = proc.probe(
            [exe, "-Y", "verify", "-f", str(signers), "-I", identity,
             "-n", namespace, "-s", str(sig)],
            stdin_bytes=message, timeout=timeout, inherit_env=False,
            env=_scrubbed_env(home, base))
    return result.returncode == 0 and not result.timed_out


# --- strict manifest parsing ---------------------------------------------------

class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateKey(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON constant {value!r}")


def parse_strict(raw: bytes) -> dict:
    """Parse a manifest, rejecting non-ASCII, non-canonical form, duplicate keys,
    and non-finite constants (NaN / Infinity)."""
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("release manifest is not ASCII") from exc
    document = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    if not isinstance(document, dict):
        raise ValueError("release manifest is not an object")
    if canonical_bytes(document) != raw:
        raise ValueError("release manifest is not in canonical form")
    return document


def _aware(value: Any) -> _dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None  # aware only; naive is refused


def _is_int(value: Any, lo: int, hi: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and lo <= value <= hi


def _exact_keys(obj: Any, allowed: set[str]) -> bool:
    return isinstance(obj, dict) and set(obj.keys()) == allowed


def _string_list(value: Any) -> bool:
    """A list of non-empty ASCII tokens with no duplicates."""
    if not isinstance(value, list):
        return False
    if any(not isinstance(x, str) or not x or not x.isascii() for x in value):
        return False
    return len(set(value)) == len(value)


# --- sealed, deeply-immutable authorization ------------------------------------

_SEAL = object()  # only verify() holds this; it gates construction


class Artifact:
    __slots__ = ("file", "name", "version", "size", "sha256", "py_tag", "abi_tag", "plat_tag")

    def __init__(self, seal, file, name, version, size, sha256, py_tag, abi_tag, plat_tag):
        if seal is not _SEAL:
            raise TypeError("Artifact is constructed only by release verification")
        object.__setattr__(self, "file", file)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "size", size)
        object.__setattr__(self, "sha256", sha256)
        object.__setattr__(self, "py_tag", py_tag)
        object.__setattr__(self, "abi_tag", abi_tag)
        object.__setattr__(self, "plat_tag", plat_tag)

    def __setattr__(self, *_a):
        raise AttributeError("Artifact is immutable")


class RoleRelease:
    __slots__ = ("role", "repository", "revision", "distribution", "version",
                 "source_sha256", "extras", "entrypoints", "server_entrypoints",
                 "launch_mode", "protocol", "artifacts_root", "artifacts")

    def __init__(self, seal, **kw):
        if seal is not _SEAL:
            raise TypeError("RoleRelease is constructed only by release verification")
        for key in self.__slots__:
            object.__setattr__(self, key, kw[key])

    def __setattr__(self, *_a):
        raise AttributeError("RoleRelease is immutable")

    @property
    def root_artifact(self) -> "Artifact | None":
        matches = [a for a in self.artifacts if normalized_name(a.name) == normalized_name(self.distribution)]
        return matches[0] if len(matches) == 1 else None


class ReleaseAuthorization:
    __slots__ = ("release_version", "identity", "lock_digest", "created_at", "expires_at", "_roles")

    def __init__(self, seal, release_version, identity, lock_digest, created_at, expires_at, roles):
        if seal is not _SEAL:
            raise TypeError("ReleaseAuthorization is constructed only by release verification")
        object.__setattr__(self, "release_version", release_version)
        object.__setattr__(self, "identity", identity)
        object.__setattr__(self, "lock_digest", lock_digest)
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "_roles", types.MappingProxyType(dict(roles)))

    def __setattr__(self, *_a):
        raise AttributeError("ReleaseAuthorization is immutable")

    @property
    def roles(self) -> "types.MappingProxyType[str, RoleRelease]":
        return self._roles

    def role(self, role: str) -> "RoleRelease | None":
        return self._roles.get(role)


def _parse_wheel_filename(file: str) -> tuple[str, str, str, str, str] | None:
    match = _WHEEL_FILE_RE.match(file)
    if not match:
        return None
    return (match["name"], match["ver"], match["py"], match["abi"], match["plat"])


def _role_release(role: str, spec: Any) -> RoleRelease | None:
    if not _exact_keys(spec, _ROLE_KEYS):
        return None
    repository = spec["repository"]; revision = spec["revision"]
    distribution = spec["distribution"]; version = spec["version"]
    source_sha256 = spec["source_sha256"]; launch_mode = spec["launch_mode"]
    protocol = spec["protocol"]; extras = spec["extras"]; entrypoints = spec["entrypoints"]
    server_entrypoints = spec["server_entrypoints"]; requirements = spec["requirements"]
    artifacts_root = spec["artifacts_root"]
    if not (isinstance(repository, str) and repository.isascii() and repository
            and isinstance(revision, str) and _HEX40_RE.match(revision)):
        return None
    if not (isinstance(distribution, str) and _TOKEN_RE.match(distribution)
            and isinstance(version, str) and version and version.isascii()):
        return None
    if not (isinstance(source_sha256, str) and _HEX64_RE.match(source_sha256)):
        return None
    if not (isinstance(launch_mode, str) and launch_mode and launch_mode.isascii()
            and isinstance(protocol, str) and protocol and protocol.isascii()):
        return None
    if not (isinstance(artifacts_root, str) and _ROOT_COMPONENT_RE.match(artifacts_root)
            and artifacts_root not in ("..", ".")):
        return None
    if not (_string_list(extras) and _string_list(entrypoints) and _string_list(server_entrypoints)):
        return None
    if not isinstance(requirements, list) or not (0 < len(requirements) <= _MAX_ARTIFACTS_PER_ROLE):
        return None
    artifacts: list[Artifact] = []
    seen_files: set[str] = set()
    seen_pkgs: set[str] = set()
    for req in requirements:
        if not _exact_keys(req, _WHEEL_KEYS):
            return None
        file = req["file"]; name = req["name"]; ver = req["version"]
        size = req["size"]; sha = req["sha256"]; tags = req["tags"]; root = req["root"]
        parsed = _parse_wheel_filename(file) if isinstance(file, str) else None
        if parsed is None:
            return None
        fname, fver, fpy, fabi, fplat = parsed
        if not (isinstance(name, str) and _TOKEN_RE.match(name)
                and isinstance(ver, str) and ver and ver.isascii()):
            return None
        # The signed name/version must agree with the filename's embedded ones.
        if normalized_name(fname) != normalized_name(name) or fver != ver:
            return None
        if not _is_int(size, 0, _MAX_WHEEL_SIZE) or not (isinstance(sha, str) and _HEX64_RE.match(sha)):
            return None
        if not (_string_list(tags) and isinstance(root, list) and all(isinstance(r, str) and r for r in root)):
            return None
        if file in seen_files:
            return None
        norm = normalized_name(name)
        if norm in seen_pkgs:
            return None  # the same package pinned twice — an ambiguous closure
        seen_files.add(file); seen_pkgs.add(norm)
        artifacts.append(Artifact(_SEAL, file, name, ver, size, sha.lower(), fpy, fabi, fplat))
    # Exactly one wheel is the role's own distribution (the unique root wheel).
    roots = [a for a in artifacts if normalized_name(a.name) == normalized_name(distribution)]
    if len(roots) != 1:
        return None
    return RoleRelease(_SEAL, role=role, repository=repository, revision=revision,
                       distribution=distribution, version=version, source_sha256=source_sha256.lower(),
                       extras=tuple(extras), entrypoints=tuple(entrypoints),
                       server_entrypoints=tuple(server_entrypoints), launch_mode=launch_mode,
                       protocol=protocol, artifacts_root=artifacts_root, artifacts=tuple(artifacts))


def _validate_manifest(document: dict, identity: str, python_info: tuple[int, int],
                       abi: str, platform_token: str, now: _dt.datetime, mode: str,
                       ) -> tuple[str | None, ReleaseAuthorization | None]:
    if mode not in _MODES:
        return f"unknown manifest validation mode {mode!r}", None
    if now.tzinfo is None:
        return "the verifying clock is not timezone-aware", None
    if not _exact_keys(document, _MANIFEST_KEYS):
        return "release manifest has an unknown or missing top-level field", None
    if document["schema"] != RELEASE_SCHEMA:
        return "release manifest schema is unrecognised", None
    if document["identity"] != identity:
        return "release manifest identity does not match the signer", None
    if not _is_int(document["release_version"], 1, _MAX_RELEASE_VERSION):
        return "release_version is not a positive bounded integer", None
    created = _aware(document["created_at"])
    expiry = _aware(document["expires_at"])
    if created is None or expiry is None:
        return "release timestamps must be aware UTC", None
    if created > now + _MAX_SKEW:
        return "release created_at is too far in the future", None
    if expiry <= created:
        return "release expiry is not after its creation", None
    if expiry - created > _MAX_LIFETIME:
        return "release lifetime exceeds the maximum", None
    # The acquisition window, and only the acquisition window, is mode-gated. A
    # retained release keeps its signature, its bounded lifetime, and every other
    # check after `expires_at`; it simply may not be newly acquired.
    if mode in _ENFORCES_ACQUISITION_WINDOW and expiry <= now:
        return "release is expired: its installation and update window has closed", None
    py = document["python"]
    if not _exact_keys(py, _PYTHON_KEYS):
        return "release python constraint is malformed", None
    try:
        pmin = tuple(int(x) for x in py["min"]); pmax = tuple(int(x) for x in py["max_exclusive"])
    except (TypeError, ValueError):
        return "release python constraint is malformed", None
    if not (pmin <= python_info < pmax):
        return f"this interpreter {python_info} is outside the release python range", None
    if not (_string_list(document["abi"]) and abi in document["abi"]):
        return f"this interpreter ABI {abi!r} is not authorized by the release", None
    if not (_string_list(document["platforms"]) and platform_token in document["platforms"]):
        return f"this platform {platform_token!r} is not authorized by the release", None
    roles_spec = document["roles"]
    if not isinstance(roles_spec, dict) or set(roles_spec.keys()) != set(ROLES):
        return "a signed release must describe exactly the compute, distill and validator roles", None
    roles: dict[str, RoleRelease] = {}
    for role, spec in roles_spec.items():
        parsed = _role_release(role, spec)
        if parsed is None:
            return f"release manifest role {role!r} is malformed or has an unknown field", None
        roles[role] = parsed
    auth = ReleaseAuthorization(_SEAL, document["release_version"], identity,
                                digest_bytes(canonical_bytes(document)),
                                document["created_at"], document["expires_at"], roles)
    return None, auth


def _sha256_file(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


class AuthorizedBundle:
    """A bundle whose signature AND every inert artifact hash have verified.

    Construction is sealed: :meth:`verify` is the only path, so holding an instance
    is proof that the manifest was signed by the pinned identity and that every wheel
    and source archive on disk matches it byte-for-byte. The authorization it carries
    is deeply immutable.
    """

    __slots__ = ("directory", "authorization")

    def __init__(self, seal, directory, authorization):
        if seal is not _SEAL:
            raise TypeError("AuthorizedBundle is produced only by AuthorizedBundle.verify")
        object.__setattr__(self, "directory", directory)
        object.__setattr__(self, "authorization", authorization)

    def __setattr__(self, *_a):
        raise AttributeError("AuthorizedBundle is immutable")

    @classmethod
    def verify(cls, directory: Path, *, allowed_signers_path: Path, identity: str,
               python_info: tuple[int, int], abi: str, platform_token: str,
               min_release_version: int, active_lock_digest: str | None,
               now: _dt.datetime, mode: str = CANDIDATE_ACQUISITION,
               namespace: str = NAMESPACE, timeout: float = 10.0,
               ) -> tuple[bool, str, "AuthorizedBundle | None"]:
        directory = Path(directory)
        ok, reason, allowed_signers = read_trust_file(allowed_signers_path)
        if not ok or allowed_signers is None:
            return False, reason, None
        manifest_path = directory / "release.json"
        sig_path = directory / "release.json.sig"
        for path in (directory, manifest_path, sig_path):
            if path.is_symlink():
                return False, f"{path.name or 'bundle'} is a symlink", None
        # Reject anything in the bundle beyond the signed layout, before reading it.
        allowed_top = {"release.json", "release.json.sig", "roles"}
        try:
            present_top = {p.name for p in directory.iterdir()}
        except OSError as exc:
            return False, f"the release bundle is unreadable: {exc}", None
        if present_top - allowed_top:
            return False, f"the bundle contains unexpected entries {sorted(present_top - allowed_top)}", None
        try:
            release_bytes = manifest_path.read_bytes()
            signature = sig_path.read_bytes()
        except OSError as exc:
            return False, f"could not read the release bundle: {exc}", None
        if not _verify_signature(release_bytes, signature, allowed_signers, identity, namespace, timeout):
            return False, "release signature did not verify with a trusted verifier", None
        try:
            document = parse_strict(release_bytes)
        except _DuplicateKey as exc:
            return False, f"release manifest has a {exc}", None
        except ValueError as exc:
            return False, str(exc), None
        reason, auth = _validate_manifest(document, identity, python_info, abi, platform_token,
                                          now, mode)
        if auth is None:
            return False, reason or "release manifest is invalid", None
        if auth.release_version < min_release_version:
            return False, (f"release_version {auth.release_version} is older than the floor "
                           f"{min_release_version}; a downgrade is refused"), None
        if auth.release_version == min_release_version and auth.lock_digest != (active_lock_digest or ""):
            return False, (f"release_version {auth.release_version} equals the floor but is a "
                           f"different release; refusing to replace it"), None
        ok, reason = _verify_artifacts(directory, auth)
        if not ok:
            return False, reason, None
        return True, "ok", cls(_SEAL, directory, auth)

    def wheel_paths(self, role: str) -> list[tuple[Path, str]]:
        spec = self.authorization.role(role)
        if spec is None:
            return []
        base = self.directory / "roles" / role / spec.artifacts_root
        return [(base / a.file, a.sha256) for a in spec.artifacts]

    def source_archive(self, role: str) -> Path:
        return self.directory / "roles" / role / "source.tar"


def _verify_artifacts(directory: Path, auth: ReleaseAuthorization) -> tuple[bool, str]:
    roles_dir = directory / "roles"
    if roles_dir.is_symlink() or not roles_dir.is_dir():
        return False, "the bundle has no roles directory"
    try:
        present_roles = {p.name for p in roles_dir.iterdir()}
    except OSError as exc:
        return False, f"the roles directory is unreadable: {exc}"
    if present_roles != set(auth.roles.keys()):
        return False, f"the bundle roles {sorted(present_roles)} are not exactly the signed set"
    total = 0
    for role, spec in auth.roles.items():
        root = roles_dir / role
        if root.is_symlink():
            return False, f"{role}: the role directory is a symlink"
        try:
            present = {p.name for p in root.iterdir()}
        except OSError as exc:
            return False, f"{role}: role directory unreadable: {exc}"
        if present != {"source.tar", spec.artifacts_root}:
            return False, f"{role}: unexpected role-directory entries {sorted(present)}"
        source = root / "source.tar"
        if source.is_symlink() or not source.is_file():
            return False, f"{role}: the source archive is missing or a symlink"
        total += source.stat().st_size
        if _sha256_file(source) != spec.source_sha256:
            return False, f"{role}: the source archive hash does not match the signed release"
        wheels_dir = root / spec.artifacts_root
        if wheels_dir.is_symlink() or not wheels_dir.is_dir():
            return False, f"{role}: the wheelhouse is missing or a symlink"
        try:
            present_wheels = {p.name for p in wheels_dir.iterdir()}
        except OSError as exc:
            return False, f"{role}: wheelhouse unreadable: {exc}"
        signed_files = {a.file for a in spec.artifacts}
        if present_wheels != signed_files:
            extra = sorted(present_wheels - signed_files)
            missing = sorted(signed_files - present_wheels)
            return False, f"{role}: wheelhouse mismatch (unexpected {extra}, missing {missing})"
        for artifact in spec.artifacts:
            wheel = wheels_dir / artifact.file
            if wheel.is_symlink() or not wheel.is_file():
                return False, f"{role}: {artifact.file} is missing or a symlink"
            try:
                size = wheel.stat().st_size
            except OSError:
                return False, f"{role}: {artifact.file} is unreadable"
            if size != artifact.size:
                return False, f"{role}: {artifact.file} size does not match the signed release"
            total += size
            if total > _MAX_BUNDLE_BYTES:
                return False, "the bundle exceeds the maximum size"
            if _sha256_file(wheel) != artifact.sha256:
                return False, f"{role}: {artifact.file} hash does not match the signed release"
    return True, "ok"


def verify_manifest(release_bytes: bytes, signature: bytes, allowed_signers: str, identity: str, *,
                    python_info: tuple[int, int], abi: str, platform_token: str, now: _dt.datetime,
                    mode: str, namespace: str = NAMESPACE, timeout: float = 10.0,
                    ) -> tuple[bool, str, ReleaseAuthorization | None]:
    """Verify only the manifest's signature and shape (no on-disk artifacts).

    Used by the channel fetcher to learn the exact artifact list to download *after*
    the signature is trusted, and by retained-runtime and pending-recovery
    verification of an already-installed release. ``mode`` is mandatory: it is the
    single place the acquisition window is applied or deliberately not applied, so
    no call site can drift into treating expiry as a runtime kill switch.
    """
    if not _verify_signature(release_bytes, signature, allowed_signers, identity, namespace, timeout):
        return False, "release signature did not verify with a trusted verifier", None
    try:
        document = parse_strict(release_bytes)
    except _DuplicateKey as exc:
        return False, f"release manifest has a {exc}", None
    except ValueError as exc:
        return False, str(exc), None
    reason, auth = _validate_manifest(document, identity, python_info, abi, platform_token, now, mode)
    return (auth is not None), (reason or "ok"), auth


def verify_detached_signature(message: bytes, signature: bytes, allowed_signers: str,
                              identity: str, namespace: str, timeout: float = 10.0) -> bool:
    """The trusted-verifier primitive, for the other signed-document authorities
    (revocation today; policy, directives and authorizations later). Same hardened
    ``ssh-keygen`` from an absolute allowlist, same scrubbed environment."""
    return _verify_signature(message, signature, allowed_signers, identity, namespace, timeout)


def authorize_role(auth: ReleaseAuthorization, role: str, *, repository: str, revision: str,
                   distribution: str, extras: list[str], entrypoints: list[str],
                   server_entrypoints: list[str], protocol: str, launch_mode: str,
                   ) -> tuple[bool, str, RoleRelease | None]:
    """Confirm the signed release authorizes exactly this role's pinned contract."""
    spec = auth.role(role)
    if spec is None:
        return False, f"the release does not authorize the {role} role", None
    for field, signed, pinned in (
        ("repository", spec.repository, repository), ("revision", spec.revision, revision),
        ("distribution", spec.distribution, distribution), ("launch_mode", spec.launch_mode, launch_mode),
        ("protocol", spec.protocol, protocol)):
        if signed != pinned:
            return False, f"the release authorizes a different {field} for {role}", None
    for field, signed, pinned in (
        ("extras", sorted(spec.extras), sorted(extras)),
        ("entrypoints", sorted(spec.entrypoints), sorted(entrypoints)),
        ("server_entrypoints", sorted(spec.server_entrypoints), sorted(server_entrypoints))):
        if signed != pinned:
            return False, f"the release authorizes a different {field} set for {role}", None
    return True, "ok", spec
