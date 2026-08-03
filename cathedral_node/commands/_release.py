"""Resolving the signed release bundle an install command must use.

Two delivery modes, one verification. Normal ``setup``/``update`` pull the bundle
from a configured HTTPS **release channel**; ``--release <dir>`` is an explicit
recovery/test override that reads a local bundle directly. Either way the fetch only
moves *inert* bytes, and the identical signature-and-artifact verification then runs
before any interpreter or subprocess — the installer re-verifies the whole bundle
via :class:`AuthorizedBundle`, so a channel fetch can never shortcut trust.

The trusted signer is pinned in code (``release@cathedral.computer``) and must be
authorized by the local, root-owned ``allowed_signers`` file. It is never inferred
from the trust file's contents.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import os
import shutil
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cathedral_node import paths, release_lock
from cathedral_node.engines import installer

ENV_RELEASE = "CATHEDRAL_RELEASE"          # explicit local bundle dir (recovery/test)
ENV_CHANNEL = "CATHEDRAL_RELEASE_CHANNEL"  # configured HTTPS channel base URL
ENV_SIGNERS = "CATHEDRAL_ALLOWED_SIGNERS"  # root-owned trust file

_MANIFEST_MAX = 1 << 20            # 1 MiB
_ARTIFACT_MAX = 4 * (1 << 30)      # 4 GiB
_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def channel(ctx) -> str | None:
    """The configured release channel, if any. The signed revocation snapshot is
    served from the same channel base, so acquisition can retain its first
    snapshot instead of failing closed on a fresh node with an empty cache."""
    return getattr(ctx.args, "channel", None) or os.environ.get(ENV_CHANNEL)


def default_signers_path() -> Path:
    override = os.environ.get(ENV_SIGNERS)
    return Path(override).expanduser() if override else paths.home() / "allowed_signers"


def trust_authorizes_identity(signers_path: Path, identity: str) -> tuple[bool, str]:
    """The trust file must both pass its ownership/mode checks AND name the pinned
    identity as a principal — so the operator has explicitly vouched for it."""
    ok, reason, text = release_lock.read_trust_file(signers_path)
    if not ok or text is None:
        return False, reason
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and identity in stripped.split()[0].split(","):
            return True, "ok"
    return False, f"the allowed_signers file does not authorize {identity}"


@dataclasses.dataclass(frozen=True, slots=True)
class ReleaseSource:
    bundle_dir: Path
    signers_path: Path
    identity: str


def resolve(ctx) -> tuple[ReleaseSource | None, str]:
    identity = release_lock.RELEASE_IDENTITY
    arg_signers = getattr(ctx.args, "signers", None)
    signers = Path(arg_signers).expanduser() if arg_signers else default_signers_path()
    ok, reason = trust_authorizes_identity(signers, identity)
    if not ok:
        return None, (f"the allowed_signers trust file at {signers} is unusable: {reason}. It must be "
                      f"root-owned, non-writable, and authorize {identity}.")

    local = getattr(ctx.args, "release", None) or os.environ.get(ENV_RELEASE)
    if local:
        bundle = Path(local).expanduser()
        if bundle.is_symlink() or not (bundle / "release.json").is_file():
            return None, f"{bundle} is not a release bundle (no release.json)"
        return ReleaseSource(bundle_dir=bundle, signers_path=signers, identity=identity), ""

    channel = getattr(ctx.args, "channel", None) or os.environ.get(ENV_CHANNEL)
    if not channel:
        return None, ("no release source. Configure a signed release channel "
                      f"({ENV_CHANNEL}) or pass --release <bundle-dir> for a local recovery install.")
    cache = paths.cache_dir() / "release-fetch"
    bundle, reason = fetch_channel(channel, cache, signers, identity)
    if bundle is None:
        return None, reason
    return ReleaseSource(bundle_dir=bundle, signers_path=signers, identity=identity), ""


# --- the channel fetcher (inert bytes only) ------------------------------------

def _scheme_ok(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        return True
    # Plaintext or file only for loopback/local mirrors — never a remote http host.
    if parsed.scheme == "file":
        return True
    if parsed.scheme == "http" and (parsed.hostname or "") in _LOOPBACK:
        return True
    return False


def _fetch(url: str, limit: int) -> bytes:
    if not _scheme_ok(url):
        raise ValueError(f"refusing a non-HTTPS release URL: {url}")
    with urllib.request.urlopen(url, timeout=120) as response:  # noqa: S310 - scheme gated above
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"release artifact at {url} exceeds {limit} bytes")
    return data


def fetch_channel(base_url: str, cache_dir: Path, signers_path: Path, identity: str,
                  ) -> tuple[Path | None, str]:
    """Fetch a bundle from ``base_url`` into ``cache_dir`` as inert bytes, verifying
    the manifest signature before downloading any artifact and re-laying the bundle
    for the installer's full re-verification."""
    base_exec, reason = installer.trusted_base_executable()
    if base_exec is None:
        return None, reason
    python_info, abi, platform_token, target_reason = installer._node_target(base_exec)
    if python_info is None:
        return None, target_reason
    ok, _reason, allowed = release_lock.read_trust_file(signers_path)
    if not ok or allowed is None:
        return None, _reason
    base = base_url.rstrip("/")
    try:
        manifest_bytes = _fetch(f"{base}/release.json", _MANIFEST_MAX)
        signature = _fetch(f"{base}/release.json.sig", _MANIFEST_MAX)
    except (urllib.error.URLError, ValueError, OSError) as exc:
        return None, f"could not fetch the release manifest: {exc}"
    ok, reason, auth = release_lock.verify_manifest(
        manifest_bytes, signature, allowed, identity, python_info=python_info, abi=abi,
        platform_token=platform_token, now=_dt.datetime.now(_dt.timezone.utc),
        # Fetching from a channel IS an acquisition, so the acquisition window
        # applies: an expired release must not be newly installed. (A release
        # already retained on disk keeps running -- that is RETAINED_RUNTIME, and
        # the distinction is why `mode` is mandatory.)
        mode=release_lock.CANDIDATE_ACQUISITION)
    if not ok or auth is None:
        return None, f"the channel manifest did not verify: {reason}"

    installer._force_rmtree(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "release.json").write_bytes(manifest_bytes)
    (cache_dir / "release.json.sig").write_bytes(signature)
    try:
        for role, spec in auth.roles.items():
            rd = cache_dir / "roles" / role
            (rd / spec.artifacts_root).mkdir(parents=True, exist_ok=True)
            (rd / "source.tar").write_bytes(_fetch(f"{base}/roles/{role}/source.tar", _ARTIFACT_MAX))
            for artifact in spec.artifacts:
                dest = rd / spec.artifacts_root / artifact.file  # artifact.file is a validated component
                dest.write_bytes(_fetch(f"{base}/roles/{role}/{spec.artifacts_root}/{artifact.file}", _ARTIFACT_MAX))
    except (urllib.error.URLError, ValueError, OSError) as exc:
        installer._force_rmtree(cache_dir)
        return None, f"could not fetch a release artifact: {exc}"
    # The installer now re-verifies signature AND every artifact hash from disk.
    return cache_dir, "ok"
