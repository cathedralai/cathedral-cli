#!/usr/bin/env python3
"""Build and sign a Cathedral release bundle (`cathedral.release.v2`).

This is the publisher-side counterpart of ``cathedral_node/release_lock.py``:
it produces exactly the bundle shape that module verifies, and refuses to emit
a bundle its own verifier would reject.

For each engine pinned in ``cathedral.lock.json`` it:

1. fetches the pinned revision and archives it as the inert ``source.tar``;
2. builds the engine wheel plus its *complete transitive* wheel closure with
   the trusted target Python (the node installs offline: anything missing from
   the closure cannot be installed, anything extra is refused);
3. records file/name/version/size/sha256/tags/root for every wheel;

then writes the canonical ``release.json``, signs it with ``ssh-keygen -Y sign
-n cathedral-release``, optionally emits a signed revocation snapshot from the
SEPARATE offline revocation key, and finally re-verifies the finished bundle
through the node's own ``release_lock`` code path.

The bundle directory it produces is directly usable as:

  cathedral setup <role> --release <out>          # local bundle
  CATHEDRAL_RELEASE_CHANNEL=file://<out>          # local channel rehearsal
  https://<host>/<path>/                          # uploaded as-is

Example:

  python3.11 scripts/build_release_bundle.py \\
      --out dist/release-1 --release-version 1 \\
      --key ~/.cathedral-release/cathedral_release_ed25519 \\
      --revocation-key ~/.cathedral-release/cathedral_revocation_ed25519
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from cathedral_node import lockfile, release_lock, revocation  # noqa: E402

_PY_RANGE_RE = re.compile(r">=\s*(\d+)\.(\d+)\s*,\s*<\s*(\d+)\.(\d+)")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"    $ {' '.join(str(c) for c in cmd)}")
    return subprocess.run([str(c) for c in cmd], check=True, **kw)


def fetch_source(pin, workdir: Path) -> Path:
    """Clone the pinned revision and emit an inert ``git archive`` tar."""
    src = workdir / "src"
    tar = workdir / "source.tar"
    if not (src / ".git").exists():
        src.mkdir(parents=True, exist_ok=True)
        run(["git", "init", "-q", src])
        run(["git", "-C", src, "remote", "add", "origin", pin.repository])
    run(["git", "-C", src, "fetch", "-q", "--depth", "1", "origin", pin.revision])
    run(["git", "-C", src, "checkout", "-q", pin.revision])
    head = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != pin.revision:
        raise SystemExit(f"{pin.role}: checked-out revision {head} != pinned {pin.revision}")
    run(["git", "-C", src, "archive", "--format=tar", "-o", tar.resolve(), pin.revision])
    return tar


def build_closure(python: str, srcdir: Path, extras: tuple[str, ...], wheelhouse: Path) -> list[Path]:
    """Build the engine wheel and its complete transitive closure as wheels."""
    if wheelhouse.exists():
        shutil.rmtree(wheelhouse)
    wheelhouse.mkdir(parents=True)
    target = str(srcdir) + (f"[{','.join(extras)}]" if extras else "")
    run([python, "-m", "pip", "wheel", "--wheel-dir", wheelhouse, target])
    wheels = sorted(wheelhouse.glob("*.whl"))
    if not wheels:
        raise SystemExit(f"no wheels produced for {srcdir}")
    return wheels


def wheel_roots(wheel: Path) -> list[str]:
    """Top-level importable names, from top_level.txt or inferred from contents."""
    with zipfile.ZipFile(wheel) as z:
        for info in z.namelist():
            if info.endswith(".dist-info/top_level.txt"):
                names = z.read(info).decode().split()
                if names:
                    return sorted(set(names))
        roots: set[str] = set()
        for name in z.namelist():
            first = name.split("/", 1)[0]
            if first.endswith(".dist-info") or first.endswith(".data"):
                continue
            roots.add(first[:-3] if "/" not in name and first.endswith(".py") else first)
        return sorted(roots)


def wheel_entry(wheel: Path) -> dict:
    m = release_lock._WHEEL_FILE_RE.match(wheel.name)
    if not m:
        raise SystemExit(f"{wheel.name} is not a valid single-component wheel filename")
    tags = [f"{py}-{abi}-{plat}"
            for py in m["py"].split(".") for abi in m["abi"].split(".") for plat in m["plat"].split(".")]
    return {"file": wheel.name, "name": m["name"], "version": m["ver"],
            "size": wheel.stat().st_size, "sha256": sha256_file(wheel),
            "tags": tags, "root": wheel_roots(wheel)}


def sign(path: Path, key: Path, namespace: str) -> Path:
    sig = Path(str(path) + ".sig")
    sig.unlink(missing_ok=True)  # ssh-keygen -Y sign prompts if the .sig exists
    run(["ssh-keygen", "-Y", "sign", "-f", key, "-n", namespace, path], capture_output=True)
    return sig


def target_triple(python: str) -> tuple[tuple[int, int], str, str]:
    out = subprocess.run(
        [python, "-c", "import sys,sysconfig;print(sys.version_info.major,sys.version_info.minor);"
                       "print(f'cp{sys.version_info.major}{sys.version_info.minor}');"
                       "print(sysconfig.get_platform())"],
        capture_output=True, text=True, check=True).stdout.splitlines()
    maj, minor = (int(x) for x in out[0].split())
    return (maj, minor), out[1].strip(), out[2].strip()


def python_range(requirement: str) -> dict:
    m = _PY_RANGE_RE.search(requirement)
    if not m:
        raise SystemExit(f"cannot parse a bounded python range from {requirement!r}")
    return {"min": [int(m[1]), int(m[2])], "max_exclusive": [int(m[3]), int(m[4])]}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--out", type=Path, required=True, help="bundle output directory")
    ap.add_argument("--release-version", type=int, required=True,
                    help="monotonic release version (never reuse or decrease)")
    ap.add_argument("--key", type=Path, required=True,
                    help=f"SSH key signing as {release_lock.RELEASE_IDENTITY}")
    ap.add_argument("--lockfile", type=Path, default=REPO_ROOT / "cathedral.lock.json")
    ap.add_argument("--python", default="python3.11",
                    help="trusted target Python used to build the wheel closure")
    ap.add_argument("--workdir", type=Path, default=REPO_ROOT / ".release-build")
    ap.add_argument("--expires-days", type=int, default=30,
                    help="acquisition window; installs are refused after expiry")
    ap.add_argument("--revocation-key", type=Path, default=None,
                    help=f"SEPARATE offline key signing as {revocation.REVOCATION_IDENTITY}; "
                         "emits revocation.json/.sig alongside the bundle")
    ap.add_argument("--revocation-sequence", type=int, default=1)
    args = ap.parse_args()

    lock = lockfile.load(args.lockfile)
    python = args.python
    py_info, abi, platform_token = target_triple(python)
    out: Path = args.out
    if out.exists():
        raise SystemExit(f"{out} already exists; a release build starts clean")
    out.mkdir(parents=True)

    roles_manifest: dict[str, dict] = {}
    for role, pin in sorted(lock.engines.items()):
        print(f"[{role}] {pin.distribution} @ {pin.revision[:12]} from {pin.repository}")
        rw = args.workdir / role
        rw.mkdir(parents=True, exist_ok=True)
        source_tar = fetch_source(pin, rw)
        wheels = build_closure(python, rw / "src", pin.extras, rw / "wheelhouse")

        role_dir = out / "roles" / role
        (role_dir / "wheels").mkdir(parents=True)
        shutil.copy(source_tar, role_dir / "source.tar")
        entries = []
        for w in wheels:
            shutil.copy(w, role_dir / "wheels" / w.name)
            entries.append(wheel_entry(w))
        own = [e for e in entries
               if release_lock.normalized_name(e["name"]) == release_lock.normalized_name(pin.distribution)]
        if len(own) != 1:
            raise SystemExit(f"{role}: expected exactly one wheel named {pin.distribution!r}, "
                             f"got {[e['name'] for e in own]}")
        roles_manifest[role] = {
            "repository": pin.repository, "revision": pin.revision,
            "distribution": pin.distribution, "version": own[0]["version"],
            "source_sha256": sha256_file(role_dir / "source.tar"),
            "extras": list(pin.extras), "entrypoints": list(pin.entrypoints),
            "server_entrypoints": list(pin.server_entrypoints),
            "launch_mode": pin.launch_mode, "protocol": pin.protocol,
            "artifacts_root": "wheels", "requirements": entries}
        print(f"[{role}] {len(entries)} wheels, source {roles_manifest[role]['source_sha256'][:12]}…")

    now = dt.datetime.now(dt.timezone.utc)
    manifest = {"schema": release_lock.RELEASE_SCHEMA,
                "release_version": args.release_version,
                "identity": release_lock.RELEASE_IDENTITY,
                "created_at": (now - dt.timedelta(hours=1)).isoformat(),
                "expires_at": (now + dt.timedelta(days=args.expires_days)).isoformat(),
                "python": python_range(lock.python_requirement),
                "abi": [abi], "platforms": [platform_token],
                "roles": roles_manifest}
    manifest_bytes = release_lock.canonical_bytes(manifest)
    (out / "release.json").write_bytes(manifest_bytes)
    sig = sign(out / "release.json", args.key, release_lock.NAMESPACE)
    shutil.move(str(sig), out / "release.json.sig")

    if args.revocation_key:
        snapshot = {"schema": revocation.SNAPSHOT_SCHEMA,
                    "sequence": args.revocation_sequence,
                    "issued_at": (now - dt.timedelta(hours=1)).isoformat(),
                    "expires_at": (now + dt.timedelta(days=args.expires_days)).isoformat(),
                    "revoked_release_digests": [], "revoked_signer_fingerprints": [],
                    "signer_key_id": f"cathedral-revocation-{now.year}"}
        raw = release_lock.canonical_bytes(snapshot)
        (out / "revocation.json").write_bytes(raw)
        rsig = sign(out / "revocation.json", args.revocation_key, revocation.NAMESPACE)
        shutil.move(str(rsig), out / "revocation.json.sig")
        print("emitted signed revocation snapshot "
              f"(sequence {args.revocation_sequence}, nothing revoked)")
    else:
        print("NOTE: no --revocation-key; installs also require a valid signed "
              "revocation snapshot on the channel or in the node cache.")

    # Refuse to ship a bundle the node itself would reject.
    trust = f"{release_lock.RELEASE_IDENTITY} {args.key.with_suffix('.pub').read_text().strip()}\n"
    ok, reason, auth = release_lock.verify_manifest(
        manifest_bytes, (out / "release.json.sig").read_bytes(), trust,
        release_lock.RELEASE_IDENTITY, python_info=py_info, abi=abi,
        platform_token=platform_token, now=dt.datetime.now(dt.timezone.utc),
        mode=release_lock.CANDIDATE_ACQUISITION)
    if not ok or auth is None:
        raise SystemExit(f"SELF-VERIFY FAILED (manifest): {reason}")
    for role, spec in auth.roles.items():
        rd = out / "roles" / role
        if sha256_file(rd / "source.tar") != spec.source_sha256:
            raise SystemExit(f"SELF-VERIFY FAILED: {role}/source.tar hash mismatch")
        for artifact in spec.artifacts:
            p = rd / spec.artifacts_root / artifact.file
            if p.stat().st_size != artifact.size or sha256_file(p) != artifact.sha256:
                raise SystemExit(f"SELF-VERIFY FAILED: {role}/{artifact.file} mismatch")
    print(f"\nSELF-VERIFY PASSED — release {args.release_version} at {out}")
    print(f"  identity   {release_lock.RELEASE_IDENTITY}")
    print(f"  target     python {py_info[0]}.{py_info[1]} / {abi} / {platform_token}")
    print(f"  window     {manifest['created_at']} -> {manifest['expires_at']}")
    print("Serve this directory as-is over HTTPS, or rehearse locally with:")
    print(f"  CATHEDRAL_RELEASE_CHANNEL=file://{out.resolve()}")


if __name__ == "__main__":
    main()
