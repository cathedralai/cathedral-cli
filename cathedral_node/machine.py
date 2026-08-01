"""What this machine is, honestly.

Every probe returns a definite answer or says it could not tell. Nothing here
guesses: "unknown" is a first-class result, because reporting "no TDX" on a
platform where we cannot look is a lie an operator would act on.
"""

from __future__ import annotations

import dataclasses
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Literal

Verdict = Literal["yes", "no", "unknown"]


@dataclasses.dataclass(frozen=True, slots=True)
class Probe:
    name: str
    verdict: Verdict
    detail: str
    value: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "verdict": self.verdict, "detail": self.detail, "value": self.value}


def _run(argv: list[str], timeout: float = 5.0) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return 127, ""


# --- platform ------------------------------------------------------------------

def os_probe() -> Probe:
    system = platform.system()
    release = platform.release()
    machine = platform.machine()
    label = f"{system} {release} ({machine})"
    if system == "Linux":
        return Probe("os", "yes", label, {"system": system, "machine": machine})
    if system == "Darwin":
        return Probe(
            "os",
            "no",
            f"{label} — development and local tests only",
            {"system": system, "machine": machine},
        )
    return Probe("os", "no", f"{label} — not a supported host", {"system": system, "machine": machine})


def python_probe(minimum: tuple[int, int] = (3, 11), maximum: tuple[int, int] = (3, 14)) -> Probe:
    """Is there an interpreter the engines can be installed into?

    The question is not whether *we* are running on a supported version — the
    node can inspect the host on newer Python releases, but engine installation
    needs 3.11-3.13. This probe checks whether a usable interpreter exists on
    this machine at all. Answering the narrower question produced a false
    failure on a host running 3.14 with 3.11 sitting right beside it.
    """
    running = ".".join(str(p) for p in sys.version_info[:3])
    usable = find_supported_python(minimum, maximum)
    window = f"{minimum[0]}.{minimum[1]}-{maximum[0]}.{maximum[1] - 1}"

    if usable is None:
        return Probe(
            "python",
            "no",
            f"running {running}; engines need {window} and no such interpreter is on PATH",
            {"running": running, "engine_interpreter": None},
        )
    if Path(usable) == Path(sys.executable):
        return Probe("python", "yes", running, {"running": running, "engine_interpreter": str(usable)})
    return Probe(
        "python",
        "yes",
        f"{running} here; engines will use {usable.name}",
        {"running": running, "engine_interpreter": str(usable)},
    )


def find_supported_python(minimum: tuple[int, int] = (3, 11), maximum: tuple[int, int] = (3, 14)) -> Path | None:
    """An interpreter the engines can actually be installed into.

    Searched oldest-first inside the supported window, not newest-first. The
    validator pulls in bittensor, whose wheels appear for a new Python release
    considerably later than the release itself, so the oldest supported
    interpreter is the one most likely to resolve. Returning None is a
    remediable condition, not a crash.
    """
    preference = [(3, minor) for minor in range(minimum[1], maximum[1])]
    current = sys.version_info[:2]

    for version in preference:
        if version == current:
            return Path(sys.executable)
        found = shutil.which(f"python{version[0]}.{version[1]}")
        if found:
            return Path(found)
    return None


def disk_probe(target: Path, need_gb: float = 5.0) -> Probe:
    # A test-only seam for a deterministic free-space measurement. It overrides the
    # MEASURED free space, never the production threshold (which stays ``need_gb``),
    # so disk-independent behaviour can be exercised on a space-constrained CI host.
    override = os.environ.get("CATHEDRAL_TEST_ASSUME_DISK_GB")
    if override is not None:
        try:
            free_gb = float(override)
        except ValueError:
            free_gb = 0.0
    else:
        try:
            usage = shutil.disk_usage(target if target.exists() else target.parent)
        except OSError as exc:
            return Probe("disk", "unknown", f"could not measure free space: {exc}")
        free_gb = usage.free / 1024**3
    verdict: Verdict = "yes" if free_gb >= need_gb else "no"
    return Probe("disk", verdict, f"{free_gb:.1f} GB free (need {need_gb:.0f} GB)", round(free_gb, 1))


def memory_probe(need_gb: float = 4.0) -> Probe:
    total: float | None = None
    try:
        if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names and "SC_PHYS_PAGES" in os.sysconf_names:
            total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 1024**3
    except (ValueError, OSError):
        total = None
    if total is None and platform.system() == "Darwin":
        rc, out = _run(["sysctl", "-n", "hw.memsize"])
        if rc == 0 and out.strip().isdigit():
            total = int(out.strip()) / 1024**3
    if total is None:
        return Probe("memory", "unknown", "could not measure installed memory")
    verdict: Verdict = "yes" if total >= need_gb else "no"
    return Probe("memory", verdict, f"{total:.1f} GB installed (need {need_gb:.0f} GB)", round(total, 1))


def cpu_probe() -> Probe:
    count = os.cpu_count() or 0
    return Probe("cpu", "yes" if count >= 2 else "no", f"{count} logical cores", count)


def tool_probe(name: str, *, required: bool, purpose: str) -> Probe:
    found = shutil.which(name)
    if found:
        return Probe(name, "yes", found, found)
    verdict: Verdict = "no" if required else "unknown"
    return Probe(name, verdict, f"not on PATH — {purpose}", None)


def container_runtime_probe() -> Probe:
    """Docker or udocker. Distill's real-corpus verification needs one; the
    synthetic local test does not."""
    for name in ("docker", "podman", "udocker"):
        found = shutil.which(name)
        if found:
            return Probe("container", "yes", f"{name} at {found}", name)
    return Probe(
        "container",
        "no",
        "no docker, podman, or udocker — needed only for real-corpus Distill verification",
        None,
    )


# --- confidential compute ------------------------------------------------------

def tdx_probe() -> Probe:
    """Intel TDX guest capability.

    On Linux we look for the TDX guest device. Anywhere else we say "unknown",
    never "no" — a macOS laptop simply cannot answer this question about the
    machine an operator might actually mine on.
    """
    if platform.system() != "Linux":
        return Probe(
            "tdx",
            "unknown",
            f"cannot be determined on {platform.system()} — check on the target Linux host",
        )
    for device in ("/dev/tdx_guest", "/dev/tdx-guest", "/dev/tdx-attest"):
        if Path(device).exists():
            return Probe("tdx", "yes", f"TDX guest device {device}", device)
    flags = ""
    try:
        flags = Path("/proc/cpuinfo").read_text(errors="ignore")
    except OSError:
        pass
    if "tdx" in flags.lower():
        return Probe("tdx", "unknown", "CPU reports TDX but no guest device — not running inside a TD")
    return Probe("tdx", "no", "no TDX guest device — this host is not an Intel TDX confidential VM")


def gpu_probe() -> Probe:
    if not shutil.which("nvidia-smi"):
        return Probe("gpu", "no", "no nvidia-smi — no NVIDIA GPU visible")
    rc, out = _run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"])
    if rc != 0:
        return Probe("gpu", "unknown", "nvidia-smi present but did not answer")
    names = [line.strip() for line in out.splitlines() if line.strip()]
    if not names:
        return Probe("gpu", "no", "nvidia-smi reported no devices")
    return Probe("gpu", "yes", ", ".join(names), names)


def network_probe(host: str = "api.cathedral.computer", timeout: float = 4.0) -> Probe:
    """Can we reach the feed? Never fails the whole doctor — an air-gapped
    machine can still run every local test."""
    import socket

    try:
        socket.setdefaulttimeout(timeout)
        socket.getaddrinfo(host, 443)
    except OSError as exc:
        return Probe("network", "no", f"cannot resolve {host}: {exc.__class__.__name__}")
    finally:
        socket.setdefaulttimeout(None)
    return Probe("network", "yes", f"{host} resolves")


def summary() -> dict[str, Any]:
    """A compact machine description for diagnostics and the agent brief."""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": ".".join(str(p) for p in sys.version_info[:3]),
        "cpu_count": os.cpu_count(),
    }


def as_json(probes: list[Probe]) -> list[dict[str, Any]]:
    return [p.to_dict() for p in probes]


def load_engine_census(engine_python: Path, env: dict[str, str] | None = None,
                       ) -> dict[str, Any] | None:
    """Ask the Compute engine's own probe, so our answer and the engine's can
    never disagree. Returns None when the engine is not installed.

    This runs signed-release code, so unlike the host-tool probes above it gets the
    scrubbed signed-child environment rather than this process's.
    """
    from cathedral_node import proc as _proc
    binary = engine_python.parent / "cathedral"
    if not binary.exists():
        return None
    child_env = env or _proc.signed_child_env(home=engine_python.parent.parent)
    result = _proc.run([str(binary), "census", "--json"], timeout=30.0,
                       inherit_env=False, env=child_env)
    rc, out = result.returncode, result.stdout
    if rc != 0:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None
