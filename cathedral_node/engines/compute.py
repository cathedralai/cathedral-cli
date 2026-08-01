"""The Compute track.

A worker runs inside an Intel TDX confidential VM and produces vendor-backed
evidence bound to a fresh challenge, its hotkey, and its protected channel.
Cathedral verifies the evidence, dispatches bounded work, verifies the returned
witness, and derives credit itself.

Attestation is admission, not payment. The node says so everywhere, because the
most expensive mistake an operator can make here is paying for a machine whose
measurement was never going to be approved.
"""

from __future__ import annotations

import json
from typing import Any

from cathedral_node import machine, proc
from cathedral_node.engines.base import Engine, Progress, Qualification, TestOutcome

# The active measurement policy profile, from the engine's own mining guide.
ACTIVE_PROFILE = "cpu-tdx-sn39-v2"

_POLICY_TEST = r'''
import json, sys, subprocess

# Exercise the engine's own quote verifier against a policy: an approved
# measurement is admitted, and three refusals must actually refuse. The point
# is to prove the gate is closed, not that a happy path exists.
BIN = sys.argv[1]
APPROVED = "aa" * 48
OTHER    = "bb" * 48
CURRENT_TCB = "5"     # the platform's reported TCB version
REQUIRED_TCB = "5"    # the minimum the policy accepts

def check(name, argv, expect_pass, why):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    passed = (proc.returncode == 0)
    return {
        "name": name,
        "expected": "admit" if expect_pass else "refuse",
        "observed": "admit" if passed else "refuse",
        "passed": passed == expect_pass,
        "exit_code": proc.returncode,
        "why": why,
        "detail": (proc.stdout or proc.stderr).strip().splitlines()[-1:] or [""],
    }

def quote(measurement, tcb, allowed, min_tcb):
    return [BIN, "verify-quote", "--measurement", measurement, "--tcb", tcb,
            "--allowed-measurement", allowed, "--min-tcb", min_tcb]

checks = [
    check("approved measurement is admitted",
          quote(APPROVED, CURRENT_TCB, APPROVED, REQUIRED_TCB),
          True, "a measurement on the signed policy list, at or above the required TCB, is eligible"),
    check("unknown measurement is refused",
          quote(OTHER, CURRENT_TCB, APPROVED, REQUIRED_TCB),
          False, "a cryptographically valid quote with an unlisted measurement earns nothing"),
    check("out-of-date TCB is refused",
          quote(APPROVED, "3", APPROVED, REQUIRED_TCB),
          False, "stale platform firmware is not eligible even with an approved measurement"),
    check("empty policy admits nothing",
          quote(APPROVED, CURRENT_TCB, "", REQUIRED_TCB),
          False, "with no approved list the verifier fails closed rather than open"),
]
print(json.dumps({"checks": checks, "all_passed": all(c["passed"] for c in checks)}))
'''


class ComputeEngine(Engine):
    role = "compute"
    title = "Compute"
    tagline = "Sell confidential compute you can prove ran untampered."

    # ---- description ----------------------------------------------------------

    def explain(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "title": self.title,
            "tagline": self.tagline,
            "what_you_do": (
                "You run a measured worker inside an Intel TDX confidential VM. Cathedral sends it "
                "a fresh challenge, your worker returns hardware-backed evidence bound to that "
                "challenge and its identity, and then does bounded work whose result Cathedral "
                "checks independently."
            ),
            "how_you_are_scored": (
                "Cathedral verifies the quote, the platform TCB, the measurement against the signed "
                "policy, and your identity — then verifies the work you returned and derives the "
                "credit itself. Your own report of how much work you did is never the number used."
            ),
            "what_it_costs": (
                "An Intel TDX capable machine, running continuously. Do not buy one before your "
                "measurement is approved."
            ),
            "what_you_need": [
                "An Intel TDX confidential VM whose measurement is already on the signed policy list",
                f"The active profile is {ACTIVE_PROFILE}, requiring TCB status UpToDate",
                "An SN39 hotkey address (never a coldkey)",
                "HTTPS with channel binding for any worker reachable off-host",
            ],
            "not_yet_true": [
                "There is no reproducible image yet, so you cannot build a matching measurement "
                "yourself. A maintainer must review and sign yours in before you can be admitted.",
                "Enrolment is operator-assisted, not self-service.",
                "AMD SEV-SNP and NVIDIA confidential-GPU scoring are not enabled.",
                "Testnet SN292 is non-paying.",
            ],
            "before_you_spend": (
                "Request a beta slot and get your measurement approved before provisioning or paying "
                "for a machine. A VM that boots to an unapproved measurement is refused every epoch, "
                "however correct everything else is."
            ),
        }

    def capabilities(self) -> dict[str, Any]:
        tdx = machine.tdx_probe()
        census = (machine.load_engine_census(self.python(), self.child_env())
                  if self.has_bin("python") else None)
        return {
            "local_test": {
                "available": True,
                "requires_credentials": False,
                "requires_network": False,
                "what_it_proves": (
                    "The measurement policy gate fails closed on this build: an approved "
                    "measurement is admitted and unlisted measurements, stale TCB, and an empty "
                    "policy are all refused."
                ),
            },
            "hardware_evidence": {
                "available": tdx.verdict == "yes",
                "verdict": tdx.verdict,
                "detail": tdx.detail,
                "requires_operator": tdx.verdict != "yes",
            },
            "worker_serve_local": {
                "available": True,
                "detail": "A loopback worker with development auth disabled. Never a production path.",
            },
            "worker_serve_production": {
                "available": False,
                "detail": "Needs an approved measurement, TLS with channel binding, and an "
                "operator-assisted enrolment.",
                "requires_operator": True,
            },
            "earning": {
                "available": False,
                "detail": "Onboarding is operator-assisted and positive weight is never guaranteed.",
                "requires_operator": True,
            },
            # A capability object like every other entry, so an agent iterating
            # capabilities never meets a null: `available` is whether the installed
            # engine's package inventory could be read, and the inventory rides
            # along under `inventory` (null until the engine is installed).
            "engine_census": {
                "available": census is not None,
                "detail": (
                    "installed engine package inventory"
                    if census is not None
                    else "not available until the compute engine is installed"
                ),
                "inventory": census,
            },
        }

    # ---- readiness ------------------------------------------------------------

    def qualify(self, cfg: dict[str, Any]) -> Qualification:
        blockers: list[dict[str, Any]] = []
        notes: list[str] = []

        if not self.has_bin("cathedral"):
            blockers.append(
                {
                    "code": "install.engine_missing",
                    "what": "the Compute engine is not installed",
                    "fix": "cathedral setup compute",
                    "blocks": ["local_test", "operate"],
                }
            )

        if not cfg.get("hotkey"):
            blockers.append(
                {
                    "code": "identity.hotkey_missing",
                    "what": "no hotkey configured, so a worker cannot identify itself",
                    "fix": "cathedral config set compute hotkey <your-ss58-address>",
                    "blocks": ["operate"],
                }
            )

        tdx = machine.tdx_probe()
        if tdx.verdict == "no":
            blockers.append(
                {
                    "code": "hardware.no_tdx",
                    "what": "this host is not an Intel TDX confidential VM, so it cannot produce evidence",
                    "fix": None,
                    "requires_operator": True,
                    "blocks": ["operate"],
                }
            )
        elif tdx.verdict == "unknown":
            notes.append(f"TDX capability {tdx.detail}. Local tests still run here.")

        notes.append(
            f"Admission needs your measurement on the signed {ACTIVE_PROFILE} policy list. "
            "That is an operator review, not something this node can grant."
        )

        host = str(cfg.get("host", "127.0.0.1"))
        if host not in ("127.0.0.1", "::1", "localhost") and not cfg.get("tls_certificate"):
            blockers.append(
                {
                    "code": "config.field_required",
                    "what": f"the worker would bind {host} with no TLS certificate",
                    "fix": "cathedral config set compute tls_certificate /path/to/cert.pem",
                    "blocks": ["operate"],
                }
            )

        return Qualification(
            can_local_test=not any("local_test" in b["blocks"] for b in blockers),
            can_operate=not any("operate" in b["blocks"] for b in blockers),
            blockers=blockers,
            notes=notes,
        )

    # ---- operations -----------------------------------------------------------

    def local_test(
        self, cfg: dict[str, Any], run_id: str, *, progress: Progress, timeout: float
    ) -> TestOutcome:
        progress("policy", "four measurement-policy decisions, three of which must refuse")
        result = proc.run(
            [str(self.python()), "-c", _POLICY_TEST, str(self.bin("cathedral"))],
            timeout=timeout, inherit_env=False, env=self.child_env(cfg),
        )
        if not result.ok:
            return TestOutcome(
                passed=False,
                summary="the Compute engine could not evaluate the measurement policy",
                checks=[],
                failure_code="upstream.failed",
                remediation="cathedral setup compute --force",
                identifiers={"engine_stderr": result.tail(6)},
            )
        try:
            payload = json.loads(result.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return TestOutcome(
                passed=False,
                summary="the Compute engine returned output this node could not read",
                checks=[],
                failure_code="contract.engine_incompatible",
                remediation="cathedral setup compute --force",
                identifiers={"engine_stdout": result.tail(6)},
            )

        checks = payload["checks"]
        passed = bool(payload["all_passed"])
        refusals = sum(1 for c in checks if c["expected"] == "refuse" and c["passed"])
        progress("verify", f"{refusals} of 3 refusals held")

        census = ((machine.load_engine_census(self.python(), self.child_env()) or {})
                  if self.has_bin("python") else {})
        return TestOutcome(
            passed=passed,
            summary=(
                "the measurement policy gate fails closed: approved evidence admitted, "
                f"{refusals} of 3 disallowed cases refused"
                if passed
                else "the measurement policy gate did not behave as specified"
            ),
            checks=[
                {
                    "label": "admit" if c["expected"] == "admit" else "refuse",
                    "name": c["name"],
                    "passed": c["passed"],
                    "detail": f"expected {c['expected']}, observed {c['observed']} — {c['why']}",
                }
                for c in checks
            ],
            identifiers={
                "policy_profile": ACTIVE_PROFILE,
                "cc_capable": census.get("cc_capable"),
                "tdx_present": census.get("tdx"),
            },
            failure_code=None if passed else "verify.policy_refused",
            remediation=None if passed else "cathedral setup compute --force",
        )

    def operate_argv(self, cfg: dict[str, Any], *, dry_run: bool) -> list[str]:
        if dry_run:
            return [str(self.bin("cathedral")), "census", "--json"]
        argv = [
            str(self.bin("cathedral")),
            "worker",
            "serve",
            "--hotkey",
            str(cfg.get("hotkey", "")),
            "--host",
            str(cfg.get("host", "127.0.0.1")),
            "--port",
            str(cfg.get("port", 8901)),
        ]
        cert, key = cfg.get("tls_certificate"), cfg.get("tls_private_key")
        if cert and key:
            argv += ["--tls-certificate", str(cert), "--tls-private-key", str(key)]
        secret_name = str(cfg.get("bearer_token_secret") or "")
        if secret_name:
            # The engine reads the token from this env var. The value never
            # appears in argv, so it cannot leak through `ps`.
            argv += ["--bearer-token-env", secret_name]
        return argv

    def operate_env(self, cfg: dict[str, Any]) -> dict[str, str]:
        from cathedral_node import config as config_module

        return dict(config_module.secret_environment(self.role, cfg))

    def interpret_line(self, line: str) -> dict[str, Any] | None:
        stripped = line.strip()
        low = stripped.lower()
        if not stripped:
            return None
        if "quote" in low and ("verified" in low or "accepted" in low):
            return {"event": "EVIDENCE", "stage": "attest", "status": "PASS", "detail": stripped}
        if "refus" in low or "reject" in low or "admit=n" in low:
            return {"event": "REFUSED", "stage": "attest", "status": "FAIL", "detail": stripped}
        if "listening" in low or "serving" in low or "bound" in low:
            return {"event": "READY", "stage": "serve", "status": "INFO", "detail": stripped}
        if "receipt" in low:
            return {"event": "RECEIPT", "stage": "evidence", "status": "INFO", "detail": stripped}
        return None
