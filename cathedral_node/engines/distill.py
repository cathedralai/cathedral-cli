"""The Distill track.

Miners produce proof-of-concept exploits for already-patched, publicly disclosed
vulnerabilities. A validator verifies each PoC by running it against both the
vulnerable and the patched build. There is no judge model and no self-reported
score: a solve is a physical fact.

The local test here runs the engine's **own** synthetic challenge generator and
its **own** differential executor, inside the engine's environment. It is a real
exercise of the scoring predicate — not a fixture that returns success.
"""

from __future__ import annotations

import json
from typing import Any

from cathedral_node import machine, proc
from cathedral_node.engines.base import Engine, Progress, Qualification, TestOutcome

# Run inside the engine's interpreter. Imports only engine modules, so what it
# proves is the engine's behaviour and not this file's idea of it.
_LOCAL_TEST = r'''
import json, sys, hashlib
from cathedral_distill import cybergym_synthetic as syn
from cathedral_distill.cybergym import Level

nonce = sys.argv[1]
levels = [0, 1, 2, 3]
checks, ids = [], []
solved = 0
weights = {0: 8, 1: 4, 2: 2, 3: 1}
score = 0

for index, level in enumerate(levels):
    bug = syn.generate_bug(nonce, index, level=level)
    task = bug.to_task()

    # The witness a solving miner would submit for this challenge.
    poc = bug.trigger
    vulnerable = syn.execute(bug, poc, patched=False)
    patched = syn.execute(bug, poc, patched=True)
    crashes_vulnerable = vulnerable not in (0, 300)
    clean_on_patched = patched in (0, 300)
    passed = crashes_vulnerable and clean_on_patched

    # A control: random bytes must NOT count as a solve. If this ever passes,
    # the differential is not discriminating and the whole track is broken.
    decoy = hashlib.sha256(f"decoy{index}".encode()).digest()
    decoy_vulnerable = syn.execute(bug, decoy, patched=False)
    decoy_rejected = decoy_vulnerable in (0, 300)

    if passed:
        solved += 1
        score += weights[level]

    checks.append({
        "name": f"level{level} differential",
        "task_id": task.task_id,
        "level": level,
        "binary_digest": task.binary_digest,
        "bug_class": bug.bug_class,
        "poc_sha256": "sha256:" + hashlib.sha256(poc).hexdigest(),
        "poc_bytes": len(poc),
        "exit_vulnerable": vulnerable,
        "exit_patched": patched,
        "crashes_vulnerable": crashes_vulnerable,
        "clean_on_patched": clean_on_patched,
        "decoy_rejected": decoy_rejected,
        "passed": bool(passed and decoy_rejected),
    })
    ids.append(task.task_id)

print(json.dumps({
    "nonce": nonce,
    "tasks": len(levels),
    "solved": solved,
    "score": score,
    "max_score": sum(weights[l] for l in levels),
    "task_ids": ids,
    "checks": checks,
    "all_passed": all(c["passed"] for c in checks),
}))
'''

_ENGINE_VERSION = r'''
import json, importlib.metadata as m
from cathedral_distill import cybergym_protocol as p
out = {"distribution": m.version("cathedral-cybergym")}
for name in ("SUBMISSION_SCHEMA", "RECEIPT_SCHEMA", "DISPATCH_SCHEMA"):
    if hasattr(p, name):
        out[name.lower()] = getattr(p, name)
print(json.dumps(out))
'''


def _nonce_from(run_id: str) -> str:
    """A nonce the engine's task-id grammar accepts.

    The engine builds ``synthvuln:<nonce[-8:]>:<index>`` and requires those last
    eight characters to be lowercase alphanumeric, so a run id with a hyphen in
    the wrong place would be rejected deep inside the engine. Derive instead.
    """
    import hashlib

    return hashlib.sha256(run_id.encode()).hexdigest()[:16]


class DistillEngine(Engine):
    role = "distill"
    title = "Distill"
    tagline = "Find real vulnerabilities. Get paid for the ones you can prove."

    # ---- description ----------------------------------------------------------

    def explain(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "title": self.title,
            "tagline": self.tagline,
            "what_you_do": (
                "Your model reads a codebase with a known, already-patched vulnerability and "
                "writes a proof-of-concept input that triggers the bug."
            ),
            "how_you_are_scored": (
                "A solve counts only when your input crashes the vulnerable build and does not "
                "crash the patched one. A generic crash that also affects the patched build is "
                "not a solve. Harder levels tell you less: level 0 gives only the binary and is "
                "worth 8x, level 3 gives you the patch diff and is worth 1x."
            ),
            "what_it_costs": (
                "Whatever your model costs. A local model server (Ollama, vLLM, llama.cpp) has no "
                "per-call cost and keeps your work private."
            ),
            "what_you_need": [
                "Any machine that can run your model or reach an OpenAI-compatible endpoint",
                "An SN39 hotkey address to be scored under (never a coldkey)",
                "A container runtime, only for the real corpus — the local test needs none",
            ],
            "not_yet_true": [
                "Live on-chain participation needs the operator key ceremony and the mechanism "
                "registered on chain. Both are owner steps.",
                "Per-solve Intel TDX binding is proven for the synthetic profile. An attested "
                "real-corpus solve is not proven.",
                "Emissions are not active for this track.",
            ],
            "safety": (
                "Targets are historical vulnerabilities that already have a public fix — "
                "verification requires the patched build to exist. No live system is a target."
            ),
        }

    def capabilities(self) -> dict[str, Any]:
        container = machine.container_runtime_probe()
        return {
            "local_test": {
                "available": True,
                "requires_credentials": False,
                "requires_network": False,
                "what_it_proves": (
                    "The differential scoring predicate works on this machine: a correct witness "
                    "is accepted and a decoy is refused, using the engine's own generator."
                ),
            },
            "agent_solve": {
                "available": True,
                "requires_credentials": True,
                "detail": "Needs an OpenAI-compatible model endpoint. A local server needs no key.",
            },
            "real_corpus": {
                "available": container.verdict == "yes",
                "detail": container.detail,
                "requires_network": True,
            },
            "live_dispatch": {
                "available": False,
                "detail": "Phase-2 gated in the engine. Not reachable from this node.",
                "requires_operator": True,
            },
            "earning": {
                "available": False,
                "detail": "Emissions for this track are not active. Owner step.",
                "requires_operator": True,
            },
        }

    # ---- readiness ------------------------------------------------------------

    def qualify(self, cfg: dict[str, Any]) -> Qualification:
        blockers: list[dict[str, Any]] = []
        notes: list[str] = []

        if not self.has_bin("python"):
            blockers.append(
                {
                    "code": "install.engine_missing",
                    "what": "the Distill engine is not installed",
                    "fix": "cathedral setup distill",
                    "blocks": ["local_test", "operate"],
                }
            )

        if not cfg.get("hotkey"):
            blockers.append(
                {
                    "code": "identity.hotkey_missing",
                    "what": "no hotkey configured, so work cannot be attributed to you",
                    "fix": "cathedral config set distill hotkey <your-ss58-address>",
                    "blocks": ["operate"],
                }
            )

        api_base = str(cfg.get("api_base") or "")
        local_model = any(host in api_base for host in ("localhost", "127.0.0.1", "::1"))
        if not api_base:
            blockers.append(
                {
                    "code": "config.field_required",
                    "what": "no model endpoint configured, so the agent has nothing to solve with",
                    "fix": "cathedral config set distill api_base http://localhost:11434/v1",
                    "blocks": ["operate"],
                }
            )
        elif local_model:
            notes.append("Model endpoint is local: no per-call cost and your prompts stay on this host.")
        else:
            notes.append(f"Model endpoint is remote ({api_base}). Solves will cost whatever it charges.")

        container = machine.container_runtime_probe()
        if container.verdict != "yes":
            notes.append(
                "No container runtime, so real-corpus verification is unavailable. "
                "The local test and synthetic work do not need one."
            )

        operate_blocked = any("operate" in b["blocks"] for b in blockers)
        test_blocked = any("local_test" in b["blocks"] for b in blockers)
        return Qualification(
            can_local_test=not test_blocked,
            can_operate=not operate_blocked,
            blockers=blockers,
            notes=notes,
        )

    # ---- operations -----------------------------------------------------------

    def local_test(
        self, cfg: dict[str, Any], run_id: str, *, progress: Progress, timeout: float
    ) -> TestOutcome:
        progress("generate", "four sealed challenges, one per difficulty level")
        nonce = _nonce_from(run_id)
        result = proc.run(
            [str(self.python()), "-c", _LOCAL_TEST, nonce],
            timeout=timeout, inherit_env=False, env=self.child_env(cfg),
        )
        if not result.ok:
            return TestOutcome(
                passed=False,
                summary="the Distill engine could not run the differential",
                checks=[],
                failure_code="upstream.failed",
                remediation="cathedral setup distill --force",
                identifiers={"engine_stderr": result.tail(6)},
            )

        try:
            payload = json.loads(result.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return TestOutcome(
                passed=False,
                summary="the Distill engine returned output this node could not read",
                checks=[],
                failure_code="contract.engine_incompatible",
                remediation="cathedral setup distill --force",
                identifiers={"engine_stdout": result.tail(6)},
            )

        progress("verify", f"{payload['solved']}/{payload['tasks']} proofs-of-concept accepted")
        checks = payload["checks"]
        passed = bool(payload["all_passed"])
        decoys_ok = all(c["decoy_rejected"] for c in checks)

        if passed:
            summary = (
                f"{payload['solved']} of {payload['tasks']} challenges solved and verified, "
                f"score {payload['score']}/{payload['max_score']} (levels weighted 8/4/2/1); "
                f"every decoy refused"
            )
        elif not decoys_ok:
            summary = "a decoy input was accepted as a solve — the differential is not discriminating"
        else:
            summary = f"only {payload['solved']} of {payload['tasks']} proofs-of-concept verified"

        return TestOutcome(
            passed=passed,
            summary=summary,
            checks=[
                {
                    "label": f"level{c['level']}",
                    "name": c["name"],
                    "passed": c["passed"],
                    "detail": (
                        f"vulnerable build exit {c['exit_vulnerable']}, "
                        f"patched build exit {c['exit_patched']}, decoy refused"
                        if c["passed"]
                        else f"vulnerable exit {c['exit_vulnerable']}, patched exit {c['exit_patched']}"
                    ),
                    "task_id": c["task_id"],
                    "poc_sha256": c["poc_sha256"],
                }
                for c in checks
            ],
            identifiers={
                "batch_nonce": payload["nonce"],
                "task_ids": payload["task_ids"],
                "solved": payload["solved"],
                "score": payload["score"],
                "max_score": payload["max_score"],
            },
            failure_code=None if passed else "verify.differential_failed",
            remediation=None if passed else "cathedral setup distill --force",
        )

    def operate_argv(self, cfg: dict[str, Any], *, dry_run: bool) -> list[str]:
        argv = [
            str(self.bin("cathedral-cybergym-agent")),
            "--model",
            str(cfg.get("model", "hermes3")),
            "--api-base",
            str(cfg.get("api_base", "http://localhost:11434/v1")),
            "--max-turns",
            str(cfg.get("max_turns", 24)),
        ]
        validator_url = str(cfg.get("validator_url") or "")
        if validator_url and not dry_run:
            argv += ["--dispatch-url", validator_url]
            if cfg.get("hotkey"):
                argv += ["--miner", str(cfg["hotkey"])]
        else:
            argv.append("--local")
        return argv

    def operate_env(self, cfg: dict[str, Any]) -> dict[str, str]:
        from cathedral_node import config as config_module

        secrets = config_module.secret_environment(self.role, cfg)
        env = {
            "AGENT_MODEL": str(cfg.get("model", "hermes3")),
            "AGENT_API_BASE": str(cfg.get("api_base", "http://localhost:11434/v1")),
            "AGENT_API_KEY": "",
        }
        secret_name = str(cfg.get("api_key_secret") or "")
        if secret_name and secret_name in secrets:
            env["AGENT_API_KEY"] = secrets[secret_name]
        return env

    def interpret_line(self, line: str) -> dict[str, Any] | None:
        stripped = line.strip()
        if not stripped:
            return None
        if stripped.startswith("▶ task"):
            return {"event": "CHALLENGE", "stage": "dispatch", "status": "INFO", "detail": stripped[2:].strip()}
        if "solved=True" in stripped:
            return {"event": "SOLVED", "stage": "solve", "status": "PASS", "detail": stripped.lstrip("─ ")}
        if "solved=False" in stripped:
            status = "FAIL"
            detail = stripped.lstrip("─ ")
            if "model_error" in stripped:
                status = "ERROR"
            return {"event": "UNSOLVED", "stage": "solve", "status": status, "detail": detail}
        return None

    def engine_versions(self) -> dict[str, Any]:
        if not self.has_bin("python"):
            return {}
        result = proc.run([str(self.python()), "-c", _ENGINE_VERSION], timeout=60,
                          inherit_env=False, env=self.child_env())
        if not result.ok:
            return {}
        try:
            return json.loads(result.stdout.strip().splitlines()[-1])
        except (json.JSONDecodeError, IndexError):
            return {}
