"""The Validator.

Fetches Cathedral's signed score feed, verifies it cryptographically before
every write, composes one weight vector across lanes under an owner-signed burn
and allocation policy, and submits weights only when explicitly told to.

Two properties of this engine drive the whole design here:

* It is safe by default. Without ``--broadcast`` nothing reaches the chain, and
  ``--offline`` additionally removes all chain access.
* It already emits a good JSONL event stream. The node reads that stream rather
  than inventing a second one, so what an operator sees and what an agent parses
  come from the same source.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cathedral_node import paths, proc
from cathedral_node.engines.base import Engine, Progress, Qualification, TestOutcome

# The engine's derived-copy status, stated plainly wherever it matters. This is
# not editorial: deploying production weight authority from the derived mirror
# is an owner cutover decision, and the node must not imply otherwise.
DERIVED_NOTICE = (
    "cathedral-validator is a derived copy of the validator, extracted from cathedralai/cathedral. "
    "Running it locally, in dry run, and against the live signed feed is supported here. Making it "
    "your production weight authority is a separate owner cutover decision."
)


class ValidatorEngine(Engine):
    role = "validator"
    title = "Validator"
    tagline = "Verify what miners claim. Decide what goes on chain."

    # ---- description ----------------------------------------------------------

    def explain(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "title": self.title,
            "tagline": self.tagline,
            "what_you_do": (
                "You fetch Cathedral's signed score feed, verify its signature, freshness, and "
                "replay fence, check the burn contract, compose one weight vector, and — only when "
                "you explicitly allow it — submit that vector to the chain."
            ),
            "what_you_verify": [
                "The feed is signed by the key you pinned, and nothing else is accepted",
                "It is fresh, unexpired, and newer than anything already applied",
                "The burn contract holds and the burn destination is not taken from the feed on faith",
                "Target UIDs stay provably stable for the whole lifetime of the write",
            ],
            "what_it_never_does": [
                "Never writes to the chain without --broadcast",
                "Never writes twice for one attempt: a durable attempt journal prevents it",
                "Never guesses — an unprovable outcome halts and re-proves rather than resubmitting",
            ],
            "what_you_need": [
                "A Bittensor wallet registered on SN39 with a validator permit and stake",
                "A machine that stays on",
                "Python 3.11-3.13",
            ],
            "not_yet_true": [DERIVED_NOTICE],
            "who_sets_the_burn": (
                "Not you, and not this node. The burn share comes from the signed weight vector "
                "under the pinned validated_supply_v1 contract, and the integration lane reads "
                "Cathedral-signed burn and allocation documents. What is yours is which contract "
                "and which signing key you will accept — `require_policy` and `weight_policy_key` "
                "— plus your wallet and network. Updates never change those."
            ),
        }

    def capabilities(self) -> dict[str, Any]:
        return {
            "dry_run": {
                "available": True,
                "requires_credentials": False,
                "requires_network": True,
                "what_it_proves": (
                    "The full verify path runs against the real signed feed and prints the vector "
                    "it would write. Nothing is submitted."
                ),
            },
            "offline_dry_run": {
                "available": True,
                "requires_credentials": False,
                "requires_network": True,
                "detail": (
                    "--offline removes all chain access and uses a synthetic UID map. It does not "
                    "remove the HTTPS fetch of the signed feed, which is what is being verified."
                ),
            },
            "broadcast": {
                "available": False,
                "detail": (
                    "Submitting weights needs a registered validator wallet with a permit and an "
                    "explicit --broadcast. This node will not enable it for you."
                ),
                "requires_operator": True,
            },
            "production_authority": {
                "available": False,
                "detail": DERIVED_NOTICE,
                "requires_operator": True,
            },
        }

    # ---- readiness ------------------------------------------------------------

    def qualify(self, cfg: dict[str, Any]) -> Qualification:
        blockers: list[dict[str, Any]] = []
        notes: list[str] = []

        if not self.has_bin("cathedral-validator"):
            blockers.append(
                {
                    "code": "install.engine_missing",
                    "what": "the validator engine is not installed",
                    "fix": "cathedral setup validator",
                    "blocks": ["local_test", "operate"],
                }
            )

        if not cfg.get("wallet_name") or not cfg.get("wallet_hotkey"):
            notes.append(
                "No wallet configured. Dry runs work without one; broadcasting does not."
            )

        runtime_root = Path(str(cfg.get("runtime_root") or paths.home() / "validator-runtime"))
        notes.append(f"Runtime root {paths.relative_to_home(runtime_root)} holds the cross-mode lock and journal.")
        notes.append(DERIVED_NOTICE)

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
        """One offline tick: verify the signed feed and print the vector it would
        write. No chain access, no broadcast, nothing consumed."""
        run_root = paths.run_dir(run_id)
        runtime_root = run_root / "runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        runtime_root.chmod(0o700)
        events = run_root / "validator-events.jsonl"

        progress("verify", "fetching and verifying the signed score feed")
        argv = [
            str(self.bin("cathedral-validator")),
            "serve",
            "--config",
            str(self._config_path()),
            "--once",
            "--dry-run",
            "--offline",
            "--provenance",
            "off",
            "--runtime-root",
            str(runtime_root),
            "--state-file",
            str(run_root / "state.json"),
            "--jsonl",
            str(events),
            "--network",
            str(cfg.get("network", "finney")),
            "--netuid",
            str(cfg.get("netuid", 39)),
        ]
        result = proc.run(argv, timeout=timeout, log_path=run_root / "engine.log",
                          inherit_env=False, env=self.child_env(cfg))

        parsed = _read_events(events)
        checks = _checks_from_events(parsed)

        if not checks:
            offline_note = (
                "the validator produced no events — it may not have reached the signed feed"
                if result.ok
                else f"the validator exited {result.returncode}"
            )
            return TestOutcome(
                passed=False,
                summary=offline_note,
                checks=[],
                failure_code="network.unreachable" if result.ok else "upstream.failed",
                remediation="cathedral doctor validator",
                identifiers={"engine_stderr": result.tail(8)},
            )

        passed = result.ok and all(c["passed"] for c in checks)
        vector = next((e for e in parsed if e.get("event") == "WEIGHTS_DRY_RUN"), {})
        accepted = next((e for e in parsed if e.get("event") == "VECTOR_ACCEPTED"), {})

        return TestOutcome(
            passed=passed,
            summary=(
                "the signed feed verified and a weight vector was composed; nothing was written"
                if passed
                else "the validator refused to compose a vector"
            ),
            checks=checks,
            identifiers={
                "vector_id": vector.get("vector_id") or accepted.get("artifact"),
                "policy_version": vector.get("policy_version"),
                "signed_vector_sha256": vector.get("signed_vector_sha256"),
                "uid_count": vector.get("uid_count"),
                "burn_uid": vector.get("burn_uid"),
                "burn_share": vector.get("burn_share"),
                "uid_weights": vector.get("uid_weights"),
                "events": str(events),
            },
            failure_code=None if passed else "verify.signature_failed",
            remediation=None if passed else "cathedral logs validator --run " + run_id,
        )

    def operate_argv(self, cfg: dict[str, Any], *, dry_run: bool) -> list[str]:
        """The real validator command.

        ``--broadcast`` is never added here. Turning on chain writes is an
        explicit operator action through ``cathedral validate --broadcast``,
        which requires a separate confirmation, so it can never be reached by
        an agent that merely retried a start.
        """
        runtime_root = Path(str(cfg.get("runtime_root") or paths.home() / "validator-runtime"))
        runtime_root.mkdir(parents=True, exist_ok=True)
        runtime_root.chmod(0o700)
        argv = [
            str(self.bin("cathedral-validator")),
            "serve",
            "--config",
            str(self._config_path()),
            "--network",
            str(cfg.get("network", "finney")),
            "--netuid",
            str(cfg.get("netuid", 39)),
            "--publisher-url",
            str(cfg.get("publisher_url", "https://api.cathedral.computer")),
            "--interval-secs",
            str(cfg.get("interval_secs", 1500)),
            "--provenance",
            str(cfg.get("provenance", "shadow")),
            "--runtime-root",
            str(runtime_root),
            "--state-file",
            str(paths.state_dir() / "validator-thin-state.json"),
        ]
        if cfg.get("wallet_name"):
            argv += ["--wallet-name", str(cfg["wallet_name"])]
        if cfg.get("wallet_hotkey"):
            argv += ["--wallet-hotkey", str(cfg["wallet_hotkey"])]
        if dry_run:
            argv.append("--dry-run")
        return argv

    def operate_env(self, cfg: dict[str, Any]) -> dict[str, str]:
        from cathedral_node import config as config_module

        return dict(config_module.secret_environment(self.role, cfg))

    def interpret_line(self, line: str) -> dict[str, Any] | None:
        """The validator renders its own excellent status view. We pass it
        through untouched rather than re-styling it — it is already the
        clearest presentation of what it is doing."""
        stripped = line.rstrip()
        if not stripped.strip():
            return None
        return {"event": "ENGINE", "stage": "run", "status": "INFO", "detail": stripped, "passthrough": True}

    # ---- internals ------------------------------------------------------------

    def _config_path(self) -> Path:
        """The engine's own TOML. The node writes a validator.toml derived from
        its config, falling back to the engine's shipped default."""
        managed = paths.config_dir() / "validator-engine.toml"
        if managed.exists():
            return managed
        # The verified generation's inert source tree, or nothing. There is no
        # pointer re-read here: an unbound adapter simply has no engine default.
        if self.verified is None:
            return managed
        return self.source_dir() / "config" / "validator.toml"

    def render_engine_config(self, cfg: dict[str, Any]) -> str:
        """Project node config onto the engine's TOML and return the TEXT.

        Rendering is separated from writing so a failure to render cannot leave a
        half-updated pair of files behind: the caller commits the node config and
        this derived config only after both are known good.

        Owner-controlled burn and allocation settings are projected here and
        nowhere else, so an engine upgrade cannot silently reset them.
        """
        source = (self.source_dir() / "config" / "validator.toml"
                  if self.verified is not None else None)
        base = source.read_text() if source is not None and source.exists() else ""

        lines = [
            "# Cathedral node — validator engine configuration.",
            "# Generated from $CATHEDRAL_HOME/config/validator.toml by `cathedral config set`.",
            "# Edit the node's config, not this file: this one is rewritten.",
            "#",
            "# Burn fraction, burn destination, and lane allocation are NOT here and are",
            "# not operator settings. The validator takes them from Cathedral-signed",
            "# cathedral_burn_config_v1 / cathedral_lane_allocation_v1 documents, and the",
            "# serving path takes the burn share from the signed vector under the pinned",
            "# weight contract below.",
            "",
        ]
        replaced = _substitute(
            base,
            {
                "[network]": {
                    "name": cfg.get("network", "finney"),
                    "netuid": cfg.get("netuid", 39),
                    "wallet_name": cfg.get("wallet_name", "validator"),
                    "validator_hotkey": cfg.get("wallet_hotkey", "default"),
                },
                "[publisher]": {"url": cfg.get("publisher_url", "https://api.cathedral.computer")},
                "[weight_policy]": {
                    "require_policy": cfg.get("require_policy", "validated_supply_v1"),
                    "public_key_hex": cfg.get(
                        "weight_policy_key",
                        "10890a66aa752479cb3b634f366d7bd27c374324d83f88d2d6b69ab066f25e26",
                    ),
                },
                "[weights]": {"interval_secs": cfg.get("interval_secs", 1500)},
                "[provenance]": {"mode": cfg.get("provenance", "shadow")},
            },
        )
        rendered = "\n".join(lines) + replaced

        # Parse what was actually produced, and require the fields this projection
        # exists to carry. Writing a file that does not parse, or that silently
        # lost the owner-controlled settings, is worse than refusing: the engine
        # would start and quietly use its own defaults.
        import tomllib
        try:
            parsed = tomllib.loads(rendered)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"the derived validator configuration does not parse: {exc}") from exc
        for section, field in self.REQUIRED_PROJECTED_FIELDS:
            container = parsed.get(section) if section else parsed
            if not isinstance(container, dict) or field not in container:
                raise ValueError(
                    f"the derived validator configuration is missing "
                    f"{'.'.join(filter(None, (section, field)))}")
        return rendered

    # What the projection must carry through, checked against the PARSED result.
    # Checking the parsed document rather than the rendered text is the point: a
    # substitution that silently failed to land still produces plausible-looking
    # text, and only parsing shows the field is not there.
    REQUIRED_PROJECTED_FIELDS = (("network", "name"), ("network", "netuid"),
                                 ("network", "wallet_name"), ("network", "validator_hotkey"),
                                 ("weight_policy", "public_key_hex"))

    def commit_engine_config(self, rendered: str) -> Path:
        """Write the already-validated derived configuration atomically."""
        from cathedral_node import safeio
        managed = paths.config_dir() / "validator-engine.toml"
        safeio.secure_write_atomic(managed, rendered.encode("utf-8"), mode=0o600)
        return managed

    def write_engine_config(self, cfg: dict[str, Any]) -> Path:
        """Render, validate, then commit. The single-call form, for setup paths."""
        return self.commit_engine_config(self.render_engine_config(cfg))


def _substitute(toml_text: str, sections: dict[str, dict[str, Any]]) -> str:
    """Replace known scalar keys inside known sections, leaving everything else
    — comments, pinned keys, provenance bundles — byte-identical.

    Deliberately conservative: the engine's config carries security-critical
    pins we must not rewrite, so anything not named here is passed through.
    """
    out: list[str] = []
    current: str | None = None
    written: dict[str, set[str]] = {section: set() for section in sections}
    for raw in toml_text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped
            out.append(raw)
            continue
        if current in sections and "=" in stripped and not stripped.startswith("#"):
            key = stripped.split("=", 1)[0].strip()
            if key in sections[current]:
                value = sections[current][key]
                rendered = _toml_scalar(value)
                out.append(f"{key} = {rendered}")
                written[current].add(key)
                continue
        out.append(raw)

    # Anything the base did not already contain is APPENDED rather than dropped.
    # Substitution alone was only ever correct when the base was the engine's own
    # shipped default; with an empty or trimmed base it silently produced a config
    # carrying none of the projection, which the engine would then start against
    # using its own defaults. Emitting the section is what makes the projection a
    # guarantee instead of a best effort.
    missing = {section: {k: v for k, v in values.items() if k not in written[section]}
               for section, values in sections.items()}
    for section, values in missing.items():
        if not values:
            continue
        out.append("")
        out.append(section)
        for key, value in values.items():
            out.append(f"{key} = {_toml_scalar(value)}")
    return "\n".join(out) + "\n"


def _toml_scalar(value: Any) -> str:
    """Render a scalar for the engine's TOML.

    Shares config.py's escaping deliberately: an unescaped value here could
    inject keys into a security-critical section, or break the file so the
    engine will not start.
    """
    from cathedral_node.config import _toml_value

    return _toml_value(value)


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def _checks_from_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn the engine's own events into the node's uniform check shape.

    Only events that represent a real verification decision become checks;
    startup and bookkeeping lines are diagnostics, not results.
    """
    # (label, description, verdict) where verdict is the meaning of the event
    # NAME itself. The name is authoritative: VECTOR_REJECTED means the feed was
    # refused whatever the status field happens to say, or fails to say.
    interesting: dict[str, tuple[str, str, bool]] = {
        "VECTOR_ACCEPTED": ("feed", "the signed score feed verified", True),
        "VECTOR_REJECTED": ("feed", "the signed score feed was refused", False),
        "WEIGHTS_DRY_RUN": ("vector", "a weight vector was composed without writing", True),
        "WEIGHTS_SUBMITTED": ("submit", "weights were submitted", True),
        "PROVENANCE_AUDIT_PASS": ("audit", "the independent provenance audit agreed", True),
        "PROVENANCE_AUDIT_NOT_PROVEN": ("audit", "the provenance audit could not prove the epoch", False),
        "PROVENANCE_VECTOR_MISMATCH": ("audit", "the independent audit computed a different vector", False),
        "PROVENANCE_DIVERGENCE": ("audit", "the independent provenance audit disagreed", False),
        "TICK_FAILED": ("tick", "the validator could not complete the tick", False),
        "PENDING_RECEIPT_CONTRADICTION": ("receipt", "a pending submission contradicts the chain", False),
        "PENDING_RECEIPT_NOT_PROVEN": ("receipt", "a pending submission could not be proven", False),
    }

    checks = []
    for event in events:
        name = event.get("event")
        if name not in interesting:
            continue
        label, description, name_says_pass = interesting[name]

        # Fail closed on the status field. Only an explicit affirmative counts;
        # a missing, empty, or unrecognised status is NOT a pass. Reading "" as
        # success meant a refused vector reported as verified — the engine's
        # verdict inverted by a field the node neither sets nor requires.
        raw_status = str(event.get("status", "")).strip().upper()
        if raw_status in ("PASS", "INFO"):
            status_says_pass = True
        elif raw_status in ("FAIL", "NOT_PROVEN", "ERROR", "WARN"):
            status_says_pass = False
        else:
            status_says_pass = False  # unknown or absent: refuse

        checks.append(
            {
                "label": label,
                "name": description,
                # Both must agree. Either signal alone saying "no" is a no.
                "passed": bool(name_says_pass and status_says_pass),
                "detail": event.get("detail", ""),
                "event": name,
                "event_status": raw_status or None,
                "artifact": event.get("artifact"),
            }
        )
    return checks
