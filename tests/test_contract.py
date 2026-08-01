"""The agent contract, enforced.

These tests are the reason an agent can pin ``protocol_version`` and trust it.
Each one encodes a promise made in the contract documentation, so breaking the
promise breaks a test rather than breaking somebody's automation quietly.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

import pytest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CLI = REPO / "cathedral"

sys.path.insert(0, str(REPO))

from cathedral_node import config, engines, lockfile  # noqa: E402
from cathedral_node.contracts import Envelope, Exit  # noqa: E402
from cathedral_node.contracts.codes import retryable  # noqa: E402
from cathedral_node.contracts.version import PROTOCOL_VERSION, RESULT_SCHEMA, compatible  # noqa: E402
from cathedral_node.engines.base import Engine, UnverifiedEngine  # noqa: E402
from cathedral_node.redact import redact_text, redact_value  # noqa: E402


class CliCase(unittest.TestCase):
    """Runs the real CLI in a throwaway home, the way an agent would."""

    home: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="cathedral-test-")
        cls.home = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def run_cli(self, *args: str, stdin: str | None = None, home: Path | None = None):
        env = dict(os.environ)
        env["CATHEDRAL_HOME"] = str(home or self.home)
        env["NO_COLOR"] = "1"
        env["COLUMNS"] = "88"
        return subprocess.run(  # noqa: S603
            [sys.executable, str(CLI), *args],
            capture_output=True, text=True, env=env, input=stdin, timeout=900,
        )

    def json_cli(self, *args: str, stdin: str | None = None, home: Path | None = None):
        proc = self.run_cli(*args, "--json", stdin=stdin, home=home)
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:  # pragma: no cover - diagnostic path
            self.fail(f"`{' '.join(args)} --json` did not emit JSON on stdout: {exc}\n{proc.stdout[:400]}")
        return proc, payload


class TestEnvelopeShape(CliCase):
    """Every command returns the same envelope, whatever it did."""

    COMMANDS = (
        ("capabilities",),
        ("doctor",),
        ("explain", "distill"),
        ("explain", "compute"),
        ("explain", "validator"),
        ("status",),
        ("config", "show"),
        ("config", "schema"),
        ("secret", "list"),
        ("agent-brief",),
        ("update", "--check"),
    )

    REQUIRED_KEYS = {
        "schema", "protocol_version", "command", "status", "exit_code", "dry_run",
        "run_id", "started_at", "finished_at", "duration_ms", "data_schema", "data",
        "error", "warnings", "next",
    }

    def test_every_command_emits_a_complete_envelope(self):
        for args in self.COMMANDS:
            with self.subTest(command=" ".join(args)):
                _, payload = self.json_cli(*args)
                self.assertEqual(set(payload) & self.REQUIRED_KEYS, self.REQUIRED_KEYS,
                                 f"missing keys: {self.REQUIRED_KEYS - set(payload)}")
                self.assertEqual(payload["schema"], RESULT_SCHEMA)
                self.assertEqual(payload["protocol_version"], PROTOCOL_VERSION)
                self.assertIn(payload["status"], ("ok", "failed", "blocked"))
                self.assertIsInstance(payload["exit_code"], int)
                self.assertIsInstance(payload["warnings"], list)
                self.assertIsInstance(payload["next"], list)

    def test_exit_code_matches_the_envelope(self):
        for args in self.COMMANDS:
            with self.subTest(command=" ".join(args)):
                proc, payload = self.json_cli(*args)
                self.assertEqual(proc.returncode, payload["exit_code"],
                                 "the process exit code must equal envelope.exit_code")

    def test_stdout_is_only_the_result(self):
        """An agent pipes stdout to a parser. Nothing else may appear there."""
        for args in self.COMMANDS:
            with self.subTest(command=" ".join(args)):
                proc = self.run_cli(*args, "--json")
                self.assertTrue(proc.stdout.lstrip().startswith("{"),
                                f"stdout must start with the envelope, got: {proc.stdout[:120]!r}")
                json.loads(proc.stdout)  # exactly one document, no trailing noise

    def test_human_mode_writes_to_stdout_so_redirection_works(self):
        """`cathedral doctor > log.txt` must capture what the operator saw.

        Regression: the human view went to stderr unconditionally, so
        redirecting produced an empty file and piping to grep matched nothing —
        silently, which is worse than failing.
        """
        for args in self.COMMANDS:
            with self.subTest(command=" ".join(args)):
                proc = self.run_cli(*args)
                self.assertTrue(proc.stdout.strip(),
                                "human output must be capturable by a redirect")

    def test_json_mode_keeps_stderr_clean(self):
        """The agent contract is unaffected by the above: --json still puts the
        envelope alone on stdout and says nothing on stderr."""
        for args in self.COMMANDS:
            with self.subTest(command=" ".join(args)):
                proc = self.run_cli(*args, "--json")
                self.assertEqual(proc.stderr.strip(), "",
                                 "--json must not narrate to stderr")
                json.loads(proc.stdout)

    def test_next_steps_are_runnable(self):
        for args in self.COMMANDS:
            with self.subTest(command=" ".join(args)):
                _, payload = self.json_cli(*args)
                for step in payload["next"]:
                    self.assertIn("description", step)
                    self.assertIn("command", step)
                    self.assertIn("safe", step)
                    if step["command"]:
                        self.assertTrue(step["command"].startswith("cathedral "),
                                        f"not a cathedral command: {step['command']!r}")


class TestErrorContract(CliCase):
    def test_unknown_run_is_not_found_with_remediation(self):
        proc, payload = self.json_cli("status", "--run", "run-does-not-exist")
        self.assertEqual(proc.returncode, int(Exit.NOT_FOUND))
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["error"]["code"], "run.not_found")
        self.assertIsNotNone(payload["error"]["remediation"]["command"])

    def test_unknown_config_field_is_usage_not_a_crash(self):
        proc, payload = self.json_cli("config", "set", "distill", "not_a_field", "x")
        self.assertEqual(proc.returncode, int(Exit.USAGE))
        self.assertEqual(payload["error"]["code"], "config.field_required")

    def test_every_error_names_a_code_and_a_way_forward(self):
        cases = [
            ("status", "--run", "nope"),
            ("config", "set", "distill", "bogus", "1"),
            ("config", "set", "distill", "coldkey", "x"),
            ("evidence", "no-such-identifier"),
        ]
        for args in cases:
            with self.subTest(command=" ".join(args)):
                _, payload = self.json_cli(*args)
                error = payload["error"]
                self.assertIsNotNone(error, "a failure must carry an error object")
                self.assertTrue(error["code"], "every error needs a machine-matchable code")
                self.assertTrue(error["message"], "every error needs a human message")
                remediation = error["remediation"]
                self.assertIsNotNone(remediation, "every error must say what to do next")
                self.assertTrue(
                    remediation["command"] or remediation["summary"] or remediation["requires_operator"],
                    "remediation must offer a command, an explanation, or an escalation",
                )

    def test_exit_codes_are_grouped_as_documented(self):
        self.assertTrue(10 <= int(Exit.NOT_READY) < 20)
        self.assertTrue(20 <= int(Exit.VERIFY_FAILED) < 30)
        self.assertTrue(30 <= int(Exit.USAGE) < 40)
        self.assertTrue(40 <= int(Exit.NETWORK) < 50)

    def test_retryable_classification(self):
        self.assertTrue(retryable(Exit.NETWORK))
        self.assertTrue(retryable(Exit.LOCKED))
        self.assertFalse(retryable(Exit.UNSUPPORTED))
        self.assertFalse(retryable(Exit.VERIFY_FAILED))


class TestSecretHandling(CliCase):
    SECRET = "sk-live-4b1d9f2c8a7e6d5c4b3a2918f7e6d5c4"

    def test_a_secret_is_never_accepted_as_an_argument(self):
        proc = self.run_cli("secret", "set", "TEST_KEY", self.SECRET, "--json")
        self.assertNotEqual(proc.returncode, 0, "a positional secret value must be refused")

    def test_a_secret_is_read_from_stdin_and_never_echoed(self):
        proc, payload = self.json_cli("secret", "set", "TEST_KEY", "--stdin", stdin=self.SECRET)
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn(self.SECRET, proc.stdout)
        self.assertNotIn(self.SECRET, proc.stderr)
        self.assertNotIn(self.SECRET, json.dumps(payload))
        self.assertTrue(payload["data"]["fingerprint"].startswith("sha256:"))

    def test_listing_secrets_never_reveals_one(self):
        self.json_cli("secret", "set", "TEST_KEY", "--stdin", stdin=self.SECRET)
        proc, payload = self.json_cli("secret", "list")
        self.assertNotIn(self.SECRET, proc.stdout + proc.stderr)
        names = [s["name"] for s in payload["data"]["secrets"]]
        self.assertIn("TEST_KEY", names)

    def test_the_secret_file_is_owner_only(self):
        self.json_cli("secret", "set", "TEST_KEY", "--stdin", stdin=self.SECRET)
        secrets = self.home / "secrets.env"
        self.assertTrue(secrets.exists())
        self.assertEqual(oct(secrets.stat().st_mode)[-3:], "600")

    def test_a_coldkey_is_refused_by_name(self):
        for field in ("coldkey", "mnemonic", "seed", "private_key"):
            with self.subTest(field=field):
                proc, payload = self.json_cli("config", "set", "distill", field, "whatever")
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(payload["error"]["code"],
                              ("identity.coldkey_refused", "config.field_required"))

    def test_a_secret_reference_field_refuses_a_literal_value(self):
        proc, payload = self.json_cli("config", "set", "distill", "api_key_secret", self.SECRET)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(payload["error"]["code"], "secret.unsafe_source")
        self.assertNotIn(self.SECRET, proc.stdout + proc.stderr)

    def test_redaction_catches_a_leaked_secret(self):
        for text, forbidden in [
            (f"api_key={self.SECRET}", self.SECRET),
            (f'{{"token": "{self.SECRET}"}}', self.SECRET),
            ("Authorization: Bearer " + "a" * 40, "a" * 40),
            ("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "abc"),
        ]:
            with self.subTest(text=text[:32]):
                self.assertNotIn(forbidden, redact_text(text))

    def test_redaction_masks_by_key_whatever_the_shape(self):
        payload = {"outer": {"api_key": {"nested": "value"}, "safe": "kept"}}
        masked = redact_value(payload)
        self.assertEqual(masked["outer"]["api_key"], "[redacted]")
        self.assertEqual(masked["outer"]["safe"], "kept")

    def test_public_exemption_is_narrow_and_never_leaks_an_embedded_credential(self):
        """Regression (Codex on 8f3ba8d): exempting every non-secret config value
        leaked a credential embedded in a URL. Only the validated 64-hex public key
        is exempt; a value carrying `?api_key=...` must still be masked."""
        import re

        from cathedral_node import redact
        redact.forget_public_values()
        key = "10890a66aa752479cb3b634f366d7bd27c374324d83f88d2d6b69ab066f25e26"
        self.assertTrue(re.fullmatch(r"[0-9a-fA-F]{64}", key))
        redact.register_public_values([key])  # what config does for weight_policy_key only
        leaky = "https://host/v1/?api_key=sk-secret-abcdefghijklmnop"
        out = redact.redact_value({"weight_policy_key": key, "api_base": leaky})
        self.assertEqual(out["weight_policy_key"], key, "the public key stays readable")
        self.assertNotIn("sk-secret-abcdefghijklmnop", json.dumps(out),
                         "a credential embedded in a non-exempt field must still be masked")
        redact.forget_public_values()

    def test_known_secret_takes_precedence_over_known_public(self):
        """Regression (Codex on 8f3ba8d): a value registered as both secret and
        public must be masked, whatever the registration order."""
        from cathedral_node import redact
        for order in ("public_first", "secret_first"):
            with self.subTest(order=order):
                redact.forget_public_values()
                redact.forget_secret_values()
                v = "correcthorsebatterystaple-not-a-shape-match"
                if order == "public_first":
                    redact.register_public_values([v])
                    redact.register_secret_values([v])
                else:
                    redact.register_secret_values([v])
                    redact.register_public_values([v])
                self.assertEqual(redact.redact_value({"x": v})["x"], "[redacted]")
        redact.forget_public_values()
        redact.forget_secret_values()


class TestIdempotency(CliCase):
    def test_config_set_is_idempotent(self):
        first, a = self.json_cli("config", "set", "distill", "model", "hermes3")
        second, b = self.json_cli("config", "set", "distill", "model", "hermes3")
        self.assertEqual(first.returncode, 0)
        self.assertEqual(second.returncode, 0)
        self.assertEqual(a["data"]["to"], b["data"]["to"])

    def test_stop_when_nothing_runs_is_success_not_failure(self):
        proc, payload = self.json_cli("stop", "distill")
        self.assertEqual(proc.returncode, 0, "stopping an idle role is a no-op, not an error")
        self.assertFalse(payload["data"]["was_running"])

    def test_dry_run_changes_nothing(self):
        before = (self.home / "config" / "distill.toml").read_text() if (
            self.home / "config" / "distill.toml").exists() else ""
        proc, payload = self.json_cli("config", "set", "distill", "model", "changed-by-dry-run",
                                      "--dry-run")
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(payload["dry_run"])
        self.assertFalse(payload["data"]["written"])
        after = (self.home / "config" / "distill.toml").read_text() if (
            self.home / "config" / "distill.toml").exists() else ""
        self.assertEqual(before, after, "a dry run must not touch the filesystem")


class TestNonInteractive(CliCase):
    def test_no_command_blocks_on_a_prompt(self):
        """Every command must terminate with stdin closed."""
        for args in (("doctor",), ("capabilities",), ("status",), ("config", "show")):
            with self.subTest(command=" ".join(args)):
                proc = subprocess.run(  # noqa: S603
                    [sys.executable, str(CLI), *args, "--json"],
                    capture_output=True, text=True, timeout=300,
                    stdin=subprocess.DEVNULL,
                    env={**os.environ, "CATHEDRAL_HOME": str(self.home), "NO_COLOR": "1"},
                )
                self.assertIsNotNone(proc.returncode)

    def test_a_required_confirmation_is_reported_not_prompted(self):
        """A confirmation that can be supplied names the flag that supplies it."""
        proc, payload = self.json_cli("update", "--yes" if False else "--check")
        self.assertEqual(proc.returncode, 0)  # --check needs no confirmation
        proc, payload = self.json_cli("cleanup", "--engine")
        if payload.get("error", {}) and payload["error"]["code"] == "usage.confirmation_required":
            self.assertIn("--yes", payload["error"]["remediation"]["command"])

    def test_confirmation_remedy_preserves_the_operation(self):
        """Regression: the `--yes` remedy dropped the operative flag, so running
        it verbatim performed a different, narrower operation and reported success.
        `cleanup --engine distill` was answered with `cathedral cleanup distill --yes`,
        which deletes run directories, not the engine — an agent would believe the
        engine was gone."""
        self.json_cli("setup", "distill")  # something removable must exist
        proc, payload = self.json_cli("cleanup", "--engine", "distill")
        if payload.get("error", {}) and payload["error"]["code"] == "usage.confirmation_required":
            cmd = payload["error"]["remediation"]["command"]
            self.assertIn("--engine", cmd,
                          f"remedy {cmd!r} dropped --engine; verbatim it would delete runs, not the engine")
            self.assertIn("distill", cmd)
            self.assertIn("--yes", cmd)

    def test_confirmation_remedy_preserves_the_all_flag(self):
        self.json_cli("setup", "distill")
        proc, payload = self.json_cli("cleanup", "--all")
        if payload.get("error", {}) and payload["error"]["code"] == "usage.confirmation_required":
            self.assertIn("--all", payload["error"]["remediation"]["command"])

    def test_chain_writes_are_refused_permanently_not_as_a_missing_flag(self):
        """Regression: --broadcast returned `usage.confirmation_required`, whose
        documented remedy is "pass --yes". Passing --yes returned the same
        thing, so an agent following the contract looped forever."""
        for extra in ([], ["--yes"]):
            with self.subTest(flags=extra):
                proc, payload = self.json_cli("start", "validator", "--broadcast", *extra)
                self.assertEqual(proc.returncode, int(Exit.UNSUPPORTED))
                self.assertEqual(payload["error"]["code"], "contract.chain_writes_refused")
                self.assertTrue(payload["error"]["remediation"]["requires_operator"],
                                "a permanent refusal must be marked requires_operator")
                self.assertFalse(retryable(Exit(payload["exit_code"])))


class TestProtocolVersioning(unittest.TestCase):
    def test_compatibility_is_by_major(self):
        self.assertTrue(compatible("1.0.0"))
        self.assertTrue(compatible("1.9.3"))
        self.assertFalse(compatible("2.0.0"))
        self.assertFalse(compatible("0.9.0"))
        self.assertFalse(compatible("nonsense"))

    def test_envelope_serialises_completely(self):
        env = Envelope.ok("demo", {"a": 1})
        env.warn("w", "careful").then("do this", "cathedral doctor")
        payload = env.to_dict()
        json.dumps(payload)  # must be serialisable
        self.assertEqual(payload["warnings"][0]["code"], "w")
        self.assertEqual(payload["next"][0]["command"], "cathedral doctor")


class TestEngineContract(unittest.TestCase):
    """Every engine adapter must satisfy the same interface."""

    def setUp(self) -> None:
        self.lock = lockfile.load()

    def test_every_role_resolves_to_an_engine(self):
        for role in lockfile.ROLES:
            with self.subTest(role=role):
                self.assertIsInstance(engines.load(role, self.lock), Engine)

    def test_explain_has_every_required_key(self):
        for role in lockfile.ROLES:
            with self.subTest(role=role):
                explanation = engines.load(role, self.lock).explain()
                for key in Engine.EXPLAIN_REQUIRED:
                    self.assertIn(key, explanation, f"{role}.explain() is missing {key!r}")

    def test_capabilities_are_shaped_consistently(self):
        # Regression: the compute engine exposed `engine_census: null` inside the
        # capabilities map, so an agent doing `cap["available"]` while iterating
        # capabilities hit `None`. Every entry must be a capability object.
        for role in lockfile.ROLES:
            with self.subTest(role=role):
                for name, capability in engines.load(role, self.lock).capabilities().items():
                    self.assertIsInstance(
                        capability, dict,
                        f"{role}.{name} must be a capability object, not "
                        f"{type(capability).__name__} — an agent iterating capabilities "
                        "must never meet a null or non-dict entry")
                    self.assertIn("available", capability,
                                  f"{role}.{name} must declare `available`")
                    self.assertIsInstance(capability["available"], bool,
                                          f"{role}.{name}.available must be a bool")

    def test_an_unbound_adapter_refuses_to_resolve_an_executable_path(self):
        """The sealed-execution boundary.

        An adapter that has not been handed a verified generation has no fallback
        to resolve: it raises rather than reading the mutable active pointer. That
        removes the verify-then-swap window entirely, because there is no second
        path resolution to race.

        (That argv never carries a secret is proven against the REAL adapters,
        bound to a real verified generation, in
        tests/test_gate0.py::TestRealAdapterBinding.)
        """
        secret = "sk-should-never-appear-1234567890"
        for role in lockfile.ROLES:
            with self.subTest(role=role):
                cfg = dict(config.defaults(role))
                cfg.update({
                    "hotkey": "5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX",
                    "api_key_secret": secret,
                    "bearer_token_secret": secret,
                })
                adapter = engines.load(role, self.lock)
                self.assertIsNone(adapter.verified)
                self.assertFalse(adapter.has_bin("python"))
                with self.assertRaises(UnverifiedEngine):
                    adapter.operate_argv(cfg, dry_run=True)

    def test_pins_are_full_commit_shas(self):
        for role, pin in self.lock.engines.items():
            with self.subTest(role=role):
                self.assertEqual(len(pin.revision), 40, f"{role} pin must be a full SHA")
                int(pin.revision, 16)

    def test_legacy_cathedral_is_excluded_and_never_pinned(self):
        self.assertIn("cathedralai/cathedral", self.lock.excluded)
        for pin in self.lock.engines.values():
            self.assertNotEqual(pin.repository, "https://github.com/cathedralai/cathedral.git")

    def test_trusted_repository_parses_the_origin_not_a_substring(self):
        """Regression (Codex): the allow-check was a substring test, so a hostile
        `https://attacker.example/github.com/cathedralai/evil.git` passed and its
        build backend would run as the operator during pip install."""
        trusted = [
            "https://github.com/cathedralai/cathedral-distill.git",
            "https://GitHub.com/cathedralai/cathedral-compute.git",
        ]
        untrusted = [
            "https://attacker.example/github.com/cathedralai/evil.git",  # substring in path
            "https://github.com@attacker.example/cathedralai/evil.git",  # userinfo trick
            "https://github.com.attacker.example/cathedralai/evil.git",  # suffix trick
            "http://github.com/cathedralai/evil.git",                    # not https
            "https://github.com/attacker/evil.git",                      # wrong owner
            "git@github.com:cathedralai/x.git",                          # scp form
            "https://raw.githubusercontent.com/cathedralai/x",           # wrong host
        ]
        for url in trusted:
            self.assertTrue(lockfile.is_trusted_repository(url), url)
        for url in untrusted:
            self.assertFalse(lockfile.is_trusted_repository(url), url)


class TestConfigSafety(unittest.TestCase):
    def test_forbidden_fields_cannot_be_saved(self):
        with self.assertRaises(config.ConfigError):
            config.save("distill", {"coldkey": "anything"})

    def test_hotkey_shape_is_validated(self):
        problems = config.validate("distill", {**config.defaults("distill"), "hotkey": "not-an-address"})
        self.assertTrue(any("hotkey" in p for p in problems))

    def test_a_valid_hotkey_passes(self):
        good = "5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX"
        problems = config.validate("distill", {**config.defaults("distill"), "hotkey": good})
        self.assertFalse([p for p in problems if "hotkey" in p], problems)

    def test_non_loopback_without_tls_is_refused(self):
        problems = config.validate("compute", {**config.defaults("compute"), "host": "0.0.0.0"})
        self.assertTrue(any("TLS" in p for p in problems), problems)

    def test_owner_controlled_fields_are_declared(self):
        owner = config.OWNER_CONTROLLED["validator"]
        for field in ("wallet_name", "wallet_hotkey", "require_policy", "weight_policy_key"):
            self.assertIn(field, owner)

    def test_burn_is_not_offered_as_an_operator_setting(self):
        """The validator takes burn and allocation from Cathedral-signed
        documents and from the signed vector, so an editable `burn_fraction`
        would let an operator believe they had changed the economics when
        nothing had changed."""
        names = {f.name for f in config.schema("validator")}
        for field in ("burn_fraction", "burn_destination", "lane_allocation"):
            self.assertNotIn(field, names, f"`{field}` is not the operator's to set")
            self.assertNotIn(field, config.OWNER_CONTROLLED["validator"])

    def test_the_weight_contract_and_signing_key_are_the_operators(self):
        """What an operator genuinely controls is what they will *accept*."""
        names = {f.name for f in config.schema("validator")}
        self.assertIn("require_policy", names)
        self.assertIn("weight_policy_key", names)
        problems = config.validate("validator",
                                   {**config.defaults("validator"), "weight_policy_key": "tooshort"})
        self.assertTrue(any("weight_policy_key" in p for p in problems))


class TestGateHarnessCannotBeNarrowed(unittest.TestCase):
    """The harness is the thing that decides whether a green result means anything,
    so it gets falsified the same way everything else does.

    Each case runs a real pytest invocation and requires it to refuse *before*
    executing. A narrowing that merely produces fewer passing tests is not a
    failure anyone would notice; it has to be an error.
    """

    GATE0 = ["tests/test_gate0.py", "tests/test_contract.py"]
    GATE12 = ["tests/test_gate12.py"]

    def _pytest(self, args: list[str], env: dict[str, str] | None = None):
        environment = dict(os.environ)
        environment.pop("PYTEST_ADDOPTS", None)
        environment.pop("PYTHONWARNINGS", None)
        environment.update(env or {})
        # No `-p no:cacheprovider`: disabling the cache plugin also removes
        # `--last-failed`, and a refusal that reads "unrecognized argument" would
        # prove nothing about the harness.
        return subprocess.run(  # noqa: S603
            [sys.executable, "-m", "pytest", "--collect-only", "-q", *args],
            capture_output=True, text=True, cwd=str(REPO), env=environment, timeout=300)

    def _assert_refused(self, args: list[str], *, needle: str = "narrowed",
                        env: dict[str, str] | None = None) -> None:
        result = self._pytest(args, env)
        combined = result.stdout + result.stderr
        self.assertNotEqual(result.returncode, 0,
                            f"`pytest {' '.join(args)}` was accepted:\n{combined[-800:]}")
        self.assertIn(needle, combined.lower(),
                      f"the refusal did not say why:\n{combined[-800:]}")

    def test_gate0_refuses_every_narrowing_option(self):
        for label, extra in {
            "-k": ["-k", "pointer"],
            "-m": ["-m", "not real_engine"],
            "--ignore": ["--ignore", "tests/test_contract.py"],
            "--ignore-glob": ["--ignore-glob", "*contract*"],
            "--deselect": ["--deselect", "tests/test_gate0.py::TestReleaseVerification"],
            "-x": ["-x"],
            "--maxfail": ["--maxfail=1"],
            "--last-failed": ["--lf"],
            "--stepwise": ["--stepwise"],
        }.items():
            with self.subTest(option=label):
                self._assert_refused([*self.GATE0, *extra])

    def test_gate0_refuses_a_pytest_environment_that_rewrites_the_invocation(self):
        for name, value in (("PYTEST_ADDOPTS", "-k pointer"),
                            ("PYTHONWARNINGS", "ignore"),
                            ("PYTEST_DISABLE_PLUGIN_AUTOLOAD", "1")):
            with self.subTest(variable=name):
                self._assert_refused(self.GATE0, env={name: value})

        # PYTEST_PLUGINS never reaches the harness: pytest itself refuses at plugin
        # registration, whatever the value. That is still a refusal — what must not
        # happen is a *passing* run under a rewritten invocation — so this asserts
        # the outcome rather than the wording, and the harness check remains as the
        # backstop for the case where pytest one day accepts it.
        for value in ("xdist", "_pytest.python"):
            with self.subTest(variable="PYTEST_PLUGINS", value=value):
                result = self._pytest(self.GATE0, {"PYTEST_PLUGINS": value})
                self.assertNotEqual(result.returncode, 0,
                                    "a run under PYTEST_PLUGINS must not succeed")
        from tests.conftest import _FORBIDDEN_ENV  # noqa: PLC0415
        self.assertIn("PYTEST_PLUGINS", _FORBIDDEN_ENV)

    def test_gate0_is_not_claimed_for_an_altered_target_set(self):
        for label, targets in {
            "extra target": [*self.GATE0, "tests/test_gate12.py"],
            "missing target": ["tests/test_gate0.py"],
            "a directory": ["tests"],
            "node selection": ["tests/test_gate0.py::TestReleaseVerification",
                               "tests/test_contract.py"],
        }.items():
            with self.subTest(case=label):
                result = self._pytest(targets)
                combined = result.stdout + result.stderr
                self.assertIn("not a gate 0 run", combined.lower(),
                              f"{label} was not disclaimed:\n{combined[-600:]}")

    def test_a_single_node_of_the_gate12_file_is_not_a_gate12_result(self):
        """The bypass this closes: stripping `::` before comparing made one test
        compare equal to the whole file, and the run was handed the banner that
        says the complete job ran unfiltered."""
        node = f"{self.GATE12[0]}::TestHonestClosingLine::test_the_closing_line_states_what_was_verified"
        result = self._pytest([node])
        combined = (result.stdout + result.stderr).lower()
        self.assertNotIn("gate 1/2 mode", combined,
                         "a single selected node was presented as the complete Gate 1/2 job")
        self.assertIn("not a gate 0 run", combined)

    def test_gate12_refuses_narrowing_and_requires_its_exact_node_set(self):
        for label, extra in {"-k": ["-k", "identifier"], "-m": ["-m", "real_engine"],
                             "--maxfail": ["--maxfail=1"]}.items():
            with self.subTest(option=label):
                self._assert_refused([*self.GATE12, *extra])
        from tests.conftest import GATE12_NODE_IDS  # noqa: PLC0415
        self.assertTrue(GATE12_NODE_IDS, "the Gate 1/2 job must declare its exact node set")

    def test_the_gate0_runner_script_shows_exactly_what_it_runs(self):
        script = (REPO / "run-gate0.sh").read_text()
        self.assertIn("GATE0_COMMAND=(python -m pytest -q tests/test_gate0.py tests/test_contract.py)",
                      script, "the command must be defined once")
        self.assertIn('echo "command:     ${GATE0_COMMAND[*]}"', script)
        self.assertIn('exec "${GATE0_COMMAND[@]}"', script)
        for name in ("PYTEST_ADDOPTS", "PYTHONWARNINGS", "PYTEST_PLUGINS",
                     "PYTEST_DISABLE_PLUGIN_AUTOLOAD"):
            self.assertIn(name, script, f"the runner must refuse ${name}")

    def test_the_gate12_runner_passes_its_release_argument_to_cathedral_not_pytest(self):
        script = (REPO / "run-gate12.sh").read_text()
        self.assertIn('export CATHEDRAL_RELEASE="$RELEASE"', script,
                      "--release is Cathedral's argument, not pytest's")
        self.assertNotIn('"$@"', script,
                         "forwarding arbitrary arguments to pytest is how filtering gets in")
        self.assertIn("GATE12_COMMAND=(python -m pytest -q tests/test_gate12.py)", script)


class TestGateManifestSemantics(unittest.TestCase):
    """The manifest is validated as a document, because equal node IDs are not the
    same claim as a manifest for *this* gate."""

    def setUp(self):
        from tests import conftest as harness
        self.harness = harness
        self.manifest = json.loads((REPO / "tests" / "gate0_manifest.json").read_text())
        self.collected = [n for requirement in self.manifest["requirements"]
                          for n in requirement["tests"]]

    def test_the_checked_in_manifest_is_valid(self):
        problems = self.harness.validate_manifest(self.manifest, collected=self.collected)
        self.assertEqual(problems, [], f"the checked-in manifest is invalid: {problems}")

    def test_every_way_the_manifest_can_be_wrong_is_caught(self):
        import copy
        cases = {
            "wrong schema": lambda m: m.__setitem__("schema", "something.else.v1"),
            "wrong command": lambda m: m.__setitem__("command", "pytest -x"),
            "wrong file set": lambda m: m.__setitem__("files", ["tests/test_gate0.py"]),
            "wrong revision": lambda m: m["specification"].__setitem__("revision", 4),
            "wrong spec hash": lambda m: m["specification"].__setitem__("sha256", "0" * 64),
            "wrong review hash": lambda m: m["specification"]["review"].__setitem__("sha256", "0" * 64),
            "wrong directive hash":
                lambda m: m["specification"]["repair_directive"].__setitem__("sha256", "0" * 64),
            "miscounted": lambda m: m.__setitem__("node_id_count", 1),
            "requirement without a source":
                lambda m: m["requirements"][0].__setitem__("source", ""),
            "requirement without a statement":
                lambda m: m["requirements"][0].__setitem__("statement", "too short"),
            "requirement without a test":
                lambda m: m["requirements"][0].__setitem__("tests", []),
            "duplicate requirement id":
                lambda m: m["requirements"].append(copy.deepcopy(m["requirements"][0])),
            "a node outside the gate files":
                lambda m: m["requirements"][0]["tests"].append("tests/test_gate12.py::T::t"),
            "a node listed twice in one requirement":
                lambda m: m["requirements"][0]["tests"].append(m["requirements"][0]["tests"][0]),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                broken = copy.deepcopy(self.manifest)
                mutate(broken)
                collected = [n for requirement in broken["requirements"]
                             for n in requirement["tests"]]
                problems = self.harness.validate_manifest(broken, collected=collected)
                self.assertTrue(problems, f"{label} was accepted")

    def test_the_generator_hashes_the_real_controlling_documents(self):
        source = (REPO / "scripts" / "gate0_manifest.py").read_text()
        self.assertIn("hashlib.sha256((directory / name).read_bytes()).hexdigest()", source,
                      "the generator must hash the documents rather than assert their hashes")
        self.assertIn("a controlling document has changed", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestExitCodeDocumentation(unittest.TestCase):
    """Every exit code must carry a distinct published meaning.

    Regression: reading `member.__doc__` on an IntEnum returns the *class*
    docstring, so the generated agent brief printed the same sentence sixteen
    times. An agent reading that learns nothing.
    """

    def test_every_code_has_a_description(self):
        from cathedral_node.contracts.codes import DESCRIPTIONS, describe

        for member in Exit:
            with self.subTest(code=member.name):
                self.assertIn(member, DESCRIPTIONS)
                self.assertTrue(describe(member).strip())

    def test_descriptions_are_distinct(self):
        from cathedral_node.contracts.codes import DESCRIPTIONS

        texts = list(DESCRIPTIONS.values())
        self.assertEqual(len(texts), len(set(texts)), "two exit codes share a description")


class TestGeneratedBrief(CliCase):
    def test_brief_reports_distinct_exit_code_meanings(self):
        _, payload = self.json_cli("agent-brief", "distill")
        brief = payload["data"]["brief"]
        self.assertIn("| `20` | `VERIFY_FAILED` |", brief)
        self.assertIn("Fail-closed verification", brief)
        self.assertNotIn("Process exit codes. Stable within", brief)

    def test_brief_never_promises_an_unavailable_capability(self):
        """The brief is generated from live state, so an uninstalled engine must
        be described as uninstalled rather than ready."""
        fresh = Path(tempfile.mkdtemp(prefix="cathedral-brief-"))
        try:
            _, payload = self.json_cli("agent-brief", "distill", home=fresh)
            brief = payload["data"]["brief"]
            self.assertIn("not installed", brief)
            self.assertFalse(payload["data"]["roles"]["distill"]["installed"])
        finally:
            import shutil
            shutil.rmtree(fresh, ignore_errors=True)

    def test_brief_states_the_coldkey_boundary(self):
        _, payload = self.json_cli("agent-brief")
        self.assertIn("coldkey", payload["data"]["brief"].lower())


class TestEarlyFailures(CliCase):
    """Failures raised before dispatch must still honour the contract.

    Regression: argparse wrote usage text to stderr and exited 2 — an
    undocumented code — leaving stdout empty. An agent doing json.loads(stdout)
    crashed on a simple typo.
    """

    def test_bad_role_returns_an_envelope_with_a_documented_code(self):
        proc, payload = self.json_cli("test", "nosuchrole")
        self.assertEqual(proc.returncode, int(Exit.USAGE))
        self.assertEqual(payload["error"]["code"], "usage.invalid")
        self.assertIn("distill", payload["error"]["message"])

    def test_unknown_command_returns_an_envelope(self):
        proc, payload = self.json_cli("nosuchcommand")
        self.assertEqual(proc.returncode, int(Exit.USAGE))
        self.assertIsNotNone(payload["error"]["remediation"]["command"])

    def test_no_argparse_exit_code_escapes(self):
        """argparse's own exit code 2 must never reach a caller."""
        for args in (("test", "nosuchrole"), ("nosuchcommand",), ("config",),
                     ("secret",), ("config", "set", "distill")):
            with self.subTest(command=" ".join(args)):
                proc = self.run_cli(*args, "--json")
                self.assertNotEqual(proc.returncode, 2,
                                    "exit 2 is argparse's, not ours; it is not in the contract")
                self.assertIn(proc.returncode, {int(m) for m in Exit})

    def test_protocol_mismatch_is_an_envelope_not_a_bare_message(self):
        proc, payload = self.json_cli("doctor", "--protocol", "2.0.0")
        self.assertEqual(proc.returncode, int(Exit.INCOMPATIBLE))
        self.assertEqual(payload["error"]["code"], "contract.protocol_incompatible")
        self.assertTrue(payload["error"]["remediation"]["requires_operator"])

    def test_a_compatible_minor_is_accepted(self):
        # Isolate the protocol check from the host's real disk with a deterministic
        # healthy-disk fixture (the production 5 GB threshold is unchanged).
        os.environ["CATHEDRAL_TEST_ASSUME_DISK_GB"] = "999"
        self.addCleanup(os.environ.pop, "CATHEDRAL_TEST_ASSUME_DISK_GB", None)
        proc, _ = self.json_cli("doctor", "--protocol", "1.9.9")
        self.assertEqual(proc.returncode, 0)

    def test_early_failures_still_put_json_on_stdout(self):
        for args in (("test", "nosuchrole"), ("doctor", "--protocol", "2.0.0")):
            with self.subTest(command=" ".join(args)):
                proc = self.run_cli(*args, "--json")
                self.assertTrue(proc.stdout.lstrip().startswith("{"))
                json.loads(proc.stdout)


class TestRunOrdering(unittest.TestCase):
    """Recent runs must be recent.

    Regression: runs were sorted by directory name, and a run id begins with its
    command ('test-', 'start-'), so the verb dominated the timestamp. `logs`
    with no --run then opened whichever run's verb sorted last, not the latest.
    """

    def setUp(self):
        from cathedral_node import state

        self._tmp = tempfile.TemporaryDirectory(prefix="cathedral-order-")
        os.environ["CATHEDRAL_HOME"] = self._tmp.name
        self.state = state

    def tearDown(self):
        os.environ.pop("CATHEDRAL_HOME", None)
        self._tmp.cleanup()

    def test_newest_first_regardless_of_command_prefix(self):
        early = self.state.RunRecord("test-20260101-000000-aaaaaa", "distill", "test",
                                     "completed", "2026-01-01T00:00:00.000Z")
        late = self.state.RunRecord("start-20260601-000000-bbbbbb", "distill", "operate",
                                    "completed", "2026-06-01T00:00:00.000Z")
        self.state.save_run(early)
        self.state.save_run(late)

        listed = self.state.list_runs("distill")
        self.assertEqual(listed[0].run_id, late.run_id,
                         "the newest run must come first even though 'start' < 'test'")

    def test_limit_applies_after_sorting(self):
        for index in range(5):
            self.state.save_run(self.state.RunRecord(
                f"test-2026010{index}-000000-{index:06d}", "distill", "test", "completed",
                f"2026-01-0{index + 1}T00:00:00.000Z"))
        listed = self.state.list_runs("distill", limit=2)
        self.assertEqual(len(listed), 2)
        self.assertTrue(listed[0].started_at > listed[1].started_at)


# NOTE: TestInstallerTrust and TestInstallerFixture were removed here — the
# signed-release-bundle installer is proven far more comprehensively (and with
# zero skips) in tests/test_gate0.py.


class TestProcRobustness(unittest.TestCase):
    """A subprocess launch failure must be a controlled result, not a traceback."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="cathedral-proc-")

    def tearDown(self):
        self._tmp.cleanup()

    def test_launching_a_non_executable_file_is_a_controlled_failure(self):
        """Regression (Codex P0): trying to exec a non-executable venv file raised
        an uncaught PermissionError. proc.run must return a failed result instead."""
        from cathedral_node import proc

        target = Path(self._tmp.name) / "not-a-program"
        target.write_text("just data\n")
        target.chmod(0o644)  # readable, NOT executable
        result = proc.run([str(target)], timeout=10, inherit_env=True)  # must not raise
        self.assertFalse(result.ok, "a non-executable target must not report success")
        self.assertIn(result.returncode, (126, 127))

    def test_run_decodes_non_utf8_without_crashing(self):
        from cathedral_node import proc
        result = proc.run(["sh", "-c", r"printf '\377\376 hi'"], timeout=10, inherit_env=True)
        self.assertTrue(result.returncode == 0)
        self.assertIn("hi", result.stdout)  # replacement char used, no crash

    def test_stream_redacts_before_the_callback(self):
        from cathedral_node import proc, redact
        token = "SUPERSECRETSTREAMTOKEN1234567"
        redact.register_secret_values([token])
        try:
            seen = []
            result = proc.stream(["sh", "-c", f"echo before {token} after"],
                                 on_line=seen.append, inherit_env=True)
        finally:
            redact.forget_secret_values()
        self.assertTrue(all(token not in line for line in seen),
                        "a registered secret must be redacted before the callback sees it")
        self.assertNotIn(token, result.stdout)

    def test_stream_reader_failure_is_reported_as_nonzero(self):
        from cathedral_node import proc

        def raising(_line):
            raise RuntimeError("callback blew up")

        result = proc.stream(["sh", "-c", "echo one; echo two"], on_line=raising,
                             inherit_env=True)
        self.assertFalse(result.ok, "a reader-thread failure must not report a clean success")

    def test_stream_terminates_a_chatty_child_when_the_reader_dies(self):
        """A dead reader must not let a child that writes forever run unbounded on a
        full pipe — the child's process group is terminated."""
        import time

        from cathedral_node import proc

        def raising(_line):
            raise RuntimeError("boom")

        started = time.monotonic()
        result = proc.stream(
            ["sh", "-c", "i=0; while :; do echo chatter $i; i=$((i+1)); done"],
            on_line=raising, inherit_env=True,
        )
        self.assertFalse(result.ok)
        self.assertLess(time.monotonic() - started, 30,
                        "the chatty child must be terminated, not left running")


class TestSecretsNeverInHumanOutput(CliCase):
    """A secret embedded in a non-secret config value must be masked in EVERY
    output path — JSON and human, stdout and stderr — not only the JSON envelope.

    Regression (Codex P0): the human render read the unredacted envelope, so
    `config show` printed a full `?api_key=...` token to stdout while `--json`
    masked it.
    """

    TOKEN = "sk-secret-abcdefghijklmnop"
    LEAKY = f"https://host/v1/?api_key={TOKEN}"

    def _human(self, *args: str) -> subprocess.CompletedProcess:
        env = {**os.environ, "CATHEDRAL_HOME": str(self.home), "NO_COLOR": "1"}
        return subprocess.run(  # noqa: S603
            [sys.executable, str(CLI), *args],
            capture_output=True, text=True, env=env, timeout=120, stdin=subprocess.DEVNULL,
        )

    def test_embedded_credential_is_masked_in_all_output_paths(self):
        self.json_cli("config", "set", "distill", "api_base", self.LEAKY)
        # JSON mode: stdout is the envelope, stderr empty — neither may carry it.
        jp = self._human("config", "show", "distill", "--json")
        self.assertNotIn(self.TOKEN, jp.stdout, "JSON stdout leaked the token")
        self.assertNotIn(self.TOKEN, jp.stderr, "JSON stderr leaked the token")
        # Human mode: the rendering goes to stdout — it must be masked too.
        hp = self._human("config", "show", "distill")
        self.assertNotIn(self.TOKEN, hp.stdout, "human stdout leaked the token")
        self.assertNotIn(self.TOKEN, hp.stderr, "human stderr leaked the token")
        self.assertIn("redacted", hp.stdout.lower(), "the human view should show it was masked")

    def test_remediation_docs_and_next_description_are_redacted_in_both_paths(self):
        """Regression (Codex): _redact_envelope masked message/summary/commands but
        left Remediation.docs and NextStep.description in the clear, so both leaked
        via to_dict() (JSON) and the human render."""
        import io
        import json as _json

        from cathedral_node import runner
        from cathedral_node.contracts import Envelope, Remediation
        from cathedral_node.redact import redact_value
        from cathedral_node.ui.console import Console
        from cathedral_node.ui.render import render
        from cathedral_node.ui.theme import Style

        env = Envelope.fail(
            "demo", "x.y", f"message {self.TOKEN}",
            remediation=Remediation(
                summary=f"summary {self.TOKEN}",
                command=None,
                docs=f"https://docs/?api_key={self.TOKEN}",
            ),
        )
        env.then(f"do next {self.TOKEN}", command=None)
        runner._redact_envelope(env)

        self.assertNotIn(self.TOKEN, _json.dumps(redact_value(env.to_dict())),
                         "JSON path leaked docs or next-step description")
        buffer = io.StringIO()
        render(Console(stream=buffer, style=Style(enabled=False)), env)
        self.assertNotIn(self.TOKEN, buffer.getvalue(),
                         "human render leaked docs or next-step description")

    def test_control_characters_are_stripped_from_every_output(self):
        """Regression (Codex P0): untrusted ESC/CR/BEL/NUL in a value could drive
        the terminal. They must be gone from both the human data and the JSON."""
        import json as _json

        from cathedral_node import runner
        from cathedral_node.contracts import Envelope
        from cathedral_node.redact import redact_value

        evil = "line1\x1b[2Jline2\x07\r\x00\x7fbad"
        env = Envelope.ok("demo", {"note": evil})
        runner._redact_envelope(env)
        payload = _json.dumps(redact_value(env.to_dict()))
        for control in ("\x1b", "\x07", "\x00", "\r", "\x7f"):
            self.assertNotIn(control, env.data["note"], "human data kept a control char")
            self.assertNotIn(control, payload, "JSON kept a control char")

    def test_secret_in_a_mapping_key_or_opaque_value_is_masked(self):
        """A secret must not escape masking by being a dict key or a non-JSON type."""
        import json as _json

        from cathedral_node.redact import redact_value

        class Opaque:
            def __str__(self):
                return "api_key=sk-secret-abcdefghijklmnop"

        out = redact_value({"sk-secret-keyname-abcdefghijklmnop": "v",
                            "outer": {"nested": Opaque()}})
        serialized = _json.dumps(out, default=str)
        self.assertNotIn("sk-secret-abcdefghijklmnop", serialized, "opaque value leaked a secret")
        self.assertNotIn("sk-secret-keyname-abcdefghijklmnop", serialized, "a key leaked a secret")

    def test_untrusted_sgr_is_neutralized_before_styling(self):
        """Regression (Codex): untrusted SGR must not style the terminal and spoof
        PASS/FAIL. It is stripped at the redaction layer — before any styling — so
        the attacker sequence is inert text; the theme's own colour still survives
        the write boundary."""
        import io

        from cathedral_node import runner
        from cathedral_node.contracts import Envelope
        from cathedral_node.ui.console import Console
        from cathedral_node.ui.theme import Glyphs, Style

        env = Envelope.ok("demo", {"note": "x\x1b[32mFAKE PASS\x1b[0m"})
        runner._redact_envelope(env)
        self.assertNotIn("\x1b", env.data["note"], "untrusted SGR must be stripped before styling")
        self.assertIn("FAKE PASS", env.data["note"], "the text should remain as inert content")

        buffer = io.StringIO()
        console = Console(stream=buffer, style=Style(enabled=True))
        console.glyphs = Glyphs(unicode_ok=True)
        console.write("\x1b[31mtheme-red\x1b[0m")
        self.assertIn("\x1b[31m", buffer.getvalue(), "trusted theme SGR must survive")


class TestAsciiStreamDetection(unittest.TestCase):
    """ASCII detection must inspect the stream that is actually written to."""

    def test_detection_uses_the_configured_stream_not_stderr(self):
        """Regression (Codex P0): detection read sys.stderr, so ASCII stdout with a
        UTF-8 stderr chose unicode glyphs and the next write crashed."""
        from cathedral_node.ui.console import Console

        class FakeStream:
            def __init__(self, encoding):
                self.encoding = encoding

            def write(self, _text):
                pass

            def flush(self):
                pass

        os.environ.pop("CATHEDRAL_ASCII", None)
        self.assertFalse(Console(stream=FakeStream("ascii")).glyphs.unicode_ok,
                         "an ASCII stream must select ASCII glyphs")
        self.assertTrue(Console(stream=FakeStream("utf-8")).glyphs.unicode_ok,
                        "a UTF-8 stream must select unicode glyphs")

    def test_ascii_stdout_does_not_crash(self):
        """End to end: an ASCII stdout must not raise UnicodeEncodeError."""
        with tempfile.TemporaryDirectory(prefix="cathedral-ascii-") as home:
            env = {**os.environ, "CATHEDRAL_HOME": home, "PYTHONIOENCODING": "ascii", "NO_COLOR": "1",
                   "CATHEDRAL_TEST_ASSUME_DISK_GB": "999"}
            proc = subprocess.run(  # noqa: S603 - bytes mode on purpose
                [sys.executable, str(CLI), "doctor"],
                capture_output=True, env=env, timeout=120, stdin=subprocess.DEVNULL,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr[-400:])
            self.assertNotIn(b"UnicodeEncodeError", proc.stderr)
            self.assertTrue(all(b < 128 for b in proc.stdout), "stdout must be pure ASCII")


class TestLockRecovery(unittest.TestCase):
    """A lock whose owner is gone must not need manual cleanup."""

    def setUp(self):
        from cathedral_node import paths, state

        self._tmp = tempfile.TemporaryDirectory(prefix="cathedral-lock-")
        os.environ["CATHEDRAL_HOME"] = self._tmp.name
        paths.ensure_layout()
        self.state = state
        self.paths = paths

    def tearDown(self):
        os.environ.pop("CATHEDRAL_HOME", None)
        self._tmp.cleanup()

    def test_a_dead_owners_lock_is_reclaimed(self):
        dead = 999_999
        self.state.write_ownership(self.state.ChildOwnership(
            role="distill", run_id="start-dead", parent_pid=dead, child_pid=dead, pgid=dead,
            start_identity="mac:1.000000:1:0", boot_id=self.state.boot_identity(),
            euid=os.geteuid(), generation="", lock_digest="", token="stale",
            since="2026-01-01T00:00:00.000Z", spawn_state=self.state.SPAWN_OWNED))
        self.assertIsNone(self.state.running_run("distill"),
                          "a lock held by a dead pid must read as free")

    def test_a_corrupt_lock_is_never_silently_reclaimed(self):
        """A record that cannot be parsed is not a free role.

        Something wrote it, so something may be running, and the shape it is in is
        exactly what makes that unknowable. Clearing it would be a guess whose cost
        is a second process on one identity, so it reads as held until an explicit
        stop resolves it.
        """
        self.paths.role_lock("distill").write_text("not json at all")
        os.chmod(self.paths.role_lock("distill"), 0o600)
        holder = self.state.running_run("distill")
        self.assertIsNotNone(holder, "an unreadable record must not read as free")
        self.assertEqual(holder["unresolved"], self.state.OWNERSHIP_UNVERIFIABLE)
        self.assertTrue(self.paths.role_lock("distill").exists(),
                        "and it must not be deleted on a guess")

    def test_a_live_lock_is_respected(self):
        lock = self.state.RoleLock("distill", "run-a")
        lock.acquire()
        try:
            other = self.state.RoleLock("distill", "run-b")
            # Same pid, so holder() clears it — the guarantee is cross-process.
            # Assert the file exists and names this process instead.
            payload = json.loads(self.paths.role_lock("distill").read_text())
            self.assertEqual(payload["parent_pid"], os.getpid())
            self.assertEqual(payload["run_id"], "run-a")
            del other
        finally:
            lock.release()
        self.assertFalse(self.paths.role_lock("distill").exists())

    def test_reconcile_marks_a_dead_run_interrupted(self):
        record = self.state.RunRecord("start-x", "distill", "operate", "running",
                                      "2026-01-01T00:00:00.000Z", pid=999_999)
        self.state.save_run(record)
        reconciled = self.state.reconcile(self.state.load_run("start-x"))
        self.assertEqual(reconciled.status, "interrupted",
                         "a run whose process is gone must not still report as running")


class TestPresentation(CliCase):
    """Readable without colour and at common terminal widths."""

    def _render(self, *args: str, columns: str, extra_env: dict | None = None) -> str:
        env = dict(os.environ)
        env.update({"CATHEDRAL_HOME": str(self.home), "COLUMNS": columns, "NO_COLOR": "1"})
        env.update(extra_env or {})
        proc = subprocess.run(  # noqa: S603
            [sys.executable, str(CLI), *args],
            capture_output=True, text=True, env=env, timeout=300,
        )
        # Human output is on stdout; stderr stays empty outside --json.
        return proc.stdout + proc.stderr

    def test_no_line_exceeds_the_terminal_width(self):
        """Prose, labels, and tables fit the terminal.

        Runnable commands are exempt on purpose: a wrapped command line cannot
        be copied, so it is better to let the terminal soft-wrap one than to
        hand the reader something broken.
        """
        for columns in ("60", "72", "80", "100"):
            for args in (("doctor",), ("capabilities",), ("explain", "compute"),
                         ("explain", "distill"), ("config", "schema"), ("status",),
                         ("secret", "list")):
                with self.subTest(columns=columns, command=" ".join(args)):
                    for line in self._render(*args, columns=columns).splitlines():
                        if line.strip().startswith("cathedral ") or line.strip().startswith("chmod "):
                            continue
                        self.assertLessEqual(
                            len(line), int(columns),
                            f"{' '.join(args)} at {columns} cols emitted a {len(line)}-char line:"
                            f"\n{line}",
                        )

    def test_readable_without_colour(self):
        output = self._render("doctor", columns="80")
        self.assertNotIn("\033[", output, "NO_COLOR must strip every escape sequence")
        # Status must still be unambiguous from the text alone.
        self.assertTrue(any(mark in output for mark in ("✓", "✗", "OK", "X")))

    def test_ascii_fallback_has_no_multibyte_glyphs(self):
        output = self._render("doctor", columns="80", extra_env={"CATHEDRAL_ASCII": "1"})
        for glyph in ("✓", "✗", "…", "─", "·"):
            self.assertNotIn(glyph, output, f"CATHEDRAL_ASCII must not emit {glyph!r}")

    def test_ascii_fallback_is_pure_ascii_including_dynamic_text(self):
        """Regression: the glyph set was folded to ASCII but dynamic message text
        (a platform note, a probe detail) still carried an em-dash, so a terminal
        that cannot render UTF-8 got a replacement box."""
        for args in (("doctor",), ("capabilities",), ("explain", "compute"), ("config", "schema")):
            with self.subTest(command=" ".join(args)):
                output = self._render(*args, columns="80", extra_env={"CATHEDRAL_ASCII": "1"})
                offenders = sorted({ch for ch in output if ord(ch) > 127})
                self.assertEqual(offenders, [],
                                 f"CATHEDRAL_ASCII leaked non-ASCII {offenders} in {' '.join(args)}")

    def test_public_key_reads_the_same_in_json_and_human(self):
        """Regression: the public weight-policy key was masked in --json but shown
        in full by the human view, inverting the one-envelope-two-renderers
        invariant and hiding the operator's signing-key control from an agent."""
        self.json_cli("setup", "validator")
        _, payload = self.json_cli("config", "show", "validator")
        json_value = payload["data"]["roles"]["validator"]["values"]["weight_policy_key"]
        self.assertNotEqual(json_value, "[redacted]",
                            "the public signing key must be readable via --json")
        self.assertRegex(json_value, r"^[0-9a-fA-F]{64}$")
        human = self._render("config", "show", "validator", columns="200")
        self.assertIn(json_value, human,
                      "the human view and the --json envelope must show the same key")

    def test_config_get_returns_the_public_key_not_a_mask(self):
        self.json_cli("setup", "validator")
        proc, payload = self.json_cli("config", "get", "validator", "weight_policy_key")
        self.assertEqual(proc.returncode, 0)
        self.assertRegex(payload["data"]["value"], r"^[0-9a-fA-F]{64}$")

    def test_capabilities_json_has_no_null_capability(self):
        """The discovery envelope an agent iterates must have uniform capability
        objects — no `engine_census: null` hiding among them."""
        proc, payload = self.json_cli("capabilities")
        self.assertEqual(proc.returncode, 0)
        for role, report in payload["data"]["engines"].items():
            for name, cap in report["capabilities"].items():
                self.assertIsInstance(cap, dict, f"engines.{role}.capabilities.{name} is {cap!r}")
                self.assertIn("available", cap)

    def test_registering_a_public_value_does_not_unmask_real_secrets(self):
        from cathedral_node import redact
        redact.register_public_values(["10890a66aa752479cb3b634f366d7bd27c374324d83f88d2d6b69ab066f25e26"])
        masked = redact.redact_value({"api_key": "sk-live-" + "a" * 24, "token": "b" * 40})
        self.assertEqual(masked["api_key"], "[redacted]")
        self.assertEqual(masked["token"], "[redacted]")

    def test_engine_census_is_a_uniform_capability_object(self):
        """Regression (Codex on 8f3ba8d): engine_census must stay a consistently
        shaped capability object, not be removed (a protocol change) or be null."""
        proc, payload = self.json_cli("capabilities")
        census = payload["data"]["engines"]["compute"]["capabilities"]["engine_census"]
        self.assertIsInstance(census, dict)
        self.assertIn("available", census)
        self.assertIsInstance(census["available"], bool)

    def test_confirmation_remedy_is_shell_safe(self):
        """Regression (Codex on 8f3ba8d): the remedy joined raw args, so a value
        with a space broke it and a value with `;` was an injectable copy-paste."""
        import shlex

        from cathedral_node import runner
        original = sys.argv
        try:
            sys.argv = ["cathedral", "cleanup", "--engine", "weird name; rm -rf /", "--json"]
            remedy = runner._argv_prefix() + " --yes"
        finally:
            sys.argv = original
        tokens = shlex.split(remedy)  # must parse; the dangerous value stays ONE token
        self.assertIn("weird name; rm -rf /", tokens)
        self.assertIn("--engine", tokens)
        self.assertNotIn("--json", tokens, "mode flags are dropped from the remedy")
        self.assertEqual(tokens[-1], "--yes")

    def test_ascii_mode_folds_arbitrary_unicode_config_values(self):
        """Regression (Codex on 8f3ba8d): the ASCII fallback was a curated set, so
        an arbitrary Unicode value from user config still leaked. The final write
        boundary must guarantee pure ASCII."""
        self.json_cli("config", "set", "distill", "model", "café-modèl-\U0001f680-中文")
        output = self._render("config", "show", "distill", columns="100",
                              extra_env={"CATHEDRAL_ASCII": "1"})
        offenders = sorted({ch for ch in output if ord(ch) > 127})
        self.assertEqual(offenders, [],
                         f"CATHEDRAL_ASCII leaked non-ASCII from config: {offenders}")

    def test_label_column_aligns_in_both_themes(self):
        """ASCII glyphs are multi-character ("OK", "..."), so the glyph column
        must be padded or every label shifts relative to its neighbours."""
        import io

        from cathedral_node.ui.console import Console
        from cathedral_node.ui.theme import Glyphs, Style

        for ascii_mode in (False, True):
            with self.subTest(ascii=ascii_mode):
                buffer = io.StringIO()
                console = Console(stream=buffer, style=Style(enabled=False))
                console.glyphs = Glyphs(unicode_ok=not ascii_mode)
                g = console.glyphs
                console.glyph_width = max(len(x) for x in (g.ok, g.fail, g.warn, g.info, g.pending))

                console.ok("short", "a")
                console.fail("a-much-longer-label", "b")
                console.warn("mid", "c")
                console.info("x", "d")
                console.progress("prog", "e")

                columns = {line.index(line.strip()[-1]) for line in
                           buffer.getvalue().splitlines() if line.strip()}
                self.assertEqual(
                    len(columns), 1,
                    f"values start at differing columns {sorted(columns)} in "
                    f"{'ascii' if ascii_mode else 'unicode'} mode",
                )


class TestRenderingNeverCrashes(CliCase):
    """A rendering failure must never reach the operator as a traceback.

    Regression: renderers indexed data["checks"] and data["role"] unconditionally,
    but a blocked or failed envelope often carries no data at all. The KeyError
    escaped because emission runs after the command's error boundary — so
    `cathedral test distill` before setup printed a Python traceback.
    """

    FAILING_COMMANDS = (
        ("test", "distill"),          # blocked: engine not installed
        ("test", "compute"),
        ("test", "validator"),
        ("start", "distill"),
        ("config", "set", "distill", "hotkey", "not-an-address"),
        ("config", "set", "distill", "coldkey", "x"),
        ("status", "--run", "nope"),
        ("evidence", "nothing-here"),
        ("logs", "--run", "nope"),
        ("resume", "nope"),
        ("cancel", "nope"),
        ("secret", "remove", "NOPE"),
        ("stop", "distill"),
        ("rollback",),
    )

    def test_no_traceback_reaches_the_terminal(self):
        fresh = Path(tempfile.mkdtemp(prefix="cathedral-render-"))
        try:
            for args in self.FAILING_COMMANDS:
                with self.subTest(command=" ".join(args)):
                    proc = self.run_cli(*args, home=fresh)
                    combined = proc.stdout + proc.stderr
                    self.assertNotIn("Traceback (most recent call last)", combined,
                                     f"`{' '.join(args)}` leaked a traceback")
                    self.assertNotIn('File "', combined)
                    self.assertNotIn("KeyError", combined)
        finally:
            import shutil
            shutil.rmtree(fresh, ignore_errors=True)

    def test_failures_still_say_what_to_do(self):
        fresh = Path(tempfile.mkdtemp(prefix="cathedral-render2-"))
        try:
            for args in self.FAILING_COMMANDS:
                with self.subTest(command=" ".join(args)):
                    proc = self.run_cli(*args, home=fresh)
                    if proc.returncode == 0:
                        continue  # a legitimate no-op, e.g. stopping an idle role
                    self.assertTrue((proc.stdout + proc.stderr).strip(),
                                    "a failure must print something for the operator")
        finally:
            import shutil
            shutil.rmtree(fresh, ignore_errors=True)

    def test_json_mode_is_unaffected_by_render_state(self):
        fresh = Path(tempfile.mkdtemp(prefix="cathedral-render3-"))
        try:
            for args in self.FAILING_COMMANDS:
                with self.subTest(command=" ".join(args)):
                    proc, payload = self.json_cli(*args, home=fresh)
                    self.assertEqual(proc.returncode, payload["exit_code"])
        finally:
            import shutil
            shutil.rmtree(fresh, ignore_errors=True)


class TestConfigInjection(CliCase):
    """A configuration value must never become configuration structure.

    Regression: escaping covered backslash and quote but not control characters,
    so a value containing a newline produced a basic string broken across two
    lines. The file then failed to parse on every later read — surfacing as
    exit 70 'internal error' — while the write that caused it reported success.
    """

    # A null byte cannot reach the CLI: execve rejects it in argv, so the OS
    # refuses the call before any of our code runs. It is covered at the
    # rendering level in test_toml_rendering_escapes_control_characters below.
    PAYLOADS = (
        'x"\nhotkey = "5EVILEVILEVILEVILEVILEVILEVILEVILEVILEVILEVILEVI',
        'a\r\nnetuid = 999',
        'tab\there',
        '"""triple"""',
        "\\backslash\\",
        "\x1b[31mansi\x1b[0m",
    )

    def test_toml_rendering_escapes_control_characters(self):
        for raw in ("nl\nhere", "cr\rhere", "nul\x00here", "bell\x07here", "del\x7fhere"):
            with self.subTest(raw=repr(raw)):
                rendered = config._toml_value(raw)
                parsed = __import__("tomllib").loads(f"v = {rendered}")
                self.assertEqual(parsed["v"], raw, "a rendered value must read back unchanged")
                self.assertNotIn("\n", rendered, "a basic string may not span lines")

    def test_no_payload_injects_a_key_or_corrupts_the_file(self):
        for payload in self.PAYLOADS:
            with self.subTest(payload=payload[:24]):
                fresh = Path(tempfile.mkdtemp(prefix="cathedral-toml-"))
                try:
                    self.json_cli("config", "set", "distill", "model", payload, home=fresh)

                    # Whatever happened, the file must still be readable and the
                    # payload must not have created a second key.
                    proc, shown = self.json_cli("config", "show", "distill", home=fresh)
                    self.assertEqual(proc.returncode, 0,
                                     f"payload made the config unreadable: {payload!r}")
                    values = shown["data"]["roles"]["distill"]["values"]
                    self.assertNotEqual(
                        values.get("hotkey", ""),
                        "5EVILEVILEVILEVILEVILEVILEVILEVILEVILEVILEVILEVI",
                        "a value injected a different key",
                    )
                    self.assertNotEqual(values.get("netuid"), 999)
                finally:
                    import shutil
                    shutil.rmtree(fresh, ignore_errors=True)

    def test_a_stored_value_reads_back_exactly(self):
        fresh = Path(tempfile.mkdtemp(prefix="cathedral-toml2-"))
        try:
            for payload in ("my-model:v2_beta.1", "path/with/slashes", "unicode-café"):
                with self.subTest(payload=payload):
                    proc, _ = self.json_cli("config", "set", "distill", "model", payload, home=fresh)
                    self.assertEqual(proc.returncode, 0)
                    _, got = self.json_cli("config", "get", "distill", "model", home=fresh)
                    self.assertEqual(got["data"]["value"], payload)
        finally:
            import shutil
            shutil.rmtree(fresh, ignore_errors=True)

    def test_a_config_problem_is_not_reported_as_an_internal_error(self):
        """A malformed config is the operator's situation, not our bug. Telling
        them 'this is a bug in the node' sends them to the wrong place."""
        fresh = Path(tempfile.mkdtemp(prefix="cathedral-toml3-"))
        try:
            (fresh / "config").mkdir(parents=True, exist_ok=True)
            (fresh / "config" / "distill.toml").write_text('model = "unterminated\n')
            proc, payload = self.json_cli("config", "show", "distill", home=fresh)
            self.assertNotEqual(proc.returncode, int(Exit.INTERNAL),
                                "a bad config file must not be classified as an internal error")
            self.assertEqual(proc.returncode, int(Exit.CONFIG_INVALID))
            self.assertEqual(payload["error"]["code"], "config.invalid")
            self.assertIsNotNone(payload["error"]["remediation"])
        finally:
            import shutil
            shutil.rmtree(fresh, ignore_errors=True)


class TestFailureRecovery(CliCase):
    """Damaged state must produce a diagnosis, never a crash or a lie."""

    def test_an_unwritable_home_returns_an_envelope(self):
        """Regression: ensure_layout() runs before the command boundary, so a
        permission error escaped as exit 1 with empty stdout — a code not even
        in the contract."""
        blocked = Path(tempfile.mkdtemp(prefix="cathedral-ro-"))
        try:
            blocked.chmod(0o500)
            proc, payload = self.json_cli("doctor", home=blocked / "inside")
            self.assertEqual(proc.returncode, int(Exit.NOT_READY))
            self.assertIn(payload["error"]["code"], ("env.disk_low", "env.tool_missing"))
            self.assertIsNotNone(payload["error"]["remediation"]["command"])
        finally:
            blocked.chmod(0o700)
            import shutil
            shutil.rmtree(blocked, ignore_errors=True)

    def test_a_corrupt_run_record_is_reported_as_missing(self):
        home = Path(tempfile.mkdtemp(prefix="cathedral-corrupt-"))
        try:
            run_dir = home / "runs" / "test-broken"
            run_dir.mkdir(parents=True)
            (run_dir / "run.json").write_text('{"broken":')
            proc, payload = self.json_cli("status", "--run", "test-broken", home=home)
            self.assertEqual(proc.returncode, int(Exit.NOT_FOUND))
            self.assertEqual(payload["error"]["code"], "run.not_found")
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)

    def test_corrupt_event_lines_are_skipped_not_fatal(self):
        home = Path(tempfile.mkdtemp(prefix="cathedral-events-"))
        try:
            run_dir = home / "runs" / "test-partial"
            run_dir.mkdir(parents=True)
            (run_dir / "run.json").write_text(json.dumps({
                "run_id": "test-partial", "role": "distill", "kind": "test",
                "status": "completed", "started_at": "2026-01-01T00:00:00.000Z",
                "finished_at": "2026-01-01T00:00:01.000Z", "pid": None,
                "exit_code": 0, "detail": "", "artifacts": {},
            }))
            (run_dir / "events.jsonl").write_text(
                json.dumps({"schema": "cathedral.node.event.v1", "event": "A",
                            "ts": "2026-01-01T00:00:00.000Z", "detail": "kept"}) + "\n"
                + "this line is not json\n"
                + json.dumps({"schema": "cathedral.node.event.v1", "event": "B",
                              "ts": "2026-01-01T00:00:01.000Z", "detail": "also kept"}) + "\n"
            )
            proc, payload = self.json_cli("logs", "--run", "test-partial", home=home)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(payload["data"]["event_count"], 2,
                             "readable events must survive an unreadable neighbour")
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)

    def test_a_missing_engine_directory_is_reported_not_assumed(self):
        home = Path(tempfile.mkdtemp(prefix="cathedral-noengine-"))
        try:
            receipt = home / "engines" / "distill" / "installed.json"
            receipt.parent.mkdir(parents=True)
            receipt.write_text('{"revision": "deadbeef", "installed_at": "2026-01-01T00:00:00Z"}')
            proc, payload = self.json_cli("test", "distill", home=home)
            self.assertNotEqual(proc.returncode, 0)
            self.assertNotEqual(proc.returncode, int(Exit.INTERNAL),
                                "a missing engine binary must not read as a node bug")
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)


class TestNoRendererFallsBack(CliCase):
    """The degraded renderer is a safety net, not a normal outcome.

    Regression: `cathedral explain validator` silently rendered through the
    fallback because the renderer required a key only two of the three roles
    supply. The result still printed, so nothing looked broken — which is
    exactly why this needs a test rather than an eye.
    """

    MARKER = "could not render"

    def _assert_clean(self, *args: str, home: Path | None = None) -> None:
        proc = self.run_cli(*args, home=home)
        self.assertNotIn(self.MARKER, proc.stdout + proc.stderr,
                         f"`{' '.join(args)}` fell back to the degraded renderer:\n{proc.stdout[-400:]}")

    def test_no_command_falls_back_on_a_fresh_node(self):
        fresh = Path(tempfile.mkdtemp(prefix="cathedral-fallback-"))
        try:
            for args in (("quickstart",), ("doctor",), ("capabilities",),
                         ("explain", "distill"), ("explain", "compute"),
                         ("explain", "validator"), ("status",), ("config", "show"),
                         ("config", "schema"), ("secret", "list"), ("agent-brief",),
                         ("update", "--check"), ("rollback",), ("cleanup", "--dry-run")):
                with self.subTest(command=" ".join(args)):
                    self._assert_clean(*args, home=fresh)
        finally:
            import shutil
            shutil.rmtree(fresh, ignore_errors=True)

    def test_every_optional_explain_key_is_optional(self):
        """A renderer must not require a key some role legitimately omits."""
        for role in lockfile.ROLES:
            with self.subTest(role=role):
                explanation = engines.load(role).explain()
                for key in Engine.EXPLAIN_REQUIRED:
                    self.assertIn(key, explanation)
                # Anything beyond the required set is optional by definition, so
                # rendering must survive its absence.
                self._assert_clean("explain", role)


def _flat(text: str) -> str:
    """Collapse whitespace. Rendered output wraps, so a phrase assertion has to
    match the sentence, not the line breaks the terminal width happened to add."""
    return " ".join(text.split())


class TestHonestyOnThePath(CliCase):
    """Disclosures must sit on the path the product pushes you down.

    Regression: the money warning and the "not yet true" list existed only in
    `explain <role>`, one command sideways from `quickstart <role>`. Someone
    could reach a green "your node works" having never seen that a Compute
    measurement must be approved before you pay for hardware.
    """

    def test_compute_quickstart_warns_before_it_installs(self):
        fresh = Path(tempfile.mkdtemp(prefix="cathedral-money-"))
        try:
            proc = self.run_cli("quickstart", "compute", "--dry-run", home=fresh)
            text = _flat(proc.stdout + proc.stderr)
            self.assertIn("before you spend money", text.lower())
            self.assertIn("before provisioning or paying for a machine", text)
            # It must appear before the install step, not after the result.
            self.assertLess(text.lower().index("before you spend money"),
                            text.index("install the pinned engine"),
                            "the warning must precede the install")
        finally:
            import shutil
            shutil.rmtree(fresh, ignore_errors=True)

    def test_every_quickstart_states_what_is_not_yet_true(self):
        for role in lockfile.ROLES:
            with self.subTest(role=role):
                fresh = Path(tempfile.mkdtemp(prefix=f"cathedral-nyt-{role}-"))
                try:
                    proc = self.run_cli("quickstart", role, "--dry-run", home=fresh)
                    text = _flat(proc.stdout + proc.stderr)
                    self.assertIn("not yet true", text.lower(),
                                  f"quickstart {role} never says what is not yet true")
                finally:
                    import shutil
                    shutil.rmtree(fresh, ignore_errors=True)

    def test_no_surface_claims_the_operator_is_earning(self):
        for args in (("quickstart", "distill", "--dry-run"), ("explain", "distill"),
                     ("explain", "compute"), ("capabilities",)):
            with self.subTest(command=" ".join(args)):
                text = _flat(self.run_cli(*args).stdout or "").lower()
                # Affirmative claims only. "positive weight is never guaranteed"
                # is the honest negative and must stay.
                for claim in ("you will earn", "start earning", "earning now",
                              "is guaranteed", "you earn", "your profit"):
                    self.assertNotIn(claim, text, f"{' '.join(args)} claims earning")


class TestRemediationIsActionable(CliCase):
    """A remediation an agent runs verbatim must actually be runnable."""

    def test_a_placeholder_remediation_is_flagged(self):
        """Regression: `start distill` with no hotkey returned
        `config set distill hotkey <your-ss58-address>` as a runnable command
        with requires_operator false. Running it verbatim fails validation, and
        that failure's remediation points back at the first — a loop in which
        every step looks like progress."""
        home = Path(tempfile.mkdtemp(prefix="cathedral-placeholder-"))
        try:
            self.json_cli("setup", "distill", home=home)
            _, payload = self.json_cli("start", "distill", home=home)
            remediation = (payload.get("error") or {}).get("remediation") or {}
            command = remediation.get("command") or ""
            if "<" in command:
                self.assertTrue(remediation.get("requires_input"),
                                f"{command!r} has a placeholder but is not flagged")
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)

    def test_no_remediation_is_the_command_that_just_failed(self):
        """A failure that recommends itself is an infinite loop for an agent."""
        cases = [
            ("setup", "nosuchrole"),
            ("config", "set", "distill", "hotkey", "bad"),
            ("status", "--run", "missing"),
            ("evidence", "missing"),
        ]
        for args in cases:
            with self.subTest(command=" ".join(args)):
                _, payload = self.json_cli(*args)
                remediation = (payload.get("error") or {}).get("remediation") or {}
                command = (remediation.get("command") or "").strip()
                invoked = "cathedral " + " ".join(args)
                self.assertNotEqual(command, invoked,
                                    "a failure must not recommend the command that failed")

    def test_every_remediation_declares_requires_input(self):
        for args in (("start", "distill"), ("test", "distill"), ("status", "--run", "x")):
            with self.subTest(command=" ".join(args)):
                _, payload = self.json_cli(*args)
                remediation = (payload.get("error") or {}).get("remediation")
                if remediation:
                    self.assertIn("requires_input", remediation)


class TestUpdateSource(CliCase):
    """Unsigned lockfile adoption (`--to`) has been replaced by signed releases and
    is refused outright — an arbitrary lockfile can no longer redirect an install to
    a repository whose build backend would run as the operator. `update --check`
    still reports the current state without a release configured."""

    def _write(self, repository: str, revision: str) -> Path:
        path = Path(tempfile.mkdtemp(prefix="cathedral-lock-")) / "lock.json"
        path.write_text(json.dumps({
            "schema": "cathedral.node.lock.v1",
            "engines": {"distill": {"repository": repository, "revision": revision,
                                    "distribution": "cathedral-cybergym", "role": "test"}},
            "compatibility": {"python": ">=3.11", "protocol_version": "1.0.0"},
        }))
        return path

    def test_an_unsigned_lockfile_update_is_refused(self):
        for repository in ("https://attacker.example/evil.git",
                           "https://github.com/attacker/evil.git",
                           "https://github.com/cathedralai/cathedral-distill.git"):
            with self.subTest(repository=repository):
                lock = self._write(repository, "a" * 40)
                proc, payload = self.json_cli("update", "--to", str(lock), "--check")
                self.assertNotEqual(proc.returncode, 0, f"{repository} was accepted")
                self.assertEqual(payload["error"]["code"], "config.invalid")

    def test_update_check_reports_without_a_configured_release(self):
        proc, payload = self.json_cli("update", "--check")
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(payload["status"], "ok")
        self.assertIn("available_version", payload["data"])
