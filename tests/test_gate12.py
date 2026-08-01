"""Gate 1/2: real signed-engine tests. Not part of Gate 0."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
CLI = REPO / "cathedral"
sys.path.insert(0, str(REPO))

from cathedral_node import engines, lockfile  # noqa: E402
from cathedral_node.engines.base import Engine  # noqa: E402


def _flat(text: str) -> str:
    return " ".join(text.split())


class CliCase(unittest.TestCase):
    home: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = tempfile.TemporaryDirectory(prefix="cathedral-gate12-")
        cls.home = Path(cls._tmp.name)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmp.cleanup()

    def run_cli(self, *args: str, stdin: str | None = None, home: Path | None = None):
        env = dict(os.environ)
        env["CATHEDRAL_HOME"] = str(home or self.home)
        env["NO_COLOR"] = "1"
        env["COLUMNS"] = "88"
        return subprocess.run(
            [sys.executable, str(CLI), *args], capture_output=True, text=True,
            env=env, input=stdin, timeout=1800,
        )

    def json_cli(self, *args: str, stdin: str | None = None, home: Path | None = None):
        proc = self.run_cli(*args, "--json", stdin=stdin, home=home)
        return proc, json.loads(proc.stdout)

class TestIdentifierRoundTrip(CliCase):
    """An identifier returned in a result must be resolvable later.

    Regression: task ids appeared in the test envelope but never reached the
    event log, so `cathedral evidence <task-id>` — the whole reason for
    returning exact identifiers — reported the id as unknown.
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        proc = subprocess.run(  # noqa: S603
            [sys.executable, str(CLI), "setup", "distill", "--json"],
            capture_output=True, text=True, timeout=1800,
            env={**os.environ, "CATHEDRAL_HOME": str(cls.home), "NO_COLOR": "1"},
        )
        cls.engine_ready = proc.returncode == 0

    def test_every_returned_identifier_resolves(self):
        if not self.engine_ready:
            self.skipTest("the distill engine could not be installed in this environment")
        _, result = self.json_cli("test", "distill")
        self.assertEqual(result["status"], "ok", result.get("error"))

        identifiers = result["data"]["identifiers"]
        needles = list(identifiers["task_ids"]) + [identifiers["batch_nonce"]]
        needles += [c["poc_sha256"] for c in result["data"]["checks"]]

        for needle in needles:
            with self.subTest(identifier=needle):
                proc, found = self.json_cli("evidence", needle)
                self.assertEqual(proc.returncode, 0,
                                 f"{needle} was returned in a result but cannot be looked up")
                self.assertGreater(found["data"]["match_count"], 0)
                self.assertIn(result["run_id"], found["data"]["runs"])

    def test_duration_measures_the_command_not_the_envelope(self):
        """Regression: duration_ms was computed from envelope construction, so
        every command reported roughly zero and an agent could not use it."""
        if not self.engine_ready:
            self.skipTest("the distill engine could not be installed in this environment")
        _, result = self.json_cli("test", "distill")
        self.assertGreater(result["duration_ms"], 0,
                           "duration_ms must reflect real elapsed time")


class TestAllEnginesRunTheirLocalTest(CliCase):
    """The three local tests, run for real against the pinned engines.

    Slow (each installs an engine) but non-negotiable: a change that broke only
    the validator path shipped once because the fast tests never exercised it.
    Set CATHEDRAL_SKIP_SLOW=1 to skip when iterating.
    """

    EXPECTED = {
        "distill": {"min_checks": 4, "must_contain": "decoy refused"},
        "compute": {"min_checks": 4, "must_contain": "fails closed"},
        "validator": {"min_checks": 2, "must_contain": "nothing was written"},
    }

    def setUp(self):
        if os.environ.get("CATHEDRAL_SKIP_SLOW"):
            self.skipTest("CATHEDRAL_SKIP_SLOW is set")

    def test_each_engine_installs_and_verifies(self):
        for role, expectation in self.EXPECTED.items():
            with self.subTest(role=role):
                home = Path(tempfile.mkdtemp(prefix=f"cathedral-{role}-"))
                try:
                    proc, setup = self.json_cli("setup", role, home=home)
                    if proc.returncode != 0:
                        self.skipTest(f"{role} engine could not be installed here: "
                                      f"{(setup.get('error') or {}).get('message')}")

                    proc, result = self.json_cli("test", role, home=home)
                    self.assertEqual(proc.returncode, 0,
                                     f"{role} local test failed: {result.get('error')}")
                    self.assertTrue(result["data"]["passed"])
                    self.assertGreaterEqual(result["data"]["checks_total"],
                                            expectation["min_checks"])
                    self.assertEqual(result["data"]["checks_passed"],
                                     result["data"]["checks_total"])
                    self.assertIn(expectation["must_contain"],
                                  result["data"]["summary"].lower())
                    self.assertFalse(result["data"]["touches_chain"])
                    self.assertEqual(result["data"]["pays"], "nothing")

                    # Every event must be well-formed: an engine field must never
                    # shadow an envelope field.
                    events = (home / "runs" / result["run_id"] / "events.jsonl").read_text()
                    for line in events.splitlines():
                        if not line.strip():
                            continue
                        event = json.loads(line)
                        self.assertEqual(event["schema"], "cathedral.node.event.v1")
                        self.assertTrue(event["event"])
                        self.assertEqual(event["run_id"], result["run_id"])
                finally:
                    import shutil
                    shutil.rmtree(home, ignore_errors=True)


class TestRendererAfterARealRun(CliCase):
    pytestmark = pytest.mark.real_engine
    MARKER = "could not render"

    def _assert_clean(self, *args: str, home: Path | None = None) -> None:
        proc = self.run_cli(*args, home=home)
        self.assertNotIn(self.MARKER, proc.stdout + proc.stderr)

    def test_no_command_falls_back_after_a_real_run(self):
        home = Path(tempfile.mkdtemp(prefix="cathedral-fallback2-"))
        try:
            proc = self.run_cli("setup", "distill", "--json", home=home)
            if proc.returncode != 0:
                self.skipTest("the distill engine could not be installed here")
            self.run_cli("test", "distill", "--json", home=home)
            for args in (("status",), ("logs",), ("doctor",), ("capabilities",),
                         ("test", "distill"), ("start", "distill", "--dry-run"),
                         ("setup", "distill")):
                with self.subTest(command=" ".join(args)):
                    self._assert_clean(*args, home=home)
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)


class TestHonestClosingLine(CliCase):
    pytestmark = pytest.mark.real_engine

    def test_the_closing_line_states_what_was_verified(self):
        """Regression: it said "Your node works" after a Compute run that only
        exercised a policy gate on synthetic evidence, on a host whose own
        doctor reports TDX as undetermined."""
        home = Path(tempfile.mkdtemp(prefix="cathedral-claim-"))
        try:
            proc = self.run_cli("setup", "compute", "--json", home=home)
            if proc.returncode != 0:
                self.skipTest("the compute engine could not be installed here")
            proc = self.run_cli("quickstart", "compute", home=home)
            text = _flat(proc.stdout + proc.stderr)
            self.assertNotIn("Your node works", text)
            self.assertIn("measurement policy gate fails closed", text)
        finally:
            import shutil
            shutil.rmtree(home, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
