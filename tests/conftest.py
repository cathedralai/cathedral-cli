"""The Gate 0 acceptance harness.

Revision 5 fixes one exact command::

    python -m pytest -q tests/test_gate0.py tests/test_contract.py

Gate mode is decided in ``pytest_configure`` from the **invocation** — the target
list pytest was given and the options it was given — and never from the collected
items. That ordering is the whole point. Deriving it from ``items`` means deriving
it from a list a ``-k`` or ``--ignore`` has *already* pruned, so the run that most
needs to be refused is the one that looks smallest and tidiest. By the time items
exist it is too late to notice what is missing from them.

In gate mode this file enforces the acceptance contract itself:

1. every filtering option is refused outright — ``-k``, ``-m``, ``--ignore``,
   ``--ignore-glob``, ``--deselect``, ``--last-failed``, ``--stepwise``, ``-x`` /
   ``--maxfail``, and parallel distribution;
2. every environment variable that can mutate a pytest invocation from outside the
   command line is refused — ``PYTEST_ADDOPTS``, ``PYTHONWARNINGS``,
   ``PYTEST_PLUGINS``, ``PYTEST_DISABLE_PLUGIN_AUTOLOAD``;
3. the manifest is validated as a **document**, not just as a bag of node IDs:
   schema, controlling-specification identity and hashes, command string, file set,
   declared count, and the shape of every requirement;
4. the collected node IDs must equal the manifest exactly, checked before anything
   executes;
5. a skip, a deselection, a warning, or a collection error fails the session, with
   no environment variable that can turn it off.

The previous harness got two of these wrong in ways that produced a false PASS: the
runner passed ``-m "not real_engine"`` and deselected five required tests, and the
no-skip rule was opt-in through an environment variable the PRD command never set.
Both are now structural — the live-engine tests live in ``tests/test_gate12.py``
where this command does not reach them, and there is no opt-out.

Outside gate mode (a developer running one file or one test) nothing is enforced,
and the banner says so, so a partial run can never be mistaken for gate evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
MANIFEST_PATH = TESTS_DIR / "gate0_manifest.json"

# The exact PRD test set and the exact PRD command. Order is irrelevant; the set
# and the string are not.
GATE0_FILES = ("tests/test_gate0.py", "tests/test_contract.py")
GATE0_FILE_SET = frozenset(GATE0_FILES)
GATE0_COMMAND = "python -m pytest -q tests/test_gate0.py tests/test_contract.py"
# The Gate 1/2 live-engine job. A separate file and a separate command, so the Gate 0
# command cannot reach it — and so narrowing *it* cannot masquerade as a complete
# Gate 1/2 result either.
GATE12_FILES = ("tests/test_gate12.py",)
GATE12_FILE_SET = frozenset(GATE12_FILES)
# The exact live-engine job. Naming the file is not the same as running all of it,
# so the collected set must equal this exactly.
GATE12_NODE_IDS = (
    "tests/test_gate12.py::TestIdentifierRoundTrip::test_duration_measures_the_command_not_the_envelope",
    "tests/test_gate12.py::TestIdentifierRoundTrip::test_every_returned_identifier_resolves",
    "tests/test_gate12.py::TestAllEnginesRunTheirLocalTest::test_each_engine_installs_and_verifies",
    "tests/test_gate12.py::TestRendererAfterARealRun::test_no_command_falls_back_after_a_real_run",
    "tests/test_gate12.py::TestHonestClosingLine::test_the_closing_line_states_what_was_verified",
)
MANIFEST_SCHEMA = "cathedral.gate0.requirement_manifest.v1"
SPEC_REVISION = 5

# The controlling documents are shipped with the repository and pinned by hash.
# An explicit environment override is available for independent comparison, but
# neither path accepts a hash it has not computed from bytes on disk.
CONTROLLING_DOCUMENTS = {
    "CATHEDRAL-CLI-LAUNCH-PRD-TECH-SPEC-20260731.md":
        "c1d6f1be5a44dd1c773089d6d4214290a72774f619336590cc17869608fff2d1",
    "GATE0-INDEPENDENT-REVIEW-20260731.md":
        "0a9f4f1ad0d0853d0a67cb7678e635f126c20564e51c1a3d2a64996673928c31",
    "GATE0-FABLE-REPAIR-DIRECTIVE-20260731.md":
        "e92760de335c92527cb414bde4334e741c04ef1741a8fcb29345dc904bd39d1f",
}
_SPEC_DIR_ENV = "CATHEDRAL_SPEC_DIR"
_SPEC_DIR_DEFAULTS = (
    str(REPO_ROOT / "docs" / "gate0-spec"),
    "~/Documents/PROJECTS/cathedral-unified-cli-launch",
)

# Environment variables that change what pytest does without appearing in the
# command line. In gate mode the displayed command must be the executed command.
_FORBIDDEN_ENV = ("PYTEST_ADDOPTS", "PYTHONWARNINGS", "PYTEST_PLUGINS",
                  "PYTEST_DISABLE_PLUGIN_AUTOLOAD")

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class _Gate0State:
    def __init__(self) -> None:
        self.targeted = False      # the invocation named exactly the two PRD files
        self.enforcing = False     # ... and the run is a real (non collect-only) run
        self.skipped: list[str] = []
        self.deselected: list[str] = []
        self.warnings: list[str] = []
        self.collect_errors: list[str] = []

    @property
    def problems(self) -> list[str]:
        problems: list[str] = []
        for label, items in (("skipped", self.skipped), ("deselected", self.deselected),
                             ("warning", self.warnings), ("collection error", self.collect_errors)):
            problems.extend(f"{label}: {item}" for item in items)
        return problems


_STATE = _Gate0State()


# --- manifest ------------------------------------------------------------------

def load_manifest() -> dict:
    try:
        return json.loads(MANIFEST_PATH.read_text())
    except OSError as exc:
        raise pytest.UsageError(f"the Gate 0 requirement manifest is unreadable: {exc}") from exc
    except ValueError as exc:
        raise pytest.UsageError(f"the Gate 0 requirement manifest is not valid JSON: {exc}") from exc


def manifest_node_ids(manifest: dict) -> tuple[list[str], list[str]]:
    """(unique node IDs in order, duplicates).

    One test may legitimately be proof for more than one requirement — a strict
    pointer parse is evidence for both the pointer matrix and the sealed-group
    contract. What is a defect is the SAME node ID listed twice inside ONE
    requirement, which inflates how much that requirement is actually covered.
    """
    seen: set[str] = set()
    ordered: list[str] = []
    duplicates: list[str] = []
    for requirement in manifest.get("requirements", []):
        within: set[str] = set()
        for node_id in requirement.get("tests", []):
            if node_id in within:
                duplicates.append(f"{requirement.get('id')}: {node_id}")
            within.add(node_id)
            if node_id not in seen:
                seen.add(node_id)
                ordered.append(node_id)
    return ordered, duplicates


def spec_directory() -> Path | None:
    """Where the controlling documents live, if they are reachable from here."""
    candidates = []
    override = os.environ.get(_SPEC_DIR_ENV)
    if override:
        candidates.append(Path(override).expanduser())
    candidates.extend(Path(p).expanduser() for p in _SPEC_DIR_DEFAULTS)
    for candidate in candidates:
        if all((candidate / name).is_file() for name in CONTROLLING_DOCUMENTS):
            return candidate
    return None


def document_hashes(directory: Path) -> dict[str, str]:
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
            for name in CONTROLLING_DOCUMENTS}


def validate_manifest(manifest: dict, *, collected: list[str]) -> list[str]:
    """Validate the manifest as a document. A manifest whose node IDs happen to
    match but whose schema, specification identity, command or counts are wrong is
    not a manifest for *this* gate, and matching IDs would hide that."""
    problems: list[str] = []

    if manifest.get("schema") != MANIFEST_SCHEMA:
        problems.append(f"manifest schema is {manifest.get('schema')!r}, expected {MANIFEST_SCHEMA!r}")
    if manifest.get("command") != GATE0_COMMAND:
        problems.append(f"manifest command is {manifest.get('command')!r}, expected {GATE0_COMMAND!r}")
    files = manifest.get("files")
    if not isinstance(files, list) or set(files) != GATE0_FILE_SET:
        problems.append(f"manifest files are {files!r}, expected {list(GATE0_FILES)!r}")

    spec = manifest.get("specification")
    if not isinstance(spec, dict):
        problems.append("manifest has no specification block")
    else:
        if spec.get("revision") != SPEC_REVISION:
            problems.append(f"manifest names revision {spec.get('revision')!r}, expected {SPEC_REVISION}")
        declared = {
            spec.get("document"): spec.get("sha256"),
            (spec.get("review") or {}).get("document"): (spec.get("review") or {}).get("sha256"),
            (spec.get("repair_directive") or {}).get("document"):
                (spec.get("repair_directive") or {}).get("sha256"),
        }
        for name, expected in CONTROLLING_DOCUMENTS.items():
            actual = declared.get(name)
            if actual is None:
                problems.append(f"the manifest does not name {name}")
            elif not (isinstance(actual, str) and _HEX64.match(actual)):
                problems.append(f"the manifest hash for {name} is not a lowercase sha256 digest")
            elif actual != expected:
                problems.append(f"the manifest hash for {name} is not the pinned hash")
        directory = spec_directory()
        if directory is not None:
            for name, actual in document_hashes(directory).items():
                if actual != CONTROLLING_DOCUMENTS[name]:
                    problems.append(
                        f"{name} on disk hashes to {actual}, not the pinned "
                        f"{CONTROLLING_DOCUMENTS[name]} — the controlling document changed")

    requirements = manifest.get("requirements")
    if not isinstance(requirements, list) or not requirements:
        problems.append("the manifest has no requirements")
        return problems

    seen_ids: set[str] = set()
    for index, requirement in enumerate(requirements):
        where = f"requirement #{index}"
        if not isinstance(requirement, dict):
            problems.append(f"{where} is not an object")
            continue
        rid = requirement.get("id")
        where = f"requirement {rid!r}"
        if not isinstance(rid, str) or not rid.strip():
            problems.append(f"{where} has no id")
        elif rid in seen_ids:
            problems.append(f"{where} is declared twice")
        else:
            seen_ids.add(rid)
        if not isinstance(requirement.get("source"), str) or not requirement["source"].strip():
            problems.append(f"{where} does not cite a source in the controlling documents")
        statement = requirement.get("statement")
        if not isinstance(statement, str) or len(statement.strip()) < 20:
            problems.append(f"{where} has no usable statement")
        tests = requirement.get("tests")
        if not isinstance(tests, list) or not tests:
            problems.append(f"{where} names no test")
            continue
        for node_id in tests:
            if not isinstance(node_id, str) or "::" not in node_id:
                problems.append(f"{where} names a malformed node ID {node_id!r}")
            elif node_id.split("::")[0] not in GATE0_FILE_SET:
                problems.append(f"{where} names {node_id!r}, which is outside the gate file set")

    unique, duplicates = manifest_node_ids(manifest)
    if duplicates:
        problems.append(f"the manifest lists {len(duplicates)} duplicate node ID(s) inside a single "
                        f"requirement: {sorted(set(duplicates))[:5]}")
    declared_count = manifest.get("node_id_count")
    if declared_count != len(unique):
        problems.append(f"the manifest declares {declared_count!r} node IDs but lists {len(unique)}")

    expected_set, collected_set = set(unique), set(collected)
    missing = sorted(expected_set - collected_set)
    unknown = sorted(collected_set - expected_set)
    if missing:
        problems.append(f"{len(missing)} manifest node ID(s) did not collect: {missing[:5]}")
    if unknown:
        problems.append(f"{len(unknown)} collected node ID(s) are absent from the manifest: "
                        f"{unknown[:5]}")
    return problems


# --- gate mode, decided from the invocation ------------------------------------

def _invocation_targets(config: pytest.Config) -> set[str] | None:
    """The files the invocation named, repo-relative — or ``None`` if any argument
    was not a plain file target.

    Stripping ``::`` before comparing was a bypass, and a quiet one. It made
    ``pytest tests/test_gate12.py::TestX::test_y`` — one single test — compare
    equal to the whole file, so a single passing node was handed the banner that
    says the complete job ran unfiltered. A node or class selector IS a filter; it
    just spells itself differently from ``-k``. So the raw argument is required to
    be exactly a file path, and anything containing ``::`` makes the target set
    unrecognisable rather than "close enough".
    """
    targets: set[str] = set()
    params = getattr(config, "invocation_params", None)
    invocation = Path(params.dir) if params is not None else Path.cwd()
    for arg in config.args:
        raw = str(arg)
        if "::" in raw:
            return None
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = invocation / candidate
        try:
            targets.add(str(candidate.resolve().relative_to(REPO_ROOT)))
        except (OSError, ValueError):
            targets.add(str(candidate))
    return targets


def _filtering_options(config: pytest.Config) -> list[str]:
    """Every way this invocation could be running less than the whole gate."""
    option = config.option
    found: list[str] = []
    if getattr(option, "keyword", ""):
        found.append(f"-k {option.keyword!r}")
    if getattr(option, "markexpr", ""):
        found.append(f"-m {option.markexpr!r}")
    if getattr(option, "ignore", None):
        found.append(f"--ignore {list(option.ignore)!r}")
    if getattr(option, "ignore_glob", None):
        found.append(f"--ignore-glob {list(option.ignore_glob)!r}")
    if getattr(option, "deselect", None):
        found.append(f"--deselect {list(option.deselect)!r}")
    if getattr(option, "lf", False) or getattr(option, "failedfirst", False):
        found.append("--last-failed/--failed-first")
    if getattr(option, "stepwise", False):
        found.append("--stepwise")
    if getattr(option, "maxfail", 0):
        found.append(f"--maxfail={option.maxfail} (or -x): the gate must run every case")
    if getattr(option, "numprocesses", None):
        found.append("-n/--numprocesses: the gate runs in one process")
    if getattr(option, "collectonly", False):
        found.append("--collect-only")
    for name in _FORBIDDEN_ENV:
        if os.environ.get(name):
            found.append(f"${name} is set: the displayed command would not be the executed command")
    return found


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "real_engine: a live signed cathedral engine is required (Gate 1/2 only). These "
        "live in tests/test_gate12.py and are never collected by the Gate 0 command.")

    targets = _invocation_targets(config)
    if targets is None:
        # A node or class selector was used. That is a development run by
        # definition; it is never a gate.
        _STATE.targeted = False
        return
    _STATE.targeted = targets == GATE0_FILE_SET
    if targets == GATE12_FILE_SET:
        # The same refusal, for the same reason: a Gate 1/2 run that quietly dropped
        # a live-engine case would be reported as "Gate 1/2 passed" exactly as a
        # narrowed Gate 0 run was reported as green.
        # `--collect-only` is not itself a narrowing here: the Gate 0 manifest
        # generator needs it, and a collect-only run executes nothing. A FILTER
        # under collect-only still is one, though — otherwise "collect one test and
        # look at the banner" is a bypass with an extra step.
        narrowed = [flag for flag in _filtering_options(config)
                    if not flag.startswith("--collect-only")]
        if narrowed:
            raise pytest.UsageError(
                "Gate 1/2 refuses a narrowed run: every live-engine case must execute.\n  - "
                + "\n  - ".join(narrowed))
        if not getattr(config.option, "collectonly", False):
            _STATE.enforcing = True
        return
    if not _STATE.targeted:
        return

    problems = _filtering_options(config)
    collect_only = bool(getattr(config.option, "collectonly", False))
    if collect_only and problems == ["--collect-only"]:
        # Collect-only executes nothing, so it can never be gate evidence, and it is
        # what `scripts/gate0_manifest.py` uses to build the manifest in the first
        # place. It is reported, not enforced, and it is not a bypass: there are no
        # passing tests in a collect-only run to launder.
        return
    if problems:
        raise pytest.UsageError(
            "Gate 0 refuses a narrowed run. The acceptance command is exactly\n"
            f"    {GATE0_COMMAND}\n"
            "with nothing added. A filter, a fail-fast limit, or an environment "
            "variable that rewrites the invocation is how a required case disappears "
            "while the gate still reports green.\n  - " + "\n  - ".join(problems))
    _STATE.enforcing = True


def pytest_collection_modifyitems(session: pytest.Session, config: pytest.Config, items) -> None:
    # `item.nodeid` is exactly what the manifest records and exactly what an
    # operator would pass back to pytest — no reconstruction, no drift.
    collected = [item.nodeid for item in items]
    if _STATE.enforcing and not _STATE.targeted:
        # Gate 1/2. Exact node equality, for the same reason Gate 0 has a manifest:
        # "the file was named" is not the same claim as "every case in it ran".
        missing = sorted(set(GATE12_NODE_IDS) - set(collected))
        unknown = sorted(set(collected) - set(GATE12_NODE_IDS))
        if missing or unknown:
            raise pytest.UsageError(
                "Gate 1/2 collected a different set of tests than the job is defined as.\n"
                + (f"  missing: {missing}\n" if missing else "")
                + (f"  unknown: {unknown}\n" if unknown else "")
                + "Update GATE12_NODE_IDS in tests/conftest.py deliberately if the job changed.")
        _banner(config, f"Gate 1/2 mode: {len(collected)} live-engine tests, exactly the defined "
                        f"set, unfiltered. A skip is a failure.")
        return
    if not _STATE.enforcing:
        _banner(config, f"NOT a Gate 0 run: {len(collected)} node IDs collected from "
                        f"{sorted({n.split('::')[0] for n in collected})}. "
                        f"This run is not Gate 0 evidence.")
        return

    problems: list[str] = []
    files = {node_id.split("::")[0] for node_id in collected}
    if files != GATE0_FILE_SET:
        problems.append(f"collection produced {sorted(files)}, not {sorted(GATE0_FILES)}")

    seen: set[str] = set()
    repeated: set[str] = set()
    for node_id in collected:
        if node_id in seen:
            repeated.add(node_id)
        seen.add(node_id)
    collected_duplicates = sorted(repeated)
    if collected_duplicates:
        problems.append(f"pytest collected duplicate node IDs: {collected_duplicates[:5]}")

    problems.extend(validate_manifest(load_manifest(), collected=collected))

    if problems:
        raise pytest.UsageError(
            "Gate 0 manifest check FAILED before execution:\n  - " + "\n  - ".join(problems) +
            f"\n\nManifest: {MANIFEST_PATH}\n"
            f"Regenerate with: python scripts/gate0_manifest.py --write")

    manifest = load_manifest()
    _banner(config, f"Gate 0 mode: {len(collected)} collected node IDs == manifest "
                    f"({len(manifest['requirements'])} requirements, schema validated, "
                    f"controlling hashes pinned). Zero skips, deselections, warnings or "
                    f"collection errors are permitted.")


def _banner(config: pytest.Config, message: str) -> None:
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line(message)


# --- the four things a gate run may never contain ------------------------------

@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if not report.skipped:
        return
    # A skip is never acceptable evidence: in gate mode it becomes a failure, and
    # `CATHEDRAL_NO_SKIP=1` keeps the same behaviour available to any other run.
    if _STATE.enforcing or os.environ.get("CATHEDRAL_NO_SKIP"):
        _STATE.skipped.append(report.nodeid)
        report.outcome = "failed"
        report.longrepr = (f"Gate 0 forbids skips; this test skipped instead of proving "
                           f"anything: {report.longrepr}")


def pytest_deselected(items) -> None:
    for item in items:
        _STATE.deselected.append(getattr(item, "nodeid", str(item)))


def pytest_warning_recorded(warning_message, when, nodeid, location) -> None:
    _STATE.warnings.append(f"{nodeid or when}: {warning_message.category.__name__}: "
                           f"{warning_message.message}")


def pytest_collectreport(report) -> None:
    if report.failed:
        _STATE.collect_errors.append(str(report.nodeid))


def pytest_sessionfinish(session: pytest.Session, exitstatus) -> None:
    if not _STATE.enforcing:
        return
    problems = _STATE.problems
    if not problems:
        return
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        reporter.write_line("")
        reporter.write_line("Gate 0 acceptance contract violated:", red=True)
        for problem in problems:
            reporter.write_line(f"  - {problem}", red=True)
    if exitstatus == 0:
        session.exitstatus = 1
