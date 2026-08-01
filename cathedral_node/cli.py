"""Argument parsing and the top-level entry point.

The command surface, and why it is shaped this way:

    cathedral <verb> [role] [options]

Verb first, role second. The first decision an operator makes is *what they are
doing*; the role is the object it acts on. It also gives an agent a flat,
templatable surface — ``cathedral test distill --json`` and
``cathedral test compute --json`` differ by one token.

Upstream command names are not preserved. ``cathedral-cybergym-agent --local``,
``cathedral worker serve``, and ``cathedral-validator serve --dry-run --offline``
are three unrelated spellings of "try this safely"; here they are all
``cathedral test <role>``.
"""

from __future__ import annotations

import argparse
import sys

from cathedral_node import lockfile, paths
from cathedral_node.contracts import Envelope, Exit, Remediation
from cathedral_node.contracts import codes as C
from cathedral_node.contracts.version import PROTOCOL_VERSION, compatible
from cathedral_node.runner import Context, build_console, emit, execute, new_run_id, registry

VERSION = "1.0.0"


class UsageError(Exception):
    """A bad command line. Carries argparse's message so we can put it in an
    envelope instead of letting argparse write usage text and exit 2."""

    def __init__(self, message: str, usage: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.usage = usage


class ContractParser(argparse.ArgumentParser):
    """An ArgumentParser that never calls ``sys.exit`` on a usage error.

    argparse's default is to print usage to stderr and exit ``2``. That breaks
    two contract promises at once: ``2`` is not a documented exit code, and an
    agent running with ``--json`` gets an empty stdout and has to read stderr to
    find out what happened. Raising instead lets ``main`` emit a real envelope.
    """

    def error(self, message: str):  # noqa: A003 - argparse's own name
        raise UsageError(message, self.format_usage().strip())

_EPILOG = """\
first run
  cathedral quickstart            guided setup, ending in a verified local test
  cathedral doctor                can this machine do the work?

miner
  cathedral explain distill       what the track does and what it pays
  cathedral setup distill         install the pinned engine
  cathedral test distill          verified local test, pays nothing
  cathedral start distill         begin mining
  cathedral status                what is running, and what happened

validator
  cathedral setup validator
  cathedral test validator        safe dry run against the signed feed
  cathedral start validator       begin validating (never broadcasts by default)

agents
  every command takes --json      versioned envelope on stdout; diagnostics on stderr
  without --json                   the human view is on stdout (capturable, pipeable)
  cathedral capabilities --json   discovery: protocol, commands, exit codes
  cathedral agent-brief           an instruction block to paste into an agent
"""


def build_parser() -> argparse.ArgumentParser:
    parser = ContractParser(
        prog="cathedral",
        description="Cathedral node — one command for Distill mining, Compute mining, and validation.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"cathedral {VERSION} (protocol {PROTOCOL_VERSION})")

    common = ContractParser(add_help=False)
    common.add_argument("--json", action="store_true", dest="json_mode",
                        help="write a versioned result envelope to stdout")
    common.add_argument("--yes", "-y", action="store_true", dest="assume_yes",
                        help="supply any required confirmation without prompting")
    common.add_argument("--dry-run", action="store_true",
                        help="report what would happen; change nothing")
    common.add_argument("--verbose", "-v", action="store_true", help="include engine diagnostics")
    common.add_argument("--quiet", "-q", action="store_true", help="suppress the human view")
    common.add_argument("--protocol", metavar="VERSION", default=None,
                        help="refuse to run unless the node's protocol MAJOR matches")

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    def add(name: str, help_text: str, *, role: str | None = "optional") -> argparse.ArgumentParser:
        sub = subparsers.add_parser(name, parents=[common], help=help_text, description=help_text)
        sub.error = parser.error  # type: ignore[method-assign]
        if role == "required":
            sub.add_argument("role", choices=lockfile.ROLES, help="distill, compute, or validator")
        elif role == "optional":
            sub.add_argument("role", nargs="?", choices=lockfile.ROLES, default=None,
                             help="limit to one role")
        return sub

    def add_release_args(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--release", metavar="DIR", default=None,
                         help="install from a local signed release bundle (recovery/test override)")
        sub.add_argument("--channel", metavar="URL", default=None,
                         help="HTTPS signed release channel to fetch from (overrides the configured one)")
        sub.add_argument("--signers", metavar="FILE", default=None,
                         help="root-owned allowed_signers trust file (default: $CATHEDRAL_HOME/allowed_signers)")

    # --- discovery and orientation ---------------------------------------------
    quickstart_cmd = add("quickstart", "Guided path from a clean machine to a verified local test",
                         role="optional")
    add_release_args(quickstart_cmd)
    add("doctor", "Check whether this machine and identity qualify")
    add("capabilities", "What this node can do, and what needs an owner decision", role=None)
    add("explain", "What a role does, what it needs, and what it pays", role="required")

    # --- setup -------------------------------------------------------------------
    setup = add("setup", "Install the signed release and write configuration", role="required")
    setup.add_argument("--force", action="store_true", help="reinstall even if already correct")
    add_release_args(setup)

    add("recover", "Finish or undo an interrupted release transaction", role=None)

    # --- configuration -------------------------------------------------------------
    config_cmd = subparsers.add_parser("config", parents=[common], help="Read and write configuration")
    config_sub = config_cmd.add_subparsers(dest="action", metavar="<action>")
    show = config_sub.add_parser("show", parents=[common], help="Print configuration (never a secret)")
    show.add_argument("role", nargs="?", choices=lockfile.ROLES, default=None)
    set_cmd = config_sub.add_parser("set", parents=[common], help="Set one field")
    set_cmd.add_argument("role", choices=lockfile.ROLES)
    set_cmd.add_argument("field")
    set_cmd.add_argument("value")
    get_cmd = config_sub.add_parser("get", parents=[common], help="Read one field")
    get_cmd.add_argument("role", choices=lockfile.ROLES)
    get_cmd.add_argument("field")
    schema_cmd = config_sub.add_parser("schema", parents=[common], help="Every field, with its meaning")
    schema_cmd.add_argument("role", nargs="?", choices=lockfile.ROLES, default=None)

    secret_cmd = subparsers.add_parser("secret", parents=[common],
                                       help="Store credentials safely; never printed")
    secret_sub = secret_cmd.add_subparsers(dest="action", metavar="<action>")
    secret_sub.add_parser("list", parents=[common], help="What is stored, without revealing it")
    secret_set = secret_sub.add_parser("set", parents=[common], help="Store one secret, read from stdin")
    secret_set.add_argument("name")
    secret_set.add_argument("--stdin", action="store_true",
                            help="read the value from stdin (the only accepted source)")
    secret_rm = secret_sub.add_parser("remove", parents=[common], help="Delete one secret")
    secret_rm.add_argument("name")

    # --- running -------------------------------------------------------------------
    test_cmd = add("test", "Run the verified local test — pays nothing, touches no chain", role="required")
    test_cmd.add_argument("--timeout", type=float, default=0, help="seconds before giving up")

    start = add("start", "Start mining or validating", role="required")
    start.add_argument("--broadcast", action="store_true",
                       help="validator only: allow chain writes. Requires --yes as well.")
    start.add_argument("--foreground", action="store_true", default=True,
                       help="run in this terminal (the default)")
    start.add_argument("--once", action="store_true", help="one cycle, then exit")

    add("stop", "Stop a running role", role="required")

    status = add("status", "What is running, and what recently happened")
    status.add_argument("--run", dest="run", default=None, help="one run by id")
    status.add_argument("--limit", type=int, default=10)

    logs = add("logs", "Stream meaningful state changes")
    logs.add_argument("--run", dest="run", default=None)
    logs.add_argument("--follow", "-f", action="store_true")
    logs.add_argument("--lines", "-n", type=int, default=40)
    logs.add_argument("--raw", action="store_true", help="engine output rather than node events")

    resume = add("resume", "Continue an interrupted run", role=None)
    resume.add_argument("run", help="run id")

    cancel = add("cancel", "Cancel a run, preserving its state", role=None)
    cancel.add_argument("run", help="run id")

    cleanup = add("cleanup", "Remove run history, caches, or an engine")
    cleanup.add_argument("--runs", action="store_true", help="delete completed run directories")
    cleanup.add_argument("--engine", action="store_true", help="remove the installed engine")
    cleanup.add_argument("--all", action="store_true", help="everything except config and secrets")
    cleanup.add_argument("--keep-days", type=int, default=7)

    # --- evidence and identifiers -----------------------------------------------
    evidence = subparsers.add_parser("evidence", parents=[common],
                                     help="Look up a challenge, receipt, submission, or score by id")
    evidence.add_argument("identifier", help="any id this node has emitted")

    # --- updates -------------------------------------------------------------------
    update = subparsers.add_parser("update", parents=[common],
                                   help="Move to new pinned engine revisions, safely")
    update.add_argument("--check", action="store_true", help="report what would change; change nothing")
    update.add_argument("--to", metavar="LOCKFILE", default=None,
                        help="adopt pins from another lockfile. NOT verified: review it, and "
                             "the repositories it names, before using it")
    add_release_args(update)
    update.add_argument("role", nargs="?", choices=lockfile.ROLES, default=None)

    # Rollback is node-wide (there is no per-role rollback): it undoes an interrupted
    # transaction, or explains that a deliberate rollback is a newly-signed release.
    subparsers.add_parser("rollback", parents=[common],
                          help="Undo an interrupted release, or explain a signed rollback")

    # --- agents ---------------------------------------------------------------------
    brief = add("agent-brief", "Print an instruction block for a coding agent")
    brief.add_argument("--format", choices=("markdown", "text"), default="markdown")

    return parser


def main(argv: list[str] | None = None) -> int:
    raw = argv if argv is not None else sys.argv[1:]
    wants_json = "--json" in raw
    parser = build_parser()

    try:
        args = parser.parse_args(raw)
    except UsageError as exc:
        return _fail_early(
            "usage",
            C.E_USAGE,
            exc.message,
            Exit.USAGE,
            wants_json,
            remediation=Remediation(
                summary="Nothing ran. Check the command and its arguments.",
                command="cathedral --help",
            ),
            detail={"usage": exc.usage},
        )

    if not getattr(args, "command", None):
        if not wants_json:
            parser.print_help(sys.stderr)
            return int(Exit.USAGE)
        return _fail_early(
            "usage", C.E_USAGE, "no command given", Exit.USAGE, wants_json,
            remediation=Remediation(summary="Discover the surface.",
                                    command="cathedral capabilities --json"),
        )

    # Import for side effects: each module registers its command and renderer.
    from cathedral_node import commands  # noqa: F401

    name = args.command
    # Two-level commands dispatch as "config.set", "secret.list", and so on.
    action = getattr(args, "action", None)
    if name in ("config", "secret"):
        if not action:
            if not wants_json:
                parser.print_help(sys.stderr)
                return int(Exit.USAGE)
            return _fail_early(
                "usage", C.E_USAGE, f"`{name}` needs an action", Exit.USAGE, wants_json,
                remediation=Remediation(summary=f"Try `cathedral {name} show` or `list`.",
                                        command=f"cathedral {name} --help"),
            )
        name = f"{name}.{action}"

    requested = getattr(args, "protocol", None)
    if requested and not compatible(requested):
        return _fail_early(
            name,
            C.E_PROTOCOL_INCOMPATIBLE,
            f"this node speaks protocol {PROTOCOL_VERSION}; you asked for {requested}",
            Exit.INCOMPATIBLE,
            wants_json,
            remediation=Remediation(
                summary="Re-run discovery and update your integration before continuing.",
                command="cathedral capabilities --json",
                requires_operator=True,
            ),
            detail={"node_protocol": PROTOCOL_VERSION, "requested": requested},
        )

    handler = registry().get(name)
    if handler is None:
        return _fail_early(
            name, C.E_USAGE, f"`{name}` is not implemented in this build", Exit.USAGE, wants_json,
            remediation=Remediation(summary="List what this build supports.",
                                    command="cathedral capabilities --json"),
        )

    try:
        paths.ensure_layout()
    except OSError as exc:
        # The node root is created before any command runs, so a failure here
        # escapes the command boundary entirely. Without this it exited 1 with
        # nothing on stdout — an exit code not even in the contract.
        return _fail_early(
            name,
            C.E_DISK_LOW,
            f"cannot use the node directory {paths.home()}: {exc.strerror or exc}",
            Exit.NOT_READY,
            wants_json,
            remediation=Remediation(
                summary="Nothing ran. Point CATHEDRAL_HOME somewhere writable, or fix the "
                "permissions on that path.",
                command=f"CATHEDRAL_HOME=$HOME/.cathedral cathedral {name}",
            ),
            detail={"home": str(paths.home()), "errno": getattr(exc, "errno", None)},
        )

    json_mode = bool(getattr(args, "json_mode", False))
    ctx = Context(
        args=args,
        console=build_console(json_mode, quiet=bool(getattr(args, "quiet", False))),
        json_mode=json_mode,
        assume_yes=bool(getattr(args, "assume_yes", False)),
        dry_run=bool(getattr(args, "dry_run", False)),
        verbose=bool(getattr(args, "verbose", False)),
        run_id=new_run_id(name.split(".")[0]),
        home=paths.home(),
    )
    return execute(name, handler, ctx)


def _fail_early(
    command: str,
    code: str,
    message: str,
    exit_code: Exit,
    wants_json: bool,
    *,
    remediation: Remediation | None = None,
    detail: dict | None = None,
) -> int:
    """A failure raised before a command could be dispatched.

    Still returns a complete envelope, because an agent that asked for ``--json``
    must never have to fall back to reading stderr — including when what it got
    wrong was the command line itself.
    """
    env = Envelope.fail(command, code, message, exit_code=exit_code,
                        remediation=remediation, detail=detail or {})
    env.run_id = new_run_id("usage")
    ctx = Context(
        args=None,
        console=build_console(wants_json),
        json_mode=wants_json,
        assume_yes=False,
        dry_run=False,
        verbose=False,
        run_id=env.run_id,
        home=paths.home(),
    )
    emit(env, ctx)
    return int(exit_code)


if __name__ == "__main__":
    raise SystemExit(main())
