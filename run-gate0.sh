#!/usr/bin/env bash
# Gate 0 acceptance.
#
# This runs the Revision 5 command VERBATIM. The string printed below and the
# argument vector executed below are built from the SAME array, so they cannot
# drift: there is no way for this script to show one command and run another.
#
# It also refuses to run under an environment that rewrites a pytest invocation
# from outside the command line. PYTEST_ADDOPTS can insert `-k`, `-m` or
# `--deselect`; PYTHONWARNINGS can silence the warnings the gate treats as
# failures; PYTEST_PLUGINS and PYTEST_DISABLE_PLUGIN_AUTOLOAD can change which
# plugins load. Any of them would make the displayed command a lie, so the script
# stops rather than guessing what the operator meant. (tests/conftest.py refuses
# them too, so a reviewer running the raw command gets the same answer.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ "$#" -ne 0 ]; then
    echo "run-gate0.sh takes no arguments: the acceptance command is fixed by Revision 5." >&2
    echo "Refused: $*" >&2
    exit 2
fi

for var in PYTEST_ADDOPTS PYTHONWARNINGS PYTEST_PLUGINS PYTEST_DISABLE_PLUGIN_AUTOLOAD; do
    if [ -n "${!var-}" ]; then
        echo "refusing to run: \$$var is set (${!var})." >&2
        echo "It can change the invocation without changing the command line, so the" >&2
        echo "command this script prints would not be the command it runs. Unset it." >&2
        exit 2
    fi
done
# PYTHONPATH and PYTHONSTARTUP reach the interpreter itself rather than pytest, and
# the node's own subprocesses scrub them — but the gate process is not scrubbed, so
# they are cleared here rather than left to influence collection or imports.
unset PYTHONPATH PYTHONSTARTUP || true

VENV="${CATHEDRAL_DEV_VENV:-$ROOT/.venv}"
if [ ! -x "$VENV/bin/python" ]; then
    echo "provisioning the development environment (it must provide \`python\`)..."
    ./scripts/dev-env.sh
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

# ONE definition. Displayed and executed from the same array.
GATE0_COMMAND=(python -m pytest -q tests/test_gate0.py tests/test_contract.py)

echo "interpreter: $(python -V 2>&1) at $(command -v python)"
echo "pytest:      $(python -m pytest --version 2>&1 | head -1)"
echo "command:     ${GATE0_COMMAND[*]}"
echo

exec "${GATE0_COMMAND[@]}"
