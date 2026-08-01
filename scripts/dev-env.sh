#!/usr/bin/env bash
# Provision the released development environment.
#
# Revision 5 fixes the Gate 0 acceptance command as:
#
#     python -m pytest -q tests/test_gate0.py tests/test_contract.py
#
# so the development environment must actually provide a `python` entrypoint.
# Many hosts ship only `python3`, and the node itself requires CPython 3.11-3.13
# (3.14 removed APIs the pinned engines need), so this script builds a local
# virtual environment from a supported interpreter. `.venv/bin/python` is that
# documented entrypoint; activating the environment puts it on PATH and the exact
# PRD command then runs verbatim.
#
#   ./scripts/dev-env.sh          # provision
#   source .venv/bin/activate     # then `python -m pytest ...` works as written
#
# ./run-gate0.sh does both and runs the exact command for you.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${CATHEDRAL_DEV_VENV:-$ROOT/.venv}"
PYTEST_PIN="pytest==8.3.0"

find_supported_python() {
    if [ -n "${PYTHON:-}" ]; then echo "$PYTHON"; return; fi
    for name in python3.13 python3.12 python3.11; do
        if command -v "$name" >/dev/null 2>&1; then echo "$name"; return; fi
        for prefix in /opt/homebrew/bin /usr/local/bin /usr/bin; do
            [ -x "$prefix/$name" ] && { echo "$prefix/$name"; return; }
        done
    done
    echo ""
}

BASE="$(find_supported_python)"
if [ -z "$BASE" ]; then
    echo "error: no CPython 3.11-3.13 found. The node requires one; install it and retry." >&2
    echo "       (set PYTHON=/path/to/python3.11 to choose explicitly)" >&2
    exit 1
fi

echo "base interpreter: $BASE ($("$BASE" -V 2>&1))"
if [ ! -x "$VENV/bin/python" ]; then
    "$BASE" -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet "$PYTEST_PIN"

echo "provisioned $VENV"
echo "  python: $("$VENV/bin/python" -V 2>&1)"
echo "  pytest: $("$VENV/bin/python" -m pytest --version 2>&1 | head -1)"
echo
echo "activate it, then the Revision 5 command runs verbatim:"
echo "  source $VENV/bin/activate"
echo "  python -m pytest -q tests/test_gate0.py tests/test_contract.py"
