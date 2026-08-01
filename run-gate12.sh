#!/usr/bin/env bash
# Gate 1/2 acceptance — the REAL signed-engine job. Not part of Gate 0.
#
# Two things this script exists to get right.
#
# The documented `--release <dir>` argument is for **Cathedral**, not for pytest.
# Passing arbitrary trailing arguments through to pytest meant the
# documented usage silently became a pytest path argument — which either errored or,
# worse, replaced the target file set. Here it becomes CATHEDRAL_RELEASE, which is
# what the CLI actually reads.
#
# Nothing else is accepted. A Gate 1/2 result must cover every live-engine case, so
# there is no way to pass `-k`, `-m` or a subset of tests through this script and
# still be told the job passed. tests/conftest.py enforces the same rule for anyone
# running pytest directly.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

RELEASE="${CATHEDRAL_RELEASE:-}"
while [ "$#" -gt 0 ]; do
    case "$1" in
        --release)
            [ "$#" -ge 2 ] || { echo "--release needs a bundle directory" >&2; exit 2; }
            RELEASE="$2"; shift 2 ;;
        --release=*)
            RELEASE="${1#--release=}"; shift ;;
        *)
            echo "run-gate12.sh accepts only --release <bundle-dir>." >&2
            echo "Refused: $1" >&2
            echo "Filtering is refused on purpose: a Gate 1/2 result must cover every" >&2
            echo "live-engine case, so a narrowed run must not be able to report one." >&2
            exit 2 ;;
    esac
done

if [ -z "$RELEASE" ]; then
    echo "Gate 1/2 needs real signed cathedral-* artifacts." >&2
    echo "Usage: ./run-gate12.sh --release /path/to/signed/bundle" >&2
    echo "   or: CATHEDRAL_RELEASE=/path/to/signed/bundle ./run-gate12.sh" >&2
    exit 2
fi
if [ ! -f "$RELEASE/release.json" ]; then
    echo "$RELEASE is not a release bundle (no release.json)." >&2
    exit 2
fi
export CATHEDRAL_RELEASE="$RELEASE"

for var in PYTEST_ADDOPTS PYTHONWARNINGS PYTEST_PLUGINS PYTEST_DISABLE_PLUGIN_AUTOLOAD; do
    if [ -n "${!var-}" ]; then
        echo "refusing to run: \$$var is set; it would change the invocation invisibly." >&2
        exit 2
    fi
done

VENV="${CATHEDRAL_DEV_VENV:-$ROOT/.venv}"
if [ ! -x "$VENV/bin/python" ]; then
    ./scripts/dev-env.sh
fi
# shellcheck disable=SC1091
source "$VENV/bin/activate"

# A failed install or a runtime error must be a FAILURE, never a skip.
export CATHEDRAL_NO_SKIP=1

GATE12_COMMAND=(python -m pytest -q tests/test_gate12.py)
echo "release:  $CATHEDRAL_RELEASE"
echo "command:  ${GATE12_COMMAND[*]}"
echo
exec "${GATE12_COMMAND[@]}"
