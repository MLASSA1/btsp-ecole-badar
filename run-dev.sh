#!/bin/sh
# Start the app for local preview.
#
# Deliberately does NOT use venv/bin/python. That interpreter reads
# venv/pyvenv.cfg at startup, and the dev-server launcher runs in a sandbox
# that is denied that file when this project is not the primary working
# directory — Python then dies with:
#
#   PermissionError: [Errno 1] Operation not permitted: .../venv/pyvenv.cfg
#
# Pointing PYTHONPATH at the venv's packages and running the base interpreter
# gets the same environment without the config lookup, so the launcher works
# whichever directory it was started from.

set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PY=/Library/Developer/CommandLineTools/usr/bin/python3
SITE_PACKAGES="$HERE/venv/lib/python3.9/site-packages"

[ -x "$PY" ] || PY=$(command -v python3)
[ -d "$SITE_PACKAGES" ] || { echo "Missing $SITE_PACKAGES — run: python3 -m venv venv && venv/bin/pip install -r requirements.txt" >&2; exit 1; }

export PYTHONPATH="$SITE_PACKAGES${PYTHONPATH:+:$PYTHONPATH}"
export PORT="${PORT:-5055}"

exec "$PY" "$HERE/app.py"
