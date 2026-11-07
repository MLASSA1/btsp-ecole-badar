#!/bin/sh
# Run every test suite against a throwaway copy of the local database.
#   ./tests/run.sh
# Nothing touches database.db itself: harness.py copies it to a temp dir.
cd "$(dirname "$0")" || exit 1
ROOT="$(cd .. && pwd)"
PY=/Library/Developer/CommandLineTools/usr/bin/python3
[ -x "$PY" ] || PY=$(command -v python3)
export PYTHONPATH="$ROOT/venv/lib/python3.9/site-packages"
status=0
for t in test_phase12 test_phase3_online test_short_courses test_admin_sweep test_public_funnels; do
    out=$("$PY" "$t.py" 2>&1)
    printf '%-22s %4s ok   %s\n' "$t" "$(printf '%s\n' "$out" | grep -c '^  ok')" "$(printf '%s\n' "$out" | tail -1)"
    printf '%s\n' "$out" | grep '^  FAIL' && status=1
done
exit $status
