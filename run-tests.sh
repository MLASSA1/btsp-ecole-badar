#!/bin/sh
# Run every test suite (pages, admin show/hide, paid online courses, short
# courses, all routes, public forms) against a throwaway copy of database.db.
#   ./run-tests.sh
exec "$(dirname "$0")/tests/run.sh"
