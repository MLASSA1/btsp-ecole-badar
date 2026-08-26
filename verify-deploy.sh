#!/bin/bash
# Confirm the live site is really running the committed code.
#
# Run it after every release:  ./verify-deploy.sh
#
# It checks behaviour, not image digests. Comparing digests is what let a
# reverted deploy pass unnoticed: the local :latest tag had been replaced by
# the older image the server was running, so the comparison was the reverted
# image against itself and matched perfectly while the fixes were absent.

set -u
SITE="${1:-https://ecole-badar.visionxart.com}"
fails=0

check() {           # check <description> <actual> <expected>
    if [ "$2" = "$3" ]; then
        printf '  ok    %-42s %s\n' "$1" "$2"
    else
        printf '  FAIL  %-42s got %s, expected %s\n' "$1" "$2" "$3"
        fails=$((fails + 1))
    fi
}

code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "Verifying $SITE"
echo ""

check "homepage"            "$(code "$SITE/")"                      200
check "programme page"      "$(code "$SITE/formation/1")"           200
check "arabic homepage"     "$(code "$SITE/ar/")"                   200
check "admin login page"    "$(code "$SITE/admin/login")"           200
check "student login page"  "$(code "$SITE/student/login")"         200
check "diploma specimen"    "$(code "$SITE/uploads/diplome-specimen-btsp.jpg")" 200

echo ""
headers=$(curl -s -D - -o /dev/null "$SITE/")
for h in x-frame-options x-content-type-options referrer-policy content-security-policy; do
    check "header $h" "$(printf '%s' "$headers" | grep -ci "^$h:")" 1
done

echo ""
check "source not served"   "$(code "$SITE/static-site/app.py")"    404
check "database not served" "$(code "$SITE/static-site/database.db")" 404
check "cross-origin write refused" \
      "$(code -X POST -H 'Origin: https://evil.example' -d 'x=1' "$SITE/admin/paiements/mark")" 403

echo ""
# Seven failures against a name nobody uses; the seventh must be refused. The
# throttle counts in the database, so this holds across gunicorn workers.
probe="verify-probe-$$"
last=""
for i in 1 2 3 4 5 6 7; do
    last=$(code -X POST -d "username=$probe&password=wrong$i" "$SITE/admin/login")
done
check "brute-force cap (7th attempt)" "$last" 429

echo ""
images=$(curl -s "$SITE/" | grep -oE 'images\.unsplash\.com/photo-[a-z0-9-]+' | sort -u | wc -l | tr -d ' ')
if [ "$images" -ge 26 ]; then
    printf '  ok    %-42s %s unique\n' "programme photos" "$images"
else
    printf '  FAIL  %-42s %s unique, expected 26+\n' "programme photos" "$images"
    fails=$((fails + 1))
fi
check "iPhone viewport-fit" "$(curl -s "$SITE/" | grep -c 'viewport-fit=cover')" 1

echo ""
if [ "$fails" -eq 0 ]; then
    echo "All checks passed — the deployed site matches this release."
else
    echo "$fails check(s) failed. The server is NOT running this code."
    echo "Rebuild and redeploy, then run this again:"
    echo "  ssh visionxart"
    echo "  cd /opt/build/btsp-ecole-badar && git pull"
    echo "  docker build -t ghcr.io/visionxartorg/btsp-ecole-badar:latest ."
    echo "  docker push ghcr.io/visionxartorg/btsp-ecole-badar:latest"
    echo "  cd /opt/clients/btsp-ecole-badar && docker compose up -d"
    exit 1
fi
