#!/bin/bash
# BTSP Website — pull the latest release onto a server already set up by
# deploy-vps.sh. Safe to run as often as you like.
#
#   sudo /opt/btsp/update-vps.sh
#
# Leaves .env, the uploads directory and the database untouched; only the
# code changes. New database columns are added by the app's own migration
# step when it restarts.

set -euo pipefail

APP_USER="btsp"
APP_DIR="/opt/btsp"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo." >&2
    exit 1
fi

echo "=== Updating BTSP ==="
BEFORE=$(sudo -u "$APP_USER" git -C "$APP_DIR" rev-parse --short HEAD)

sudo -u "$APP_USER" git -C "$APP_DIR" fetch --all --quiet
sudo -u "$APP_USER" git -C "$APP_DIR" reset --hard origin/main --quiet

AFTER=$(sudo -u "$APP_USER" git -C "$APP_DIR" rev-parse --short HEAD)
if [ "$BEFORE" = "$AFTER" ]; then
    echo "Already at $AFTER — nothing new to deploy."
else
    echo "$BEFORE -> $AFTER"
    sudo -u "$APP_USER" git -C "$APP_DIR" log --oneline "$BEFORE..$AFTER" | sed 's/^/  /'
fi

"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

systemctl restart btsp
sleep 2

if systemctl is-active --quiet btsp; then
    echo ""
    echo "Running commit $AFTER — service is up."
else
    echo ""
    echo "Service failed to start. Last lines:" >&2
    journalctl -u btsp -n 30 --no-pager >&2
    exit 1
fi
