#!/bin/bash
# BTSP Website — VPS deployment
#
# Sets up the site on a fresh Ubuntu/Debian or Oracle Linux/RHEL server:
# PostgreSQL, gunicorn under systemd, nginx in front, and a Let's Encrypt
# certificate. Run it once per server; use update-vps.sh for later releases.
#
# Usage (on the VPS, as root):
#   git clone https://github.com/MLASSA1/btsp-ecole-badar.git /opt/btsp-src
#   cd /opt/btsp-src
#   chmod +x deploy-vps.sh
#   sudo ./deploy-vps.sh btsp.ma admin@btsp.ma
#
# The domain's A record must already point at this server, otherwise the
# certificate step is skipped and you re-run certbot once DNS has caught up.

set -euo pipefail

DOMAIN="${1:?Usage: sudo ./deploy-vps.sh your-domain.com [admin-email]}"
LE_EMAIL="${2:-}"
APP_USER="btsp"
APP_DIR="/opt/btsp"
REPO_URL="${BTSP_REPO_URL:-https://github.com/MLASSA1/btsp-ecole-badar.git}"

echo "=== BTSP deployment ==="
echo "Domain: $DOMAIN"
echo "Source: $REPO_URL"
echo ""

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo." >&2
    exit 1
fi

# --- Detect OS ---
if [ -f /etc/oracle-release ] || [ -f /etc/redhat-release ]; then
    PKG="dnf"
    echo "Detected: Oracle Linux / RHEL"
elif [ -f /etc/debian_version ]; then
    PKG="apt"
    echo "Detected: Ubuntu / Debian"
else
    echo "Unsupported OS. Use Ubuntu/Debian or Oracle Linux/RHEL." >&2
    exit 1
fi

# --- Install packages ---
echo ""
echo "=== Installing packages ==="
if [ "$PKG" = "dnf" ]; then
    dnf install -y git python3 python3-pip python3-devel postgresql-server postgresql \
                   nginx certbot python3-certbot-nginx gcc openssl
    if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
        postgresql-setup --initdb
    fi
    systemctl enable --now postgresql
    systemctl enable --now nginx
else
    apt update
    apt install -y git python3 python3-pip python3-venv python3-dev postgresql postgresql-contrib \
                   nginx certbot python3-certbot-nginx gcc openssl
    systemctl enable --now postgresql
    systemctl enable --now nginx
fi

# --- Create app user ---
echo ""
echo "=== Setting up app user ==="
id "$APP_USER" &>/dev/null || useradd -r -m -s /bin/bash "$APP_USER"

# --- Fetch the code ---
#
# Clone rather than copy, so releases are a git pull instead of a manual
# re-upload and the server can always report exactly which commit it runs.
echo ""
echo "=== Fetching application ==="
if [ -d "$APP_DIR/.git" ]; then
    sudo -u "$APP_USER" git -C "$APP_DIR" fetch --all --quiet
    sudo -u "$APP_USER" git -C "$APP_DIR" reset --hard origin/main --quiet
else
    rm -rf "$APP_DIR"
    git clone --quiet "$REPO_URL" "$APP_DIR"
    chown -R "$APP_USER:$APP_USER" "$APP_DIR"
fi
mkdir -p "$APP_DIR/uploads"

# --- PostgreSQL ---
#
# SQLite is fine on a laptop but a single file on a server is a restore
# problem waiting to happen; pupil records and payments live in Postgres.
echo ""
echo "=== Setting up PostgreSQL ==="
if sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$APP_USER'" | grep -q 1; then
    echo "Role $APP_USER already exists — keeping its password."
    DB_PASS=""
else
    DB_PASS=$(openssl rand -hex 16)
    sudo -u postgres psql -c "CREATE USER $APP_USER WITH PASSWORD '$DB_PASS';"
fi
sudo -u postgres psql -tAc "SELECT 1 FROM pg_database WHERE datname='btsp'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE btsp OWNER $APP_USER;"

PG_HBA=$(sudo -u postgres psql -tAc "SHOW hba_file;" | xargs)
if ! grep -q "^local *btsp" "$PG_HBA" 2>/dev/null; then
    sed -i '/^local.*all.*all/i local   btsp        btsp                            md5' "$PG_HBA"
    systemctl reload postgresql
fi

# --- Python environment ---
echo ""
echo "=== Installing Python dependencies ==="
if [ ! -d "$APP_DIR/venv" ]; then
    python3 -m venv "$APP_DIR/venv"
fi
"$APP_DIR/venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# --- Environment file ---
#
# Written once and then left alone: regenerating SECRET_KEY would log every
# user out, and regenerating the admin password on each deploy is useless.
echo ""
echo "=== Writing environment ==="
ADMIN_PASS=""
if [ ! -f "$APP_DIR/.env" ]; then
    if [ -z "$DB_PASS" ]; then
        echo "Postgres role existed but .env is missing — set DATABASE_URL by hand." >&2
        DB_PASS="CHANGE_ME"
    fi
    ADMIN_PASS=$(openssl rand -base64 12 | tr -d '/+=' | cut -c1-16)
    cat > "$APP_DIR/.env" <<EOF
DATABASE_URL=postgresql://$APP_USER:$DB_PASS@localhost/btsp
SECRET_KEY=$(openssl rand -hex 32)
BTSP_ADMIN_USER=admin
BTSP_ADMIN_PASSWORD=$ADMIN_PASS
EOF
else
    echo "Keeping the existing $APP_DIR/.env"
fi
chown "$APP_USER:$APP_USER" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

# --- systemd service ---
echo ""
echo "=== Creating systemd service ==="
cat > /etc/systemd/system/btsp.service <<EOF
[Unit]
Description=BTSP Website
After=network.target postgresql.service

[Service]
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$APP_DIR/venv/bin/gunicorn app:app --bind 127.0.0.1:8000 --workers 2
Restart=always
RestartSec=5

# The app only ever writes to its own uploads directory.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now btsp
systemctl restart btsp

# --- nginx ---
#
# Note there is deliberately no `location /static-site/` alias here. That
# path maps to the application root, so aliasing the directory would let
# anyone download app.py, and .env with the database password and secret
# key inside it. The app whitelists the two public stylesheets itself.
echo ""
echo "=== Configuring nginx ==="
NGINX_CONF="/etc/nginx/conf.d/btsp.conf"
cat > "$NGINX_CONF" <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    client_max_body_size 10M;

    location /uploads/ {
        alias $APP_DIR/uploads/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

rm -f /etc/nginx/conf.d/default.conf /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# --- Firewall ---
echo ""
echo "=== Opening firewall ==="
if command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
elif command -v ufw &>/dev/null; then
    ufw allow 80/tcp
    ufw allow 443/tcp
fi

# --- HTTPS ---
echo ""
echo "=== Setting up HTTPS ==="
CERTBOT_ARGS=(--nginx -d "$DOMAIN" --non-interactive --agree-tos --redirect)
if [ -n "$LE_EMAIL" ]; then
    CERTBOT_ARGS+=(--email "$LE_EMAIL")
else
    # Without an address Let's Encrypt cannot warn you before expiry.
    CERTBOT_ARGS+=(--register-unsafely-without-email)
fi
certbot "${CERTBOT_ARGS[@]}" || {
    echo ""
    echo "Certificate not issued — usually DNS for $DOMAIN does not point here yet."
    echo "Once it does:  sudo certbot --nginx -d $DOMAIN --redirect"
}

# --- Done ---
echo ""
echo "=========================================="
echo "  BTSP deployment complete"
echo "=========================================="
echo ""
echo "  Site:   https://$DOMAIN"
echo "  Admin:  https://$DOMAIN/admin/login"
if [ -n "$ADMIN_PASS" ]; then
    echo ""
    echo "  First admin login"
    echo "    user:     admin"
    echo "    password: $ADMIN_PASS"
    echo "  Shown once. Save it now, then change it from Réglages after login."
else
    echo "  Admin credentials unchanged (see $APP_DIR/.env)."
fi
echo ""
echo "  Logs:      journalctl -u btsp -f"
echo "  Restart:   sudo systemctl restart btsp"
echo "  Update:    sudo $APP_DIR/update-vps.sh"
echo ""
if [ "$PKG" = "dnf" ]; then
    echo "  Oracle Cloud: also open 80 and 443 under"
    echo "  Networking > VCN > Security Lists > Ingress Rules"
fi
echo "=========================================="
