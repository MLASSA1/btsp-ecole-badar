#!/bin/bash
# BTSP Website - Oracle Cloud Free Tier Deployment Script
# Run this on a fresh Oracle Linux / Ubuntu ARM VM
#
# Usage:
#   1. SSH into your Oracle Cloud VM
#   2. Clone your repo: git clone https://github.com/YOUR_USER/RHCE.git
#   3. cd RHCE/website
#   4. chmod +x deploy-oracle.sh
#   5. sudo ./deploy-oracle.sh your-domain.com

set -e

DOMAIN="${1:?Usage: sudo ./deploy-oracle.sh your-domain.com}"
APP_USER="btsp"
APP_DIR="/opt/btsp"
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== BTSP Deployment to Oracle Cloud ==="
echo "Domain: $DOMAIN"
echo ""

# --- Detect OS ---
if [ -f /etc/oracle-release ] || [ -f /etc/redhat-release ]; then
    PKG="dnf"
    echo "Detected: Oracle Linux / RHEL"
elif [ -f /etc/debian_version ]; then
    PKG="apt"
    echo "Detected: Ubuntu / Debian"
else
    echo "Unsupported OS. Use Oracle Linux or Ubuntu."
    exit 1
fi

# --- Install packages ---
echo ""
echo "=== Installing packages ==="
if [ "$PKG" = "dnf" ]; then
    dnf install -y python3 python3-pip python3-devel postgresql-server postgresql nginx certbot python3-certbot-nginx gcc
    # Init PostgreSQL if first time
    if [ ! -f /var/lib/pgsql/data/PG_VERSION ]; then
        postgresql-setup --initdb
    fi
    systemctl enable --now postgresql
    systemctl enable --now nginx
else
    apt update
    apt install -y python3 python3-pip python3-venv python3-dev postgresql postgresql-contrib nginx certbot python3-certbot-nginx gcc
    systemctl enable --now postgresql
    systemctl enable --now nginx
fi

# --- Create app user ---
echo ""
echo "=== Setting up app user ==="
id "$APP_USER" &>/dev/null || useradd -r -m -s /bin/bash "$APP_USER"

# --- Create PostgreSQL database ---
echo ""
echo "=== Setting up PostgreSQL ==="
DB_PASS=$(openssl rand -hex 16)
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='$APP_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $APP_USER WITH PASSWORD '$DB_PASS';"
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='btsp'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE btsp OWNER $APP_USER;"

# Update pg_hba.conf to allow password auth for local connections
PG_HBA=$(sudo -u postgres psql -t -c "SHOW hba_file;" | xargs)
if ! grep -q "btsp" "$PG_HBA" 2>/dev/null; then
    sed -i '/^local.*all.*all/i local   btsp        btsp                            md5' "$PG_HBA"
    systemctl reload postgresql
fi

# --- Copy app files ---
echo ""
echo "=== Deploying application ==="
mkdir -p "$APP_DIR"
cp -r "$REPO_DIR"/* "$APP_DIR"/
rm -rf "$APP_DIR/venv" "$APP_DIR/__pycache__" "$APP_DIR/database.db"

# Create uploads directory
mkdir -p "$APP_DIR/uploads"

# Create Python virtual environment
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt"

# Set ownership
chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# --- Create .env file ---
cat > "$APP_DIR/.env" <<EOF
DATABASE_URL=postgresql://$APP_USER:$DB_PASS@localhost/btsp
SECRET_KEY=$(openssl rand -hex 32)
EOF
chown "$APP_USER:$APP_USER" "$APP_DIR/.env"
chmod 600 "$APP_DIR/.env"

# --- Create systemd service ---
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

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now btsp

# --- Configure Nginx ---
echo ""
echo "=== Configuring Nginx ==="
cat > /etc/nginx/conf.d/btsp.conf <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    client_max_body_size 10M;

    location /uploads/ {
        alias $APP_DIR/uploads/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    location /static-site/ {
        alias $APP_DIR/;
        expires 7d;
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

# Remove default site if it exists
rm -f /etc/nginx/conf.d/default.conf
rm -f /etc/nginx/sites-enabled/default

nginx -t && systemctl reload nginx

# --- Open firewall ---
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

# --- SSL with Let's Encrypt ---
echo ""
echo "=== Setting up SSL ==="
echo "Attempting to get SSL certificate..."
echo "NOTE: Make sure your domain ($DOMAIN) A record points to this server's IP first!"
echo ""
certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email || {
    echo ""
    echo "SSL setup failed. This is normal if DNS isn't pointing here yet."
    echo "Once DNS is ready, run: sudo certbot --nginx -d $DOMAIN"
}

# --- Done ---
echo ""
echo "=========================================="
echo "  BTSP Deployment Complete!"
echo "=========================================="
echo ""
echo "  URL:      http://$DOMAIN"
echo "  Admin:    http://$DOMAIN/admin/login"
echo "  User:     admin"
echo "  Password: admin123  (CHANGE THIS!)"
echo ""
echo "  Database: postgresql://$APP_USER:****@localhost/btsp"
echo "  .env:     $APP_DIR/.env"
echo "  Logs:     journalctl -u btsp -f"
echo ""
echo "  To redeploy after code changes:"
echo "    cd $APP_DIR && sudo -u $APP_USER git pull"
echo "    sudo systemctl restart btsp"
echo ""
echo "  IMPORTANT: Also open ports 80 and 443 in Oracle Cloud"
echo "  Console > Networking > VCN > Security Lists > Ingress Rules"
echo "=========================================="
