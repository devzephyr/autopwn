#!/usr/bin/env bash
# corpweb.sh — Provision corpweb.neutron.local (172.16.20.11)
# Services: WordPress + nginx + PHP-FPM + MySQL + HTTPS (DC-issued cert)
# Run as: root   |   Idempotent   |   Fully unattended
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[corpweb] $(date '+%H:%M:%S') $*"; }

retry_curl() {
    # retry_curl <dest> <url>  — fetches URL to dest, retries up to 3 times
    local dest="$1" url="$2"
    curl --retry 3 --retry-delay 5 --retry-connrefused \
         --fail --silent --show-error \
         -o "$dest" "$url"
}

MARKER=/var/lib/.corpweb_provisioned
if [[ -f "$MARKER" ]]; then
    log "Already provisioned (remove $MARKER to re-run). Exiting."
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. Hostname + static IP
# ---------------------------------------------------------------------------
log "--- Stage 1: Hostname + networking ---"

hostnamectl set-hostname corpweb.neutron.local

NETPLAN_FILE=/etc/netplan/99-corpweb-static.yaml
if [[ ! -f "$NETPLAN_FILE" ]]; then
    cat > "$NETPLAN_FILE" <<'NETPLAN'
network:
  version: 2
  ethernets:
    eth1:
      addresses:
        - 172.16.20.11/24
      routes:
        - to: default
          via: 172.16.20.1
      nameservers:
        addresses:
          - 172.16.10.10
        search:
          - neutron.local
      dhcp4: false
NETPLAN
    chmod 600 "$NETPLAN_FILE"
    netplan apply || true
    log "Static IP applied: 172.16.20.11/24 gw 172.16.20.1 dns 172.16.10.10"
else
    log "Netplan config already present, skipping."
fi

# Ensure /etc/hosts has local entry (helps WP-CLI URL resolution)
grep -qF 'corpweb.neutron.local' /etc/hosts \
    || echo '172.16.20.11 corpweb.neutron.local corpweb' >> /etc/hosts

# ---------------------------------------------------------------------------
# 2. Package installation
# ---------------------------------------------------------------------------
log "--- Stage 2: Package installation ---"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    nginx \
    php8.1-fpm \
    php8.1-mysql \
    php8.1-curl \
    php8.1-gd \
    php8.1-mbstring \
    php8.1-xml \
    php8.1-zip \
    mysql-server \
    curl \
    openssl \
    ca-certificates \
    unzip

log "Packages installed."

# ---------------------------------------------------------------------------
# 3. TLS certificate from DC
# ---------------------------------------------------------------------------
log "--- Stage 3: Fetch TLS cert from DC (172.16.10.10) ---"

DC_HTTP="http://172.16.10.10"
CERT_DIR=/etc/nginx/certs
mkdir -p "$CERT_DIR"

# Root CA — install into system trust store
if [[ ! -f /usr/local/share/ca-certificates/neutron-root-ca.crt ]]; then
    log "Fetching neutron root CA..."
    retry_curl /usr/local/share/ca-certificates/neutron-root-ca.crt \
               "${DC_HTTP}/certs/neutron-root-ca.cer"
    update-ca-certificates
    log "Root CA installed."
else
    log "Root CA already installed, skipping."
fi

# Site cert (PFX)
if [[ ! -f "${CERT_DIR}/corpweb.crt" || ! -f "${CERT_DIR}/corpweb.key" ]]; then
    log "Fetching corpweb.pfx from DC..."
    retry_curl /tmp/corpweb.pfx "${DC_HTTP}/certs/corpweb.pfx"

    openssl pkcs12 \
        -in /tmp/corpweb.pfx \
        -clcerts -nokeys \
        -out "${CERT_DIR}/corpweb.crt" \
        -passin pass:CertPass123 \
        2>/dev/null
    openssl pkcs12 \
        -in /tmp/corpweb.pfx \
        -nocerts -nodes \
        -out "${CERT_DIR}/corpweb.key" \
        -passin pass:CertPass123 \
        2>/dev/null

    chmod 640 "${CERT_DIR}/corpweb.key"
    chown root:www-data "${CERT_DIR}/corpweb.key"
    rm -f /tmp/corpweb.pfx
    log "TLS cert + key written to ${CERT_DIR}."
else
    log "TLS cert already present, skipping."
fi

# ---------------------------------------------------------------------------
# 4. MySQL: WordPress database + user
# ---------------------------------------------------------------------------
log "--- Stage 4: MySQL setup ---"

systemctl enable --now mysql

# Idempotent: only run if the DB does not already exist
DB_EXISTS=$(mysql -Nse "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA \
    WHERE SCHEMA_NAME='wordpress';" 2>/dev/null || true)

if [[ -z "$DB_EXISTS" ]]; then
    log "Creating wordpress database and user..."
    mysql -e "CREATE DATABASE IF NOT EXISTS wordpress CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -e "CREATE USER IF NOT EXISTS 'wpuser'@'localhost' IDENTIFIED BY 'wppass';"
    mysql -e "GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    log "Database ready."
else
    log "WordPress database already exists, skipping."
fi

# ---------------------------------------------------------------------------
# 5. WordPress download + WP-CLI install
# ---------------------------------------------------------------------------
log "--- Stage 5: WordPress + WP-CLI ---"

WP_ROOT=/var/www/wordpress

# WP-CLI
if [[ ! -x /usr/local/bin/wp ]]; then
    log "Installing WP-CLI..."
    retry_curl /usr/local/bin/wp \
               "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp.phar"
    chmod +x /usr/local/bin/wp
    log "WP-CLI installed."
else
    log "WP-CLI already installed."
fi

# WordPress core files
if [[ ! -f "${WP_ROOT}/wp-includes/version.php" ]]; then
    log "Downloading WordPress..."
    retry_curl /tmp/wordpress-latest.tar.gz \
               "https://wordpress.org/latest.tar.gz"
    tar xzf /tmp/wordpress-latest.tar.gz -C /var/www/
    rm -f /tmp/wordpress-latest.tar.gz
    chown -R www-data:www-data "$WP_ROOT"
    log "WordPress extracted to ${WP_ROOT}."
else
    log "WordPress already extracted."
fi

# wp-config.php
if [[ ! -f "${WP_ROOT}/wp-config.php" ]]; then
    log "Generating wp-config.php..."
    wp config create \
        --path="$WP_ROOT" \
        --dbname=wordpress \
        --dbuser=wpuser \
        --dbpass=wppass \
        --dbhost=localhost \
        --allow-root \
        --quiet
    log "wp-config.php created."
else
    log "wp-config.php already exists."
fi

# Core install (sets admin credentials)
WP_INSTALLED=$(wp core is-installed --path="$WP_ROOT" --allow-root 2>&1 || true)
if echo "$WP_INSTALLED" | grep -qi 'not installed\|error\|Error'; then
    log "Running WordPress core install..."
    wp core install \
        --path="$WP_ROOT" \
        --url="https://corpweb.neutron.local" \
        --title="Neutron Corp Intranet" \
        --admin_user=admin \
        --admin_password=password \
        --admin_email=admin@neutron.local \
        --allow-root \
        --quiet
    log "WordPress installed. admin / password"
else
    log "WordPress already installed."
fi

chown -R www-data:www-data "$WP_ROOT"
find "$WP_ROOT" -type d -exec chmod 755 {} \;
find "$WP_ROOT" -type f -exec chmod 644 {} \;

# ---------------------------------------------------------------------------
# 6. nginx vhost: HTTP -> HTTPS redirect + HTTPS with DC cert
# ---------------------------------------------------------------------------
log "--- Stage 6: nginx virtual host ---"

VHOST=/etc/nginx/sites-available/corpweb
cat > "$VHOST" <<'NGINX'
# HTTP: redirect everything to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name corpweb.neutron.local www.neutron.local;
    return 301 https://$host$request_uri;
}

# HTTPS: WordPress
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name corpweb.neutron.local www.neutron.local;

    root /var/www/wordpress;
    index index.php index.html;

    ssl_certificate     /etc/nginx/certs/corpweb.crt;
    ssl_certificate_key /etc/nginx/certs/corpweb.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_session_cache   shared:SSL:10m;
    ssl_session_timeout 10m;

    # WordPress pretty permalinks
    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location ~ /\.ht {
        deny all;
    }

    # Expose wp-login.php (intentionally weak for lab)
    location = /wp-login.php {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
    }

    access_log /var/log/nginx/corpweb_access.log;
    error_log  /var/log/nginx/corpweb_error.log;
}
NGINX

# Enable site, disable default
ln -sf "$VHOST" /etc/nginx/sites-enabled/corpweb
rm -f /etc/nginx/sites-enabled/default

nginx -t
systemctl enable --now nginx
systemctl enable --now php8.1-fpm
systemctl reload nginx
log "nginx vhost active."

# ---------------------------------------------------------------------------
# 7. Sensitive file for postex.py to find
# ---------------------------------------------------------------------------
log "--- Stage 7: Plant lab artefacts ---"

# .env in web root (postex.py Linux command: cat /var/www/html/.env)
cat > /var/www/html/.env <<'ENV'
DB_HOST=localhost
DB_NAME=wordpress
DB_USER=wpuser
DB_PASSWORD=wppass
SECRET_KEY=abc123secret
APP_ENV=production
SMTP_PASSWORD=MailPass2024!
ENV
chown www-data:www-data /var/www/html/.env
chmod 640 /var/www/html/.env
log ".env planted at /var/www/html/.env"

# Also place one inside the WordPress tree so wp-config scrape path works
cp /var/www/html/.env "${WP_ROOT}/.env"
chown www-data:www-data "${WP_ROOT}/.env"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
touch "$MARKER"
log "=== corpweb.neutron.local provisioning complete ==="
