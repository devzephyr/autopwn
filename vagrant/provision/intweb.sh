#!/usr/bin/env bash
# intweb.sh — Provision intweb.neutron.local (172.16.20.12)
# Services: DVWA + Apache2 + PHP + MySQL + HTTPS (DC-issued cert)
# Run as: root   |   Idempotent   |   Fully unattended
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[intweb] $(date '+%H:%M:%S') $*"; }

retry_curl() {
    local dest="$1" url="$2"
    curl --retry 3 --retry-delay 5 --retry-connrefused \
         --fail --silent --show-error \
         -o "$dest" "$url"
}

MARKER=/var/lib/.intweb_provisioned
if [[ -f "$MARKER" ]]; then
    log "Already provisioned (remove $MARKER to re-run). Exiting."
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. Hostname + static IP
# ---------------------------------------------------------------------------
log "--- Stage 1: Hostname + networking ---"

hostnamectl set-hostname intweb.neutron.local

NETPLAN_FILE=/etc/netplan/99-intweb-static.yaml
if [[ ! -f "$NETPLAN_FILE" ]]; then
    cat > "$NETPLAN_FILE" <<'NETPLAN'
network:
  version: 2
  ethernets:
    eth1:
      addresses:
        - 172.16.20.12/24
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
    log "Static IP applied: 172.16.20.12/24 gw 172.16.20.1 dns 172.16.10.10"
else
    log "Netplan config already present."
fi

grep -qF 'intweb.neutron.local' /etc/hosts \
    || echo '172.16.20.12 intweb.neutron.local intweb' >> /etc/hosts

# ---------------------------------------------------------------------------
# 2. Package installation
# ---------------------------------------------------------------------------
log "--- Stage 2: Package installation ---"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    apache2 \
    libapache2-mod-php8.1 \
    php8.1 \
    php8.1-mysql \
    php8.1-gd \
    php8.1-curl \
    php8.1-mbstring \
    php8.1-xml \
    php8.1-zip \
    mysql-server \
    git \
    curl \
    openssl \
    ca-certificates

a2enmod ssl rewrite headers
log "Packages installed."

# ---------------------------------------------------------------------------
# 3. TLS certificate from DC
# ---------------------------------------------------------------------------
log "--- Stage 3: Fetch TLS cert from DC (172.16.10.10) ---"

DC_HTTP="http://172.16.10.10"
CERT_DIR=/etc/ssl/neutron
mkdir -p "$CERT_DIR"

# Root CA
if [[ ! -f /usr/local/share/ca-certificates/neutron-root-ca.crt ]]; then
    log "Fetching neutron root CA..."
    retry_curl /usr/local/share/ca-certificates/neutron-root-ca.crt \
               "${DC_HTTP}/certs/neutron-root-ca.cer"
    update-ca-certificates
    log "Root CA installed."
else
    log "Root CA already installed."
fi

# Site cert (PFX)
if [[ ! -f "${CERT_DIR}/intweb.crt" || ! -f "${CERT_DIR}/intweb.key" ]]; then
    log "Fetching intweb.pfx from DC..."
    retry_curl /tmp/intweb.pfx "${DC_HTTP}/certs/intweb.pfx"

    openssl pkcs12 \
        -in /tmp/intweb.pfx \
        -clcerts -nokeys \
        -out "${CERT_DIR}/intweb.crt" \
        -passin pass:CertPass123 \
        2>/dev/null
    openssl pkcs12 \
        -in /tmp/intweb.pfx \
        -nocerts -nodes \
        -out "${CERT_DIR}/intweb.key" \
        -passin pass:CertPass123 \
        2>/dev/null

    chmod 640 "${CERT_DIR}/intweb.key"
    chown root:www-data "${CERT_DIR}/intweb.key"
    rm -f /tmp/intweb.pfx
    log "TLS cert + key written to ${CERT_DIR}."
else
    log "TLS cert already present."
fi

# ---------------------------------------------------------------------------
# 4. MySQL: DVWA database + user
# ---------------------------------------------------------------------------
log "--- Stage 4: MySQL setup ---"

systemctl enable --now mysql

DB_EXISTS=$(mysql -Nse "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA \
    WHERE SCHEMA_NAME='dvwa';" 2>/dev/null || true)

if [[ -z "$DB_EXISTS" ]]; then
    log "Creating dvwa database and user..."
    mysql -e "CREATE DATABASE IF NOT EXISTS dvwa CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    mysql -e "CREATE USER IF NOT EXISTS 'dvwa'@'localhost' IDENTIFIED BY 'dvwa';"
    mysql -e "GRANT ALL PRIVILEGES ON dvwa.* TO 'dvwa'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    log "DVWA database ready."
else
    log "DVWA database already exists."
fi

# ---------------------------------------------------------------------------
# 5. Clone DVWA
# ---------------------------------------------------------------------------
log "--- Stage 5: DVWA installation ---"

DVWA_DIR=/var/www/html/dvwa

if [[ ! -d "$DVWA_DIR/.git" ]]; then
    log "Cloning DVWA from GitHub..."
    git clone --depth=1 --quiet \
        https://github.com/digininja/DVWA.git "$DVWA_DIR"
    log "DVWA cloned."
else
    log "DVWA already cloned, pulling latest..."
    git -C "$DVWA_DIR" pull --quiet || true
fi

# DVWA config
DVWA_CFG="${DVWA_DIR}/config/config.inc.php"
if [[ ! -f "$DVWA_CFG" ]]; then
    log "Writing DVWA config..."
    cp "${DVWA_DIR}/config/config.inc.php.dist" "$DVWA_CFG"
fi

# Apply settings idempotently using sed
# db credentials
sed -i "s/\$_DVWA\[ 'db_password' \].*=.*/\$_DVWA[ 'db_password' ] = 'dvwa';/" "$DVWA_CFG"
sed -i "s/\$_DVWA\[ 'db_user' \].*=.*/\$_DVWA[ 'db_user' ] = 'dvwa';/" "$DVWA_CFG"
sed -i "s/\$_DVWA\[ 'db_database' \].*=.*/\$_DVWA[ 'db_database' ] = 'dvwa';/" "$DVWA_CFG"
sed -i "s/\$_DVWA\[ 'db_server' \].*=.*/\$_DVWA[ 'db_server' ] = '127.0.0.1';/" "$DVWA_CFG"
# Security level: low (makes SQLi and other vulns exploitable without auth bypass)
sed -i "s/\$_DVWA\[ 'default_security_level' \].*=.*/\$_DVWA[ 'default_security_level' ] = 'low';/" "$DVWA_CFG"
# Blank reCAPTCHA keys (not needed in lab)
sed -i "s/\$_DVWA\[ 'recaptcha_public_key' \].*=.*/\$_DVWA[ 'recaptcha_public_key' ] = '';/" "$DVWA_CFG"
sed -i "s/\$_DVWA\[ 'recaptcha_private_key' \].*=.*/\$_DVWA[ 'recaptcha_private_key' ] = '';/" "$DVWA_CFG"

chown -R www-data:www-data "$DVWA_DIR"
chmod -R 755 "$DVWA_DIR"
# DVWA needs write access to its config and hackable dirs
chmod -R 777 "${DVWA_DIR}/hackable/uploads"
chmod -R 777 "${DVWA_DIR}/config"
log "DVWA configured."

# ---------------------------------------------------------------------------
# 6. Apache vhost: HTTP + HTTPS
# ---------------------------------------------------------------------------
log "--- Stage 6: Apache virtual host ---"

# Disable the default site
a2dissite 000-default 2>/dev/null || true

VHOST_HTTP=/etc/apache2/sites-available/intweb-http.conf
cat > "$VHOST_HTTP" <<'APACHE_HTTP'
<VirtualHost *:80>
    ServerName  intweb.neutron.local
    ServerAlias intweb

    DocumentRoot /var/www/html
    DirectoryIndex index.php index.html

    # Redirect to HTTPS
    RewriteEngine On
    RewriteCond %{HTTPS} off
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

    ErrorLog  ${APACHE_LOG_DIR}/intweb_error.log
    CustomLog ${APACHE_LOG_DIR}/intweb_access.log combined
</VirtualHost>
APACHE_HTTP

VHOST_HTTPS=/etc/apache2/sites-available/intweb-https.conf
cat > "$VHOST_HTTPS" <<APACHE_HTTPS
<VirtualHost *:443>
    ServerName  intweb.neutron.local
    ServerAlias intweb

    DocumentRoot /var/www/html
    DirectoryIndex index.php index.html

    SSLEngine             on
    SSLCertificateFile    ${CERT_DIR}/intweb.crt
    SSLCertificateKeyFile ${CERT_DIR}/intweb.key
    SSLProtocol           all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite        HIGH:!aNULL:!MD5

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>

    <Directory /var/www/html/dvwa>
        AllowOverride All
        Require all granted
        Options FollowSymLinks
    </Directory>

    ErrorLog  \${APACHE_LOG_DIR}/intweb_ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/intweb_ssl_access.log combined
</VirtualHost>
APACHE_HTTPS

# Substitute the cert dir path (heredoc used literal to avoid expansion)
sed -i "s|\${CERT_DIR}|${CERT_DIR}|g" "$VHOST_HTTPS"

a2ensite intweb-http intweb-https
apache2ctl configtest
systemctl enable --now apache2
systemctl reload apache2
log "Apache vhosts active on 80 + 443."

# ---------------------------------------------------------------------------
# 7. Lab artefact: crontab entry with hardcoded credentials
# ---------------------------------------------------------------------------
log "--- Stage 7: Plant lab artefacts ---"

CRON_ENTRY='*/5 * * * * root /opt/scripts/backup.sh'
if ! grep -qF '/opt/scripts/backup.sh' /etc/crontab; then
    echo "$CRON_ENTRY" >> /etc/crontab
    log "Crontab entry added: $CRON_ENTRY"
else
    log "Crontab entry already present."
fi

# Create the backup script that postex.py can read for hardcoded creds
mkdir -p /opt/scripts
cat > /opt/scripts/backup.sh <<'BACKUP'
#!/usr/bin/env bash
# Database backup script
# TODO: move credentials to a secrets manager before prod deployment

DB_HOST=127.0.0.1
DB_NAME=dvwa
# Hardcoded for now — rotate before go-live
DB_USER=dvwa
DB_PASS=dvwa
BACKUP_DIR=/var/backups/db
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"
mysqldump -h"$DB_HOST" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" \
    > "${BACKUP_DIR}/dvwa_${TIMESTAMP}.sql"

# Remote sync — admin:BackupAdmin2024! on 172.16.10.50
# rsync -avz "$BACKUP_DIR/" admin@172.16.10.50:/backups/dvwa/

echo "Backup complete: ${BACKUP_DIR}/dvwa_${TIMESTAMP}.sql"
BACKUP

chmod 750 /opt/scripts/backup.sh
log "/opt/scripts/backup.sh created with hardcoded DB credentials."

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
touch "$MARKER"
log "=== intweb.neutron.local provisioning complete ==="
