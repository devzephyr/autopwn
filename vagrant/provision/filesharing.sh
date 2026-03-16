#!/usr/bin/env bash
# filesharing.sh — Provision filesharing.neutron.local (172.16.20.13)
# Services: Nextcloud + Apache2 + MySQL + NFS (DC-issued cert)
# Run as: root   |   Idempotent   |   Fully unattended
set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[filesharing] $(date '+%H:%M:%S') $*"; }

retry_curl() {
    local dest="$1" url="$2"
    curl --retry 3 --retry-delay 5 --retry-connrefused \
         --fail --silent --show-error \
         -o "$dest" "$url"
}

MARKER=/var/lib/.filesharing_provisioned
if [[ -f "$MARKER" ]]; then
    log "Already provisioned (remove $MARKER to re-run). Exiting."
    exit 0
fi

# ---------------------------------------------------------------------------
# 1. Hostname + static IP
# ---------------------------------------------------------------------------
log "--- Stage 1: Hostname + networking ---"

hostnamectl set-hostname filesharing.neutron.local

NETPLAN_FILE=/etc/netplan/99-filesharing-static.yaml
if [[ ! -f "$NETPLAN_FILE" ]]; then
    cat > "$NETPLAN_FILE" <<'NETPLAN'
network:
  version: 2
  ethernets:
    eth1:
      addresses:
        - 172.16.20.13/24
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
    log "Static IP applied: 172.16.20.13/24 gw 172.16.20.1 dns 172.16.10.10"
else
    log "Netplan config already present."
fi

grep -qF 'filesharing.neutron.local' /etc/hosts \
    || echo '172.16.20.13 filesharing.neutron.local filesharing' >> /etc/hosts

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
    php8.1-bz2 \
    php8.1-intl \
    php8.1-bcmath \
    php8.1-gmp \
    php8.1-imagick \
    php8.1-redis \
    mysql-server \
    nfs-kernel-server \
    curl \
    openssl \
    ca-certificates \
    bzip2 \
    unzip

a2enmod ssl rewrite headers env dir mime
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
if [[ ! -f "${CERT_DIR}/filesharing.crt" || ! -f "${CERT_DIR}/filesharing.key" ]]; then
    log "Fetching filesharing.pfx from DC..."
    retry_curl /tmp/filesharing.pfx "${DC_HTTP}/certs/filesharing.pfx"

    openssl pkcs12 \
        -in /tmp/filesharing.pfx \
        -clcerts -nokeys \
        -out "${CERT_DIR}/filesharing.crt" \
        -passin pass:CertPass123 \
        2>/dev/null
    openssl pkcs12 \
        -in /tmp/filesharing.pfx \
        -nocerts -nodes \
        -out "${CERT_DIR}/filesharing.key" \
        -passin pass:CertPass123 \
        2>/dev/null

    chmod 640 "${CERT_DIR}/filesharing.key"
    chown root:www-data "${CERT_DIR}/filesharing.key"
    rm -f /tmp/filesharing.pfx
    log "TLS cert + key written to ${CERT_DIR}."
else
    log "TLS cert already present."
fi

# ---------------------------------------------------------------------------
# 4. MySQL: Nextcloud database + user
# ---------------------------------------------------------------------------
log "--- Stage 4: MySQL setup ---"

systemctl enable --now mysql

DB_EXISTS=$(mysql -Nse "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA \
    WHERE SCHEMA_NAME='nextcloud';" 2>/dev/null || true)

if [[ -z "$DB_EXISTS" ]]; then
    log "Creating nextcloud database and user..."
    mysql -e "CREATE DATABASE IF NOT EXISTS nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
    mysql -e "CREATE USER IF NOT EXISTS 'ncuser'@'localhost' IDENTIFIED BY 'ncpass';"
    mysql -e "GRANT ALL PRIVILEGES ON nextcloud.* TO 'ncuser'@'localhost';"
    mysql -e "FLUSH PRIVILEGES;"
    log "Nextcloud database ready."
else
    log "Nextcloud database already exists."
fi

# ---------------------------------------------------------------------------
# 5. Download + extract Nextcloud
# ---------------------------------------------------------------------------
log "--- Stage 5: Nextcloud download ---"

NC_ROOT=/var/www/nextcloud

if [[ ! -f "${NC_ROOT}/index.php" ]]; then
    log "Downloading Nextcloud (latest)..."
    retry_curl /tmp/nextcloud-latest.tar.bz2 \
               "https://download.nextcloud.com/server/releases/latest.tar.bz2"
    log "Extracting Nextcloud..."
    tar xjf /tmp/nextcloud-latest.tar.bz2 -C /var/www/
    rm -f /tmp/nextcloud-latest.tar.bz2
    chown -R www-data:www-data "$NC_ROOT"
    log "Nextcloud extracted to ${NC_ROOT}."
else
    log "Nextcloud already extracted."
fi

# PHP memory/upload settings Nextcloud requires
PHP_INI=/etc/php/8.1/apache2/conf.d/99-nextcloud.ini
if [[ ! -f "$PHP_INI" ]]; then
    cat > "$PHP_INI" <<'PHPINI'
memory_limit = 512M
upload_max_filesize = 512M
post_max_size = 512M
max_execution_time = 300
date.timezone = America/Toronto
opcache.enable = 1
opcache.interned_strings_buffer = 8
opcache.max_accelerated_files = 10000
opcache.memory_consumption = 128
opcache.save_comments = 1
opcache.revalidate_freq = 1
PHPINI
    log "PHP INI tuning written."
fi

# ---------------------------------------------------------------------------
# 6. Nextcloud initial install via occ
# ---------------------------------------------------------------------------
log "--- Stage 6: Nextcloud occ install ---"

OCC_DONE="${NC_ROOT}/config/config.php"
if [[ ! -f "$OCC_DONE" ]]; then
    log "Running Nextcloud maintenance:install..."
    sudo -u www-data php "${NC_ROOT}/occ" maintenance:install \
        --database      mysql \
        --database-name nextcloud \
        --database-host 127.0.0.1 \
        --database-user ncuser \
        --database-pass ncpass \
        --admin-user    admin \
        --admin-pass    password \
        --data-dir      "${NC_ROOT}/data" \
        2>&1 | while IFS= read -r line; do log "occ: $line"; done

    # Allow access from any trusted domain (lab only)
    sudo -u www-data php "${NC_ROOT}/occ" config:system:set \
        trusted_domains 0 --value='filesharing.neutron.local'
    sudo -u www-data php "${NC_ROOT}/occ" config:system:set \
        trusted_domains 1 --value='172.16.20.13'
    sudo -u www-data php "${NC_ROOT}/occ" config:system:set \
        trusted_domains 2 --value='*'
    # Disable HTTPS-only enforcement so HTTP test paths still work
    sudo -u www-data php "${NC_ROOT}/occ" config:system:set \
        overwriteprotocol --value='https'
    sudo -u www-data php "${NC_ROOT}/occ" config:system:set \
        overwrite.cli.url --value="https://filesharing.neutron.local"

    log "Nextcloud installed. admin / password"
else
    log "Nextcloud config.php already exists, skipping occ install."
fi

chown -R www-data:www-data "$NC_ROOT"

# ---------------------------------------------------------------------------
# 7. Apache vhost: HTTPS with DC cert
# ---------------------------------------------------------------------------
log "--- Stage 7: Apache virtual host ---"

a2dissite 000-default 2>/dev/null || true

VHOST_HTTP=/etc/apache2/sites-available/filesharing-http.conf
cat > "$VHOST_HTTP" <<'APACHE_HTTP'
<VirtualHost *:80>
    ServerName  filesharing.neutron.local
    ServerAlias filesharing

    RewriteEngine On
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]

    ErrorLog  ${APACHE_LOG_DIR}/filesharing_error.log
    CustomLog ${APACHE_LOG_DIR}/filesharing_access.log combined
</VirtualHost>
APACHE_HTTP

VHOST_HTTPS=/etc/apache2/sites-available/filesharing-https.conf
cat > "$VHOST_HTTPS" <<APACHE_HTTPS
<VirtualHost *:443>
    ServerName  filesharing.neutron.local
    ServerAlias filesharing

    DocumentRoot /var/www/nextcloud

    SSLEngine             on
    SSLCertificateFile    ${CERT_DIR}/filesharing.crt
    SSLCertificateKeyFile ${CERT_DIR}/filesharing.key
    SSLProtocol           all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite        HIGH:!aNULL:!MD5

    <Directory /var/www/nextcloud>
        Options     +FollowSymLinks
        AllowOverride All
        Require all granted
        Satisfy Any
    </Directory>

    <IfModule mod_headers.c>
        Header always set Strict-Transport-Security "max-age=15552000; includeSubDomains"
    </IfModule>

    ErrorLog  \${APACHE_LOG_DIR}/filesharing_ssl_error.log
    CustomLog \${APACHE_LOG_DIR}/filesharing_ssl_access.log combined
</VirtualHost>
APACHE_HTTPS

# Expand the cert path variable into the vhost file
sed -i "s|\${CERT_DIR}|${CERT_DIR}|g" "$VHOST_HTTPS"

a2ensite filesharing-http filesharing-https
apache2ctl configtest
systemctl enable --now apache2
systemctl reload apache2
log "Apache vhosts active on 80 + 443."

# ---------------------------------------------------------------------------
# 8. NFS export
# ---------------------------------------------------------------------------
log "--- Stage 8: NFS export setup ---"

NFS_SHARE=/srv/files
mkdir -p "$NFS_SHARE"

# Plant sensitive lab files for postex.py to discover
if [[ ! -f "${NFS_SHARE}/passwords.txt" ]]; then
    log "Planting lab artefacts in ${NFS_SHARE}..."

    cat > "${NFS_SHARE}/passwords.txt" <<'PWFILE'
# Internal credential store - DO NOT DISTRIBUTE
# Last updated: 2025-11-15

Service Accounts
----------------
svc_backup        : BackupSvc2024!
svc_monitoring    : Monitor@2024
svc_sqlreport     : SQLReport#99

Windows Admin Accounts
----------------------
administrator     : P@ssw0rd2024!
dc01\administrator: NeutronDC@2024

Linux Accounts
--------------
root              : toor
vagrant           : vagrant
ubuntu            : ubuntu

Database Credentials
--------------------
MySQL root        : (empty)
dvwa db user      : dvwa / dvwa
nextcloud db user : ncuser / ncpass
wordpress db user : wpuser / wppass
PWFILE

    cat > "${NFS_SHARE}/backup.sql" <<'SQLFILE'
-- MySQL dump extracted from corpweb.neutron.local
-- Host: localhost    Database: wordpress
-- Credentials: wpuser / wppass
-- Server version: 8.0.31

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;

--
-- Table structure for table `wp_users`
--
CREATE TABLE IF NOT EXISTS `wp_users` (
  `ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `user_login` varchar(60) NOT NULL DEFAULT '',
  `user_pass` varchar(255) NOT NULL DEFAULT '',
  `user_email` varchar(100) NOT NULL DEFAULT '',
  PRIMARY KEY (`ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Dumping data for table `wp_users`
--
INSERT INTO `wp_users` VALUES
(1,'admin','$P$BicGn8v0RWBfaXWCi9yB3FHzVF8GKr/','admin@neutron.local'),
(2,'jsmith','$P$BaDPass123abc456def789ghi012jkl','jsmith@neutron.local'),
(3,'svc_backup','$P$BSvcBackup2024abcdefghijk','svc_backup@neutron.local');

-- Plaintext reference (from old config backup - DELETE ME)
-- admin:password
-- jsmith:Password123
-- svc_backup:BackupSvc2024!
SQLFILE

    # Fake SSH private key (RSA-format structure, not a real key)
    cat > "${NFS_SHARE}/id_rsa" <<'KEYFILE'
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4Bq/PHKOT6MlfT7YRQV0MmXbzW
qMNRqiA6z/lFcHEXz5QiEgzPdFSREMPHaO2ZmCmtfkSOhKMOSuMFB4lpWGYJhY5
xEm9SkFqbxs4kJ8sCxUzYfvSj6ZOLVHZnFxuRCIxA1HxFJnFmz8smO0kLHAaYWm
--- TRUNCATED FOR SECURITY --- rotate this key immediately ---
svc_backup@neutron.local 2024-03-01
-----END RSA PRIVATE KEY-----
KEYFILE

    chmod 644 "${NFS_SHARE}/passwords.txt"
    chmod 644 "${NFS_SHARE}/backup.sql"
    chmod 600 "${NFS_SHARE}/id_rsa"
    chown -R nobody:nogroup "$NFS_SHARE" 2>/dev/null || chown -R root:root "$NFS_SHARE"
    log "Lab artefacts planted in ${NFS_SHARE}."
else
    log "Lab artefacts already present."
fi

# /etc/exports entry
EXPORTS_ENTRY="${NFS_SHARE}  *(rw,sync,no_subtree_check,no_root_squash)"
if ! grep -qF "$NFS_SHARE" /etc/exports; then
    echo "$EXPORTS_ENTRY" >> /etc/exports
    log "/etc/exports updated: ${EXPORTS_ENTRY}"
else
    log "/etc/exports entry already present."
fi

systemctl enable --now nfs-kernel-server
exportfs -ra
log "NFS exports active. Verify with: showmount -e 172.16.20.13"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
touch "$MARKER"
log "=== filesharing.neutron.local provisioning complete ==="
