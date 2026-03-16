#!/usr/bin/env bash
# =============================================================================
# esite.sh — Provision script for esite.neutron.local (172.16.20.14)
# Ubuntu 22.04, runs as root, fully unattended, idempotent
# Services: Apache2 + PHP 8.1 + MySQL (empty root password) + Redis
# Intentional vulnerabilities for lab exploitation testing:
#   - MySQL root with no password (exploit_mysql target)
#   - Redis bound to 0.0.0.0, no auth (exploit_redis target)
#   - PHP page with unsanitised GET parameter (sqlmap / exploit_dvwa-style target)
#   - SSH key artifact left in /tmp and /root (postex finding)
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# 0. Helpers
# ---------------------------------------------------------------------------
log() { echo "[esite] $(date +%H:%M:%S) $*"; }

IFACE="eth1"          # Vagrant typically places the private network on eth1
IP="172.16.20.14"
PREFIX="24"
GATEWAY="172.16.20.1"
DNS="172.16.10.10"
HOSTNAME="esite.neutron.local"
DC_CERT_URL="http://172.16.10.10/certs/neutron-root-ca.cer"

# ---------------------------------------------------------------------------
# 1. Hostname
# ---------------------------------------------------------------------------
log "Setting hostname to ${HOSTNAME}"
if [[ "$(hostname)" != "${HOSTNAME}" ]]; then
    hostnamectl set-hostname "${HOSTNAME}"
fi
grep -qxF "127.0.1.1 ${HOSTNAME}" /etc/hosts \
    || echo "127.0.1.1 ${HOSTNAME}" >> /etc/hosts

# ---------------------------------------------------------------------------
# 2. Static IP — write netplan only if the file is missing or stale
# ---------------------------------------------------------------------------
NETPLAN_FILE="/etc/netplan/99-esite.yaml"
log "Configuring static IP ${IP}/${PREFIX} on ${IFACE}"
cat > "${NETPLAN_FILE}" <<NETPLAN
network:
  version: 2
  ethernets:
    ${IFACE}:
      addresses:
        - ${IP}/${PREFIX}
      routes:
        - to: default
          via: ${GATEWAY}
      nameservers:
        addresses: [${DNS}]
      dhcp4: false
NETPLAN
chmod 600 "${NETPLAN_FILE}"
netplan apply || true     # non-fatal: Vagrant may already manage eth0

# ---------------------------------------------------------------------------
# 3. Package installation
# ---------------------------------------------------------------------------
log "Updating apt cache"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

log "Installing Apache, PHP 8.1, MySQL, Redis"
apt-get install -y -qq \
    apache2 \
    php8.1 \
    libapache2-mod-php8.1 \
    php8.1-mysql \
    php8.1-cli \
    mysql-server \
    redis-server \
    curl \
    openssl

# ---------------------------------------------------------------------------
# 4. Fetch TLS certificate from DC
# ---------------------------------------------------------------------------
log "Fetching Neutron Root CA from DC at ${DNS}"
CA_DEST="/usr/local/share/ca-certificates/neutron-root-ca.crt"
if [[ ! -f "${CA_DEST}" ]]; then
    curl -sf --retry 5 --retry-delay 3 \
        "${DC_CERT_URL}" -o "${CA_DEST}" \
        || log "WARNING: Could not fetch DC cert — HTTPS vhost will use self-signed"
fi
update-ca-certificates --fresh 2>/dev/null || true

# Generate a self-signed cert for esite if we did not get the DC-signed one
CERT_DIR="/etc/ssl/esite"
mkdir -p "${CERT_DIR}"
if [[ ! -f "${CERT_DIR}/esite.crt" ]]; then
    log "Generating self-signed TLS cert for ${HOSTNAME}"
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout "${CERT_DIR}/esite.key" \
        -out    "${CERT_DIR}/esite.crt" \
        -subj "/CN=${HOSTNAME}/O=Neutron Lab/C=CA" \
        -addext "subjectAltName=DNS:${HOSTNAME},IP:${IP}" \
        2>/dev/null
fi

# ---------------------------------------------------------------------------
# 5. MySQL setup
# ---------------------------------------------------------------------------
log "Configuring MySQL"

# Ensure MySQL is running before we touch it
systemctl enable mysql --quiet
systemctl start  mysql

# Allow remote connections (bind to all interfaces)
MYSQL_CONF="/etc/mysql/mysql.conf.d/mysqld.cnf"
if grep -q "^bind-address" "${MYSQL_CONF}"; then
    sed -i 's/^bind-address.*/bind-address = 0.0.0.0/' "${MYSQL_CONF}"
else
    echo "bind-address = 0.0.0.0" >> "${MYSQL_CONF}"
fi

# Idempotent SQL setup — wrap in a single mysql call so it is re-runnable
mysql --user=root <<'SQL'
-- Remove root password (lab intentional misconfiguration)
ALTER USER IF EXISTS 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '';
ALTER USER IF EXISTS 'root'@'%'        IDENTIFIED WITH mysql_native_password BY '';
FLUSH PRIVILEGES;

-- Shop database
CREATE DATABASE IF NOT EXISTS shop CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- shopuser
CREATE USER IF NOT EXISTS 'shopuser'@'%' IDENTIFIED BY 'shoppass';
GRANT ALL PRIVILEGES ON shop.* TO 'shopuser'@'%';

-- Products table
CREATE TABLE IF NOT EXISTS shop.products (
    id    INT          NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name  VARCHAR(100) NOT NULL,
    price DECIMAL(8,2) NOT NULL
);

-- Seed products (INSERT IGNORE keeps it idempotent)
INSERT IGNORE INTO shop.products (id, name, price) VALUES
    (1, 'Widget Pro',     19.99),
    (2, 'Gadget Ultra',   49.99),
    (3, 'Doohickey Plus',  9.99),
    (4, 'Thingamajig',    34.99),
    (5, 'Whatsit Deluxe', 74.99);

-- Users table with MD5-hashed password (deliberately weak)
CREATE TABLE IF NOT EXISTS shop.users (
    id       INT         NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(100) NOT NULL
);

-- admin / password — MD5('password') = 5f4dcc3b5aa765d61d8327deb882cf99
INSERT IGNORE INTO shop.users (id, username, password) VALUES
    (1, 'admin',   MD5('password')),
    (2, 'jsmith',  MD5('Password123')),
    (3, 'dbadmin', MD5('dbadmin2024'));

FLUSH PRIVILEGES;
SQL

# Restart MySQL to pick up bind-address change
systemctl restart mysql

# ---------------------------------------------------------------------------
# 6. PHP e-commerce page with deliberate SQL injection
# ---------------------------------------------------------------------------
log "Writing vulnerable PHP e-commerce application to /var/www/html"

# Remove default Apache placeholder
rm -f /var/www/html/index.html

cat > /var/www/html/index.php <<'PHP'
<?php
/**
 * Neutron E-Site — deliberately vulnerable e-commerce page
 * SQLi vector: GET parameter 'id' is passed raw into the query.
 * For lab / sqlmap testing ONLY.
 */
$host   = 'localhost';
$dbuser = 'shopuser';
$dbpass = 'shoppass';
$dbname = 'shop';

$conn = mysqli_connect($host, $dbuser, $dbpass, $dbname);
if (!$conn) {
    die('<p>Database connection failed: ' . mysqli_connect_error() . '</p>');
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Neutron E-Site — Product Catalogue</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        h1   { color: #333; }
        table { border-collapse: collapse; width: 60%; background: #fff; }
        th, td { border: 1px solid #ccc; padding: 8px 14px; }
        th { background: #4a90e2; color: #fff; }
        .search { margin-bottom: 20px; }
        input[type=text] { padding: 6px; width: 200px; }
        input[type=submit] { padding: 6px 14px; }
    </style>
</head>
<body>
<h1>Neutron E-Site</h1>
<h2>Product Catalogue</h2>

<div class="search">
    <form method="GET" action="">
        <label for="id">Search by Product ID:</label>
        <input type="text" name="id" id="id"
               value="<?php echo isset($_GET['id']) ? htmlspecialchars($_GET['id']) : ''; ?>">
        <input type="submit" value="Search">
    </form>
</div>

<?php
/* -----------------------------------------------------------------------
 * INTENTIONAL SQL INJECTION VULNERABILITY
 * $id is taken directly from user input with NO sanitization.
 * Payload example: ?id=1 UNION SELECT username,password,1 FROM users--
 * ----------------------------------------------------------------------- */
if (isset($_GET['id']) && $_GET['id'] !== '') {
    $id     = $_GET['id'];                        // NO sanitization — intentional
    $sql    = "SELECT * FROM products WHERE id=$id";
    $result = mysqli_query($conn, $sql);

    if ($result && mysqli_num_rows($result) > 0) {
        echo '<table>';
        echo '<tr><th>ID</th><th>Name</th><th>Price (CAD)</th></tr>';
        while ($row = mysqli_fetch_assoc($result)) {
            echo '<tr>';
            echo '<td>' . htmlspecialchars($row['id'])    . '</td>';
            echo '<td>' . htmlspecialchars($row['name'])  . '</td>';
            echo '<td>$' . htmlspecialchars($row['price']) . '</td>';
            echo '</tr>';
        }
        echo '</table>';
    } else {
        echo '<p>No products found for that ID.</p>';
    }
} else {
    /* Show full catalogue by default */
    $result = mysqli_query($conn, "SELECT * FROM products ORDER BY id");
    if ($result && mysqli_num_rows($result) > 0) {
        echo '<table>';
        echo '<tr><th>ID</th><th>Name</th><th>Price (CAD)</th></tr>';
        while ($row = mysqli_fetch_assoc($result)) {
            echo '<tr>';
            echo '<td>' . htmlspecialchars($row['id'])    . '</td>';
            echo '<td>' . htmlspecialchars($row['name'])  . '</td>';
            echo '<td>$' . htmlspecialchars($row['price']) . '</td>';
            echo '</tr>';
        }
        echo '</table>';
    }
}
mysqli_close($conn);
?>
<hr>
<p><small>esite.neutron.local &mdash; Neutron Enterprise Lab</small></p>
</body>
</html>
PHP

# Ensure Apache can serve it
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

# ---------------------------------------------------------------------------
# 7. Apache virtual hosts (HTTP + HTTPS)
# ---------------------------------------------------------------------------
log "Configuring Apache virtual hosts"

a2enmod ssl rewrite headers 2>/dev/null || true

# HTTP vhost
cat > /etc/apache2/sites-available/esite-http.conf <<APACHEHTTP
<VirtualHost *:80>
    ServerName ${HOSTNAME}
    ServerAlias esite
    DocumentRoot /var/www/html

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
        Options -Indexes +FollowSymLinks
    </Directory>

    ErrorLog  \${APACHE_LOG_DIR}/esite-error.log
    CustomLog \${APACHE_LOG_DIR}/esite-access.log combined
</VirtualHost>
APACHEHTTP

# HTTPS vhost
cat > /etc/apache2/sites-available/esite-https.conf <<APACHEHTTPS
<VirtualHost *:443>
    ServerName ${HOSTNAME}
    ServerAlias esite
    DocumentRoot /var/www/html

    SSLEngine on
    SSLCertificateFile    ${CERT_DIR}/esite.crt
    SSLCertificateKeyFile ${CERT_DIR}/esite.key

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
        Options -Indexes +FollowSymLinks
    </Directory>

    ErrorLog  \${APACHE_LOG_DIR}/esite-ssl-error.log
    CustomLog \${APACHE_LOG_DIR}/esite-ssl-access.log combined
</VirtualHost>
APACHEHTTPS

a2dissite 000-default.conf 2>/dev/null || true
a2ensite esite-http.conf esite-https.conf 2>/dev/null || true

systemctl enable apache2 --quiet
systemctl restart apache2

# ---------------------------------------------------------------------------
# 8. Redis — bind all interfaces, no auth, protected-mode off
# ---------------------------------------------------------------------------
log "Configuring Redis (no-auth, bind 0.0.0.0)"

REDIS_CONF="/etc/redis/redis.conf"

# bind: replace existing bind directive
if grep -q "^bind " "${REDIS_CONF}"; then
    sed -i 's/^bind .*/bind 0.0.0.0/' "${REDIS_CONF}"
else
    echo "bind 0.0.0.0" >> "${REDIS_CONF}"
fi

# protected-mode off
if grep -q "^protected-mode" "${REDIS_CONF}"; then
    sed -i 's/^protected-mode.*/protected-mode no/' "${REDIS_CONF}"
else
    echo "protected-mode no" >> "${REDIS_CONF}"
fi

# requirepass — ensure it is absent / commented out
sed -i 's/^requirepass/#requirepass/' "${REDIS_CONF}"

systemctl enable redis-server --quiet
systemctl restart redis-server

# ---------------------------------------------------------------------------
# 9. SSH key artifact (intentional postex finding)
# ---------------------------------------------------------------------------
log "Placing SSH key artifact for postex discovery"

# Ensure vagrant home .ssh exists
VAGRANT_SSH_DIR="/home/vagrant/.ssh"
mkdir -p "${VAGRANT_SSH_DIR}"
chmod 700 "${VAGRANT_SSH_DIR}"

# Copy authorized_keys to a "backup" in /tmp — simulates sloppy admin
if [[ -f "${VAGRANT_SSH_DIR}/authorized_keys" ]]; then
    cp "${VAGRANT_SSH_DIR}/authorized_keys" /tmp/id_rsa_backup
    chmod 644 /tmp/id_rsa_backup
fi

# Drop a fake private key comment in /root — realistic postex breadcrumb
mkdir -p /root/.ssh
cat >> /root/.ssh_backup_key <<'FAKEKEY'
# SSH key backup - DO NOT COMMIT
# Generated: 2026-01-15 by sysadmin@neutron.local
# Target: esite.neutron.local
# This file is a configuration artifact — key material stored in vault.
FAKEKEY
chmod 600 /root/.ssh_backup_key

# Also drop a plaintext creds file that postex.py will discover via find
cat > /var/www/html/.env <<'ENVFILE'
# Application environment — esite.neutron.local
APP_ENV=production
DB_HOST=localhost
DB_NAME=shop
DB_USER=shopuser
DB_PASS=shoppass
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
ADMIN_USER=admin
ADMIN_PASS=password
ENVFILE
chmod 644 /var/www/html/.env

# ---------------------------------------------------------------------------
# 10. Firewall: open required ports
# ---------------------------------------------------------------------------
log "Opening firewall ports: 22, 80, 443, 3306, 6379"
if command -v ufw &>/dev/null; then
    ufw allow 22/tcp   2>/dev/null || true
    ufw allow 80/tcp   2>/dev/null || true
    ufw allow 443/tcp  2>/dev/null || true
    ufw allow 3306/tcp 2>/dev/null || true
    ufw allow 6379/tcp 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 11. Smoke tests
# ---------------------------------------------------------------------------
log "Running smoke tests"

# MySQL: confirm root can connect with empty password
mysql --user=root --password='' --execute="SELECT 'MySQL OK';" 2>/dev/null \
    && log "  MySQL: PASS (root / no password)" \
    || log "  MySQL: FAIL — check service"

# Redis: confirm PING responds
redis-cli -h 127.0.0.1 PING 2>/dev/null | grep -q PONG \
    && log "  Redis: PASS (+PONG)" \
    || log "  Redis: FAIL — check service"

# Apache: confirm HTTP returns 200
curl -sf http://127.0.0.1/ -o /dev/null -w "%{http_code}" 2>/dev/null \
    | grep -q 200 \
    && log "  Apache HTTP: PASS (200)" \
    || log "  Apache HTTP: FAIL — check service"

log "esite.neutron.local provisioning complete."
log "Attack surfaces:"
log "  MySQL  :3306 — root / '' (empty password)"
log "  Redis  :6379 — no auth, bound to 0.0.0.0"
log "  HTTP   :80   — SQLi at http://${IP}/?id=1"
log "  HTTPS  :443  — same app over TLS"
log "  Postex — /var/www/html/.env contains DB + admin creds"
