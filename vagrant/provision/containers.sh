#!/usr/bin/env bash
# =============================================================================
# containers.sh - Vagrant provisioner for containers.neutron.local
# VM: Ubuntu 22.04 | IP: 172.16.20.10
#
# Attack surfaces exposed by this host:
#   HTTP  :80    corpweb (nginx) - static company site
#   HTTPS :443   corpweb (nginx) - TLS with self-signed or DC-signed cert
#   HTTP  :8080  esite (php:apache) - SQLi-vulnerable e-commerce app
#   HTTPS :8443  esite (php:apache) - TLS variant
#   HTTP  :8069  odoo (ERP) - default credentials odoo/odoo
#   HTTP  :9000  nextcloud - default admin/password
#   MySQL :3306  neutron-mysql - root with empty password, shopuser/shoppass
#   Redis :6379  neutron-redis - no authentication (protected-mode off)
#   NFS   :2049  /srv/files - no_root_squash, world-readable
#                  contains: passwords.txt, backup.sql (MD5 hashes), id_rsa
#   .env file at /opt/containers/esite/.env - plaintext credentials (postex)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [containers] $*"
}

# Env vars supplied by Vagrantfile
HOST_IP="${HOST_IP:-172.16.20.10}"
VLAN20_GW="${VLAN20_GW:-172.16.20.1}"
DC_IP="${DC_IP:-172.16.10.10}"

log "Starting provisioner | HOST_IP=${HOST_IP} VLAN20_GW=${VLAN20_GW} DC_IP=${DC_IP}"

# =============================================================================
# Section 1: Hostname
# =============================================================================
log "Section 1: Setting hostname"

hostnamectl set-hostname containers.neutron.local

if ! grep -q "containers.neutron.local" /etc/hosts; then
    echo "${HOST_IP}  containers.neutron.local containers" >> /etc/hosts
fi

# =============================================================================
# Section 2: Netplan static IP on eth1
# =============================================================================
log "Section 2: Configuring network (eth1 -> ${HOST_IP}/24)"

cat > /etc/netplan/99-containers.yaml <<EOF
network:
  version: 2
  ethernets:
    eth1:
      addresses:
        - ${HOST_IP}/24
      routes:
        - to: 0.0.0.0/0
          via: ${VLAN20_GW}
      nameservers:
        addresses:
          - ${DC_IP}
          - 8.8.8.8
      dhcp4: false
EOF

chmod 600 /etc/netplan/99-containers.yaml
netplan apply || true

# =============================================================================
# Section 3: Package installation
# =============================================================================
log "Section 3: Installing packages"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    docker.io \
    docker-compose-plugin \
    curl \
    openssl \
    nfs-kernel-server \
    redis-tools

systemctl enable docker
systemctl start docker

# =============================================================================
# Section 4: TLS certificate
# =============================================================================
log "Section 4: Generating/fetching TLS certificate"

mkdir -p /etc/ssl/containers

CERT_FILE="/etc/ssl/containers/containers.crt"
KEY_FILE="/etc/ssl/containers/containers.key"

if [ ! -f "${CERT_FILE}" ] || [ ! -f "${KEY_FILE}" ]; then
    # Try to fetch DC-signed cert first
    DC_CERT_FETCHED=false
    if curl --retry 5 --retry-delay 3 --connect-timeout 10 \
            -fsSo /etc/ssl/containers/neutron-root-ca.cer \
            "http://${DC_IP}/certs/neutron-root-ca.cer" 2>/dev/null; then
        log "Fetched DC root CA from http://${DC_IP}/certs/neutron-root-ca.cer"
        DC_CERT_FETCHED=true
    else
        log "DC unreachable or cert not available - falling back to self-signed"
    fi

    # Generate self-signed cert (used regardless; if DC CA was fetched it can
    # be used separately for trust-store purposes)
    openssl req -x509 -nodes -days 825 \
        -newkey rsa:2048 \
        -keyout "${KEY_FILE}" \
        -out "${CERT_FILE}" \
        -subj "/CN=containers.neutron.local/O=Neutron Corp/C=CA" \
        -extensions v3_req \
        -addext "subjectAltName=DNS:containers.neutron.local,DNS:corpweb.neutron.local,IP:${HOST_IP}"

    chmod 640 "${KEY_FILE}"
    chmod 644 "${CERT_FILE}"
    log "Self-signed TLS certificate written to ${CERT_FILE}"
fi

# =============================================================================
# Section 5: Docker Compose service definitions
# =============================================================================
log "Section 5: Writing Docker Compose configuration"

mkdir -p /opt/containers

cat > /opt/containers/docker-compose.yml <<'COMPOSE'
version: "3.9"

services:

  corpweb:
    image: nginx:alpine
    container_name: corpweb
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/containers/corpweb:/usr/share/nginx/html:ro
      - /opt/containers/nginx-corpweb.conf:/etc/nginx/conf.d/default.conf:ro
      - /etc/ssl/containers:/etc/ssl/containers:ro
    restart: unless-stopped

  esite:
    image: php:8.1-apache
    container_name: esite
    ports:
      - "8080:80"
      - "8443:443"
    environment:
      - MYSQL_HOST=mysql
      - MYSQL_DB=shop
      - MYSQL_USER=shopuser
      - MYSQL_PASS=shoppass
    volumes:
      - /opt/containers/esite:/var/www/html
    depends_on:
      - mysql
    restart: unless-stopped

  odoo:
    image: odoo:16
    container_name: odoo
    ports:
      - "8069:8069"
    environment:
      - HOST=postgres
      - USER=odoo
      - PASSWORD=odoo
    depends_on:
      - postgres
    restart: unless-stopped

  nextcloud:
    image: nextcloud:27
    container_name: nextcloud
    ports:
      - "9000:80"
    environment:
      - MYSQL_HOST=mariadb
      - MYSQL_DATABASE=nextcloud
      - MYSQL_USER=ncuser
      - MYSQL_PASSWORD=ncpass
      - NEXTCLOUD_ADMIN_USER=admin
      - NEXTCLOUD_ADMIN_PASSWORD=password
    depends_on:
      - mariadb
    volumes:
      - /srv/nextcloud:/var/www/html
    restart: unless-stopped

  mysql:
    image: mysql:8
    container_name: neutron-mysql
    ports:
      - "3306:3306"
    environment:
      - MYSQL_ROOT_PASSWORD=
      - MYSQL_ALLOW_EMPTY_PASSWORD=yes
      - MYSQL_DATABASE=shop
      - MYSQL_USER=shopuser
      - MYSQL_PASSWORD=shoppass
    restart: unless-stopped

  postgres:
    image: postgres:15
    container_name: neutron-postgres
    environment:
      - POSTGRES_DB=postgres
      - POSTGRES_USER=odoo
      - POSTGRES_PASSWORD=odoo
    restart: unless-stopped

  mariadb:
    image: mariadb:10.11
    container_name: neutron-mariadb
    environment:
      - MARIADB_ROOT_PASSWORD=root
      - MARIADB_DATABASE=nextcloud
      - MARIADB_USER=ncuser
      - MARIADB_PASSWORD=ncpass
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    container_name: neutron-redis
    ports:
      - "6379:6379"
    command: redis-server --protected-mode no
    restart: unless-stopped
COMPOSE

log "docker-compose.yml written"

# =============================================================================
# Section 6: corpweb content
# =============================================================================
log "Section 6: Creating corpweb web content"

mkdir -p /opt/containers/corpweb

cat > /opt/containers/corpweb/index.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Neutron Corp &mdash; Enterprise Solutions</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; color: #222; background: #f5f7fa; }

    /* Navbar */
    nav {
      background: #1a2a4a;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 2rem;
      height: 60px;
      position: sticky;
      top: 0;
      z-index: 100;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3);
    }
    nav .brand { font-size: 1.4rem; font-weight: 700; letter-spacing: 1px; }
    nav ul { list-style: none; display: flex; gap: 2rem; }
    nav ul li a {
      color: #cbd5e1;
      text-decoration: none;
      font-size: 0.95rem;
      transition: color 0.2s;
    }
    nav ul li a:hover { color: #7dd3fc; }

    /* Hero */
    .hero {
      background: linear-gradient(135deg, #1a2a4a 0%, #2563eb 100%);
      color: #fff;
      text-align: center;
      padding: 6rem 2rem;
    }
    .hero h1 { font-size: 3rem; font-weight: 800; margin-bottom: 1rem; }
    .hero p { font-size: 1.2rem; max-width: 600px; margin: 0 auto 2rem; color: #bfdbfe; }
    .hero .btn {
      display: inline-block;
      background: #7dd3fc;
      color: #1a2a4a;
      padding: 0.85rem 2.5rem;
      border-radius: 4px;
      font-weight: 700;
      text-decoration: none;
      transition: background 0.2s;
    }
    .hero .btn:hover { background: #38bdf8; }

    /* About */
    .about {
      max-width: 900px;
      margin: 4rem auto;
      padding: 0 2rem;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 3rem;
      align-items: center;
    }
    .about h2 { font-size: 2rem; color: #1a2a4a; margin-bottom: 1rem; }
    .about p { line-height: 1.7; color: #444; margin-bottom: 0.75rem; }

    .card-grid {
      max-width: 900px;
      margin: 0 auto 4rem;
      padding: 0 2rem;
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1.5rem;
    }
    .card {
      background: #fff;
      border-radius: 8px;
      padding: 2rem;
      box-shadow: 0 2px 12px rgba(0,0,0,0.07);
      text-align: center;
    }
    .card .icon { font-size: 2.5rem; margin-bottom: 1rem; }
    .card h3 { color: #1a2a4a; margin-bottom: 0.5rem; }
    .card p { font-size: 0.9rem; color: #555; line-height: 1.6; }

    /* Footer */
    footer {
      background: #1a2a4a;
      color: #94a3b8;
      text-align: center;
      padding: 1.5rem;
      font-size: 0.875rem;
    }
  </style>
</head>
<body>

<nav>
  <div class="brand">&#9889; Neutron Corp</div>
  <ul>
    <li><a href="#">Home</a></li>
    <li><a href="#">Solutions</a></li>
    <li><a href="#">Products</a></li>
    <li><a href="#">Support</a></li>
    <li><a href="#">Contact</a></li>
  </ul>
</nav>

<section class="hero">
  <h1>Enterprise Solutions<br/>Built for Scale</h1>
  <p>Neutron Corp delivers mission-critical infrastructure, cloud integration,
     and managed services for organizations that demand reliability.</p>
  <a href="#about" class="btn">Learn More</a>
</section>

<section id="about" class="about">
  <div>
    <h2>About Neutron Corp</h2>
    <p>Founded in 2008, Neutron Corp has grown to serve over 400 enterprise
       clients across North America and Europe. Our integrated platform combines
       ERP, collaboration, and e-commerce into a single managed stack.</p>
    <p>Our team of certified engineers maintains a 99.97% uptime SLA backed by
       redundant data centres in Toronto, Montreal, and Vancouver.</p>
    <p>Contact us at <strong>info@neutron.local</strong> or call
       <strong>+1 (416) 555-0199</strong>.</p>
  </div>
  <div class="card-grid" style="display:block;">
    <div class="card" style="margin-bottom:1rem;">
      <div class="icon">&#128202;</div>
      <h3>ERP &amp; Analytics</h3>
      <p>Real-time dashboards, financial reporting, and supply-chain visibility.</p>
    </div>
    <div class="card">
      <div class="icon">&#9729;</div>
      <h3>Cloud &amp; Hybrid</h3>
      <p>Flexible deployment across on-premise, private cloud, and public cloud.</p>
    </div>
  </div>
</section>

<div class="card-grid">
  <div class="card">
    <div class="icon">&#128274;</div>
    <h3>Security First</h3>
    <p>ISO 27001 certified. End-to-end encryption and continuous threat monitoring.</p>
  </div>
  <div class="card">
    <div class="icon">&#128101;</div>
    <h3>Collaboration</h3>
    <p>Integrated file sharing, video conferencing, and team workspaces.</p>
  </div>
  <div class="card">
    <div class="icon">&#128218;</div>
    <h3>Compliance</h3>
    <p>PIPEDA, SOC 2 Type II, and GDPR compliance built into every layer.</p>
  </div>
</div>

<footer>
  &copy; 2024 Neutron Corp Inc. &mdash; All rights reserved. |
  172.16.20.10 &mdash; corpweb.neutron.local
</footer>

</body>
</html>
EOF

cat > /opt/containers/nginx-corpweb.conf <<'EOF'
server {
    listen 80;
    server_name corpweb.neutron.local;

    root /usr/share/nginx/html;
    index index.html;

    access_log /var/log/nginx/corpweb_access.log;
    error_log  /var/log/nginx/corpweb_error.log;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~* \.(css|js|png|jpg|gif|ico|woff2?)$ {
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header Server "nginx";
}
EOF

log "corpweb content written"

# =============================================================================
# Section 7: esite content (SQLi-vulnerable PHP e-commerce)
# =============================================================================
log "Section 7: Creating esite PHP content"

mkdir -p /opt/containers/esite/dvwa

cat > /opt/containers/esite/index.php <<'EOF'
<?php
/**
 * Neutron Corp - E-Commerce Storefront
 * WARNING: This application is intentionally vulnerable for lab purposes.
 * SQLi present: user-supplied $id passed directly into query without sanitization.
 */

$db_host = getenv('MYSQL_HOST') ?: 'mysql';
$db_name = getenv('MYSQL_DB')   ?: 'shop';
$db_user = getenv('MYSQL_USER') ?: 'shopuser';
$db_pass = getenv('MYSQL_PASS') ?: 'shoppass';

$product = null;
$results = [];
$error   = null;
$id      = isset($_GET['id']) ? $_GET['id'] : null;

if ($id !== null) {
    try {
        $pdo = new PDO(
            "mysql:host={$db_host};dbname={$db_name};charset=utf8",
            $db_user,
            $db_pass,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );

        // !! INTENTIONAL SQLi - NO SANITIZATION !!
        $sql   = "SELECT * FROM products WHERE id=$id";
        $stmt  = $pdo->query($sql);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

    } catch (PDOException $e) {
        $error = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Neutron Corp Shop</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f0f4f8; color: #222; margin: 0; }
    header { background: #1a2a4a; color: #fff; padding: 1rem 2rem; }
    header h1 { margin: 0; font-size: 1.5rem; }
    .container { max-width: 900px; margin: 2rem auto; padding: 0 1rem; }
    .search-bar { display: flex; gap: 0.5rem; margin-bottom: 2rem; }
    .search-bar input { flex: 1; padding: 0.6rem; border: 1px solid #ccc; border-radius: 4px; font-size: 1rem; }
    .search-bar button { padding: 0.6rem 1.5rem; background: #2563eb; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
    table { width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    th { background: #1a2a4a; color: #fff; padding: 0.75rem 1rem; text-align: left; }
    td { padding: 0.7rem 1rem; border-bottom: 1px solid #eee; }
    tr:last-child td { border-bottom: none; }
    .error { background: #fee2e2; border: 1px solid #f87171; border-radius: 4px; padding: 1rem; color: #b91c1c; margin-bottom: 1rem; font-family: monospace; white-space: pre-wrap; }
    .notice { background: #fef9c3; border: 1px solid #fde047; border-radius: 4px; padding: 0.75rem 1rem; margin-bottom: 1rem; font-size: 0.875rem; }
    footer { text-align: center; padding: 2rem; color: #888; font-size: 0.8rem; }
  </style>
</head>
<body>

<header>
  <h1>&#9889; Neutron Corp &mdash; Online Shop</h1>
</header>

<div class="container">

  <div class="notice">
    Search products by ID. Example: <a href="?id=1">?id=1</a>, <a href="?id=2">?id=2</a>
  </div>

  <form class="search-bar" method="GET">
    <input type="text" name="id" placeholder="Enter product ID..." value="<?php echo htmlspecialchars((string)$id); ?>" />
    <button type="submit">Search</button>
  </form>

<?php if ($error): ?>
  <div class="error">Database error: <?php echo htmlspecialchars($error); ?></div>
<?php endif; ?>

<?php if (!empty($results)): ?>
  <table>
    <thead>
      <tr>
        <?php foreach (array_keys($results[0]) as $col): ?>
          <th><?php echo htmlspecialchars($col); ?></th>
        <?php endforeach; ?>
      </tr>
    </thead>
    <tbody>
      <?php foreach ($results as $row): ?>
      <tr>
        <?php foreach ($row as $val): ?>
          <td><?php echo htmlspecialchars((string)$val); ?></td>
        <?php endforeach; ?>
      </tr>
      <?php endforeach; ?>
    </tbody>
  </table>
<?php elseif ($id !== null && !$error): ?>
  <p>No products found for ID: <strong><?php echo htmlspecialchars((string)$id); ?></strong></p>
<?php endif; ?>

</div>

<footer>Neutron Corp E-Commerce Platform v2.3.1 | Powered by PHP <?php echo PHP_VERSION; ?></footer>

</body>
</html>
EOF

# DVWA placeholder/redirect
cat > /opt/containers/esite/dvwa/index.php <<'EOF'
<?php
/**
 * DVWA is not installed in this container.
 * DVWA is available in the standalone Docker test environment.
 * See autopwn-test/docker-compose.yml for the dvwa-target service.
 */
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>DVWA - Redirect</title>
  <style>
    body { font-family: Arial, sans-serif; text-align: center; padding: 4rem; background: #1a2a4a; color: #fff; }
    a { color: #7dd3fc; }
  </style>
</head>
<body>
  <h1>Damn Vulnerable Web Application</h1>
  <p>DVWA is not installed on this host.</p>
  <p>Access DVWA via the dedicated container at
     <a href="http://172.28.0.21/dvwa/">http://172.28.0.21/dvwa/</a>
     (Docker test environment) or see <code>autopwn-test/docker-compose.yml</code>.</p>
</body>
</html>
EOF

cat > /opt/containers/esite/.htaccess <<'EOF'
Options -Indexes
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ index.php?path=$1 [QSA,L]
EOF

log "esite content written"

# =============================================================================
# Section 8: .env file with credentials (intentional postex finding)
# =============================================================================
log "Section 8: Writing .env credential file (intentional postex finding)"

cat > /opt/containers/esite/.env <<'EOF'
# Neutron Corp E-Commerce - Environment Configuration
# DO NOT COMMIT TO VERSION CONTROL

DB_HOST=mysql
DB_NAME=shop
DB_USER=shopuser
DB_PASS=shoppass

REDIS_HOST=redis
REDIS_PORT=6379

ADMIN_USER=admin
ADMIN_PASS=password

APP_SECRET=neutron-secret-key-do-not-share
APP_ENV=production
APP_DEBUG=false

SMTP_HOST=mail.neutron.local
SMTP_USER=noreply@neutron.local
SMTP_PASS=SmtpPass2024
EOF

chmod 644 /opt/containers/esite/.env
log ".env written"

# =============================================================================
# Section 9: NFS share with postex goodies
# =============================================================================
log "Section 9: Configuring NFS share"

mkdir -p /srv/files
mkdir -p /srv/nextcloud

cat > /srv/files/passwords.txt <<'EOF'
# Neutron Corp - Internal Password Reference (CONFIDENTIAL)
# Last updated: 2024-11-01 by jsmith
# DO NOT DISTRIBUTE

Service         Username        Password
-------         --------        --------
Domain Admin    administrator   NeutronAdmin2024!
Backup Svc      svc_backup      Backup$ervice1
File Share      files_admin     FilePass99
Database        dbadmin         Dbp@ss2024
VPN             vpnuser         Vpn$ecure1
SNMP            -               public
SSH (Linux)     root            password123
WordPress       admin           password
EOF

cat > /srv/files/backup.sql <<'EOF'
-- Neutron Corp Database Backup
-- Generated: 2024-11-01 03:00:01
-- Host: neutron-mysql

CREATE DATABASE IF NOT EXISTS `corp_users`;
USE `corp_users`;

DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `id`         INT          NOT NULL AUTO_INCREMENT,
  `username`   VARCHAR(64)  NOT NULL,
  `password`   VARCHAR(64)  NOT NULL COMMENT 'MD5 hashed',
  `email`      VARCHAR(128) NOT NULL,
  `role`       VARCHAR(32)  NOT NULL DEFAULT 'user',
  `created_at` DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT INTO `users` (`username`, `password`, `email`, `role`) VALUES
('administrator', '7b24afc8bc80e548d66c4e7ff72171c5', 'admin@neutron.local',      'admin'),
('jsmith',        '482c811da5d5b4bc6d497ffa98491e38', 'jsmith@neutron.local',      'user'),
('svc_backup',    'e10adc3949ba59abbe56e057f20f883e', 'backup@neutron.local',      'service'),
('hrdept',        'fcea920f7412b5da7be0cf42b8c93759', 'hr@neutron.local',          'user'),
('dbadmin',       '1a1dc91c907325c69271ddf0c944bc72', 'dbadmin@neutron.local',     'admin');

-- MD5 reference (for recovery purposes only):
--   7b24afc8bc80e548d66c4e7ff72171c5 = NeutronAdmin2024!
--   482c811da5d5b4bc6d497ffa98491e38 = password456
--   e10adc3949ba59abbe56e057f20f883e = 123456
--   fcea920f7412b5da7be0cf42b8c93759 = welcome1
--   1a1dc91c907325c69271ddf0c944bc72 = p4ssw0rd
EOF

cat > /srv/files/id_rsa <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBFAKE0000FAKE0000FAKE0000FAKE0000FAKE0000FAKE0000FAKE00AAAA
JFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEAAAAs
-----END OPENSSH PRIVATE KEY-----
# NOTE: This is a placeholder RSA key file left in the backup share.
# In a real engagement this file would contain a valid private key.
# Username associated: jsmith@neutron.local
# Last used: 2024-10-28
EOF

# NFS exports
if ! grep -q "/srv/files" /etc/exports; then
    echo "/srv/files *(rw,sync,no_subtree_check,no_root_squash)" >> /etc/exports
fi

exportfs -ra
systemctl enable nfs-kernel-server
systemctl restart nfs-kernel-server

log "NFS share configured: /srv/files exported"

# =============================================================================
# Section 10: Start Docker containers
# =============================================================================
log "Section 10: Starting Docker containers"

cd /opt/containers
docker compose up -d

log "Waiting 15 seconds for containers to initialise..."
sleep 15

log "Container status:"
docker ps

# =============================================================================
# Section 11: UFW firewall rules
# =============================================================================
log "Section 11: Configuring UFW rules"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow 22/tcp    comment 'SSH'
ufw allow 80/tcp    comment 'corpweb HTTP'
ufw allow 443/tcp   comment 'corpweb HTTPS'
ufw allow 3306/tcp  comment 'MySQL'
ufw allow 6379/tcp  comment 'Redis'
ufw allow 8069/tcp  comment 'Odoo ERP'
ufw allow 8080/tcp  comment 'esite HTTP'
ufw allow 8443/tcp  comment 'esite HTTPS'
ufw allow 9000/tcp  comment 'Nextcloud'
ufw allow 2049/tcp  comment 'NFS'
ufw allow 2049/udp  comment 'NFS UDP'
ufw allow 111/tcp   comment 'RPC portmapper'
ufw allow 111/udp   comment 'RPC portmapper UDP'

ufw --force enable
log "UFW enabled"

# =============================================================================
# Section 12: Smoke tests
# =============================================================================
log "Section 12: Running smoke tests"

SMOKE_PASS=0
SMOKE_FAIL=0

_check() {
    local desc="$1"
    shift
    if "$@" &>/dev/null; then
        log "  PASS: ${desc}"
        SMOKE_PASS=$((SMOKE_PASS + 1))
    else
        log "  FAIL: ${desc}"
        SMOKE_FAIL=$((SMOKE_FAIL + 1))
    fi
}

_check "corpweb HTTP (port 80)"  curl -sf --max-time 10 http://127.0.0.1/
_check "esite HTTP (port 8080)"  curl -sf --max-time 10 http://127.0.0.1:8080/
_check "docker ps shows containers" docker ps --format '{{.Names}}' | grep -q corpweb
_check "redis PING"              redis-cli -h 127.0.0.1 -p 6379 PING | grep -q PONG
_check "NFS showmount"           showmount -e 127.0.0.1 2>/dev/null | grep -q "/srv/files"

log "Smoke tests complete: ${SMOKE_PASS} passed, ${SMOKE_FAIL} failed"

# =============================================================================
# Summary
# =============================================================================
log "============================================================"
log "containers.neutron.local provisioning complete"
log "Attack surfaces:"
log "  HTTP  :80    corpweb (nginx) - Neutron Corp landing page"
log "  HTTPS :443   corpweb (nginx) - TLS (self-signed or DC-signed)"
log "  HTTP  :8080  esite (php:apache) - SQLi-vulnerable e-commerce"
log "  HTTPS :8443  esite (php:apache) - TLS variant"
log "  HTTP  :8069  odoo ERP - default creds odoo/odoo"
log "  HTTP  :9000  nextcloud - default creds admin/password"
log "  MySQL :3306  root empty password; shopuser/shoppass"
log "  Redis :6379  unauthenticated (protected-mode off)"
log "  NFS   :2049  /srv/files - no_root_squash, passwords.txt, backup.sql, id_rsa"
log "  File  /opt/containers/esite/.env - plaintext credentials (postex)"
log "============================================================"
