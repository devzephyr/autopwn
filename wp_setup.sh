#!/bin/bash
# wp_setup.sh
# Run this ONCE after docker compose up to configure WordPress with weak credentials
# The WordPress container needs ~60 seconds to finish initial setup before running this

set -e

WP_CONTAINER="autopwn_wordpress"
SITE_URL="http://172.28.0.31"
ADMIN_USER="admin"
ADMIN_PASS="password"       # intentionally weak - on wordlist
ADMIN_EMAIL="admin@neutron.local"
SITE_TITLE="Neutron Corp Intranet"

echo "[*] Waiting for WordPress to finish initialising..."
sleep 60

echo "[*] Installing WP-CLI into container..."
docker exec $WP_CONTAINER bash -c "
    curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && \
    chmod +x wp-cli.phar && \
    mv wp-cli.phar /usr/local/bin/wp
"

echo "[*] Running WordPress install..."
docker exec $WP_CONTAINER bash -c "
    wp core install \
        --url='$SITE_URL' \
        --title='$SITE_TITLE' \
        --admin_user='$ADMIN_USER' \
        --admin_password='$ADMIN_PASS' \
        --admin_email='$ADMIN_EMAIL' \
        --allow-root \
        --path=/var/www/html
"

echo "[*] Setting admin password to weak value for testing..."
docker exec $WP_CONTAINER bash -c "
    wp user update $ADMIN_USER \
        --user_pass='$ADMIN_PASS' \
        --allow-root \
        --path=/var/www/html
"

echo "[+] WordPress configured:"
echo "    URL:      $SITE_URL"
echo "    User:     $ADMIN_USER"
echo "    Password: $ADMIN_PASS"
echo ""
echo "[*] Verify manually: curl -s http://localhost:8081/wp-login.php | grep -i 'login'"
