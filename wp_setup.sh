#!/bin/bash
# wp_setup.sh
# Run this ONCE after docker compose up to configure WordPress with weak credentials
# Waits for WordPress to become ready before running WP-CLI setup

set -e

WP_CONTAINER="${WP_CONTAINER:-autopwn_wordpress}"
# Auto-detect the container's IP rather than hardcoding one
SITE_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$WP_CONTAINER" 2>/dev/null)
if [ -z "$SITE_IP" ]; then
    echo "[-] Could not detect IP for container '$WP_CONTAINER'. Is it running?"
    exit 1
fi
SITE_URL="http://${SITE_IP}"
ADMIN_USER="admin"
ADMIN_PASS="password"       # intentionally weak - on wordlist
ADMIN_EMAIL="admin@neutron.local"
SITE_TITLE="Neutron Corp Intranet"

echo "[*] Detected WordPress container IP: $SITE_IP"
echo "[*] Waiting for WordPress to finish initialising..."

# Poll for readiness instead of a fixed sleep
MAX_WAIT=120
ELAPSED=0
until curl -sf "${SITE_URL}/wp-login.php" >/dev/null 2>&1; do
    if [ "$ELAPSED" -ge "$MAX_WAIT" ]; then
        echo "[-] WordPress did not become ready within ${MAX_WAIT}s"
        exit 1
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
    echo "    ... waiting (${ELAPSED}s)"
done
echo "[+] WordPress is responding after ${ELAPSED}s"

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
echo "[*] Verify manually: curl -s ${SITE_URL}/wp-login.php | grep -i 'login'"
