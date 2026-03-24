#!/bin/bash
# wp_setup.sh
# Run this ONCE on the WordPress VM after docker compose up.
# Configures WordPress with weak credentials for autopwn testing.
#
# Usage:
#   SITE_URL=http://172.16.10.36 ./wp_setup.sh
#   WP_CONTAINER=mycontainer SITE_URL=http://10.0.0.5 ./wp_setup.sh

set -e

WP_CONTAINER="${WP_CONTAINER:-autopwn_wordpress}"
SITE_URL="${SITE_URL:?'Set SITE_URL to the VM IP reachable by other hosts (e.g. SITE_URL=http://172.16.10.36)'}"
ADMIN_USER="admin"
ADMIN_PASS="password"       # intentionally weak - on wordlist
ADMIN_EMAIL="admin@neutron.local"
SITE_TITLE="Neutron Corp Intranet"

echo "[*] WordPress container: $WP_CONTAINER"
echo "[*] Site URL:            $SITE_URL"
echo "[*] Waiting for WordPress to finish initialising..."

# Poll for readiness instead of a fixed sleep
MAX_WAIT=120
ELAPSED=0
until docker exec "$WP_CONTAINER" wp --allow-root --path=/var/www/html core is-installed 2>/dev/null \
   || curl -sf "${SITE_URL}/wp-login.php" >/dev/null 2>&1; do
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
docker exec "$WP_CONTAINER" bash -c "
    curl -sO https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && \
    chmod +x wp-cli.phar && \
    mv wp-cli.phar /usr/local/bin/wp
"

echo "[*] Running WordPress install..."
docker exec "$WP_CONTAINER" bash -c "
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
docker exec "$WP_CONTAINER" bash -c "
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
