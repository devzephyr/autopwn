#!/usr/bin/env bash
# =============================================================================
# privdns.sh — Provision script for privdns.neutron.local (172.16.10.53)
# VM: Ubuntu 22.04 | IP: 172.16.10.53 | VLAN10
#
# Role: Internal-only authoritative DNS for neutron.local
#   - Authoritative for neutron.local zone (A records for all lab hosts)
#   - Accepts queries from VLAN10, VLAN20, VLAN30, and VPN clients (10.8.0.0/24)
#   - REFUSES queries from VLAN40 (172.16.40.0/24) — external simulation network
#   - Forwards non-neutron.local queries to 8.8.8.8
#   - Supports zone transfer (AXFR) from trusted internal ACL (lab feature)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[privdns] $(date +%H:%M:%S) $*"; }

# Env vars supplied by Vagrantfile
HOST_IP="${HOST_IP:-172.16.10.53}"
VLAN10_GW="${VLAN10_GW:-172.16.10.1}"
DC_IP="${DC_IP:-172.16.10.10}"

log "Starting provisioner | HOST_IP=${HOST_IP} VLAN10_GW=${VLAN10_GW} DC_IP=${DC_IP}"

# =============================================================================
# Section 1: Hostname
# =============================================================================
log "Section 1: Setting hostname"

hostnamectl set-hostname privdns.neutron.local

if ! grep -q "privdns.neutron.local" /etc/hosts; then
    echo "${HOST_IP}  privdns.neutron.local privdns" >> /etc/hosts
fi

# =============================================================================
# Section 2: Netplan static IP on eth1
# =============================================================================
log "Section 2: Configuring network (eth1 -> ${HOST_IP}/24)"

cat > /etc/netplan/99-privdns.yaml <<EOF
network:
  version: 2
  ethernets:
    eth1:
      addresses:
        - ${HOST_IP}/24
      routes:
        - to: 0.0.0.0/0
          via: ${VLAN10_GW}
      nameservers:
        addresses:
          - 127.0.0.1
          - 8.8.8.8
      dhcp4: false
EOF

chmod 600 /etc/netplan/99-privdns.yaml
netplan apply || true

# =============================================================================
# Section 3: Install Bind9
# =============================================================================
log "Section 3: Installing Bind9"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq bind9 bind9utils bind9-doc dnsutils

# =============================================================================
# Section 4: Bind9 named.conf.options — ACLs, forwarders, REFUSE for VLAN40
# =============================================================================
log "Section 4: Writing named.conf.options"

cat > /etc/bind/named.conf.options <<'EOF'
// privdns.neutron.local — internal-only DNS
// Serves: VLAN10 (172.16.10.0/24), VLAN20 (172.16.20.0/24),
//         VLAN30 (172.16.30.0/24), VPN pool (10.8.0.0/24)
// Refuses: VLAN40 (172.16.40.0/24) — external simulation segment

acl "trusted" {
    127.0.0.1;
    172.16.10.0/24;   // VLAN10 — internal
    172.16.20.0/24;   // VLAN20 — server
    172.16.30.0/24;   // VLAN30 — DMZ
    10.8.0.0/24;      // VPN pool
};

acl "external" {
    172.16.40.0/24;   // VLAN40 — refused
};

options {
    directory "/var/cache/bind";

    // Only listen on loopback and the lab NIC
    listen-on { 127.0.0.1; PRIVDNS_IP; };
    listen-on-v6 { none; };

    // Forward unknown names to Google
    forwarders { 8.8.8.8; 8.8.4.4; };
    forward only;

    // Refuse recursive queries from external/VLAN40 segment
    allow-query     { trusted; };
    allow-recursion { trusted; };
    allow-transfer  { trusted; };   // AXFR allowed from internal — lab feature

    // Do not expose version string
    version "Bind 9 (internal)";

    dnssec-validation no;
    recursion yes;
};
EOF

# Substitute the actual IP (the file above uses a placeholder token)
sed -i "s/PRIVDNS_IP/${HOST_IP}/" /etc/bind/named.conf.options

# =============================================================================
# Section 5: Zone declaration
# =============================================================================
log "Section 5: Writing named.conf.local zone declaration"

# Idempotent: only add zone block if not already present
if ! grep -q "neutron.local" /etc/bind/named.conf.local; then
    cat >> /etc/bind/named.conf.local <<'ZONECONF'

// Authoritative zone for neutron.local internal domain
zone "neutron.local" {
    type master;
    file "/etc/bind/db.neutron.local";
    allow-transfer { trusted; };
    notify yes;
};

// Reverse zone for 172.16.10.0/24 (VLAN10)
zone "10.16.172.in-addr.arpa" {
    type master;
    file "/etc/bind/db.172.16.10";
    allow-transfer { trusted; };
};

// Reverse zone for 172.16.20.0/24 (VLAN20)
zone "20.16.172.in-addr.arpa" {
    type master;
    file "/etc/bind/db.172.16.20";
    allow-transfer { trusted; };
};

// Reverse zone for 172.16.30.0/24 (VLAN30)
zone "30.16.172.in-addr.arpa" {
    type master;
    file "/etc/bind/db.172.16.30";
    allow-transfer { trusted; };
};
ZONECONF
fi

# =============================================================================
# Section 6: Zone data file for neutron.local
# =============================================================================
log "Section 6: Writing forward zone file /etc/bind/db.neutron.local"

cat > /etc/bind/db.neutron.local <<EOF
\$ORIGIN neutron.local.
\$TTL 300
@    IN SOA  privdns.neutron.local. admin.neutron.local. (
              2026031701 ; serial (YYYYMMDDNN)
              3600       ; refresh
              1800       ; retry
              604800     ; expire
              300 )      ; minimum TTL

; Name servers
@         IN NS   privdns.neutron.local.

; VLAN10 — Internal
dc01      IN A    172.16.10.10
adminws   IN A    172.16.10.20
userws    IN A    172.16.10.21
privdns   IN A    ${HOST_IP}

; VLAN20 — Server / container host
containers IN A   172.16.20.10
corpweb    IN A   172.16.20.10
esite      IN A   172.16.20.10
odoo       IN A   172.16.20.10
nextcloud  IN A   172.16.20.10
files      IN A   172.16.20.10
shop       IN A   172.16.20.10
www        IN A   172.16.20.10

; VLAN30 — DMZ
pubdns    IN A    172.16.30.10
jumpbox   IN A    172.16.30.20
vpn       IN A    172.16.30.30

; Aliases
remote    IN CNAME  vpn.neutron.local.
mail      IN A    172.16.10.10
EOF

# =============================================================================
# Section 7: Reverse zone files
# =============================================================================
log "Section 7: Writing reverse zone files"

cat > /etc/bind/db.172.16.10 <<'EOF'
$TTL 300
@    IN SOA  privdns.neutron.local. admin.neutron.local. (
              2026031701 3600 1800 604800 300 )
@    IN NS   privdns.neutron.local.

10   IN PTR  dc01.neutron.local.
20   IN PTR  adminws.neutron.local.
21   IN PTR  userws.neutron.local.
53   IN PTR  privdns.neutron.local.
EOF

cat > /etc/bind/db.172.16.20 <<'EOF'
$TTL 300
@    IN SOA  privdns.neutron.local. admin.neutron.local. (
              2026031701 3600 1800 604800 300 )
@    IN NS   privdns.neutron.local.

10   IN PTR  containers.neutron.local.
EOF

cat > /etc/bind/db.172.16.30 <<'EOF'
$TTL 300
@    IN SOA  privdns.neutron.local. admin.neutron.local. (
              2026031701 3600 1800 604800 300 )
@    IN NS   privdns.neutron.local.

10   IN PTR  pubdns.neutron.local.
20   IN PTR  jumpbox.neutron.local.
30   IN PTR  vpn.neutron.local.
EOF

# =============================================================================
# Section 8: Validate and start Bind9
# =============================================================================
log "Section 8: Validating and starting Bind9"

named-checkconf /etc/bind/named.conf || { log "named.conf syntax error — abort"; exit 1; }
named-checkzone neutron.local /etc/bind/db.neutron.local \
    || { log "Zone file syntax error — abort"; exit 1; }

systemctl enable named
systemctl restart named

# =============================================================================
# Section 9: UFW rules
# =============================================================================
log "Section 9: Configuring UFW rules"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow 22/tcp   comment 'SSH management'
ufw allow 53/tcp   comment 'DNS TCP'
ufw allow 53/udp   comment 'DNS UDP'

ufw --force enable

# =============================================================================
# Section 10: Smoke tests
# =============================================================================
log "Section 10: Running smoke tests"

sleep 2   # give named a moment to fully start

PASS=0; FAIL=0

_chk() {
    local desc="$1"; shift
    if "$@" &>/dev/null; then
        log "  PASS: ${desc}"; PASS=$((PASS+1))
    else
        log "  FAIL: ${desc}"; FAIL=$((FAIL+1))
    fi
}

_chk "named service active"       systemctl is-active named
_chk "dc01 resolves"               dig +short @127.0.0.1 dc01.neutron.local | grep -q "172.16.10.10"
_chk "containers resolves"         dig +short @127.0.0.1 containers.neutron.local | grep -q "172.16.20.10"
_chk "vpn resolves"                dig +short @127.0.0.1 vpn.neutron.local | grep -q "172.16.30.30"
_chk "reverse PTR dc01"            dig +short @127.0.0.1 -x 172.16.10.10 | grep -q "dc01"

log "Smoke tests complete: ${PASS} passed, ${FAIL} failed"

log "============================================================"
log "privdns.neutron.local provisioning complete"
log "  Authoritative for: neutron.local"
log "  Listening on: ${HOST_IP}:53"
log "  Trusted clients: VLAN10/20/30 + VPN pool 10.8.0.0/24"
log "  REFUSED: 172.16.40.0/24 (VLAN40)"
log "  AXFR: allowed from trusted ACL (lab feature)"
log "============================================================"
