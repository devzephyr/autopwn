#!/usr/bin/env bash
# =============================================================================
# pubdns.sh — Provision script for pubdns.neutron.local (172.16.30.10)
# VM: Ubuntu 22.04 | IP: 172.16.30.10 | VLAN30 (DMZ)
#
# Role: Public / external-facing DNS resolver
#   - NO neutron.local zone — queries for *.neutron.local return NXDOMAIN
#   - Forwards all other queries to 8.8.8.8 (simulates internet resolver)
#   - Accepts queries from all segments (serves DMZ and VLAN40)
#   - Used by remoteuser (VLAN40) before VPN connects
#   - After VPN connects, clients receive privdns (172.16.10.53) via push
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[pubdns] $(date +%H:%M:%S) $*"; }

HOST_IP="${HOST_IP:-172.16.30.10}"
VLAN30_GW="${VLAN30_GW:-172.16.30.1}"

log "Starting provisioner | HOST_IP=${HOST_IP} VLAN30_GW=${VLAN30_GW}"

# =============================================================================
# Section 1: Hostname
# =============================================================================
log "Section 1: Setting hostname"

hostnamectl set-hostname pubdns.neutron.local

if ! grep -q "pubdns.neutron.local" /etc/hosts; then
    echo "${HOST_IP}  pubdns.neutron.local pubdns" >> /etc/hosts
fi

# =============================================================================
# Section 2: Netplan static IP on eth1
# =============================================================================
log "Section 2: Configuring network (eth1 -> ${HOST_IP}/24)"

cat > /etc/netplan/99-pubdns.yaml <<EOF
network:
  version: 2
  ethernets:
    eth1:
      addresses:
        - ${HOST_IP}/24
      routes:
        - to: 0.0.0.0/0
          via: ${VLAN30_GW}
      nameservers:
        addresses:
          - 127.0.0.1
          - 8.8.8.8
      dhcp4: false
EOF

chmod 600 /etc/netplan/99-pubdns.yaml
netplan apply || true

# =============================================================================
# Section 3: Install Bind9
# =============================================================================
log "Section 3: Installing Bind9"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq bind9 bind9utils dnsutils

# =============================================================================
# Section 4: named.conf.options — forward-only, no internal zone
# =============================================================================
log "Section 4: Writing named.conf.options"

cat > /etc/bind/named.conf.options <<EOF
// pubdns.neutron.local — DMZ / public-facing DNS
// No neutron.local zone — *.neutron.local returns NXDOMAIN to callers.
// Forwards everything else to Google DNS.

options {
    directory "/var/cache/bind";

    listen-on { 127.0.0.1; ${HOST_IP}; };
    listen-on-v6 { none; };

    // Forward all to Google — no internal resolution available
    forwarders { 8.8.8.8; 8.8.4.4; };
    forward only;

    // Accept queries from any source (public resolver behaviour)
    allow-query     { any; };
    allow-recursion { any; };

    // No zone transfers
    allow-transfer  { none; };

    version "DNS Resolver";

    dnssec-validation no;
    recursion yes;
};
EOF

# =============================================================================
# Section 5: Stub zone for neutron.local → NXDOMAIN
#
# Declaring neutron.local as an empty authoritative zone means the server
# answers authoritatively with NXDOMAIN for all *.neutron.local queries
# instead of forwarding them (where they would leak or eventually resolve).
# =============================================================================
log "Section 5: Adding empty neutron.local zone (NXDOMAIN for all queries)"

if ! grep -q "neutron.local" /etc/bind/named.conf.local; then
    cat >> /etc/bind/named.conf.local <<'ZONECONF'

// Empty authoritative zone — causes NXDOMAIN for all *.neutron.local queries.
// This simulates split-horizon: the internal domain is invisible externally.
zone "neutron.local" {
    type master;
    file "/etc/bind/db.neutron.local.empty";
    allow-query { any; };
    allow-transfer { none; };
};
ZONECONF
fi

# Minimal SOA-only zone file — no A records, all queries get NXDOMAIN
cat > /etc/bind/db.neutron.local.empty <<'EOF'
$TTL 300
@ IN SOA pubdns.neutron.local. admin.neutron.local. (
          2026031701 3600 1800 604800 300 )
@ IN NS  pubdns.neutron.local.
; Intentionally empty — no A/CNAME records.
; All *.neutron.local queries return NXDOMAIN.
EOF

# =============================================================================
# Section 6: Validate and start Bind9
# =============================================================================
log "Section 6: Validating and starting Bind9"

named-checkconf /etc/bind/named.conf || { log "named.conf syntax error — abort"; exit 1; }
named-checkzone neutron.local /etc/bind/db.neutron.local.empty \
    || { log "Zone file syntax error — abort"; exit 1; }

systemctl enable named
systemctl restart named

# =============================================================================
# Section 7: UFW rules
# =============================================================================
log "Section 7: Configuring UFW rules"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow 22/tcp  comment 'SSH management'
ufw allow 53/tcp  comment 'DNS TCP'
ufw allow 53/udp  comment 'DNS UDP'

ufw --force enable

# =============================================================================
# Section 8: Smoke tests
# =============================================================================
log "Section 8: Running smoke tests"

sleep 2

PASS=0; FAIL=0

_chk() {
    local desc="$1"; shift
    if "$@" &>/dev/null; then
        log "  PASS: ${desc}"; PASS=$((PASS+1))
    else
        log "  FAIL: ${desc}"; FAIL=$((FAIL+1))
    fi
}

_chk "named service active"    systemctl is-active named
_chk "google.com resolves"     dig +short @127.0.0.1 google.com | grep -qP '\d+\.\d+\.\d+\.\d+'
_chk "dc01.neutron.local NXDOMAIN" bash -c 'dig @127.0.0.1 dc01.neutron.local | grep -q NXDOMAIN'
_chk "containers.neutron.local NXDOMAIN" bash -c 'dig @127.0.0.1 containers.neutron.local | grep -q NXDOMAIN'

log "Smoke tests complete: ${PASS} passed, ${FAIL} failed"

log "============================================================"
log "pubdns.neutron.local provisioning complete"
log "  Listening on: ${HOST_IP}:53"
log "  Accepts queries from: any (public resolver)"
log "  neutron.local: empty zone — NXDOMAIN for all internal names"
log "  All other queries: forwarded to 8.8.8.8"
log "============================================================"
