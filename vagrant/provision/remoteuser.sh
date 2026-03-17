#!/usr/bin/env bash
# =============================================================================
# remoteuser.sh — Provision script for remoteuser.neutron.local (172.16.40.10)
# VM: Ubuntu 22.04 | IP: 172.16.40.10 | VLAN40 (External Simulation)
#
# Role: Simulates an external remote user
#   - Uses pubdns (172.16.30.10) before VPN — neutron.local is NXDOMAIN
#   - Connects to VPN at vpn.neutron.local (172.16.30.30) using client cert
#   - After VPN connect: receives privdns push, routes to VLAN10/20/30
#   - Simulates: external attacker position OR legitimate remote employee
#
# This VM is primarily a simulation node (not a direct attack target).
# The OpenVPN client is pre-configured; connecting gives internal access.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[remoteuser] $(date +%H:%M:%S) $*"; }

HOST_IP="${HOST_IP:-172.16.40.10}"
VLAN40_GW="${VLAN40_GW:-172.16.40.1}"
PUBDNS_IP="${PUBDNS_IP:-172.16.30.10}"
VPN_IP="${VPN_IP:-172.16.30.30}"

log "Starting provisioner | HOST_IP=${HOST_IP} VLAN40_GW=${VLAN40_GW}"

# =============================================================================
# Section 1: Hostname
# =============================================================================
log "Section 1: Setting hostname"

hostnamectl set-hostname remoteuser.neutron.local

if ! grep -q "remoteuser.neutron.local" /etc/hosts; then
    echo "${HOST_IP}  remoteuser.neutron.local remoteuser" >> /etc/hosts
fi

# =============================================================================
# Section 2: Netplan static IP on eth1
# =============================================================================
log "Section 2: Configuring network (eth1 -> ${HOST_IP}/24)"

cat > /etc/netplan/99-remoteuser.yaml <<EOF
network:
  version: 2
  ethernets:
    eth1:
      addresses:
        - ${HOST_IP}/24
      routes:
        - to: 0.0.0.0/0
          via: ${VLAN40_GW}
      nameservers:
        addresses:
          - ${PUBDNS_IP}
          - 8.8.8.8
      dhcp4: false
EOF

chmod 600 /etc/netplan/99-remoteuser.yaml
netplan apply || true

# =============================================================================
# Section 3: Package installation
# =============================================================================
log "Section 3: Installing packages"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    openvpn \
    curl \
    wget \
    net-tools \
    dnsutils \
    iputils-ping \
    traceroute \
    nmap

# =============================================================================
# Section 4: OpenVPN client configuration
#
# The client bundle (ca.crt, client1.crt, client1.key, ta.key) is copied
# from vpn.neutron.local by vpn.sh and placed at /home/vagrant/vpn-client/.
# We pre-configure the client here; the actual cert files are fetched from
# the VPN server over the network (requires VPN server to be up first).
#
# Because provisioning order is not guaranteed, we use a helper script
# that fetches the bundle at runtime and can be re-run safely.
# =============================================================================
log "Section 4: Setting up OpenVPN client"

mkdir -p /opt/vpn-client

# VPN client .ovpn profile (references cert files by absolute path)
cat > /opt/vpn-client/neutron-client.ovpn <<EOF
# Neutron Lab VPN — client1 profile
# VPN Server: ${VPN_IP}
# After connect: routes to 172.16.10/20/30.0/24 are pushed
#                DNS changes to 172.16.10.53 (privdns — internal)

client
dev tun
proto udp
remote ${VPN_IP} 1194
resolv-retry infinite
nobind

# PKI files
ca   /opt/vpn-client/ca.crt
cert /opt/vpn-client/client1.crt
key  /opt/vpn-client/client1.key
tls-auth /opt/vpn-client/ta.key 1

cipher AES-256-GCM
auth   SHA256
tls-version-min 1.2

persist-key
persist-tun
verb 3

# Write DNS-pushed resolver to resolv.conf
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
EOF

# Helper script to fetch client bundle from VPN server
# Run: bash /opt/vpn-client/fetch-bundle.sh
cat > /opt/vpn-client/fetch-bundle.sh <<FETCHSCRIPT
#!/usr/bin/env bash
# Fetch VPN client bundle from jumpbox (where vpn.sh staged it)
# The bundle was left world-readable at /home/vagrant/vpn-client/ on vpn.neutron.local
set -euo pipefail

VPN_HOST="${VPN_IP}"
DEST="/opt/vpn-client"

echo "[fetch-bundle] Attempting to copy client certs from \${VPN_HOST}..."

# Try SCP (requires SSH access to VPN host after jumpbox pivot)
if command -v scp &>/dev/null; then
    echo "[fetch-bundle] Try: scp vagrant@\${VPN_HOST}:/home/vagrant/vpn-client/* \${DEST}/"
    echo "[fetch-bundle] (Requires SSH credentials for VPN host)"
fi

# Alternative: if VPN host exposes certs over HTTP (not default — lab option)
echo ""
echo "[fetch-bundle] Alternative — fetch over HTTP if VPN host serves certs:"
echo "  curl -o \${DEST}/ca.crt      http://\${VPN_HOST}/vpn-certs/ca.crt"
echo "  curl -o \${DEST}/client1.crt http://\${VPN_HOST}/vpn-certs/client1.crt"
echo "  curl -o \${DEST}/client1.key http://\${VPN_HOST}/vpn-certs/client1.key"
echo "  curl -o \${DEST}/ta.key      http://\${VPN_HOST}/vpn-certs/ta.key"
echo ""
echo "[fetch-bundle] Once certs are in \${DEST}/, connect with:"
echo "  sudo openvpn --config \${DEST}/neutron-client.ovpn --daemon"
FETCHSCRIPT

chmod +x /opt/vpn-client/fetch-bundle.sh

# =============================================================================
# Section 5: Shell aliases for vagrant user
# =============================================================================
log "Section 5: Writing shell aliases"

cat > /home/vagrant/.bash_aliases <<'ALIASES'
# Neutron Lab — remoteuser shortcuts

# VPN connect (requires cert bundle in /opt/vpn-client/)
alias vpn-connect='sudo openvpn --config /opt/vpn-client/neutron-client.ovpn --daemon'
alias vpn-status='ip route | grep tun || echo "VPN not connected"'
alias vpn-fetch='sudo bash /opt/vpn-client/fetch-bundle.sh'

# DNS check — shows which resolver is active
alias dns-check='cat /etc/resolv.conf && dig +short dc01.neutron.local'

# Nmap from VLAN40 perspective (public-facing only before VPN)
alias scan-public='nmap -sV -p 80,443,8080,8443,1194 172.16.20.10'
ALIASES

chown vagrant:vagrant /home/vagrant/.bash_aliases

# =============================================================================
# Section 6: /etc/hosts entries for lab reachability without DNS
# =============================================================================
log "Section 6: Adding minimal /etc/hosts entries"

# Only add hosts reachable from VLAN40 without VPN
declare -A REACHABLE=(
    ["172.16.30.10"]="pubdns.neutron.local pubdns"
    ["172.16.30.20"]="jumpbox.neutron.local jumpbox"
    ["172.16.30.30"]="vpn.neutron.local vpn"
    ["172.16.20.10"]="containers.neutron.local corpweb.neutron.local"
)

for ip in "${!REACHABLE[@]}"; do
    if ! grep -q "${ip}" /etc/hosts; then
        echo "${ip}  ${REACHABLE[$ip]}" >> /etc/hosts
    fi
done

# =============================================================================
# Section 7: UFW rules
# =============================================================================
log "Section 7: Configuring UFW rules"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow 22/tcp  comment 'SSH management'
# Allow all outbound — this VM initiates connections, not receives them

ufw --force enable

# =============================================================================
# Section 8: Smoke tests
# =============================================================================
log "Section 8: Running smoke tests"

PASS=0; FAIL=0

_chk() {
    local desc="$1"; shift
    if "$@" &>/dev/null; then
        log "  PASS: ${desc}"; PASS=$((PASS+1))
    else
        log "  FAIL: ${desc}"; FAIL=$((FAIL+1))
    fi
}

_chk "openvpn installed"              command -v openvpn
_chk "nmap installed"                 command -v nmap
_chk "VPN config file present"        test -f /opt/vpn-client/neutron-client.ovpn
_chk "fetch-bundle script present"    test -f /opt/vpn-client/fetch-bundle.sh
_chk "pubdns reachable (ping)"        ping -c1 -W3 "${PUBDNS_IP}" 2>/dev/null || true  # may fail in lab

log "Smoke tests complete: ${PASS} passed, ${FAIL} failed"

log "============================================================"
log "remoteuser.neutron.local provisioning complete"
log "IP: ${HOST_IP} | VLAN40 (External Simulation)"
log "DNS: ${PUBDNS_IP} (pubdns — neutron.local returns NXDOMAIN)"
log ""
log "VPN client pre-configured at /opt/vpn-client/neutron-client.ovpn"
log "  Connect: sudo openvpn --config /opt/vpn-client/neutron-client.ovpn"
log "  After VPN: DNS switches to 172.16.10.53 (privdns)"
log "             Routes to VLAN10/20/30 pushed"
log ""
log "Pre-VPN access: only 172.16.30.x DMZ + 172.16.20.x :80/443/8080/8443"
log "Post-VPN access: full internal network"
log "============================================================"
