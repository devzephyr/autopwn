#!/usr/bin/env bash
# =============================================================================
# vpn.sh — Provision script for vpn.neutron.local (172.16.30.10)
# Ubuntu 22.04, runs as root, fully unattended, idempotent
# Services: OpenVPN with PKI certificate authentication (no password logins)
# Intentional finding: client cert + key left readable at /home/vagrant/vpn-client/
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# 0. Helpers
# ---------------------------------------------------------------------------
log() { echo "[vpn] $(date +%H:%M:%S) $*"; }

IFACE="eth1"
IP="${HOST_IP:-172.16.30.30}"
PREFIX="24"
GATEWAY="${VLAN30_GW:-172.16.30.1}"
DNS="${PRIVDNS_IP:-172.16.10.53}"
HOSTNAME="vpn.neutron.local"

EASYRSA_DIR="/etc/openvpn/easy-rsa"
OVPN_DIR="/etc/openvpn"
CLIENT_STAGING="/home/vagrant/vpn-client"

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
# 2. Static IP
# ---------------------------------------------------------------------------
NETPLAN_FILE="/etc/netplan/99-vpn.yaml"
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
netplan apply || true

# ---------------------------------------------------------------------------
# 3. Package installation
# ---------------------------------------------------------------------------
log "Updating apt cache"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq

log "Installing OpenVPN and easy-rsa"
apt-get install -y -qq openvpn easy-rsa iptables-persistent

# ---------------------------------------------------------------------------
# 4. PKI setup (idempotent — skip if CA already exists)
# ---------------------------------------------------------------------------
if [[ ! -f "${EASYRSA_DIR}/pki/ca.crt" ]]; then
    log "Initialising PKI with easy-rsa"
    make-cadir "${EASYRSA_DIR}"

    cd "${EASYRSA_DIR}"

    # Initialise PKI directory
    ./easyrsa init-pki

    # Build CA (no passphrase — lab convenience)
    ./easyrsa --batch build-ca nopass

    # Server certificate and key
    ./easyrsa --batch gen-req server nopass
    ./easyrsa --batch sign-req server server

    # DH parameters (2048-bit for speed on lab hardware)
    ./easyrsa --batch gen-dh

    # Client certificate and key (simulates a legitimate user cert)
    ./easyrsa --batch gen-req client1 nopass
    ./easyrsa --batch sign-req client client1

    # TLS-Auth key (replay-attack prevention)
    openvpn --genkey secret "${OVPN_DIR}/ta.key"

    log "PKI initialisation complete"
else
    log "PKI already initialised — skipping"
fi

# ---------------------------------------------------------------------------
# 5. OpenVPN server configuration
# ---------------------------------------------------------------------------
log "Writing /etc/openvpn/server.conf"
cat > "${OVPN_DIR}/server.conf" <<OVPNCONF
# Neutron Lab — vpn.neutron.local
# Certificate-based auth only; no password logins

port    1194
proto   udp
dev     tun

# PKI material
ca   ${EASYRSA_DIR}/pki/ca.crt
cert ${EASYRSA_DIR}/pki/issued/server.crt
key  ${EASYRSA_DIR}/pki/private/server.key
dh   ${EASYRSA_DIR}/pki/dh.pem

# TLS hardening
tls-auth ${OVPN_DIR}/ta.key 0
tls-version-min 1.2
cipher AES-256-GCM
auth   SHA256

# Client certificate is mandatory
verify-client-cert require

# VPN subnet — hands clients 10.8.0.x
server 10.8.0.0 255.255.255.0

# Advertise internal lab routes to clients
push "route 172.16.10.0 255.255.255.0"
push "route 172.16.20.0 255.255.255.0"
push "route 172.16.30.0 255.255.255.0"
# Push privdns as DNS so VPN clients can resolve neutron.local
push "dhcp-option DNS ${DNS}"

# Keepalive / housekeeping
keepalive 10 120
persist-key
persist-tun
status    /var/log/openvpn/status.log
log-append /var/log/openvpn/openvpn.log
verb      3

# Allow multiple clients to reuse the same cert (lab only)
duplicate-cn
OVPNCONF

mkdir -p /var/log/openvpn

# ---------------------------------------------------------------------------
# 6. IP forwarding + NAT masquerade for VPN clients
# ---------------------------------------------------------------------------
log "Enabling IP forwarding"
SYSCTL_CONF="/etc/sysctl.d/99-vpn-forward.conf"
if [[ ! -f "${SYSCTL_CONF}" ]]; then
    echo "net.ipv4.ip_forward=1" > "${SYSCTL_CONF}"
fi
sysctl -p "${SYSCTL_CONF}" 2>/dev/null || true

# Determine the outbound (non-VPN) interface — typically eth0 under Vagrant
OUTBOUND_IFACE="$(ip route | awk '/default/ {print $5; exit}')"
log "NAT masquerade outbound via ${OUTBOUND_IFACE}"

# iptables-persistent: apply rules idempotently
RULES_FILE="/etc/iptables/rules.v4"
# Only insert the rule if it is not already present
if ! iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "${OUTBOUND_IFACE}" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "${OUTBOUND_IFACE}" -j MASQUERADE
fi
if ! iptables -C FORWARD -i tun0 -o "${OUTBOUND_IFACE}" -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -i tun0 -o "${OUTBOUND_IFACE}" -j ACCEPT
fi
if ! iptables -C FORWARD -i "${OUTBOUND_IFACE}" -o tun0 -m state \
        --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; then
    iptables -A FORWARD -i "${OUTBOUND_IFACE}" -o tun0 \
        -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# Persist the rules so they survive reboot
mkdir -p /etc/iptables
iptables-save > "${RULES_FILE}"

# ---------------------------------------------------------------------------
# 7. Firewall: open VPN UDP port
# ---------------------------------------------------------------------------
if command -v ufw &>/dev/null; then
    ufw allow 22/tcp    2>/dev/null || true
    ufw allow 1194/udp  2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# 8. Start OpenVPN
# ---------------------------------------------------------------------------
log "Enabling and starting openvpn@server"
systemctl enable openvpn@server --quiet
systemctl restart openvpn@server

# ---------------------------------------------------------------------------
# 9. DELIBERATE FINDING: client cert material left readable
#    Simulates an admin forgetting to remove creds from a compromised host.
#    postex.py Linux commands will find these via 'find / -name "*.ovpn"'
# ---------------------------------------------------------------------------
log "Staging client cert bundle at ${CLIENT_STAGING} (intentional postex finding)"
mkdir -p "${CLIENT_STAGING}"

# Copy PKI assets (idempotent — overwrite each run so cert is always current)
cp "${EASYRSA_DIR}/pki/issued/client1.crt"   "${CLIENT_STAGING}/client1.crt"
cp "${EASYRSA_DIR}/pki/private/client1.key"  "${CLIENT_STAGING}/client1.key"
cp "${EASYRSA_DIR}/pki/ca.crt"               "${CLIENT_STAGING}/ca.crt"
cp "${OVPN_DIR}/ta.key"                      "${CLIENT_STAGING}/ta.key"

# Intentionally world-readable — the "mistake" a sysadmin would make
chmod 644 "${CLIENT_STAGING}/client1.crt" \
           "${CLIENT_STAGING}/ca.crt" \
           "${CLIENT_STAGING}/ta.key"
chmod 644 "${CLIENT_STAGING}/client1.key"   # should be 600 — left open on purpose

# Ready-to-use .ovpn profile so an attacker can immediately import and connect
cat > "${CLIENT_STAGING}/client1.ovpn" <<OVPN
# Neutron Lab VPN — client1 profile
# Generated by vpn.sh provision script
# Connect: openvpn --config client1.ovpn

client
dev tun
proto udp
remote ${IP} 1194
resolv-retry infinite
nobind

# PKI files (paths relative to this .ovpn file)
ca   ca.crt
cert client1.crt
key  client1.key
tls-auth ta.key 1

# Must match server cipher
cipher AES-256-GCM
auth   SHA256
tls-version-min 1.2

persist-key
persist-tun
verb 3
OVPN
chmod 644 "${CLIENT_STAGING}/client1.ovpn"

# Ownership: vagrant owns the directory so SSH post-exploitation can read it
chown -R vagrant:vagrant "${CLIENT_STAGING}"

# Also drop a note in /root for the postex Linux 'find /' sweep
mkdir -p /root/admin
cat > /root/admin/vpn-setup-notes.txt <<NOTES
VPN Server Setup Notes — vpn.neutron.local
==========================================
CA passphrase:  (none — nopass build)
Server cert:    ${EASYRSA_DIR}/pki/issued/server.crt
Client1 bundle: ${CLIENT_STAGING}/
TLS-Auth key:   ${OVPN_DIR}/ta.key

TODO: Move client bundle off this server before prod cutover.
NOTES
chmod 600 /root/admin/vpn-setup-notes.txt

# ---------------------------------------------------------------------------
# 10. Smoke tests
# ---------------------------------------------------------------------------
log "Running smoke tests"

systemctl is-active openvpn@server >/dev/null 2>&1 \
    && log "  OpenVPN: PASS (service active)" \
    || log "  OpenVPN: FAIL — check journalctl -u openvpn@server"

[[ -f "${CLIENT_STAGING}/client1.ovpn" ]] \
    && log "  Client bundle: PASS (files present at ${CLIENT_STAGING})" \
    || log "  Client bundle: FAIL"

sysctl net.ipv4.ip_forward 2>/dev/null | grep -q "= 1" \
    && log "  IP forwarding: PASS" \
    || log "  IP forwarding: FAIL"

log "vpn.neutron.local provisioning complete."
log "Attack surfaces:"
log "  OpenVPN :1194/udp — cert-auth only (no password spray possible)"
log "  Postex  — client certs at ${CLIENT_STAGING}/"
log "  Postex  — admin notes at /root/admin/vpn-setup-notes.txt"
log "  Lateral — import client1.ovpn to pivot into other VLANs"
