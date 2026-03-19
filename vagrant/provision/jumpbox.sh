#!/usr/bin/env bash
# =============================================================================
# jumpbox.sh — Provision script for jumpbox.neutron.local (172.16.30.20)
# VM: Ubuntu 22.04 | IP: 172.16.30.20 | VLAN30 (DMZ)
#
# Role: SSH + xRDP jump host in the DMZ
#   - Accessible from VLAN40 (remoteuser) and VLAN10/20 (internal)
#   - SSH password auth enabled — bruteforceable with wordlist
#   - xRDP installed for RDP (port 3389)
#   - Intentional postex finding: saved domain credentials in home dir
#     (simulates a sysadmin who stored creds on the jump box)
#
# Attack chains:
#   1. SSH brute-force (ssh_brute) → shell → find saved creds → WinRM to adminws
#   2. RDP credential login → GUI session → credential browser
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() { echo "[jumpbox] $(date +%H:%M:%S) $*"; }

HOST_IP="${HOST_IP:-172.16.30.20}"
VLAN30_GW="${VLAN30_GW:-172.16.30.1}"
DC_IP="${DC_IP:-172.16.10.10}"
# DNS: use pubdns (VLAN30 local), NOT privdns (VLAN10).
# pfSense blocks VLAN30→VLAN10 for all DMZ hosts except the VPN server,
# so privdns is unreachable from jumpbox. pubdns is on the same VLAN.
PUBDNS_IP="${PUBDNS_IP:-172.16.30.10}"

log "Starting provisioner | HOST_IP=${HOST_IP} VLAN30_GW=${VLAN30_GW}"

# =============================================================================
# Section 1: Hostname
# =============================================================================
log "Section 1: Setting hostname"

hostnamectl set-hostname jumpbox.neutron.local

if ! grep -q "jumpbox.neutron.local" /etc/hosts; then
    echo "${HOST_IP}  jumpbox.neutron.local jumpbox" >> /etc/hosts
fi

# =============================================================================
# Section 2: Netplan static IP on eth1
# =============================================================================
log "Section 2: Configuring network (eth1 -> ${HOST_IP}/24)"

cat > /etc/netplan/99-jumpbox.yaml <<EOF
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
          - ${PUBDNS_IP}
          - 8.8.8.8
      dhcp4: false
EOF

chmod 600 /etc/netplan/99-jumpbox.yaml
netplan apply || true

# =============================================================================
# Section 3: Package installation
# =============================================================================
log "Section 3: Installing packages"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    openssh-server \
    xrdp \
    xfce4 \
    xfce4-terminal \
    curl \
    wget \
    net-tools \
    dnsutils \
    smbclient \
    winbind \
    libpam-winbind

# =============================================================================
# Section 4: SSH configuration — enable password auth (intentional)
# =============================================================================
log "Section 4: Configuring SSH (password auth enabled — bruteforceable)"

SSHD_CONFIG="/etc/ssh/sshd_config"

# Enable password authentication
sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "${SSHD_CONFIG}"
sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "${SSHD_CONFIG}"
sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "${SSHD_CONFIG}"

# Ensure the settings are present if not already in the file
grep -q "^PasswordAuthentication" "${SSHD_CONFIG}" \
    || echo "PasswordAuthentication yes" >> "${SSHD_CONFIG}"
grep -q "^PermitRootLogin" "${SSHD_CONFIG}" \
    || echo "PermitRootLogin yes" >> "${SSHD_CONFIG}"

systemctl enable ssh
systemctl restart ssh

# Set root password to something in the SSH wordlist (intentional weakness)
echo "root:password123" | chpasswd
log "root password set to 'password123' (bruteforceable — intentional)"

# =============================================================================
# Section 5: xRDP configuration
# =============================================================================
log "Section 5: Configuring xRDP"

# Configure xRDP to use xfce4 desktop
echo "startxfce4" > /etc/skel/.xsession
echo "startxfce4" > /root/.xsession

# Set xRDP to listen on 3389 (default — confirm not changed)
if ! grep -q "^port=3389" /etc/xrdp/xrdp.ini; then
    sed -i 's/^port=.*/port=3389/' /etc/xrdp/xrdp.ini
fi

systemctl enable xrdp
systemctl restart xrdp

# =============================================================================
# Section 6: Create jsmith local account (mirrors domain account)
# =============================================================================
log "Section 6: Creating jsmith local account"

if ! id jsmith &>/dev/null; then
    useradd -m -s /bin/bash -G sudo jsmith
    echo "jsmith:Password123" | chpasswd
    log "Created local account: jsmith / Password123"
else
    log "jsmith already exists — skipping"
fi

# =============================================================================
# Section 7: Intentional postex findings — saved domain credentials
# =============================================================================
log "Section 7: Dropping intentional postex findings"

# Create sysadmin working directory
mkdir -p /root/admin
mkdir -p /home/jsmith/Desktop

# --- Finding 1: plaintext creds in a notes file ---
cat > /root/admin/domain-creds.txt <<'EOF'
Neutron Domain — Admin Credentials
====================================
DC01 (172.16.10.10)
  Administrator  / NeutronAdmin2024!
  hradmin        / HrAdmin2024!

WinRM Access (adminws 172.16.10.20)
  NEUTRON\hradmin / HrAdmin2024!
  Command: winrm quickconfig
           Enter-PSSession -ComputerName adminws -Credential NEUTRON\hradmin

RDP (adminws / userws)
  Port 3389
  NEUTRON\hradmin / HrAdmin2024!

File Shares (containers 172.16.20.10)
  SMB: \\172.16.20.10\files  — no creds needed (guest)
  NFS: mount 172.16.20.10:/srv/files /mnt/files

Last updated: 2024-11-15 — jdoe
TODO: Remove this file before next audit!
EOF

chmod 600 /root/admin/domain-creds.txt
log "Saved domain creds at /root/admin/domain-creds.txt"

# --- Finding 2: SSH config with saved host entries ---
mkdir -p /root/.ssh
cat > /root/.ssh/config <<'EOF'
# Neutron Lab SSH Shortcuts
Host dc01
    HostName 172.16.10.10
    User Administrator

Host adminws
    HostName 172.16.10.20
    User hradmin

Host containers
    HostName 172.16.20.10
    User root
    IdentityFile ~/.ssh/id_rsa_lab
EOF
chmod 600 /root/.ssh/config

# Placeholder private key (same format as containers NFS finding)
cat > /root/.ssh/id_rsa_lab <<'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBFAKE0000FAKE0000FAKE0000FAKE0000FAKE0000FAKE0000FAKE00AAAA
JFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEKEYFAKEAAAAs
-----END OPENSSH PRIVATE KEY-----
# NOTE: Placeholder — see /srv/files/id_rsa on containers host for real key.
# Username: root@containers.neutron.local
EOF
chmod 600 /root/.ssh/id_rsa_lab

# --- Finding 3: bash history with credential usage ---
cat > /root/.bash_history <<'EOF'
ssh hradmin@172.16.10.20
winrm -hostname 172.16.10.20 -username hradmin -password HrAdmin2024!
smbclient //172.16.20.10/files -N
mount -t nfs 172.16.20.10:/srv/files /mnt/files
cat /root/admin/domain-creds.txt
ssh -i ~/.ssh/id_rsa_lab root@172.16.20.10
EOF
chmod 600 /root/.bash_history

# --- Finding 4: jsmith desktop note ---
cat > /home/jsmith/Desktop/VPN-setup.txt <<'EOF'
VPN Access Notes — jsmith
===========================
VPN Server: vpn.neutron.local (172.16.30.30)
Port: 1194 UDP

Client config at: /home/vagrant/vpn-client/ on vpn.neutron.local
After connect: push routes to VLAN10/20/30
DNS pushed: 172.16.10.53 (privdns)

My domain creds: jsmith / Password123
Work laptop IP: 172.16.40.10 (remoteuser)
EOF
chown jsmith:jsmith /home/jsmith/Desktop/VPN-setup.txt
chmod 644 /home/jsmith/Desktop/VPN-setup.txt

log "Postex findings planted"

# =============================================================================
# Section 8: UFW rules
# =============================================================================
log "Section 8: Configuring UFW rules"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing

ufw allow 22/tcp    comment 'SSH'
ufw allow 3389/tcp  comment 'xRDP'

ufw --force enable

# =============================================================================
# Section 9: Smoke tests
# =============================================================================
log "Section 9: Running smoke tests"

PASS=0; FAIL=0

_chk() {
    local desc="$1"; shift
    if "$@" &>/dev/null; then
        log "  PASS: ${desc}"; PASS=$((PASS+1))
    else
        log "  FAIL: ${desc}"; FAIL=$((FAIL+1))
    fi
}

_chk "sshd active"              systemctl is-active ssh
_chk "xrdp active"              systemctl is-active xrdp
_chk "jsmith account exists"    id jsmith
_chk "creds file present"       test -f /root/admin/domain-creds.txt
_chk "bash history planted"     test -f /root/.bash_history
_chk "port 22 listening"        ss -tlnp | grep -q ':22 '
_chk "port 3389 listening"      ss -tlnp | grep -q ':3389 '

log "Smoke tests complete: ${PASS} passed, ${FAIL} failed"

log "============================================================"
log "jumpbox.neutron.local provisioning complete"
log "Attack surfaces:"
log "  SSH    :22  — password auth, root/password123 (wordlist hit)"
log "  xRDP   :3389 — root/password123, jsmith/Password123"
log "Postex findings:"
log "  /root/admin/domain-creds.txt  — plaintext domain creds"
log "  /root/.ssh/config             — SSH shortcuts to internal hosts"
log "  /root/.bash_history           — credential usage history"
log "  /home/jsmith/Desktop/VPN-setup.txt — VPN + domain creds"
log "============================================================"
