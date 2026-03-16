#!/usr/bin/env bash
# =============================================================================
# kali.sh — Provision script for kali.neutron.local (172.16.30.50)
# Ubuntu 22.04 (Kali packages layered on top), runs as root, fully unattended
# Role: ATTACKER machine — all autopwn dependencies installed and ready
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# 0. Helpers
# ---------------------------------------------------------------------------
log()  { echo "[kali] $(date +%H:%M:%S) $*"; }
warn() { echo "[kali] WARNING: $*" >&2; }

IFACE="eth1"
IP="172.16.30.50"
PREFIX="24"
GATEWAY="172.16.30.1"
DNS="172.16.10.10"
HOSTNAME="kali.neutron.local"

DC_CERT_URL="http://172.16.10.10/certs/neutron-root-ca.cer"
AUTOPWN_DEST="/opt/autopwn"
AUTOPWN_REPO="https://github.com/devzephyr/autopwn"

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
NETPLAN_FILE="/etc/netplan/99-kali.yaml"
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
# 3. Apt sources — add Kali rolling repo for offensive tools
# ---------------------------------------------------------------------------
log "Adding Kali Linux rolling repository"
export DEBIAN_FRONTEND=noninteractive

# Import Kali archive signing key
KALI_KEY="/usr/share/keyrings/kali-archive-keyring.gpg"
if [[ ! -f "${KALI_KEY}" ]]; then
    curl -fsSL https://archive.kali.org/archive-key.asc \
        | gpg --dearmor -o "${KALI_KEY}"
fi

KALI_LIST="/etc/apt/sources.list.d/kali.list"
if [[ ! -f "${KALI_LIST}" ]]; then
    cat > "${KALI_LIST}" <<KALISOURCE
deb [signed-by=${KALI_KEY}] https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
KALISOURCE
fi

log "Updating apt cache (Kali + Ubuntu repos)"
apt-get update -qq

# ---------------------------------------------------------------------------
# 4. System tools
# ---------------------------------------------------------------------------
log "Installing system tools: nmap, metasploit, sqlmap, hashcat, git, curl, wget"
apt-get install -y -qq \
    nmap \
    metasploit-framework \
    sqlmap \
    hashcat \
    git \
    curl \
    wget \
    python3 \
    python3-pip \
    python3-dev \
    libssl-dev \
    libffi-dev \
    build-essential \
    postgresql \
    postgresql-client \
    iproute2 \
    net-tools \
    iputils-ping \
    dnsutils \
    netcat-openbsd \
    openssl \
    ca-certificates

# ---------------------------------------------------------------------------
# 5. Python libraries
# ---------------------------------------------------------------------------
log "Installing Python libraries"

# Core autopwn requirements
pip3 install --quiet --break-system-packages \
    python-nmap \
    pymysql \
    jinja2 \
    pywinrm \
    paramiko \
    requests \
    ldap3

# impacket: install from pip if not already present at the required version
if ! python3 -c "import impacket" 2>/dev/null; then
    log "Installing impacket"
    pip3 install --quiet --break-system-packages impacket
else
    log "impacket already installed"
fi

# pymssql is optional (MSSQL reuse path) — non-fatal if it fails
pip3 install --quiet --break-system-packages pymssql 2>/dev/null \
    || warn "pymssql install failed — MSSQL reuse path will be unavailable"

# Confirm key libraries are importable
log "Verifying Python library imports"
python3 - <<'PYCHECK'
import sys
failures = []
libs = [
    ("nmap",     "python-nmap"),
    ("pymysql",  "pymysql"),
    ("jinja2",   "jinja2"),
    ("winrm",    "pywinrm"),
    ("paramiko", "paramiko"),
    ("requests", "requests"),
    ("ldap3",    "ldap3"),
    ("impacket", "impacket"),
]
for module, pkg in libs:
    try:
        __import__(module)
        print(f"  [OK]  {pkg}")
    except ImportError:
        print(f"  [ERR] {pkg} — import failed", file=sys.stderr)
        failures.append(pkg)
if failures:
    print(f"\nFailed imports: {failures}", file=sys.stderr)
    sys.exit(1)
PYCHECK

# ---------------------------------------------------------------------------
# 6. Verify system tools are in PATH
# ---------------------------------------------------------------------------
log "Verifying system tool paths"
for tool in nmap msfconsole sqlmap hashcat git python3 pip3; do
    if command -v "${tool}" &>/dev/null; then
        log "  [OK]  ${tool} -> $(command -v ${tool})"
    else
        warn "  [MISSING] ${tool} not found in PATH"
    fi
done

# ---------------------------------------------------------------------------
# 7. Clone autopwn repository
# ---------------------------------------------------------------------------
log "Setting up autopwn at ${AUTOPWN_DEST}"

if [[ -d "${AUTOPWN_DEST}/.git" ]]; then
    log "autopwn repo already present — pulling latest"
    git -C "${AUTOPWN_DEST}" pull --ff-only 2>/dev/null \
        || log "git pull failed (offline?) — using existing checkout"
else
    log "Cloning autopwn from ${AUTOPWN_REPO}"
    if git clone "${AUTOPWN_REPO}" "${AUTOPWN_DEST}" 2>/dev/null; then
        log "Clone successful"
    else
        warn "git clone failed (repo may require auth or be unreachable)"
        log "Falling back to Vagrant synced folder copy"
        if [[ -d "/vagrant" && -f "/vagrant/autopwn.py" ]]; then
            cp -r /vagrant "${AUTOPWN_DEST}"
            log "Copied from /vagrant"
        elif [[ -d "/vagrant/autopwn" ]]; then
            cp -r /vagrant/autopwn "${AUTOPWN_DEST}"
            log "Copied from /vagrant/autopwn"
        else
            log "Creating empty autopwn scaffold (neither git nor /vagrant available)"
            mkdir -p "${AUTOPWN_DEST}/modules/exploits" \
                     "${AUTOPWN_DEST}/wordlists" \
                     "${AUTOPWN_DEST}/templates" \
                     "${AUTOPWN_DEST}/state" \
                     "${AUTOPWN_DEST}/output"
        fi
    fi
fi

# Ensure state and output directories exist regardless of clone method
mkdir -p "${AUTOPWN_DEST}/state" \
         "${AUTOPWN_DEST}/output"

# ---------------------------------------------------------------------------
# 8. Initialise Metasploit database
# ---------------------------------------------------------------------------
log "Initialising Metasploit PostgreSQL database"

# msfdb requires postgresql to be running
systemctl enable postgresql --quiet
systemctl start  postgresql

# msfdb init is idempotent — safe to re-run
if msfdb status 2>/dev/null | grep -q "connected"; then
    log "Metasploit DB already initialised"
else
    msfdb init 2>/dev/null \
        && log "msfdb init complete" \
        || warn "msfdb init failed — run 'msfdb init' manually after boot"
fi

# ---------------------------------------------------------------------------
# 9. Install Neutron Root CA so TLS verification works against lab hosts
# ---------------------------------------------------------------------------
log "Installing Neutron Root CA"
CA_DEST="/usr/local/share/ca-certificates/neutron-root-ca.crt"
if [[ ! -f "${CA_DEST}" ]]; then
    curl -sf --retry 5 --retry-delay 3 \
        "${DC_CERT_URL}" -o "${CA_DEST}" 2>/dev/null \
        && update-ca-certificates --fresh 2>/dev/null \
        && log "Neutron Root CA installed" \
        || warn "Could not fetch DC cert (DC may not be up yet) — re-run after DC is online"
else
    log "Neutron Root CA already installed"
fi

# ---------------------------------------------------------------------------
# 10. Lab-specific /etc/hosts shortcuts
# ---------------------------------------------------------------------------
log "Adding Neutron lab hosts to /etc/hosts"
declare -A LAB_HOSTS=(
    ["172.16.10.10"]="dc01.neutron.local dc01"
    ["172.16.20.14"]="esite.neutron.local esite"
    ["172.16.30.10"]="vpn.neutron.local vpn"
)
for ip in "${!LAB_HOSTS[@]}"; do
    hostnames="${LAB_HOSTS[$ip]}"
    if ! grep -q "${ip}" /etc/hosts; then
        echo "${ip}  ${hostnames}" >> /etc/hosts
    fi
done

# ---------------------------------------------------------------------------
# 11. Write /opt/autopwn/run_tests.sh
# ---------------------------------------------------------------------------
log "Writing run_tests.sh"
cat > "${AUTOPWN_DEST}/run_tests.sh" <<'TESTSCRIPT'
#!/usr/bin/env bash
# =============================================================================
# run_tests.sh — Quick smoke tests for the autopwn pipeline
# Run from /opt/autopwn as root after provisioning is complete.
# Targets: esite.neutron.local (172.16.20.14)
# =============================================================================
set -uo pipefail

AUTOPWN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${AUTOPWN_DIR}"

pass=0
fail=0

run_test() {
    local label="$1"
    local cmd="$2"
    echo -n "[*] ${label}... "
    if output=$(eval "${cmd}" 2>&1); then
        echo "PASS"
        echo "    ${output}" | head -3
        ((pass++)) || true
    else
        echo "FAIL"
        echo "    ${output}" | head -3
        ((fail++)) || true
    fi
}

echo "========================================"
echo " autopwn smoke tests — $(date)"
echo "========================================"
echo ""

echo "--- Module import checks ---"
run_test "import discovery"  "python3 -c 'import modules.discovery' 2>&1 | grep -v '^$'"
run_test "import enrichment" "python3 -c 'import modules.enrichment' 2>&1 | grep -v '^$'"
run_test "import ad_enum"    "python3 -c 'import modules.ad_enum' 2>&1 | grep -v '^$'"
run_test "import planner"    "python3 -c 'import modules.planner' 2>&1 | grep -v '^$'"
run_test "import ssh exploit"      "python3 -c 'from modules.exploits.ssh import exploit_ssh'"
run_test "import database exploit" "python3 -c 'from modules.exploits.database import exploit_mysql, exploit_redis'"
run_test "import web exploit"      "python3 -c 'from modules.exploits.web import exploit_dvwa, exploit_wordpress'"

echo ""
echo "--- Live service tests against 172.16.20.14 ---"

run_test "Redis exploit (esite :6379)" \
    "python3 -c \"
from modules.exploits.database import exploit_redis
r = exploit_redis('172.16.20.14')
assert r.get('success'), f'Redis failed: {r}'
print(r.get('evidence',''))
\""

run_test "MySQL exploit (esite :3306)" \
    "python3 -c \"
from modules.exploits.database import exploit_mysql
r = exploit_mysql('172.16.20.14')
assert r.get('success'), f'MySQL failed: {r}'
print(r.get('evidence',''))
\""

echo ""
echo "--- Dry-run full pipeline (172.16.20.0/24) ---"
run_test "autopwn dry-run" \
    "python3 autopwn.py --target 172.16.20.0/24 --dry-run"

echo ""
echo "========================================"
printf " Results: %d passed, %d failed\n" "${pass}" "${fail}"
echo "========================================"

[[ "${fail}" -eq 0 ]]
TESTSCRIPT

chmod +x "${AUTOPWN_DEST}/run_tests.sh"

# ---------------------------------------------------------------------------
# 12. Shell convenience aliases for vagrant user
# ---------------------------------------------------------------------------
BASH_ALIASES="/home/vagrant/.bash_aliases"
cat > "${BASH_ALIASES}" <<'ALIASES'
# autopwn lab aliases
alias autopwn='cd /opt/autopwn && python3 autopwn.py'
alias pwn-test='cd /opt/autopwn && bash run_tests.sh'
alias pwn-dry='cd /opt/autopwn && python3 autopwn.py --target 172.16.20.0/24 --dry-run'
alias msfconsole='msfconsole -q'
ALIASES
chown vagrant:vagrant "${BASH_ALIASES}"

# ---------------------------------------------------------------------------
# 13. Smoke tests
# ---------------------------------------------------------------------------
log "Running smoke tests"

python3 -c "import nmap, pymysql, jinja2, paramiko, requests, ldap3, impacket" \
    && log "  Python imports: PASS" \
    || warn "  Python imports: one or more failed"

command -v nmap       &>/dev/null && log "  nmap:       PASS" || warn "  nmap:       MISSING"
command -v msfconsole &>/dev/null && log "  msfconsole: PASS" || warn "  msfconsole: MISSING"
command -v sqlmap     &>/dev/null && log "  sqlmap:     PASS" || warn "  sqlmap:     MISSING"
command -v hashcat    &>/dev/null && log "  hashcat:    PASS" || warn "  hashcat:    MISSING"

[[ -d "${AUTOPWN_DEST}" ]] \
    && log "  autopwn dir: PASS (${AUTOPWN_DEST})" \
    || warn "  autopwn dir: MISSING"

systemctl is-active postgresql &>/dev/null \
    && log "  PostgreSQL (MSF DB): PASS" \
    || warn "  PostgreSQL: not running"

log "kali.neutron.local provisioning complete."
log ""
log "Quick start:"
log "  ssh vagrant@${IP}"
log "  sudo bash /opt/autopwn/run_tests.sh"
log "  sudo python3 /opt/autopwn/autopwn.py --target 172.16.20.0/24 --dry-run"
