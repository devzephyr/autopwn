#!/usr/bin/env bash
# =============================================================================
# preflight.sh — validate the Vagrant lab environment before running vagrant up
#
# Checks performed (no VMs are started):
#   1. Required tools present (vagrant, ruby, vboxmanage, shellcheck, curl, jq)
#   2. Vagrantfile Ruby syntax  (ruby -c)
#   3. Vagrantfile config logic (vagrant validate)
#   4. Every .sh provisioner   (shellcheck)
#   5. Every .ps1 provisioner  (PSScriptAnalyzer via pwsh if available)
#   6. Every box in BOXES[]    verified against Vagrant Cloud API
#      - box exists
#      - virtualbox provider available
#      - expected version pinned in Vagrantfile matches cloud
#   7. Host RAM  >= MIN_RAM_GB
#   8. Host disk >= MIN_DISK_GB free on the Vagrant home partition
#   9. VirtualBox version      >= MIN_VBOX_MAJOR
#
# Usage:
#   chmod +x preflight.sh
#   ./preflight.sh
#
# Exit codes:
#   0 = all checks passed
#   1 = one or more checks failed (details printed above the summary)
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration — adjust to match your Vagrantfile
# ---------------------------------------------------------------------------
VAGRANTFILE_DIR="$(cd "$(dirname "$0")" && pwd)"   # same dir as this script
MIN_RAM_GB=24          # minimum host RAM required (GB) — new topology needs ~18 GB
MIN_DISK_GB=80         # minimum free disk space required (GB) — 11 VMs, boxes are large
MIN_VBOX_MAJOR=6       # minimum VirtualBox major version

# Boxes used in the Vagrantfile: "org/name" "pinned-version"
# Leave version blank ("") to just check the box exists.
declare -A BOXES=(
    ["gusztavvargadr/windows-server-2022-standard-core"]="2309.0.2402"
    ["gusztavvargadr/windows-10"]=""
    ["gusztavvargadr/ubuntu-server-2204"]=""
    ["nicholaswilde/pfsense"]=""
    ["kalilinux/rolling"]=""
)

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

PASS=0; FAIL=0; WARN=0

_ok()   { echo -e "  ${GREEN}[PASS]${RESET} $*"; ((PASS++)); }
_fail() { echo -e "  ${RED}[FAIL]${RESET} $*"; ((FAIL++)); }
_warn() { echo -e "  ${YELLOW}[WARN]${RESET} $*"; ((WARN++)); }
_head() { echo -e "\n${CYAN}${BOLD}── $* ──${RESET}"; }

# ---------------------------------------------------------------------------
# 1. Required tools
# ---------------------------------------------------------------------------
_head "Required tools"

REQUIRED_TOOLS=(vagrant ruby curl jq vboxmanage)
OPTIONAL_TOOLS=(shellcheck pwsh)

for tool in "${REQUIRED_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        _ok "$tool found: $(command -v "$tool")"
    else
        _fail "$tool NOT found — install it before running vagrant up"
    fi
done

for tool in "${OPTIONAL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        _ok "$tool found (optional): $(command -v "$tool")"
    else
        _warn "$tool not found — ${tool} checks will be skipped"
    fi
done

# ---------------------------------------------------------------------------
# 2. Vagrantfile Ruby syntax
# ---------------------------------------------------------------------------
_head "Vagrantfile Ruby syntax"

VAGRANTFILE="$VAGRANTFILE_DIR/Vagrantfile"

if [[ ! -f "$VAGRANTFILE" ]]; then
    _fail "Vagrantfile not found at $VAGRANTFILE"
else
    if ruby -c "$VAGRANTFILE" &>/dev/null; then
        _ok "Vagrantfile Ruby syntax OK"
    else
        _fail "Vagrantfile has Ruby syntax errors:"
        ruby -c "$VAGRANTFILE" 2>&1 | sed 's/^/      /'
    fi
fi

# ---------------------------------------------------------------------------
# 3. vagrant validate
# ---------------------------------------------------------------------------
_head "vagrant validate"

if command -v vagrant &>/dev/null && [[ -f "$VAGRANTFILE" ]]; then
    output=$(cd "$VAGRANTFILE_DIR" && vagrant validate 2>&1)
    if echo "$output" | grep -qi "Vagrantfile validated successfully"; then
        _ok "vagrant validate passed"
    else
        _fail "vagrant validate failed:"
        echo "$output" | sed 's/^/      /'
    fi
fi

# ---------------------------------------------------------------------------
# 4. shellcheck on all .sh provisioners
# ---------------------------------------------------------------------------
_head "Bash provisioner scripts (shellcheck)"

if command -v shellcheck &>/dev/null; then
    SH_FILES=("$VAGRANTFILE_DIR"/provision/*.sh)
    if [[ ${#SH_FILES[@]} -eq 0 ]] || [[ ! -f "${SH_FILES[0]}" ]]; then
        _warn "No .sh provisioner scripts found in provision/"
    else
        all_sh_ok=true
        for f in "${SH_FILES[@]}"; do
            fname=$(basename "$f")
            if shellcheck -S warning "$f" 2>/dev/null; then
                _ok "$fname — shellcheck clean"
            else
                _fail "$fname — shellcheck issues:"
                shellcheck -S warning "$f" 2>&1 | head -20 | sed 's/^/      /'
                all_sh_ok=false
            fi
        done
    fi
else
    _warn "shellcheck not installed — skipping bash script validation"
    echo "       Install: apt install shellcheck  OR  brew install shellcheck"
fi

# ---------------------------------------------------------------------------
# 5. PSScriptAnalyzer on all .ps1 provisioners
# ---------------------------------------------------------------------------
_head "PowerShell provisioner scripts (PSScriptAnalyzer)"

if command -v pwsh &>/dev/null; then
    PS1_FILES=("$VAGRANTFILE_DIR"/provision/*.ps1)
    if [[ ${#PS1_FILES[@]} -eq 0 ]] || [[ ! -f "${PS1_FILES[0]}" ]]; then
        _warn "No .ps1 provisioner scripts found in provision/"
    else
        for f in "${PS1_FILES[@]}"; do
            fname=$(basename "$f")
            result=$(pwsh -NoProfile -Command "
                if (Get-Module -ListAvailable PSScriptAnalyzer) {
                    \$r = Invoke-ScriptAnalyzer -Path '$f' -Severity Warning,Error
                    if (\$r) { \$r | Format-Table -AutoSize; exit 1 }
                    exit 0
                } else {
                    Write-Warning 'PSScriptAnalyzer not installed'
                    exit 2
                }
            " 2>&1)
            rc=$?
            if   [[ $rc -eq 0 ]]; then _ok "$fname — PSScriptAnalyzer clean"
            elif [[ $rc -eq 2 ]]; then _warn "$fname — PSScriptAnalyzer module not installed in pwsh"
            else
                _fail "$fname — PSScriptAnalyzer issues:"
                echo "$result" | head -20 | sed 's/^/      /'
            fi
        done
    fi
else
    _warn "pwsh not installed — skipping PowerShell script validation"
    echo "       Install: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell"
fi

# ---------------------------------------------------------------------------
# 6. Vagrant Cloud box verification
# ---------------------------------------------------------------------------
_head "Vagrant Cloud box verification"

VAGRANT_CLOUD_API="https://app.vagrantup.com/api/v1/box"

for box_slug in "${!BOXES[@]}"; do
    pinned_version="${BOXES[$box_slug]}"
    org=$(echo "$box_slug" | cut -d/ -f1)
    name=$(echo "$box_slug" | cut -d/ -f2)

    api_url="$VAGRANT_CLOUD_API/$org/$name"
    http_code=$(curl -s -o /tmp/preflight_box.json -w "%{http_code}" "$api_url" 2>/dev/null || echo "000")

    if [[ "$http_code" == "404" ]]; then
        _fail "$box_slug — NOT FOUND on Vagrant Cloud (box deleted or name typo)"
        continue
    elif [[ "$http_code" != "200" ]]; then
        _warn "$box_slug — Vagrant Cloud API returned HTTP $http_code (network issue?)"
        continue
    fi

    # Box exists — check virtualbox provider
    has_vbox=$(jq -r '
        .current_version.providers[]? |
        select(.name == "virtualbox") |
        .name
    ' /tmp/preflight_box.json 2>/dev/null || echo "")

    if [[ -z "$has_vbox" ]]; then
        _fail "$box_slug — NO virtualbox provider in current version"
        # Show what providers ARE available
        providers=$(jq -r '.current_version.providers[]?.name' /tmp/preflight_box.json 2>/dev/null | tr '\n' ' ')
        echo "       Available providers: ${providers:-none}"
    else
        cloud_version=$(jq -r '.current_version.version' /tmp/preflight_box.json 2>/dev/null)
        box_size_mb=$(jq -r '
            .current_version.providers[] |
            select(.name == "virtualbox") |
            (.download_url_filesize // 0) / 1048576 | floor
        ' /tmp/preflight_box.json 2>/dev/null || echo "?")

        if [[ -n "$pinned_version" ]] && [[ "$pinned_version" != "$cloud_version" ]]; then
            _warn "$box_slug — pinned version $pinned_version but cloud current is $cloud_version"
        else
            _ok "$box_slug — exists, virtualbox provider available, version $cloud_version (~${box_size_mb} MB)"
        fi
    fi
done
rm -f /tmp/preflight_box.json

# ---------------------------------------------------------------------------
# 7. Host RAM check
# ---------------------------------------------------------------------------
_head "Host resources"

if [[ "$(uname)" == "Linux" ]]; then
    total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    total_ram_gb=$(( total_ram_kb / 1024 / 1024 ))
elif [[ "$(uname)" == "Darwin" ]]; then
    total_ram_gb=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
else
    total_ram_gb=0
fi

if (( total_ram_gb >= MIN_RAM_GB )); then
    _ok "Host RAM: ${total_ram_gb}GB (need ${MIN_RAM_GB}GB minimum)"
else
    _fail "Host RAM: ${total_ram_gb}GB — need at least ${MIN_RAM_GB}GB (11 VMs require ~18GB)"
fi

# ---------------------------------------------------------------------------
# 8. Disk space check
# ---------------------------------------------------------------------------
VAGRANT_HOME="${VAGRANT_HOME:-$HOME/.vagrant.d}"
# Check free space on the partition that holds VAGRANT_HOME
if [[ "$(uname)" == "Linux" ]] || [[ "$(uname)" == "Darwin" ]]; then
    free_disk_gb=$(df -BG "$VAGRANT_HOME" 2>/dev/null | awk 'NR==2 {gsub("G",""); print $4}' || echo 0)
    if (( free_disk_gb >= MIN_DISK_GB )); then
        _ok "Free disk on $VAGRANT_HOME: ${free_disk_gb}GB (need ${MIN_DISK_GB}GB for box downloads)"
    else
        _fail "Free disk on $VAGRANT_HOME: ${free_disk_gb}GB — need at least ${MIN_DISK_GB}GB"
    fi
fi

# ---------------------------------------------------------------------------
# 9. VirtualBox version
# ---------------------------------------------------------------------------
if command -v vboxmanage &>/dev/null; then
    vbox_version=$(vboxmanage --version | grep -oP '^\d+\.\d+\.\d+')
    vbox_major=$(echo "$vbox_version" | cut -d. -f1)
    if (( vbox_major >= MIN_VBOX_MAJOR )); then
        _ok "VirtualBox version: $vbox_version (need >= $MIN_VBOX_MAJOR.x)"
    else
        _fail "VirtualBox version: $vbox_version — need >= $MIN_VBOX_MAJOR.x"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo -e "${BOLD}══════════════════════════════════════════${RESET}"
echo -e "${BOLD}  Preflight summary${RESET}"
echo -e "  ${GREEN}Passed : $PASS${RESET}"
echo -e "  ${YELLOW}Warnings: $WARN${RESET}"
echo -e "  ${RED}Failed : $FAIL${RESET}"
echo -e "${BOLD}══════════════════════════════════════════${RESET}"

if (( FAIL > 0 )); then
    echo -e "\n${RED}${BOLD}Fix the FAIL items above before running vagrant up.${RESET}"
    exit 1
else
    echo -e "\n${GREEN}${BOLD}All required checks passed. Safe to run: vagrant up${RESET}"
    exit 0
fi
