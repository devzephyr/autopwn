#!/usr/bin/env bash
# =============================================================================
# apply.sh — Apply netplan static IP configs to Neutron Lab Linux hosts
#
# Real SPR500 topology — run FROM Kali (172.16.21.11) via SSH on each target,
# or copy the relevant YAML to each machine and run netplan apply locally.
#
# Usage:
#   bash apply.sh <hostname>          # apply to a specific host
#   bash apply.sh all                 # apply to all reachable Linux hosts
#   bash apply.sh check               # ping-check all hosts first
#
# Requirements: ssh key or password access to each host as root/sudo.
#
# Host map (real SPR500 IPs):
#   privdns      172.16.12.11   VLAN30  — internal DNS (Bind9)
#   privdocker   172.16.12.12   VLAN30  — private Docker (files, erp)
#   pubdns       172.16.10.35   DMZ     — public DNS (Bind9)
#   pubdocker    172.16.10.36   DMZ     — public Docker (shop, corp)
#   vpn          172.16.10.40   DMZ     — OpenVPN server
#   jumpbox      172.16.10.41   DMZ     — SSH/RDP jump host
#   remoteuser   172.16.21.20   Ext     — VPN user / external client
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Host → config mapping  (hostname : current-ip : yaml-file)
# NOTE: privdns and privdocker are on VLAN30; Kali cannot reach them directly
# before VPN. Connect via jumpbox or apply locally on each machine first.
declare -A HOSTS=(
    ["privdns"]="172.16.12.11:${SCRIPT_DIR}/privdns.yaml"
    ["privdocker"]="172.16.12.12:${SCRIPT_DIR}/containers.yaml"
    ["pubdns"]="172.16.10.35:${SCRIPT_DIR}/pubdns.yaml"
    ["pubdocker"]="172.16.10.36:${SCRIPT_DIR}/publicdocker.yaml"
    ["vpn"]="172.16.10.40:${SCRIPT_DIR}/vpn.yaml"
    ["jumpbox"]="172.16.10.41:${SCRIPT_DIR}/jumpbox.yaml"
    ["remoteuser"]="172.16.21.20:${SCRIPT_DIR}/remoteuser.yaml"
)

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=5"

# ---------------------------------------------------------------------------
apply_host() {
    local name="$1"
    local ip yaml
    ip="${HOSTS[$name]%%:*}"
    yaml="${HOSTS[$name]##*:}"

    echo "==> Applying ${yaml} to ${name} (${ip})"
    if ! ping -c1 -W2 "${ip}" &>/dev/null; then
        echo "    SKIP: ${ip} unreachable"
        return
    fi

    # Detect interface on the remote host
    IFACE=$(ssh ${SSH_OPTS} root@"${ip}" \
        "ip -o link show | awk -F': ' '\$2!~/lo|docker|br-|veth/ {print \$2; exit}'")

    if [[ -z "${IFACE}" ]]; then
        echo "    ERROR: could not detect interface on ${name}"
        return
    fi

    echo "    Interface detected: ${IFACE}"

    # Upload YAML with the correct interface name substituted
    sed "s/enp0s3/${IFACE}/g" "${yaml}" \
        | ssh ${SSH_OPTS} root@"${ip}" \
            "cat > /etc/netplan/99-neutron.yaml && chmod 600 /etc/netplan/99-neutron.yaml && netplan apply && echo '    netplan applied OK'"
}

check_hosts() {
    echo "==> Connectivity check"
    for name in "${!HOSTS[@]}"; do
        local ip="${HOSTS[$name]%%:*}"
        if ping -c1 -W2 "${ip}" &>/dev/null; then
            echo "  UP   ${name} (${ip})"
        else
            echo "  DOWN ${name} (${ip})"
        fi
    done
}

# ---------------------------------------------------------------------------
case "${1:-help}" in
    all)
        for name in "${!HOSTS[@]}"; do apply_host "${name}"; done
        ;;
    check)
        check_hosts
        ;;
    help|--help|-h)
        echo "Usage: $0 <privdns|privdocker|pubdns|pubdocker|vpn|jumpbox|remoteuser|all|check>"
        ;;
    *)
        if [[ -v "HOSTS[$1]" ]]; then
            apply_host "$1"
        else
            echo "Unknown host: $1"
            echo "Known hosts: ${!HOSTS[*]}"
            exit 1
        fi
        ;;
esac
