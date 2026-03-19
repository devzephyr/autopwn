#!/usr/bin/env bash
# =============================================================================
# apply.sh — Apply netplan static IP configs to Neutron Lab Linux hosts
#
# Run this FROM Kali (172.16.40.50) via SSH on each target host, or copy
# the relevant YAML to each machine and run netplan apply locally.
#
# Usage:
#   bash apply.sh <hostname>          # apply to a specific host
#   bash apply.sh all                 # apply to all reachable Linux hosts
#   bash apply.sh check               # ping-check all hosts first
#
# Requirements: ssh key or password access to each host as root/sudo.
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Host → config mapping  (hostname : ip : yaml-file)
declare -A HOSTS=(
    ["privdns"]="172.16.10.53:${SCRIPT_DIR}/privdns.yaml"
    ["containers"]="172.16.20.10:${SCRIPT_DIR}/containers.yaml"
    ["pubdns"]="172.16.30.10:${SCRIPT_DIR}/pubdns.yaml"
    ["jumpbox"]="172.16.30.20:${SCRIPT_DIR}/jumpbox.yaml"
    ["vpn"]="172.16.30.30:${SCRIPT_DIR}/vpn.yaml"
    ["remoteuser"]="172.16.40.10:${SCRIPT_DIR}/remoteuser.yaml"
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
        echo "Usage: $0 <privdns|containers|pubdns|jumpbox|vpn|remoteuser|all|check>"
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
