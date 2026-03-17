#!/bin/sh
# =============================================================================
# pfsense.sh — Post-config-push reload for Neutron Lab pfSense
# Runs on the pfSense (FreeBSD) VM after config.xml has been pushed.
# Uses /bin/sh — no bash-specific syntax.
#
# Interface mapping after config load:
#   vtnet0  WAN   DHCP (VirtualBox NAT — outbound internet)
#   vtnet1  LAN   172.16.99.1/24 (host-only mgmt — vagrant ssh)
#   vtnet2  OPT1  172.16.10.1/24 (VLAN10 internal)
#   vtnet3  OPT2  172.16.20.1/24 (VLAN20 servers)
#   vtnet4  OPT3  172.16.30.1/24 (VLAN30 DMZ)
#   vtnet5  OPT4  172.16.40.1/24 (VLAN40 external simulation)
# =============================================================================

echo "[pfsense] Neutron Lab pfSense provisioner starting..."

# Verify config was pushed by the file provisioner
if [ ! -f /cf/conf/config.xml ]; then
    echo "[pfsense] ERROR: /cf/conf/config.xml not found — file provisioner may have failed"
    exit 1
fi

echo "[pfsense] config.xml confirmed at /cf/conf/config.xml"

# Reload all pfSense subsystems from the new config
# This re-reads interfaces, firewall rules, NAT, DNS forwarder, routing
echo "[pfsense] Reloading pfSense subsystems (/etc/rc.reload_all)..."
/etc/rc.reload_all start 2>/dev/null || true

# Explicitly flush and reload firewall rules
echo "[pfsense] Reloading firewall rules..."
/usr/local/sbin/pfctl -f /tmp/rules.debug 2>/dev/null || true

# Reload DNS forwarder (dnsmasq with neutron.local override)
echo "[pfsense] Reloading DNS forwarder..."
/usr/local/sbin/pfctl -e 2>/dev/null || true

echo ""
echo "[pfsense] ============================================"
echo "[pfsense] Neutron Lab pfSense provisioning complete"
echo "[pfsense] Web GUI: https://172.16.99.1 (admin/pfsense)"
echo "[pfsense] Interfaces:"
echo "[pfsense]   WAN  vtnet0: DHCP (VirtualBox NAT)"
echo "[pfsense]   LAN  vtnet1: 172.16.99.1/24  (mgmt)"
echo "[pfsense]   OPT1 vtnet2: 172.16.10.1/24  (VLAN10 internal)"
echo "[pfsense]   OPT2 vtnet3: 172.16.20.1/24  (VLAN20 servers)"
echo "[pfsense]   OPT3 vtnet4: 172.16.30.1/24  (VLAN30 DMZ)"
echo "[pfsense]   OPT4 vtnet5: 172.16.40.1/24  (VLAN40 external)"
echo "[pfsense] ============================================"
