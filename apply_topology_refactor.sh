#!/bin/bash
# apply_topology_refactor.sh
#
# Step-by-step runbook for applying all topology changes.
# Run each section on the indicated machine.
# This file is documentation, not meant to be executed as a single script.

cat << 'RUNBOOK'
=============================================================================
  TOPOLOGY REFACTOR RUNBOOK
  Apply in order. Each section indicates which machine to run on.
=============================================================================

STEP 1: PFSENSE NAT PORT-FORWARDS
----------------------------------
Machine: pfSense (web GUI at https://172.16.21.1)

  1. Log into pfSense web GUI
  2. Go to Firewall > NAT > Port Forward
  3. Add each of the 7 rules from pfsense_nat_and_firewall.sh
     (or paste the XML blocks into /cf/conf/config.xml)
  4. For each rule, select "Add associated filter rule" to auto-create
     the companion firewall pass rule
  5. Apply changes

  Verify:
    From Kali: nmap -sT -p 80,443,8080,8443,9000 172.16.21.1
    Expected: all 5 ports open (NAT forwards active)


STEP 2: PFSENSE FIREWALL RULES FOR DMZ PIVOT
---------------------------------------------
Machine: pfSense (web GUI)

  1. Go to Firewall > Rules > DMZ (em2)
  2. Add rules (ABOVE default block):

     a) Pass TCP from 172.16.10.40 (vpn) to VLAN30 net, any port
        Description: "VPN server full access to VLAN30"

     b) Pass TCP from 172.16.10.41 (jumpbox) to 172.16.12.10 (DC),
        ports 88, 389, 445, 5985
        Description: "Jumpbox to DC AD services"

     c) Pass TCP from 172.16.10.36 (pubdocker) to 172.16.12.12 (privdocker),
        ports 3306, 6379
        Description: "pubdocker to privdocker DB services"

  3. Apply changes

  Verify:
    From pubdocker (after SSH compromise):
      mysql -h 172.16.10.33 -P 3306 -u root
      (connects via pfSense DMZ port-forward to privdocker)


STEP 3: VPN SERVER SETUP (for autopwn pivot chain)
---------------------------------------------------
Machine: vpn.neutron.local (172.16.10.40)

  # Enable SSH with weak credentials
  sudo useradd -m -s /bin/bash admin
  echo "admin:P@ssw0rd" | sudo chpasswd
  sudo sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' \
       /etc/ssh/sshd_config
  sudo systemctl restart sshd

  # Stage OpenVPN client config for autopwn to discover
  sudo mkdir -p /home/admin/vpn-client
  sudo cp /etc/openvpn/client/neutron-client.ovpn /home/admin/vpn-client/
  sudo cp /etc/openvpn/client/client.key /home/admin/vpn-client/
  sudo cp /etc/openvpn/client/client.crt /home/admin/vpn-client/
  sudo cp /etc/openvpn/client/ca.crt /home/admin/vpn-client/
  sudo chown -R admin:admin /home/admin/vpn-client
  sudo chmod 600 /home/admin/vpn-client/*.key

  Verify:
    From Kali: ssh admin@172.16.10.40  (password: P@ssw0rd)
    ls /home/admin/vpn-client/  (should show .ovpn + key files)


STEP 4: JUMPBOX SETUP
----------------------
Machine: jumpbox (172.16.10.41)

  # Apply netplan (if not done)
  sudo cp /opt/autopwn/netplan/41-jumpbox.yaml /etc/netplan/
  sudo netplan apply

  # Verify SSH with weak creds
  ssh root@172.16.10.41  (password: password123)

  # Stage domain credentials for post-ex discovery
  sudo mkdir -p /root/admin
  cat > /root/admin/domain-creds.txt << EOF
# Domain admin credentials (for emergency access)
# Last updated: 2025-10-08
Domain: neutron.local
Username: hradmin
Password: HrAdmin2024!
EOF

  # Leave breadcrumbs in bash_history
  echo "smbclient //172.16.12.10/SYSVOL -U hradmin%HrAdmin2024!" >> /root/.bash_history
  echo "evil-winrm -i 172.16.12.10 -u hradmin -p HrAdmin2024!" >> /root/.bash_history


STEP 5: AUTOPWN SCRIPT ALIGNMENT
---------------------------------
Machine: Kali (172.16.21.11)

  cd /opt/autopwn

  # 5a. Update README.md Vagrant section
  #     Replace everything between "## Vagrant Full Lab" and "## Project Structure"
  #     with the contents of README_vagrant_section.md

  # 5b. Add TOPOLOGY.md to repo root
  cp TOPOLOGY.md /opt/autopwn/

  # 5c. Update dns_names.txt wordlist (add any missing hostnames)
  cat >> wordlists/dns_names.txt << 'EOF'
erp
files
odoo
nextcloud
privdocker
pubdocker
introuter
EOF
  sort -u wordlists/dns_names.txt -o wordlists/dns_names.txt

  # 5d. Update the default target suggestion in autopwn.py help text
  #     (if it still references old /24 subnets)
  sed -i 's|172.16.20.0/24|172.16.10.32/28|g' autopwn.py
  sed -i 's|172.16.10.0/24|172.16.10.32/28|g' autopwn.py
  sed -i 's|172.16.30.0/24|172.16.10.32/28|g' autopwn.py
  sed -i 's|172.16.40.0/24|172.16.21.0/26|g' autopwn.py

  # 5e. Commit all changes
  git add -A
  git commit -m "refactor: reconcile topology docs with pfSense reality

  - Add TOPOLOGY.md as canonical reference (resolves 4-way conflict)
  - Rewrite README Vagrant section with real pfSense addressing
  - Old /24 subnets replaced with actual /28 and /27 CIDRs
  - Add pfSense NAT port-forward documentation
  - Add access control matrix
  - Update dns_names.txt with missing hostnames"


STEP 6: VERIFY END-TO-END
--------------------------
Machine: Kali

  # Verify NAT port-forwards are reachable
  nmap -sT -p 80,443,8080,8443,9000 172.16.21.1
  # Expected: 5 open ports

  # Verify DMZ services directly reachable
  nmap -sT -p 22,80,443 172.16.10.35-36
  # Expected: pubdns :53, pubdocker :22,:80,:443

  # Verify VLAN30 is NOT directly reachable
  nmap -sT -p 88,389,3306 172.16.12.10-12 --max-retries 1
  # Expected: filtered/timeout (blocked by pfSense)

  # Dry run of autopwn against DMZ
  sudo python3 autopwn.py --target 172.16.10.32/28 --dry-run

  # Full run (will find pubdocker SSH, WordPress, then pivot)
  sudo python3 autopwn.py --target 172.16.10.32/28 --max-iterations 5


=============================================================================
  WHAT CHANGED VS OLD TOPOLOGY (for your report/presentation)
=============================================================================

  REMOVED:
    - Simulated Internet Pi (172.16.21.1 old)
    - Border Router (Ubuntu, FRR/OSPF, 172.16.21.2)
    - Internal Router (Ubuntu, nftables DNAT, DHCP-relay, FRR/OSPF)
    - OVS Switch-1 and Switch-2 (GRE tunnel)
    - All nftables rules (PREROUTING DNAT, INPUT, FORWARD, OUTPUT)
    - OSPF between Border and Internal routers

  ADDED:
    - pfSense CE (single appliance, 7 interfaces)
    - pfSense NAT port-forwards (7 rules, replaces broken DNAT)
    - pfSense per-interface firewall rules
    - Per-host DMZ access rules (vpn/jumpbox/pubdocker each get
      specific permissions to VLAN30, not blanket allow)

  FIXED:
    - Old DNAT had duplicate rules per port (second rule never fired)
    - Old DNAT routed ALL traffic to privdocker, pubdocker was unreachable
    - New NAT gives each service its own unique external port
    - Public web (80/443) now correctly reaches pubdocker
    - Internal services (Odoo/Nextcloud) on separate high ports (8080/9000)
    - DB services (MySQL/Redis) restricted to DMZ-only access

  PRESERVED:
    - Same subnet assignments (same /28 and /27 ranges)
    - Same host IPs (DC .12.10, privdns .12.11, etc.)
    - Same VLAN segmentation philosophy
    - Same attack chains (just with corrected routing)

RUNBOOK
