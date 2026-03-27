## Vagrant Full Lab (Neutron Enterprise -- pfSense Topology)

The `vagrant/` directory contains the full multi-VLAN enterprise lab topology
used for live testing. Requires ~18 GB RAM. The current topology uses a single
**pfSense firewall** (7 adapters) replacing the old 3-router + OVS/GRE design.

### Topology

```
EXT -- 172.16.21.0/26 -- External (em1, gw .21.1)
  172.16.21.11   kali        Kali Linux -- AutoPwn attacker
  172.16.21.20   remoteuser  Ubuntu -- OpenVPN client (simulated external)

DMZ -- 172.16.10.32/28 -- Public Services (em2, gw .10.33)
  172.16.10.35   pubdns      Ubuntu -- Public DNS (BIND9, no recursion)
  172.16.10.36   pubdocker   Ubuntu + Docker:
                   :80/:443    corp/shop   WordPress (public web)
  172.16.10.40   vpn         Ubuntu -- OpenVPN server, SSH (pivot point)
  172.16.10.41   jumpbox     Ubuntu -- SSH + xRDP, saved domain creds

VLAN10 -- 172.16.10.0/28 -- Internal Admin (em3, gw .10.1)
  (no hosts currently deployed -- reserved for Ansible controller)

VLAN20 -- 172.16.10.16/28 -- Internal Users (em4, gw .10.17)
  172.16.10.18   rootca      Ubuntu -- Root CA (not running)
  172.16.10.19   intca       Ubuntu -- Intermediate CA (not running)

VLAN30 -- 172.16.12.0/27 -- Core Infrastructure (em5, gw .12.1)
  172.16.12.10   dc01        Windows Server 2022 -- AD DS, DHCP, WinRM
  172.16.12.11   privdns     Ubuntu -- Private DNS (BIND9, authoritative)
  172.16.12.12   privdocker  Ubuntu + Docker:
                   :3306       mysql      Empty root password
                   :6379       redis      No-auth Redis
                   :2049       nfs        World-readable /srv/files
                   :8069       odoo       ERP (admin:admin)
                   :9000       nextcloud  File sharing (admin:password)

VLAN40 -- 172.16.12.32/27 -- Reserved (em6, gw .12.33)
  (empty -- no hosts assigned)
```

### pfSense Firewall Policy

| Source | Destination | Rule | Notes |
|--------|-------------|------|-------|
| EXT | DMZ | Allow SSH, HTTP/S, VPN, RDP | Public service access |
| EXT | VLAN10-40 | **Block all** | Segmentation enforced |
| DMZ vpn (.40) | VLAN30 | Allow all | VPN pivot path (NAT masquerade) |
| DMZ jumpbox (.41) | VLAN30 DC | Allow 88, 389, 445, 5985 | AD management |
| DMZ pubdocker (.36) | VLAN30 privdocker | Allow 3306, 6379 | DB pivot chain |
| DMZ (others) | VLAN10-40 | **Block all** | Default deny |

### NAT Port-Forwards (replicates old DNAT)

| External Port | Target | Service | Security Intent |
|---------------|--------|---------|-----------------|
| EXT:80 | pubdocker .10.36:80 | corp/shop HTTP | Legitimate public access |
| EXT:443 | pubdocker .10.36:443 | corp/shop HTTPS | Legitimate public access |
| EXT:8080 | privdocker .12.12:8069 | Odoo ERP | **Intentional misconfig** |
| EXT:8443 | privdocker .12.12:443 | files HTTPS | **Intentional misconfig** |
| EXT:9000 | privdocker .12.12:9000 | Nextcloud | **Intentional misconfig** |
| DMZ:3306 | privdocker .12.12:3306 | MySQL | DMZ-only pivot path |
| DMZ:6379 | privdocker .12.12:6379 | Redis | DMZ-only pivot path |

### Start

```bash
cd vagrant
./preflight.sh          # verify RAM, Vagrant, and required boxes
vagrant up              # boots all VMs (~15 min first run)

# DC01 requires a second provisioning pass after AD forest promotion reboot
vagrant provision dc01 --provision-with dc01-pass2
```

### Attack

```bash
vagrant ssh kali
cd /opt/autopwn

# Start from the external network -- scan DMZ first
sudo python3 autopwn.py --target 172.16.10.32/28

# AutoPwn will pivot into 172.16.12.0/27 automatically when:
#   - VPN server is compromised and .ovpn config is found
#   - Or jumpbox is compromised and domain creds are recovered
# The orchestrator detects new routes from post-ex output and
# queues them for the next iteration.

# To also scan the pfSense NAT'd services directly:
sudo python3 autopwn.py --target 172.16.10.32/28 172.16.21.1/32

# Force more pivot iterations (default: 3)
sudo python3 autopwn.py --target 172.16.10.32/28 --max-iterations 5
```

### Attack Chains

| # | Chain | Entry Point | Pivot | Outcome |
|---|-------|-------------|-------|---------|
| 1 | External web exploit | WordPress on pubdocker :443 | DB creds via MySQL port-fwd | Internal host access |
| 2 | VPN pivot | SSH brute vpn.neutron.local | OpenVPN .ovpn + keys staged | Full VLAN30 access |
| 3 | Jumpbox cred theft | SSH brute jumpbox | domain-creds.txt on disk | WinRM to DC |
| 4 | NAT port-fwd discovery | Nmap finds :8080/:8443/:9000 | Odoo/Nextcloud default creds | Data exfil |
| 5 | NFS loot (post-pivot) | mount privdocker:/srv/files | passwords.txt, backup.sql, id_rsa | Credential reuse |
| 6 | AD full chain | LDAP anon bind on DC | AS-REP roast + Kerberoast | Domain Admin (hradmin) |
| 7 | Redis RCE (post-pivot) | redis-cli to .12.12:6379 | CONFIG SET dir/dbfilename | Shell on privdocker |
| 8 | MS17-010 (if unpatched) | EternalBlue on Windows host | Meterpreter SYSTEM | Full host compromise |

### Populate AD with BadBlood (optional)

```powershell
# Run on dc01 as Domain Admin
git clone https://github.com/davidprowe/BadBlood C:\BadBlood
cd C:\BadBlood
.\invoke-badblood.ps1
```

BadBlood creates AS-REP-roastable accounts, Kerberoastable service accounts
with SPNs, and weak passwords matching the AutoPwn wordlists. Stage 3 will
enumerate and crack them automatically.
