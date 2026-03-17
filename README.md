# AutoPwn

> Topology-agnostic automated internal network penetration testing pipeline.  
> RIS602 Network Penetration Testing — Seneca Polytechnic

AutoPwn accepts a single CIDR as input and autonomously walks the kill chain from host discovery through post-exploitation, credential reuse, and lateral movement — repeating the cycle until no new attack surface remains. Every stage writes a JSON checkpoint; the pipeline can be paused and resumed at any point.

---

## Pipeline

```
python3 autopwn.py --target 172.16.10.0/24
```

```
CIDR input
  │
  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  ITERATION LOOP  (repeats until convergence or --max-iterations)    │
│                                                                     │
│  Stage 1 ─ Host Discovery        state/discovery.json              │
│            ARP sweep · TCP/UDP probes · rDNS · DNS brute-force      │
│                                                                     │
│  Stage 2 ─ Service Enrichment    state/services.json               │
│            Nmap SYN + version + OS · 12 NSE script bundles         │
│                                                                     │
│  Stage 3 ─ AD Enumeration        state/ad_findings.json            │
│            LDAP anon bind · AS-REP roast · Kerberoast · hashcat    │
│                                                                     │
│  Stage 4 ─ Attack Planning       state/attack_plan.json            │
│            19-technique confidence scoring · priority ranking       │
│                                                                     │
│  Stage 5 ─ Exploitation          state/exploitation.json           │
│            Dispatches to exploit modules (HIGH confidence only)     │
│                                                                     │
│  Stage 6 ─ Credential Reuse      state/lateral.json                │
│            Every recovered credential tested against all services   │
│                                                                     │
│  Stage 7 ─ Post-Exploitation     state/postex.json                 │
│            Structured enum of every compromised host                │
│            Extracts new subnets from arp/route/ipconfig output      │
│                       │                                             │
│                        ──► new CIDR found? add to pending queue     │
│                            new creds found? re-run reuse sweep      │
│                            nothing new? CONVERGED → exit loop       │
└─────────────────────────────────────────────────────────────────────┘
  │
  ▼
Stage 8 ─ Report Generation       output/report_<timestamp>.html
          Jinja2 + Bootstrap 5 · executive summary · host cards
          lateral movement map · attack timeline · raw evidence
```

The loop enables automatic VLAN pivoting: if a compromised host reveals a new internal subnet via its ARP table or routing table, AutoPwn queues that subnet and attacks it next — without any manual intervention.

---

## Exploit Modules

| Technique | Module | Trigger Condition |
|---|---|---|
| MS17-010 (EternalBlue) | `exploits/smb.py` | Port 445 open, NSE confirms vulnerable |
| SMB null session | `exploits/smb.py` | Port 445, guest access detected |
| SSH brute-force | `exploits/ssh.py` | Port 22, password auth allowed |
| WordPress credential attack | `exploits/web.py` | Port 80/443, WordPress fingerprinted |
| DVWA / SQLi | `exploits/web.py` | DVWA login page detected |
| MySQL empty root | `exploits/database.py` | Port 3306, NSE confirms empty password |
| Redis unauthenticated | `exploits/database.py` | Port 6379, no-auth detected |
| MSSQL SA empty password | `exploits/mssql.py` | Port 1433, SA auth attempted |
| WinRM credential auth | `exploits/winrm.py` | Port 5985, credentials available |
| RDP credential test + BlueKeep | `exploits/rdp.py` | Port 3389 open |
| NFS world-readable mount | `exploits/nfs.py` | Port 2049, showmount responds |
| Nextcloud user enum + brute | `exploits/nextcloud.py` | Port 80/443, Nextcloud fingerprinted |
| AS-REP Roasting | `ad_enum.py` | Port 88 open, users enumerated |
| Kerberoasting | `ad_enum.py` | Port 88, domain credentials available |
| FTP anonymous | enrichment NSE | Port 21, `ftp-anon` NSE fires |
| SNMP default community | enrichment NSE | Port 161/UDP, `snmp-info` NSE fires |

All techniques respect `--dry-run`. Every exploit enforces a hard timeout (45 s default). Results are written atomically after each attempt so a crash loses at most one result.

---

## Requirements

### System (Kali Linux)

```bash
which nmap msfconsole sqlmap hashcat
```

### Python (3.13+)

```bash
pip3 install python-nmap pymysql jinja2 pywinrm --break-system-packages
```

Already present on Kali:

| Package | Version |
|---|---|
| impacket | 0.14.0.dev0 |
| ldap3 | 2.9.1 |
| paramiko | 4.0.0 |

---

## Quick Start

```bash
# Clone and enter the repo
git clone <repo-url> autopwn && cd autopwn

# Install Python dependencies
pip3 install python-nmap pymysql jinja2 pywinrm --break-system-packages

# Full run against a target subnet (requires root for raw sockets)
sudo python3 autopwn.py --target 172.16.10.0/24

# Auto-detect your local subnet
sudo python3 autopwn.py --auto

# Dry run — build the attack plan without firing any exploits
sudo python3 autopwn.py --target 172.16.10.0/24 --dry-run

# Resume a run that was interrupted
sudo python3 autopwn.py --target 172.16.10.0/24 --resume

# Allow more pivot iterations (default: 3)
sudo python3 autopwn.py --target 172.16.10.0/24 --max-iterations 5

# Skip AD enumeration and post-exploitation
sudo python3 autopwn.py --target 172.16.10.0/24 --skip-ad --skip-postex
```

---

## Docker Test Environment

Eight vulnerable containers cover every exploit module that does not require Windows. Run them on any Linux/macOS host with Docker.

### Start

```bash
docker compose up -d
docker compose ps        # all should show "Up"
```

### LDAP one-time seed (run once after first `compose up`)

```bash
# Add test users
ldapadd -x -D "cn=admin,dc=neutron,dc=local" -w adminpass \
        -H ldap://localhost:1389 -f ldap_seed/users.ldif

# Open anonymous read access
docker exec autopwn_ldap bash -c '
cp /dev/stdin /tmp/fix_acl.ldif && ldapmodify -Y EXTERNAL -H ldapi:/// -f /tmp/fix_acl.ldif
' < ldap_seed/fix_acl.ldif

# Verify
ldapsearch -x -H ldap://localhost:1389 \
  -b "dc=neutron,dc=local" "(objectClass=inetOrgPerson)" uid cn
```

### WordPress one-time setup

```bash
chmod +x wp_setup.sh && ./wp_setup.sh
```

### Container map

| IP | Hostname | Service | Credentials | Exercises |
|---|---|---|---|---|
| 172.28.0.10 | ssh-target | SSH :22 | root / password123 | `ssh.py`, postex Linux |
| 172.28.0.11 | mysql-target | MySQL :3306 | root / (empty) | `database.py` MySQL |
| 172.28.0.12 | redis-target | Redis :6379 | no auth | `database.py` Redis |
| 172.28.0.13 | ftp-target | FTP :21 | anonymous | enrichment FTP NSE |
| 172.28.0.14 | snmp-target | SNMP :161/udp | community: public | enrichment SNMP NSE |
| 172.28.0.21 | dvwa-target | HTTP :80 | admin / password | `web.py` DVWA SQLi |
| 172.28.0.31 | wordpress-target | HTTP :80 | admin / password | `web.py` WordPress |
| 172.28.0.40 | ldap-target | LDAP :389 | anonymous bind | `ad_enum.py` |

### Run autopwn against the test environment

```bash
sudo python3 autopwn.py --target 172.28.0.0/24
```

### Test individual modules

```bash
# SSH
python3 -c "from modules.exploits.ssh import exploit_ssh; print(exploit_ssh('172.28.0.10'))"

# MySQL / Redis
python3 -c "
from modules.exploits.database import exploit_mysql, exploit_redis
print(exploit_mysql('172.28.0.11'))
print(exploit_redis('172.28.0.12'))
"

# DVWA
python3 -c "from modules.exploits.web import exploit_dvwa; print(exploit_dvwa('172.28.0.21'))"

# WordPress
python3 -c "from modules.exploits.web import exploit_wordpress; print(exploit_wordpress('172.28.0.31'))"

# AD enumeration (feed it the LDAP container)
python3 -c "
import json, pathlib
data = {'hosts': [{'ip': '172.28.0.40', 'hostname': 'ldap-target',
  'os_guess': 'Linux', 'ports': [
    {'port': 389, 'protocol': 'tcp', 'state': 'open',
     'service': 'ldap', 'version': '', 'nse_results': {}}],
  'flags': {'is_domain_controller': True, 'has_wordpress': False,
            'has_dvwa': False, 'ms17_010_vulnerable': False}}]}
pathlib.Path('state').mkdir(exist_ok=True)
pathlib.Path('state/services.json').write_text(json.dumps(data, indent=2))
"
python3 modules/ad_enum.py
```

### Teardown

```bash
docker compose down          # stop, keep volumes
docker compose down -v       # stop and wipe volumes (clean slate)
```

---

## Vagrant Full Lab (Neutron Enterprise)

The `vagrant/` directory contains the full multi-VLAN enterprise lab topology used for live testing. Requires ~18 GB RAM.

### Topology

```
VLAN10 — 172.16.10.0/24 — Internal
  172.16.10.10   dc01        Windows Server 2022 — AD DS, DNS
  172.16.10.20   adminws     Windows 10 — hradmin (domain-joined)
  172.16.10.21   userws      Windows 10 — jsmith (domain-joined)
  172.16.10.53   privdns     Ubuntu — Bind9, authoritative for neutron.local

VLAN20 — 172.16.20.0/24 — Server / DMZ-facing
  172.16.20.10   containers  Ubuntu + Docker:
                   :80/:443    corpweb    Company landing page
                   :8080/:8443 esite      E-commerce + SQLi + DVWA
                   :9000/:9443 nextcloud  File sharing (internal only)
                   :3306       mysql      Empty root password
                   :6379       redis      No-auth Redis
                   :2049       nfs        World-readable /srv/files

VLAN30 — 172.16.30.0/24 — DMZ
  172.16.30.10   pubdns      Ubuntu — public DNS, *.neutron.local → NXDOMAIN
  172.16.30.20   jumpbox     Ubuntu — SSH + xRDP, saved domain creds
  172.16.30.30   vpn         Ubuntu — OpenVPN, PKI cert auth

VLAN40 — 172.16.40.0/24 — External simulation
  172.16.40.10   remoteuser  Ubuntu — OpenVPN client, simulates external user
  172.16.40.50   kali        Kali Linux — AutoPwn attacker
```

### Start

```bash
cd vagrant
./preflight.sh          # verify RAM, Vagrant, and required boxes
vagrant up              # boots all VMs (~15 min first run)

# DC01 requires a second provisioning pass after AD forest promotion reboot
vagrant provision dc01 --provision-with dc01-pass2

# Join workstations to the domain
vagrant provision adminws --provision-with adminws-join
vagrant provision userws  --provision-with userws-join
```

### Attack

```bash
vagrant ssh kali
cd /opt/autopwn

# Start from the public-facing network
sudo python3 autopwn.py --target 172.16.20.0/24

# AutoPwn will pivot into 172.16.10.0/24 automatically when
# post-exploitation reveals the internal VLAN via arp/route output.
# To force manual pivoting or extend iterations:
sudo python3 autopwn.py --target 172.16.20.0/24 --max-iterations 5
```

### Populate AD with BadBlood (optional — adds 2,500 users + misconfigurations)

```powershell
# Run on dc01 as Domain Admin
git clone https://github.com/davidprowe/BadBlood C:\BadBlood
cd C:\BadBlood
.\invoke-badblood.ps1
```

BadBlood creates AS-REP-roastable accounts, Kerberoastable service accounts with SPNs, and weak passwords matching the AutoPwn wordlists. Stage 3 will enumerate and crack them automatically.

---

## Attack Chains

The following chains have been designed into the lab topology:

| # | Chain | Entry Point | Pivot | Outcome |
|---|---|---|---|---|
| 1 | External web → DB | SQLi on esite `:8080` | Creds in DB dump | Internal host access |
| 2 | External → VPN pivot | Brute VPN or steal client cert | OpenVPN connect | Full internal access |
| 3 | Internal → Domain Admin | LDAP enum → AS-REP roast | Kerberoast svc_backup | DA compromise |
| 4 | Jump box pivot | SSH into jumpbox | Saved domain creds | WinRM → kiwi dump |
| 5 | NFS loot | Mount `/srv/files` | `backup.sql` + `id_rsa` | Credential reuse |
| 6 | Nextcloud brute | OCS user enum | WebDAV file dump | Sensitive data exfil |
| 7 | Odoo default creds | `admin:admin` on `:8069` | Internal ERP access | Data access |
| 8 | MS17-010 | EternalBlue on unpatched Windows | Meterpreter SYSTEM | Full host compromise |

---

## Project Structure

```
autopwn/
├── autopwn.py                  # Orchestrator — iterative pipeline loop
├── modules/
│   ├── discovery.py            # Stage 1: ARP + TCP/UDP + rDNS + DNS brute
│   ├── enrichment.py           # Stage 2: Nmap SYN/version/OS + NSE
│   ├── ad_enum.py              # Stage 3: LDAP + AS-REP roast + Kerberoast
│   ├── planner.py              # Stage 4: Confidence scoring + attack plan
│   ├── exploits/
│   │   ├── smb.py              # MS17-010 (Metasploit) + null session
│   │   ├── web.py              # WordPress brute + DVWA/sqlmap
│   │   ├── database.py         # MySQL empty-pass + Redis unauth
│   │   ├── ssh.py              # SSH brute-force (paramiko)
│   │   ├── winrm.py            # WinRM NTLM auth
│   │   ├── mssql.py            # MSSQL SA empty-pass + xp_cmdshell
│   │   ├── rdp.py              # RDP credential test + BlueKeep check
│   │   ├── nfs.py              # NFS world-readable mount + file hunt
│   │   └── nextcloud.py        # Nextcloud OCS enum + brute + WebDAV
│   ├── reuse.py                # Stage 6: Credential reuse engine
│   ├── postex.py               # Stage 7: Post-exploitation enumeration
│   └── report.py               # Stage 8: HTML report generator
├── templates/
│   └── report.html             # Jinja2 + Bootstrap 5 report template
├── wordlists/
│   ├── ssh_passwords.txt       # 20-entry SSH wordlist
│   ├── wp_passwords.txt        # 50-entry WordPress wordlist
│   └── dns_names.txt           # DNS brute-force names
├── ldap_seed/
│   ├── users.ldif              # Test users for Docker LDAP container
│   └── fix_acl.ldif            # Anonymous read ACL for OpenLDAP
├── vagrant/                    # Full Neutron Enterprise Lab topology
│   ├── Vagrantfile
│   ├── preflight.sh
│   └── provision/
│       ├── dc01.ps1            # Windows Server 2022 — AD DS
│       ├── adminws.ps1         # Windows 10 workstation
│       ├── userws.ps1          # Windows 10 workstation
│       ├── containers.sh       # Ubuntu Docker host (all web services)
│       ├── privdns.sh          # Internal authoritative DNS
│       ├── pubdns.sh           # DMZ/public DNS
│       ├── jumpbox.sh          # SSH/RDP jump host
│       ├── vpn.sh              # OpenVPN server
│       ├── remoteuser.sh       # External user simulation
│       ├── kali.sh             # Attacker VM setup
│       └── pfsense.sh          # pfSense firewall rules
├── docker-compose.yml          # Docker test environment
├── wp_setup.sh                 # WordPress weak-credential setup script
├── TESTING.md                  # Step-by-step test guide
└── state/                      # Auto-created — JSON checkpoints per run
```

---

## State Files

Each stage writes a JSON checkpoint that is read by the next stage. The pipeline can be interrupted and resumed at any point with `--resume`.

| File | Written by | Read by |
|---|---|---|
| `state/discovery.json` | Stage 1 | Stage 2 |
| `state/services.json` | Stage 2 | Stages 3, 4 |
| `state/ad_findings.json` | Stage 3 | Stages 4, 5, 6 |
| `state/attack_plan.json` | Stage 4 | Stage 5 |
| `state/exploitation.json` | Stage 5 | Stages 6, 7 |
| `state/lateral.json` | Stage 6 | Stage 8 |
| `state/postex.json` | Stage 7 | Orchestrator pivot logic, Stage 8 |
| `state/timeline.json` | All stages | Stage 8 |

All writes are atomic (write to `.tmp` then `os.rename`). Partial or corrupted state from a crash is never left in place.

---

## Design Constraints

- **Run as root** — Nmap SYN scanning requires raw socket privileges.
- **No hardcoded IPs** — Every target is derived from scan output or the CIDR argument. The pipeline produces identical results regardless of which VLAN the attacker sits on.
- **Topology-agnostic by design** — Stage 1 uses four independent discovery methods so that hosts filtered by ICMP are found via TCP/UDP probes; hosts not responding to probes are found via DNS brute-force.
- **Stop on first success per host** — Exploit modules do not pile on after a host is compromised.
- **Dry-run respected everywhere** — Every exploit module checks the flag before executing.
- **Timeouts on all subprocesses** — No stage can hang indefinitely.

---

*Built for RIS602 Network Penetration Testing, Seneca Polytechnic.*
