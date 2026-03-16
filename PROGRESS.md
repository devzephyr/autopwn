# RIS602 Autopwn — Session Progress & Continuation Notes

> Last updated: 2026-03-16
> Branch: `claude/review-current-state-GYu7R`
> Status: **Topology redesign in progress — Vagrant infrastructure partially complete**

---

## What Is Built and Working

### Python Pipeline — Complete ✅

All 8 stages of `autopwn.py` are written and committed.

| File | Stage | Status |
|---|---|---|
| `autopwn.py` | Orchestrator (CLI + linear pipeline) | ✅ |
| `modules/discovery.py` | Stage 1: ARP + multi-probe + rDNS + DNS AXFR | ✅ |
| `modules/enrichment.py` | Stage 2: nmap SYN scan + NSE + 12 host flags | ✅ |
| `modules/ad_enum.py` | Stage 3: LDAP anon bind + AS-REP roast + Kerberoast + hashcat | ✅ |
| `modules/planner.py` | Stage 4: 19-technique confidence scoring | ✅ |
| `modules/exploits/smb.py` | MS17-010 (Metasploit) + null session + share walk | ✅ |
| `modules/exploits/web.py` | WordPress brute-force + DVWA/sqlmap | ✅ |
| `modules/exploits/database.py` | MySQL empty-pass + Redis unauth | ✅ |
| `modules/exploits/ssh.py` | paramiko brute-force (6 users × wordlist) | ✅ |
| `modules/exploits/winrm.py` | pywinrm NTLM auth + enum commands | ✅ |
| `modules/exploits/mssql.py` | MSSQL SA empty-pass + xp_cmdshell | ✅ |
| `modules/exploits/rdp.py` | BlueKeep check + xfreerdp credential test | ✅ |
| `modules/exploits/nfs.py` | showmount + mount + recursive file hunt | ✅ |
| `modules/exploits/nextcloud.py` | OCS user enum + brute-force + WebDAV dump | ✅ |
| `modules/reuse.py` | Stage 6: credential reuse across all hosts/services | ✅ |
| `modules/postex.py` | Stage 7: Windows (kiwi/secretsdump) + Linux enum | ✅ |
| `modules/report.py` + `templates/report.html` | Stage 8: Jinja2 + Bootstrap 5 HTML report | ✅ |

### Wordlists — Complete ✅

- `wordlists/ssh_passwords.txt` — 20 entries
- `wordlists/wp_passwords.txt` — 50 entries
- `wordlists/dns_names.txt` — 60 DNS brute-force names

---

## Vagrant Lab — Original Topology (Built, Superseded)

These files exist and are committed but represent the **old** topology that is being replaced:

| File | Replaces | Notes |
|---|---|---|
| `vagrant/provision/corpweb.sh` | → containers.sh | DVWA + MySQL (standalone) |
| `vagrant/provision/intweb.sh` | → containers.sh | WordPress + nginx |
| `vagrant/provision/filesharing.sh` | → containers.sh | Nextcloud + NFS (standalone) |
| `vagrant/provision/esite.sh` | → containers.sh | SQLi e-commerce + MySQL + Redis |

These **four files should be deleted** when the new topology is implemented.

---

## Topology Redesign — Decided, Not Yet Built

### Agreed New Architecture

```
VLAN10 — 172.16.10.0/24 — Internal
  172.16.10.1   pfsense (gateway)
  172.16.10.10  dc01        Windows Server 2022 — AD DS, ADCS, DNS
  172.16.10.20  adminws     Windows 10 — hradmin logged in, domain-joined
  172.16.10.21  userws      Windows 10 — jsmith logged in, domain-joined
  172.16.10.53  privdns     Ubuntu — Bind9, authoritative for neutron.local

VLAN20 — 172.16.20.0/24 — Server / Container Host
  172.16.20.1   pfsense (gateway)
  172.16.20.10  containers  Ubuntu — Docker Compose host:
                  :80/:443    corpweb    Company landing page (PUBLIC)
                  :8080/:8443 esite      E-commerce + SQLi + DVWA (PUBLIC)
                  :8069       odoo       Odoo 16 ERP (INTERNAL — firewall blocks)
                  :9000/:9443 nextcloud  Nextcloud file sharing (INTERNAL — firewall blocks)
                  :3306       mysql      Empty root password (exposed for lab)
                  :6379       redis      No-auth Redis (exposed for lab)
                  :2049       nfs        NFS world-readable /srv/files (host-level)

VLAN30 — 172.16.30.0/24 — DMZ
  172.16.30.1   pfsense (gateway)
  172.16.30.10  pubdns      Ubuntu — Bind9, public DNS only (neutron.local → NXDOMAIN)
  172.16.30.20  jumpbox     Ubuntu — SSH + xRDP jump host, saved domain creds (postex finding)
  172.16.30.30  vpn         Ubuntu — OpenVPN, PKI cert auth, pushes privdns to clients

VLAN40 — 172.16.40.0/24 — External Simulation
  172.16.40.1   pfsense (gateway)
  172.16.40.10  remoteuser  Ubuntu — OpenVPN client, uses pubdns (simulates external user)
  172.16.40.50  kali        Kali Linux — autopwn attacker
```

### pfSense Firewall Rules (New)

| Source | Destination | Ports | Action | Reason |
|---|---|---|---|---|
| VLAN40 | VLAN20 | 80, 443, 8080, 8443 | ALLOW | Public web sites |
| VLAN40 | VLAN20 | 8069, 9000, 9443 | BLOCK | Internal apps |
| VLAN40 | VLAN10 | any | BLOCK | External cannot reach AD |
| VLAN40 | VLAN30 | 1194/udp | ALLOW | VPN connect |
| VLAN40 | WAN | any | ALLOW | Internet access |
| VLAN30 | VLAN20 | 80, 443, 8080, 8443 | ALLOW | DMZ reaches public sites |
| VLAN30 | VLAN20 | 8069, 9000, 9443 | BLOCK | Internal apps from DMZ |
| VLAN30 | VLAN10 | any | BLOCK | DMZ cannot reach AD |
| VLAN30 | WAN | any | ALLOW | DMZ outbound |
| VLAN20 | VLAN10 | 88, 389, 445, 636 | ALLOW | Container host auths to AD |
| VLAN10 | any | any | ALLOW | Internal full access |
| LAN (mgmt) | any | any | ALLOW | Host management |

### DNS Split-Horizon Behaviour

- **privdns (172.16.10.53)**: Authoritative for `neutron.local`. Serves VLAN10/20/30 and VPN clients (10.8.0.0/24). VLAN40 queries → REFUSED.
- **pubdns (172.16.30.10)**: No `neutron.local` zone. `*.neutron.local` → NXDOMAIN. Forwards everything else to 8.8.8.8.
- VPN push: `dhcp-option DNS 172.16.10.53` and routes to VLAN10/20/30.

---

## Files That Need To Be Written Next Session

### New Provision Scripts

| File | VM | Priority |
|---|---|---|
| `vagrant/provision/containers.sh` | 172.16.20.10 | **HIGH** — replaces 4 old VMs |
| `vagrant/provision/privdns.sh` | 172.16.10.53 | **HIGH** |
| `vagrant/provision/pubdns.sh` | 172.16.30.10 | **HIGH** |
| `vagrant/provision/jumpbox.sh` | 172.16.30.20 | MEDIUM |
| `vagrant/provision/remoteuser.sh` | 172.16.40.10 | MEDIUM |
| `vagrant/provision/adminws.ps1` | 172.16.10.20 | MEDIUM |
| `vagrant/provision/userws.ps1` | 172.16.10.21 | MEDIUM |

### Modified Existing Files

| File | Change Needed |
|---|---|
| `vagrant/Vagrantfile` | Complete rewrite — add 7 new VMs, add VLAN40, remove 4 old VMs |
| `vagrant/provision/pfsense_config.xml` | Add OPT4 (VLAN40) interface + new firewall rules |
| `vagrant/provision/vpn.sh` | Update IP: 172.16.30.10 → 172.16.30.30; add PRIVDNS_IP env var for push DNS |
| `vagrant/provision/kali.sh` | Update IP: 172.16.30.50 → 172.16.40.50; gateway 172.16.30.1 → 172.16.40.1 |
| `vagrant/preflight.sh` | Add `gusztavvargadr/windows-10` to BOXES array; update RAM minimum to 24GB |
| `vagrant/provision/dc01.ps1` | Add DNS A records for new hosts (privdns, containers, pubdns, jumpbox, adminws, userws) |

### Files To Delete

```
vagrant/provision/corpweb.sh     ← replaced by containers.sh
vagrant/provision/intweb.sh      ← replaced by containers.sh
vagrant/provision/filesharing.sh ← replaced by containers.sh
vagrant/provision/esite.sh       ← replaced by containers.sh
```

### Python Module Updates Needed (lower priority)

- `modules/enrichment.py`: Add ports 8069 (Odoo), 8080 (esite), 8443 to `PORT_SCRIPTS` and `INTERESTING_PORTS`
- `modules/planner.py`: Add `odoo_default` scoring rule (port 8069 open, default admin/admin creds)
- `modules/exploits/`: Consider adding `odoo.py` for Odoo default credential exploitation

---

## Vagrant New Topology — Startup Sequence

Once all files are written, the full startup procedure is:

```bash
# 0. Validate environment (no VMs started)
cd autopwn/vagrant && ./preflight.sh

# 1. Boot all VMs (dc01 comes up first, others in parallel)
vagrant up

# 2. Wait ~5 min for DC01 to finish rebooting after AD forest promotion
vagrant provision dc01 --provision-with dc01-pass2

# 3. Join workstations to domain (requires dc01-pass2 to be complete)
vagrant provision adminws --provision-with adminws-join
vagrant provision userws --provision-with userws-join

# 4. Attack from Kali
vagrant ssh kali
python3 /opt/autopwn/autopwn.py --target 172.16.20.0/24   # public-facing first
# After VPN pivot or credential reuse:
python3 /opt/autopwn/autopwn.py --target 172.16.10.0/24   # internal
```

---

## RAM Budget (New Topology)

| VM | OS | RAM |
|---|---|---|
| pfsense | pfSense (FreeBSD) | 512 MB |
| dc01 | Windows Server 2022 Core | 4096 MB |
| privdns | Ubuntu 22.04 | 512 MB |
| containers | Ubuntu 22.04 + Docker | 4096 MB |
| pubdns | Ubuntu 22.04 | 512 MB |
| jumpbox | Ubuntu 22.04 + xRDP | 1024 MB |
| vpn | Ubuntu 22.04 | 512 MB |
| adminws | Windows 10 | 2048 MB |
| userws | Windows 10 | 2048 MB |
| remoteuser | Ubuntu 22.04 | 512 MB |
| kali | Kali Linux | 2048 MB |
| **Total** | | **~18 GB** |

Campus workstations have 64 GB RAM — well within budget.

---

## Vagrant Box References

| Box | Used by | Version pinned? |
|---|---|---|
| `nicholaswilde/pfsense` | pfsense | no |
| `gusztavvargadr/windows-server-2022-standard-core` | dc01 | `2309.0.2402` |
| `gusztavvargadr/ubuntu-server-2204` | all Linux VMs | no |
| `gusztavvargadr/windows-10` | adminws, userws | no (add to preflight) |
| `kalilinux/rolling` | kali | no |

---

## Key Design Decisions (Do Not Change)

1. **No hardcoded IPs in provisioners** — all addresses come from Vagrantfile constants passed as env vars (`$HOST_IP`, `$DC_IP`, etc.)
2. **Idempotent provisioners** — every script can be run twice safely (marker files, `CREATE TABLE IF NOT EXISTS`, `INSERT IGNORE`, etc.)
3. **Atomic JSON writes** — all Python state files use write-to-.tmp then `os.rename()`
4. **DNS AXFR** — discovery.py attempts zone transfer first; this survives IP topology scrambles
5. **Two-pass DC provisioning** — Pass 1 installs AD DS and reboots; Pass 2 (`run: "never"`) runs post-reboot
6. **Container host consolidation** — All 4 web services run as Docker containers on a single Ubuntu VM to save RAM
7. **Public vs internal firewall split** — pfSense BLOCKS Odoo (:8069) and Nextcloud (:9000) from VLAN30/40; only ports 80/443/8080/8443 are externally reachable
8. **Split-horizon DNS** — privdns (internal) vs pubdns (DMZ/external); remoteuser uses pubdns until VPN connects

---

## Attack Chains This Topology Enables

1. **External → Public web exploit** — SQLi on esite (VLAN40 → VLAN20:8080) → DB dump → creds → lateral move
2. **External → VPN pivot** — Brute VPN endpoint or steal client cert (postex on vpn/jumpbox) → connect VPN → internal access → AD enum
3. **Internal → AD attack** — LDAP enum → AS-REP roast (jsmith) → hashcat → Kerberoast (svc_backup) → domain compromise
4. **Internal → MS17-010** — If a Windows 7/2008 VM is added later; currently placeholder in planner
5. **Jump box pivot** — SSH/RDP into jumpbox (VLAN30) → find saved domain creds → WinRM to adminws → kiwi dump → domain admin
6. **NFS world-readable** — Mount /srv/files from container host → find backup.sql + id_rsa → credential reuse
7. **Nextcloud brute-force** — After internal access via VPN → OCS user enum → brute admin → WebDAV sensitive file download
8. **Odoo default creds** — admin/admin default on fresh Odoo → internal access

---

*For questions about this project, see `CLAUDE.md` for full architecture docs.*
