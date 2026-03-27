# Neutron Enterprise Lab -- Canonical Topology Reference

**Version:** 3.0 (pfSense migration)
**Last updated:** 2026-03-26
**Authors:** Patrick Miskowiec, Abdul Folarin, Jordan Lam -- Group 5
**Course:** RIS602 Network Penetration Testing / SPR500 -- Seneca Polytechnic

---

## 1. Migration Summary

The Lab 02 topology used a 3-router architecture (Simulated Internet Pi + Border Router
+ Internal Router) with two Open vSwitch instances connected by a GRE tunnel. The
Internal Router ran FRR/OSPF for dynamic routing, ISC-DHCP-Relay for cross-VLAN
DHCP, and nftables with explicit DNAT/FORWARD/INPUT/OUTPUT chains.

The current topology replaces all three routers and both OVS switches with a single
**pfSense firewall** (7 adapters: 1 WAN + 6 internal). All inter-VLAN routing,
NAT port-forwarding, and firewall policy is now handled by pfSense.

### What was removed

- Border Router (Ubuntu, FRR/OSPF, 172.16.21.2)
- Internal Router (Ubuntu, FRR/OSPF, nftables, DHCP-relay)
- OVS Switch-1 and Switch-2 (GRE tunnel between them)
- All nftables DNAT/FORWARD rules
- OSPF dynamic routing between routers

### What replaced them

- pfSense CE (FreeBSD, em0-em6, web GUI management)
- pfSense NAT port-forward rules (replaces nftables DNAT)
- pfSense firewall rules per interface (replaces nftables FORWARD/INPUT)
- pfSense static routing (replaces OSPF, acceptable for lab scale)

---

## 2. VLAN Numbering Reconciliation

Four sources existed with conflicting VLAN-to-subnet mappings. This document
establishes the **pfSense/Tables numbering** as canonical, since pfSense is the
running system.

| Subnet           | Lab 02 Report Label | Lab 5 Tables Label | pfSense Interface | **Canonical Label** |
|------------------|--------------------|--------------------|-------------------|---------------------|
| 172.16.21.0/26   | External           | External           | em1 (EXT)         | **EXT**             |
| 172.16.10.32/28  | VLAN 30            | DMZ                | em2 (DMZ)         | **DMZ**             |
| 172.16.10.0/28   | VLAN 10            | VLAN10             | em3 (VLAN10)      | **VLAN10**          |
| 172.16.10.16/28  | VLAN 20            | VLAN20             | em4 (VLAN20)      | **VLAN20**          |
| 172.16.12.0/27   | VLAN 40            | VLAN30             | em5 (VLAN30)      | **VLAN30**          |
| 172.16.12.32/27  | (not in report)    | VLAN40             | em6 (VLAN40)      | **VLAN40**          |

**Key conflict resolved:** The Lab 02 report called the public services subnet (.10.32/28)
"VLAN 30" and the core infrastructure subnet (.12.0/26) "VLAN 40." The Lab 5 Tables
and pfSense both label the public services subnet as "DMZ" and the core subnet as
"VLAN30." This document uses the Tables/pfSense convention throughout.

The repo README Vagrant section used /24 subnets (172.16.10.0/24, 172.16.20.0/24,
etc.) that exist nowhere in the real lab. That section must be rewritten entirely.

---

## 3. Network Device Table (Authoritative)

| FQDN                    | Role                    | IP Address (CIDR)     | Gateway       | Segment  |
|-------------------------|-------------------------|-----------------------|---------------|----------|
| --                      | pfSense Firewall        | em0: NAT (WAN)        | --            | WAN      |
| --                      | pfSense Firewall        | em1: 172.16.21.1/26   | --            | EXT      |
| --                      | pfSense Firewall        | em2: 172.16.10.33/28  | --            | DMZ      |
| --                      | pfSense Firewall        | em3: 172.16.10.1/28   | --            | VLAN10   |
| --                      | pfSense Firewall        | em4: 172.16.10.17/28  | --            | VLAN20   |
| --                      | pfSense Firewall        | em5: 172.16.12.1/27   | --            | VLAN30   |
| --                      | pfSense Firewall        | em6: 172.16.12.33/27  | --            | VLAN40   |
| --                      | Kali (attacker)         | 172.16.21.11/26       | 172.16.21.1   | EXT      |
| --                      | VPN User                | 172.16.21.20/26       | 172.16.21.1   | EXT      |
| pubdns.neutron.local    | Public DNS (BIND9)      | 172.16.10.35/28       | 172.16.10.33  | DMZ      |
| pubdocker (corp/shop)   | Public Docker            | 172.16.10.36/28       | 172.16.10.33  | DMZ      |
| vpn.neutron.local       | OpenVPN Server           | 172.16.10.40/28       | 172.16.10.33  | DMZ      |
| --                      | Jumpbox (SSH/RDP)        | 172.16.10.41/28       | 172.16.10.33  | DMZ      |
| dc.neutron.local        | AD DS / DHCP             | 172.16.12.10/27       | 172.16.12.1   | VLAN30   |
| privdns.neutron.local   | Private DNS (BIND9)      | 172.16.12.11/27       | 172.16.12.1   | VLAN30   |
| privdocker (erp/files)  | Private Docker            | 172.16.12.12/27       | 172.16.12.1   | VLAN30   |
| --                      | RootCA                   | 172.16.10.18/28       | 172.16.10.17  | VLAN20   |
| --                      | IntermediateCA           | 172.16.10.19/28       | 172.16.10.17  | VLAN20   |

---

## 4. Service Port Map

### DMZ Hosts (172.16.10.32/28)

| Host       | Port    | Service         | Credentials / Notes                    |
|------------|---------|-----------------|----------------------------------------|
| pubdns     | 53/tcp  | BIND9 DNS       | Recursion off; AXFR leaks zone         |
| pubdocker  | 22/tcp  | SSH             | admin:P@ssw0rd (intentionally weak)    |
| pubdocker  | 80/tcp  | HTTP            | Redirects to HTTPS                     |
| pubdocker  | 443/tcp | HTTPS           | WordPress (corp/shop)                  |
| vpn        | 22/tcp  | SSH             | admin:P@ssw0rd (staged for pivot)      |
| vpn        | 1194/udp| OpenVPN         | Certificate auth; client config staged |
| jumpbox    | 22/tcp  | SSH             | root:password123                       |
| jumpbox    | 3389/tcp| xRDP            | Domain creds saved on disk             |

### VLAN30 Hosts (172.16.12.0/27) -- Core Infrastructure

| Host       | Port     | Service         | Credentials / Vulnerability             |
|------------|----------|-----------------|-----------------------------------------|
| dc         | 88/tcp   | Kerberos        | AS-REP roastable: svc_backup            |
| dc         | 389/tcp  | LDAP            | Anonymous bind allowed                  |
| dc         | 445/tcp  | SMB             | Domain users enumerable                 |
| dc         | 636/tcp  | LDAPS           | --                                      |
| dc         | 5985/tcp | WinRM           | Domain credential auth                  |
| privdns    | 53/tcp   | BIND9 DNS       | Authoritative neutron.local; AXFR open  |
| privdocker | 80/tcp   | HTTP (Odoo)     | admin:admin                             |
| privdocker | 3306/tcp | MySQL           | root with EMPTY password                |
| privdocker | 6379/tcp | Redis           | No authentication                       |
| privdocker | 2049/tcp | NFS             | /srv/files world-readable, no_root_squash |
| privdocker | 8069/tcp | Odoo ERP        | admin:admin                             |
| privdocker | 9000/tcp | Nextcloud       | admin:password                          |

---

## 5. Access Control Matrix

### Role-Based Access Rules (pfSense Firewall Policy)

| Source         | Destination    | Allowed Ports                          | Purpose                     |
|----------------|----------------|----------------------------------------|-----------------------------|
| EXT            | DMZ            | 22, 80, 443, 1194/udp, 3389           | Public service access       |
| EXT            | VLAN10-40      | NONE                                   | Segmentation enforced       |
| DMZ (vpn .40)  | VLAN30         | ANY                                    | VPN pivot path (NAT masq)   |
| DMZ (jumpbox)  | VLAN30         | 88, 389, 445, 5985                     | AD management path          |
| DMZ (pubdocker)| VLAN30         | 3306, 6379                             | DB connection (attack chain)|
| DMZ (others)   | VLAN10-40      | NONE                                   | Default deny                |
| VLAN10         | ALL            | ANY                                    | Admin full access           |
| VLAN20         | DMZ            | 80, 443, 53                            | User web/DNS access         |
| VLAN20         | VLAN30         | 389, 445, 88 (via DHCP relay)          | Domain services             |
| VLAN30         | VLAN30         | ANY                                    | Internal service mesh       |
| VLAN30         | WAN            | 80, 443, 53                            | Outbound updates            |
| VLAN40         | --             | NONE (empty segment)                   | Reserved                    |

### NAT Port-Forward Rules (replaces old nftables DNAT)

These rules live on pfSense and make specific VLAN30 services reachable
from the DMZ without full routing access. This replicates the old Internal
Router DNAT behavior.

| pfSense Interface | Ext Port | Dest Host        | Dest Port | Service                  |
|-------------------|----------|------------------|-----------|--------------------------|
| EXT (em1)         | 80       | 172.16.10.36     | 80        | pubdocker HTTP (corp)    |
| EXT (em1)         | 443      | 172.16.10.36     | 443       | pubdocker HTTPS (shop)   |
| EXT (em1)         | 8080     | 172.16.12.12     | 8069      | privdocker Odoo ERP      |
| EXT (em1)         | 8443     | 172.16.12.12     | 443       | privdocker HTTPS (files) |
| EXT (em1)         | 9000     | 172.16.12.12     | 9000      | privdocker Nextcloud     |
| DMZ (em2)         | 3306     | 172.16.12.12     | 3306      | privdocker MySQL         |
| DMZ (em2)         | 6379     | 172.16.12.12     | 6379      | privdocker Redis         |

**Security note:** The EXT port-forwards to privdocker (8080, 8443, 9000) are
intentionally insecure. They replicate the old DNAT behavior where external
users could reach internal services through the router. In a real enterprise
this would be a misconfiguration. For the pentest lab, this creates additional
attack surface that AutoPwn can discover and exploit.

The DMZ-only port-forwards (3306, 6379) are more realistic: a compromised
DMZ host can reach the database backend, but external attackers cannot
directly hit MySQL/Redis from EXT.

---

## 6. DNS Architecture

### Private DNS (privdns.neutron.local -- 172.16.12.11)

- Authoritative for `neutron.local` forward zone
- Reverse zones: `12.16.172.in-addr.arpa`, `10.16.172.in-addr.arpa`
- A records: dc, dns1, dns2, erp, files, corp, shop, vpn
- AXFR allowed from trusted ACL (all internal segments)
- Accepts queries from VLAN10/20/30 + VPN pool
- Refuses queries from VLAN40

### Public DNS (pubdns.neutron.local -- 172.16.10.35)

- Authoritative for `neutron.local` (external subset only)
- A records: dns2 (.10.34), corp (.10.35), shop (.10.35) only
- Recursion disabled
- AXFR misconfiguration: zone transfer succeeds from pfSense DNS forwarder
  (leaks all records to external attackers -- intentional vuln)

### pfSense DNS Forwarder

- pfSense forwards DNS queries to pubdns (.10.35)
- Kali uses pfSense (.21.1) as DNS server
- Chain: Kali -> pfSense -> pubdns -> AXFR reveals all internal hosts

---

## 7. Attack Chains (Updated for pfSense Topology)

### Chain 1: External Web Exploit (via NAT port-forward)

```
Kali (.21.11)
  |-- Port scan pfSense EXT IP (.21.1) or pubdocker (.10.36)
  |-- Discover HTTP/HTTPS on pubdocker
  |-- WordPress brute-force / exploit
  |-- Shell on pubdocker
  |-- Post-ex: find DB connection strings
  |-- Connect to MySQL on privdocker via DMZ port-forward (pfSense .10.33:3306)
  |-- Dump credentials from DB
  |-- Credential reuse against other hosts
```

### Chain 2: SSH Brute -> VPN Pivot -> VLAN30 Full Access

```
Kali (.21.11)
  |-- SSH brute-force vpn.neutron.local (.10.40)
  |-- Post-ex: find /home/admin/vpn-client/*.ovpn + keys
  |-- Download .ovpn to Kali, run OpenVPN
  |-- New route: 172.16.12.0/27 via tun0
  |-- AutoPwn queues 172.16.12.0/27
  |-- Full scan of VLAN30: DC, privdns, privdocker
  |-- LDAP anon bind -> enumerate users
  |-- AS-REP roast svc_backup -> hashcat
  |-- Kerberoast svc_web/svc_sql -> hashcat
  |-- Credential reuse -> WinRM to DC as hradmin (DA)
  |-- Domain compromise
```

### Chain 3: Jumpbox Pivot -> Saved Credentials

```
Kali (.21.11)
  |-- SSH brute-force jumpbox (.10.41)
  |-- Post-ex: find /root/admin/domain-creds.txt (plaintext DA creds)
  |-- Post-ex: find .ssh/config, .bash_history
  |-- WinRM to DC (.12.10) using recovered creds
  |-- kiwi + hashdump
```

### Chain 4: Port-Forward Discovery -> Direct DB Attack

```
Kali (.21.11)
  |-- Nmap finds ports 8080, 8443, 9000 open on pfSense EXT (.21.1)
  |-- Discover Odoo on :8080 -> admin:admin
  |-- Discover Nextcloud on :9000 -> admin:password
  |-- File exfiltration from Nextcloud WebDAV
  |-- Odoo internal data access
```

### Chain 5: NFS Loot (post-pivot)

```
VLAN30 access (via VPN or jumpbox)
  |-- showmount -e 172.16.12.12
  |-- mount /srv/files
  |-- Recover: passwords.txt, backup.sql (MD5 hashes), id_rsa
  |-- Credential reuse with recovered material
```

---

## 8. Diagram (Appendix A replacement)

```
                        Internet (VirtualBox NAT)
                                |
                           [ pfSense ]
                    em0=WAN  em1-em6=internal
                   /    |      |      |     |      \
                  /     |      |      |     |       \
               em1    em2    em3    em4    em5     em6
               EXT    DMZ   V10    V20    V30     V40
            .21.0/26 .10.32/28 .10.0/28 .10.16/28 .12.0/27 .12.32/27
               |       |                           |
          +----+    +--+--+--+--+              +---+---+---+
          |         |  |  |  |  |              |   |   |
        Kali    pub pub vpn jump           DC  priv priv
        .21.11  dns dock .40  .41         .12.10 dns dock
                .35 .36                         .11  .12


 Legend:
   pub dns  = pubdns.neutron.local (BIND9, DNS :53)
   pub dock = pubdocker (corp/shop WordPress, SSH :22, HTTP/S)
   vpn      = vpn.neutron.local (OpenVPN :1194, SSH :22)
   jump     = jumpbox (SSH :22, RDP :3389)
   DC       = dc.neutron.local (AD DS, LDAP, Kerberos, WinRM)
   priv dns = privdns.neutron.local (BIND9, authoritative)
   priv dock= privdocker (MySQL, Redis, NFS, Odoo, Nextcloud)

 NAT Port-Forwards (pfSense EXT interface):
   :80/:443   -> pubdocker .10.36 (public web)
   :8080      -> privdocker .12.12:8069 (Odoo)
   :8443      -> privdocker .12.12:443 (files HTTPS)
   :9000      -> privdocker .12.12:9000 (Nextcloud)

 NAT Port-Forwards (pfSense DMZ interface):
   :3306      -> privdocker .12.12:3306 (MySQL)
   :6379      -> privdocker .12.12:6379 (Redis)

 Firewall Policy:
   EXT -> DMZ:    ALLOW (SSH, HTTP/S, VPN, RDP)
   EXT -> V30:    BLOCK (except via NAT port-forwards above)
   DMZ vpn -> V30: ALLOW ALL (VPN pivot path)
   DMZ jump-> V30: ALLOW (Kerberos, LDAP, SMB, WinRM)
   DMZ dock-> V30: ALLOW (MySQL, Redis only)
   V30 <-> V30:   ALLOW ALL (internal service mesh)
```
