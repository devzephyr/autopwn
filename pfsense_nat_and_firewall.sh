#!/bin/bash
# pfsense_nat_and_firewall.sh
#
# pfSense NAT port-forward rules + firewall pass rules
# Replicates the old nftables DNAT from the Lab 02 Internal Router
#
# TWO WAYS TO APPLY:
#   Option A: Paste the XML blocks into /cf/conf/config.xml on pfSense
#   Option B: Use the pfSense web GUI (Firewall > NAT > Port Forward)
#
# After applying, run: pfctl -f /tmp/rules.debug  (or reboot pfSense)

cat << 'INSTRUCTIONS'
=============================================================================
  pfSense NAT Port-Forward Rules + Firewall Companion Rules
  Replaces old nftables DNAT on Internal Router
=============================================================================

OPTION A: Web GUI (Firewall > NAT > Port Forward)
--------------------------------------------------
Add each rule below via Firewall > NAT > Port Forward > Add

OPTION B: XML (paste into /cf/conf/config.xml inside <nat> section)
-------------------------------------------------------------------
SSH into pfSense, edit /cf/conf/config.xml, find the <nat> section,
and paste the XML blocks below BEFORE the closing </nat> tag.
Then run: rm /tmp/config.cache && /etc/rc.filter_configure

=============================================================================

=== NAT PORT-FORWARD RULES ===

Rule 1: EXT:80 -> pubdocker:80 (public web - corp/shop HTTP)
-------------------------------------------------------------
Interface:    EXT (em1)
Protocol:     TCP
Dest addr:    EXT address
Dest port:    80
Redirect IP:  172.16.10.36
Redirect port: 80
Description:  NAT pubdocker HTTP (corp/shop)
Filter rule:  Add associated filter rule

Rule 2: EXT:443 -> pubdocker:443 (public web - corp/shop HTTPS)
----------------------------------------------------------------
Interface:    EXT (em1)
Protocol:     TCP
Dest addr:    EXT address
Dest port:    443
Redirect IP:  172.16.10.36
Redirect port: 443
Description:  NAT pubdocker HTTPS (corp/shop)
Filter rule:  Add associated filter rule

Rule 3: EXT:8080 -> privdocker:8069 (Odoo ERP -- intentional misconfig)
------------------------------------------------------------------------
Interface:    EXT (em1)
Protocol:     TCP
Dest addr:    EXT address
Dest port:    8080
Redirect IP:  172.16.12.12
Redirect port: 8069
Description:  NAT privdocker Odoo (INTENTIONAL VULN)
Filter rule:  Add associated filter rule

Rule 4: EXT:8443 -> privdocker:443 (files HTTPS -- intentional misconfig)
--------------------------------------------------------------------------
Interface:    EXT (em1)
Protocol:     TCP
Dest addr:    EXT address
Dest port:    8443
Redirect IP:  172.16.12.12
Redirect port: 443
Description:  NAT privdocker HTTPS files (INTENTIONAL VULN)
Filter rule:  Add associated filter rule

Rule 5: EXT:9000 -> privdocker:9000 (Nextcloud -- intentional misconfig)
-------------------------------------------------------------------------
Interface:    EXT (em1)
Protocol:     TCP
Dest addr:    EXT address
Dest port:    9000
Redirect IP:  172.16.12.12
Redirect port: 9000
Description:  NAT privdocker Nextcloud (INTENTIONAL VULN)
Filter rule:  Add associated filter rule

Rule 6: DMZ:3306 -> privdocker:3306 (MySQL -- DMZ hosts only)
--------------------------------------------------------------
Interface:    DMZ (em2)
Protocol:     TCP
Dest addr:    DMZ address
Dest port:    3306
Redirect IP:  172.16.12.12
Redirect port: 3306
Description:  NAT privdocker MySQL (DMZ pivot path)
Filter rule:  Add associated filter rule

Rule 7: DMZ:6379 -> privdocker:6379 (Redis -- DMZ hosts only)
--------------------------------------------------------------
Interface:    DMZ (em2)
Protocol:     TCP
Dest addr:    DMZ address
Dest port:    6379
Redirect IP:  172.16.12.12
Redirect port: 6379
Description:  NAT privdocker Redis (DMZ pivot path)
Filter rule:  Add associated filter rule


=== FIREWALL PASS RULES (per-interface) ===

These companion rules must exist on each interface for the NAT
port-forwards to work. pfSense can auto-create them if you select
"Add associated filter rule" during NAT rule creation.

If adding manually (Firewall > Rules > [interface]):

EXT Interface (em1) -- add these ABOVE the default block rule:
  Pass TCP from any to 172.16.10.36 port 80     (pubdocker HTTP)
  Pass TCP from any to 172.16.10.36 port 443    (pubdocker HTTPS)
  Pass TCP from any to 172.16.12.12 port 8069   (privdocker Odoo)
  Pass TCP from any to 172.16.12.12 port 443    (privdocker files)
  Pass TCP from any to 172.16.12.12 port 9000   (privdocker Nextcloud)

DMZ Interface (em2) -- add these for compromised-host pivot:
  Pass TCP from DMZ net to 172.16.12.12 port 3306  (MySQL)
  Pass TCP from DMZ net to 172.16.12.12 port 6379  (Redis)
  Pass TCP from 172.16.10.40 to VLAN30 net any      (VPN server full access)
  Pass TCP from 172.16.10.41 to 172.16.12.10 port 88,389,445,5985 (jumpbox AD)
  Pass TCP from 172.16.10.36 to 172.16.12.12 port 3306,6379 (pubdocker DB)

VLAN30 Interface (em5) -- allow internal service mesh:
  Pass any from VLAN30 net to VLAN30 net           (internal comms)
  Pass TCP from VLAN30 net to any port 80,443,53   (outbound updates)

INSTRUCTIONS

cat << 'XML_RULES'
=============================================================================
  XML BLOCKS FOR config.xml (paste inside <nat> section)
=============================================================================

<!-- NAT Rule 1: EXT:80 -> pubdocker HTTP -->
<rule>
  <source><any/></source>
  <destination>
    <network>em1ip</network>
    <port>80</port>
  </destination>
  <protocol>tcp</protocol>
  <target>172.16.10.36</target>
  <local-port>80</local-port>
  <interface>opt0</interface>
  <descr><![CDATA[NAT pubdocker HTTP corp/shop]]></descr>
  <associated-rule-id>pass</associated-rule-id>
  <natreflection>enable</natreflection>
</rule>

<!-- NAT Rule 2: EXT:443 -> pubdocker HTTPS -->
<rule>
  <source><any/></source>
  <destination>
    <network>em1ip</network>
    <port>443</port>
  </destination>
  <protocol>tcp</protocol>
  <target>172.16.10.36</target>
  <local-port>443</local-port>
  <interface>opt0</interface>
  <descr><![CDATA[NAT pubdocker HTTPS corp/shop]]></descr>
  <associated-rule-id>pass</associated-rule-id>
  <natreflection>enable</natreflection>
</rule>

<!-- NAT Rule 3: EXT:8080 -> privdocker Odoo (INTENTIONAL VULN) -->
<rule>
  <source><any/></source>
  <destination>
    <network>em1ip</network>
    <port>8080</port>
  </destination>
  <protocol>tcp</protocol>
  <target>172.16.12.12</target>
  <local-port>8069</local-port>
  <interface>opt0</interface>
  <descr><![CDATA[NAT privdocker Odoo ERP (INTENTIONAL VULN)]]></descr>
  <associated-rule-id>pass</associated-rule-id>
</rule>

<!-- NAT Rule 4: EXT:8443 -> privdocker files HTTPS (INTENTIONAL VULN) -->
<rule>
  <source><any/></source>
  <destination>
    <network>em1ip</network>
    <port>8443</port>
  </destination>
  <protocol>tcp</protocol>
  <target>172.16.12.12</target>
  <local-port>443</local-port>
  <interface>opt0</interface>
  <descr><![CDATA[NAT privdocker HTTPS files (INTENTIONAL VULN)]]></descr>
  <associated-rule-id>pass</associated-rule-id>
</rule>

<!-- NAT Rule 5: EXT:9000 -> privdocker Nextcloud (INTENTIONAL VULN) -->
<rule>
  <source><any/></source>
  <destination>
    <network>em1ip</network>
    <port>9000</port>
  </destination>
  <protocol>tcp</protocol>
  <target>172.16.12.12</target>
  <local-port>9000</local-port>
  <interface>opt0</interface>
  <descr><![CDATA[NAT privdocker Nextcloud (INTENTIONAL VULN)]]></descr>
  <associated-rule-id>pass</associated-rule-id>
</rule>

<!-- NAT Rule 6: DMZ:3306 -> privdocker MySQL (pivot path) -->
<rule>
  <source><network>opt1</network></source>
  <destination>
    <network>opt1ip</network>
    <port>3306</port>
  </destination>
  <protocol>tcp</protocol>
  <target>172.16.12.12</target>
  <local-port>3306</local-port>
  <interface>opt1</interface>
  <descr><![CDATA[NAT privdocker MySQL via DMZ pivot]]></descr>
  <associated-rule-id>pass</associated-rule-id>
</rule>

<!-- NAT Rule 7: DMZ:6379 -> privdocker Redis (pivot path) -->
<rule>
  <source><network>opt1</network></source>
  <destination>
    <network>opt1ip</network>
    <port>6379</port>
  </destination>
  <protocol>tcp</protocol>
  <target>172.16.12.12</target>
  <local-port>6379</local-port>
  <interface>opt1</interface>
  <descr><![CDATA[NAT privdocker Redis via DMZ pivot]]></descr>
  <associated-rule-id>pass</associated-rule-id>
</rule>

XML_RULES

cat << 'INTERFACE_NOTE'
=============================================================================
  IMPORTANT: pfSense Interface Name Mapping
=============================================================================

  pfSense uses internal names like opt0, opt1, etc. for interfaces beyond
  WAN and LAN. Your config.xml likely maps them as:

    wan  = em0  (NAT to internet)
    opt0 = em1  (EXT - 172.16.21.1/26)     <-- Kali's segment
    opt1 = em2  (DMZ - 172.16.10.33/28)    <-- public services
    opt2 = em3  (VLAN10 - 172.16.10.1/28)
    opt3 = em4  (VLAN20 - 172.16.10.17/28)
    opt4 = em5  (VLAN30 - 172.16.12.1/27)  <-- core infra
    opt5 = em6  (VLAN40 - 172.16.12.33/27)

  Check your config.xml <interfaces> section to confirm. If the names
  differ, update the <interface> tags in the NAT rules above.

  After pasting into config.xml:
    1. rm /tmp/config.cache
    2. /etc/rc.filter_configure
    3. Verify: pfctl -sr | grep rdr   (should show 7 redirect rules)

=============================================================================
INTERFACE_NOTE

cat << 'OLD_VS_NEW'
=============================================================================
  OLD nftables DNAT vs NEW pfSense NAT -- Comparison
=============================================================================

  OLD (Internal Router nftables PREROUTING):
    tcp dport 80   dnat to 172.16.10.12:80     <-- privdocker (old IP)
    tcp dport 80   dnat to 172.16.10.35:80     <-- pubdocker (NEVER FIRES)
    tcp dport 443  dnat to 172.16.10.12:443    <-- privdocker
    tcp dport 443  dnat to 172.16.10.35:443    <-- NEVER FIRES
    tcp dport 8081 dnat to 172.16.10.12:8081   <-- privdocker
    tcp dport 8081 dnat to 172.16.10.35:8081   <-- NEVER FIRES
    tcp dport 8082 dnat to 172.16.10.12:8082   <-- privdocker
    tcp dport 8082 dnat to 172.16.10.35:8082   <-- NEVER FIRES

  PROBLEM: nftables processes rules top-to-bottom, first match wins.
  Every port had TWO dnat rules. The second rule for each port NEVER fired.
  Result: ALL traffic went to privdocker, pubdocker was unreachable via DNAT.

  NEW (pfSense port-forwards -- FIXED):
    EXT:80   -> pubdocker .10.36:80     (public web works)
    EXT:443  -> pubdocker .10.36:443    (public web works)
    EXT:8080 -> privdocker .12.12:8069  (Odoo on separate port)
    EXT:8443 -> privdocker .12.12:443   (files on separate port)
    EXT:9000 -> privdocker .12.12:9000  (Nextcloud on separate port)
    DMZ:3306 -> privdocker .12.12:3306  (MySQL, DMZ-only)
    DMZ:6379 -> privdocker .12.12:6379  (Redis, DMZ-only)

  FIXES:
    1. Each destination gets its own unique external port (no conflicts)
    2. Public web (80/443) correctly routes to pubdocker, not privdocker
    3. Internal services use high ports (8080/8443/9000) to separate them
    4. DB services (MySQL/Redis) are DMZ-only, not exposed to EXT
    5. IPs updated from old .10.12/.10.35 to new .12.12/.10.36

=============================================================================
OLD_VS_NEW
