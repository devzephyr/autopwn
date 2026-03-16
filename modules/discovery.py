"""
Stage 1: Layered host discovery.

Five layers all run and results are merged/deduplicated by IP:
  Layer 1  - ARP sweep (same-L2, cannot be filtered)
  Layer 2  - Multi-probe TCP/UDP (works across routed VLANs)
  Layer 3  - Reverse DNS (adds hostnames to known IPs)
  Layer 4  - Forward DNS brute-force (catches DNS-only hosts)
  Layer 4b - DNS Zone Transfer / AXFR (reveals all zone records)

Output: state/discovery.json
"""

import json
import os
import pathlib
import socket
import subprocess
import datetime

import nmap


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
STATE_DIR = BASE_DIR / "state"
WORDLISTS_DIR = BASE_DIR / "wordlists"
DNS_NAMES_FILE = WORDLISTS_DIR / "dns_names.txt"
OUTPUT_FILE = STATE_DIR / "discovery.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _atomic_write(path: pathlib.Path, data: dict) -> None:
    """Write JSON atomically: write to .tmp then os.rename."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.rename(tmp, path)


def _load_dns_names() -> list[str]:
    """Load forward-DNS brute-force names from wordlist."""
    if not DNS_NAMES_FILE.exists():
        print(f"  [!] DNS wordlist not found: {DNS_NAMES_FILE}")
        return []
    names = []
    for line in DNS_NAMES_FILE.read_text().splitlines():
        name = line.strip()
        if name and not name.startswith("#"):
            names.append(name)
    return names


def _cidr_to_network_prefix(cidr: str) -> str:
    """Return the network address without the prefix length, e.g. '10.0.0'."""
    # Used for forward-DNS: strip the host portion
    # We only need the base for suffix queries; dns_brute resolves FQDNs
    base = cidr.split("/")[0].rsplit(".", 1)[0]
    return base


# ---------------------------------------------------------------------------
# Layer 1: ARP sweep
# ---------------------------------------------------------------------------

def _layer_arp(nm: nmap.PortScanner, cidr: str) -> dict[str, dict]:
    """ARP sweep — reliable for same-L2 hosts."""
    print(f"  [Layer 1] ARP sweep: {cidr}")
    found: dict[str, dict] = {}
    try:
        nm.scan(hosts=cidr, arguments="-PR -sn")
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                hostname = nm[host].hostname() or ""
                found[host] = {
                    "ip": host,
                    "hostname": hostname,
                    "discovery_method": "arp",
                }
                print(f"    [+] ARP: {host} ({hostname or 'no hostname'})")
    except nmap.PortScannerError as exc:
        print(f"  [!] ARP sweep error: {exc}")
    print(f"  [Layer 1] ARP found {len(found)} host(s).")
    return found


# ---------------------------------------------------------------------------
# Layer 2: Multi-probe TCP/UDP
# ---------------------------------------------------------------------------

def _layer_multiprobe(nm: nmap.PortScanner, cidr: str) -> dict[str, dict]:
    """Multi-probe TCP/UDP — finds hosts across routed VLANs."""
    print(f"  [Layer 2] Multi-probe TCP/UDP: {cidr}")
    found: dict[str, dict] = {}
    args = (
        "-sn -PE -PP "
        "-PS22,80,443,445,3389,8080 "
        "-PA80,443 "
        "-PU53,161"
    )
    try:
        nm.scan(hosts=cidr, arguments=args)
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                hostname = nm[host].hostname() or ""
                found[host] = {
                    "ip": host,
                    "hostname": hostname,
                    "discovery_method": "multiprobe",
                }
                print(f"    [+] MultiProbe: {host} ({hostname or 'no hostname'})")
    except nmap.PortScannerError as exc:
        print(f"  [!] Multi-probe error: {exc}")
    print(f"  [Layer 2] Multi-probe found {len(found)} host(s).")
    return found


# ---------------------------------------------------------------------------
# Layer 3: Reverse DNS
# ---------------------------------------------------------------------------

def _layer_reverse_dns(hosts: dict[str, dict]) -> None:
    """
    Reverse-DNS lookup for each known IP. Updates hostname in-place
    if a better name is resolved. Does not add new hosts.
    """
    print(f"  [Layer 3] Reverse DNS for {len(hosts)} host(s).")
    for ip, record in hosts.items():
        if record.get("hostname"):
            # Already have a hostname; still try to get a FQDN
            pass
        try:
            fqdn, _, _ = socket.gethostbyaddr(ip)
            if fqdn and fqdn != ip:
                if not record.get("hostname"):
                    record["hostname"] = fqdn
                    print(f"    [+] rDNS: {ip} -> {fqdn}")
        except (socket.herror, socket.gaierror, OSError):
            pass


# ---------------------------------------------------------------------------
# Layer 4: Forward DNS brute-force
# ---------------------------------------------------------------------------

def _find_dns_servers(hosts: dict[str, dict]) -> list[str]:
    """
    Identify likely DNS servers: check port 53 with a quick nmap probe
    on the already-discovered hosts.
    """
    if not hosts:
        return []
    nm = nmap.PortScanner()
    dns_servers: list[str] = []
    ip_list = " ".join(hosts.keys())
    print(f"  [Layer 4] Probing {len(hosts)} host(s) for port 53 (DNS).")
    try:
        nm.scan(hosts=ip_list, arguments="-p 53 --open -T4")
        for host in nm.all_hosts():
            try:
                if nm[host]["tcp"][53]["state"] == "open":
                    dns_servers.append(host)
                    print(f"    [+] DNS server found: {host}")
            except KeyError:
                pass
    except nmap.PortScannerError as exc:
        print(f"  [!] DNS server probe error: {exc}")
    return dns_servers


def _layer_forward_dns(
    hosts: dict[str, dict],
    dns_servers: list[str],
    cidr: str,
) -> dict[str, dict]:
    """
    Forward DNS brute-force against discovered DNS servers.
    Queries each name from dns_names.txt.  If resolved to an IP not
    already known, it is added as a new host with method 'dns_brute'.
    """
    new_hosts: dict[str, dict] = {}
    names = _load_dns_names()
    if not names:
        print("  [Layer 4] No DNS names to brute-force.")
        return new_hosts
    if not dns_servers:
        print("  [Layer 4] No DNS servers discovered; skipping forward brute-force.")
        return new_hosts

    # Derive a candidate domain suffix from existing hostnames or CIDR
    domain_suffix = ""
    for record in hosts.values():
        hn = record.get("hostname", "")
        if hn and "." in hn:
            parts = hn.split(".", 1)
            if len(parts) == 2:
                domain_suffix = parts[1]
                break

    print(
        f"  [Layer 4] Forward DNS brute-force: {len(names)} names, "
        f"suffix='{domain_suffix}', servers={dns_servers}."
    )

    # Point resolver at the first discovered DNS server
    primary_dns = dns_servers[0]
    original_dns = None
    try:
        import dns.resolver  # type: ignore  # dnspython is optional
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [primary_dns]

        for name in names:
            fqdn = f"{name}.{domain_suffix}" if domain_suffix else name
            try:
                answers = resolver.resolve(fqdn, "A", lifetime=3)
                for rdata in answers:
                    ip = str(rdata)
                    if ip not in hosts and ip not in new_hosts:
                        new_hosts[ip] = {
                            "ip": ip,
                            "hostname": fqdn,
                            "discovery_method": "dns_brute",
                        }
                        print(f"    [+] DNS brute: {fqdn} -> {ip}")
            except Exception:
                pass

    except ImportError:
        # dnspython not available — fall back to socket (uses system resolver)
        print("  [Layer 4] dnspython not available; using socket fallback.")
        for name in names:
            fqdn = f"{name}.{domain_suffix}" if domain_suffix else name
            try:
                ip = socket.gethostbyname(fqdn)
                if ip and ip not in hosts and ip not in new_hosts:
                    new_hosts[ip] = {
                        "ip": ip,
                        "hostname": fqdn,
                        "discovery_method": "dns_brute",
                    }
                    print(f"    [+] DNS brute (socket): {fqdn} -> {ip}")
            except (socket.gaierror, OSError):
                pass

    print(f"  [Layer 4] Forward DNS brute-force added {len(new_hosts)} new host(s).")
    return new_hosts


# ---------------------------------------------------------------------------
# Layer 4b: DNS Zone Transfer (AXFR)
# ---------------------------------------------------------------------------

def _dns_zone_transfer(dns_servers: list[str], discovered_hosts: dict) -> list[dict]:
    """Attempt AXFR zone transfer against all discovered DNS servers."""
    new_hosts: list[dict] = []

    for dns_ip in dns_servers:
        # Derive candidate zone names from hostnames already known
        domains_to_try: set[str] = set()
        for host in discovered_hosts.values():
            if host.get("hostname"):
                parts = host["hostname"].split(".")
                if len(parts) >= 2:
                    domains_to_try.add(".".join(parts[-2:]))   # e.g. neutron.local
                if len(parts) >= 3:
                    domains_to_try.add(".".join(parts[-3:]))   # e.g. corp.neutron.local

        if not domains_to_try:
            domains_to_try = {"local", "internal", "corp", "lan", "ad", "domain"}

        for domain in domains_to_try:
            try:
                # Method 1: dnspython xfr
                try:
                    import dns.resolver    # type: ignore
                    import dns.zone        # type: ignore
                    import dns.query       # type: ignore
                    import dns.exception   # type: ignore

                    zone = dns.zone.from_xfr(dns.query.xfr(dns_ip, domain, timeout=10))
                    for name, node in zone.nodes.items():
                        for rdataset in node.rdatasets:
                            for rdata in rdataset:
                                if hasattr(rdata, "address"):
                                    ip = rdata.address
                                    hostname = f"{name}.{domain}".rstrip(".")
                                    if ip not in discovered_hosts:
                                        new_hosts.append({
                                            "ip": ip,
                                            "hostname": hostname,
                                            "discovery_method": "dns_zone_transfer",
                                        })
                                        print(f"    [+] AXFR (dnspython): {hostname} -> {ip}")
                except Exception:
                    pass

                # Method 2: subprocess dig AXFR fallback
                try:
                    result = subprocess.run(
                        ["dig", f"@{dns_ip}", domain, "AXFR", "+nocomments", "+nocmd"],
                        capture_output=True, text=True, timeout=15,
                    )
                    stdout = result.stdout
                    if stdout and "Transfer failed" not in stdout:
                        for line in stdout.splitlines():
                            parts_line = line.split()
                            if len(parts_line) >= 5 and parts_line[3] in ("A", "AAAA"):
                                ip = parts_line[4]
                                hostname = parts_line[0].rstrip(".")
                                # Skip if already captured by dnspython or known
                                already_new = any(h["ip"] == ip for h in new_hosts)
                                if ip not in discovered_hosts and not already_new:
                                    new_hosts.append({
                                        "ip": ip,
                                        "hostname": hostname,
                                        "discovery_method": "dns_zone_transfer",
                                    })
                                    print(f"    [+] AXFR (dig): {hostname} -> {ip}")
                except Exception:
                    pass

            except Exception:
                pass

    return new_hosts


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(cidr: str) -> list[dict]:
    """
    Run all discovery layers against *cidr*.

    Layers: ARP, multi-probe TCP/UDP, reverse DNS, forward DNS brute-force,
    and DNS zone transfer (AXFR).  Results are merged and deduplicated by IP.

    Returns a list of host dicts and writes state/discovery.json.
    """
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    nm = nmap.PortScanner()

    print(f"\n[Stage 1] Host Discovery — target: {cidr}")
    print("=" * 60)

    # --- Layer 1: ARP ---
    hosts = _layer_arp(nm, cidr)

    # --- Layer 2: Multi-probe ---
    multiprobe_results = _layer_multiprobe(nm, cidr)
    for ip, record in multiprobe_results.items():
        if ip not in hosts:
            hosts[ip] = record
        elif not hosts[ip].get("hostname") and record.get("hostname"):
            hosts[ip]["hostname"] = record["hostname"]

    # --- Layer 3: Reverse DNS ---
    _layer_reverse_dns(hosts)

    # --- Layer 4: Forward DNS brute-force ---
    dns_servers = _find_dns_servers(hosts)
    dns_new = _layer_forward_dns(hosts, dns_servers, cidr)
    # Reverse-DNS the newly discovered hosts too
    _layer_reverse_dns(dns_new)
    hosts.update(dns_new)

    # --- Layer 4b: DNS Zone Transfer (AXFR) ---
    print(f"  [Layer 4b] DNS Zone Transfer (AXFR) against {len(dns_servers)} server(s).")
    if dns_servers:
        axfr_new = _dns_zone_transfer(dns_servers, hosts)
        # Reverse-DNS any newly found hosts that lack a hostname
        axfr_new_dict: dict[str, dict] = {h["ip"]: h for h in axfr_new}
        _layer_reverse_dns(axfr_new_dict)
        for ip, record in axfr_new_dict.items():
            if ip not in hosts:
                hosts[ip] = record
        print(f"  [Layer 4b] AXFR added {len(axfr_new_dict)} new host(s).")
    else:
        print("  [Layer 4b] No DNS servers found; skipping zone transfer.")

    # Build final sorted host list
    host_list = sorted(hosts.values(), key=lambda h: tuple(int(o) for o in h["ip"].split(".")))

    output = {
        "cidr": cidr,
        "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
        "hosts": host_list,
    }

    _atomic_write(OUTPUT_FILE, output)
    print(f"\n[Stage 1] Discovery complete. {len(host_list)} host(s) found.")
    print(f"[Stage 1] Results written to {OUTPUT_FILE}")
    return host_list


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <cidr>")
        print(f"  e.g. python3 {sys.argv[0]} 172.16.10.0/24")
        sys.exit(1)

    discovered = run(sys.argv[1])
    print(f"\nSummary: {len(discovered)} host(s) discovered.")
    for h in discovered:
        print(f"  {h['ip']:<18} {h['hostname']:<40} [{h['discovery_method']}]")
