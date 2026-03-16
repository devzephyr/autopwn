"""
Stage 1: Layered host discovery.

Four layers all run and results are merged/deduplicated by IP:
  Layer 1 - ARP sweep (same-L2, cannot be filtered)
  Layer 2 - Multi-probe TCP/UDP (works across routed VLANs)
  Layer 3 - Reverse DNS (adds hostnames to known IPs)
  Layer 4 - Forward DNS brute-force (catches DNS-only hosts)

Output: state/discovery.json
"""

import json
import os
import pathlib
import socket
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
# Public entry point
# ---------------------------------------------------------------------------

def run(cidr: str) -> list[dict]:
    """
    Run all four discovery layers against *cidr*.

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
