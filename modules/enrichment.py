"""
Stage 2: Service fingerprinting and NSE enrichment.

For each host discovered in Stage 1:
  1. Fast pre-scan (-F) to find which common ports are open.
  2. Full SYN scan with OS detection and version intensity 7,
     plus dynamically selected NSE scripts based on open ports.
  3. Parse results into the services.json schema.
  4. Set application-level flags: is_domain_controller, has_wordpress,
     has_dvwa, ms17_010_vulnerable.

Output: state/services.json
"""

import json
import os
import pathlib

import nmap


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
STATE_DIR = BASE_DIR / "state"
DISCOVERY_FILE = STATE_DIR / "discovery.json"
OUTPUT_FILE = STATE_DIR / "services.json"


# ---------------------------------------------------------------------------
# NSE script map keyed by port number
# ---------------------------------------------------------------------------
PORT_SCRIPTS: dict[int, str] = {
    21:   "ftp-anon,ftp-proftpd-backdoor",
    22:   "ssh-auth-methods",
    80:   "http-title,http-enum,http-wordpress-enum,http-headers",
    88:   "krb5-enum-users",
    161:  "snmp-info",
    389:  "ldap-rootdse",
    443:  "http-title,http-enum,http-wordpress-enum,ssl-cert",
    445:  "smb-vuln-ms17-010,smb-os-discovery,smb-security-mode",
    1433: "ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-xp-cmdshell",
    2049: "nfs-ls,nfs-showmount,nfs-statfs",
    3306: "mysql-empty-password,mysql-info",
    3389: "rdp-enum-encryption,rdp-vuln-ms12-020",
    5985: "http-auth-finder",
    6379: "redis-info",
}

# All ports we care about (used for fast pre-scan port list)
INTERESTING_PORTS = sorted(PORT_SCRIPTS.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _atomic_write(path: pathlib.Path, data: dict) -> None:
    """Write JSON atomically via a .tmp intermediate."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.rename(tmp, path)


def _load_discovery() -> dict:
    """Load state/discovery.json, raise if missing."""
    if not DISCOVERY_FILE.exists():
        raise FileNotFoundError(
            f"discovery.json not found at {DISCOVERY_FILE}. "
            "Run Stage 1 (discovery.py) first."
        )
    return json.loads(DISCOVERY_FILE.read_text())


def _select_scripts(open_ports: set[int]) -> str:
    """
    Build a comma-separated NSE script string for the given open ports.
    Returns an empty string when no matching scripts exist.
    """
    script_set: set[str] = set()
    for port in open_ports:
        if port in PORT_SCRIPTS:
            for script in PORT_SCRIPTS[port].split(","):
                script_set.add(script.strip())
    return ",".join(sorted(script_set))


def _parse_nse_results(port_data: dict) -> dict[str, str]:
    """
    Extract NSE script results from a python-nmap port data dict.
    Returns {script_name: output_string}.
    """
    results: dict[str, str] = {}
    script_data = port_data.get("script", {})
    for script_name, output in script_data.items():
        # Flatten multi-line output to single string for JSON storage
        results[script_name] = " ".join(str(output).split())
    return results


def _extract_os_guess(nm: nmap.PortScanner, host: str) -> str:
    """Return the best OS guess string, or empty string if unavailable."""
    try:
        osmatch = nm[host].get("osmatch", [])
        if osmatch:
            return osmatch[0].get("name", "")
    except (KeyError, IndexError, TypeError):
        pass
    return ""


def _set_flags(
    ports: list[dict],
    nse_all: dict[int, dict[str, str]],
    os_guess: str = "",
) -> dict[str, bool]:
    """
    Derive application-level flags from the enriched port list.

    Args:
        ports:    list of port dicts already built for this host.
        nse_all:  {port_number: {script_name: output}} for all ports.
        os_guess: best OS guess string from nmap OS detection.
    """
    open_ports = [p for p in ports if p["state"] == "open"]
    open_port_nums = {p["port"] for p in open_ports}

    # Flat merged NSE dict for cross-port lookups
    all_nse: dict[str, str] = {}
    for port_scripts in nse_all.values():
        for k, v in port_scripts.items():
            all_nse[k] = str(v)

    # is_domain_controller: ports 88 AND 389 both open
    is_dc = (88 in open_port_nums) and (389 in open_port_nums)

    # has_wordpress: http-wordpress-enum returned results OR http-enum contains wp-login
    has_wp = False
    for port_num in (80, 443):
        scripts = nse_all.get(port_num, {})
        wp_enum = scripts.get("http-wordpress-enum", "")
        http_enum = scripts.get("http-enum", "")
        http_title = scripts.get("http-title", "")
        if wp_enum and "WordPress" in wp_enum:
            has_wp = True
        if "wp-login" in http_enum.lower() or "wordpress" in http_title.lower():
            has_wp = True

    # has_dvwa: http-title contains "dvwa" OR http-enum contains "/dvwa/"
    has_dvwa = False
    for port_num in (80, 443):
        scripts = nse_all.get(port_num, {})
        http_title = scripts.get("http-title", "").lower()
        http_enum = scripts.get("http-enum", "").lower()
        if "dvwa" in http_title or "/dvwa/" in http_enum:
            has_dvwa = True

    # has_nextcloud: http-title contains "nextcloud" OR http-enum finds
    # /nextcloud/ or /index.php/login with nextcloud markers
    has_nextcloud = False
    for port_num in (80, 443):
        scripts = nse_all.get(port_num, {})
        http_title = scripts.get("http-title", "").lower()
        http_enum  = scripts.get("http-enum",  "").lower()
        http_hdr   = scripts.get("http-headers", "").lower()
        if (
            "nextcloud" in http_title
            or "nextcloud" in http_enum
            or "/nextcloud" in http_enum
            or "oc-requestid" in http_hdr   # Nextcloud response header
            or "x-nextcloud" in http_hdr
        ):
            has_nextcloud = True

    # ms17_010_vulnerable: smb-vuln-ms17-010 output contains "VULNERABLE"
    ms17 = False
    smb_scripts = nse_all.get(445, {})
    vuln_output = smb_scripts.get("smb-vuln-ms17-010", "")
    if "VULNERABLE" in vuln_output and "NOT VULNERABLE" not in vuln_output:
        ms17 = True

    # has_mssql: port 1433 open
    has_mssql = any(p["port"] == 1433 for p in open_ports)

    # has_rdp: port 3389 open
    has_rdp = any(p["port"] == 3389 for p in open_ports)

    # has_nfs: port 2049 open
    has_nfs = any(p["port"] == 2049 for p in open_ports)

    # has_smb_shares: 445 open and SMB guest/null access indicated
    smb_mode = all_nse.get("smb-security-mode", "").lower()
    has_smb_shares = (
        445 in open_port_nums
        and ("account_used: guest" in smb_mode or "guest" in smb_mode)
    )

    # bluekeep_vulnerable: RDP open on a pre-Windows-10 / pre-2012 OS
    _os_lower = os_guess.lower()
    bluekeep_vulnerable = has_rdp and any(
        kw in _os_lower for kw in ("windows 7", "2008", "xp", "2003")
    )

    # mssql_empty_password: ms-sql-empty-password NSE mentions "sa"
    mssql_ep_output = all_nse.get("ms-sql-empty-password", "")
    mssql_empty_password = "sa" in mssql_ep_output.lower() or "empty" in mssql_ep_output.lower()

    # nfs_world_readable: nfs-showmount or nfs-ls output contains "*" or "everyone"
    nfs_world_readable = any(
        "*" in str(v) or "everyone" in str(v).lower()
        for k, v in all_nse.items()
        if "nfs" in k.lower()
    )

    return {
        "is_domain_controller":  is_dc,
        "has_wordpress":         has_wp,
        "has_dvwa":              has_dvwa,
        "has_nextcloud":         has_nextcloud,
        "ms17_010_vulnerable":   ms17,
        "has_mssql":             has_mssql,
        "has_rdp":               has_rdp,
        "has_nfs":               has_nfs,
        "has_smb_shares":        has_smb_shares,
        "bluekeep_vulnerable":   bluekeep_vulnerable,
        "mssql_empty_password":  mssql_empty_password,
        "nfs_world_readable":    nfs_world_readable,
    }


# ---------------------------------------------------------------------------
# Per-host enrichment
# ---------------------------------------------------------------------------

def _enrich_host(host_record: dict) -> dict:
    """
    Run a two-phase nmap scan against a single host and return the enriched
    host dict in the services.json schema.
    """
    ip = host_record["ip"]
    hostname = host_record.get("hostname", "")
    nm = nmap.PortScanner()

    print(f"\n  [Enrichment] Scanning {ip} ({hostname or 'no hostname'})")

    # ------------------------------------------------------------------
    # Phase 1: Fast pre-scan to discover which interesting ports are open
    # ------------------------------------------------------------------
    port_str = ",".join(str(p) for p in INTERESTING_PORTS)
    open_ports: set[int] = set()

    print(f"    [Phase 1] Fast pre-scan (ports {port_str})")
    try:
        nm.scan(hosts=ip, arguments=f"-F -T4 --open -p {port_str}")
        if ip in nm.all_hosts():
            for proto in nm[ip].all_protocols():
                for port, pdata in nm[ip][proto].items():
                    if pdata.get("state") == "open":
                        open_ports.add(int(port))
    except nmap.PortScannerError as exc:
        print(f"    [!] Fast pre-scan error: {exc}")

    print(f"    [Phase 1] Open interesting ports: {sorted(open_ports) or 'none'}")

    # ------------------------------------------------------------------
    # Phase 2: Full scan with version detection, OS, and NSE scripts
    # ------------------------------------------------------------------
    scripts = _select_scripts(open_ports)
    full_args = "-sS -sV -O --version-intensity 7"
    if scripts:
        full_args += f" --script {scripts}"

    # Restrict full scan to the ports we found open plus their protocol peers
    # to avoid unnecessary noise; fall back to all interesting ports
    scan_ports = ",".join(str(p) for p in sorted(open_ports)) if open_ports else port_str

    print(f"    [Phase 2] Full scan (ports {scan_ports or 'default'}, scripts: {bool(scripts)})")

    enriched_ports: list[dict] = []
    nse_by_port: dict[int, dict[str, str]] = {}
    os_guess = ""

    try:
        nm.scan(hosts=ip, arguments=f"{full_args} -p {scan_ports}" if scan_ports else full_args)
        if ip not in nm.all_hosts():
            print(f"    [!] Host {ip} not in full-scan results (may be down).")
        else:
            os_guess = _extract_os_guess(nm, ip)
            if os_guess:
                print(f"    [OS] {os_guess}")

            for proto in nm[ip].all_protocols():
                for port_num, pdata in nm[ip][proto].items():
                    state = pdata.get("state", "")
                    nse_results = _parse_nse_results(pdata)
                    nse_by_port[int(port_num)] = nse_results

                    port_entry = {
                        "port": int(port_num),
                        "protocol": proto,
                        "state": state,
                        "service": pdata.get("name", ""),
                        "version": " ".join(
                            filter(None, [pdata.get("product", ""), pdata.get("version", "")])
                        ),
                        "nse_results": nse_results,
                    }
                    enriched_ports.append(port_entry)
                    if state == "open":
                        nse_summary = ", ".join(
                            f"{k}: {v[:60]}" for k, v in nse_results.items()
                        )
                        print(
                            f"    [Port] {port_num}/{proto} open  "
                            f"{pdata.get('name','')}  {pdata.get('product','')}  "
                            f"{pdata.get('version','')}"
                        )
                        if nse_summary:
                            print(f"           NSE: {nse_summary}")

    except nmap.PortScannerError as exc:
        print(f"    [!] Full scan error: {exc}")

    # Sort ports for deterministic output
    enriched_ports.sort(key=lambda p: p["port"])

    flags = _set_flags(enriched_ports, nse_by_port, os_guess)
    flag_summary = [k for k, v in flags.items() if v]
    if flag_summary:
        print(f"    [Flags] {', '.join(flag_summary)}")

    return {
        "ip": ip,
        "hostname": hostname,
        "os_guess": os_guess,
        "ports": enriched_ports,
        "flags": flags,
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run() -> list[dict]:
    """
    Load discovery.json, enrich each host, write services.json.

    Returns the list of enriched host dicts.
    """
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    discovery = _load_discovery()
    host_records = discovery.get("hosts", [])

    if not host_records:
        print("[Stage 2] No hosts to enrich. Check state/discovery.json.")
        return []

    print(f"\n[Stage 2] Service Enrichment — {len(host_records)} host(s)")
    print("=" * 60)

    enriched_hosts: list[dict] = []
    for i, host_record in enumerate(host_records, start=1):
        print(f"\n  [{i}/{len(host_records)}] {host_record['ip']}")
        try:
            result = _enrich_host(host_record)
            enriched_hosts.append(result)
        except Exception as exc:
            print(f"  [!] Enrichment failed for {host_record['ip']}: {exc}")
            # Add a minimal record so downstream stages are not surprised
            enriched_hosts.append({
                "ip": host_record["ip"],
                "hostname": host_record.get("hostname", ""),
                "os_guess": "",
                "ports": [],
                "flags": {
                    "is_domain_controller":  False,
                    "has_wordpress":         False,
                    "has_dvwa":              False,
                    "ms17_010_vulnerable":   False,
                    "has_mssql":             False,
                    "has_rdp":               False,
                    "has_nfs":               False,
                    "has_smb_shares":        False,
                    "has_nextcloud":         False,
                    "bluekeep_vulnerable":   False,
                    "mssql_empty_password":  False,
                    "nfs_world_readable":    False,
                },
            })

    output = {"hosts": enriched_hosts}
    _atomic_write(OUTPUT_FILE, output)

    print(f"\n[Stage 2] Enrichment complete. Results written to {OUTPUT_FILE}")
    return enriched_hosts


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    hosts = run()
    print(f"\nSummary: {len(hosts)} host(s) enriched.")
    for h in hosts:
        open_ports = [p["port"] for p in h["ports"] if p["state"] == "open"]
        flags_set = [k for k, v in h.get("flags", {}).items() if v]
        print(
            f"  {h['ip']:<18} OS: {h['os_guess'] or 'unknown':<35} "
            f"open ports: {open_ports}  flags: {flags_set}"
        )
