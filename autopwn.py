#!/usr/bin/env python3
"""
autopwn.py - Master Orchestrator
RIS602 Final Project: Topology-Agnostic Automated Penetration Testing Pipeline

Usage:
    python3 autopwn.py --target 172.16.10.0/24
    python3 autopwn.py --target 172.16.21.0/26 172.16.10.32/28 172.16.12.0/27
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
    "ms17_010":        ("modules.exploits.smb",      "exploit_ms17_010"),
    "kerberoast":      ("modules.exploits.smb",      "exploit_ms17_010"),   # placeholder; kerberoast is AD-side
    "wordpress_creds": ("modules.exploits.web",      "exploit_wordpress"),
    "dvwa_sqli":       ("modules.exploits.web",      "exploit_dvwa"),
    "mysql_default":   ("modules.exploits.database", "exploit_mysql"),
    "redis_unauth":    ("modules.exploits.database", "exploit_redis"),
    "ssh_brute":       ("modules.exploits.ssh",      "exploit_ssh"),
    "smb_null":        ("modules.exploits.smb",      "exploit_smb_null"),
    "ftp_anon":        ("modules.exploits.smb",      "exploit_ftp_anon"),   # placeholder
    "winrm_creds":     ("modules.exploits.winrm",    "exploit_winrm"),
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
                # Gather credentials from ad_findings / earlier exploitation
                creds = _collect_credentials()
                result = fn(host, creds)
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

# ---------------------------------------------------------------------------
# Print banner
# ---------------------------------------------------------------------------
def print_banner(targets: list[str]) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "╔══════════════════════════════════════════════════════════════╗",
        "║         AutoPwn — Topology-Agnostic PenTest Pipeline        ║",
        "║              RIS602 Final Project  |  Seneca Poly           ║",
        "╚══════════════════════════════════════════════════════════════╝",
    ]
    for line in lines:
        print(_c(CYAN, line))
    if len(targets) == 1:
        print(f"  {BOLD}Target :{RESET} {WHITE}{targets[0]}{RESET}")
    else:
        print(f"  {BOLD}Targets:{RESET} {WHITE}{targets[0]}{RESET}")
        for t in targets[1:]:
            print(f"           {WHITE}{t}{RESET}")
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
        "--target", metavar="CIDR", nargs="+",
        help="One or more target subnets in CIDR notation "
             "(e.g. 172.16.21.0/26 172.16.10.32/28)",
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
    Parse post-exploitation command outputs for IP addresses that belong to
    subnets we have not yet scanned.  Derives a /24 for each new IP found
    in arp, ip route, ip addr, and ipconfig output.

    Returns a set of CIDR strings (e.g. {"10.10.20.0/24"}).
    """
    new_cidrs: set[str] = set()
    ip_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

    # Collect every string from every command output
    raw_text = ""
    for host_entry in postex_data.get("hosts", []):
        for cmd in host_entry.get("commands_run", []):
            raw_text += cmd.get("output", "") + "\n"

    # Collect IPs seen only as local interface addresses (e.g. Docker bridges)
    # so we can exclude subnets where the only host is the gateway itself.
    local_iface_ips: set[str] = set()
    iface_pattern = re.compile(
        r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})/\d+",
    )
    for m in iface_pattern.finditer(raw_text):
        local_iface_ips.add(m.group(1))

    subnet_ips: dict[str, set[str]] = {}
    for match in ip_pattern.finditer(raw_text):
        ip_str = match.group(1)
        try:
            ip = ipaddress.IPv4Address(ip_str)
        except ValueError:
            continue
        # Skip loopback, link-local, multicast, and broadcast
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.packed[-1] == 255:
            continue
        net = ipaddress.IPv4Network(f"{ip_str}/24", strict=False)
        cidr_str = str(net)
        subnet_ips.setdefault(cidr_str, set()).add(ip_str)

    for cidr_str, ips in subnet_ips.items():
        if cidr_str in known_cidrs:
            continue
        # Skip subnets where every seen IP is a local interface address
        # (catches Docker bridge networks: 172.17/18/19 etc.)
        if ips.issubset(local_iface_ips):
            continue
        new_cidrs.add(cidr_str)

    return new_cidrs


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

    # Resolve initial target CIDRs
    if args.auto:
        initial_cidrs = [detect_local_cidr()]
    else:
        initial_cidrs = args.target
        for c in initial_cidrs:
            try:
                ipaddress.IPv4Network(c, strict=False)
            except ValueError as exc:
                sys.exit(f"Invalid CIDR '{c}': {exc}")

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))

    print_banner(initial_cidrs)
    tlog("orchestrator", f"Pipeline started — targets: {', '.join(initial_cidrs)}", "start")

    lhost = detect_lhost(initial_cidrs[0])
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
    # User-supplied CIDRs are scanned in the first N iterations without being
    # treated as pivots.  Only auto-discovered subnets are marked pivot=True.
    #
    user_cidrs:    set[str]   = set(initial_cidrs)
    known_cidrs:   set[str]   = set(initial_cidrs)
    pending_cidrs: list[str]  = list(initial_cidrs)
    cred_snapshot = frozenset()
    host_snapshot = frozenset()
    iteration = 0

    while pending_cidrs and iteration < args.max_iterations:
        iteration += 1
        current_cidr = pending_cidrs.pop(0)
        pivot = current_cidr not in user_cidrs   # only auto-discovered subnets are pivots

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

        # ── Extract pivot subnets from post-ex output ──────────────────────
        postex_data = _load_json(STATE_FILES["postex"]) or {}
        pivot_subnets = _extract_pivot_subnets(postex_data, known_cidrs)

        for subnet in sorted(pivot_subnets):
            warn(f"Pivot target discovered: {subnet}")
            tlog("orchestrator", f"New pivot subnet: {subnet}", "pivot")
            known_cidrs.add(subnet)
            pending_cidrs.append(subnet)

        # ── Convergence check ──────────────────────────────────────────────
        if not pivot_subnets and not new_hosts and not new_creds:
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
    user_label = f" ({len(user_cidrs)} user-specified)" if len(user_cidrs) > 1 else ""
    print(f"  Subnets scanned : {_c(WHITE, ', '.join(sorted(known_cidrs)))}{user_label}")
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
