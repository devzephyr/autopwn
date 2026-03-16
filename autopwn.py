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
import json
import os
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
    return parser.parse_args()

# ---------------------------------------------------------------------------
# Main pipeline
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

    # Ensure required directories exist
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Ensure autopwn root is importable as a package prefix
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))

    print_banner(cidr)
    tlog("orchestrator", f"Pipeline started — target: {cidr}", "start")

    lhost = detect_lhost(cidr)
    info(f"LHOST (outbound interface): {lhost}")

    # ------------------------------------------------------------------
    # Stage 1: Discovery
    # ------------------------------------------------------------------
    def run_discovery():
        from modules import discovery  # type: ignore
        discovery.run(cidr)

    _run_stage("Host Discovery", "discovery", run_discovery, args.resume)

    # ------------------------------------------------------------------
    # Stage 2: Enrichment
    # ------------------------------------------------------------------
    def run_enrichment():
        from modules import enrichment  # type: ignore
        enrichment.run()

    _run_stage("Service Enrichment", "services", run_enrichment, args.resume)

    # ------------------------------------------------------------------
    # Stage 3: AD Enumeration (skippable)
    # ------------------------------------------------------------------
    def run_ad_enum():
        from modules import ad_enum  # type: ignore
        ad_enum.run()

    _run_stage(
        "Active Directory Enumeration", "ad_findings", run_ad_enum,
        args.resume, skip=args.skip_ad,
    )

    # ------------------------------------------------------------------
    # Stage 4: Planner
    # ------------------------------------------------------------------
    def run_planner():
        from modules import planner  # type: ignore
        planner.run()

    _run_stage("Attack Planning", "attack_plan", run_planner, args.resume)

    # ------------------------------------------------------------------
    # Stage 5: Exploitation
    # ------------------------------------------------------------------
    attack_plan = _load_json(STATE_FILES["attack_plan"]) or {"attack_paths": []}

    banner_stage(5, "Exploitation")
    tlog("exploitation", "Stage started", "start")

    if _should_skip("exploitation", args.resume):
        tlog("exploitation", "Skipped — checkpoint exists", "skip")
    else:
        t0 = time.monotonic()
        try:
            run_exploits(attack_plan, lhost, DRY_RUN)
            elapsed = time.monotonic() - t0
            ok(f"Exploitation stage completed in {elapsed:.1f}s")
            tlog("exploitation", f"Stage completed in {elapsed:.1f}s", "success")
        except Exception as exc:
            err(f"Exploitation stage failed: {exc}")
            tlog("exploitation", f"Stage failed: {exc}", "error")

    # ------------------------------------------------------------------
    # Stage 6: Credential Reuse
    # ------------------------------------------------------------------
    def run_reuse():
        from modules import reuse  # type: ignore
        reuse.run()

    _run_stage("Credential Reuse", "lateral", run_reuse, args.resume)

    # ------------------------------------------------------------------
    # Stage 7: Post-Exploitation (skippable)
    # ------------------------------------------------------------------
    def run_postex():
        from modules import postex  # type: ignore
        postex.run()

    _run_stage(
        "Post-Exploitation Enumeration", "postex", run_postex,
        args.resume, skip=args.skip_postex,
    )

    # ------------------------------------------------------------------
    # Stage 8: Report Generation
    # ------------------------------------------------------------------
    def run_report():
        from modules import report  # type: ignore
        report.run()

    _run_stage("Report Generation", "report", run_report, args.resume)

    # ------------------------------------------------------------------
    # Pipeline complete
    # ------------------------------------------------------------------
    bar = "═" * 62
    print(f"\n{GREEN}{bar}{RESET}")
    print(f"{BOLD}{GREEN}  Pipeline complete.{RESET}")

    report_files = sorted(OUTPUT_DIR.glob("report_*.html"))
    if report_files:
        ok(f"Report: {report_files[-1]}")

    print(f"{GREEN}{bar}{RESET}\n")
    tlog("orchestrator", "Pipeline finished", "done")


if __name__ == "__main__":
    main()
